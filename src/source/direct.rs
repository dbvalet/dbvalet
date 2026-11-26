//! Temporary logins created with the admin login, over admin SQL.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls};

use super::{CredentialSource, Lease, SourceError, SweepReport, UpstreamLogin};
use crate::config::RoleGrant;
use crate::endpoint::Tls;
use crate::keychain::{self, AdminLogin};
use crate::ledger::{self, State};
use crate::{DatabaseAlias, LOGIN_PREFIX, RUN_ID_BYTES, is_login_name, random_base32};

/// For the whole admin connection: TCP, startup, authentication and its first setting.
const ADMIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// So a lock someone else holds on what a login owns fails that drop instead of stalling it.
const ADMIN_LOCK_TIMEOUT: &str = "10s";
const MINIMUM_SERVER_VERSION_NUM: i32 = 150000;
/// From this version a CREATEROLE admin can inherit the roles it creates.
const CREATEROLE_SELF_GRANT_VERSION_NUM: i32 = 160000;
const LOGIN_PASSWORD_BYTES: usize = 20;
/// How far ahead of the database's clock a new login's `VALID UNTIL` is set.
const LEASE_AHEAD: &str = "15 minutes";
/// How long `pg_terminate_backend` waits for each of the login's sessions to end.
const SESSION_END_TIMEOUT_MS: i64 = 5_000;
/// A second pass catches a session that was still starting, so not yet listed, during the first.
const SESSION_END_PASSES: usize = 2;
/// Leftover logins a sweep may drop without a ledger entry. Group roles fail `rolcanlogin`,
/// and live runs anywhere keep their `VALID UNTIL` in the future.
const EXPIRED_LOGINS: &str = "
    SELECT rolname::text
    FROM pg_roles
    WHERE rolcanlogin
      AND rolname ~ '^dbvalet_[a-z2-7]{16}$'
      AND rolvaliduntil < now()
      -- Another admin's logins are left to that admin's own sweep.
      AND pg_has_role(current_user, oid, 'USAGE')";

/// Temporary logins created over admin SQL, with a fresh admin connection per operation.
#[derive(Debug)]
pub struct DirectSource {
    alias: DatabaseAlias,
    admin: Arc<AdminLogin>,
}

impl DirectSource {
    pub fn new(alias: DatabaseAlias, admin: AdminLogin) -> Self {
        Self {
            alias,
            admin: Arc::new(admin),
        }
    }
}

impl CredentialSource for DirectSource {
    async fn sweep(&self) -> Result<SweepReport, SourceError> {
        let mut report = SweepReport::default();
        let listed = match ledger::list() {
            Ok(listed) => listed,
            Err(err) => {
                // Without the ledger, pass (b) can't tell a live login, or a read-only one.
                report.failures.push(err.into());
                return Ok(report);
            }
        };
        let client =
            connect(&self.alias, &self.admin)
                .await
                .map_err(|reason| SourceError::Connect {
                    alias: self.alias.clone(),
                    reason,
                })?;

        // Pass (b) leaves every login with an entry alone. This alias's entries are pass (a)'s.
        // Another alias's are that alias's sweep's, which connects to the database holding the
        // login's objects and never has its entries locked by this sweep.
        let mut has_entry = BTreeSet::new();
        for listed in listed {
            has_entry.insert(listed.login.clone());
            if listed.alias != self.alias {
                continue;
            }
            match listed.lock() {
                Some(State::Orphan(entry)) => sweep_orphan(&client, entry, &mut report).await,
                Some(State::Held) | None => {}
                Some(State::Unreadable(err)) => report.failures.push(err.into()),
            }
        }

        let expired = match client.query(EXPIRED_LOGINS, &[]).await {
            Ok(rows) => rows,
            Err(err) => {
                report.failures.push(SourceError::ListExpiredLogins {
                    reason: describe_sql_error(&err),
                });
                return Ok(report);
            }
        };
        for row in expired {
            let login: String = row.get(0);
            if !is_login_name(&login) || has_entry.contains(&login) {
                continue;
            }
            match drop_leftover_login(&client, &login, None).await {
                Ok(true) => report.dropped.push(login),
                Ok(false) => {}
                Err(reason) => report
                    .failures
                    .push(SourceError::DropLeftoverLogin { login, reason }),
            }
        }
        Ok(report)
    }

    async fn mint(&self, grant: &RoleGrant) -> Result<Lease, SourceError> {
        let create_failed = |err: tokio_postgres::Error| SourceError::CreateLogin {
            reason: describe_sql_error(&err),
        };
        let client =
            connect(&self.alias, &self.admin)
                .await
                .map_err(|reason| SourceError::Connect {
                    alias: self.alias.clone(),
                    reason,
                })?;
        let server = client
            .query_one(
                &format!(
                    "SELECT current_setting('server_version'),
                            current_setting('server_version_num')::int,
                            to_char((now() + interval '{LEASE_AHEAD}') AT TIME ZONE 'UTC',
                                    'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                            rolsuper,
                            rolinherit
                     FROM pg_roles
                     WHERE rolname = current_user"
                ),
                &[],
            )
            .await
            .map_err(create_failed)?;
        let (version, version_num, valid_until, superuser, inherit): (
            String,
            i32,
            String,
            bool,
            bool,
        ) = (
            server.get(0),
            server.get(1),
            server.get(2),
            server.get(3),
            server.get(4),
        );
        check_mint_prerequisites(
            &self.alias,
            self.admin.user(),
            &version,
            version_num,
            superuser,
            inherit,
        )?;

        let user = new_login_name().map_err(SourceError::Random)?;
        let password = random_base32(LOGIN_PASSWORD_BYTES).map_err(SourceError::Random)?;
        // Only the SCRAM verifier reaches the server, so its logs never hold the password.
        let verifier =
            postgres_protocol::password::scram_sha_256(password.expose_secret().as_bytes());
        // The admin needs the login's privileges to end its sessions and drop what it owns:
        // PostgreSQL 16 and later give them through createrole_self_grant, older ones through ROLE.
        let (self_grant, admin_member) = if version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
            ("SET createrole_self_grant = 'inherit';", String::new())
        } else {
            ("", format!("ROLE {}", quote_ident(self.admin.user())))
        };
        // Written before the login exists, so a run killed from here on leaves it to the sweep.
        let ledger_entry = ledger::create(&self.alias, &user, grant.read_only)?;
        let read_only = if grant.read_only {
            format!("ALTER ROLE {user} SET default_transaction_read_only = on;")
        } else {
            String::new()
        };
        // One simple query runs as one transaction, so a read login never exists without read_only.
        client
            .batch_execute(&format!(
                "{self_grant}
                 CREATE ROLE {user} LOGIN PASSWORD {verifier} VALID UNTIL {valid_until}
                     IN ROLE {group} {admin_member};
                 {read_only}",
                verifier = quote_literal(&verifier),
                valid_until = quote_literal(&valid_until),
                group = quote_ident(&grant.member_of),
            ))
            .await
            .map_err(create_failed)?;

        Ok(Lease {
            login: UpstreamLogin { user, password },
            alias: self.alias.clone(),
            admin: Arc::clone(&self.admin),
            member_of: grant.member_of.clone(),
            read_only: grant.read_only,
            ledger_entry,
        })
    }
}

/// Refuses versions and admin settings under which dbvalet can't drop the login it creates.
fn check_mint_prerequisites(
    alias: &DatabaseAlias,
    user: &str,
    version: &str,
    version_num: i32,
    superuser: bool,
    inherit: bool,
) -> Result<(), SourceError> {
    if version_num < MINIMUM_SERVER_VERSION_NUM {
        return Err(SourceError::TooOld {
            version: version.to_owned(),
        });
    }
    if !superuser && version_num < CREATEROLE_SELF_GRANT_VERSION_NUM && !inherit {
        return Err(SourceError::AdminNoInherit {
            alias: alias.clone(),
            user: user.to_owned(),
            quoted: quote_ident(user),
            version: version.to_owned(),
        });
    }
    Ok(())
}

/// [`LOGIN_PREFIX`] and 16 lowercase base32 characters, safe unquoted in SQL.
fn new_login_name() -> Result<String, getrandom::Error> {
    Ok(format!(
        "{LOGIN_PREFIX}{}",
        random_base32(RUN_ID_BYTES)?.expose_secret()
    ))
}

/// Ends the login's sessions, clears or reassigns what it owns, and drops it.
pub(super) async fn drop_login(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
    user: &str,
    member_of: &str,
    read_only: bool,
) -> Result<(), SourceError> {
    let drop_failed = |reason| SourceError::DropLogin {
        login: user.to_owned(),
        reason,
    };
    let client = connect(alias, admin).await.map_err(drop_failed)?;
    end_sessions(&client, user).await.map_err(drop_failed)?;
    let reassign_to = (!read_only).then_some(member_of);
    execute_drop(&client, user, reassign_to)
        .await
        .map(|_| ())
        .map_err(drop_failed)
}

/// Drops the login of an entry whose run has ended, then removes the entry.
async fn sweep_orphan(client: &Client, entry: ledger::Entry, report: &mut SweepReport) {
    let login = entry.login().to_owned();
    match drop_leftover_login(client, &login, entry.read_only()).await {
        Ok(existed) => match entry.remove() {
            Ok(()) if existed => report.dropped.push(login),
            Ok(()) => report.already_gone.push(login),
            Err(err) => report.failures.push(err.into()),
        },
        Err(reason) => report
            .failures
            .push(SourceError::DropLeftoverLogin { login, reason }),
    }
}

/// Drops a login an ended run left behind, reading from the database what its lease knew.
/// `ledger_read_only` is the ledger entry's word, when there is one. Returns whether the
/// login still existed.
async fn drop_leftover_login(
    client: &Client,
    user: &str,
    ledger_read_only: Option<bool>,
) -> Result<bool, String> {
    let Some(role) = client
        .query_opt(
            "SELECT COALESCE('default_transaction_read_only=on' = ANY (r.rolconfig), false),
                    ARRAY(SELECT DISTINCT g.rolname::text
                          FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                          WHERE m.member = r.oid)
             FROM pg_roles r
             WHERE r.rolname = $1 AND r.rolcanlogin",
            &[&user],
        )
        .await
        .map_err(|err| describe_sql_error(&err))?
    else {
        return Ok(false);
    };
    // The login can change its own settings in either direction, but not the ledger.
    let read_only = ledger_read_only.unwrap_or_else(|| role.get(0));
    let groups: Vec<String> = role.get(1);
    let reassign_to = match (read_only, groups.as_slice()) {
        (true, _) => None,
        (false, [group]) => Some(group.as_str()),
        (false, []) => {
            return Err("it belongs to no group role that could take over what it created".into());
        }
        (false, _) => {
            return Err(format!(
                "it belongs to {} group roles, so dbvalet can't tell which one should own \
                 what it created",
                groups.len()
            ));
        }
    };
    end_sessions(client, user).await?;
    execute_drop(client, user, reassign_to).await
}

/// Runs [`drop_login_sql`]. Returns false when the login was already gone, as when a sweep
/// elsewhere dropped it first.
async fn execute_drop(
    client: &Client,
    user: &str,
    reassign_to: Option<&str>,
) -> Result<bool, String> {
    let Err(err) = client
        .batch_execute(&drop_login_sql(user, reassign_to))
        .await
    else {
        return Ok(true);
    };
    let still_exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)",
            &[&user],
        )
        .await
        .map_err(|err| describe_sql_error(&err))?
        .get(0);
    if still_exists {
        Err(describe_sql_error(&err))
    } else {
        Ok(false)
    }
}

async fn end_sessions(client: &Client, user: &str) -> Result<(), String> {
    let mut remaining: i64 = 0;
    for _ in 0..SESSION_END_PASSES {
        client
            .query(
                "SELECT pg_terminate_backend(pid, $2) FROM pg_stat_activity WHERE usename = $1",
                &[&user, &SESSION_END_TIMEOUT_MS],
            )
            .await
            .map_err(|err| describe_sql_error(&err))?;
        // pg_terminate_backend returns false rather than failing, so count what is left.
        remaining = client
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
                &[&user],
            )
            .await
            .map_err(|err| describe_sql_error(&err))?
            .get(0);
        if remaining == 0 {
            return Ok(());
        }
    }
    Err(format!(
        "{remaining} of its sessions were still open after {SESSION_END_PASSES} rounds of \
         pg_terminate_backend"
    ))
}

/// Without a group to reassign to, as for a read-only login, everything the login owns is
/// dropped, including anything created despite read-only defaults (such as large objects
/// before PostgreSQL 16).
fn drop_login_sql(user: &str, reassign_to: Option<&str>) -> String {
    let login = quote_ident(user);
    match reassign_to {
        None => format!(
            "DROP OWNED BY {login};
             DROP ROLE {login};"
        ),
        Some(group) => format!(
            "REASSIGN OWNED BY {login} TO {group};
             DROP OWNED BY {login};
             DROP ROLE {login};",
            group = quote_ident(group)
        ),
    }
}

/// One line of `dbvalet doctor`'s report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub passed: bool,
    pub message: String,
}

impl Check {
    fn passed(message: String) -> Self {
        Self {
            passed: true,
            message,
        }
    }

    fn failed(message: String) -> Self {
        Self {
            passed: false,
            message,
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.passed { "ok  " } else { "FAIL" };
        write!(f, "{status} {}", self.message)
    }
}

/// Stops at the first failed check that later checks depend on.
pub async fn doctor(alias: &DatabaseAlias, allow_plaintext: bool) -> Vec<Check> {
    let admin = match keychain::load(alias, allow_plaintext) {
        Ok(admin) => admin,
        Err(err) => return vec![Check::failed(err.to_string())],
    };
    let mut checks = vec![Check::passed(format!(
        "the keychain holds an admin login for `{alias}`"
    ))];

    let user = admin.user();
    let client = match connect(alias, &admin).await {
        Ok(client) => client,
        Err(reason) => {
            checks.push(Check::failed(format!(
                "`{user}` can't connect to {}: {reason}",
                admin.endpoint()
            )));
            return checks;
        }
    };
    checks.push(Check::passed(format!(
        "`{user}` connects to {}",
        admin.endpoint()
    )));

    match read_rights(&client).await {
        Ok(rights) => {
            checks.push(version_check(&rights));
            checks.push(create_role_check(user, &rights));
            checks.push(end_sessions_check(user, &rights));
        }
        Err(err) => checks.push(Check::failed(format!(
            "can't read the rights of `{user}`: {}",
            describe_query_error(&err)
        ))),
    }
    checks
}

struct Rights {
    server_version: String,
    server_version_num: i32,
    superuser: bool,
    create_role: bool,
    inherit: bool,
    signal_backend: bool,
    signal_backend_member: bool,
}

async fn read_rights(client: &Client) -> Result<Rights, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT current_setting('server_version'),
                    current_setting('server_version_num')::int,
                    rolsuper,
                    rolcreaterole,
                    rolinherit,
                    pg_has_role(current_user, 'pg_signal_backend', 'USAGE'),
                    pg_has_role(current_user, 'pg_signal_backend', 'MEMBER')
             FROM pg_roles
             WHERE rolname = current_user",
            &[],
        )
        .await?;
    Ok(Rights {
        server_version: row.get(0),
        server_version_num: row.get(1),
        superuser: row.get(2),
        create_role: row.get(3),
        inherit: row.get(4),
        signal_backend: row.get(5),
        signal_backend_member: row.get(6),
    })
}

fn version_check(rights: &Rights) -> Check {
    let version = &rights.server_version;
    if rights.server_version_num >= MINIMUM_SERVER_VERSION_NUM {
        Check::passed(format!("PostgreSQL {version} is 15 or later"))
    } else {
        Check::failed(format!(
            "PostgreSQL {version} is end-of-life: dbvalet needs 15 or later"
        ))
    }
}

fn create_role_check(user: &str, rights: &Rights) -> Check {
    if rights.superuser {
        Check::passed(format!("`{user}` is a superuser"))
    } else if rights.create_role {
        Check::passed(format!("`{user}` has CREATEROLE"))
    } else {
        let quoted = quote_ident(user);
        Check::failed(format!(
            "`{user}` has neither SUPERUSER nor CREATEROLE: as a superuser, \
             run ALTER ROLE {quoted} CREATEROLE, or use your provider's admin login"
        ))
    }
}

fn end_sessions_check(user: &str, rights: &Rights) -> Check {
    if rights.superuser {
        return Check::passed(format!(
            "`{user}` can end other roles' sessions, as a superuser"
        ));
    }
    if rights.signal_backend {
        return Check::passed(format!(
            "`{user}` can end other roles' sessions, through pg_signal_backend"
        ));
    }
    let quoted = quote_ident(user);
    if rights.create_role {
        if rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
            return Check::passed(format!(
                "`{user}` can end the sessions of logins it creates, \
                 because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
            ));
        }
        if rights.inherit {
            return Check::passed(format!(
                "`{user}` can end the sessions of logins it creates, \
                 because dbvalet adds it as a member of each login"
            ));
        }
        return Check::failed(format!(
            "`{user}` can't end the sessions of logins it creates because it has NOINHERIT: \
             run ALTER ROLE {quoted} INHERIT"
        ));
    }
    if rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        let grant_fix = if rights.signal_backend_member || !rights.inherit {
            format!("GRANT pg_signal_backend TO {quoted} WITH INHERIT TRUE")
        } else {
            format!("GRANT pg_signal_backend TO {quoted}")
        };
        return Check::failed(format!(
            "`{user}` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE {quoted} CREATEROLE, or {grant_fix}"
        ));
    }
    let fix = if !rights.inherit && rights.signal_backend_member {
        format!("ALTER ROLE {quoted} INHERIT")
    } else if !rights.inherit {
        format!(
            "ALTER ROLE {quoted} CREATEROLE INHERIT, \
             or GRANT pg_signal_backend TO {quoted} and ALTER ROLE {quoted} INHERIT"
        )
    } else {
        format!("ALTER ROLE {quoted} CREATEROLE, or GRANT pg_signal_backend TO {quoted}")
    };
    Check::failed(format!(
        "`{user}` can't end other roles' sessions: as a superuser, run {fix}"
    ))
}

fn quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn quote_literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The server's message and SQLSTATE: admin SQL errors never quote the statement text.
fn describe_sql_error(err: &tokio_postgres::Error) -> String {
    match err.as_db_error() {
        Some(db) => format!("{} (SQLSTATE {})", db.message(), db.code().code()),
        None => "the connection to PostgreSQL ended before it answered".to_owned(),
    }
}

async fn connect(alias: &DatabaseAlias, admin: &AdminLogin) -> Result<Client, String> {
    let endpoint = admin.endpoint();
    if endpoint.tls() == Tls::VerifyFull {
        return Err("TLS connections aren't supported yet: \
                    use --allow-plaintext with a database on localhost"
            .to_owned());
    }
    let mut config = tokio_postgres::Config::new();
    config
        .host(endpoint.host())
        .port(endpoint.port())
        .dbname(endpoint.database())
        .user(admin.user())
        .password(admin.password().expose_secret())
        .ssl_mode(SslMode::Disable);
    let connecting = async {
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|err| describe_connect_error(alias, admin, &err))?;
        tokio::spawn(connection);
        client
            .batch_execute(&format!("SET lock_timeout = '{ADMIN_LOCK_TIMEOUT}'"))
            .await
            .map_err(|err| describe_sql_error(&err))?;
        Ok(client)
    };
    tokio::time::timeout(ADMIN_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            format!(
                "no answer within {} s: check that the host and port in \
                 `dbvalet login {alias}` are a PostgreSQL server's",
                ADMIN_CONNECT_TIMEOUT.as_secs()
            )
        })?
}

/// Never prints the server's raw error text, because it can quote input fields.
fn describe_connect_error(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
    err: &tokio_postgres::Error,
) -> String {
    if let Some(db) = err.as_db_error() {
        return describe_db_connect_error(alias, admin.user(), db.code(), db.message());
    }
    if let Some(io_err) = find_io_error(err) {
        return format!(
            "{io_err}: check that PostgreSQL is running and reachable, \
             or run `dbvalet login {alias}` with the right host and port"
        );
    }
    format!(
        "couldn't establish a PostgreSQL session: check that PostgreSQL is running, \
         or run `dbvalet login {alias}` again"
    )
}

fn describe_db_connect_error(
    alias: &DatabaseAlias,
    user: &str,
    code: &SqlState,
    server_message: &str,
) -> String {
    let quoted = quote_ident(user);
    if *code == SqlState::INVALID_PASSWORD {
        return format!(
            "password authentication failed: run `dbvalet login {alias}` again with the \
             right password, or as a superuser run ALTER ROLE {quoted} VALID UNTIL 'infinity'"
        );
    }
    if *code == SqlState::INVALID_AUTHORIZATION_SPECIFICATION {
        if server_message.contains("not permitted to log in") {
            return format!(
                "role isn't permitted to log in: as a superuser, run ALTER ROLE {quoted} LOGIN"
            );
        }
        if server_message.contains("does not exist") {
            return format!(
                "role doesn't exist: check the user name and run `dbvalet login {alias}` again"
            );
        }
        return format!(
            "the server rejected the login (SQLSTATE {}): check pg_hba.conf or run \
             `dbvalet login {alias}` again",
            code.code()
        );
    }
    if *code == SqlState::INVALID_CATALOG_NAME {
        return format!(
            "database doesn't exist: run `dbvalet login {alias}` with an existing database \
             in the connection string (when omitted, it defaults to the user name)"
        );
    }
    format!(
        "the server refused the connection (SQLSTATE {}): check the server logs or run \
         `dbvalet login {alias}` again",
        code.code()
    )
}

fn describe_query_error(err: &tokio_postgres::Error) -> String {
    if let Some(db) = err.as_db_error() {
        return format!(
            "the server returned SQLSTATE {}: check the admin role's access to pg_roles",
            db.code().code()
        );
    }
    "the connection ended before PostgreSQL answered: try running `dbvalet doctor` again".to_owned()
}

fn find_io_error<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a io::Error> {
    let mut current = err.source();
    while let Some(source) = current {
        if let Some(io_err) = source.downcast_ref::<io::Error>() {
            return Some(io_err);
        }
        current = source.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(server_version: &str, server_version_num: i32) -> Rights {
        Rights {
            server_version: server_version.to_owned(),
            server_version_num,
            superuser: false,
            create_role: false,
            inherit: true,
            signal_backend: false,
            signal_backend_member: false,
        }
    }

    fn alias() -> DatabaseAlias {
        "app".parse().unwrap()
    }

    #[test]
    fn a_new_login_name_is_dbvalet_and_16_lowercase_base32_characters() {
        let name = new_login_name().unwrap();
        let run_id = name.strip_prefix("dbvalet_").unwrap();
        assert_eq!(run_id.len(), 16, "{name}");
        assert!(
            run_id
                .bytes()
                .all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')),
            "{name}"
        );
    }

    #[test]
    fn the_login_name_pattern_accepts_a_new_login_name() {
        assert!(is_login_name(&new_login_name().unwrap()));
        assert!(is_login_name("dbvalet_abcdefghijklmnop"));
        assert!(is_login_name("dbvalet_234567234567zzzz"));
    }

    #[test]
    fn the_login_name_pattern_rejects_dbvalet_reader_and_near_misses() {
        assert!(!is_login_name("dbvalet_reader"));
        assert!(!is_login_name("dbvalet_abcdefghijklmno"));
        assert!(!is_login_name("dbvalet_abcdefghijklmnopq"));
        assert!(!is_login_name("dbvalet_ABCDEFGHIJKLMNOP"));
        assert!(!is_login_name("dbvalet_abcdefghijklmno1"));
        assert!(!is_login_name("dbvalet_abcdefghijklmno\u{e9}"));
        assert!(!is_login_name("xdbvalet_abcdefghijklmnop"));
    }

    #[test]
    fn postgresql_14_fails_the_version_check_naming_15_and_end_of_life() {
        let check = version_check(&Rights {
            superuser: true,
            ..pg("14.25", 140025)
        });
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "PostgreSQL 14.25 is end-of-life: dbvalet needs 15 or later"
        );
    }

    #[test]
    fn postgresql_15_passes_the_version_check() {
        let check = version_check(&Rights {
            superuser: true,
            ..pg("15.0", 150000)
        });
        assert!(check.passed);
        assert_eq!(check.message, "PostgreSQL 15.0 is 15 or later");
    }

    #[test]
    fn a_superuser_passes_the_create_role_check() {
        let check = create_role_check(
            "admin",
            &Rights {
                superuser: true,
                ..pg("16.4", 160004)
            },
        );
        assert!(check.passed);
        assert_eq!(check.message, "`admin` is a superuser");
    }

    #[test]
    fn a_createrole_admin_passes_the_create_role_check() {
        let check = create_role_check(
            "admin",
            &Rights {
                create_role: true,
                ..pg("16.4", 160004)
            },
        );
        assert!(check.passed);
        assert_eq!(check.message, "`admin` has CREATEROLE");
    }

    #[test]
    fn an_admin_without_createrole_fails_with_a_quoted_alter_role_command() {
        let check = create_role_check("postgres.proj-1", &pg("16.4", 160004));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`postgres.proj-1` has neither SUPERUSER nor CREATEROLE: as a superuser, \
             run ALTER ROLE \"postgres.proj-1\" CREATEROLE, or use your provider's admin login"
        );
    }

    #[test]
    fn a_superuser_can_end_sessions() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                superuser: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, as a superuser"
        );
    }

    #[test]
    fn an_admin_with_pg_signal_backend_can_end_sessions_on_postgresql_15() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                signal_backend: true,
                signal_backend_member: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, through pg_signal_backend"
        );
    }

    #[test]
    fn a_createrole_admin_on_postgresql_16_can_end_sessions() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                create_role: true,
                ..pg("16.0", 160000)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end the sessions of logins it creates, \
             because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
        );
    }

    #[test]
    fn a_createrole_inherit_admin_on_postgresql_15_can_end_sessions() {
        let check = end_sessions_check(
            "app-admin",
            &Rights {
                create_role: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can end the sessions of logins it creates, \
             because dbvalet adds it as a member of each login"
        );
    }

    #[test]
    fn a_noinherit_createrole_admin_on_postgresql_15_is_told_to_enable_inherit() {
        let check = end_sessions_check(
            "app-admin",
            &Rights {
                create_role: true,
                inherit: false,
                ..pg("15.20", 150020)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can't end the sessions of logins it creates because it has NOINHERIT: \
             run ALTER ROLE \"app-admin\" INHERIT"
        );
    }

    #[test]
    fn a_plain_admin_on_postgresql_15_is_told_to_add_createrole_or_grant_pg_signal_backend() {
        let check = end_sessions_check("plain", &pg("15.20", 150020));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"plain\""
        );
    }

    #[test]
    fn a_noinherit_plain_admin_holding_pg_signal_backend_on_postgresql_15_is_told_to_enable_inherit()
     {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                signal_backend_member: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" INHERIT"
        );
    }

    #[test]
    fn a_noinherit_plain_admin_on_postgresql_15_is_told_as_superuser_to_add_createrole_and_inherit()
    {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                ..pg("15.20", 150020)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" CREATEROLE INHERIT, \
             or GRANT pg_signal_backend TO \"plain\" and ALTER ROLE \"plain\" INHERIT"
        );
    }

    #[test]
    fn an_admin_without_createrole_on_postgresql_16_is_told_to_add_createrole_first() {
        let check = end_sessions_check("Db\"Admin", &pg("16.4", 160004));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`Db\"Admin` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"Db\"\"Admin\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"Db\"\"Admin\""
        );
    }

    #[test]
    fn a_noinherit_admin_without_createrole_on_postgresql_16_is_told_grant_with_inherit_true() {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                signal_backend_member: true,
                ..pg("17.0", 170000)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"plain\" WITH INHERIT TRUE"
        );
    }

    #[test]
    fn connect_errors_name_fixes_without_echoing_raw_server_text() {
        let wrong_pw = describe_db_connect_error(
            &alias(),
            "admin",
            &SqlState::INVALID_PASSWORD,
            "password authentication failed for user \"leaked-raw\"",
        );
        assert!(wrong_pw.contains("dbvalet login app"));
        assert!(wrong_pw.contains("ALTER ROLE \"admin\" VALID UNTIL 'infinity'"));
        assert!(!wrong_pw.contains("leaked-raw"));

        let nologin = describe_db_connect_error(
            &alias(),
            "admin",
            &SqlState::INVALID_AUTHORIZATION_SPECIFICATION,
            "role \"leaked-raw\" is not permitted to log in",
        );
        assert!(nologin.contains("ALTER ROLE \"admin\" LOGIN"));
        assert!(!nologin.contains("leaked-raw"));

        let missing_db = describe_db_connect_error(
            &alias(),
            "admin",
            &SqlState::INVALID_CATALOG_NAME,
            "database \"leaked-raw\" does not exist",
        );
        assert!(missing_db.contains("dbvalet login app"));
        assert!(missing_db.contains("defaults to the user name"));
        assert!(!missing_db.contains("leaked-raw"));
    }

    #[test]
    fn mint_refuses_postgresql_14_as_end_of_life() {
        let err =
            check_mint_prerequisites(&alias(), "super", "14.25", 140025, true, true).unwrap_err();
        assert!(matches!(err, SourceError::TooOld { .. }));
        assert_eq!(
            err.to_string(),
            "PostgreSQL 14.25 is end-of-life: dbvalet needs 15 or later"
        );
    }

    #[test]
    fn mint_refuses_a_noinherit_non_superuser_before_postgresql_16() {
        let err = check_mint_prerequisites(&alias(), "app-admin", "15.8", 150008, false, false)
            .unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, SourceError::AdminNoInherit { .. }));
        assert!(
            message.contains("ALTER ROLE \"app-admin\" INHERIT"),
            "{message}"
        );
        assert!(message.contains("dbvalet doctor app"), "{message}");
    }

    #[test]
    fn mint_allows_supported_admins_on_postgresql_15_and_16() {
        assert!(check_mint_prerequisites(&alias(), "super", "15.20", 150020, true, false).is_ok());
        assert!(check_mint_prerequisites(&alias(), "admin", "15.20", 150020, false, true).is_ok());
        assert!(check_mint_prerequisites(&alias(), "admin", "16.0", 160000, false, false).is_ok());
    }

    #[test]
    fn dropping_a_read_only_login_skips_reassign_owned() {
        let sql = drop_login_sql("dbvalet_aaaaaaaaaaaaaaaa", None);
        assert!(!sql.contains("REASSIGN OWNED"), "{sql}");
        assert!(
            sql.contains("DROP OWNED BY \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
        assert!(
            sql.contains("DROP ROLE \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
    }

    #[test]
    fn dropping_a_writable_login_reassigns_owned_objects_to_its_group() {
        let sql = drop_login_sql("dbvalet_aaaaaaaaaaaaaaaa", Some("dbvalet_writer"));
        assert!(
            sql.contains("REASSIGN OWNED BY \"dbvalet_aaaaaaaaaaaaaaaa\" TO \"dbvalet_writer\";"),
            "{sql}"
        );
        assert!(
            sql.contains("DROP OWNED BY \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
        assert!(
            sql.contains("DROP ROLE \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
    }
}
