//! Temporary logins created with the admin login, over admin SQL.

use std::fmt;
use std::io;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls};

use crate::DatabaseAlias;
use crate::endpoint::Tls;
use crate::keychain::{self, AdminLogin};

const ADMIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MINIMUM_SERVER_VERSION_NUM: i32 = 140000;
/// From this version a CREATEROLE admin can inherit the roles it creates.
const CREATEROLE_SELF_GRANT_VERSION_NUM: i32 = 160000;

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
        Check::passed(format!("PostgreSQL {version} is 14 or later"))
    } else {
        Check::failed(format!(
            "PostgreSQL {version} is too old: dbvalet needs 14 or later"
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
    if rights.create_role && rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        return Check::passed(format!(
            "`{user}` can end the sessions of logins it creates, \
             because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
        ));
    }
    let quoted = quote_ident(user);
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
    let prefix = if rights.create_role {
        ""
    } else {
        "as a superuser, "
    };
    let fix = if !rights.inherit && rights.signal_backend_member {
        format!("ALTER ROLE {quoted} INHERIT")
    } else if !rights.inherit {
        format!("GRANT pg_signal_backend TO {quoted} and ALTER ROLE {quoted} INHERIT")
    } else {
        format!("GRANT pg_signal_backend TO {quoted}")
    };
    Check::failed(format!(
        "`{user}` can't end other roles' sessions: {prefix}run {fix}"
    ))
}

fn quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

async fn connect(alias: &DatabaseAlias, admin: &AdminLogin) -> Result<Client, String> {
    let endpoint = admin.endpoint();
    if endpoint.tls() == Tls::VerifyFull {
        return Err("TLS connections aren't supported yet: \
                    use --allow-plaintext with a database on localhost"
            .to_owned());
    }
    let (client, connection) = tokio_postgres::Config::new()
        .host(endpoint.host())
        .port(endpoint.port())
        .dbname(endpoint.database())
        .user(admin.user())
        .password(admin.password().expose_secret())
        .ssl_mode(SslMode::Disable)
        .connect_timeout(ADMIN_CONNECT_TIMEOUT)
        .connect(NoTls)
        .await
        .map_err(|err| describe_connect_error(alias, admin, &err))?;
    tokio::spawn(connection);
    Ok(client)
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
    fn postgresql_13_fails_the_version_check_and_names_14() {
        let check = version_check(&Rights {
            superuser: true,
            ..pg("13.18", 130018)
        });
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "PostgreSQL 13.18 is too old: dbvalet needs 14 or later"
        );
    }

    #[test]
    fn postgresql_14_passes_the_version_check() {
        let check = version_check(&Rights {
            superuser: true,
            ..pg("14.0", 140000)
        });
        assert!(check.passed);
        assert_eq!(check.message, "PostgreSQL 14.0 is 14 or later");
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
                ..pg("14.12", 140012)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, as a superuser"
        );
    }

    #[test]
    fn an_admin_with_pg_signal_backend_can_end_sessions_before_postgresql_16() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                create_role: true,
                signal_backend: true,
                signal_backend_member: true,
                ..pg("14.12", 140012)
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
    fn a_createrole_admin_before_postgresql_16_without_pg_signal_backend_is_told_to_grant_it() {
        let check = end_sessions_check(
            "app-admin",
            &Rights {
                create_role: true,
                ..pg("14.12", 140012)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can't end other roles' sessions: \
             run GRANT pg_signal_backend TO \"app-admin\""
        );
    }

    #[test]
    fn a_noinherit_createrole_admin_holding_pg_signal_backend_before_16_is_told_to_enable_inherit()
    {
        let check = end_sessions_check(
            "app-admin",
            &Rights {
                create_role: true,
                inherit: false,
                signal_backend_member: true,
                ..pg("14.12", 140012)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can't end other roles' sessions: \
             run ALTER ROLE \"app-admin\" INHERIT"
        );
    }

    #[test]
    fn a_noinherit_plain_admin_before_16_is_told_as_superuser_to_grant_and_enable_inherit() {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                ..pg("14.12", 140012)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run GRANT pg_signal_backend TO \"plain\" \
             and ALTER ROLE \"plain\" INHERIT"
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
}
