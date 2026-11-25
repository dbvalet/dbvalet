//! Temporary logins created with the admin login, over admin SQL.

use std::error::Error as _;
use std::fmt;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio_postgres::config::SslMode;
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
    let client = match connect(&admin).await {
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
            describe(&err)
        ))),
    }
    checks
}

struct Rights {
    server_version: String,
    server_version_num: i32,
    superuser: bool,
    create_role: bool,
    signal_backend: bool,
}

async fn read_rights(client: &Client) -> Result<Rights, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT current_setting('server_version'),
                    current_setting('server_version_num')::int,
                    rolsuper,
                    rolcreaterole,
                    pg_has_role(current_user, 'pg_signal_backend', 'USAGE')
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
        signal_backend: row.get(4),
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
        Check::passed(format!(
            "`{user}` can end other roles' sessions, as a superuser"
        ))
    } else if rights.signal_backend {
        Check::passed(format!(
            "`{user}` can end other roles' sessions, through pg_signal_backend"
        ))
    } else if rights.create_role && rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        Check::passed(format!(
            "`{user}` can end the sessions of logins it creates, \
             because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
        ))
    } else if rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        let quoted = quote_ident(user);
        Check::failed(format!(
            "`{user}` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE {quoted} CREATEROLE, \
             or GRANT pg_signal_backend TO {quoted}"
        ))
    } else {
        let quoted = quote_ident(user);
        Check::failed(format!(
            "`{user}` can't end other roles' sessions: \
             as a superuser, run GRANT pg_signal_backend TO {quoted}"
        ))
    }
}

fn quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

async fn connect(admin: &AdminLogin) -> Result<Client, String> {
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
        .map_err(|err| describe(&err))?;
    tokio::spawn(connection);
    Ok(client)
}

/// tokio-postgres's own message is generic ("db error"); the server's reason is its source.
fn describe(err: &tokio_postgres::Error) -> String {
    match err.source() {
        Some(cause) => format!("{err}: {cause}"),
        None => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rights(
        server_version: &str,
        server_version_num: i32,
        superuser: bool,
        create_role: bool,
        signal_backend: bool,
    ) -> Rights {
        Rights {
            server_version: server_version.to_owned(),
            server_version_num,
            superuser,
            create_role,
            signal_backend,
        }
    }

    #[test]
    fn postgresql_13_fails_the_version_check_and_names_14() {
        let check = version_check(&rights("13.18", 130018, true, false, false));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "PostgreSQL 13.18 is too old: dbvalet needs 14 or later"
        );
    }

    #[test]
    fn postgresql_14_passes_the_version_check() {
        let check = version_check(&rights("14.0", 140000, true, false, false));
        assert!(check.passed);
        assert_eq!(check.message, "PostgreSQL 14.0 is 14 or later");
    }

    #[test]
    fn a_superuser_passes_the_create_role_check() {
        let check = create_role_check("admin", &rights("16.4", 160004, true, false, false));
        assert!(check.passed);
        assert_eq!(check.message, "`admin` is a superuser");
    }

    #[test]
    fn a_createrole_admin_passes_the_create_role_check() {
        let check = create_role_check("admin", &rights("16.4", 160004, false, true, false));
        assert!(check.passed);
        assert_eq!(check.message, "`admin` has CREATEROLE");
    }

    #[test]
    fn an_admin_without_createrole_fails_with_a_quoted_alter_role_command() {
        let check = create_role_check(
            "postgres.proj-1",
            &rights("16.4", 160004, false, false, false),
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`postgres.proj-1` has neither SUPERUSER nor CREATEROLE: as a superuser, \
             run ALTER ROLE \"postgres.proj-1\" CREATEROLE, or use your provider's admin login"
        );
    }

    #[test]
    fn a_superuser_can_end_sessions() {
        let check = end_sessions_check("admin", &rights("14.12", 140012, true, false, false));
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, as a superuser"
        );
    }

    #[test]
    fn an_admin_with_pg_signal_backend_can_end_sessions_before_postgresql_16() {
        let check = end_sessions_check("admin", &rights("14.12", 140012, false, true, true));
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, through pg_signal_backend"
        );
    }

    #[test]
    fn a_createrole_admin_on_postgresql_16_can_end_sessions() {
        let check = end_sessions_check("admin", &rights("16.0", 160000, false, true, false));
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end the sessions of logins it creates, \
             because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
        );
    }

    #[test]
    fn a_createrole_admin_before_postgresql_16_without_pg_signal_backend_is_told_to_grant_it() {
        let check = end_sessions_check("app-admin", &rights("14.12", 140012, false, true, false));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can't end other roles' sessions: \
             as a superuser, run GRANT pg_signal_backend TO \"app-admin\""
        );
    }

    #[test]
    fn an_admin_without_createrole_on_postgresql_16_is_told_to_add_createrole_first() {
        let check = end_sessions_check("Db\"Admin", &rights("16.4", 160004, false, false, false));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`Db\"Admin` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"Db\"\"Admin\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"Db\"\"Admin\""
        );
    }
}
