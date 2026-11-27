//! The checks `dbvalet doctor` prints.

use std::collections::BTreeMap;
use std::fmt;

use tokio_postgres::Client;

use super::{
    CREATEROLE_SELF_GRANT_VERSION_NUM, GroupRoleStatus, MINIMUM_SERVER_VERSION_NUM, connect,
    inspect_group_role, quote_ident,
};
use crate::DatabaseAlias;
use crate::config::RoleGrant;
use crate::endpoint::{Endpoint, Tls, TrustRoot};
use crate::keychain;

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
pub async fn doctor(
    alias: &DatabaseAlias,
    allow_plaintext: bool,
    roles: &BTreeMap<String, RoleGrant>,
) -> Vec<Check> {
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
    checks.push(tls_check(admin.endpoint()));

    match read_rights(&client).await {
        Ok(rights) => {
            checks.push(version_check(&rights));
            checks.push(create_role_check(user, &rights));
            checks.push(end_sessions_check(user, &rights));
            for (role_name, grant) in roles {
                let check = match inspect_group_role(&client, &grant.member_of).await {
                    Ok(status) => group_role_check(role_name, &grant.member_of, status),
                    Err(err) => Check::failed(format!(
                        "can't check role `{role_name}` (`{}`): {}",
                        grant.member_of,
                        describe_query_error(&err)
                    )),
                };
                checks.push(check);
            }
        }
        Err(err) => checks.push(Check::failed(format!(
            "can't read the rights of `{user}`: {}",
            describe_query_error(&err)
        ))),
    }
    checks
}

fn group_role_check(role_name: &str, member_of: &str, status: GroupRoleStatus) -> Check {
    match status {
        GroupRoleStatus::Safe => Check::passed(format!(
            "role `{role_name}` (`{member_of}`) has no dangerous attributes or memberships"
        )),
        GroupRoleStatus::Missing => Check::failed(format!(
            "role `{role_name}` (`{member_of}`) doesn't exist in PostgreSQL"
        )),
        GroupRoleStatus::Dangerous(reason) => Check::failed(format!(
            "role `{role_name}` (`{member_of}`) is refused: {reason}"
        )),
    }
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

fn tls_check(endpoint: &Endpoint) -> Check {
    match endpoint.tls() {
        Tls::VerifyFull(TrustRoot::System) => {
            Check::passed("TLS verify-full using the OS trust store".to_owned())
        }
        Tls::VerifyFull(TrustRoot::PemFile(path)) => Check::passed(format!(
            "TLS verify-full using sslrootcert `{}`",
            path.display()
        )),
        Tls::Plaintext => Check::passed("plaintext on localhost (--allow-plaintext)".to_owned()),
    }
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

fn describe_query_error(err: &tokio_postgres::Error) -> String {
    if let Some(db) = err.as_db_error() {
        return format!(
            "the server returned SQLSTATE {}: check the admin role's access to pg_roles",
            db.code().code()
        );
    }
    "the connection ended before PostgreSQL answered: try running `dbvalet doctor` again".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ChannelBinding;

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
    fn doctor_tls_check_names_the_tls_state_and_trust_root() {
        let system =
            Endpoint::new("db.example.com".to_owned(), 5432, "app".to_owned(), false).unwrap();
        let system_check = tls_check(&system);
        assert!(system_check.passed);
        assert_eq!(
            system_check.message,
            "TLS verify-full using the OS trust store"
        );

        let custom = Endpoint::with_tls_options(
            "db.example.com".to_owned(),
            5432,
            "app".to_owned(),
            false,
            TrustRoot::PemFile(std::path::PathBuf::from("/etc/ssl/rds-ca.pem")),
            ChannelBinding::Prefer,
        )
        .unwrap();
        let custom_check = tls_check(&custom);
        assert!(custom_check.passed);
        assert_eq!(
            custom_check.message,
            "TLS verify-full using sslrootcert `/etc/ssl/rds-ca.pem`"
        );

        let plaintext =
            Endpoint::new("localhost".to_owned(), 5432, "postgres".to_owned(), true).unwrap();
        let plaintext_check = tls_check(&plaintext);
        assert!(plaintext_check.passed);
        assert_eq!(
            plaintext_check.message,
            "plaintext on localhost (--allow-plaintext)"
        );
    }

    #[test]
    fn group_role_check_formats_safe_missing_and_dangerous_results() {
        assert_eq!(
            group_role_check("reader", "dbvalet_reader", GroupRoleStatus::Safe),
            Check::passed(
                "role `reader` (`dbvalet_reader`) has no dangerous attributes or memberships"
                    .to_owned()
            )
        );
        assert_eq!(
            group_role_check("reader", "missing_group", GroupRoleStatus::Missing),
            Check::failed("role `reader` (`missing_group`) doesn't exist in PostgreSQL".to_owned())
        );
        assert_eq!(
            group_role_check(
                "ops",
                "ops_group",
                GroupRoleStatus::Dangerous(
                    "is a member of `pg_execute_server_program` (built-in pg_* role)".to_owned()
                )
            ),
            Check::failed(
                "role `ops` (`ops_group`) is refused: \
                 is a member of `pg_execute_server_program` (built-in pg_* role)"
                    .to_owned()
            )
        );
    }
}
