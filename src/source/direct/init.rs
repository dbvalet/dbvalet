//! `dbvalet init`: the read-only group role and its grants, over admin SQL.

use tokio_postgres::Transaction;

use super::doctor::{create_role_check, read_rights};
use super::{
    CREATEROLE_SELF_GRANT_VERSION_NUM, GroupRoleStatus, SourceError, check_mint_prerequisites,
    connect, describe_sql_error, inspect_group_role, quote_ident,
};
use crate::DatabaseAlias;
use crate::keychain::AdminLogin;

/// A concurrent `init` may create the role between the check and the create, so a duplicate
/// counts as success. The admin's membership comes from `createrole_self_grant` on 16+.
const CREATE_READER_IF_MISSING: &str = "
    DO $$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dbvalet_reader') THEN
            CREATE ROLE dbvalet_reader NOLOGIN;
        END IF;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
    END $$";
/// Before 16 CREATEROLE may grant any non-superuser role, including to itself. An init on
/// another database can grant the same cluster-wide membership first.
const GRANT_READER_WITH_ADMIN_TO_ME: &str = "
    DO $$ BEGIN
        GRANT dbvalet_reader TO CURRENT_USER WITH ADMIN OPTION;
    EXCEPTION WHEN unique_violation THEN NULL;
    END $$";
/// PostgreSQL refuses ADMIN OPTION granted back to its own grantor, so on 16+ only the rest.
const GRANT_READER_INHERIT_AND_SET_TO_ME: &str = "
    DO $$ BEGIN
        GRANT dbvalet_reader TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    EXCEPTION WHEN unique_violation THEN NULL;
    END $$";

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("can't connect as the admin login for `{alias}`: {reason}")]
    Connect {
        alias: DatabaseAlias,
        reason: String,
    },
    /// The admin or the server is one `run` would refuse too.
    #[error(transparent)]
    Refused(#[from] SourceError),
    #[error("{0}")]
    CantCreateLogins(String),
    #[error(
        "the existing role dbvalet_reader can log in, so dbvalet grants it nothing: \
         run ALTER ROLE dbvalet_reader NOLOGIN if it should be a group role"
    )]
    ReaderCanLogin,
    #[error(
        "`{user}` lacks {missing} on dbvalet_reader: ask a superuser, or a role holding \
         ADMIN OPTION on it, to run {fix}"
    )]
    AdminLacksRights {
        user: String,
        missing: String,
        fix: String,
    },
    #[error(
        "the grant of CONNECT on database `{database}` had no effect: its owner, a superuser, \
         or a role holding CONNECT WITH GRANT OPTION must run \
         GRANT CONNECT ON DATABASE {quoted} TO dbvalet_reader"
    )]
    DatabaseNotGranted { database: String, quoted: String },
    #[error(
        "the grant on schema `{schema}` had no effect: its owner, or a superuser, must run \
         GRANT USAGE ON SCHEMA {quoted} TO dbvalet_reader, or run `dbvalet init` as the owner"
    )]
    SchemaNotGranted { schema: String, quoted: String },
    #[error("couldn't set up dbvalet_reader: {reason}")]
    Sql { reason: String },
}

/// What `init` granted, for the summary it prints.
#[derive(Debug)]
pub struct InitReport {
    pub database: String,
    /// Per schema, how many existing tables stay unreadable because another role owns them.
    pub unreadable_tables: Vec<(String, i64)>,
}

/// Creates `dbvalet_reader` if missing, gives the admin ADMIN, INHERIT and SET on it, and lets
/// it read every table in `schemas`, now and as the admin creates more. Safe to run again.
pub async fn init(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
    schemas: &[String],
) -> Result<InitReport, InitError> {
    let mut client = connect(alias, admin)
        .await
        .map_err(|reason| InitError::Connect {
            alias: alias.clone(),
            reason,
        })?;
    let user = admin.user();
    let rights = read_rights(&client).await.map_err(sql_failed)?;
    check_mint_prerequisites(
        alias,
        user,
        &rights.server_version,
        rights.server_version_num,
        rights.superuser,
        rights.inherit,
    )?;
    let create_role = create_role_check(user, &rights);
    if !create_role.passed {
        return Err(InitError::CantCreateLogins(create_role.message));
    }
    let version_num = rights.server_version_num;

    // One transaction, so a failure leaves the database as it was.
    let transaction = client.transaction().await.map_err(sql_failed)?;
    // Concurrent inits on one database would fail on its ACLs, so they take turns.
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('dbvalet init', 0))",
            &[],
        )
        .await
        .map_err(sql_failed)?;
    if version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        transaction
            .batch_execute("SET LOCAL createrole_self_grant = 'set, inherit'")
            .await
            .map_err(sql_failed)?;
    }
    transaction
        .batch_execute(CREATE_READER_IF_MISSING)
        .await
        .map_err(sql_failed)?;
    check_reader(&transaction).await?;
    grant_reader_to_admin(&transaction, user, version_num).await?;
    let database: String = transaction
        .query_one("SELECT current_database()::text", &[])
        .await
        .map_err(sql_failed)?
        .get(0);
    transaction
        .batch_execute(&grants_sql(&database, schemas))
        .await
        .map_err(sql_failed)?;
    let unreadable_tables = check_reach(&transaction, &database, schemas).await?;
    transaction.commit().await.map_err(sql_failed)?;
    Ok(InitReport {
        database,
        unreadable_tables,
    })
}

/// Checks the role this transaction created or found, so a change made while init waited for
/// its lock still counts.
async fn check_reader(transaction: &Transaction<'_>) -> Result<(), InitError> {
    let status = inspect_group_role(transaction, "dbvalet_reader")
        .await
        .map_err(sql_failed)?;
    let can_login: bool = transaction
        .query_one(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = 'dbvalet_reader'",
            &[],
        )
        .await
        .map_err(sql_failed)?
        .get(0);
    refuse_existing_reader(can_login, status)
}

/// The role is cluster-wide, so someone else may have made it: grant nothing to a role that
/// `run` would refuse to join, or that can log in.
fn refuse_existing_reader(can_login: bool, status: GroupRoleStatus) -> Result<(), InitError> {
    if let GroupRoleStatus::Dangerous(reason) = status {
        return Err(SourceError::DangerousRole {
            member_of: "dbvalet_reader".to_owned(),
            reason,
        }
        .into());
    }
    if can_login {
        return Err(InitError::ReaderCanLogin);
    }
    Ok(())
}

/// What the admin can do with dbvalet_reader. It needs ADMIN to add logins to the role, INHERIT
/// to drop what they own, and SET to reassign it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReaderRights {
    admin: bool,
    inherit: bool,
    set: bool,
}

impl ReaderRights {
    fn missing(self) -> Vec<&'static str> {
        [
            (self.admin, "ADMIN OPTION"),
            (self.inherit, "INHERIT"),
            (self.set, "SET"),
        ]
        .into_iter()
        .filter_map(|(held, right)| (!held).then_some(right))
        .collect()
    }
}

/// Grants only what's missing, so a second run adds no membership, then checks the rights the
/// admin actually holds: a concurrent weaker GRANT, or one through a NOINHERIT role, falls short.
async fn grant_reader_to_admin(
    transaction: &Transaction<'_>,
    user: &str,
    version_num: i32,
) -> Result<(), InitError> {
    let self_grant = version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM;
    let before = reader_rights(transaction, self_grant).await?;
    let grant = if !self_grant {
        GRANT_READER_WITH_ADMIN_TO_ME
    } else if before.admin {
        GRANT_READER_INHERIT_AND_SET_TO_ME
    } else {
        ""
    };
    let after = if before.missing().is_empty() || grant.is_empty() {
        before
    } else {
        transaction.batch_execute(grant).await.map_err(sql_failed)?;
        reader_rights(transaction, self_grant).await?
    };
    let missing = after.missing();
    if missing.is_empty() {
        return Ok(());
    }
    let options = if self_grant {
        "WITH ADMIN OPTION, INHERIT TRUE, SET TRUE"
    } else {
        "WITH ADMIN OPTION"
    };
    Err(InitError::AdminLacksRights {
        user: user.to_owned(),
        missing: missing.join(", "),
        fix: format!("GRANT dbvalet_reader TO {} {options}", quote_ident(user)),
    })
}

async fn reader_rights(
    transaction: &Transaction<'_>,
    self_grant: bool,
) -> Result<ReaderRights, InitError> {
    // Before 16 every member may SET ROLE, so SET has no grant of its own.
    let sql = if self_grant {
        "SELECT pg_has_role('dbvalet_reader', 'MEMBER WITH ADMIN OPTION'),
                pg_has_role('dbvalet_reader', 'USAGE'),
                pg_has_role('dbvalet_reader', 'SET')"
    } else {
        "SELECT pg_has_role('dbvalet_reader', 'MEMBER WITH ADMIN OPTION'),
                pg_has_role('dbvalet_reader', 'USAGE'),
                pg_has_role('dbvalet_reader', 'MEMBER')"
    };
    let row = transaction.query_one(sql, &[]).await.map_err(sql_failed)?;
    Ok(ReaderRights {
        admin: row.get(0),
        inherit: row.get(1),
        set: row.get(2),
    })
}

fn grants_sql(database: &str, schemas: &[String]) -> String {
    let mut sql = format!(
        "GRANT CONNECT ON DATABASE {} TO dbvalet_reader;\n",
        quote_ident(database)
    );
    for schema in schemas {
        let schema = quote_ident(schema);
        sql.push_str(&format!(
            "GRANT USAGE ON SCHEMA {schema} TO dbvalet_reader;
             GRANT SELECT ON ALL TABLES IN SCHEMA {schema} TO dbvalet_reader;
             ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT SELECT ON TABLES TO dbvalet_reader;\n"
        ));
    }
    sql
}

/// A GRANT on someone else's object only warns, so check what the role can actually reach.
async fn check_reach(
    transaction: &Transaction<'_>,
    database: &str,
    schemas: &[String],
) -> Result<Vec<(String, i64)>, InitError> {
    let can_connect: bool = transaction
        .query_one(
            "SELECT has_database_privilege('dbvalet_reader', current_database(), 'CONNECT')",
            &[],
        )
        .await
        .map_err(sql_failed)?
        .get(0);
    if !can_connect {
        return Err(InitError::DatabaseNotGranted {
            database: database.to_owned(),
            quoted: quote_ident(database),
        });
    }
    let mut unreadable_tables = Vec::new();
    for schema in schemas {
        let row = transaction
            .query_one(
                "SELECT has_schema_privilege('dbvalet_reader', n.oid, 'USAGE'),
                        (SELECT count(*)
                         FROM pg_class c
                         WHERE c.relnamespace = n.oid
                           AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                           AND NOT has_table_privilege('dbvalet_reader', c.oid, 'SELECT'))
                 FROM pg_namespace n
                 WHERE n.nspname = $1",
                &[schema],
            )
            .await
            .map_err(sql_failed)?;
        let (usage, unreadable): (bool, i64) = (row.get(0), row.get(1));
        if !usage {
            return Err(InitError::SchemaNotGranted {
                schema: schema.clone(),
                quoted: quote_ident(schema),
            });
        }
        if unreadable > 0 {
            unreadable_tables.push((schema.clone(), unreadable));
        }
    }
    Ok(unreadable_tables)
}

fn sql_failed(err: tokio_postgres::Error) -> InitError {
    InitError::Sql {
        reason: describe_sql_error(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_dbvalet_reader_that_can_log_in_is_refused() {
        let err = refuse_existing_reader(true, GroupRoleStatus::Safe).unwrap_err();
        assert!(matches!(err, InitError::ReaderCanLogin));
    }

    #[test]
    fn a_dangerous_dbvalet_reader_is_refused_as_dangerous_even_when_it_can_log_in() {
        let status = GroupRoleStatus::Dangerous("it has BYPASSRLS".to_owned());
        let err = refuse_existing_reader(true, status).unwrap_err();
        assert_eq!(
            err.to_string(),
            "refusing group role `dbvalet_reader`: it has BYPASSRLS"
        );
    }

    #[test]
    fn a_safe_nologin_dbvalet_reader_is_accepted() {
        assert!(refuse_existing_reader(false, GroupRoleStatus::Safe).is_ok());
    }

    #[test]
    fn the_rights_an_admin_lacks_are_named_in_order() {
        let rights = ReaderRights {
            admin: false,
            inherit: true,
            set: false,
        };
        assert_eq!(rights.missing(), vec!["ADMIN OPTION", "SET"]);
    }

    #[test]
    fn an_admin_holding_every_right_lacks_none() {
        let rights = ReaderRights {
            admin: true,
            inherit: true,
            set: true,
        };
        assert!(rights.missing().is_empty());
    }

    #[test]
    fn the_grants_quote_the_database_and_each_schema() {
        let sql = grants_sql("my db", &["public".to_owned(), "odd\"name".to_owned()]);
        assert!(
            sql.contains("GRANT CONNECT ON DATABASE \"my db\" TO dbvalet_reader;"),
            "{sql}"
        );
        assert!(
            sql.contains("GRANT USAGE ON SCHEMA \"public\" TO dbvalet_reader;"),
            "{sql}"
        );
        assert!(
            sql.contains("GRANT SELECT ON ALL TABLES IN SCHEMA \"odd\"\"name\" TO dbvalet_reader;"),
            "{sql}"
        );
        assert!(
            sql.contains(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA \"odd\"\"name\" \
                 GRANT SELECT ON TABLES TO dbvalet_reader;"
            ),
            "{sql}"
        );
    }
}
