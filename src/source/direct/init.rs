//! `dbvalet init`: the read-only group role and its grants, over admin SQL.

use tokio_postgres::Transaction;

use super::{
    CREATEROLE_SELF_GRANT_VERSION_NUM, MINIMUM_SERVER_VERSION_NUM, connect, describe_sql_error,
    quote_ident,
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

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("can't connect as the admin login for `{alias}`: {reason}")]
    Connect {
        alias: DatabaseAlias,
        reason: String,
    },
    #[error("PostgreSQL {version} is end-of-life: dbvalet needs 15 or later")]
    TooOld { version: String },
    #[error(
        "`{user}` doesn't hold ADMIN OPTION on the existing role dbvalet_reader, and only a \
         superuser can give it on PostgreSQL 16 and later: ask one to run GRANT dbvalet_reader \
         TO {quoted} WITH ADMIN OPTION, INHERIT TRUE, SET TRUE"
    )]
    NoAdminOption { user: String, quoted: String },
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
    let server = client
        .query_one(
            "SELECT current_setting('server_version'),
                    current_setting('server_version_num')::int,
                    current_database()::text",
            &[],
        )
        .await
        .map_err(sql_failed)?;
    let (version, version_num, database): (String, i32, String) =
        (server.get(0), server.get(1), server.get(2));
    if version_num < MINIMUM_SERVER_VERSION_NUM {
        return Err(InitError::TooOld { version });
    }

    // One transaction, so a failure leaves the database as it was.
    let transaction = client.transaction().await.map_err(sql_failed)?;
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
    grant_reader_to_admin(&transaction, admin.user(), version_num).await?;
    transaction
        .batch_execute(&grants_sql(&database, schemas))
        .await
        .map_err(sql_failed)?;
    let unreadable_tables = check_schemas(&transaction, schemas).await?;
    transaction.commit().await.map_err(sql_failed)?;
    Ok(InitReport {
        database,
        unreadable_tables,
    })
}

/// The admin needs ADMIN to add logins to the role, INHERIT to drop what they own, and, on 16+,
/// SET to reassign it. Grants only what's missing, so a second run adds no membership.
async fn grant_reader_to_admin(
    transaction: &Transaction<'_>,
    user: &str,
    version_num: i32,
) -> Result<(), InitError> {
    let (has_admin, has_inherit_and_set): (bool, bool) = if version_num
        >= CREATEROLE_SELF_GRANT_VERSION_NUM
    {
        let row = transaction
            .query_one(
                "SELECT pg_has_role('dbvalet_reader', 'MEMBER WITH ADMIN OPTION'),
                        pg_has_role('dbvalet_reader', 'USAGE') AND pg_has_role('dbvalet_reader', 'SET')",
                &[],
            )
            .await
            .map_err(sql_failed)?;
        (row.get(0), row.get(1))
    } else {
        // Before 16 INHERIT is the admin's own attribute, which mint checks, and SET has no
        // separate grant.
        let row = transaction
            .query_one(
                "SELECT pg_has_role('dbvalet_reader', 'MEMBER WITH ADMIN OPTION')",
                &[],
            )
            .await
            .map_err(sql_failed)?;
        (row.get(0), true)
    };
    let quoted = quote_ident(user);
    let grant = match (has_admin, has_inherit_and_set) {
        (true, true) => return Ok(()),
        // Before 16 CREATEROLE may grant any non-superuser role, including to itself.
        (false, _) if version_num < CREATEROLE_SELF_GRANT_VERSION_NUM => {
            format!("GRANT dbvalet_reader TO {quoted} WITH ADMIN OPTION")
        }
        (false, _) => {
            return Err(InitError::NoAdminOption {
                user: user.to_owned(),
                quoted,
            });
        }
        // PostgreSQL refuses ADMIN OPTION granted back to its own grantor, so ask for the rest.
        (true, false) => format!("GRANT dbvalet_reader TO {quoted} WITH INHERIT TRUE, SET TRUE"),
    };
    transaction.batch_execute(&grant).await.map_err(sql_failed)
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
async fn check_schemas(
    transaction: &Transaction<'_>,
    schemas: &[String],
) -> Result<Vec<(String, i64)>, InitError> {
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
