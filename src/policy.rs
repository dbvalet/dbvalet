//! Which database and role a run uses, decided from `dbvalet.toml` alone.

use crate::DatabaseAlias;
use crate::config::{Config, DatabasePolicy, RoleGrant};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("dbvalet.toml lists no databases")]
    NoDatabases,
    #[error("dbvalet.toml lists more than one database: pass --db with one of {aliases}")]
    DatabaseNotChosen { aliases: String },
    #[error("dbvalet.toml doesn't list a database `{alias}`: it lists {aliases}")]
    UnknownDatabase {
        alias: DatabaseAlias,
        aliases: String,
    },
    #[error("the role `{role}` isn't allowed for `{alias}`: dbvalet.toml allows {allowed}")]
    RoleNotAllowed {
        role: String,
        alias: DatabaseAlias,
        allowed: String,
    },
}

/// Picks the requested database, or the only one listed when none is requested.
pub fn choose_database<'a>(
    config: &'a Config,
    requested: Option<&DatabaseAlias>,
) -> Result<(&'a DatabaseAlias, &'a DatabasePolicy), PolicyError> {
    let databases = &config.databases;
    let aliases = || join(databases.keys().map(DatabaseAlias::as_str));
    match requested {
        Some(alias) => databases
            .get_key_value(alias)
            .ok_or_else(|| PolicyError::UnknownDatabase {
                alias: alias.clone(),
                aliases: aliases(),
            }),
        None if databases.len() > 1 => Err(PolicyError::DatabaseNotChosen { aliases: aliases() }),
        None => databases.iter().next().ok_or(PolicyError::NoDatabases),
    }
}

pub fn choose_role<'a>(
    alias: &DatabaseAlias,
    policy: &'a DatabasePolicy,
    requested: &str,
) -> Result<&'a RoleGrant, PolicyError> {
    policy
        .roles
        .get(requested)
        .ok_or_else(|| PolicyError::RoleNotAllowed {
            role: requested.to_owned(),
            alias: alias.clone(),
            allowed: join(policy.roles.keys().map(String::as_str)),
        })
}

fn join<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let names: Vec<&str> = names.collect();
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_for_test;

    fn alias(name: &str) -> DatabaseAlias {
        name.parse().unwrap()
    }

    const ONE_DATABASE: &str = r#"
        [databases.app.roles]
        reader = { member_of = "dbvalet_reader", read_only = true }
        writer = { member_of = "app_writer", read_only = false }
    "#;

    const TWO_DATABASES: &str = r#"
        [databases.app.roles]
        reader = { member_of = "dbvalet_reader", read_only = true }
        [databases.analytics.roles]
        reader = { member_of = "dbvalet_reader", read_only = true }
    "#;

    #[test]
    fn the_only_database_is_chosen_when_none_is_requested() {
        let config = parse_for_test(ONE_DATABASE);
        let (chosen, _) = choose_database(&config, None).unwrap();
        assert_eq!(chosen, &alias("app"));
    }

    #[test]
    fn two_databases_and_none_requested_is_refused_with_the_aliases() {
        let config = parse_for_test(TWO_DATABASES);
        let err = choose_database(&config, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "dbvalet.toml lists more than one database: pass --db with one of analytics, app"
        );
    }

    #[test]
    fn a_requested_database_is_chosen_among_several() {
        let config = parse_for_test(TWO_DATABASES);
        let (chosen, _) = choose_database(&config, Some(&alias("analytics"))).unwrap();
        assert_eq!(chosen, &alias("analytics"));
    }

    #[test]
    fn an_unlisted_database_is_refused_with_the_aliases() {
        let config = parse_for_test(TWO_DATABASES);
        let err = choose_database(&config, Some(&alias("billing"))).unwrap_err();
        assert_eq!(
            err.to_string(),
            "dbvalet.toml doesn't list a database `billing`: it lists analytics, app"
        );
    }

    #[test]
    fn a_file_without_databases_is_refused() {
        let config = parse_for_test("[databases]");
        let err = choose_database(&config, None).unwrap_err();
        assert_eq!(err.to_string(), "dbvalet.toml lists no databases");
    }

    #[test]
    fn a_listed_role_gives_its_grant() {
        let config = parse_for_test(ONE_DATABASE);
        let (chosen, policy) = choose_database(&config, None).unwrap();
        let grant = choose_role(chosen, policy, "writer").unwrap();
        assert_eq!(
            grant,
            &RoleGrant {
                member_of: "app_writer".to_owned(),
                read_only: false,
            }
        );
    }

    #[test]
    fn an_unlisted_role_is_refused_with_the_allowed_roles() {
        let config = parse_for_test(ONE_DATABASE);
        let (chosen, policy) = choose_database(&config, None).unwrap();
        let err = choose_role(chosen, policy, "admin").unwrap_err();
        assert_eq!(
            err.to_string(),
            "the role `admin` isn't allowed for `app`: dbvalet.toml allows reader, writer"
        );
    }
}
