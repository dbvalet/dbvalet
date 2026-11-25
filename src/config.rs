//! `dbvalet.toml`: the databases a repository uses and the roles each one allows.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::DatabaseAlias;

pub const FILE_NAME: &str = "dbvalet.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub(crate) databases: BTreeMap<DatabaseAlias, DatabasePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabasePolicy {
    pub(crate) roles: BTreeMap<String, RoleGrant>,
}

/// The group role a temporary login joins, and whether its transactions default to read-only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleGrant {
    pub(crate) member_of: String,
    pub(crate) read_only: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no {FILE_NAME} in {} or any directory above it", start.display())]
    NotFound { start: PathBuf },
    #[error("couldn't read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} isn't valid: {message}", path.display())]
    Invalid { path: PathBuf, message: String },
}

/// Loads the nearest `dbvalet.toml`, looking in `start` and then each directory above it.
pub fn find_and_load(start: &Path) -> Result<Config, ConfigError> {
    let path = start
        .ancestors()
        .map(|dir| dir.join(FILE_NAME))
        .find(|path| path.is_file())
        .ok_or_else(|| ConfigError::NotFound {
            start: start.to_owned(),
        })?;
    let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    parse(&text).map_err(|message| ConfigError::Invalid { path, message })
}

fn parse(text: &str) -> Result<Config, String> {
    toml::from_str(text).map_err(|err| err.message().to_owned())
}

#[cfg(test)]
pub(crate) fn parse_for_test(text: &str) -> Config {
    parse(text).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_with_a_reader_role_is_parsed() {
        let config = parse(
            r#"
            [databases.app.roles]
            reader = { member_of = "dbvalet_reader", read_only = true }
            "#,
        )
        .unwrap();
        let app: DatabaseAlias = "app".parse().unwrap();
        assert_eq!(
            config.databases[&app].roles["reader"],
            RoleGrant {
                member_of: "dbvalet_reader".to_owned(),
                read_only: true,
            }
        );
    }

    #[test]
    fn a_role_without_read_only_is_refused() {
        let err = parse(
            r#"
            [databases.app.roles]
            reader = { member_of = "dbvalet_reader" }
            "#,
        )
        .unwrap_err();
        assert!(err.contains("read_only"), "{err}");
    }

    #[test]
    fn a_misspelled_field_is_refused() {
        let err = parse(
            r#"
            [databases.app.roles]
            reader = { member_of = "dbvalet_reader", read_only = true, raed_only = false }
            "#,
        )
        .unwrap_err();
        assert!(err.contains("raed_only"), "{err}");
    }

    #[test]
    fn a_database_alias_with_invalid_characters_is_refused() {
        let err = parse(
            r#"
            [databases."my app".roles]
            reader = { member_of = "dbvalet_reader", read_only = true }
            "#,
        )
        .unwrap_err();
        assert!(err.contains("database alias"), "{err}");
    }
}
