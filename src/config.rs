//! `dbvalet.toml`: the databases a repository uses and the roles each one allows.

use std::collections::BTreeMap;
use std::io;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::DatabaseAlias;

pub const FILE_NAME: &str = "dbvalet.toml";
const SECONDS_PER_MINUTE: u64 = 60;
/// Eight hours: a working day, after which a run loses database access.
const INIT_MAX_TTL_MINUTES: u64 = 480;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub(crate) databases: BTreeMap<DatabaseAlias, DatabasePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabasePolicy {
    #[serde(default)]
    pub(crate) max_ttl_minutes: Option<NonZeroU64>,
    pub(crate) roles: BTreeMap<String, RoleGrant>,
}

impl DatabasePolicy {
    pub fn max_ttl(&self) -> Option<Duration> {
        self.max_ttl_minutes
            .map(|minutes| Duration::from_secs(minutes.get().saturating_mul(SECONDS_PER_MINUTE)))
    }
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
    #[error("couldn't create {}", path.display())]
    Create {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Loads the nearest `dbvalet.toml`, looking in `start` and then each directory above it.
pub fn find_and_load(start: &Path) -> Result<Config, ConfigError> {
    let path = find(start).ok_or_else(|| ConfigError::NotFound {
        start: start.to_owned(),
    })?;
    let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    parse(&text).map_err(|message| ConfigError::Invalid { path, message })
}

/// The nearest `dbvalet.toml`, in `start` or a directory above it.
pub fn find(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|dir| dir.join(FILE_NAME))
        .find(|path| path.is_file())
}

/// The entry `dbvalet init` writes: a read-only `reader` role joining `dbvalet_reader`.
pub fn reader_entry(alias: &DatabaseAlias) -> String {
    format!(
        "[databases.{alias}]\n\
         max_ttl_minutes = {INIT_MAX_TTL_MINUTES}\n\
         \n\
         [databases.{alias}.roles]\n\
         reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n"
    )
}

/// Creates `dbvalet.toml` in `dir` holding `text`, failing with `AlreadyExists` rather than
/// replacing one. The file appears whole: a draft is written first, then hard-linked into place.
pub fn create(dir: &Path, text: &str) -> Result<PathBuf, ConfigError> {
    let path = dir.join(FILE_NAME);
    let draft = dir.join(format!(".{FILE_NAME}.{}.draft", std::process::id()));
    let created = std::fs::write(&draft, text).and_then(|()| std::fs::hard_link(&draft, &path));
    let _ = std::fs::remove_file(&draft);
    created.map_err(|source| ConfigError::Create {
        path: path.clone(),
        source,
    })?;
    Ok(path)
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

    #[test]
    fn a_database_with_max_ttl_minutes_is_parsed() {
        let config = parse(
            r#"
            [databases.app]
            max_ttl_minutes = 480

            [databases.app.roles]
            reader = { member_of = "dbvalet_reader", read_only = true }
            "#,
        )
        .unwrap();
        let app: DatabaseAlias = "app".parse().unwrap();
        assert_eq!(
            config.databases[&app].max_ttl(),
            Some(std::time::Duration::from_secs(480 * 60))
        );
    }

    #[test]
    fn the_entry_init_writes_parses_as_a_read_only_reader_for_eight_hours() {
        let app: DatabaseAlias = "app".parse().unwrap();
        let config = parse(&reader_entry(&app)).unwrap();
        assert_eq!(
            config.databases[&app].max_ttl(),
            Some(std::time::Duration::from_secs(480 * 60))
        );
        assert_eq!(
            config.databases[&app].roles["reader"],
            RoleGrant {
                member_of: "dbvalet_reader".to_owned(),
                read_only: true,
            }
        );
    }

    #[test]
    fn creating_the_file_where_one_exists_fails_and_leaves_it_unchanged() {
        let dir = std::env::temp_dir().join(format!("dbvalet-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(FILE_NAME), "# hand-written\n").unwrap();

        let err = create(&dir, "[databases.app]\n").unwrap_err();

        let kind = match err {
            ConfigError::Create { source, .. } => source.kind(),
            other => panic!("{other}"),
        };
        assert_eq!(kind, io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(dir.join(FILE_NAME)).unwrap(),
            "# hand-written\n"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_zero_max_ttl_minutes_is_refused() {
        let err = parse(
            r#"
            [databases.app]
            max_ttl_minutes = 0

            [databases.app.roles]
            reader = { member_of = "dbvalet_reader", read_only = true }
            "#,
        )
        .unwrap_err();
        assert!(err.contains("nonzero"), "{err}");
    }
}
