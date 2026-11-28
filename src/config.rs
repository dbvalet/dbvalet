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

/// The most drafts `create` tries when leftovers of interrupted runs hold the first names.
const DRAFT_ATTEMPTS: u32 = 16;

/// Creates the file `path` holding `text`, failing with `AlreadyExists` rather than replacing
/// anything there. The file appears whole: a draft of our own is written, then hard-linked.
pub fn create(path: &Path, text: &str) -> io::Result<()> {
    let mut attempt = 0;
    let (draft, mut file) = loop {
        let draft = path.with_extension(format!("toml.{}.{attempt}.draft", std::process::id()));
        // create_new never opens an existing file, so a leftover draft, or a symlink, is skipped.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&draft)
        {
            Ok(file) => break (draft, file),
            Err(err)
                if err.kind() == io::ErrorKind::AlreadyExists && attempt + 1 < DRAFT_ATTEMPTS =>
            {
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    };
    let created = io::Write::write_all(&mut file, text.as_bytes())
        .and_then(|()| std::fs::hard_link(&draft, path));
    let _ = std::fs::remove_file(&draft);
    created
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
        let path = dir.join(FILE_NAME);
        std::fs::write(&path, "# hand-written\n").unwrap();

        let err = create(&path, "[databases.app]\n").unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# hand-written\n");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn creating_the_file_skips_a_leftover_draft_without_changing_it() {
        let dir = std::env::temp_dir().join(format!("dbvalet-draft-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE_NAME);
        let leftover = dir.join(format!("dbvalet.toml.{}.0.draft", std::process::id()));
        std::fs::write(&leftover, "# a backup the leftover draft still links to\n").unwrap();

        create(&path, "[databases.app]\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[databases.app]\n");
        assert_eq!(
            std::fs::read_to_string(&leftover).unwrap(),
            "# a backup the leftover draft still links to\n"
        );
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
