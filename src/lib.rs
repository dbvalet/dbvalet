//! Temporary PostgreSQL logins for AI coding agents, behind a local proxy.

use std::fmt;
use std::str::FromStr;

pub mod cli;
pub mod endpoint;
pub mod keychain;
pub mod source;

/// A database's name in `dbvalet.toml` and in the keychain, such as `app`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DatabaseAlias(String);

#[derive(Debug, thiserror::Error)]
#[error(
    "a database alias uses only letters, digits, `_` and `-`, and can't start with `-`, like `app`"
)]
pub struct InvalidAlias;

impl DatabaseAlias {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DatabaseAlias {
    type Err = InvalidAlias;

    fn from_str(alias: &str) -> Result<Self, Self::Err> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
        if alias.is_empty() || alias.starts_with('-') || !alias.chars().all(allowed) {
            return Err(InvalidAlias);
        }
        Ok(Self(alias.to_owned()))
    }
}

impl fmt::Display for DatabaseAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_alias_of_letters_digits_underscores_and_dashes_is_accepted() {
        assert_eq!(
            "app_2-eu".parse::<DatabaseAlias>().unwrap().as_str(),
            "app_2-eu"
        );
    }

    #[test]
    fn an_empty_alias_or_one_with_other_characters_is_refused() {
        assert!("".parse::<DatabaseAlias>().is_err());
        assert!("-app".parse::<DatabaseAlias>().is_err());
        assert!("my app".parse::<DatabaseAlias>().is_err());
        assert!("../app".parse::<DatabaseAlias>().is_err());
    }
}
