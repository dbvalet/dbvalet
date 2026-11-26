//! Temporary PostgreSQL logins for AI coding agents, behind a local proxy.

use std::fmt;
use std::str::FromStr;

use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};

pub mod cli;
pub mod config;
pub mod endpoint;
pub mod keychain;
pub mod ledger;
pub mod policy;
pub mod proxy;
pub mod run;
pub mod source;

/// Every temporary login's name starts with this.
pub(crate) const LOGIN_PREFIX: &str = "dbvalet_";
/// 80 random bits, written as the 16 base32 characters after [`LOGIN_PREFIX`].
pub(crate) const RUN_ID_BYTES: usize = 10;
const RUN_ID_CHARS: usize = RUN_ID_BYTES * 8 / 5;

/// Whether `name` is a temporary login's name: `^dbvalet_[a-z2-7]{16}$`.
pub(crate) fn is_login_name(name: &str) -> bool {
    name.strip_prefix(LOGIN_PREFIX).is_some_and(|run_id| {
        run_id.len() == RUN_ID_CHARS
            && run_id
                .bytes()
                .all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7'))
    })
}

/// Lowercase RFC 4648 base32: safe in an unquoted SQL identifier, a URL and an environment value.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const BASE32_BITS: u32 = 5;

/// `bytes` random bytes from the OS, encoded as lowercase base32 and held as a secret.
/// `bytes` must be a multiple of 5, so the encoding needs no padding.
pub(crate) fn random_base32(bytes: usize) -> Result<SecretString, getrandom::Error> {
    assert_eq!(bytes % 5, 0, "random_base32 takes a multiple of 5 bytes");
    let mut random: SecretSlice<u8> = vec![0; bytes].into();
    getrandom::fill(random.expose_secret_mut())?;
    let mut encoded = String::with_capacity(bytes * 8 / 5);
    let (mut buffer, mut buffered_bits) = (0u16, 0u32);
    for &byte in random.expose_secret() {
        buffer = (buffer << 8) | u16::from(byte);
        buffered_bits += 8;
        while buffered_bits >= BASE32_BITS {
            buffered_bits -= BASE32_BITS;
            encoded.push(char::from(
                BASE32_ALPHABET[usize::from((buffer >> buffered_bits) & 31)],
            ));
        }
    }
    Ok(SecretString::from(encoded))
}

/// A database's name in `dbvalet.toml` and in the keychain, such as `app`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(try_from = "String")]
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

impl TryFrom<String> for DatabaseAlias {
    type Error = InvalidAlias;

    fn try_from(alias: String) -> Result<Self, Self::Error> {
        alias.parse()
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
    fn random_base32_gives_eight_lowercase_base32_characters_per_five_bytes() {
        let encoded = random_base32(10).unwrap();
        let encoded = encoded.expose_secret();
        assert_eq!(encoded.len(), 16);
        assert!(
            encoded.bytes().all(|c| BASE32_ALPHABET.contains(&c)),
            "{encoded}"
        );
    }

    #[test]
    fn two_random_base32_values_differ() {
        assert_ne!(
            random_base32(20).unwrap().expose_secret(),
            random_base32(20).unwrap().expose_secret()
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
