//! Where the database is and how dbvalet may reach it.

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    database: String,
    tls: Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    VerifyFull,
    /// Only ever chosen for a loopback host.
    Plaintext,
}

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("the host name isn't valid")]
    InvalidHost,
    #[error("the database name isn't valid")]
    InvalidDatabase,
    #[error("--allow-plaintext works only for a database on localhost, and `{host}` isn't")]
    PlaintextNotLoopback { host: String },
}

impl Endpoint {
    /// Refuses an invalid host or database, and refuses `allow_plaintext` for a non-loopback host.
    pub fn new(
        host: String,
        port: u16,
        database: String,
        allow_plaintext: bool,
    ) -> Result<Self, EndpointError> {
        if !is_valid_host(&host) {
            return Err(EndpointError::InvalidHost);
        }
        if !is_valid_database(&database) {
            return Err(EndpointError::InvalidDatabase);
        }
        let tls = match allow_plaintext {
            false => Tls::VerifyFull,
            true if is_loopback(&host) => Tls::Plaintext,
            true => return Err(EndpointError::PlaintextNotLoopback { host }),
        };
        Ok(Self {
            host,
            port,
            database,
            tls,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn database(&self) -> &str {
        &self.database
    }

    pub fn tls(&self) -> Tls {
        self.tls
    }
}

pub(crate) fn is_valid_host(host: &str) -> bool {
    !host.is_empty() && (host.parse::<IpAddr>().is_ok() || is_plain_hostname(host))
}

fn is_plain_hostname(host: &str) -> bool {
    const MAX_HOSTNAME_LEN: usize = 253;
    const MAX_LABEL_LEN: usize = 63;

    if host.len() > MAX_HOSTNAME_LEN || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

pub(crate) fn is_valid_database(database: &str) -> bool {
    !database.is_empty()
        && database.chars().all(|c| {
            !c.is_control()
                && !c.is_whitespace()
                && !matches!(c, '@' | '/' | '\\' | '?' | '#' | '\'' | '"' | '\u{FFFD}')
        })
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}/{}", self.host, self.port, self.database)
        } else {
            write!(f, "{}:{}/{}", self.host, self.port, self.database)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_plaintext(host: &str) -> Result<Endpoint, EndpointError> {
        Endpoint::new(host.to_owned(), 5432, "postgres".to_owned(), true)
    }

    #[test]
    fn plaintext_is_allowed_for_localhost_and_loopback_addresses() {
        assert_eq!(with_plaintext("localhost").unwrap().tls(), Tls::Plaintext);
        assert_eq!(with_plaintext("127.0.0.1").unwrap().tls(), Tls::Plaintext);
        assert_eq!(with_plaintext("::1").unwrap().tls(), Tls::Plaintext);
    }

    #[test]
    fn plaintext_is_refused_for_any_other_host() {
        assert!(with_plaintext("db.example.com").is_err());
        assert!(with_plaintext("10.0.0.5").is_err());
        assert!(with_plaintext("localhost.example.com").is_err());
    }

    #[test]
    fn without_allow_plaintext_every_host_needs_verified_tls() {
        let endpoint = Endpoint::new("localhost".to_owned(), 5432, "postgres".to_owned(), false);
        assert_eq!(endpoint.unwrap().tls(), Tls::VerifyFull);
    }

    #[test]
    fn display_brackets_ipv6_addresses_and_leaves_other_hosts_unbracketed() {
        assert_eq!(
            with_plaintext("::1").unwrap().to_string(),
            "[::1]:5432/postgres"
        );
        assert_eq!(
            with_plaintext("localhost").unwrap().to_string(),
            "localhost:5432/postgres"
        );
        assert_eq!(
            with_plaintext("127.0.0.1").unwrap().to_string(),
            "127.0.0.1:5432/postgres"
        );
    }

    #[test]
    fn an_invalid_host_or_database_is_refused_without_printing_it() {
        let bad_host = Endpoint::new(
            "secret-part@localhost".to_owned(),
            5432,
            "postgres".to_owned(),
            true,
        )
        .unwrap_err();
        assert!(!format!("{bad_host}").contains("secret-part"));
        assert!(!format!("{bad_host:?}").contains("secret-part"));

        let bad_db = Endpoint::new(
            "localhost".to_owned(),
            5432,
            "postgres/secret-part".to_owned(),
            true,
        )
        .unwrap_err();
        assert!(!format!("{bad_db}").contains("secret-part"));
        assert!(!format!("{bad_db:?}").contains("secret-part"));
    }
}
