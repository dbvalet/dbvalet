//! The admin login, kept in the OS keychain under a database alias.

use std::sync::Arc;

use keyring_core::{CredentialStore, Entry};
use secrecy::{ExposeSecret, SecretString};

use crate::DatabaseAlias;
use crate::endpoint::{self, Endpoint, EndpointError};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("dbvalet supports macOS and Linux only");

const KEYCHAIN_SERVICE: &str = "dbvalet";
const DEFAULT_PORT: u16 = 5432;

#[cfg(target_os = "linux")]
const UNAVAILABLE_FIX: &str = ": install gnome-keyring, or run dbvalet under dbus-run-session";
#[cfg(target_os = "macos")]
const UNAVAILABLE_FIX: &str = "";

#[derive(Debug)]
pub struct AdminLogin {
    endpoint: Endpoint,
    user: String,
    password: SecretString,
}

impl AdminLogin {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> &SecretString {
        &self.password
    }
}

/// No variant carries any part of the connection string beyond a validated host.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("no admin login is stored for `{alias}`: run `dbvalet login {alias}`")]
    NoEntry { alias: DatabaseAlias },
    #[error(
        "the admin connection string for `{alias}` can't be used: {problem}. \
         Run `dbvalet login {alias}` with one like postgresql://user:password@host:5432/database"
    )]
    BadConnectionString {
        alias: DatabaseAlias,
        problem: &'static str,
    },
    #[error("the keychain entry for `{alias}` can't be read: run `dbvalet login {alias}` again")]
    Unreadable { alias: DatabaseAlias },
    #[error(
        "the keychain holds more than one entry for `{alias}` under `{KEYCHAIN_SERVICE}`: \
         delete the extra ones in your keychain app"
    )]
    Ambiguous { alias: DatabaseAlias },
    #[error("the OS keychain isn't available ({reason}){fix}", fix = UNAVAILABLE_FIX)]
    Unavailable { reason: String },
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
}

/// Checks the connection string's format, then stores it as typed.
pub fn store(alias: &DatabaseAlias, connection_string: SecretString) -> Result<(), KeychainError> {
    // Without plaintext every host is accepted, so this checks the format only.
    parse(alias, &connection_string, false)?;
    entry(alias)?
        .set_password(connection_string.expose_secret())
        .map_err(|err| keyring_failure(alias, err))
}

pub fn load(alias: &DatabaseAlias, allow_plaintext: bool) -> Result<AdminLogin, KeychainError> {
    let connection_string = entry(alias)?
        .get_password()
        .map(SecretString::from)
        .map_err(|err| keyring_failure(alias, err))?;
    parse(alias, &connection_string, allow_plaintext)
}

fn entry(alias: &DatabaseAlias) -> Result<Entry, KeychainError> {
    let store = platform_store().map_err(|err| keyring_failure(alias, err))?;
    Entry::new_in_store(&store, KEYCHAIN_SERVICE, alias.as_str())
        .map_err(|err| keyring_failure(alias, err))
}

#[cfg(target_os = "macos")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(target_os = "linux")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(dbus_secret_service_keyring_store::Store::new()?)
}

/// Every problem is a fixed phrase: parser messages can quote characters of the password.
fn parse(
    alias: &DatabaseAlias,
    connection_string: &SecretString,
    allow_plaintext: bool,
) -> Result<AdminLogin, KeychainError> {
    let bad = |problem| KeychainError::BadConnectionString {
        alias: alias.clone(),
        problem,
    };
    let raw = connection_string.expose_secret();
    if raw.chars().any(|c| c.is_control() || c == '\u{FFFD}') {
        return Err(bad("it contains control or invalid characters"));
    }
    let url_has_userinfo = validate_url(raw).map_err(bad)?;

    let config: tokio_postgres::Config = raw
        .parse()
        .map_err(|_| bad("it isn't a PostgreSQL connection string"))?;

    if url_has_userinfo == Some(false) && config.get_password().is_some() {
        return Err(bad(
            "put the password before `@` (percent-encoded), not as a query parameter",
        ));
    }

    let host = match config.get_hosts() {
        [tokio_postgres::config::Host::Tcp(host)] if !host.is_empty() => host.clone(),
        [tokio_postgres::config::Host::Tcp(_)] | [] => return Err(bad("it names no host")),
        [_] => return Err(bad("a Unix socket isn't supported, name a TCP host")),
        _ => return Err(bad("it names more than one host")),
    };
    if !endpoint::is_valid_host(&host) {
        return Err(bad("its host isn't a valid hostname or IP address"));
    }
    if !config.get_hostaddrs().is_empty() {
        return Err(bad(
            "`hostaddr` isn't supported, name the address as the host",
        ));
    }
    let port = match config.get_ports() {
        [] => DEFAULT_PORT,
        [0] => return Err(bad("its port can't be 0")),
        [port] => *port,
        _ => return Err(bad("it names more than one port")),
    };
    let user = config
        .get_user()
        .filter(|user| !user.is_empty())
        .ok_or_else(|| bad("it names no user"))?;
    let password = config
        .get_password()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| bad("it has no password"))?;
    let password = std::str::from_utf8(password).map_err(|_| bad("its password isn't UTF-8"))?;
    let database = match config.get_dbname() {
        Some("") => return Err(bad("it names an empty database")),
        Some(database) => database,
        None => user,
    };
    if !endpoint::is_valid_database(database) {
        return Err(bad("its database name isn't valid"));
    }

    Ok(AdminLogin {
        endpoint: Endpoint::new(host, port, database.to_owned(), allow_plaintext)?,
        user: user.to_owned(),
        password: SecretString::from(password),
    })
}

/// Checks URL structure before tokio-postgres parses it, because tokio-postgres splits
/// credentials at the first `@` across the whole string. Returns `Some(has_userinfo)` for URLs.
fn validate_url(raw: &str) -> Result<Option<bool>, &'static str> {
    let Some(rest) = raw
        .strip_prefix("postgres://")
        .or_else(|| raw.strip_prefix("postgresql://"))
    else {
        return Ok(None);
    };
    let (before_query, query) = match rest.split_once('?') {
        Some((before, after)) => (before, Some(after)),
        None => (rest, None),
    };
    if let Some(query) = query {
        if query.contains('@') {
            return Err("percent-encode `@` as `%40` in the connection string");
        }
        for pair in query.split('&') {
            if pair
                .split_once('=')
                .is_some_and(|(key, _)| key.eq_ignore_ascii_case("password") || key.contains('%'))
            {
                return Err(
                    "put the password before `@` (percent-encoded), not as a query parameter",
                );
            }
        }
    }
    let at_count = before_query.bytes().filter(|&b| b == b'@').count();
    if at_count > 1 {
        return Err("it has more than one `@`: percent-encode `@` as `%40` in the password");
    }
    if let Some((creds, _)) = before_query.split_once('@') {
        if creds.contains('/') {
            return Err("percent-encode `/` as `%2F` in the user or password");
        }
        return Ok(Some(true));
    }
    Ok(Some(false))
}

/// Drops the payloads of keyring errors that carry the stored secret's bytes.
fn keyring_failure(alias: &DatabaseAlias, err: keyring_core::Error) -> KeychainError {
    let alias = alias.clone();
    match err {
        keyring_core::Error::NoEntry => KeychainError::NoEntry { alias },
        keyring_core::Error::BadEncoding(_) | keyring_core::Error::BadDataFormat(..) => {
            KeychainError::Unreadable { alias }
        }
        keyring_core::Error::Ambiguous(_) => KeychainError::Ambiguous { alias },
        other => KeychainError::Unavailable {
            reason: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "pw-unit-7f3a9c";

    fn alias() -> DatabaseAlias {
        "app".parse().unwrap()
    }

    fn parse_error(connection_string: &str) -> KeychainError {
        parse(&alias(), &SecretString::from(connection_string), true).unwrap_err()
    }

    fn assert_hides_password(err: &KeychainError) {
        assert!(!format!("{err}").contains(PASSWORD), "Display: {err}");
        assert!(!format!("{err:?}").contains(PASSWORD), "Debug: {err:?}");
    }

    #[test]
    fn a_url_connection_string_gives_its_host_port_database_and_user() {
        let login = parse(
            &alias(),
            &SecretString::from("postgresql://admin:pw-unit-7f3a9c@localhost:6543/app_db"),
            true,
        )
        .unwrap();
        assert_eq!(login.endpoint().to_string(), "localhost:6543/app_db");
        assert_eq!(login.user(), "admin");
        assert_eq!(login.password().expose_secret(), PASSWORD);
    }

    #[test]
    fn a_key_value_connection_string_defaults_the_port_and_the_database() {
        let login = parse(
            &alias(),
            &SecretString::from("host=127.0.0.1 user=admin password=pw-unit-7f3a9c"),
            true,
        )
        .unwrap();
        assert_eq!(login.endpoint().to_string(), "127.0.0.1:5432/admin");
    }

    #[test]
    fn an_admin_login_debug_output_hides_the_password() {
        let login = parse(
            &alias(),
            &SecretString::from("postgresql://admin:pw-unit-7f3a9c@localhost/postgres"),
            true,
        )
        .unwrap();
        assert!(!format!("{login:?}").contains(PASSWORD));
    }

    #[test]
    fn no_connection_string_error_shows_the_password() {
        assert_hides_password(&parse_error(
            "postgresql://admin:pw-unit-7f3a9c@localhost:x/db",
        ));
        assert_hides_password(&parse_error("host=localhost password='pw-unit-7f3a9c"));
        assert_hides_password(&parse_error("host=localhost password=pw-unit-7f3a9c bad"));
        assert_hides_password(&parse_error("postgresql://admin:pw-unit-7f3a9c@/db"));
        assert_hides_password(&parse_error("postgresql://admin:pw-unit-7f3a9c@one,two/db"));
        assert_hides_password(&parse_error("postgresql://admin:pw-unit-7f3a9c@%2Ftmp/db"));
        assert_hides_password(&parse_error("host=localhost password=pw-unit-7f3a9c"));
        assert_hides_password(&parse_error(
            "postgresql://admin:pw-unit-7f3a9c@db.example.com/db",
        ));
    }

    #[test]
    fn no_keychain_error_shows_the_password() {
        assert_hides_password(&keyring_failure(
            &alias(),
            keyring_core::Error::BadEncoding(PASSWORD.as_bytes().to_vec()),
        ));
        assert_hides_password(&keyring_failure(
            &alias(),
            keyring_core::Error::BadDataFormat(
                PASSWORD.as_bytes().to_vec(),
                PASSWORD.to_owned().into(),
            ),
        ));
    }

    #[test]
    fn a_connection_string_without_a_password_is_refused() {
        assert!(matches!(
            parse_error("postgresql://admin@localhost/postgres"),
            KeychainError::BadConnectionString { .. }
        ));
    }

    #[test]
    fn an_empty_host_user_password_or_database_is_refused() {
        let empty_host = parse_error("postgresql://admin:pw-unit-7f3a9c@:5432/postgres");
        assert!(matches!(
            empty_host,
            KeychainError::BadConnectionString {
                problem: "it names no host",
                ..
            }
        ));
        assert_hides_password(&empty_host);

        let empty_user = parse_error("postgresql://:pw-unit-7f3a9c@localhost:5432/postgres");
        assert!(matches!(
            empty_user,
            KeychainError::BadConnectionString {
                problem: "it names no user",
                ..
            }
        ));
        assert_hides_password(&empty_user);

        let empty_password = parse_error("postgresql://admin:@localhost:5432/postgres");
        assert!(matches!(
            empty_password,
            KeychainError::BadConnectionString {
                problem: "it has no password",
                ..
            }
        ));

        let empty_database =
            parse_error("host=localhost dbname='' user=admin password=pw-unit-7f3a9c");
        assert!(matches!(
            empty_database,
            KeychainError::BadConnectionString {
                problem: "it names an empty database",
                ..
            }
        ));
        assert_hides_password(&empty_database);
    }

    #[test]
    fn port_zero_and_multiple_ports_are_refused() {
        let port_zero = parse_error("postgresql://admin:pw-unit-7f3a9c@localhost:0/postgres");
        assert!(matches!(
            port_zero,
            KeychainError::BadConnectionString {
                problem: "its port can't be 0",
                ..
            }
        ));
        assert_hides_password(&port_zero);

        let multiple_ports =
            parse_error("host=localhost port=5432,5433 user=admin password=pw-unit-7f3a9c");
        assert!(matches!(
            multiple_ports,
            KeychainError::BadConnectionString {
                problem: "it names more than one port",
                ..
            }
        ));
        assert_hides_password(&multiple_ports);
    }

    #[test]
    fn a_password_with_an_unencoded_at_sign_is_refused_without_printing_it() {
        let err = parse_error("postgresql://admin:se@pw-unit-7f3a9c@localhost:5432/postgres");
        assert!(matches!(err, KeychainError::BadConnectionString { .. }));
        assert_hides_password(&err);
    }

    #[test]
    fn a_password_with_an_unencoded_at_and_slash_is_refused_without_printing_it() {
        let err = parse_error("postgresql://admin:se@thr/pw-unit-7f3a9c@localhost:5432/postgres");
        assert!(matches!(err, KeychainError::BadConnectionString { .. }));
        assert_hides_password(&err);
    }

    #[test]
    fn a_password_in_a_url_query_parameter_is_refused_without_printing_it() {
        let with_at = parse_error(
            "postgresql://localhost:5432/postgres?user=admin&password=pw-unit-7f3a9c@x",
        );
        assert!(matches!(with_at, KeychainError::BadConnectionString { .. }));
        assert_hides_password(&with_at);

        let plain =
            parse_error("postgresql://localhost:5432/postgres?user=admin&password=pw-unit-7f3a9c");
        assert!(matches!(plain, KeychainError::BadConnectionString { .. }));
        assert_hides_password(&plain);
    }

    #[test]
    fn a_host_or_database_with_invalid_characters_is_refused() {
        let bad_host = parse_error("host='bad host' user=admin password=pw-unit-7f3a9c");
        assert!(matches!(
            bad_host,
            KeychainError::BadConnectionString { .. }
        ));
        assert_hides_password(&bad_host);

        let slash_db =
            parse_error("host=localhost dbname='bad/db' user=admin password=pw-unit-7f3a9c");
        assert!(matches!(
            slash_db,
            KeychainError::BadConnectionString { .. }
        ));
        assert_hides_password(&slash_db);

        let newline_db = parse_error(
            "host=localhost dbname='postgres\nsecond' user=admin password=pw-unit-7f3a9c",
        );
        assert!(matches!(
            newline_db,
            KeychainError::BadConnectionString { .. }
        ));
        assert_hides_password(&newline_db);
    }

    #[test]
    fn a_connection_string_containing_a_replacement_character_is_refused() {
        let err = parse_error("postgresql://admin:pw-unit-7f3a9c\u{FFFD}@localhost:5432/postgres");
        assert!(matches!(err, KeychainError::BadConnectionString { .. }));
        assert_hides_password(&err);
    }

    #[test]
    fn percent_encoded_at_and_slash_in_a_password_are_accepted() {
        let login = parse(
            &alias(),
            &SecretString::from("postgresql://admin:se%40cr%2Fet@localhost:5432/postgres"),
            true,
        )
        .unwrap();
        assert_eq!(login.endpoint().to_string(), "localhost:5432/postgres");
        assert_eq!(login.password().expose_secret(), "se@cr/et");
    }
}
