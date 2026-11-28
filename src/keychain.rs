//! The admin login, kept in the OS keychain under a database alias.

use std::sync::Arc;

#[cfg(any(debug_assertions, test))]
use keyring_core::api::{CredentialApi, CredentialStoreApi};
use keyring_core::{CredentialStore, Entry};
use secrecy::{ExposeSecret, SecretString};

use crate::DatabaseAlias;
use crate::endpoint::{Endpoint, EndpointError, Tls, TrustRoot};
use crate::tls::{self, TlsError};

mod connection_string;
use connection_string::parse;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("dbvalet supports macOS and Linux only");

const KEYCHAIN_SERVICE: &str = "dbvalet";
/// In a debug build only, `1` keeps admin logins in memory for one process, so the CLI tests
/// never reach the OS keychain. A release build doesn't contain the code that reads it.
#[cfg(debug_assertions)]
pub const TEST_KEYCHAIN_VAR: &str = "DBVALET_TEST_KEYCHAIN";

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

/// No variant carries any part of the connection string beyond a validated host or CA path.
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
    #[error(transparent)]
    TrustRoot(#[from] TlsError),
}

/// Checks the connection string's format and its `sslrootcert` file, then stores it as typed.
pub fn store(alias: &DatabaseAlias, connection_string: SecretString) -> Result<(), KeychainError> {
    check_for_store(alias, &connection_string)?;
    #[cfg(any(debug_assertions, test))]
    if use_test_keychain() {
        return with_test_credential(alias, |credential| {
            credential.set_password(connection_string.expose_secret())
        });
    }
    entry(alias)?
        .set_password(connection_string.expose_secret())
        .map_err(|err| keyring_failure(alias, err))
}

fn check_for_store(
    alias: &DatabaseAlias,
    connection_string: &SecretString,
) -> Result<(), KeychainError> {
    // Without plaintext every host is accepted, so this checks the format and the CA file only.
    let login = parse(alias, connection_string, false)?;
    if let Tls::VerifyFull(trust_root @ TrustRoot::PemFile(_)) = login.endpoint().tls() {
        tls::client_config(trust_root)?;
    }
    Ok(())
}

pub fn load(alias: &DatabaseAlias, allow_plaintext: bool) -> Result<AdminLogin, KeychainError> {
    let connection_string = stored_connection_string(alias)?;
    parse(alias, &connection_string, allow_plaintext)
}

fn stored_connection_string(alias: &DatabaseAlias) -> Result<SecretString, KeychainError> {
    #[cfg(any(debug_assertions, test))]
    if use_test_keychain() {
        return with_test_credential(alias, |credential| {
            credential.get_password().map(SecretString::from)
        });
    }
    entry(alias)?
        .get_password()
        .map(SecretString::from)
        .map_err(|err| keyring_failure(alias, err))
}

fn entry(alias: &DatabaseAlias) -> Result<Entry, KeychainError> {
    let store = platform_store().map_err(|err| keyring_failure(alias, err))?;
    Entry::new_in_store(&store, KEYCHAIN_SERVICE, alias.as_str())
        .map_err(|err| keyring_failure(alias, err))
}

#[cfg(any(debug_assertions, test))]
fn use_test_keychain() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os(TEST_KEYCHAIN_VAR).is_some_and(|value| value == "1") {
        return true;
    }
    // Unit tests always get the test store, so none can reach the developer's keychain.
    cfg!(test)
}

// Entry's logging formats the mock's raw secret, so use the credential API directly.
#[cfg(any(debug_assertions, test))]
fn with_test_credential<T>(
    alias: &DatabaseAlias,
    operation: impl FnOnce(&dyn CredentialApi) -> keyring_core::Result<T>,
) -> Result<T, KeychainError> {
    static TEST_STORE: std::sync::LazyLock<Arc<keyring_core::mock::Store>> =
        std::sync::LazyLock::new(|| {
            keyring_core::mock::Store::new().expect("creating the mock store never fails")
        });
    let entry = TEST_STORE
        .build(KEYCHAIN_SERVICE, alias.as_str(), None)
        .map_err(|err| keyring_failure(alias, err))?;
    let credential = entry
        .as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
        .expect("the mock store builds mock credentials");
    operation(credential).map_err(|err| keyring_failure(alias, err))
}

#[cfg(target_os = "macos")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(target_os = "linux")]
fn platform_store() -> keyring_core::Result<Arc<CredentialStore>> {
    Ok(dbus_secret_service_keyring_store::Store::new()?)
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

    fn assert_hides_password(err: &KeychainError) {
        assert!(!format!("{err}").contains(PASSWORD), "Display: {err}");
        assert!(!format!("{err:?}").contains(PASSWORD), "Debug: {err:?}");
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
    fn checking_for_store_refuses_an_sslrootcert_file_it_cant_read() {
        let err = check_for_store(
            &alias(),
            &SecretString::from(
                "postgresql://admin:pw-unit-7f3a9c@db.example.com/app\
                 ?sslrootcert=/nonexistent/dbvalet-unit-test/ca.pem",
            ),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(
                "couldn't read the sslrootcert file `/nonexistent/dbvalet-unit-test/ca.pem`"
            ),
            "{err}"
        );
        assert_hides_password(&err);
    }

    #[test]
    fn a_stored_login_loads_back_from_the_test_store_in_the_same_process() {
        let alias: DatabaseAlias = "unit-test-round-trip".parse().unwrap();
        store(
            &alias,
            SecretString::from("postgresql://admin:pw-unit-7f3a9c@localhost:5432/app"),
        )
        .unwrap();

        let login = load(&alias, true).unwrap();
        assert_eq!(login.endpoint().to_string(), "localhost:5432/app");
        assert!(
            login.password().expose_secret() == PASSWORD,
            "stored password did not round-trip"
        );
    }
}
