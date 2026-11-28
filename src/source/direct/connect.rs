//! Opens the admin connection and words its failures.

use std::io;

use secrecy::ExposeSecret;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls};

use super::{ADMIN_CONNECT_TIMEOUT, describe_sql_error, quote_ident};
use crate::DatabaseAlias;
use crate::endpoint::{ChannelBinding, Tls};
use crate::keychain::AdminLogin;
use crate::tls;

/// So a lock someone else holds on what a login owns fails that drop instead of stalling it.
const ADMIN_LOCK_TIMEOUT: &str = "10s";

pub(super) async fn connect(alias: &DatabaseAlias, admin: &AdminLogin) -> Result<Client, String> {
    connect_with_cancel_tls(alias, admin)
        .await
        .map(|(client, _)| client)
}

pub(super) async fn connect_with_cancel_tls(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
) -> Result<(Client, Option<tls::MakeRustlsConnect>), String> {
    let endpoint = admin.endpoint();
    let mut config = tokio_postgres::Config::new();
    config
        .port(endpoint.port())
        .dbname(endpoint.database())
        .user(admin.user())
        .password(admin.password().expose_secret())
        .channel_binding(match endpoint.channel_binding() {
            ChannelBinding::Disable => tokio_postgres::config::ChannelBinding::Disable,
            ChannelBinding::Prefer => tokio_postgres::config::ChannelBinding::Prefer,
            ChannelBinding::Require => tokio_postgres::config::ChannelBinding::Require,
        });
    let connecting = async {
        let (client, cancel_tls) = match endpoint.tls() {
            Tls::Plaintext => {
                config.ssl_mode(SslMode::Disable);
                // Like the proxy, move on only when nothing listens, so both reach one server.
                let mut refused = None;
                let mut connected = None;
                for host in endpoint.dial_hosts() {
                    let mut attempt = config.clone();
                    attempt.host(host);
                    match attempt.connect(NoTls).await {
                        Ok(pair) => {
                            connected = Some(pair);
                            break;
                        }
                        Err(err) if nothing_listens(&err) => {
                            refused.get_or_insert(err);
                        }
                        Err(err) => return Err(describe_connect_error(alias, admin, &err)),
                    }
                }
                let (client, connection) = connected.ok_or_else(|| {
                    let err = refused.expect("dial_hosts is never empty");
                    describe_connect_error(alias, admin, &err)
                })?;
                tokio::spawn(connection);
                (client, None)
            }
            Tls::VerifyFull(trust_root) => {
                // Always Require (never Prefer), so tokio-postgres can never downgrade to plaintext.
                config.host(endpoint.host()).ssl_mode(SslMode::Require);
                let tls_config = tls::client_config(trust_root).map_err(|err| err.to_string())?;
                let tls = tls::MakeRustlsConnect::new(tls_config);
                let (client, connection) = config
                    .connect(tls.clone())
                    .await
                    .map_err(|err| describe_connect_error(alias, admin, &err))?;
                tokio::spawn(connection);
                (client, Some(tls))
            }
        };
        client
            .batch_execute(&format!("SET lock_timeout = '{ADMIN_LOCK_TIMEOUT}'"))
            .await
            .map_err(|err| describe_sql_error(&err))?;
        Ok((client, cancel_tls))
    };
    tokio::time::timeout(ADMIN_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            format!(
                "no answer within {} s: check that the host and port in \
                 `dbvalet login {alias}` are a PostgreSQL server's",
                ADMIN_CONNECT_TIMEOUT.as_secs()
            )
        })?
}

/// Never prints the server's raw error text, because it can quote input fields.
fn describe_connect_error(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
    err: &tokio_postgres::Error,
) -> String {
    if let Some(db) = err.as_db_error() {
        return describe_db_connect_error(alias, admin.user(), db.code(), db.message());
    }
    if let Some(tls_reason) = tls::describe_error_chain(admin.endpoint(), err) {
        return tls_reason;
    }
    if let Some(io_err) = find_io_error(err) {
        return format!(
            "{io_err}: check that PostgreSQL is running and reachable, \
             or run `dbvalet login {alias}` with the right host and port"
        );
    }
    format!(
        "couldn't establish a PostgreSQL session: check that PostgreSQL is running, \
         or run `dbvalet login {alias}` again"
    )
}

fn describe_db_connect_error(
    alias: &DatabaseAlias,
    user: &str,
    code: &SqlState,
    server_message: &str,
) -> String {
    let quoted = quote_ident(user);
    if *code == SqlState::INVALID_PASSWORD {
        return format!(
            "password authentication failed: run `dbvalet login {alias}` again with the \
             right password, or as a superuser run ALTER ROLE {quoted} VALID UNTIL 'infinity'"
        );
    }
    if *code == SqlState::INVALID_AUTHORIZATION_SPECIFICATION {
        if server_message.contains("not permitted to log in") {
            return format!(
                "role isn't permitted to log in: as a superuser, run ALTER ROLE {quoted} LOGIN"
            );
        }
        if server_message.contains("does not exist") {
            return format!(
                "role doesn't exist: check the user name and run `dbvalet login {alias}` again"
            );
        }
        return format!(
            "the server rejected the login (SQLSTATE {}): check pg_hba.conf or run \
             `dbvalet login {alias}` again",
            code.code()
        );
    }
    if *code == SqlState::INVALID_CATALOG_NAME {
        return format!(
            "database doesn't exist: run `dbvalet login {alias}` with an existing database \
             in the connection string (when omitted, it defaults to the user name)"
        );
    }
    format!(
        "the server refused the connection (SQLSTATE {}): check the server logs or run \
         `dbvalet login {alias}` again",
        code.code()
    )
}

fn nothing_listens(err: &tokio_postgres::Error) -> bool {
    find_io_error(err).is_some_and(|io_err| {
        matches!(
            io_err.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::AddrNotAvailable
        )
    })
}

fn find_io_error<'a>(err: &'a (dyn std::error::Error + 'static)) -> Option<&'a io::Error> {
    let mut current = err.source();
    while let Some(source) = current {
        if let Some(io_err) = source.downcast_ref::<io::Error>() {
            return Some(io_err);
        }
        current = source.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias() -> DatabaseAlias {
        "app".parse().unwrap()
    }

    #[test]
    fn connect_errors_name_fixes_without_echoing_raw_server_text() {
        let wrong_pw = describe_db_connect_error(
            &alias(),
            "admin",
            &SqlState::INVALID_PASSWORD,
            "password authentication failed for user \"leaked-raw\"",
        );
        assert!(wrong_pw.contains("dbvalet login app"));
        assert!(wrong_pw.contains("ALTER ROLE \"admin\" VALID UNTIL 'infinity'"));
        assert!(!wrong_pw.contains("leaked-raw"));

        let nologin = describe_db_connect_error(
            &alias(),
            "admin",
            &SqlState::INVALID_AUTHORIZATION_SPECIFICATION,
            "role \"leaked-raw\" is not permitted to log in",
        );
        assert!(nologin.contains("ALTER ROLE \"admin\" LOGIN"));
        assert!(!nologin.contains("leaked-raw"));

        let missing_db = describe_db_connect_error(
            &alias(),
            "admin",
            &SqlState::INVALID_CATALOG_NAME,
            "database \"leaked-raw\" does not exist",
        );
        assert!(missing_db.contains("dbvalet login app"));
        assert!(missing_db.contains("defaults to the user name"));
        assert!(!missing_db.contains("leaked-raw"));
    }
}
