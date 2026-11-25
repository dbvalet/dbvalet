//! One run: a temporary login, the proxy in front of it, and the child behind the proxy.

use std::ffi::OsString;
use std::io;
use std::process::ExitStatus;

use secrecy::{ExposeSecret, SecretString};

use crate::config::RoleGrant;
use crate::endpoint::Endpoint;
use crate::proxy::{self, ProxyError};
use crate::random_base32;
use crate::source::{CredentialSource, SourceError, UpstreamLogin};

const RUN_TOKEN_BYTES: usize = 20;
const PROXY_HOST: &str = "127.0.0.1";

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    #[error("couldn't start `{program}`")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
    #[error("couldn't wait for the command to exit")]
    Wait(#[source] io::Error),
    #[error("the OS random number generator failed")]
    Random(#[source] getrandom::Error),
}

/// Runs `command` against a new temporary login through the proxy, then drops the login.
/// A failure to drop it is printed, and the command's exit status is still returned.
pub async fn run<S: CredentialSource>(
    source: &S,
    grant: &RoleGrant,
    upstream: Endpoint,
    command: &[OsString],
) -> Result<ExitStatus, RunError> {
    assert!(!command.is_empty(), "run needs a command");
    let lease = source.mint(grant).await?;
    let finished = run_child(lease.login(), upstream, command).await;
    if let Err(err) = lease.release().await {
        eprintln!("dbvalet: {err}");
    }
    finished
}

async fn run_child(
    login: &UpstreamLogin,
    upstream: Endpoint,
    command: &[OsString],
) -> Result<ExitStatus, RunError> {
    let token = random_base32(RUN_TOKEN_BYTES).map_err(RunError::Random)?;
    let database = upstream.database().to_owned();
    let proxy = proxy::start(upstream, login.clone(), token.clone()).await?;
    let mut child = child_command(command, login.user(), &token, proxy.port(), &database);
    let finished = match child.spawn() {
        Ok(mut running) => running.wait().await.map_err(RunError::Wait),
        Err(source) => Err(RunError::Spawn {
            program: command[0].to_string_lossy().into_owned(),
            source,
        }),
    };
    proxy.stop().await;
    finished
}

/// The child inherits dbvalet's environment minus every `PG*` variable and `DATABASE_URL`,
/// then gets the proxy's address and the run token, never the login's password.
fn child_command(
    command: &[OsString],
    user: &str,
    token: &SecretString,
    port: u16,
    database: &str,
) -> tokio::process::Command {
    let (program, args) = command.split_first().expect("the CLI requires a command");
    let mut child = tokio::process::Command::new(program);
    child.args(args);
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"PG") || name == "DATABASE_URL" {
            child.env_remove(name);
        }
    }
    let token = token.expose_secret();
    let port = port.to_string();
    child
        .env("PGHOST", PROXY_HOST)
        .env("PGPORT", &port)
        .env("PGUSER", user)
        .env("PGPASSWORD", token)
        .env("PGDATABASE", database)
        .env("PGSSLMODE", "disable")
        .env(
            "DATABASE_URL",
            format!(
                "postgresql://{}:{token}@{PROXY_HOST}:{port}/{}?sslmode=disable",
                url_encoded(user),
                url_encoded(database)
            ),
        );
    child
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
fn url_encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_name_is_percent_encoded_for_the_url() {
        assert_eq!(url_encoded("app_db-1.x~"), "app_db-1.x~");
        assert_eq!(url_encoded("a%b:c&d"), "a%25b%3Ac%26d");
    }
}
