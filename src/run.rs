//! One run: a temporary login, the proxy in front of it, and the child behind the proxy.

use std::ffi::OsString;
use std::io::{self, Write};
use std::time::{Duration, SystemTime};

use secrecy::{ExposeSecret, SecretString};

use crate::DatabaseAlias;
use crate::config::RoleGrant;
use crate::endpoint::Endpoint;
use crate::proxy::{self, ProxyError};
use crate::random_base32;
use crate::runlog::{self, RunHeader, RunLogError, RunSecrets};
use crate::signals::{self, RunSignals, SIGNAL_WAIT_TIMEOUT, WaitOutcome};
use crate::source::{CredentialSource, Lease, MintOutcome, SourceError};

const RUN_TOKEN_BYTES: usize = 20;
const PROXY_HOST: &str = "127.0.0.1";

/// Policy and logging inputs for one run.
#[derive(Debug)]
pub struct RunOptions<'a> {
    pub database: &'a DatabaseAlias,
    pub role: &'a str,
    pub grant: &'a RoleGrant,
    pub max_ttl: Duration,
    pub sql_log: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    #[error(transparent)]
    RunLog(#[from] RunLogError),
    #[error("couldn't install signal handlers")]
    Signals(#[source] io::Error),
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

/// Sweeps what earlier runs left, runs `command` against a new temporary login through the
/// proxy, then drops the login. At `max_ttl` the lease drops it while `command` keeps running.
/// A failure to drop it is printed, and the command's exit status is still returned.
pub async fn run<S: CredentialSource>(
    source: &S,
    options: &RunOptions<'_>,
    upstream: Endpoint,
    command: &[OsString],
) -> Result<WaitOutcome, RunError> {
    assert!(!command.is_empty(), "run needs a command");
    for err in source.sweep().await?.failures {
        let _ = writeln!(io::stderr(), "dbvalet: {err}");
    }
    // Install signal handlers before minting so SIGINT, SIGTERM or SIGHUP can't kill
    // dbvalet while CREATE ROLE is in flight and release the ledger lock early.
    let mut signals = RunSignals::install().map_err(RunError::Signals)?;
    if let Some(signal) = signals.poll_pending().await {
        return Ok(WaitOutcome::SignalledBeforeSpawn(signal));
    }
    let lease = match source
        .mint(options.grant, options.max_ttl, signals.next_signal())
        .await?
    {
        MintOutcome::Created(lease) => lease,
        MintOutcome::Interrupted(signal) => return Ok(WaitOutcome::SignalledBeforeSpawn(signal)),
    };
    let finished = match signals.poll_pending().await {
        Some(signal) => Ok(WaitOutcome::SignalledBeforeSpawn(signal)),
        None => run_child(&mut signals, &lease, options, upstream, command).await,
    };
    if let Err(err) = lease.release().await {
        let _ = writeln!(io::stderr(), "dbvalet: {err}");
    }
    finished
}

/// Leaves the proxy to the lease, whose teardown stops it.
async fn run_child(
    signals: &mut RunSignals,
    lease: &Lease,
    options: &RunOptions<'_>,
    upstream: Endpoint,
    command: &[OsString],
) -> Result<WaitOutcome, RunError> {
    let login = lease.login();
    let token = random_base32(RUN_TOKEN_BYTES).map_err(RunError::Random)?;
    let header = RunHeader {
        run_id: lease.run_id().to_owned(),
        started_at: SystemTime::now(),
        database: options.database.clone(),
        role: options.role.to_owned(),
        valid_until: lease.valid_until().to_owned(),
        max_ttl: Some(options.max_ttl),
        command: command.to_vec(),
        sql_log: options.sql_log,
    };
    let run_log = runlog::open(
        &header,
        RunSecrets::new(token.clone(), login.password().clone()),
    )?;
    let database = upstream.database().to_owned();
    let proxy = proxy::start(
        upstream,
        login.clone(),
        token.clone(),
        options.sql_log.then_some(run_log),
        lease.access_deadline(),
    )
    .await?;
    let port = proxy.port();
    lease.attach_proxy(proxy).await;
    let finished = spawn_and_wait(signals, command, login.user(), &token, port, &database).await;
    if let Ok(WaitOutcome::TimedOut(signal)) = finished {
        let _ = writeln!(
            io::stderr(),
            "dbvalet: child didn't exit within {}s after {}; tearing down the temporary login",
            SIGNAL_WAIT_TIMEOUT.as_secs(),
            signal.name()
        );
    }
    finished
}

async fn spawn_and_wait(
    signals: &mut RunSignals,
    command: &[OsString],
    user: &str,
    token: &SecretString,
    port: u16,
    database: &str,
) -> Result<WaitOutcome, RunError> {
    if let Some(signal) = signals.poll_pending().await {
        return Ok(WaitOutcome::SignalledBeforeSpawn(signal));
    }
    let program = command[0].to_string_lossy().into_owned();
    let child = child_command(command, user, token, port, database);
    // Spawn on the current-thread runtime's main thread so PR_SET_PDEATHSIG fires only when dbvalet exits.
    let mut running =
        signals::spawn_child(child).map_err(|source| RunError::Spawn { program, source })?;
    signals
        .wait(&mut running, SIGNAL_WAIT_TIMEOUT)
        .await
        .map_err(RunError::Wait)
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
    let (program, args) = command.split_first().expect("run needs a command");
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
