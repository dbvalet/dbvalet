//! Where temporary logins come from.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use secrecy::SecretString;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::DatabaseAlias;
use crate::config::RoleGrant;
use crate::keychain::AdminLogin;
use crate::ledger::{self, LedgerError};
use crate::policy;
use crate::proxy::Proxy;

pub mod direct;

/// How far ahead of now a login's `VALID UNTIL` is set.
const LEASE_AHEAD: Duration = Duration::from_secs(15 * 60);
/// A push every 5 minutes keeps two pushes in hand before a 15-minute lead runs out.
const EXPIRY_PUSH_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// In a debug build only, how many milliseconds a lease's minute lasts, so e2e tests reach
/// pushes and max_ttl in seconds. A release build doesn't contain the code that reads it.
const TEST_MINUTE_MS_VAR: &str = "DBVALET_TEST_MINUTE_MS";
const SECONDS_PER_MINUTE: u64 = 60;

/// The temporary login the proxy connects upstream as. Its password never leaves dbvalet.
#[derive(Debug, Clone)]
pub struct UpstreamLogin {
    user: String,
    password: SecretString,
}

impl UpstreamLogin {
    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> &SecretString {
        &self.password
    }
}

/// No variant carries a password: reasons are built from SQLSTATEs and server messages only.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("can't connect as the admin login for `{alias}`: {reason}")]
    Connect {
        alias: DatabaseAlias,
        reason: String,
    },
    #[error("PostgreSQL {version} is end-of-life: dbvalet needs 15 or later")]
    TooOld { version: String },
    #[error(
        "the admin login `{user}` has NOINHERIT on PostgreSQL {version}, so it can't drop \
         temporary logins it creates: run ALTER ROLE {quoted} INHERIT, or run `dbvalet doctor {alias}`"
    )]
    AdminNoInherit {
        alias: DatabaseAlias,
        user: String,
        quoted: String,
        version: String,
    },
    #[error("couldn't create a temporary login: {reason}")]
    CreateLogin { reason: String },
    #[error(
        "couldn't drop the temporary login `{login}`: {reason}. \
         It stops accepting new connections within 15 minutes"
    )]
    DropLogin { login: String, reason: String },
    #[error("couldn't drop the leftover login `{login}`: {reason}")]
    DropLeftoverLogin { login: String, reason: String },
    #[error(
        "couldn't push the temporary login `{login}`'s expiry forward: {reason}. \
         dbvalet tries again at the next push"
    )]
    PushExpiry { login: String, reason: String },
    #[error("couldn't list the expired temporary logins: {reason}")]
    ListExpiredLogins { reason: String },
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("the OS random number generator failed")]
    Random(#[source] getrandom::Error),
}

#[expect(
    async_fn_in_trait,
    reason = "run is generic over the source on a single-threaded runtime, so no Send bound is needed"
)]
pub trait CredentialSource {
    /// Drops the logins that ended runs left behind. A failure on one login doesn't stop the rest.
    async fn sweep(&self) -> Result<SweepReport, SourceError>;
    /// Creates a login that the lease keeps alive and ends at `max_ttl`, if release hasn't.
    async fn mint(&self, grant: &RoleGrant, max_ttl: Duration) -> Result<Lease, SourceError>;
}

/// What a sweep cleaned up, and what it couldn't.
#[derive(Debug, Default)]
pub struct SweepReport {
    /// Leftover logins the sweep dropped.
    pub dropped: Vec<String>,
    /// Logins whose ledger entry the sweep removed because the login no longer existed.
    pub already_gone: Vec<String>,
    pub failures: Vec<SourceError>,
}

/// A temporary login that exists until [`Lease::release`] or its max_ttl drops it, whichever
/// comes first. Until then a task pushes its `VALID UNTIL` forward.
#[derive(Debug)]
pub struct Lease {
    login: UpstreamLogin,
    /// Taken by whichever ends the lease first, so the teardown runs exactly once.
    live: Arc<Mutex<Option<LiveLease>>>,
    keep_alive: JoinHandle<()>,
}

/// What the teardown needs, and what it stops: the proxy, the login and the ledger entry.
#[derive(Debug)]
struct LiveLease {
    alias: DatabaseAlias,
    admin: Arc<AdminLogin>,
    user: String,
    member_of: String,
    read_only: bool,
    ledger_entry: ledger::Entry,
    proxy: Option<Proxy>,
}

/// When a lease started, on the database's clock and on this process's, and its timings.
#[derive(Debug, Clone, Copy)]
struct LeaseClock {
    started: SystemTime,
    started_at: Instant,
    /// As `dbvalet.toml` gives it, for the notice.
    max_ttl: Duration,
    lasts: Duration,
    ahead: Duration,
    push_interval: Duration,
}

impl LeaseClock {
    /// `started` is the database's `now()`, read just after this process's `started_at`.
    fn new(started: SystemTime, started_at: Instant, max_ttl: Duration) -> Self {
        Self {
            started,
            started_at,
            max_ttl,
            lasts: lease_time(max_ttl),
            ahead: lease_time(LEASE_AHEAD),
            push_interval: lease_time(EXPIRY_PUSH_INTERVAL),
        }
    }

    /// The database's clock, advanced by this process's monotonic clock since the start, so a
    /// skew between the two clocks never moves the expiry.
    fn next_expiry(&self) -> SystemTime {
        let now = self.started + self.started_at.elapsed();
        policy::next_expiry(now, self.started, self.lasts, self.ahead)
    }
}

/// How long `real` lasts for a lease. Only a debug build's tests can shorten it.
fn lease_time(real: Duration) -> Duration {
    #[cfg(debug_assertions)]
    if let Some(minute_ms) = std::env::var(TEST_MINUTE_MS_VAR)
        .ok()
        .and_then(|ms| ms.parse::<u64>().ok())
        .filter(|&ms| ms > 0)
    {
        return Duration::from_millis(
            real.as_secs().saturating_mul(minute_ms) / SECONDS_PER_MINUTE,
        );
    }
    real
}

impl Lease {
    /// Starts the task that keeps the login alive and ends it at max_ttl.
    fn start(login: UpstreamLogin, live: LiveLease, clock: LeaseClock) -> Self {
        let live = Arc::new(Mutex::new(Some(live)));
        let keep_alive = tokio::spawn(keep_alive(Arc::clone(&live), clock));
        Self {
            login,
            live,
            keep_alive,
        }
    }

    pub fn login(&self) -> &UpstreamLogin {
        &self.login
    }

    /// Hands the lease the proxy in front of its login, so whichever ends the lease stops the
    /// proxy before it ends the login's sessions.
    pub async fn attach_proxy(&self, proxy: Proxy) {
        match self.live.lock().await.as_mut() {
            Some(live) => live.proxy = Some(proxy),
            None => proxy.stop().await,
        }
    }

    /// Stops the proxy, ends the login's sessions and drops it, unless max_ttl already did.
    /// On failure the ledger entry stays for the next sweep.
    pub async fn release(self) -> Result<(), SourceError> {
        // Waits for a push or a max_ttl teardown in progress.
        let live = self.live.lock().await.take();
        self.keep_alive.abort();
        match live {
            Some(live) => live.end().await,
            None => Ok(()),
        }
    }
}

impl Drop for Lease {
    /// A lease dropped without release, as on a panic, stops pushing, so its login expires and
    /// the next sweep drops it.
    fn drop(&mut self) {
        self.keep_alive.abort();
    }
}

impl LiveLease {
    async fn end(self) -> Result<(), SourceError> {
        if let Some(proxy) = self.proxy {
            proxy.stop().await;
        }
        direct::drop_login(
            &self.alias,
            &self.admin,
            &self.user,
            &self.member_of,
            self.read_only,
        )
        .await?;
        self.ledger_entry.remove()?;
        Ok(())
    }
}

/// Pushes the login's expiry forward at every interval until max_ttl, then ends the lease
/// unless release has. A failed push is printed and tried again at the next interval.
async fn keep_alive(live: Arc<Mutex<Option<LiveLease>>>, clock: LeaseClock) {
    let first_push = clock.started_at + clock.push_interval;
    let mut pushes = tokio::time::interval_at(first_push.into(), clock.push_interval);
    pushes.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let max_ttl_reached = async {
        match clock.started_at.checked_add(clock.lasts) {
            Some(end) => tokio::time::sleep_until(end.into()).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(max_ttl_reached);
    loop {
        tokio::select! {
            biased;
            () = &mut max_ttl_reached => break,
            _ = pushes.tick() => {
                let live = live.lock().await;
                let Some(lease) = live.as_ref() else { return };
                let pushed =
                    direct::push_expiry(&lease.alias, &lease.admin, &lease.user, clock.next_expiry())
                        .await;
                if let Err(err) = pushed {
                    let _ = writeln!(io::stderr(), "dbvalet: {err}");
                }
            }
        }
    }
    // Held through the teardown, so a release meanwhile waits for it and then does nothing.
    let mut live = live.lock().await;
    let Some(lease) = live.take() else { return };
    let alias = lease.alias.clone();
    let ended = lease.end().await;
    let _ = writeln!(
        io::stderr(),
        "dbvalet: `{alias}` reached its max_ttl of {} minutes: dbvalet ended the command's \
         database access, and the command keeps running",
        clock.max_ttl.as_secs() / SECONDS_PER_MINUTE
    );
    if let Err(err) = ended {
        let _ = writeln!(io::stderr(), "dbvalet: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_upstream_login_debug_output_hides_the_password() {
        let login = UpstreamLogin {
            user: "dbvalet_aaaaaaaaaaaaaaaa".to_owned(),
            password: SecretString::from("pw-upstream-unit-3e7"),
        };
        assert!(!format!("{login:?}").contains("pw-upstream-unit-3e7"));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    #[ignore = "CI runs this in a release build, with DBVALET_TEST_MINUTE_MS=1"]
    fn a_release_build_ignores_the_test_minute() {
        assert_eq!(std::env::var(TEST_MINUTE_MS_VAR).as_deref(), Ok("1"));
        assert_eq!(lease_time(LEASE_AHEAD), Duration::from_secs(15 * 60));
        assert_eq!(
            lease_time(EXPIRY_PUSH_INTERVAL),
            Duration::from_secs(5 * 60)
        );
    }
}
