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
/// Longer than any run, and short enough that no lease's clock arithmetic overflows.
const LONGEST_LEASE: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
/// In a debug build only, how many milliseconds a lease's minute lasts, so e2e tests reach
/// pushes and max_ttl in seconds. A release build doesn't contain the code that reads it.
#[cfg(any(debug_assertions, test))]
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
            lasts: lease_time(max_ttl).min(LONGEST_LEASE),
            ahead: lease_time(LEASE_AHEAD),
            push_interval: lease_time(EXPIRY_PUSH_INTERVAL),
        }
    }

    /// Read from the database's clock, so neither a skew from this machine's clock nor this
    /// machine sleeping moves the expiry.
    fn next_expiry(&self, database_now: SystemTime) -> SystemTime {
        policy::next_expiry(database_now, self.started, self.lasts, self.ahead)
    }

    /// When max_ttl arrives on this process's monotonic clock, which stops while the machine
    /// sleeps.
    fn ends_at(&self) -> Instant {
        self.started_at + self.lasts
    }

    /// How long until max_ttl on the database's clock, or `None` once it has passed.
    fn remaining(&self, database_now: SystemTime) -> Option<Duration> {
        (self.started + self.lasts)
            .duration_since(database_now)
            .ok()
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
        // A push uses its own copy of what it needs, so it never holds the teardown's lock.
        let pushes = Pushes {
            alias: live.alias.clone(),
            admin: Arc::clone(&live.admin),
            user: live.user.clone(),
            clock,
        };
        let live = Arc::new(Mutex::new(Some(live)));
        let keep_alive = tokio::spawn(keep_alive(Arc::clone(&live), pushes));
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
        let stop = {
            let mut live = self.live.lock().await;
            match live.as_mut() {
                Some(live) => live.proxy.replace(proxy),
                None => Some(proxy),
            }
        };
        if let Some(proxy) = stop {
            proxy.stop().await;
        }
    }

    /// Stops the proxy, ends the login's sessions and drops it, unless max_ttl or an earlier
    /// call already did. On failure the ledger entry stays for the next sweep.
    pub async fn end(&self) -> Result<(), SourceError> {
        // Waits for a max_ttl or earlier teardown in progress, and holds the lock through this one.
        let mut live = self.live.lock().await;
        self.keep_alive.abort();
        match live.take() {
            Some(live) => live.end().await,
            None => Ok(()),
        }
    }

    /// Consuming form of [`Lease::end`], called when the run finishes.
    pub async fn release(self) -> Result<(), SourceError> {
        self.end().await
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

/// What the expiry pushes need: the login, the admin login that pushes it and the clock.
#[derive(Debug)]
struct Pushes {
    alias: DatabaseAlias,
    admin: Arc<AdminLogin>,
    user: String,
    clock: LeaseClock,
}

/// Pushes the login's expiry forward at every interval until max_ttl, then ends the lease
/// unless release has. A failed push is printed and tried again at the next interval.
async fn keep_alive(live: Arc<Mutex<Option<LiveLease>>>, pushes: Pushes) {
    let clock = pushes.clock;
    let mut confirmed_expiry = clock.next_expiry(clock.started);
    let first_push = clock.started_at + clock.push_interval;
    let mut ticks = tokio::time::interval_at(first_push.into(), clock.push_interval);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let max_ttl_reached = tokio::time::sleep_until(clock.ends_at().into());
    tokio::pin!(max_ttl_reached);
    loop {
        tokio::select! {
            biased;
            () = &mut max_ttl_reached => break,
            _ = ticks.tick() => {}
        }
        // Bounded, so a database that stops answering mid-push only costs this push.
        let push = tokio::time::timeout(
            clock.push_interval,
            direct::push_expiry(
                &pushes.alias,
                &pushes.admin,
                &pushes.user,
                &clock,
                confirmed_expiry,
            ),
        );
        let pushed = tokio::select! {
            biased;
            () = &mut max_ttl_reached => break,
            pushed = push => pushed.unwrap_or_else(|_| {
                Err(SourceError::PushExpiry {
                    login: pushes.user.clone(),
                    reason: format!(
                        "no answer within {} ms",
                        clock.push_interval.as_millis()
                    ),
                })
            }),
        };
        match pushed {
            // After this machine slept, max_ttl comes sooner than the monotonic clock says.
            Ok(direct::PushOutcome::Pushed {
                database_now,
                expiry,
            }) => {
                confirmed_expiry = expiry;
                match clock.remaining(database_now) {
                    Some(remaining) => {
                        let ends_at = tokio::time::Instant::now() + remaining;
                        if ends_at < max_ttl_reached.deadline() {
                            max_ttl_reached.as_mut().reset(ends_at);
                        }
                    }
                    None => break,
                }
            }
            Ok(direct::PushOutcome::ReachedMaxTtl) => break,
            Ok(direct::PushOutcome::AlreadyGone) => {
                let _ = writeln!(
                    io::stderr(),
                    "dbvalet: the temporary login `{}` was already dropped",
                    pushes.user
                );
                // No further pushes can revive a dropped login; wait to close the proxy and ledger.
                max_ttl_reached.await;
                break;
            }
            Err(err) => {
                let _ = writeln!(io::stderr(), "dbvalet: {err}");
            }
        }
    }
    end_at_max_ttl(&live, clock.max_ttl).await;
}

/// Runs the teardown at max_ttl and prints the notice, unless another caller ended the lease first.
async fn end_at_max_ttl(live: &Mutex<Option<LiveLease>>, max_ttl: Duration) {
    // Held through the teardown and notice, so a release meanwhile waits and then does nothing.
    let mut live = live.lock().await;
    let Some(lease) = live.take() else { return };
    let alias = lease.alias.clone();
    let ended = lease.end().await;
    let _ = writeln!(io::stderr(), "{}", max_ttl_notice(&alias, max_ttl));
    if let Err(err) = ended {
        let _ = writeln!(io::stderr(), "dbvalet: {err}");
    }
}

fn max_ttl_notice(alias: &DatabaseAlias, max_ttl: Duration) -> String {
    let minutes = max_ttl.as_secs() / SECONDS_PER_MINUTE;
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    format!(
        "dbvalet: `{alias}` reached its max_ttl of {minutes} {unit}: dbvalet ended the \
         command's database access, and the command keeps running"
    )
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
    fn max_ttl_remains_until_the_databases_clock_passes_the_start_plus_max_ttl() {
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::new(started, Instant::now(), Duration::from_secs(600));
        assert_eq!(
            clock.remaining(started + Duration::from_secs(240)),
            Some(Duration::from_secs(360))
        );
        assert_eq!(clock.remaining(started + Duration::from_secs(601)), None);
    }

    #[test]
    fn a_max_ttl_too_long_for_the_clocks_still_gives_an_end() {
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::new(started, Instant::now(), Duration::from_secs(u64::MAX));
        assert!(clock.ends_at() > Instant::now());
        assert!(clock.remaining(started).is_some());
    }

    #[test]
    fn a_max_ttl_notice_uses_singular_and_plural_minutes() {
        let alias: DatabaseAlias = "app".parse().unwrap();
        assert_eq!(
            max_ttl_notice(&alias, Duration::from_secs(60)),
            "dbvalet: `app` reached its max_ttl of 1 minute: dbvalet ended the \
             command's database access, and the command keeps running"
        );
        assert_eq!(
            max_ttl_notice(&alias, Duration::from_secs(480 * 60)),
            "dbvalet: `app` reached its max_ttl of 480 minutes: dbvalet ended the \
             command's database access, and the command keeps running"
        );
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
