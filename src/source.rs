//! Where temporary logins come from.

use std::fmt;
use std::future::Future;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use nix::time::{ClockId, clock_gettime};
use secrecy::SecretString;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

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
/// Poll cap for suspend-aware waits: Tokio's timers pause during suspend, so we recheck
/// the suspend-aware clock at least this often after waking.
const SUSPEND_CLOCK_POLL: Duration = Duration::from_secs(1);
/// Minimum poll interval for short-timing tests so polling never spins.
const MIN_SUSPEND_CLOCK_POLL: Duration = Duration::from_millis(50);
/// Short retry delay after a failed push when `VALID UNTIL` is within one push interval
/// (for example right after waking from suspend while networking reconnects).
const URGENT_PUSH_RETRY: Duration = Duration::from_secs(5);
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

pub enum MintOutcome {
    Created(Lease),
    Interrupted(i32),
}

#[expect(
    async_fn_in_trait,
    reason = "run is generic over the source on a single-threaded runtime, so no Send bound is needed"
)]
pub trait CredentialSource {
    /// Drops the logins that ended runs left behind. A failure on one login doesn't stop the rest.
    async fn sweep(&self) -> Result<SweepReport, SourceError>;
    /// Creates a login that the lease keeps alive and ends at `max_ttl`, if release hasn't.
    async fn mint(
        &self,
        grant: &RoleGrant,
        max_ttl: Duration,
        interrupted: impl Future<Output = i32>,
    ) -> Result<MintOutcome, SourceError>;
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
    access_deadline: AccessDeadline,
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
    role_oid: Option<u32>,
    member_of: String,
    read_only: bool,
    ledger_entry: ledger::Entry,
    proxy: Option<Proxy>,
    active_push: Arc<direct::ActivePush>,
}

/// Reads a clock that keeps running while this machine sleeps.
#[derive(Clone)]
pub(crate) struct SuspendClock {
    now: Arc<dyn Fn() -> Duration + Send + Sync>,
    poll_interval: Duration,
}

impl fmt::Debug for SuspendClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuspendClock")
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

impl SuspendClock {
    fn system(poll_interval: Duration) -> Self {
        Self {
            now: Arc::new(suspend_clock_now),
            poll_interval,
        }
    }

    #[cfg(test)]
    fn fake(now: Arc<dyn Fn() -> Duration + Send + Sync>, poll_interval: Duration) -> Self {
        Self { now, poll_interval }
    }

    fn now(&self) -> Duration {
        (self.now)()
    }

    async fn wait_until(&self, target: Duration) {
        loop {
            let remaining = target.saturating_sub(self.now());
            if remaining.is_zero() {
                return;
            }
            // Tokio's timers can pause during suspend. Recheck the suspend-aware clock
            // even when the proxy is idle and the next expiry push is still minutes away.
            tokio::time::sleep(remaining.min(self.poll_interval)).await;
        }
    }
}

/// A deadline measured by a clock that keeps running while this machine sleeps.
#[derive(Clone, Debug)]
pub struct AccessDeadline {
    at: Duration,
    clock: SuspendClock,
}

pub(super) fn suspend_clock_now() -> Duration {
    // macOS's CLOCK_MONOTONIC counts sleep; Linux's doesn't, so Linux needs CLOCK_BOOTTIME.
    #[cfg(target_os = "linux")]
    let clock = ClockId::CLOCK_BOOTTIME;
    #[cfg(not(target_os = "linux"))]
    let clock = ClockId::CLOCK_MONOTONIC;
    clock_gettime(clock)
        .expect("the platform provides its suspend-aware clock")
        .into()
}

impl AccessDeadline {
    #[cfg(test)]
    pub(crate) fn at(when: Duration) -> Self {
        Self::with_clock(when, SuspendClock::system(SUSPEND_CLOCK_POLL))
    }

    fn with_clock(at: Duration, clock: SuspendClock) -> Self {
        Self { at, clock }
    }

    pub(crate) fn has_passed(&self) -> bool {
        self.clock.now() >= self.at
    }

    async fn wait(&self) {
        self.clock.wait_until(self.at).await;
    }
}

/// When a lease started, on the database's clock and on this process's, and its timings.
#[derive(Debug, Clone)]
struct LeaseClock {
    started: SystemTime,
    started_at: Instant,
    started_with_suspend: Duration,
    suspend_clock: SuspendClock,
    access_deadline: AccessDeadline,
    /// As `dbvalet.toml` gives it, for the notice.
    max_ttl: Duration,
    lasts: Duration,
    ahead: Duration,
    push_interval: Duration,
}

impl LeaseClock {
    /// `started` is the database's `now()`, read just after this process's `started_at`.
    fn new(
        started: SystemTime,
        started_at: Instant,
        started_with_suspend: Duration,
        max_ttl: Duration,
    ) -> Self {
        let lasts = lease_time(max_ttl).min(LONGEST_LEASE);
        let ahead = lease_time(LEASE_AHEAD);
        let push_interval = lease_time(EXPIRY_PUSH_INTERVAL);
        let poll = SUSPEND_CLOCK_POLL
            .min(push_interval / 4)
            .max(MIN_SUSPEND_CLOCK_POLL);
        Self::with_timings(
            started,
            started_at,
            started_with_suspend,
            SuspendClock::system(poll),
            max_ttl,
            lasts,
            ahead,
            push_interval,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "shared constructor for production and injected-clock unit tests"
    )]
    fn with_timings(
        started: SystemTime,
        started_at: Instant,
        started_with_suspend: Duration,
        suspend_clock: SuspendClock,
        max_ttl: Duration,
        lasts: Duration,
        ahead: Duration,
        push_interval: Duration,
    ) -> Self {
        let access_deadline =
            AccessDeadline::with_clock(started_with_suspend + lasts, suspend_clock.clone());
        Self {
            started,
            started_at,
            started_with_suspend,
            suspend_clock,
            access_deadline,
            max_ttl,
            lasts,
            ahead,
            push_interval,
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

    /// Delay before the next push: one full interval normally, or a short retry after a failure
    /// when `confirmed_expiry` is within one push interval of lapsing.
    fn next_push_delay(
        &self,
        now_with_suspend: Duration,
        confirmed_expiry: SystemTime,
        failed: bool,
    ) -> Duration {
        if !failed {
            return self.push_interval;
        }
        let elapsed = now_with_suspend.saturating_sub(self.started_with_suspend);
        let valid_for = confirmed_expiry
            .duration_since(self.started)
            .unwrap_or(Duration::ZERO);
        let remaining_validity = valid_for.saturating_sub(elapsed);
        if remaining_validity <= self.push_interval {
            URGENT_PUSH_RETRY
                .min(self.push_interval / 4)
                .max(MIN_SUSPEND_CLOCK_POLL)
        } else {
            self.push_interval
        }
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
        let access_deadline = clock.access_deadline.clone();
        // A push uses its own copy of what it needs, so it never holds the teardown's lock.
        let pushes = Pushes {
            alias: live.alias.clone(),
            admin: Arc::clone(&live.admin),
            user: live.user.clone(),
            active_push: Arc::clone(&live.active_push),
            clock,
        };
        let live = Arc::new(Mutex::new(Some(live)));
        let keep_alive = tokio::spawn(keep_alive(Arc::clone(&live), pushes));
        Self {
            login,
            access_deadline,
            live,
            keep_alive,
        }
    }

    pub fn login(&self) -> &UpstreamLogin {
        &self.login
    }

    pub(crate) fn access_deadline(&self) -> AccessDeadline {
        self.access_deadline.clone()
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
        self.active_push.close_and_cancel().await;
        direct::drop_login(
            &self.alias,
            &self.admin,
            &self.user,
            self.role_oid,
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
    active_push: Arc<direct::ActivePush>,
    clock: LeaseClock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeepAliveStop {
    MaxTtl,
    AlreadyGone,
}

/// Pushes the login's expiry forward at every interval until max_ttl, then ends the lease
/// unless release has. A failed push is printed and tried again at the next interval.
async fn keep_alive(live: Arc<Mutex<Option<LiveLease>>>, pushes: Pushes) {
    let max_ttl = pushes.clock.max_ttl;
    let clock = pushes.clock.clone();
    let confirmed_expiry = clock.next_expiry(clock.started);
    let stop = drive_keep_alive(clock, confirmed_expiry, |confirmed| {
        let alias = pushes.alias.clone();
        let admin = Arc::clone(&pushes.admin);
        let user = pushes.user.clone();
        let active_push = Arc::clone(&pushes.active_push);
        let clock = pushes.clock.clone();
        async move {
            // Bounded, so a database that stops answering mid-push only costs this push.
            let timed = tokio::time::timeout(
                clock.push_interval,
                direct::push_expiry(&alias, &admin, &user, &clock, confirmed, &active_push),
            )
            .await;
            match timed {
                Ok(result) => result,
                Err(_) => {
                    active_push.cancel_in_flight().await;
                    Err(SourceError::PushExpiry {
                        login: user,
                        reason: format!("no answer within {} ms", clock.push_interval.as_millis()),
                    })
                }
            }
        }
    })
    .await;
    match stop {
        KeepAliveStop::MaxTtl => end_at_max_ttl(&live, max_ttl).await,
        KeepAliveStop::AlreadyGone => end_already_gone(&live).await,
    }
}

async fn drive_keep_alive<Push, PushFut>(
    clock: LeaseClock,
    mut confirmed_expiry: SystemTime,
    mut push: Push,
) -> KeepAliveStop
where
    Push: FnMut(SystemTime) -> PushFut,
    PushFut: Future<Output = Result<direct::PushOutcome, SourceError>>,
{
    let mut next_push_at = clock.started_with_suspend + clock.push_interval;
    let max_ttl_reached = tokio::time::sleep_until(clock.ends_at().into());
    let host_deadline_reached = clock.access_deadline.wait();
    tokio::pin!(max_ttl_reached, host_deadline_reached);
    loop {
        tokio::select! {
            biased;
            () = &mut max_ttl_reached => return KeepAliveStop::MaxTtl,
            () = &mut host_deadline_reached => return KeepAliveStop::MaxTtl,
            () = clock.suspend_clock.wait_until(next_push_at) => {}
        }
        if clock.access_deadline.has_passed() {
            return KeepAliveStop::MaxTtl;
        }
        let pushed = tokio::select! {
            biased;
            () = &mut max_ttl_reached => return KeepAliveStop::MaxTtl,
            () = &mut host_deadline_reached => return KeepAliveStop::MaxTtl,
            pushed = push(confirmed_expiry) => pushed,
        };
        let failed = match pushed {
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
                    None => return KeepAliveStop::MaxTtl,
                }
                false
            }
            Ok(direct::PushOutcome::ReachedMaxTtl) => return KeepAliveStop::MaxTtl,
            Ok(direct::PushOutcome::AlreadyGone) => return KeepAliveStop::AlreadyGone,
            Err(err) => {
                let _ = writeln!(io::stderr(), "dbvalet: {err}");
                true
            }
        };
        let now = clock.suspend_clock.now();
        next_push_at = now + clock.next_push_delay(now, confirmed_expiry, failed);
    }
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

/// Ends access immediately when another actor has already dropped the login.
async fn end_already_gone(live: &Mutex<Option<LiveLease>>) {
    let mut live = live.lock().await;
    let Some(lease) = live.take() else { return };
    let user = lease.user.clone();
    let ended = lease.end().await;
    let _ = writeln!(
        io::stderr(),
        "dbvalet: the temporary login `{user}` was already dropped: dbvalet ended the \
         command's database access, and the command keeps running"
    );
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
        let clock = LeaseClock::new(
            started,
            Instant::now(),
            suspend_clock_now(),
            Duration::from_secs(600),
        );
        assert_eq!(
            clock.remaining(started + Duration::from_secs(240)),
            Some(Duration::from_secs(360))
        );
        assert_eq!(clock.remaining(started + Duration::from_secs(601)), None);
    }

    #[test]
    fn a_max_ttl_too_long_for_the_clocks_still_gives_an_end() {
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::new(
            started,
            Instant::now(),
            suspend_clock_now(),
            Duration::from_secs(u64::MAX),
        );
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

    #[tokio::test]
    async fn a_suspend_shorter_than_max_ttl_pushes_immediately_after_wake() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let elapsed_secs = Arc::new(AtomicU64::new(0));
        let reader = Arc::clone(&elapsed_secs);
        let suspend_clock = SuspendClock::fake(
            Arc::new(move || Duration::from_secs(reader.load(Ordering::Relaxed))),
            Duration::from_millis(5),
        );
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::with_timings(
            started,
            Instant::now(),
            Duration::ZERO,
            suspend_clock,
            Duration::from_secs(60 * 60),
            Duration::from_secs(60 * 60),
            Duration::from_secs(15 * 60),
            Duration::from_secs(5 * 60),
        );
        let initial_expiry = clock.next_expiry(started);
        let (pushed_tx, pushed_rx) = tokio::sync::oneshot::channel();
        let mut pushed_tx = Some(pushed_tx);
        let drive = tokio::spawn(drive_keep_alive(clock, initial_expiry, move |_confirmed| {
            let tx = pushed_tx.take();
            async move {
                if let Some(tx) = tx {
                    let _ = tx.send(());
                }
                Ok(direct::PushOutcome::Pushed {
                    database_now: started + Duration::from_secs(12 * 60),
                    expiry: started + Duration::from_secs(27 * 60),
                })
            }
        }));

        // Simulate a 12-minute suspend while monotonic time barely moves: VALID UNTIL is at 15 min.
        elapsed_secs.store(12 * 60, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_millis(500), pushed_rx)
            .await
            .expect("push did not run promptly after waking from a 12-minute suspend")
            .unwrap();
        assert!(
            !drive.is_finished(),
            "a short suspend must not end the lease"
        );
        drive.abort();
    }

    #[tokio::test]
    async fn a_failed_push_after_a_short_suspend_retries_before_valid_until_lapses() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        let elapsed_secs = Arc::new(AtomicU64::new(0));
        let reader = Arc::clone(&elapsed_secs);
        let suspend_clock = SuspendClock::fake(
            Arc::new(move || Duration::from_secs(reader.load(Ordering::Relaxed))),
            Duration::from_millis(5),
        );
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::with_timings(
            started,
            Instant::now(),
            Duration::ZERO,
            suspend_clock,
            Duration::from_secs(60 * 60),
            Duration::from_secs(60 * 60),
            Duration::from_secs(15 * 60),
            Duration::from_secs(5 * 60),
        );
        let initial_expiry = clock.next_expiry(started);
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_in_push = Arc::clone(&attempts);
        let (first_failed_tx, first_failed_rx) = tokio::sync::oneshot::channel();
        let (retry_ok_tx, retry_ok_rx) = tokio::sync::oneshot::channel();
        let mut first_failed_tx = Some(first_failed_tx);
        let mut retry_ok_tx = Some(retry_ok_tx);
        let drive = tokio::spawn(drive_keep_alive(clock, initial_expiry, move |_confirmed| {
            let attempt = attempts_in_push.fetch_add(1, Ordering::Relaxed) + 1;
            let first_tx = if attempt == 1 {
                first_failed_tx.take()
            } else {
                None
            };
            let retry_tx = if attempt == 2 {
                retry_ok_tx.take()
            } else {
                None
            };
            async move {
                if attempt == 1 {
                    if let Some(tx) = first_tx {
                        let _ = tx.send(());
                    }
                    Err(SourceError::PushExpiry {
                        login: "dbvalet_aaaaaaaaaaaaaaaa".to_owned(),
                        reason: "network still reconnecting".to_owned(),
                    })
                } else {
                    if let Some(tx) = retry_tx {
                        let _ = tx.send(());
                    }
                    Ok(direct::PushOutcome::Pushed {
                        database_now: started + Duration::from_secs(12 * 60 + 10),
                        expiry: started + Duration::from_secs(27 * 60 + 10),
                    })
                }
            }
        }));

        // Wake at 12 min (3 min before VALID UNTIL); the first push fails.
        elapsed_secs.store(12 * 60, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_millis(500), first_failed_rx)
            .await
            .expect("first push after wake did not run")
            .unwrap();

        // Advance to 12 min 10 s — well before the 15-minute VALID UNTIL lapses.
        elapsed_secs.store(12 * 60 + 10, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_millis(500), retry_ok_rx)
            .await
            .expect("failed push after wake was not retried before VALID UNTIL lapsed")
            .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert!(
            !drive.is_finished(),
            "a recovered push must not end the lease"
        );
        drive.abort();
    }

    #[tokio::test]
    async fn a_suspend_past_max_ttl_ends_the_lease_even_when_monotonic_time_paused() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let elapsed_secs = Arc::new(AtomicU64::new(0));
        let reader = Arc::clone(&elapsed_secs);
        let suspend_clock = SuspendClock::fake(
            Arc::new(move || Duration::from_secs(reader.load(Ordering::Relaxed))),
            Duration::from_millis(5),
        );
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::with_timings(
            started,
            Instant::now(),
            Duration::ZERO,
            suspend_clock,
            Duration::from_secs(10 * 60),
            Duration::from_secs(10 * 60),
            Duration::from_secs(15 * 60),
            Duration::from_secs(5 * 60),
        );
        let initial_expiry = clock.next_expiry(started);
        let drive = tokio::spawn(drive_keep_alive(clock, initial_expiry, |_| async {
            panic!("push must not run after max_ttl passed during suspend")
        }));

        elapsed_secs.store(12 * 60, Ordering::Relaxed);
        let stop = tokio::time::timeout(Duration::from_millis(500), drive)
            .await
            .expect("host deadline did not fire after waking past max_ttl")
            .unwrap();
        assert_eq!(stop, KeepAliveStop::MaxTtl);
    }

    #[tokio::test]
    async fn an_already_dropped_login_ends_keep_alive_immediately_instead_of_waiting_for_max_ttl() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let elapsed_secs = Arc::new(AtomicU64::new(0));
        let reader = Arc::clone(&elapsed_secs);
        let suspend_clock = SuspendClock::fake(
            Arc::new(move || Duration::from_secs(reader.load(Ordering::Relaxed))),
            Duration::from_millis(5),
        );
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let clock = LeaseClock::with_timings(
            started,
            Instant::now(),
            Duration::ZERO,
            suspend_clock,
            Duration::from_secs(60 * 60),
            Duration::from_secs(60 * 60),
            Duration::from_secs(15 * 60),
            Duration::from_secs(5 * 60),
        );
        let initial_expiry = clock.next_expiry(started);
        let drive = tokio::spawn(drive_keep_alive(clock, initial_expiry, |_| async {
            Ok(direct::PushOutcome::AlreadyGone)
        }));

        elapsed_secs.store(5 * 60, Ordering::Relaxed);
        let stop = tokio::time::timeout(Duration::from_millis(500), drive)
            .await
            .expect("keep_alive did not stop immediately when the login was already gone")
            .unwrap();
        assert_eq!(stop, KeepAliveStop::AlreadyGone);
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
