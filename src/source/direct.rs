//! Temporary logins created with the admin login, over admin SQL.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use secrecy::ExposeSecret;
use tokio::sync::watch;
use tokio_postgres::error::SqlState;
use tokio_postgres::{CancelToken, Client, NoTls};

use super::{
    CredentialSource, Lease, LeaseClock, LiveLease, MintOutcome, SourceError, SweepReport,
    UpstreamLogin,
};
use crate::config::RoleGrant;
use crate::keychain::AdminLogin;
use crate::ledger::{self, State};
use crate::tls;
use crate::{DatabaseAlias, LOGIN_PREFIX, RUN_ID_BYTES, is_login_name, random_base32};

mod connect;
mod doctor;
mod group_role;
mod init;
use connect::{connect, connect_with_cancel_tls};
pub use doctor::{Check, doctor};
use group_role::{AdminGrants, GroupRoleStatus, inspect_group_role, read_admin_grants};
pub use init::{InitError, InitReport, init};

/// For the whole admin connection: TCP, startup, authentication and its first setting.
const ADMIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_MINT_TIMEOUT: Duration = Duration::from_secs(15);
const MINIMUM_SERVER_VERSION_NUM: i32 = 150000;
/// From this version a CREATEROLE admin can inherit the roles it creates.
const CREATEROLE_SELF_GRANT_VERSION_NUM: i32 = 160000;
const LOGIN_PASSWORD_BYTES: usize = 20;
/// How long `pg_terminate_backend` waits for each of the login's sessions to end.
const SESSION_END_TIMEOUT_MS: i64 = 5_000;
/// A second pass catches a session that was still starting, so not yet listed, during the first.
const SESSION_END_PASSES: usize = 2;
/// Leftover logins a sweep may drop without a ledger entry. Group roles fail `rolcanlogin`,
/// and live runs anywhere keep their `VALID UNTIL` in the future.
const EXPIRED_LOGINS: &str = "
    SELECT rolname::text
    FROM pg_roles
    WHERE rolcanlogin
      AND rolname ~ '^dbvalet_[a-z2-7]{16}$'
      AND rolvaliduntil < now()
      -- Another admin's logins are left to that admin's own sweep.
      AND pg_has_role(current_user, oid, 'USAGE')";

/// Temporary logins created over admin SQL, with a fresh admin connection per operation.
#[derive(Debug)]
pub struct DirectSource {
    alias: DatabaseAlias,
    admin: Arc<AdminLogin>,
}

impl DirectSource {
    pub fn new(alias: DatabaseAlias, admin: AdminLogin) -> Self {
        Self {
            alias,
            admin: Arc::new(admin),
        }
    }
}

impl CredentialSource for DirectSource {
    async fn sweep(&self) -> Result<SweepReport, SourceError> {
        let mut report = SweepReport::default();
        let listed = match ledger::list() {
            Ok(listed) => listed,
            Err(err) => {
                // Without the ledger, pass (b) can't tell a live login, or a read-only one.
                report.failures.push(err.into());
                return Ok(report);
            }
        };
        let client =
            connect(&self.alias, &self.admin)
                .await
                .map_err(|reason| SourceError::Connect {
                    alias: self.alias.clone(),
                    reason,
                })?;

        // Pass (b) leaves every login with an entry alone. This alias's entries are pass (a)'s.
        // Another alias's are that alias's sweep's, which connects to the database holding the
        // login's objects and never has its entries locked by this sweep.
        let mut has_entry = BTreeSet::new();
        for listed in listed {
            has_entry.insert(listed.login.clone());
            if listed.alias != self.alias {
                continue;
            }
            match listed.lock() {
                Some(State::Orphan(entry)) => sweep_orphan(&client, entry, &mut report).await,
                Some(State::Held) | None => {}
                Some(State::Unreadable(err)) => report.failures.push(err.into()),
            }
        }

        let expired = match client.query(EXPIRED_LOGINS, &[]).await {
            Ok(rows) => rows,
            Err(err) => {
                report.failures.push(SourceError::ListExpiredLogins {
                    reason: describe_sql_error(&err),
                });
                return Ok(report);
            }
        };
        for row in expired {
            let login: String = row.get(0);
            if !is_login_name(&login) || has_entry.contains(&login) {
                continue;
            }
            match drop_leftover_login(&client, &login, None).await {
                Ok(true) => report.dropped.push(login),
                Ok(false) => {}
                Err(reason) => report
                    .failures
                    .push(SourceError::DropLeftoverLogin { login, reason }),
            }
        }
        Ok(report)
    }

    async fn mint(
        &self,
        grant: &RoleGrant,
        max_ttl: Duration,
        interrupted: impl Future<Output = i32>,
    ) -> Result<MintOutcome, SourceError> {
        let setup_deadline = tokio::time::Instant::now() + ADMIN_MINT_TIMEOUT;
        let preparing = tokio::time::timeout_at(setup_deadline, self.prepare_mint(grant, max_ttl));
        tokio::pin!(interrupted);
        let (mut client, version_num, clock, valid_until) = tokio::select! {
            biased;
            signal = &mut interrupted => return Ok(MintOutcome::Interrupted(signal)),
            prepared = preparing => prepared.map_err(mint_timed_out)??,
        };
        let user = new_login_name().map_err(SourceError::Random)?;
        let starting = tokio::time::timeout_at(setup_deadline, lock_creation(&mut client, &user));
        let transaction = tokio::select! {
            biased;
            signal = &mut interrupted => return Ok(MintOutcome::Interrupted(signal)),
            started = starting => started.map_err(mint_timed_out)??,
        };
        let password = random_base32(LOGIN_PASSWORD_BYTES).map_err(SourceError::Random)?;
        // Only the SCRAM verifier reaches the server, so its logs never hold the password.
        let verifier =
            postgres_protocol::password::scram_sha_256(password.expose_secret().as_bytes());
        // The admin needs the login's privileges to end its sessions and drop what it owns:
        // PostgreSQL 16 and later give them through createrole_self_grant, older ones through ROLE.
        let (self_grant, admin_member) = if version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
            ("SET createrole_self_grant = 'inherit';", String::new())
        } else {
            ("", format!("ROLE {}", quote_ident(self.admin.user())))
        };
        // Written before the login exists, so a run killed from here on leaves it to the sweep.
        let ledger_entry = ledger::create(&self.alias, &user, grant.read_only)?;
        let read_only = if grant.read_only {
            format!("ALTER ROLE {user} SET default_transaction_read_only = on;")
        } else {
            String::new()
        };
        let create = format!(
            "{self_grant}
             CREATE ROLE {user} LOGIN PASSWORD {verifier} VALID UNTIL {valid_until}
                 IN ROLE {group} {admin_member};
             {read_only}",
            verifier = quote_literal(&verifier),
            group = quote_ident(&grant.member_of),
        );
        // Once creation starts, give it a bounded chance to finish. On an uncertain
        // outcome the ledger stays, and the database lock protects it from the sweep.
        tokio::time::timeout(ADMIN_MINT_TIMEOUT, async {
            transaction.batch_execute(&create).await?;
            transaction.commit().await
        })
        .await
        .map_err(mint_timed_out)?
        .map_err(create_failed)?;
        // Best-effort: kept so end_sessions can still match backends by usesysid if another
        // actor drops the role. A lookup failure here shouldn't abort a run whose login already
        // exists, and the ledger entry is already on disk.
        let role_oid: Option<u32> = tokio::time::timeout(
            Duration::from_secs(2),
            client.query_opt("SELECT oid FROM pg_roles WHERE rolname = $1", &[&user]),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .flatten()
        .map(|row| row.get(0));

        let active_push = Arc::new(ActivePush::default());
        let live = LiveLease {
            alias: self.alias.clone(),
            admin: Arc::clone(&self.admin),
            user: user.clone(),
            role_oid,
            member_of: grant.member_of.clone(),
            read_only: grant.read_only,
            ledger_entry,
            proxy: None,
            active_push,
        };
        Ok(MintOutcome::Created(Lease::start(
            UpstreamLogin::new(user, password),
            valid_until.trim_matches('\'').to_owned(),
            live,
            clock,
        )))
    }
}

impl DirectSource {
    async fn prepare_mint(
        &self,
        grant: &RoleGrant,
        max_ttl: Duration,
    ) -> Result<(Client, i32, LeaseClock, String), SourceError> {
        let member_of = grant.member_of.as_str();
        let client =
            connect(&self.alias, &self.admin)
                .await
                .map_err(|reason| SourceError::Connect {
                    alias: self.alias.clone(),
                    reason,
                })?;
        let started_at = Instant::now();
        let started_with_suspend = super::suspend_clock_now();
        let server = client
            .query_one(
                "SELECT current_setting('server_version'),
                        current_setting('server_version_num')::int,
                        now(),
                        rolsuper,
                        rolinherit
                 FROM pg_roles
                 WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(create_failed)?;
        let (version, version_num, started, superuser, inherit): (
            String,
            i32,
            SystemTime,
            bool,
            bool,
        ) = (
            server.get(0),
            server.get(1),
            server.get(2),
            server.get(3),
            server.get(4),
        );
        check_mint_prerequisites(
            &self.alias,
            self.admin.user(),
            &version,
            version_num,
            superuser,
            inherit,
        )?;
        match inspect_group_role(&client, member_of)
            .await
            .map_err(create_failed)?
        {
            GroupRoleStatus::Safe => {}
            GroupRoleStatus::Missing => {
                return Err(SourceError::CreateLogin {
                    reason: format!("group role `{member_of}` doesn't exist"),
                });
            }
            GroupRoleStatus::Dangerous(reason) => {
                return Err(SourceError::DangerousRole {
                    member_of: member_of.to_owned(),
                    reason,
                });
            }
        }
        // A write login's teardown runs REASSIGN OWNED, so a login it couldn't run would stay
        // behind for good. Refused here, before the ledger entry or the login exists.
        if !grant.read_only {
            match read_admin_grants(&client, member_of, version_num)
                .await
                .map_err(create_failed)?
            {
                None => {
                    return Err(SourceError::CreateLogin {
                        reason: format!("group role `{member_of}` doesn't exist"),
                    });
                }
                Some(AdminGrants {
                    set: Some(false), ..
                }) => {
                    return Err(SourceError::AdminCannotReassign {
                        alias: self.alias.clone(),
                        user: self.admin.user().to_owned(),
                        member_of: member_of.to_owned(),
                    });
                }
                Some(_) => {}
            }
        }
        let clock = LeaseClock::new(started, started_at, started_with_suspend, max_ttl);
        let valid_until = timestamp_literal(&client, clock.next_expiry(started))
            .await
            .map_err(create_failed)?;
        Ok((client, version_num, clock, valid_until))
    }
}

async fn lock_creation<'a>(
    client: &'a mut Client,
    user: &str,
) -> Result<tokio_postgres::Transaction<'a>, SourceError> {
    let transaction = client.transaction().await.map_err(create_failed)?;
    transaction
        .batch_execute(&format!(
            "SET LOCAL statement_timeout = '{}ms'",
            ADMIN_MINT_TIMEOUT.as_millis()
        ))
        .await
        .map_err(create_failed)?;
    // Acquire the lock before publishing the ledger entry. A later sweep can
    // then distinguish a missing role from an unsettled creation transaction.
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&user],
        )
        .await
        .map_err(create_failed)?;
    Ok(transaction)
}

fn create_failed(err: tokio_postgres::Error) -> SourceError {
    SourceError::CreateLogin {
        reason: describe_sql_error(&err),
    }
}

fn mint_timed_out(_: tokio::time::error::Elapsed) -> SourceError {
    SourceError::CreateLogin {
        reason: format!("no answer within {} s", ADMIN_MINT_TIMEOUT.as_secs()),
    }
}

/// `time` as a quoted literal that `VALID UNTIL` takes, to the microsecond.
async fn timestamp_literal(
    client: &Client,
    time: SystemTime,
) -> Result<String, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT to_char($1::timestamptz AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
            &[&time],
        )
        .await?;
    Ok(quote_literal(row.get(0)))
}

/// Tracks an in-flight `ALTER ROLE ... VALID UNTIL` so teardown cancels it on PostgreSQL
/// and waits for it to settle before running `DROP ROLE`.
#[derive(Debug, Default)]
pub(super) struct ActivePush {
    next_id: AtomicU64,
    state: Mutex<ActivePushState>,
}

#[derive(Debug, Default)]
struct ActivePushState {
    closed: bool,
    in_flight: Option<InFlightPush>,
}

#[derive(Clone)]
struct InFlightPush {
    id: u64,
    cancel_token: CancelToken,
    cancel_tls: Option<tls::MakeRustlsConnect>,
    done: watch::Receiver<bool>,
}

impl fmt::Debug for InFlightPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InFlightPush")
            .field("id", &self.id)
            .finish()
    }
}

struct PushGuard {
    active_push: Arc<ActivePush>,
    id: u64,
    done: watch::Sender<bool>,
}

impl Drop for PushGuard {
    fn drop(&mut self) {
        let mut state = self
            .active_push
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if state.in_flight.as_ref().is_some_and(|p| p.id == self.id) {
            state.in_flight = None;
        }
        drop(state);
        let _ = self.done.send(true);
    }
}

impl ActivePush {
    fn begin(
        self: &Arc<Self>,
        cancel_token: CancelToken,
        cancel_tls: Option<tls::MakeRustlsConnect>,
    ) -> Option<PushGuard> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (done_tx, done_rx) = watch::channel(false);
        state.in_flight = Some(InFlightPush {
            id,
            cancel_token,
            cancel_tls,
            done: done_rx,
        });
        Some(PushGuard {
            active_push: Arc::clone(self),
            id,
            done: done_tx,
        })
    }

    /// Prevents any new `ALTER ROLE` push from starting and cancels an in-flight one.
    pub(super) async fn close_and_cancel(&self) {
        let in_flight = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.closed = true;
            state.in_flight.take()
        };
        if let Some(in_flight) = in_flight {
            cancel_and_wait(in_flight).await;
        }
    }

    /// Cancels the currently running `ALTER ROLE` (for example after a push timeout) while
    /// allowing later pushes to run. Leaves the record in place until `PushGuard` drops, so
    /// a concurrent teardown still waits for the push to settle.
    pub(super) async fn cancel_in_flight(&self) {
        let in_flight = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.in_flight.clone()
        };
        if let Some(in_flight) = in_flight {
            cancel_and_wait(in_flight).await;
        }
    }
}

async fn cancel_and_wait(mut in_flight: InFlightPush) {
    let deadline = tokio::time::Instant::now() + ADMIN_CONNECT_TIMEOUT;
    loop {
        if *in_flight.done.borrow() {
            return;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        let cancel = async {
            match in_flight.cancel_tls.clone() {
                Some(tls) => in_flight.cancel_token.cancel_query(tls).await,
                None => in_flight.cancel_token.cancel_query(NoTls).await,
            }
        };
        let _ = tokio::time::timeout(remaining.min(Duration::from_secs(2)), cancel).await;
        let wait = remaining.min(Duration::from_millis(200));
        if tokio::time::timeout(wait, in_flight.done.changed())
            .await
            .is_ok()
            && *in_flight.done.borrow()
        {
            return;
        }
    }
}

/// Outcome of one expiry push against the database.
pub(super) enum PushOutcome {
    /// The login's expiry is at least `expiry`, as of `database_now`.
    Pushed {
        database_now: SystemTime,
        expiry: SystemTime,
    },
    /// The database's clock has already passed `max_ttl`.
    ReachedMaxTtl,
    /// The login no longer exists (for instance, dropped by a sweep after a long outage).
    AlreadyGone,
}

/// Moves the login's `VALID UNTIL` to its next expiry, over a fresh admin connection.
/// Always checks that the login still exists and reads the database's clock, skipping
/// `ALTER ROLE` once the expiry has already reached the cap.
pub(super) async fn push_expiry(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
    user: &str,
    clock: &LeaseClock,
    confirmed_expiry: SystemTime,
    active_push: &Arc<ActivePush>,
) -> Result<PushOutcome, SourceError> {
    let push_failed = |reason| SourceError::PushExpiry {
        login: user.to_owned(),
        reason,
    };
    let (client, cancel_tls) = connect_with_cancel_tls(alias, admin)
        .await
        .map_err(|reason| {
            push_failed(format!(
                "can't connect as the admin login for `{alias}`: {reason}"
            ))
        })?;
    let sql_failed = |err: tokio_postgres::Error| push_failed(describe_sql_error(&err));
    let row = client
        .query_one(
            "SELECT now(), EXISTS (SELECT FROM pg_roles WHERE rolname = $1)",
            &[&user],
        )
        .await
        .map_err(sql_failed)?;
    let database_now: SystemTime = row.get(0);
    let exists: bool = row.get(1);
    if !exists {
        return Ok(PushOutcome::AlreadyGone);
    }
    if clock.remaining(database_now).is_none() {
        return Ok(PushOutcome::ReachedMaxTtl);
    }
    let expiry = clock.next_expiry(database_now);
    if expiry <= confirmed_expiry {
        return Ok(PushOutcome::Pushed {
            database_now,
            expiry: confirmed_expiry,
        });
    }
    let valid_until = timestamp_literal(&client, expiry)
        .await
        .map_err(sql_failed)?;
    let Some(guard) = active_push.begin(client.cancel_token(), cancel_tls) else {
        // Teardown already closed pushes; leave the rest to teardown.
        return Ok(PushOutcome::ReachedMaxTtl);
    };
    let sql = format!("ALTER ROLE {} VALID UNTIL {valid_until}", quote_ident(user));
    // Run in its own task so dropping push_expiry (on abort/timeout) doesn't drop the client
    // before ActivePush::close_and_cancel cancels the server-side statement and observes completion.
    let result = tokio::spawn(async move {
        let _guard = guard;
        client.batch_execute(&sql).await
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(PushOutcome::Pushed {
            database_now,
            expiry,
        }),
        Ok(Err(err)) => {
            if err
                .as_db_error()
                .is_some_and(|db| *db.code() == SqlState::UNDEFINED_OBJECT)
            {
                return Ok(PushOutcome::AlreadyGone);
            }
            Err(sql_failed(err))
        }
        Err(_) => Err(push_failed(
            "the expiry push task stopped unexpectedly".to_owned(),
        )),
    }
}

/// Refuses versions and admin settings under which dbvalet can't drop the login it creates.
fn check_mint_prerequisites(
    alias: &DatabaseAlias,
    user: &str,
    version: &str,
    version_num: i32,
    superuser: bool,
    inherit: bool,
) -> Result<(), SourceError> {
    if version_num < MINIMUM_SERVER_VERSION_NUM {
        return Err(SourceError::TooOld {
            version: version.to_owned(),
        });
    }
    if !superuser && version_num < CREATEROLE_SELF_GRANT_VERSION_NUM && !inherit {
        return Err(SourceError::AdminNoInherit {
            alias: alias.clone(),
            user: user.to_owned(),
            quoted: quote_ident(user),
            version: version.to_owned(),
        });
    }
    Ok(())
}

/// [`LOGIN_PREFIX`] and 16 lowercase base32 characters, safe unquoted in SQL.
fn new_login_name() -> Result<String, getrandom::Error> {
    Ok(format!(
        "{LOGIN_PREFIX}{}",
        random_base32(RUN_ID_BYTES)?.expose_secret()
    ))
}

/// Ends the login's sessions, clears or reassigns what it owns, and drops it.
pub(super) async fn drop_login(
    alias: &DatabaseAlias,
    admin: &AdminLogin,
    user: &str,
    role_oid: Option<u32>,
    member_of: &str,
    read_only: bool,
) -> Result<(), SourceError> {
    let drop_failed = |reason| SourceError::DropLogin {
        login: user.to_owned(),
        reason,
    };
    let client = connect(alias, admin).await.map_err(drop_failed)?;
    end_sessions(&client, user, role_oid)
        .await
        .map_err(drop_failed)?;
    let reassign_to = (!read_only).then_some(member_of);
    execute_drop(&client, user, reassign_to)
        .await
        .map(|_| ())
        .map_err(drop_failed)
}

/// Drops the login of an entry whose run has ended, then removes the entry.
async fn sweep_orphan(client: &Client, entry: ledger::Entry, report: &mut SweepReport) {
    let login = entry.login().to_owned();
    match sweep_login(client, &login, entry.read_only()).await {
        Ok(None) => {}
        Ok(Some(existed)) => match entry.remove() {
            Ok(()) if existed => report.dropped.push(login),
            Ok(()) => report.already_gone.push(login),
            Err(err) => report.failures.push(err.into()),
        },
        Err(reason) => report
            .failures
            .push(SourceError::DropLeftoverLogin { login, reason }),
    }
}

async fn sweep_login(
    client: &Client,
    login: &str,
    read_only: Option<bool>,
) -> Result<Option<bool>, String> {
    // The creating connection may still hold its lock after dbvalet has gone away.
    // The existence check needs a fresh snapshot taken after that lock is gone.
    let ready: bool = client
        .query_one(
            "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))",
            &[&login],
        )
        .await
        .map_err(|err| describe_sql_error(&err))?
        .get(0);
    if !ready {
        return Ok(None);
    }
    drop_leftover_login(client, login, read_only)
        .await
        .map(Some)
}

/// Drops a login an ended run left behind, reading from the database what its lease knew.
/// `ledger_read_only` is the ledger entry's word, when there is one. Returns whether the
/// login still existed.
async fn drop_leftover_login(
    client: &Client,
    user: &str,
    ledger_read_only: Option<bool>,
) -> Result<bool, String> {
    let Some(role) = client
        .query_opt(
            "SELECT r.oid,
                    COALESCE('default_transaction_read_only=on' = ANY (r.rolconfig), false),
                    ARRAY(SELECT DISTINCT g.rolname::text
                          FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                          WHERE m.member = r.oid)
             FROM pg_roles r
             WHERE r.rolname = $1 AND r.rolcanlogin",
            &[&user],
        )
        .await
        .map_err(|err| describe_sql_error(&err))?
    else {
        return Ok(false);
    };
    let role_oid: u32 = role.get(0);
    // The login can change its own settings in either direction, but not the ledger.
    let read_only = ledger_read_only.unwrap_or_else(|| role.get(1));
    let groups: Vec<String> = role.get(2);
    let reassign_to = match (read_only, groups.as_slice()) {
        (true, _) => None,
        (false, [group]) => Some(group.as_str()),
        (false, []) => {
            return Err("it belongs to no group role that could take over what it created".into());
        }
        (false, _) => {
            return Err(format!(
                "it belongs to {} group roles, so dbvalet can't tell which one should own \
                 what it created",
                groups.len()
            ));
        }
    };
    end_sessions(client, user, Some(role_oid)).await?;
    execute_drop(client, user, reassign_to).await
}

/// Runs [`drop_login_sql`]. Returns false when the login was already gone, as when a sweep
/// elsewhere dropped it first.
async fn execute_drop(
    client: &Client,
    user: &str,
    reassign_to: Option<&str>,
) -> Result<bool, String> {
    let Err(err) = client
        .batch_execute(&drop_login_sql(user, reassign_to))
        .await
    else {
        return Ok(true);
    };
    let still_exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)",
            &[&user],
        )
        .await
        .map_err(|err| describe_sql_error(&err))?
        .get(0);
    if still_exists {
        Err(describe_sql_error(&err))
    } else {
        Ok(false)
    }
}

async fn end_sessions(client: &Client, user: &str, role_oid: Option<u32>) -> Result<(), String> {
    let mut remaining: i64 = 0;
    for _ in 0..SESSION_END_PASSES {
        client
            .query(
                "SELECT pg_terminate_backend(pid, $3)
                 FROM pg_stat_activity
                 WHERE usename = $1 OR ($2::oid IS NOT NULL AND usesysid = $2)",
                &[&user, &role_oid, &SESSION_END_TIMEOUT_MS],
            )
            .await
            .map_err(|err| describe_sql_error(&err))?;
        // pg_terminate_backend returns false rather than failing, so count what is left.
        remaining = client
            .query_one(
                "SELECT count(*)
                 FROM pg_stat_activity
                 WHERE usename = $1 OR ($2::oid IS NOT NULL AND usesysid = $2)",
                &[&user, &role_oid],
            )
            .await
            .map_err(|err| describe_sql_error(&err))?
            .get(0);
        if remaining == 0 {
            return Ok(());
        }
    }
    Err(format!(
        "{remaining} of its sessions were still open after {SESSION_END_PASSES} rounds of \
         pg_terminate_backend"
    ))
}

/// Without a group to reassign to, as for a read-only login, everything the login owns is
/// dropped, including anything created despite read-only defaults (such as large objects
/// before PostgreSQL 16).
fn drop_login_sql(user: &str, reassign_to: Option<&str>) -> String {
    let login = quote_ident(user);
    match reassign_to {
        None => format!(
            "DROP OWNED BY {login};
             DROP ROLE {login};"
        ),
        Some(group) => format!(
            "REASSIGN OWNED BY {login} TO {group};
             DROP OWNED BY {login};
             DROP ROLE {login};",
            group = quote_ident(group)
        ),
    }
}

fn quote_ident(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn quote_literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The server's message and SQLSTATE: admin SQL errors never quote the statement text.
fn describe_sql_error(err: &tokio_postgres::Error) -> String {
    match err.as_db_error() {
        Some(db) => format!("{} (SQLSTATE {})", db.message(), db.code().code()),
        None => "the connection to PostgreSQL ended before it answered".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias() -> DatabaseAlias {
        "app".parse().unwrap()
    }

    #[test]
    fn a_new_login_name_is_dbvalet_and_16_lowercase_base32_characters() {
        let name = new_login_name().unwrap();
        let run_id = name.strip_prefix("dbvalet_").unwrap();
        assert_eq!(run_id.len(), 16, "{name}");
        assert!(
            run_id
                .bytes()
                .all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')),
            "{name}"
        );
    }

    #[test]
    fn the_login_name_pattern_accepts_a_new_login_name() {
        assert!(is_login_name(&new_login_name().unwrap()));
        assert!(is_login_name("dbvalet_abcdefghijklmnop"));
        assert!(is_login_name("dbvalet_234567234567zzzz"));
    }

    #[test]
    fn the_login_name_pattern_rejects_dbvalet_reader_and_near_misses() {
        assert!(!is_login_name("dbvalet_reader"));
        assert!(!is_login_name("dbvalet_abcdefghijklmno"));
        assert!(!is_login_name("dbvalet_abcdefghijklmnopq"));
        assert!(!is_login_name("dbvalet_ABCDEFGHIJKLMNOP"));
        assert!(!is_login_name("dbvalet_abcdefghijklmno1"));
        assert!(!is_login_name("dbvalet_abcdefghijklmno\u{e9}"));
        assert!(!is_login_name("xdbvalet_abcdefghijklmnop"));
    }

    #[test]
    fn mint_refuses_postgresql_14_as_end_of_life() {
        let err =
            check_mint_prerequisites(&alias(), "super", "14.25", 140025, true, true).unwrap_err();
        assert!(matches!(err, SourceError::TooOld { .. }));
        assert_eq!(
            err.to_string(),
            "PostgreSQL 14.25 is end-of-life: dbvalet needs 15 or later"
        );
    }

    #[test]
    fn mint_refuses_a_noinherit_non_superuser_before_postgresql_16() {
        let err = check_mint_prerequisites(&alias(), "app-admin", "15.8", 150008, false, false)
            .unwrap_err();
        let message = err.to_string();
        assert!(matches!(err, SourceError::AdminNoInherit { .. }));
        assert!(
            message.contains("ALTER ROLE \"app-admin\" INHERIT"),
            "{message}"
        );
        assert!(message.contains("dbvalet doctor app"), "{message}");
    }

    #[test]
    fn mint_allows_supported_admins_on_postgresql_15_and_16() {
        assert!(check_mint_prerequisites(&alias(), "super", "15.20", 150020, true, false).is_ok());
        assert!(check_mint_prerequisites(&alias(), "admin", "15.20", 150020, false, true).is_ok());
        assert!(check_mint_prerequisites(&alias(), "admin", "16.0", 160000, false, false).is_ok());
    }

    #[test]
    fn dropping_a_read_only_login_skips_reassign_owned() {
        let sql = drop_login_sql("dbvalet_aaaaaaaaaaaaaaaa", None);
        assert!(!sql.contains("REASSIGN OWNED"), "{sql}");
        assert!(
            sql.contains("DROP OWNED BY \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
        assert!(
            sql.contains("DROP ROLE \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
    }

    #[test]
    fn dropping_a_writable_login_reassigns_owned_objects_to_its_group() {
        let sql = drop_login_sql("dbvalet_aaaaaaaaaaaaaaaa", Some("dbvalet_writer"));
        assert!(
            sql.contains("REASSIGN OWNED BY \"dbvalet_aaaaaaaaaaaaaaaa\" TO \"dbvalet_writer\";"),
            "{sql}"
        );
        assert!(
            sql.contains("DROP OWNED BY \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
        assert!(
            sql.contains("DROP ROLE \"dbvalet_aaaaaaaaaaaaaaaa\";"),
            "{sql}"
        );
    }
}
