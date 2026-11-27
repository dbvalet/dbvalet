//! Temporary logins created with the admin login, over admin SQL.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use secrecy::ExposeSecret;
use tokio::sync::watch;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{CancelToken, Client, NoTls};

use super::{
    CredentialSource, Lease, LeaseClock, LiveLease, MintOutcome, SourceError, SweepReport,
    UpstreamLogin,
};
use crate::config::RoleGrant;
use crate::endpoint::Tls;
use crate::keychain::{self, AdminLogin};
use crate::ledger::{self, State};
use crate::{DatabaseAlias, LOGIN_PREFIX, RUN_ID_BYTES, is_login_name, random_base32};

/// For the whole admin connection: TCP, startup, authentication and its first setting.
const ADMIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ADMIN_MINT_TIMEOUT: Duration = Duration::from_secs(15);
/// So a lock someone else holds on what a login owns fails that drop instead of stalling it.
const ADMIN_LOCK_TIMEOUT: &str = "10s";
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
/// Walks a group role and every ancestor it belongs to; `UNION` deduplicates diamond grants and
/// prevents cycles. Includes the starting role so a missing role returns zero rows.
const GROUP_ROLE_GRAPH: &str = "
    WITH RECURSIVE chain AS (
        SELECT oid, rolname, rolsuper, rolcreaterole, rolbypassrls, rolreplication
        FROM pg_roles
        WHERE rolname = $1
        UNION
        SELECT r.oid, r.rolname, r.rolsuper, r.rolcreaterole, r.rolbypassrls, r.rolreplication
        FROM chain c
        JOIN pg_auth_members m ON m.member = c.oid
        JOIN pg_roles r ON r.oid = m.roleid
    )
    SELECT rolname::text, rolsuper, rolcreaterole, rolbypassrls, rolreplication
    FROM chain
    WHERE rolname = $1
       OR rolsuper
       OR rolcreaterole
       OR rolbypassrls
       OR rolreplication
       OR starts_with(rolname::text, 'pg_')
    ORDER BY rolname::text ASC";

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
        let preparing =
            tokio::time::timeout_at(setup_deadline, self.prepare_mint(&grant.member_of, max_ttl));
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
            UpstreamLogin { user, password },
            valid_until.trim_matches('\'').to_owned(),
            live,
            clock,
        )))
    }
}

impl DirectSource {
    async fn prepare_mint(
        &self,
        member_of: &str,
        max_ttl: Duration,
    ) -> Result<(Client, i32, LeaseClock, String), SourceError> {
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
    fn begin(self: &Arc<Self>, cancel_token: CancelToken) -> Option<PushGuard> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (done_tx, done_rx) = watch::channel(false);
        state.in_flight = Some(InFlightPush {
            id,
            cancel_token,
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
        let _ = tokio::time::timeout(
            remaining.min(Duration::from_secs(2)),
            in_flight.cancel_token.cancel_query(NoTls),
        )
        .await;
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
    let client = connect(alias, admin).await.map_err(|reason| {
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
    let Some(guard) = active_push.begin(client.cancel_token()) else {
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

/// One line of `dbvalet doctor`'s report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub passed: bool,
    pub message: String,
}

impl Check {
    fn passed(message: String) -> Self {
        Self {
            passed: true,
            message,
        }
    }

    fn failed(message: String) -> Self {
        Self {
            passed: false,
            message,
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.passed { "ok  " } else { "FAIL" };
        write!(f, "{status} {}", self.message)
    }
}

/// Stops at the first failed check that later checks depend on.
pub async fn doctor(
    alias: &DatabaseAlias,
    allow_plaintext: bool,
    roles: &BTreeMap<String, RoleGrant>,
) -> Vec<Check> {
    let admin = match keychain::load(alias, allow_plaintext) {
        Ok(admin) => admin,
        Err(err) => return vec![Check::failed(err.to_string())],
    };
    let mut checks = vec![Check::passed(format!(
        "the keychain holds an admin login for `{alias}`"
    ))];

    let user = admin.user();
    let client = match connect(alias, &admin).await {
        Ok(client) => client,
        Err(reason) => {
            checks.push(Check::failed(format!(
                "`{user}` can't connect to {}: {reason}",
                admin.endpoint()
            )));
            return checks;
        }
    };
    checks.push(Check::passed(format!(
        "`{user}` connects to {}",
        admin.endpoint()
    )));

    match read_rights(&client).await {
        Ok(rights) => {
            checks.push(version_check(&rights));
            checks.push(create_role_check(user, &rights));
            checks.push(end_sessions_check(user, &rights));
            for (role_name, grant) in roles {
                let check = match inspect_group_role(&client, &grant.member_of).await {
                    Ok(status) => group_role_check(role_name, &grant.member_of, status),
                    Err(err) => Check::failed(format!(
                        "can't check role `{role_name}` (`{}`): {}",
                        grant.member_of,
                        describe_query_error(&err)
                    )),
                };
                checks.push(check);
            }
        }
        Err(err) => checks.push(Check::failed(format!(
            "can't read the rights of `{user}`: {}",
            describe_query_error(&err)
        ))),
    }
    checks
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleEntry {
    name: String,
    superuser: bool,
    create_role: bool,
    bypass_rls: bool,
    replication: bool,
}

impl RoleEntry {
    fn dangerous_attributes(&self) -> Vec<&'static str> {
        let mut attributes = Vec::new();
        if self.superuser {
            attributes.push("SUPERUSER");
        }
        if self.create_role {
            attributes.push("CREATEROLE");
        }
        if self.bypass_rls {
            attributes.push("BYPASSRLS");
        }
        if self.replication {
            attributes.push("REPLICATION");
        }
        attributes
    }

    fn is_builtin_pg_role(&self) -> bool {
        self.name.starts_with("pg_")
    }

    fn is_dangerous(&self) -> bool {
        self.superuser
            || self.create_role
            || self.bypass_rls
            || self.replication
            || self.is_builtin_pg_role()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GroupRoleStatus {
    Safe,
    Missing,
    Dangerous(String),
}

async fn inspect_group_role(
    client: &Client,
    member_of: &str,
) -> Result<GroupRoleStatus, tokio_postgres::Error> {
    let rows = client.query(GROUP_ROLE_GRAPH, &[&member_of]).await?;
    let entries: Vec<RoleEntry> = rows
        .into_iter()
        .map(|row| RoleEntry {
            name: row.get(0),
            superuser: row.get(1),
            create_role: row.get(2),
            bypass_rls: row.get(3),
            replication: row.get(4),
        })
        .collect();
    Ok(classify_group_role(member_of, &entries))
}

fn classify_group_role(member_of: &str, entries: &[RoleEntry]) -> GroupRoleStatus {
    if entries.is_empty() {
        return GroupRoleStatus::Missing;
    }
    let mut dangerous: Vec<&RoleEntry> = entries
        .iter()
        .filter(|entry| entry.is_dangerous())
        .collect();
    if dangerous.is_empty() {
        return GroupRoleStatus::Safe;
    }
    dangerous.sort_by(|a, b| {
        (b.name == member_of)
            .cmp(&(a.name == member_of))
            .then_with(|| a.name.cmp(&b.name))
    });
    let reasons: Vec<String> = dangerous
        .into_iter()
        .map(|entry| describe_role_danger(member_of, entry))
        .collect();
    GroupRoleStatus::Dangerous(reasons.join("; "))
}

fn describe_role_danger(member_of: &str, entry: &RoleEntry) -> String {
    let attributes = entry.dangerous_attributes();
    let builtin = entry.is_builtin_pg_role();
    if entry.name == member_of {
        return match (!attributes.is_empty(), builtin) {
            (true, false) => format!("has {}", attributes.join(", ")),
            (false, true) => "is a built-in pg_* role".to_owned(),
            (true, true) => {
                format!("is a built-in pg_* role and has {}", attributes.join(", "))
            }
            (false, false) => unreachable!("describe_role_danger only receives dangerous roles"),
        };
    }
    let mut traits = attributes;
    if builtin {
        traits.push("built-in pg_* role");
    }
    format!("is a member of `{}` ({})", entry.name, traits.join(", "))
}

fn group_role_check(role_name: &str, member_of: &str, status: GroupRoleStatus) -> Check {
    match status {
        GroupRoleStatus::Safe => Check::passed(format!(
            "role `{role_name}` (`{member_of}`) has no dangerous attributes or memberships"
        )),
        GroupRoleStatus::Missing => Check::failed(format!(
            "role `{role_name}` (`{member_of}`) doesn't exist in PostgreSQL"
        )),
        GroupRoleStatus::Dangerous(reason) => Check::failed(format!(
            "role `{role_name}` (`{member_of}`) is refused: {reason}"
        )),
    }
}

struct Rights {
    server_version: String,
    server_version_num: i32,
    superuser: bool,
    create_role: bool,
    inherit: bool,
    signal_backend: bool,
    signal_backend_member: bool,
}

async fn read_rights(client: &Client) -> Result<Rights, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT current_setting('server_version'),
                    current_setting('server_version_num')::int,
                    rolsuper,
                    rolcreaterole,
                    rolinherit,
                    pg_has_role(current_user, 'pg_signal_backend', 'USAGE'),
                    pg_has_role(current_user, 'pg_signal_backend', 'MEMBER')
             FROM pg_roles
             WHERE rolname = current_user",
            &[],
        )
        .await?;
    Ok(Rights {
        server_version: row.get(0),
        server_version_num: row.get(1),
        superuser: row.get(2),
        create_role: row.get(3),
        inherit: row.get(4),
        signal_backend: row.get(5),
        signal_backend_member: row.get(6),
    })
}

fn version_check(rights: &Rights) -> Check {
    let version = &rights.server_version;
    if rights.server_version_num >= MINIMUM_SERVER_VERSION_NUM {
        Check::passed(format!("PostgreSQL {version} is 15 or later"))
    } else {
        Check::failed(format!(
            "PostgreSQL {version} is end-of-life: dbvalet needs 15 or later"
        ))
    }
}

fn create_role_check(user: &str, rights: &Rights) -> Check {
    if rights.superuser {
        Check::passed(format!("`{user}` is a superuser"))
    } else if rights.create_role {
        Check::passed(format!("`{user}` has CREATEROLE"))
    } else {
        let quoted = quote_ident(user);
        Check::failed(format!(
            "`{user}` has neither SUPERUSER nor CREATEROLE: as a superuser, \
             run ALTER ROLE {quoted} CREATEROLE, or use your provider's admin login"
        ))
    }
}

fn end_sessions_check(user: &str, rights: &Rights) -> Check {
    if rights.superuser {
        return Check::passed(format!(
            "`{user}` can end other roles' sessions, as a superuser"
        ));
    }
    if rights.signal_backend {
        return Check::passed(format!(
            "`{user}` can end other roles' sessions, through pg_signal_backend"
        ));
    }
    let quoted = quote_ident(user);
    if rights.create_role {
        if rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
            return Check::passed(format!(
                "`{user}` can end the sessions of logins it creates, \
                 because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
            ));
        }
        if rights.inherit {
            return Check::passed(format!(
                "`{user}` can end the sessions of logins it creates, \
                 because dbvalet adds it as a member of each login"
            ));
        }
        return Check::failed(format!(
            "`{user}` can't end the sessions of logins it creates because it has NOINHERIT: \
             run ALTER ROLE {quoted} INHERIT"
        ));
    }
    if rights.server_version_num >= CREATEROLE_SELF_GRANT_VERSION_NUM {
        let grant_fix = if rights.signal_backend_member || !rights.inherit {
            format!("GRANT pg_signal_backend TO {quoted} WITH INHERIT TRUE")
        } else {
            format!("GRANT pg_signal_backend TO {quoted}")
        };
        return Check::failed(format!(
            "`{user}` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE {quoted} CREATEROLE, or {grant_fix}"
        ));
    }
    let fix = if !rights.inherit && rights.signal_backend_member {
        format!("ALTER ROLE {quoted} INHERIT")
    } else if !rights.inherit {
        format!(
            "ALTER ROLE {quoted} CREATEROLE INHERIT, \
             or GRANT pg_signal_backend TO {quoted} and ALTER ROLE {quoted} INHERIT"
        )
    } else {
        format!("ALTER ROLE {quoted} CREATEROLE, or GRANT pg_signal_backend TO {quoted}")
    };
    Check::failed(format!(
        "`{user}` can't end other roles' sessions: as a superuser, run {fix}"
    ))
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

async fn connect(alias: &DatabaseAlias, admin: &AdminLogin) -> Result<Client, String> {
    let endpoint = admin.endpoint();
    if endpoint.tls() == Tls::VerifyFull {
        return Err("TLS connections aren't supported yet: \
                    use --allow-plaintext with a database on localhost"
            .to_owned());
    }
    let mut config = tokio_postgres::Config::new();
    config
        .host(endpoint.host())
        .port(endpoint.port())
        .dbname(endpoint.database())
        .user(admin.user())
        .password(admin.password().expose_secret())
        .ssl_mode(SslMode::Disable);
    let connecting = async {
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|err| describe_connect_error(alias, admin, &err))?;
        tokio::spawn(connection);
        client
            .batch_execute(&format!("SET lock_timeout = '{ADMIN_LOCK_TIMEOUT}'"))
            .await
            .map_err(|err| describe_sql_error(&err))?;
        Ok(client)
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

fn describe_query_error(err: &tokio_postgres::Error) -> String {
    if let Some(db) = err.as_db_error() {
        return format!(
            "the server returned SQLSTATE {}: check the admin role's access to pg_roles",
            db.code().code()
        );
    }
    "the connection ended before PostgreSQL answered: try running `dbvalet doctor` again".to_owned()
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

    fn pg(server_version: &str, server_version_num: i32) -> Rights {
        Rights {
            server_version: server_version.to_owned(),
            server_version_num,
            superuser: false,
            create_role: false,
            inherit: true,
            signal_backend: false,
            signal_backend_member: false,
        }
    }

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
    fn postgresql_14_fails_the_version_check_naming_15_and_end_of_life() {
        let check = version_check(&Rights {
            superuser: true,
            ..pg("14.25", 140025)
        });
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "PostgreSQL 14.25 is end-of-life: dbvalet needs 15 or later"
        );
    }

    #[test]
    fn postgresql_15_passes_the_version_check() {
        let check = version_check(&Rights {
            superuser: true,
            ..pg("15.0", 150000)
        });
        assert!(check.passed);
        assert_eq!(check.message, "PostgreSQL 15.0 is 15 or later");
    }

    #[test]
    fn a_superuser_passes_the_create_role_check() {
        let check = create_role_check(
            "admin",
            &Rights {
                superuser: true,
                ..pg("16.4", 160004)
            },
        );
        assert!(check.passed);
        assert_eq!(check.message, "`admin` is a superuser");
    }

    #[test]
    fn a_createrole_admin_passes_the_create_role_check() {
        let check = create_role_check(
            "admin",
            &Rights {
                create_role: true,
                ..pg("16.4", 160004)
            },
        );
        assert!(check.passed);
        assert_eq!(check.message, "`admin` has CREATEROLE");
    }

    #[test]
    fn an_admin_without_createrole_fails_with_a_quoted_alter_role_command() {
        let check = create_role_check("postgres.proj-1", &pg("16.4", 160004));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`postgres.proj-1` has neither SUPERUSER nor CREATEROLE: as a superuser, \
             run ALTER ROLE \"postgres.proj-1\" CREATEROLE, or use your provider's admin login"
        );
    }

    #[test]
    fn a_superuser_can_end_sessions() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                superuser: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, as a superuser"
        );
    }

    #[test]
    fn an_admin_with_pg_signal_backend_can_end_sessions_on_postgresql_15() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                signal_backend: true,
                signal_backend_member: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end other roles' sessions, through pg_signal_backend"
        );
    }

    #[test]
    fn a_createrole_admin_on_postgresql_16_can_end_sessions() {
        let check = end_sessions_check(
            "admin",
            &Rights {
                create_role: true,
                ..pg("16.0", 160000)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`admin` can end the sessions of logins it creates, \
             because dbvalet sets createrole_self_grant on PostgreSQL 16 and later"
        );
    }

    #[test]
    fn a_createrole_inherit_admin_on_postgresql_15_can_end_sessions() {
        let check = end_sessions_check(
            "app-admin",
            &Rights {
                create_role: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can end the sessions of logins it creates, \
             because dbvalet adds it as a member of each login"
        );
    }

    #[test]
    fn a_noinherit_createrole_admin_on_postgresql_15_is_told_to_enable_inherit() {
        let check = end_sessions_check(
            "app-admin",
            &Rights {
                create_role: true,
                inherit: false,
                ..pg("15.20", 150020)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`app-admin` can't end the sessions of logins it creates because it has NOINHERIT: \
             run ALTER ROLE \"app-admin\" INHERIT"
        );
    }

    #[test]
    fn a_plain_admin_on_postgresql_15_is_told_to_add_createrole_or_grant_pg_signal_backend() {
        let check = end_sessions_check("plain", &pg("15.20", 150020));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"plain\""
        );
    }

    #[test]
    fn a_noinherit_plain_admin_holding_pg_signal_backend_on_postgresql_15_is_told_to_enable_inherit()
     {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                signal_backend_member: true,
                ..pg("15.20", 150020)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" INHERIT"
        );
    }

    #[test]
    fn a_noinherit_plain_admin_on_postgresql_15_is_told_as_superuser_to_add_createrole_and_inherit()
    {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                ..pg("15.20", 150020)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" CREATEROLE INHERIT, \
             or GRANT pg_signal_backend TO \"plain\" and ALTER ROLE \"plain\" INHERIT"
        );
    }

    #[test]
    fn an_admin_without_createrole_on_postgresql_16_is_told_to_add_createrole_first() {
        let check = end_sessions_check("Db\"Admin", &pg("16.4", 160004));
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`Db\"Admin` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"Db\"\"Admin\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"Db\"\"Admin\""
        );
    }

    #[test]
    fn a_noinherit_admin_without_createrole_on_postgresql_16_is_told_grant_with_inherit_true() {
        let check = end_sessions_check(
            "plain",
            &Rights {
                inherit: false,
                signal_backend_member: true,
                ..pg("17.0", 170000)
            },
        );
        assert!(!check.passed);
        assert_eq!(
            check.message,
            "`plain` can't end other roles' sessions: \
             as a superuser, run ALTER ROLE \"plain\" CREATEROLE, \
             or GRANT pg_signal_backend TO \"plain\" WITH INHERIT TRUE"
        );
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

    fn role_entry(name: &str) -> RoleEntry {
        RoleEntry {
            name: name.to_owned(),
            superuser: false,
            create_role: false,
            bypass_rls: false,
            replication: false,
        }
    }

    #[test]
    fn a_plain_group_role_and_non_pg_prefix_names_are_safe() {
        assert_eq!(
            classify_group_role("dbvalet_reader", &[role_entry("dbvalet_reader")]),
            GroupRoleStatus::Safe
        );
        assert_eq!(
            classify_group_role("pgx_reader", &[role_entry("pgx_reader")]),
            GroupRoleStatus::Safe
        );
        assert_eq!(
            classify_group_role("app_pg_reader", &[role_entry("app_pg_reader")]),
            GroupRoleStatus::Safe
        );
    }

    #[test]
    fn an_absent_group_role_is_classified_as_missing() {
        assert_eq!(
            classify_group_role("no_such_role", &[]),
            GroupRoleStatus::Missing
        );
    }

    #[test]
    fn a_group_role_with_any_dangerous_attribute_is_refused_naming_the_attribute() {
        let super_role = RoleEntry {
            superuser: true,
            ..role_entry("super_group")
        };
        assert_eq!(
            classify_group_role("super_group", &[super_role]),
            GroupRoleStatus::Dangerous("has SUPERUSER".to_owned())
        );

        let create_role = RoleEntry {
            create_role: true,
            ..role_entry("creator_group")
        };
        assert_eq!(
            classify_group_role("creator_group", &[create_role]),
            GroupRoleStatus::Dangerous("has CREATEROLE".to_owned())
        );

        let bypass_rls = RoleEntry {
            bypass_rls: true,
            ..role_entry("rls_group")
        };
        assert_eq!(
            classify_group_role("rls_group", &[bypass_rls]),
            GroupRoleStatus::Dangerous("has BYPASSRLS".to_owned())
        );

        let replication = RoleEntry {
            replication: true,
            ..role_entry("repl_group")
        };
        assert_eq!(
            classify_group_role("repl_group", &[replication]),
            GroupRoleStatus::Dangerous("has REPLICATION".to_owned())
        );
    }

    #[test]
    fn a_builtin_pg_role_is_refused() {
        assert_eq!(
            classify_group_role(
                "pg_execute_server_program",
                &[role_entry("pg_execute_server_program")],
            ),
            GroupRoleStatus::Dangerous("is a built-in pg_* role".to_owned())
        );
    }

    #[test]
    fn a_group_role_inheriting_from_dangerous_ancestors_names_each_offending_role() {
        let entries = vec![
            role_entry("pg_execute_server_program"),
            RoleEntry {
                create_role: true,
                ..role_entry("parent_admin")
            },
            RoleEntry {
                bypass_rls: true,
                ..role_entry("app_group")
            },
        ];
        assert_eq!(
            classify_group_role("app_group", &entries),
            GroupRoleStatus::Dangerous(
                "has BYPASSRLS; \
                 is a member of `parent_admin` (CREATEROLE); \
                 is a member of `pg_execute_server_program` (built-in pg_* role)"
                    .to_owned()
            )
        );
    }

    #[test]
    fn group_role_check_formats_safe_missing_and_dangerous_results() {
        assert_eq!(
            group_role_check("reader", "dbvalet_reader", GroupRoleStatus::Safe),
            Check::passed(
                "role `reader` (`dbvalet_reader`) has no dangerous attributes or memberships"
                    .to_owned()
            )
        );
        assert_eq!(
            group_role_check("reader", "missing_group", GroupRoleStatus::Missing),
            Check::failed("role `reader` (`missing_group`) doesn't exist in PostgreSQL".to_owned())
        );
        assert_eq!(
            group_role_check(
                "ops",
                "ops_group",
                GroupRoleStatus::Dangerous(
                    "is a member of `pg_execute_server_program` (built-in pg_* role)".to_owned()
                )
            ),
            Check::failed(
                "role `ops` (`ops_group`) is refused: \
                 is a member of `pg_execute_server_program` (built-in pg_* role)"
                    .to_owned()
            )
        );
    }
}
