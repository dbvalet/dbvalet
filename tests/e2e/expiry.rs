//! The expiry push, max_ttl and concurrent drops.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::support::{
    DBVALET, SUPERUSER_URL, ledger_entry, printed, project_with_reader, run_command, runtime,
    superuser_count, superuser_sql, sweeping_alone, text, wait_for_active_query,
};

/// A lease minute in the short-timing tests, so `VALID UNTIL` is set 6 s ahead and pushed
/// every 2 s. Only a debug build of dbvalet honours the setting.
const SHORT_MINUTE_MS: &str = "400";

/// Like [`project_with_reader`], with `max_ttl_minutes` set for `alias`.
fn project_with_reader_and_max_ttl(alias: &str, max_ttl_minutes: u32) -> PathBuf {
    let dir = project_with_reader(alias);
    std::fs::write(
        dir.join("dbvalet.toml"),
        format!(
            "[databases.{alias}]\n\
             max_ttl_minutes = {max_ttl_minutes}\n\
             [databases.{alias}.roles]\n\
             reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n"
        ),
    )
    .unwrap();
    dir
}

/// Starts `dbvalet run` in `dir` with [`SHORT_MINUTE_MS`] lease minutes and the child
/// `sh -c <script>`. Returns once the child prints READY, with the run, the rest of its stdout
/// and the login name the child printed as `login=`.
///
/// The caller holds [`sweeping_alone`] until the run ends: at max_ttl the login's `VALID UNTIL`
/// passes before its own teardown drops it, and another test's superuser sweep would see it.
fn start_short_run(dir: &Path, script: &str) -> (Child, BufReader<ChildStdout>, String) {
    let mut run = Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("DBVALET_TEST_MINUTE_MS", SHORT_MINUTE_MS)
        .args(["run", "--allow-plaintext", "--", "sh", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut seen = String::new();
    while !seen.ends_with("READY\n") {
        assert_ne!(stdout.read_line(&mut seen).unwrap(), 0, "stdout: {seen}");
    }
    let login_name = printed(&seen, "login").to_owned();
    (run, stdout, login_name)
}

fn database_now() -> SystemTime {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.query_one("SELECT now()", &[]).await.unwrap().get(0)
    })
}

/// The login's `VALID UNTIL`, or `None` once the login is gone.
fn valid_until(login: &str) -> Option<SystemTime> {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query_opt(
                "SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1",
                &[&login],
            )
            .await
            .unwrap()
            .map(|row| row.get(0))
    })
}

/// Every distinct `VALID UNTIL` the login has, in order, sampled every 50 ms until it is gone.
fn expiries_until_dropped(login: &str) -> Vec<SystemTime> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut expiries: Vec<SystemTime> = Vec::new();
    while let Some(expiry) = valid_until(login) {
        assert!(
            Instant::now() < deadline,
            "{login} still exists: {expiries:?}"
        );
        if expiries.last() != Some(&expiry) {
            expiries.push(expiry);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    expiries
}

/// Waits up to `limit` for a started run to exit, killing it and failing the test after that.
fn exit_within(mut run: Child, limit: Duration) -> Output {
    let deadline = Instant::now() + limit;
    while run.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            run.kill().unwrap();
            panic!("still running after {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    run.wait_with_output().unwrap()
}

/// Waits up to 30 s for `path` to be gone.
fn wait_until_removed(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while path.exists() {
        assert!(Instant::now() < deadline, "{} still exists", path.display());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits up to 30 s for the database's clock to pass `time`.
fn wait_until_database_passes(time: SystemTime) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while database_now() <= time {
        assert!(
            Instant::now() < deadline,
            "the database's clock didn't pass {time:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits up to 30 s for the login's `VALID UNTIL` to move past `previous`.
fn wait_until_expiry_passes(login: &str, previous: SystemTime) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while valid_until(login).expect("the login was dropped before its expiry moved") <= previous {
        assert!(
            Instant::now() < deadline,
            "{login}'s expiry stayed at {previous:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn during_a_run_the_logins_expiry_moves_forward_at_each_push_and_never_past_max_ttl() {
    // 30 lease minutes of 400 ms: max_ttl is 12 s, and pushes land 8, 10 and 12 s past the start.
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-push-expiry", 30);
    let (mut run, mut stdout, login_name) =
        start_short_run(&dir, "echo \"login=$PGUSER\"; echo READY; read line");
    let max_ttl_end_bound = database_now() + Duration::from_secs(12);

    let expiries = expiries_until_dropped(&login_name);
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let finished = exit_within(run, Duration::from_secs(30));
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();

    assert!(expiries.len() >= 3, "{expiries:?}");
    assert!(
        expiries.windows(2).all(|pair| pair[0] < pair[1]),
        "{expiries:?}"
    );
    assert!(
        *expiries.last().unwrap() <= max_ttl_end_bound,
        "{expiries:?} passed {max_ttl_end_bound:?}"
    );
    assert!(
        finished.status.success(),
        "stderr: {}",
        text(&finished.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_that_reaches_max_ttl_keeps_the_command_running_drops_the_login_and_prints_a_notice() {
    // 20 lease minutes of 400 ms: max_ttl arrives 8 s after the start.
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-max-ttl-reached", 20);
    let (mut run, mut stdout, login_name) = start_short_run(
        &dir,
        "echo \"login=$PGUSER\"; \
         psql -qAtXc 'SELECT pg_sleep(60)' >/dev/null 2>&1 & \
         echo READY; read line; echo still-running; exit 7",
    );
    wait_for_active_query(&login_name);

    wait_until_removed(&ledger_entry(&dir, "e2e-max-ttl-reached", &login_name));
    let logins_at_max_ttl = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let sessions_at_max_ttl = superuser_count(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
        &login_name,
    );
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let finished = exit_within(run, Duration::from_secs(30));
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();

    let stderr = text(&finished.stderr);
    let dbvalet_lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("dbvalet:"))
        .collect();
    assert_eq!(logins_at_max_ttl, 0);
    assert_eq!(sessions_at_max_ttl, 0);
    assert_eq!(rest, "still-running\n");
    assert_eq!(finished.status.code(), Some(7), "stderr: {stderr}");
    assert_eq!(
        dbvalet_lines,
        [
            "dbvalet: `e2e-max-ttl-reached` reached its max_ttl of 20 minutes: \
             dbvalet ended the command's database access, and the command keeps running"
        ],
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("pw-e2e-max-ttl-reached-admin"), "{stderr}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn another_machines_run_during_a_long_run_leaves_its_login_alone_until_max_ttl() {
    // 30 lease minutes of 400 ms: the first VALID UNTIL is 6 s ahead, and max_ttl is 12 s.
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-long-run-swept", 30);
    let (mut run, mut stdout, login_name) = start_short_run(
        &dir,
        "echo \"login=$PGUSER\"; echo READY; read line; \
         psql -qAtXc 'SELECT 1' 2>/dev/null || echo psql-failed; read line",
    );
    let first_expiry = valid_until(&login_name).unwrap();
    wait_until_database_passes(first_expiry);

    let second = run_command(&dir, &["true"])
        .env("XDG_STATE_HOME", dir.join("other-machine-state"))
        .env("DBVALET_TEST_MINUTE_MS", SHORT_MINUTE_MS)
        .output()
        .unwrap();
    let logins_after_second_run = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let mut stdin = run.stdin.take().unwrap();
    stdin.write_all(b"\n").unwrap();
    let mut queried = String::new();
    stdout.read_line(&mut queried).unwrap();
    wait_until_removed(&ledger_entry(&dir, "e2e-long-run-swept", &login_name));
    let logins_after_max_ttl = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let finished = exit_within(run, Duration::from_secs(30));

    assert!(second.status.success(), "stderr: {}", text(&second.stderr));
    assert_eq!(logins_after_second_run, 1);
    assert_eq!(queried, "1\n");
    assert_eq!(logins_after_max_ttl, 0);
    assert!(
        finished.status.success(),
        "stderr: {}",
        text(&finished.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_failed_push_is_printed_and_the_next_push_moves_the_expiry_forward() {
    // 120 lease minutes of 400 ms: pushes every 2 s, and max_ttl is 48 s, well after the test.
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-push-fails", 120);
    let (mut run, _stdout, login_name) =
        start_short_run(&dir, "echo \"login=$PGUSER\"; echo READY; read line");
    let (lines, received) = std::sync::mpsc::channel();
    let stderr = run.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let _ = lines.send(line.unwrap());
        }
    });

    superuser_sql("ALTER ROLE e2e_push_fails NOLOGIN;");
    let failure = received.recv_timeout(Duration::from_secs(10)).unwrap();
    let expiry_at_failure = valid_until(&login_name).unwrap();
    superuser_sql("ALTER ROLE e2e_push_fails LOGIN;");
    wait_until_expiry_passes(&login_name, expiry_at_failure);
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let finished = exit_within(run, Duration::from_secs(30));
    reader.join().unwrap();

    assert!(
        failure.starts_with(&format!(
            "dbvalet: couldn't push the temporary login `{login_name}`'s expiry forward: "
        )),
        "{failure}"
    );
    assert!(failure.contains("isn't permitted to log in"), "{failure}");
    assert!(!failure.contains("pw-e2e-push-fails-admin"), "{failure}");
    assert!(finished.status.success());
}

/// Waits up to 30 s until a query matching `pattern` for `login` is waiting on a PostgreSQL lock.
fn wait_for_locked_query(login: &str, pattern: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let count: i64 = runtime().block_on(async {
            let (client, connection) =
                tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
                    .await
                    .unwrap();
            tokio::spawn(connection);
            client
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity \
                     WHERE query LIKE $1 AND query LIKE $2 AND wait_event_type = 'Lock'",
                    &[&format!("%{login}%"), &pattern],
                )
                .await
                .unwrap()
                .get(0)
        });
        if count > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "no lock-waiting query matching `{pattern}` for {login}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Backend PIDs currently connected as `login`.
fn active_pids_for_login(login: &str) -> Vec<i32> {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query(
                "SELECT pid FROM pg_stat_activity WHERE usename = $1 ORDER BY pid",
                &[&login],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    })
}

/// Number of backends in `pg_stat_activity` whose PID is in `pids` (even when `usename` is NULL).
fn surviving_backend_count(pids: &[i32]) -> i64 {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE pid = ANY($1)",
                &[&pids],
            )
            .await
            .unwrap()
            .get(0)
    })
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn teardown_cancels_an_in_flight_push_instead_of_failing_with_a_concurrent_update() {
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-push-race", 60);
    let (mut run, _stdout, login_name) = start_short_run(
        &dir,
        "echo \"login=$PGUSER\"; echo READY; read line; exit 9",
    );

    // Hold a lock on the role's pg_authid row so the expiry push blocks on it.
    let (lock_ready_tx, lock_ready_rx) = std::sync::mpsc::channel();
    let (release_lock_tx, release_lock_rx) = std::sync::mpsc::channel();
    let locked_login = login_name.clone();
    let locker = std::thread::spawn(move || {
        runtime().block_on(async {
            let (client, connection) =
                tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
                    .await
                    .unwrap();
            tokio::spawn(connection);
            client
                .batch_execute(&format!(
                    "BEGIN; ALTER ROLE {locked_login} CONNECTION LIMIT 100;"
                ))
                .await
                .unwrap();
            lock_ready_tx.send(()).unwrap();
            let _ = release_lock_rx.recv();
            let _ = client.batch_execute("ROLLBACK;").await;
        });
    });
    lock_ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();

    wait_for_locked_query(&login_name, "%ALTER ROLE%VALID UNTIL%");
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    wait_for_locked_query(&login_name, "%DROP ROLE%");
    release_lock_tx.send(()).unwrap();

    let finished = exit_within(run, Duration::from_secs(30));
    locker.join().unwrap();

    let stderr = text(&finished.stderr);
    let dbvalet_lines: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("dbvalet:"))
        .collect();
    let roles_left = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    assert_eq!(finished.status.code(), Some(9), "stderr: {stderr}");
    assert_eq!(roles_left, 0, "stderr: {stderr}");
    assert!(
        !ledger_entry(&dir, "e2e-push-race", &login_name).exists(),
        "ledger entry remained; stderr: {stderr}"
    );
    assert!(dbvalet_lines.is_empty(), "stderr: {stderr}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn when_another_admin_drops_the_login_access_and_open_sessions_end_at_once() {
    // 60 lease minutes of 400 ms: max_ttl is 24 s, pushes every 2 s.
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-dropped-midrun", 60);
    let fifo = dir.join("psql.in");
    let inter_out = dir.join("inter.out");
    let script = format!(
        "echo \"login=$PGUSER\"; \
         psql -qAtXc 'SELECT pg_sleep(60)' >/dev/null 2>&1 & \
         mkfifo '{fifo}'; \
         psql -qAtX < '{fifo}' > '{inter_out}' 2>/dev/null & \
         exec 3>'{fifo}'; \
         echo \"SELECT 'before';\" >&3; \
         echo READY; \
         read line; \
         echo \"SELECT 'after';\" >&3; \
         exec 3>&-; \
         read line2; \
         exit 6",
        fifo = fifo.display(),
        inter_out = inter_out.display(),
    );
    let (mut run, _stdout, login_name) = start_short_run(&dir, &script);
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    while !std::fs::read_to_string(&inter_out)
        .unwrap_or_default()
        .contains("before")
    {
        assert!(
            Instant::now() < ready_deadline,
            "interactive psql did not print before"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    wait_for_active_query(&login_name);
    let deadline = Instant::now() + Duration::from_secs(10);
    let backend_pids = loop {
        let pids = active_pids_for_login(&login_name);
        if pids.len() >= 2 {
            break pids;
        }
        assert!(
            Instant::now() < deadline,
            "expected 2 sessions, got {pids:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    superuser_sql(&format!("DROP ROLE {login_name};"));
    // Teardown must happen on the next push tick (~2 s), well before the 24 s max_ttl.
    let drop_detected_deadline = Instant::now() + Duration::from_secs(10);
    let entry = ledger_entry(&dir, "e2e-dropped-midrun", &login_name);
    while entry.exists() {
        assert!(
            Instant::now() < drop_detected_deadline,
            "ledger entry was not removed promptly after DROP ROLE"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let mut stdin = run.stdin.take().unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let finished = exit_within(run, Duration::from_secs(30));
    let inter_text = std::fs::read_to_string(&inter_out).unwrap_or_default();
    let surviving = surviving_backend_count(&backend_pids);

    let stderr = text(&finished.stderr);
    assert_eq!(finished.status.code(), Some(6), "stderr: {stderr}");
    assert!(
        !inter_text.contains("after"),
        "open session still ran queries after DROP ROLE: {inter_text:?}"
    );
    assert_eq!(
        surviving, 0,
        "backend outlived dbvalet after DROP ROLE: {backend_pids:?}"
    );
    assert!(stderr.contains("was already dropped"), "stderr: {stderr}");
    assert!(!stderr.contains("reached its max_ttl"), "stderr: {stderr}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn when_another_admin_drops_the_login_in_the_capped_window_it_is_reported_and_not_called_max_ttl() {
    // 15 lease minutes of 400 ms: VALID UNTIL starts capped at max_ttl (6 s); pushes tick every 2 s.
    let _alone = sweeping_alone();
    let dir = project_with_reader_and_max_ttl("e2e-dropped-capped", 15);
    let (mut run, _stdout, login_name) = start_short_run(
        &dir,
        "echo \"login=$PGUSER\"; echo READY; read line; exit 3",
    );

    superuser_sql(&format!("DROP ROLE {login_name};"));
    wait_until_removed(&ledger_entry(&dir, "e2e-dropped-capped", &login_name));

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let finished = exit_within(run, Duration::from_secs(30));

    let stderr = text(&finished.stderr);
    assert_eq!(finished.status.code(), Some(3), "stderr: {stderr}");
    assert!(stderr.contains("was already dropped"), "stderr: {stderr}");
    assert!(!stderr.contains("reached its max_ttl"), "stderr: {stderr}");
}
