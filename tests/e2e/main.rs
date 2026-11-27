//! `dbvalet` as a subprocess, against real PostgreSQL on localhost:5432 and the real OS
//! keychain. CI runs these with `cargo test --test e2e -- --ignored`.
//!
//! Every test uses its own alias and admin role, so they can run in parallel.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

mod login_doctor;
mod run_proxy;
mod support;
mod sweep_gc;
use support::{
    DBVALET, SUPERUSER_URL, create_reader_group, gc_command, ledger_entry, login, passwords_of,
    printed, project_with_reader, project_with_reader_and_admin, run_command, run_in, runtime,
    superuser_count, superuser_sql, sweeping, sweeping_alone, text, wait_for_active_query,
};

fn read_until_ready(stdout: &mut BufReader<std::process::ChildStdout>) -> String {
    let mut seen = String::new();
    while !seen.ends_with("READY\n") {
        assert_ne!(stdout.read_line(&mut seen).unwrap(), 0, "stdout: {seen}");
    }
    seen
}

fn line_value(text: &str, prefix: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing `{prefix}` in:\n{text}"))
        .to_owned()
}

fn pid_of(child: &Child) -> Pid {
    Pid::from_raw(i32::try_from(child.id()).unwrap())
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigint_to_dbvalet_waits_for_the_child_drops_the_login_and_returns_its_exit_code() {
    let dir = project_with_reader("e2e-run-sigint-trap");
    let sweeping = sweeping();
    let mut run = Command::new("python3")
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "-c",
            "import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])",
            DBVALET,
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "trap 'kill \"$p\" 2>/dev/null; echo \"after-sigint=$(psql -qAtc \"SELECT 1\")\"; exit 42' INT; \
             echo \"login=$PGUSER\"; \
             psql -qAtc 'SELECT 1' >/dev/null; \
             sleep 60 >/dev/null 2>&1 & p=$!; \
             echo READY; \
             wait \"$p\"",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut stderr = run.stderr.take().unwrap();
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");

    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();

    let status = run.wait().unwrap();
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(status.code(), Some(42), "stderr: {stderr_text}");
    assert!(rest.contains("after-sigint=1"), "stdout: {seen}{rest}");
    // PostgreSQL 19 warns on stderr about the temporary login's short VALID UNTIL expiry,
    // and the first SIGINT prints a waiting hint; check that teardown itself didn't fail.
    assert!(
        !stderr_text.contains("couldn't drop"),
        "stderr: {stderr_text}"
    );
    assert!(!ledger_entry(&dir, "e2e-run-sigint-trap", &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigint_to_dbvalet_with_an_untrapped_child_drops_the_login_and_returns_130() {
    let dir = project_with_reader("e2e-run-sigint-default");
    let sweeping = sweeping();
    let mut run = Command::new("python3")
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "-c",
            "import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])",
            DBVALET,
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; psql -qAtc 'SELECT 1' >/dev/null; echo READY; exec cat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _stdin = run.stdin.take().unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut stderr = run.stderr.take().unwrap();
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");

    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();

    let status = run.wait().unwrap();
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(status.code(), Some(130), "stderr: {stderr_text}");
    // PostgreSQL 19 warns on stderr about the temporary login's short VALID UNTIL expiry,
    // and the first SIGINT may print a waiting hint; check that teardown itself didn't fail.
    assert!(
        !stderr_text.contains("couldn't drop"),
        "stderr: {stderr_text}"
    );
    assert!(!ledger_entry(&dir, "e2e-run-sigint-default", &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigterm_to_dbvalet_with_a_child_that_ignores_it_tears_down_after_the_timeout() {
    let dir = project_with_reader("e2e-run-sigterm-ignore");
    let sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(
            "trap '' TERM; echo \"login=$PGUSER\"; echo \"child_pid=$$\"; \
             psql -qAtc 'SELECT 1' >/dev/null; echo READY; read line",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = run.stdin.take().unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut stderr = run.stderr.take().unwrap();
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");
    let child_pid = Pid::from_raw(line_value(&seen, "child_pid=").parse().unwrap());

    signal::kill(pid_of(&run), Signal::SIGTERM).unwrap();

    let status = run.wait().unwrap();
    let child_still_alive = signal::kill(child_pid, None).is_ok();
    // Close stdin so the child that ignored SIGTERM exits and releases the stderr pipe.
    drop(stdin);
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(status.code(), Some(143), "stderr: {stderr_text}");
    assert!(
        child_still_alive,
        "child should still have been running after ignoring SIGTERM"
    );
    assert!(stderr_text.contains("SIGTERM"), "stderr: {stderr_text}");
    assert!(
        !stderr_text.contains("pw-e2e-run-sigterm-ignore-admin"),
        "stderr: {stderr_text}"
    );
    assert!(!ledger_entry(&dir, "e2e-run-sigterm-ignore", &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sighup_to_dbvalet_with_a_child_that_ignores_it_tears_down_after_the_timeout() {
    let dir = project_with_reader("e2e-run-sighup-ignore");
    let sweeping = sweeping();
    // Ignore TERM as well as HUP so Linux PR_SET_PDEATHSIG(SIGTERM) doesn't kill the
    // child when dbvalet exits before we check that the child outlived the SIGHUP timeout.
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(
            "trap '' HUP TERM; echo \"login=$PGUSER\"; echo \"child_pid=$$\"; \
             psql -qAtc 'SELECT 1' >/dev/null; echo READY; read line",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = run.stdin.take().unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let mut stderr = run.stderr.take().unwrap();
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");
    let child_pid = Pid::from_raw(line_value(&seen, "child_pid=").parse().unwrap());

    signal::kill(pid_of(&run), Signal::SIGHUP).unwrap();

    let status = run.wait().unwrap();
    let child_still_alive = signal::kill(child_pid, None).is_ok();
    drop(stdin);
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(status.code(), Some(129), "stderr: {stderr_text}");
    assert!(
        child_still_alive,
        "child should still have been running after ignoring SIGHUP"
    );
    assert!(stderr_text.contains("SIGHUP"), "stderr: {stderr_text}");
    assert!(
        !stderr_text.contains("pw-e2e-run-sighup-ignore-admin"),
        "stderr: {stderr_text}"
    );
    assert!(!ledger_entry(&dir, "e2e-run-sighup-ignore", &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &login_name
        ),
        0
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigkill_of_dbvalet_on_linux_ends_the_child() {
    use std::os::unix::process::ExitStatusExt;
    use std::sync::mpsc;

    let dir = project_with_reader("e2e-run-sigkill-linux");
    let sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg("echo \"login=$PGUSER\"; psql -qAtc 'SELECT 1' >/dev/null; echo READY; exec cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Keep stdin open so `cat` stays blocked unless PR_SET_PDEATHSIG ends it.
    let _stdin = run.stdin.take().unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");

    signal::kill(pid_of(&run), Signal::SIGKILL).unwrap();
    let status = run.wait().unwrap();
    assert_eq!(status.signal(), Some(Signal::SIGKILL as i32));

    // Once dbvalet is gone, `cat` is the only process holding stdout open; EOF proves it died.
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut rest = Vec::new();
        let _ = stdout.read_to_end(&mut rest);
        let _ = done_tx.send(());
    });
    let child_ended = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();

    // SIGKILL skips teardown, so the ledger entry stays until the next sweep cleans it up.
    assert!(ledger_entry(&dir, "e2e-run-sigkill-linux", &login_name).exists());
    let swept = gc_in(&dir);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!ledger_entry(&dir, "e2e-run-sigkill-linux", &login_name).exists());

    assert!(
        child_ended,
        "child should exit via PR_SET_PDEATHSIG(SIGTERM) when dbvalet is SIGKILLed"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_signal_during_mint_holds_the_ledger_lock_and_drops_the_login_without_spawning_the_child() {
    let dir = project_with_reader("e2e-run-signal-during-mint");
    let _alone = sweeping_alone();

    // Hold an exclusive lock on pg_authid so CREATE ROLE blocks after the ledger entry is written.
    let blocker_rt = runtime();
    let blocker = blocker_rt.block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .batch_execute("BEGIN; LOCK TABLE pg_catalog.pg_authid IN EXCLUSIVE MODE;")
            .await
            .unwrap();
        client
    });

    let run = Command::new("python3")
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "-c",
            "import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])",
            DBVALET,
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo CHILD_RAN",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait until mint writes the ledger entry before CREATE ROLE blocks on pg_authid.
    let ledger_dir = dir.join("state/dbvalet/ledger");
    let deadline = Instant::now() + Duration::from_secs(10);
    let login_name = loop {
        if let Ok(entries) = std::fs::read_dir(&ledger_dir)
            && let Some(login) = entries.flatten().find_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_prefix("e2e-run-signal-during-mint.")
                    .map(str::to_owned)
            })
        {
            break login;
        }
        assert!(Instant::now() < deadline, "ledger entry never appeared");
        std::thread::sleep(Duration::from_millis(20));
    };

    // Send SIGINT while CREATE ROLE is blocked; dbvalet must stay alive holding the ledger lock.
    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();

    // Run gc while the lock is still held: dbvalet must still hold the ledger entry so gc
    // can't delete it before CREATE ROLE commits.
    let gc_during_lock = gc_command(&dir).output().unwrap();
    let entry_kept_during_lock =
        ledger_entry(&dir, "e2e-run-signal-during-mint", &login_name).exists();

    // Release pg_authid so CREATE ROLE commits and dbvalet can drop the login and exit.
    blocker_rt.block_on(async {
        let _ = blocker.batch_execute("ROLLBACK;").await;
    });
    drop(blocker);
    drop(blocker_rt);

    let output = run.wait_with_output().unwrap();
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    let roles_left = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let sessions_left = superuser_count(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
        &login_name,
    );
    // Clean up if the assertion below fails so the suite stays clean.
    if roles_left > 0 {
        superuser_sql(&format!("DROP ROLE IF EXISTS {login_name};"));
    }

    assert!(
        gc_during_lock.status.success(),
        "gc stderr: {}",
        text(&gc_during_lock.stderr)
    );
    assert!(
        entry_kept_during_lock,
        "gc removed the ledger entry while CREATE ROLE was still queued; gc stdout: {}",
        text(&gc_during_lock.stdout)
    );
    assert_eq!(output.status.code(), Some(130), "stderr: {stderr}");
    assert!(!stdout.contains("CHILD_RAN"), "stdout: {stdout}");
    assert!(!stderr.contains("dbvalet:"), "stderr: {stderr}");
    assert!(!ledger_entry(&dir, "e2e-run-signal-during-mint", &login_name).exists());
    assert_eq!(
        roles_left, 0,
        "leftover login {login_name} remained in pg_roles"
    );
    assert_eq!(sessions_left, 0);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_still_starts_its_child_after_the_dbvalet_binary_is_replaced_in_place() {
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    create_reader_group();
    let alias = "e2e-run-upgrade-linux";
    let admin = alias.replace('-', "_");
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {admin};
         CREATE ROLE {admin} LOGIN SUPERUSER PASSWORD 'pw-{alias}-admin';
         GRANT dbvalet_reader TO {admin} WITH ADMIN OPTION;"
    ));

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(alias);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        format!(
            "[databases.{alias}.roles]\n\
             reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n"
        ),
    )
    .unwrap();

    let bin = dir.join("dbvalet-copy");
    std::fs::copy(DBVALET, &bin).unwrap();

    // Intercept the first admin connection (before child spawn) to atomically replace `bin`,
    // matching what `cargo install` or a package manager does during an upgrade.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let gate_port = listener.local_addr().unwrap().port();
    let bin_for_gate = bin.clone();
    let staged_for_gate = dir.join("dbvalet-copy.new");
    let replaced = Arc::new(AtomicBool::new(false));
    let replaced_for_gate = Arc::clone(&replaced);
    std::thread::spawn(move || {
        for incoming in listener.incoming().flatten() {
            if !replaced_for_gate.swap(true, Ordering::SeqCst) {
                std::fs::copy(DBVALET, &staged_for_gate).unwrap();
                std::fs::rename(&staged_for_gate, &bin_for_gate).unwrap();
            }
            let Ok(upstream) = TcpStream::connect("127.0.0.1:5432") else {
                continue;
            };
            let Ok(mut in_r) = incoming.try_clone() else {
                continue;
            };
            let Ok(mut out_w) = upstream.try_clone() else {
                continue;
            };
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut in_r, &mut out_w);
            });
            std::thread::spawn(move || {
                let mut out_r = upstream;
                let mut in_w = incoming;
                let _ = std::io::copy(&mut out_r, &mut in_w);
            });
        }
    });

    let stored = login(
        alias,
        &format!("postgresql://{admin}:pw-{alias}-admin@127.0.0.1:{gate_port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let _sweeping = sweeping();
    let output = Command::new(&bin)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; echo child-ran",
        ])
        .output()
        .unwrap();

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(replaced.load(Ordering::SeqCst), "binary was never replaced");
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stdout.contains("child-ran\n"), "stdout: {stdout}");
    let login_name = line_value(&stdout, "login=");
    assert!(!ledger_entry(&dir, alias, &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_started_through_the_dynamic_loader_runs_the_child_and_exits_zero() {
    let dir = project_with_reader("e2e-run-ldso-linux");
    let _sweeping = sweeping();
    let mut loaders: Vec<PathBuf> = ["/lib", "/lib64"]
        .into_iter()
        .filter_map(|root| std::fs::read_dir(root).ok())
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("ld-linux-") && name.contains(".so."))
        })
        .collect();
    loaders.sort();
    let loader = loaders.into_iter().next().expect(
        "expected a dynamic loader matching /lib/ld-linux-*.so.* or /lib64/ld-linux-*.so.*",
    );

    let output = Command::new(&loader)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            DBVALET,
            "run",
            "--allow-plaintext",
            "--",
            "echo",
            "child-ran",
        ])
        .output()
        .unwrap();

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    let ledger_dir = dir.join("state/dbvalet/ledger");
    let ledger_entries: Vec<_> = std::fs::read_dir(&ledger_dir)
        .into_iter()
        .flatten()
        .flatten()
        .collect();

    assert_eq!(
        output.status.code(),
        Some(0),
        "loader={} stderr: {stderr}",
        loader.display()
    );
    assert_eq!(stdout, "child-ran\n", "stderr: {stderr}");
    assert!(
        ledger_dir.exists(),
        "mint never created the ledger directory"
    );
    assert!(
        ledger_entries.is_empty(),
        "unexpected ledger entries: {ledger_entries:?}"
    );
}

/// Reads lines from `stderr` on a background thread until one contains `needle`, then keeps
/// draining `stderr` to EOF so the child never blocks on a full pipe.
fn wait_for_stderr_line(
    stderr: std::process::ChildStderr,
    needle: &'static str,
    limit: Duration,
) -> std::thread::JoinHandle<String> {
    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut all = String::new();
        let mut notified = false;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    all.push_str(&line);
                    if !notified && line.contains(needle) {
                        notified = true;
                        let _ = seen_tx.send(());
                    }
                }
            }
        }
        all
    });
    assert!(
        seen_rx.recv_timeout(limit).is_ok(),
        "stderr never contained `{needle}` within {limit:?}"
    );
    handle
}

fn wait_for_exit(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("dbvalet was still running after {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn two_ctrl_cs_while_psql_runs_a_long_query_end_the_run_and_drop_the_login() {
    let dir = project_with_reader("e2e-run-sigint-psql-twice");
    let sweeping = sweeping();
    let mut run = Command::new("python3")
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "-c",
            "import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])",
            DBVALET,
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; echo READY; exec psql -qAtX -c 'SELECT pg_sleep(600)'",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let stderr = run.stderr.take().unwrap();
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");
    wait_for_active_query(&login_name);

    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();
    let stderr_handle = wait_for_stderr_line(
        stderr,
        "press Ctrl-C again to stop it and drop the temporary login",
        Duration::from_secs(5),
    );

    let after_second = Instant::now();
    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();
    let status = wait_for_exit(&mut run, Duration::from_secs(8));
    let elapsed = after_second.elapsed();
    let stderr_text = stderr_handle.join().unwrap();

    assert_eq!(
        status.code(),
        Some(143),
        "elapsed={elapsed:?} stderr: {stderr_text}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "expected forwarded SIGTERM to end psql before the 5 s timeout, took {elapsed:?}"
    );
    assert!(
        !stderr_text.contains("couldn't drop"),
        "stderr: {stderr_text}"
    );
    assert!(!ledger_entry(&dir, "e2e-run-sigint-psql-twice", &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn two_sigints_to_dbvalet_pid_alone_end_the_run_and_drop_the_login() {
    let dir = project_with_reader("e2e-run-sigint-pid-twice");
    let sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg("echo \"login=$PGUSER\"; psql -qAtc 'SELECT 1' >/dev/null; echo READY; exec cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _stdin = run.stdin.take().unwrap();
    let mut stdout = BufReader::new(run.stdout.take().unwrap());
    let stderr = run.stderr.take().unwrap();
    let seen = read_until_ready(&mut stdout);
    drop(sweeping);
    let login_name = line_value(&seen, "login=");

    signal::kill(pid_of(&run), Signal::SIGINT).unwrap();
    let stderr_handle = wait_for_stderr_line(
        stderr,
        "press Ctrl-C again to stop it and drop the temporary login",
        Duration::from_secs(5),
    );

    let after_second = Instant::now();
    signal::kill(pid_of(&run), Signal::SIGINT).unwrap();
    let status = wait_for_exit(&mut run, Duration::from_secs(8));
    let elapsed = after_second.elapsed();
    let stderr_text = stderr_handle.join().unwrap();

    assert_eq!(
        status.code(),
        Some(143),
        "elapsed={elapsed:?} stderr: {stderr_text}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "expected forwarded SIGTERM to end the child before the 5 s timeout, took {elapsed:?}"
    );
    assert!(
        !stderr_text.contains("couldn't drop"),
        "stderr: {stderr_text}"
    );
    assert!(!ledger_entry(&dir, "e2e-run-sigint-pid-twice", &login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigterm_during_login_setup_exits_143_without_starting_the_child_or_writing_a_ledger_entry() {
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};

    create_reader_group();
    let alias = "e2e-run-sigterm-setup";
    let admin = alias.replace('-', "_");
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {admin};
         CREATE ROLE {admin} LOGIN SUPERUSER PASSWORD 'pw-{alias}-admin';
         GRANT dbvalet_reader TO {admin} WITH ADMIN OPTION;"
    ));

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(alias);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        format!(
            "[databases.{alias}.roles]\n\
             reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n"
        ),
    )
    .unwrap();

    // Relay the initial sweep connection to PostgreSQL, then stall the mint setup connection
    // silently so SIGTERM lands inside `prepare_mint` after signal handlers are installed.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let gate_port = listener.local_addr().unwrap().port();
    let (mint_tx, mint_rx) = mpsc::channel();
    let seen_conns = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        let mut stalled = Vec::new();
        for incoming in listener.incoming().flatten() {
            let n = seen_conns.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let Ok(upstream) = TcpStream::connect("127.0.0.1:5432") else {
                    continue;
                };
                let Ok(mut in_r) = incoming.try_clone() else {
                    continue;
                };
                let Ok(mut out_w) = upstream.try_clone() else {
                    continue;
                };
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut in_r, &mut out_w);
                });
                std::thread::spawn(move || {
                    let mut out_r = upstream;
                    let mut in_w = incoming;
                    let _ = std::io::copy(&mut out_r, &mut in_w);
                });
            } else {
                stalled.push(incoming);
                let _ = mint_tx.send(());
            }
        }
    });

    let stored = login(
        alias,
        &format!("postgresql://{admin}:pw-{alias}-admin@127.0.0.1:{gate_port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo CHILD_RAN",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    mint_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("mint never connected to the silent listener");
    let sent = Instant::now();
    signal::kill(pid_of(&run), Signal::SIGTERM).unwrap();

    let status = wait_for_exit(&mut run, Duration::from_secs(3));
    let elapsed = sent.elapsed();
    let mut stdout = String::new();
    run.stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let mut stderr = String::new();
    run.stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    let ledger_entries: Vec<_> = std::fs::read_dir(dir.join("state/dbvalet/ledger"))
        .into_iter()
        .flatten()
        .flatten()
        .collect();

    assert_eq!(
        status.code(),
        Some(143),
        "elapsed={elapsed:?} stderr: {stderr}"
    );
    assert!(!stdout.contains("CHILD_RAN"), "stdout: {stdout}");
    assert!(
        ledger_entries.is_empty(),
        "unexpected ledger entries: {ledger_entries:?}"
    );
}

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

fn ledger_entries_in(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir.join("state/dbvalet/ledger"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect()
}

fn logins_in_group(group: &str) -> i64 {
    superuser_count(
        "SELECT count(*)
         FROM pg_roles r
         JOIN pg_auth_members m ON m.member = r.oid
         JOIN pg_roles g ON g.oid = m.roleid
         WHERE g.rolname = $1
           AND r.rolcanlogin
           AND starts_with(r.rolname::text, 'dbvalet_')",
        group,
    )
}

fn project_with_group(alias: &str, admin_attributes: &str, group: &str) -> PathBuf {
    let admin = format!("{}_admin", alias.replace('-', "_"));
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {admin};
         CREATE ROLE {admin} LOGIN {admin_attributes} PASSWORD 'pw-{alias}-admin';
         GRANT \"{group}\" TO {admin} WITH ADMIN OPTION;"
    ));
    let stored = login(
        alias,
        &format!("postgresql://{admin}:pw-{alias}-admin@localhost:5432/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(alias);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        format!(
            "[databases.{alias}.roles]\n\
             reader = {{ member_of = \"{group}\", read_only = true }}\n"
        ),
    )
    .unwrap();
    dir
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_superuser_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_super;
         CREATE ROLE e2e_danger_super NOLOGIN SUPERUSER;",
    );
    let dir = project_with_group("e2e-danger-super", "SUPERUSER", "e2e_danger_super");

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_super"), "stderr: {stderr}");
    assert!(stderr.contains("SUPERUSER"), "stderr: {stderr}");
    assert!(!stderr.contains("pw-e2e-danger-super-admin"));
    assert_eq!(logins_in_group("e2e_danger_super"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_createrole_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_createrole;
         CREATE ROLE e2e_danger_createrole NOLOGIN CREATEROLE;",
    );
    let dir = project_with_group(
        "e2e-danger-createrole",
        "SUPERUSER",
        "e2e_danger_createrole",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_createrole"), "stderr: {stderr}");
    assert!(stderr.contains("CREATEROLE"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_createrole"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_bypassrls_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_bypassrls;
         CREATE ROLE e2e_danger_bypassrls NOLOGIN BYPASSRLS;",
    );
    let dir = project_with_group("e2e-danger-bypassrls", "CREATEROLE", "e2e_danger_bypassrls");

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_bypassrls"), "stderr: {stderr}");
    assert!(stderr.contains("BYPASSRLS"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_bypassrls"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_replication_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_replication;
         CREATE ROLE e2e_danger_replication NOLOGIN REPLICATION;",
    );
    let dir = project_with_group(
        "e2e-danger-replication",
        "CREATEROLE",
        "e2e_danger_replication",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("e2e_danger_replication"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("REPLICATION"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_replication"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_pg_execute_server_program_as_group_role_without_creating_a_login() {
    let dir = project_with_group(
        "e2e-danger-pg-exec",
        "SUPERUSER",
        "pg_execute_server_program",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("pg_execute_server_program"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pg_*"), "stderr: {stderr}");
    assert_eq!(logins_in_group("pg_execute_server_program"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_group_role_that_is_a_direct_member_of_pg_execute_server_program() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_direct_exec;
         CREATE ROLE e2e_danger_direct_exec NOLOGIN;
         GRANT pg_execute_server_program TO e2e_danger_direct_exec;",
    );
    let dir = project_with_group(
        "e2e-danger-direct-exec",
        "SUPERUSER",
        "e2e_danger_direct_exec",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("e2e_danger_direct_exec"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("pg_execute_server_program"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pg_*"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_direct_exec"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_group_role_that_is_a_transitive_member_of_pg_execute_server_program() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_leaf_exec;
         DROP ROLE IF EXISTS e2e_danger_mid_exec;
         CREATE ROLE e2e_danger_mid_exec NOLOGIN;
         CREATE ROLE e2e_danger_leaf_exec NOLOGIN;
         GRANT pg_execute_server_program TO e2e_danger_mid_exec;
         GRANT e2e_danger_mid_exec TO e2e_danger_leaf_exec;",
    );
    let dir = project_with_group("e2e-danger-leaf-exec", "CREATEROLE", "e2e_danger_leaf_exec");

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_leaf_exec"), "stderr: {stderr}");
    assert!(
        stderr.contains("pg_execute_server_program"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pg_*"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_leaf_exec"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_group_role_that_is_a_member_of_a_superuser_role() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_child_super;
         DROP ROLE IF EXISTS e2e_danger_parent_super;
         CREATE ROLE e2e_danger_parent_super NOLOGIN SUPERUSER;
         CREATE ROLE e2e_danger_child_super NOLOGIN;
         GRANT e2e_danger_parent_super TO e2e_danger_child_super;",
    );
    let dir = project_with_group(
        "e2e-danger-child-super",
        "SUPERUSER",
        "e2e_danger_child_super",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("e2e_danger_child_super"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("e2e_danger_parent_super"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("SUPERUSER"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_child_super"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_reports_each_dangerous_configured_role_and_passes_dbvalet_reader() {
    create_reader_group();
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_doc_danger_admin;
         DROP ROLE IF EXISTS e2e_doc_super;
         DROP ROLE IF EXISTS e2e_doc_createrole;
         DROP ROLE IF EXISTS e2e_doc_leaf_exec;
         DROP ROLE IF EXISTS e2e_doc_mid_exec;
         CREATE ROLE e2e_doc_danger_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-doc-danger-9a4b';
         CREATE ROLE e2e_doc_super NOLOGIN SUPERUSER;
         CREATE ROLE e2e_doc_createrole NOLOGIN CREATEROLE;
         CREATE ROLE e2e_doc_mid_exec NOLOGIN;
         CREATE ROLE e2e_doc_leaf_exec NOLOGIN;
         GRANT pg_execute_server_program TO e2e_doc_mid_exec;
         GRANT e2e_doc_mid_exec TO e2e_doc_leaf_exec;",
    );
    let stored = login(
        "e2e-doc-danger",
        "postgresql://e2e_doc_danger_admin:pw-e2e-doc-danger-9a4b@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-doc-danger");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-doc-danger.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         bad_super = { member_of = \"e2e_doc_super\", read_only = true }\n\
         bad_createrole = { member_of = \"e2e_doc_createrole\", read_only = true }\n\
         bad_exec = { member_of = \"e2e_doc_leaf_exec\", read_only = true }\n",
    )
    .unwrap();

    let checked = Command::new(DBVALET)
        .current_dir(&dir)
        .args(["doctor", "--allow-plaintext", "e2e-doc-danger"])
        .output()
        .unwrap();

    let stdout = text(&checked.stdout);
    let stderr = text(&checked.stderr);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains("ok   role `reader` (`dbvalet_reader`)"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("FAIL role `bad_super` (`e2e_doc_super`)") && stdout.contains("SUPERUSER"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("FAIL role `bad_createrole` (`e2e_doc_createrole`)")
            && stdout.contains("CREATEROLE"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("FAIL role `bad_exec` (`e2e_doc_leaf_exec`)")
            && stdout.contains("pg_execute_server_program")
            && stdout.contains("pg_*"),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("pw-e2e-doc-danger-9a4b"));
    assert!(!stderr.contains("pw-e2e-doc-danger-9a4b"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_passes_when_dbvalet_toml_configures_only_dbvalet_reader() {
    let dir = project_with_reader_and_admin("e2e-doc-safe-reader", "CREATEROLE");

    let checked = Command::new(DBVALET)
        .current_dir(&dir)
        .args(["doctor", "--allow-plaintext", "e2e-doc-safe-reader"])
        .output()
        .unwrap();

    let stdout = text(&checked.stdout);
    assert!(checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains("ok   role `reader` (`dbvalet_reader`)"),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("FAIL"), "doctor: {stdout}");
}

fn isolated_state_home(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("state-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dbvalet_log(state_home: &Path, args: &[&str]) -> Output {
    Command::new(DBVALET)
        .env("XDG_STATE_HOME", state_home)
        .arg("log")
        .args(args)
        .output()
        .unwrap()
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn after_a_run_dbvalet_log_shows_the_header_and_simple_query_text() {
    let dir = project_with_reader("e2e-log-simple");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-log-simple]\n\
         max_ttl_minutes = 480\n\
         \n\
         [databases.e2e-log-simple.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    let state = isolated_state_home("e2e-log-simple");

    let _sweeping = sweeping();
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args(["run", "--allow-plaintext", "--", "psql", "-c", "select 1"])
        .output()
        .unwrap();
    drop(_sweeping);
    assert!(run.status.success(), "stderr: {}", text(&run.stderr));

    let listing = dbvalet_log(&state, &[]);
    assert!(
        listing.status.success(),
        "stderr: {}",
        text(&listing.stderr)
    );
    let listed = text(&listing.stdout);
    let first_line = listed.lines().next().unwrap();
    let run_id = first_line.split_whitespace().nth(1).unwrap();

    let shown = dbvalet_log(&state, &[run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains(&format!("run_id: {run_id}\n")), "{log}");
    assert!(log.contains("started_at: "), "{log}");
    assert!(log.contains("database: e2e-log-simple\n"), "{log}");
    assert!(log.contains("role: reader\n"), "{log}");
    assert!(log.contains("valid_until: "), "{log}");
    assert!(log.contains("max_ttl: 480m\n"), "{log}");
    assert!(log.contains("sql_log: enabled\n"), "{log}");
    assert!(log.contains("command: psql -c 'select 1'\n"), "{log}");
    assert!(log.contains(" [Q] select 1\n"), "{log}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_prepared_statement_sent_over_the_extended_protocol_appears_in_the_run_log() {
    let dir = project_with_reader("e2e-log-extended");
    let state = isolated_state_home("e2e-log-extended");

    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; echo \"url=$DATABASE_URL\"; echo READY; read line",
        ])
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
    let login_name = seen
        .lines()
        .find_map(|line| line.strip_prefix("login="))
        .unwrap()
        .to_owned();
    let run_id = login_name.strip_prefix("dbvalet_").unwrap().to_owned();
    let proxy_url = seen
        .lines()
        .find_map(|line| line.strip_prefix("url="))
        .unwrap()
        .to_owned();

    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(&proxy_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        let add_stmt = client.prepare("SELECT $1::int + 1 AS total").await.unwrap();
        let total: i32 = client.query_one(&add_stmt, &[&41i32]).await.unwrap().get(0);
        assert_eq!(total, 42);

        let echo_stmt = client.prepare("SELECT $1::text AS echo").await.unwrap();
        let echoed: String = client
            .query_one(&echo_stmt, &[&"bound-param-secret-7c3e"])
            .await
            .unwrap()
            .get(0);
        assert_eq!(echoed, "bound-param-secret-7c3e");
    });

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));

    let shown = dbvalet_log(&state, &[&run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains(" [P] SELECT $1::int + 1 AS total\n"), "{log}");
    assert!(log.contains(" [P] SELECT $1::text AS echo\n"), "{log}");
    assert!(!log.contains("bound-param-secret-7c3e"), "{log}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_with_no_sql_log_records_the_header_and_no_statements() {
    let dir = project_with_reader("e2e-log-no-sql");
    let state = isolated_state_home("e2e-log-no-sql");

    let _sweeping = sweeping();
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--no-sql-log",
            "--",
            "psql",
            "-Atc",
            "SELECT 'no-sql-log-marker-4a1f';",
        ])
        .output()
        .expect("run psql");
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "no-sql-log-marker-4a1f\n");

    let listing = dbvalet_log(&state, &[]);
    assert!(
        listing.status.success(),
        "stderr: {}",
        text(&listing.stderr)
    );
    let listed = text(&listing.stdout);
    let run_id = listed
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();

    let shown = dbvalet_log(&state, &[run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains(&format!("run_id: {run_id}\n")), "{log}");
    assert!(log.contains("database: e2e-log-no-sql\n"), "{log}");
    assert!(log.contains("role: reader\n"), "{log}");
    assert!(log.contains("sql_log: disabled (--no-sql-log)\n"), "{log}");
    assert!(log.contains("command: psql\n"), "{log}");
    assert!(!log.contains("no-sql-log-marker-4a1f"), "{log}");
    assert!(!log.contains(" [Q] "), "{log}");
    assert!(!log.contains(" [P] "), "{log}");
    let (_, after_header) = log.split_once("\n\n").unwrap();
    assert!(after_header.is_empty(), "body: {after_header:?}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_run_log_hides_the_token_login_password_and_sql_passwords() {
    let dir = project_with_reader("e2e-log-secrets");
    let state = isolated_state_home("e2e-log-secrets");
    let witness = "e2e_log_secrets_witness";

    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(
            "echo \"login=$PGUSER\"; \
             echo \"token=$PGPASSWORD\"; \
             psql -c \"ALTER ROLE e2e_log_target PASSWORD 'pw-alter-role-8f3c'\" || true; \
             psql -c 'CREATE ROLE e2e_log_created LOGIN PASSWORD $$pw-create-role-4d9a$$' || true; \
             echo \"echoed=$(psql -Atc \"SELECT '$PGPASSWORD'\")\"; \
             echo READY; read line",
        )
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
    let login_name = seen
        .lines()
        .find_map(|line| line.strip_prefix("login="))
        .unwrap()
        .to_owned();
    let run_id = login_name.strip_prefix("dbvalet_").unwrap().to_owned();
    let token = seen
        .lines()
        .find_map(|line| line.strip_prefix("token="))
        .unwrap()
        .to_owned();
    let echoed = seen
        .lines()
        .find_map(|line| line.strip_prefix("echoed="))
        .unwrap()
        .to_owned();
    // Proxy must not rewrite or block SQL on the wire (ADR-0002).
    assert_eq!(echoed, token);

    let verifier: String = runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query_one(
                "SELECT rolpassword FROM pg_authid WHERE rolname = $1",
                &[&login_name],
            )
            .await
            .unwrap()
            .get(0)
    });
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {witness}; CREATE ROLE {witness} LOGIN PASSWORD '{verifier}';"
    ));

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    // PostgreSQL itself refused ALTER ROLE in a read-only transaction, proving the proxy relayed it.
    assert!(
        stderr.contains("cannot execute ALTER ROLE in a read-only transaction"),
        "stderr: {stderr}"
    );

    let shown = dbvalet_log(&state, &[&run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(
        log.contains(" [Q] ALTER ROLE e2e_log_target PASSWORD '[REDACTED]'\n"),
        "{log}"
    );
    assert!(
        log.contains(" [Q] CREATE ROLE e2e_log_created LOGIN PASSWORD '[REDACTED]'\n"),
        "{log}"
    );
    assert!(log.contains(" [Q] SELECT '[REDACTED]'\n"), "{log}");
    assert!(!log.contains("pw-alter-role-8f3c"), "{log}");
    assert!(!log.contains("pw-create-role-4d9a"), "{log}");
    assert!(!log.contains(&token), "{log}");
    assert!(!log.contains("pw-e2e-log-secrets-admin"), "{log}");
    assert_eq!(passwords_of(witness, &log), Vec::<String>::new());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_run_log_header_redacts_sql_passwords_even_with_long_flags() {
    let dir = project_with_reader("e2e-log-header-pw");
    let state = isolated_state_home("e2e-log-header-pw");

    let _sweeping = sweeping();
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "psql",
            "--command=ALTER ROLE e2e_log_target PASSWORD 'pw-cli-arg-2b7e'",
        ])
        .output()
        .unwrap();
    drop(_sweeping);
    assert!(!run.status.success());

    let listed = text(&dbvalet_log(&state, &[]).stdout);
    let run_id = listed
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let log = text(&dbvalet_log(&state, &[run_id]).stdout);
    assert!(
        log.contains(" [Q] ALTER ROLE e2e_log_target PASSWORD '[REDACTED]'\n"),
        "{log}"
    );
    assert!(!log.contains("pw-cli-arg-2b7e"), "{log}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_failed_run_log_open_still_drops_the_temporary_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_log_open_fail_group;
         CREATE ROLE e2e_log_open_fail_group NOLOGIN;
         DROP ROLE IF EXISTS e2e_log_open_fail_admin;
         CREATE ROLE e2e_log_open_fail_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-log-open-fail';",
    );
    let stored = login(
        "e2e-log-open-fail",
        "postgresql://e2e_log_open_fail_admin:pw-e2e-log-open-fail@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-log-open-fail");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-log-open-fail.roles]\n\
         reader = { member_of = \"e2e_log_open_fail_group\", read_only = true }\n",
    )
    .unwrap();
    // Leave dbvalet/ledger writable so mint() creates the login, then block dbvalet/runs
    // with a regular file so opening the run log fails after mint().
    let state = isolated_state_home("e2e-log-open-fail");
    let app_state = state.join("dbvalet");
    std::fs::create_dir_all(&app_state).unwrap();
    std::fs::write(app_state.join("runs"), b"not a directory").unwrap();

    let _sweeping = sweeping();
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo child-ran",
        ])
        .output()
        .unwrap();
    drop(_sweeping);

    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stdout: {}", text(&output.stdout));
    assert!(
        output.stdout.is_empty(),
        "child should not run, stdout: {}",
        text(&output.stdout)
    );
    assert!(
        stderr.contains("couldn't create the run log directory"),
        "stderr: {stderr}"
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*)
             FROM pg_roles r
             JOIN pg_auth_members m ON m.member = r.oid
             JOIN pg_roles g ON g.oid = m.roleid
             WHERE g.rolname = $1 AND r.rolcanlogin AND r.rolname LIKE 'dbvalet\\_%' ESCAPE '\\'",
            "e2e_log_open_fail_group"
        ),
        0
    );
    let ledger_entries: Vec<_> = std::fs::read_dir(app_state.join("ledger"))
        .unwrap()
        .collect();
    assert!(ledger_entries.is_empty(), "ledger: {ledger_entries:?}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn dbvalet_log_lists_runs_newest_first() {
    let dir = project_with_reader("e2e-log-order");
    let state = isolated_state_home("e2e-log-order");

    let _sweeping = sweeping();
    let first = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"$PGUSER\"",
        ])
        .output()
        .unwrap();
    assert!(first.status.success(), "stderr: {}", text(&first.stderr));
    let first_id = text(&first.stdout)
        .trim()
        .strip_prefix("dbvalet_")
        .unwrap()
        .to_owned();

    let second = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"$PGUSER\"",
        ])
        .output()
        .unwrap();
    assert!(second.status.success(), "stderr: {}", text(&second.stderr));
    let second_id = text(&second.stdout)
        .trim()
        .strip_prefix("dbvalet_")
        .unwrap()
        .to_owned();

    let listing = dbvalet_log(&state, &[]);
    assert!(
        listing.status.success(),
        "stderr: {}",
        text(&listing.stderr)
    );
    let listed = text(&listing.stdout);
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 2, "{listed}");
    assert!(lines[0].contains(&second_id), "{listed}");
    assert!(lines[1].contains(&first_id), "{listed}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_unicode_statement_containing_password_returns_the_same_result_with_and_without_sql_log() {
    let dir = project_with_reader("e2e-log-unicode-fwd");
    let state = isolated_state_home("e2e-log-unicode-fwd");
    let query = "SELECT 'Forgot your password? Réinitialisez-le'";

    let _sweeping = sweeping();
    let logged = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-AtXc",
            query,
        ])
        .output()
        .unwrap();
    let unlogged = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--no-sql-log",
            "--",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-AtXc",
            query,
        ])
        .output()
        .unwrap();

    assert!(logged.status.success(), "stderr: {}", text(&logged.stderr));
    assert!(
        unlogged.status.success(),
        "stderr: {}",
        text(&unlogged.stderr)
    );
    assert_eq!(logged.stdout, unlogged.stdout);
    assert_eq!(
        text(&logged.stdout),
        "Forgot your password? Réinitialisez-le\n"
    );

    let listed = text(&dbvalet_log(&state, &[]).stdout);
    let logged_id = listed
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let shown = text(&dbvalet_log(&state, &[logged_id]).stdout);
    assert!(shown.contains(&format!(" [Q] {query}\n")), "{shown}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn non_utf8_and_complex_password_statements_are_omitted_or_redacted_without_changing_results() {
    let dir = project_with_reader("e2e-log-hardening");
    let state = isolated_state_home("e2e-log-hardening");

    let script = concat!(
        "echo \"login=$PGUSER\"; ",
        "echo \"token=$PGPASSWORD\"; ",
        "printf \"SELECT 'caf\\351';\\n\" | PGCLIENTENCODING=LATIN1 psql -v ON_ERROR_STOP=1 -AtX | od -An -tx1 | tr -d ' \\n'; echo; ",
        "printf \"SELECT 'caf\\303\\251';\\n\" | PGCLIENTENCODING=LATIN1 psql -v ON_ERROR_STOP=1 -AtX >/dev/null; ",
        "printf \"ALTER ROLE CURRENT_USER PASSWORD -- note\\r'synthetic-e2e-cr';\\n\" | psql -X >/dev/null 2>&1 || true; ",
        "printf \"ALTER ROLE CURRENT_USER PASSWORD\\013'synthetic-e2e-vt';\\n\" | psql -X >/dev/null 2>&1 || true; ",
        "psql -X -c \"DO \\$a\\$ BEGIN EXECUTE \\$b\\$ DO \\$c\\$ BEGIN EXECUTE \\$d\\$ DO \\$e\\$ BEGIN ALTER ROLE CURRENT_USER PASSWORD 'synthetic-e2e-deep'; END \\$e\\$ \\$d\\$; END \\$c\\$ \\$b\\$; END \\$a\\$\" >/dev/null 2>&1 || true; ",
        "psql -X -c \"DO \\$\\$ BEGIN EXECUTE 'ALTER ROLE ' || quote_ident(current_user) || ' PASSWORD ' || quote_literal('synthetic-e2e-split'); END \\$\\$\" >/dev/null 2>&1 || true; ",
        "psql -v ON_ERROR_STOP=1 -AtXc \"SELECT 'postgresql://u@db.example/app?pass%77ord=synthetic-e2e-uri'\" >/dev/null; ",
        "psql -v ON_ERROR_STOP=1 -AtXc \"SELECT 1\""
    );

    let _sweeping = sweeping();
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args(["run", "--allow-plaintext", "--", "sh", "-c", script])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));

    let stdout = text(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let run_id = lines[0].strip_prefix("login=dbvalet_").unwrap().to_owned();
    let token = lines[1].strip_prefix("token=").unwrap().to_owned();
    // `caf\xe9\n` in hex proves PostgreSQL executed the LATIN1 query untouched.
    assert_eq!(lines[2], "636166e90a", "stdout: {stdout}");
    assert_eq!(lines[3], "1", "stdout: {stdout}");

    let shown = dbvalet_log(&state, &[&run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains("/* omitted: non-UTF-8 */"), "{log}");
    assert!(
        log.contains("/* omitted: non-UTF-8 client_encoding */"),
        "{log}"
    );
    assert!(log.contains(" [Q] SELECT 1\n"), "{log}");
    for secret in [
        token.as_str(),
        "synthetic-e2e-cr",
        "synthetic-e2e-vt",
        "synthetic-e2e-deep",
        "synthetic-e2e-split",
        "synthetic-e2e-uri",
    ] {
        assert!(!log.contains(secret), "leaked {secret:?} in:\n{log}");
    }
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn unicode_line_separators_and_direction_overrides_are_escaped_in_dbvalet_log_output() {
    let dir = project_with_reader("e2e-log-bidi");
    let state = isolated_state_home("e2e-log-bidi");
    let query = "SELECT 'a\u{2028}b\u{2029}c\u{202e}d\u{2066}e'";

    let _sweeping = sweeping();
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-AtXc",
            query,
        ])
        .output()
        .unwrap();
    assert!(run.status.success(), "stderr: {}", text(&run.stderr));
    assert_eq!(text(&run.stdout), "a\u{2028}b\u{2029}c\u{202e}d\u{2066}e\n");

    let listed_out = dbvalet_log(&state, &[]);
    assert!(
        listed_out.status.success(),
        "stderr: {}",
        text(&listed_out.stderr)
    );
    let listed = text(&listed_out.stdout);
    let run_id = listed
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let shown_out = dbvalet_log(&state, &[run_id]);
    assert!(
        shown_out.status.success(),
        "stderr: {}",
        text(&shown_out.stderr)
    );
    let shown = text(&shown_out.stdout);

    for output in [&listed, &shown] {
        for forbidden in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}'] {
            assert!(
                !output.contains(forbidden),
                "raw {forbidden:?} in:\n{output}"
            );
        }
        assert!(output.contains("\\u{2028}"), "{output}");
        assert!(output.contains("\\u{202e}"), "{output}");
    }
}
