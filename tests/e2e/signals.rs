//! SIGINT, SIGTERM, SIGHUP, SIGKILL and setup interrupts.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use crate::support::{
    DBVALET, SUPERUSER_URL, create_reader_group, gc_command, ledger_entry, login,
    project_with_reader, runtime, superuser_count, superuser_sql, sweeping, sweeping_alone, text,
    wait_for_active_query,
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

    use crate::support::gc_in;

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
