//! Cancelling a running query through the proxy.

use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use crate::support::{printed, project_with_reader, run_command, sweeping, wait_for_active_query};

/// Far longer than mint, the cancelled query and teardown take together.
const RUN_DEADLINE: Duration = Duration::from_secs(60);
/// Well before the 30 s the query would sleep without the cancel.
const CANCEL_WITHIN: Duration = Duration::from_secs(10);

/// The run, SIGKILLed with its whole process group (psql included) and reaped when dropped
/// before it exits, so a failing assertion or a timeout never leaves it running.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Ok(None) = self.0.try_wait() {
            let group = Pid::from_raw(i32::try_from(self.0.id()).unwrap());
            let _ = signal::killpg(group, Signal::SIGKILL);
            let _ = self.0.wait();
        }
    }
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigint_to_psql_cancels_a_running_query_through_the_proxy() {
    let dir = project_with_reader("e2e-cancel-psql");
    let _sweeping = sweeping();
    let run = run_command(
        &dir,
        &[
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; echo \"psql=$$\"; echo READY; \
             exec psql -Atc 'SELECT pg_sleep(30)'",
        ],
    )
    .process_group(0)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let run_group = Pid::from_raw(i32::try_from(run.id()).unwrap());
    let mut run = KillOnDrop(run);
    // Kills the whole run, psql included, if it outlives RUN_DEADLINE, so the reads and
    // the wait below return and the test fails instead of hanging.
    let (finished, finish) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        let expired = finish.recv_timeout(RUN_DEADLINE) == Err(RecvTimeoutError::Timeout);
        if expired {
            let _ = signal::killpg(run_group, Signal::SIGKILL);
        }
        expired
    });
    let mut stdout = BufReader::new(run.0.stdout.take().unwrap());
    let mut seen = String::new();
    while !seen.ends_with("READY\n") {
        assert_ne!(stdout.read_line(&mut seen).unwrap(), 0, "stdout: {seen}");
    }
    wait_for_active_query(printed(&seen, "login"));

    let psql = Pid::from_raw(printed(&seen, "psql").parse().unwrap());
    signal::kill(psql, Signal::SIGINT).unwrap();
    let cancelled_at = Instant::now();
    let mut stderr = String::new();
    run.0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let status = run.0.wait().unwrap();
    let cancelled_after = cancelled_at.elapsed();
    finished.send(()).unwrap();

    assert!(
        !watchdog.join().unwrap(),
        "the run was killed after {RUN_DEADLINE:?}"
    );
    assert!(
        stderr.contains("canceling statement due to user request"),
        "stderr: {stderr}"
    );
    assert!(cancelled_after < CANCEL_WITHIN, "took {cancelled_after:?}");
    assert_eq!(status.code(), Some(1), "stderr: {stderr}");
}
