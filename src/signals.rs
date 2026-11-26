//! Signal handling and parent-death wiring for a run's child process.
//!
//! dbvalet and its child share the terminal's process group:
//! - On `SIGINT`, dbvalet keeps waiting for the child (which received `SIGINT` too).
//! - On `SIGTERM` or `SIGHUP`, dbvalet forwards the signal to the child, waits up to
//!   [`SIGNAL_WAIT_TIMEOUT`], and lets teardown proceed whether or not the child exited.
//! - On Linux, the child receives `PR_SET_PDEATHSIG(SIGTERM)` via an internal self-exec
//!   shim so it exits if dbvalet is killed with `SIGKILL`. macOS has no equivalent kernel
//!   mechanism; an orphaned child there keeps running without database access once the
//!   proxy is gone.

#[cfg(any(target_os = "linux", test))]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::pin::Pin;
use std::process::ExitStatus;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tokio::process::Child;
use tokio::signal::unix::{self, SignalKind};
use tokio::time::Sleep;

/// How long dbvalet waits for the child to exit after forwarding `SIGTERM` or `SIGHUP`
/// before tearing down the proxy and dropping the temporary login anyway.
pub const SIGNAL_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(any(target_os = "linux", test))]
const PDEATHSIG_SHIM_ARG: &str = "__dbvalet-pdeathsig-exec";

#[cfg(target_os = "linux")]
const SELF_EXE: &str = "/proc/self/exe";

/// Only `main()` enables the self-exec shim so library unit tests on Linux don't re-exec
/// the `cargo test` harness binary.
#[cfg(target_os = "linux")]
static PDEATHSIG_SHIM_ENABLED: AtomicBool = AtomicBool::new(false);

/// Signals that dbvalet forwards to the child before running a bounded-wait teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationSignal {
    Terminate,
    Hangup,
}

impl TerminationSignal {
    pub fn name(self) -> &'static str {
        self.as_nix().as_str()
    }

    pub fn number(self) -> i32 {
        self.as_nix() as i32
    }

    fn as_nix(self) -> Signal {
        match self {
            Self::Terminate => Signal::SIGTERM,
            Self::Hangup => Signal::SIGHUP,
        }
    }
}

/// Result of waiting for a run's child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The child exited before any teardown deadline elapsed.
    Exited(ExitStatus),
    /// A signal arrived after minting the login and before spawning the child.
    SignalledBeforeSpawn(i32),
    /// dbvalet forwarded the signal and the child didn't exit within the grace period.
    TimedOut(TerminationSignal),
}

enum SignalStream {
    Os(unix::Signal),
    #[cfg(test)]
    Test(tokio::sync::mpsc::UnboundedReceiver<()>),
}

impl SignalStream {
    async fn recv(&mut self) -> Option<()> {
        match self {
            Self::Os(signal) => signal.recv().await,
            #[cfg(test)]
            Self::Test(rx) => rx.recv().await,
        }
    }
}

/// Active signal handlers for a single run. Must be installed before starting the proxy
/// and spawning the child so a signal arriving during startup isn't missed.
pub struct RunSignals {
    interrupt: SignalStream,
    terminate: SignalStream,
    hangup: SignalStream,
}

impl RunSignals {
    pub fn install() -> io::Result<Self> {
        Ok(Self {
            interrupt: SignalStream::Os(unix::signal(SignalKind::interrupt())?),
            terminate: SignalStream::Os(unix::signal(SignalKind::terminate())?),
            hangup: SignalStream::Os(unix::signal(SignalKind::hangup())?),
        })
    }

    /// Returns the signal number if `SIGTERM`, `SIGHUP` or `SIGINT` already arrived since
    /// [`Self::install`], without waiting for a future signal.
    pub async fn poll_pending(&mut self) -> Option<i32> {
        // Let tokio's signal driver drain any OS signal delivered right before this check.
        tokio::task::yield_now().await;
        tokio::select! {
            biased;

            Some(()) = self.terminate.recv() => Some(Signal::SIGTERM as i32),
            Some(()) = self.hangup.recv() => Some(Signal::SIGHUP as i32),
            Some(()) = self.interrupt.recv() => Some(Signal::SIGINT as i32),
            () = std::future::ready(()) => None,
        }
    }

    /// Waits for `child` to exit while handling `SIGINT`, `SIGTERM` and `SIGHUP`.
    ///
    /// On `SIGINT`, waits for `child` without forwarding a second signal. On `SIGTERM` or
    /// `SIGHUP`, forwards the signal to `child` and returns [`WaitOutcome::TimedOut`] if
    /// `child` hasn't exited within `timeout`.
    pub async fn wait(&mut self, child: &mut Child, timeout: Duration) -> io::Result<WaitOutcome> {
        // Capture the PID before polling `wait()` to completion: until `waitpid` reaps the
        // child, its PID stays reserved in the process table and cannot be reused.
        let child_pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(Pid::from_raw);
        let child_exit = child.wait();
        tokio::pin!(child_exit);

        let mut triggered: Option<TerminationSignal> = None;
        let mut deadline: Option<Pin<Box<Sleep>>> = None;

        loop {
            tokio::select! {
                biased;

                status = &mut child_exit => {
                    return status.map(WaitOutcome::Exited);
                }
                () = wait_deadline(&mut deadline) => {
                    let signal = triggered.expect("deadline is only armed after a termination signal");
                    return Ok(WaitOutcome::TimedOut(signal));
                }
                Some(()) = self.interrupt.recv() => {
                    // dbvalet and the child share the terminal's process group, so Ctrl-C
                    // already reached the child; keep waiting until it exits.
                }
                Some(()) = self.terminate.recv() => {
                    forward_signal(child_pid, TerminationSignal::Terminate);
                    arm_deadline(&mut triggered, &mut deadline, TerminationSignal::Terminate, timeout);
                }
                Some(()) = self.hangup.recv() => {
                    // Forward SIGHUP directly too, so a SIGHUP sent only to dbvalet's PID
                    // reaches the child before the grace-period teardown runs.
                    forward_signal(child_pid, TerminationSignal::Hangup);
                    arm_deadline(&mut triggered, &mut deadline, TerminationSignal::Hangup, timeout);
                }
            }
        }
    }
}

async fn wait_deadline(deadline: &mut Option<Pin<Box<Sleep>>>) {
    match deadline.as_mut() {
        Some(sleep) => sleep.await,
        None => std::future::pending().await,
    }
}

fn forward_signal(child_pid: Option<Pid>, sig: TerminationSignal) {
    if let Some(pid) = child_pid {
        // `ESRCH` means the child already exited and `child.wait()` is about to return it.
        let _ = signal::kill(pid, sig.as_nix());
    }
}

fn arm_deadline(
    triggered: &mut Option<TerminationSignal>,
    deadline: &mut Option<Pin<Box<Sleep>>>,
    sig: TerminationSignal,
    timeout: Duration,
) {
    // Keep the first deadline so repeated signals can't delay teardown indefinitely.
    if triggered.is_none() {
        *triggered = Some(sig);
        *deadline = Some(Box::pin(tokio::time::sleep(timeout)));
    }
}

/// On Linux, handles the internal self-exec invocation that sets `PR_SET_PDEATHSIG(SIGTERM)`
/// without `unsafe`, and otherwise enables the shim for child processes spawned by this binary.
/// Must be called at the start of `main()` before starting the async runtime. No-op elsewhere.
pub fn init_parent_death_shim() {
    #[cfg(target_os = "linux")]
    {
        let args: Vec<OsString> = std::env::args_os().collect();
        let Some(parsed) = parse_pdeathsig_shim_args(&args) else {
            PDEATHSIG_SHIM_ENABLED.store(true, Ordering::Relaxed);
            return;
        };
        let exec = match parsed {
            Ok(exec) => exec,
            Err(reason) => {
                let _ = writeln!(
                    io::stderr(),
                    "dbvalet: invalid internal exec arguments: {reason}"
                );
                std::process::exit(1);
            }
        };
        if let Err(err) = nix::sys::prctl::set_pdeathsig(Signal::SIGTERM) {
            let _ = writeln!(
                io::stderr(),
                "dbvalet: couldn't set PR_SET_PDEATHSIG: {err}"
            );
            std::process::exit(1);
        }
        // Close the fork-to-prctl race: if dbvalet died before PR_SET_PDEATHSIG took
        // effect, we were already reparented and won't receive the death signal.
        if nix::unistd::getppid() != Pid::from_raw(exec.parent_pid) {
            let _ = signal::raise(Signal::SIGTERM);
            std::process::exit(128 + Signal::SIGTERM as i32);
        }
        let err = std::process::Command::new(exec.program)
            .args(exec.args)
            .exec();
        let _ = writeln!(
            io::stderr(),
            "dbvalet: couldn't start `{}`: {err}",
            exec.program.to_string_lossy()
        );
        // Exit 1 to match `RunError::Spawn` on platforms that spawn the child directly.
        std::process::exit(1);
    }
}

/// Builds the base `Command` for the run's child. On Linux (when running through `main`),
/// wraps it with the self-exec shim so the child gets `PR_SET_PDEATHSIG(SIGTERM)`.
///
/// The caller must spawn on the process's main thread (`current_thread` runtime), because
/// Linux delivers `PR_SET_PDEATHSIG` when the spawning thread exits rather than the process.
pub(crate) fn child_command_base(command: &[OsString]) -> tokio::process::Command {
    let (program, args) = command.split_first().expect("run needs a command");
    #[cfg(target_os = "linux")]
    if PDEATHSIG_SHIM_ENABLED.load(Ordering::Relaxed) {
        // Execute /proc/self/exe directly rather than reading its symlink path: after an
        // in-place binary upgrade, readlink returns "... (deleted)" and fails with ENOENT,
        // whereas /proc/self/exe resolves to the running binary's open inode.
        let mut shim = tokio::process::Command::new(SELF_EXE);
        shim.args(pdeathsig_shim_args(std::process::id(), command));
        return shim;
    }
    let mut child = tokio::process::Command::new(program);
    child.args(args);
    child
}

#[cfg(any(target_os = "linux", test))]
fn pdeathsig_shim_args(parent_pid: u32, command: &[OsString]) -> Vec<OsString> {
    let mut args = Vec::with_capacity(command.len() + 3);
    args.push(OsString::from(PDEATHSIG_SHIM_ARG));
    args.push(OsString::from(parent_pid.to_string()));
    args.push(OsString::from("--"));
    args.extend(command.iter().cloned());
    args
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct PdeathsigExec<'a> {
    parent_pid: i32,
    program: &'a OsStr,
    args: &'a [OsString],
}

#[cfg(any(target_os = "linux", test))]
fn parse_pdeathsig_shim_args(args: &[OsString]) -> Option<Result<PdeathsigExec<'_>, &'static str>> {
    if args.get(1).and_then(|arg| arg.to_str()) != Some(PDEATHSIG_SHIM_ARG) {
        return None;
    }
    let Some(pid_arg) = args.get(2).and_then(|arg| arg.to_str()) else {
        return Some(Err("missing parent PID"));
    };
    let Ok(parent_pid) = pid_arg.parse::<i32>() else {
        return Some(Err("parent PID is not an integer"));
    };
    if parent_pid <= 0 {
        return Some(Err("parent PID must be positive"));
    }
    if args.get(3).and_then(|arg| arg.to_str()) != Some("--") {
        return Some(Err("missing `--` separator"));
    }
    let Some((program, child_args)) = args.get(4..)?.split_first() else {
        return Some(Err("missing child command"));
    };
    Some(Ok(PdeathsigExec {
        parent_pid,
        program: program.as_os_str(),
        args: child_args,
    }))
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;
    use std::time::Instant;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::mpsc;

    use super::*;

    fn test_signals() -> (
        RunSignals,
        mpsc::UnboundedSender<()>,
        mpsc::UnboundedSender<()>,
        mpsc::UnboundedSender<()>,
    ) {
        let (int_tx, int_rx) = mpsc::unbounded_channel();
        let (term_tx, term_rx) = mpsc::unbounded_channel();
        let (hup_tx, hup_rx) = mpsc::unbounded_channel();
        let signals = RunSignals {
            interrupt: SignalStream::Test(int_rx),
            terminate: SignalStream::Test(term_rx),
            hangup: SignalStream::Test(hup_rx),
        };
        (signals, int_tx, term_tx, hup_tx)
    }

    async fn wait_for_ready(child: &mut Child) {
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await.unwrap() {
            if line == "READY" {
                return;
            }
        }
        panic!("child exited before printing READY");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poll_pending_returns_none_when_no_signal_arrived() {
        let (mut signals, _int, _term, _hup) = test_signals();
        assert_eq!(signals.poll_pending().await, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poll_pending_returns_a_signal_that_arrived_before_spawn() {
        let (mut signals, int, term, _hup) = test_signals();
        int.send(()).unwrap();
        assert_eq!(signals.poll_pending().await, Some(Signal::SIGINT as i32));

        term.send(()).unwrap();
        assert_eq!(signals.poll_pending().await, Some(Signal::SIGTERM as i32));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sigint_waits_for_the_child_without_forwarding_a_duplicate_signal() {
        let (mut signals, int, _term, _hup) = test_signals();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "trap 'exit 99' INT; echo READY; read line; exit 7"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        wait_for_ready(&mut child).await;

        int.send(()).unwrap();
        let release_child = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            stdin.write_all(b"\n").await.unwrap();
            drop(stdin);
        });
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            signals.wait(&mut child, Duration::from_millis(50)),
        )
        .await
        .expect("wait should return once the child exits")
        .unwrap();
        release_child.await.unwrap();

        match outcome {
            WaitOutcome::Exited(status) => assert_eq!(status.code(), Some(7)),
            other => panic!("SIGINT should wait for exit, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sigterm_is_forwarded_to_the_child_and_returns_its_exit_status() {
        let (mut signals, _int, term, _hup) = test_signals();
        let mut child = tokio::process::Command::new("python3")
            .args([
                "-c",
                "import signal, sys; \
                 signal.signal(signal.SIGTERM, lambda *_: sys.exit(42)); \
                 print('READY', flush=True); \
                 signal.pause()",
            ])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        wait_for_ready(&mut child).await;

        term.send(()).unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            signals.wait(&mut child, Duration::from_secs(2)),
        )
        .await
        .expect("child should exit promptly after forwarded SIGTERM")
        .unwrap();

        match outcome {
            WaitOutcome::Exited(status) => assert_eq!(status.code(), Some(42)),
            other => panic!("expected child to exit, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sigterm_to_a_child_that_ignores_it_returns_timed_out_after_the_deadline() {
        let (mut signals, _int, term, _hup) = test_signals();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "trap '' TERM; echo READY; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        wait_for_ready(&mut child).await;

        term.send(()).unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            signals.wait(&mut child, Duration::from_millis(150)),
        )
        .await
        .expect("wait should return after the grace period")
        .unwrap();

        assert_eq!(outcome, WaitOutcome::TimedOut(TerminationSignal::Terminate));
        drop(stdin);
        let _ = child.wait().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sighup_is_forwarded_to_the_child_and_returns_its_exit_status() {
        let (mut signals, _int, _term, hup) = test_signals();
        // Use python3 rather than `sh -c trap`, because POSIX forbids a non-interactive
        // shell from trapping SIGHUP if the test runner started with SIGHUP ignored.
        let mut child = tokio::process::Command::new("python3")
            .args([
                "-c",
                "import signal, sys; \
                 signal.signal(signal.SIGHUP, lambda *_: sys.exit(43)); \
                 print('READY', flush=True); \
                 signal.pause()",
            ])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        wait_for_ready(&mut child).await;

        hup.send(()).unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            signals.wait(&mut child, Duration::from_secs(2)),
        )
        .await
        .expect("child should exit promptly after forwarded SIGHUP")
        .unwrap();

        match outcome {
            WaitOutcome::Exited(status) => assert_eq!(status.code(), Some(43)),
            other => panic!("expected child to exit, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sighup_to_a_child_that_ignores_it_returns_timed_out_after_the_deadline() {
        let (mut signals, _int, _term, hup) = test_signals();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "trap '' HUP; echo READY; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        wait_for_ready(&mut child).await;

        hup.send(()).unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            signals.wait(&mut child, Duration::from_millis(150)),
        )
        .await
        .expect("wait should return after the grace period")
        .unwrap();

        assert_eq!(outcome, WaitOutcome::TimedOut(TerminationSignal::Hangup));
        drop(stdin);
        let _ = child.wait().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_second_termination_signal_does_not_extend_the_deadline() {
        let (mut signals, _int, term, hup) = test_signals();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "trap '' TERM HUP; echo READY; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        wait_for_ready(&mut child).await;

        let started = Instant::now();
        term.send(()).unwrap();
        let second = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(350)).await;
            let _ = hup.send(());
        });
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            signals.wait(&mut child, Duration::from_millis(500)),
        )
        .await
        .expect("wait should keep the original deadline")
        .unwrap();
        second.await.unwrap();

        assert_eq!(outcome, WaitOutcome::TimedOut(TerminationSignal::Terminate));
        // A reset deadline would expire at ~850 ms (350 + 500); the original ends at ~500 ms.
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "second signal extended the deadline: {:?}",
            started.elapsed()
        );
        drop(stdin);
        let _ = child.wait().await;
    }

    #[test]
    fn pdeathsig_shim_arguments_round_trip_with_child_dashes() {
        let command = vec![
            OsString::from("psql"),
            OsString::from("--"),
            OsString::from("-c"),
            OsString::from("SELECT 1"),
        ];
        let mut argv = vec![OsString::from("/usr/local/bin/dbvalet")];
        argv.extend(pdeathsig_shim_args(12345, &command));

        let exec = parse_pdeathsig_shim_args(&argv)
            .expect("shim marker should be recognized")
            .expect("valid shim invocation should parse");

        assert_eq!(exec.parent_pid, 12345);
        assert_eq!(exec.program, OsStr::new("psql"));
        assert_eq!(
            exec.args,
            &[
                OsString::from("--"),
                OsString::from("-c"),
                OsString::from("SELECT 1"),
            ]
        );
    }

    #[test]
    fn pdeathsig_shim_parser_ignores_normal_invocations() {
        let normal = vec![OsString::from("dbvalet"), OsString::from("run")];
        assert!(parse_pdeathsig_shim_args(&normal).is_none());
    }

    #[test]
    fn pdeathsig_shim_parser_rejects_malformed_shim_args() {
        let missing_pid = vec![
            OsString::from("dbvalet"),
            OsString::from(PDEATHSIG_SHIM_ARG),
        ];
        assert!(parse_pdeathsig_shim_args(&missing_pid).unwrap().is_err());

        let zero_pid = vec![
            OsString::from("dbvalet"),
            OsString::from(PDEATHSIG_SHIM_ARG),
            OsString::from("0"),
            OsString::from("--"),
            OsString::from("true"),
        ];
        assert!(parse_pdeathsig_shim_args(&zero_pid).unwrap().is_err());

        let missing_separator = vec![
            OsString::from("dbvalet"),
            OsString::from(PDEATHSIG_SHIM_ARG),
            OsString::from("42"),
            OsString::from("true"),
        ];
        assert!(
            parse_pdeathsig_shim_args(&missing_separator)
                .unwrap()
                .is_err()
        );

        let missing_command = vec![
            OsString::from("dbvalet"),
            OsString::from(PDEATHSIG_SHIM_ARG),
            OsString::from("42"),
            OsString::from("--"),
        ];
        assert!(
            parse_pdeathsig_shim_args(&missing_command)
                .unwrap()
                .is_err()
        );
    }
}
