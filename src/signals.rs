//! Signal handling and parent-death wiring for a run's child process.
//!
//! dbvalet and its child share the terminal's process group:
//! - Two Ctrl-C presses (`SIGINT`) end the run: the first prints a short hint on stderr
//!   and waits for the child (which in a terminal process group received `SIGINT` too), and
//!   the second forwards `SIGTERM` to the child and starts the [`SIGNAL_WAIT_TIMEOUT`]
//!   deadline, tearing down when the child exits or after 5 seconds if it hasn't (returning
//!   the child's code, or `130` on timeout). `SIGINT`s sent in quick succession may be
//!   coalesced by tokio and count as one; supervisors and scripts should send `SIGTERM`,
//!   which ends the run within [`SIGNAL_WAIT_TIMEOUT`].
//! - On `SIGTERM` or `SIGHUP`, dbvalet forwards the signal to the child and tears down
//!   when it exits, or after [`SIGNAL_WAIT_TIMEOUT`] if it hasn't (returning the child's
//!   code, or `143` / `129` on timeout). Earlier deadlines are never extended by
//!   subsequent signals.
//! - On Linux, the child receives `PR_SET_PDEATHSIG(SIGTERM)` via `process-wrap`'s
//!   `PropagateThreadDeath` so it exits if dbvalet is killed with `SIGKILL`. A set-user-ID
//!   or file-capability child, or a grandchild, isn't killed when dbvalet is `SIGKILL`ed;
//!   it still loses database access when the proxy stops, and `gc` or the next run drops
//!   the login. macOS has no equivalent kernel mechanism, so an orphaned child there keeps
//!   running without database access once the proxy is gone, and `gc` or the next run drops
//!   the login.

use std::io::{self, Write};
use std::pin::Pin;
use std::process::ExitStatus;
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tokio::process::Child;
use tokio::signal::unix::{self, SignalKind};
use tokio::time::Sleep;

/// How long dbvalet waits for the child to exit after a second `SIGINT`, `SIGTERM` or
/// `SIGHUP` before tearing down the proxy and dropping the temporary login anyway.
pub const SIGNAL_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Signals that can trigger a bounded-wait teardown of the run's child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationSignal {
    Interrupt,
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
            Self::Interrupt => Signal::SIGINT,
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
    /// A signal arrived before the child was spawned.
    SignalledBeforeSpawn(i32),
    /// dbvalet forwarded a stop signal (`SIGTERM` or `SIGHUP`) and the child didn't exit
    /// within the grace period.
    TimedOut(TerminationSignal),
}

/// A running child process spawned by [`spawn_child`].
pub struct SpawnedChild {
    #[cfg(target_os = "linux")]
    inner: Box<dyn process_wrap::tokio::ChildWrapper>,
    #[cfg(not(target_os = "linux"))]
    inner: Child,
}

impl SpawnedChild {
    pub fn id(&self) -> Option<u32> {
        self.inner.id()
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait().await
    }
}

impl From<Child> for SpawnedChild {
    fn from(child: Child) -> Self {
        #[cfg(target_os = "linux")]
        let inner: Box<dyn process_wrap::tokio::ChildWrapper> = Box::new(child);
        #[cfg(not(target_os = "linux"))]
        let inner = child;
        Self { inner }
    }
}

/// Spawns `command`. On Linux, attaches `PR_SET_PDEATHSIG(SIGTERM)` through `process-wrap`'s
/// `PropagateThreadDeath`, including its spawning-thread check.
///
/// Must be called from the `current_thread` runtime's main thread (never from
/// `spawn_blocking` or `block_in_place`), because Linux delivers `PR_SET_PDEATHSIG` when the
/// spawning thread exits rather than when the process exits.
pub fn spawn_child(command: tokio::process::Command) -> io::Result<SpawnedChild> {
    #[cfg(target_os = "linux")]
    {
        let mut wrapped = process_wrap::tokio::CommandWrap::from(command);
        wrapped.wrap(process_wrap::tokio::PropagateThreadDeath::default());
        // Spawn on the current-thread runtime's main thread so PR_SET_PDEATHSIG fires only when dbvalet exits.
        Ok(SpawnedChild {
            inner: wrapped.spawn()?,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut command = command;
        Ok(SpawnedChild {
            inner: command.spawn()?,
        })
    }
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
            signal = self.next_signal() => Some(signal),
            () = std::future::ready(()) => None,
        }
    }

    pub(crate) async fn next_signal(&mut self) -> i32 {
        tokio::select! {
            biased;
            Some(()) = self.terminate.recv() => Signal::SIGTERM as i32,
            Some(()) = self.hangup.recv() => Signal::SIGHUP as i32,
            Some(()) = self.interrupt.recv() => Signal::SIGINT as i32,
            else => std::future::pending().await,
        }
    }

    /// Waits for `child` to exit while handling `SIGINT`, `SIGTERM` and `SIGHUP`.
    ///
    /// On the first `SIGINT`, prints a hint and waits for `child` without forwarding a
    /// duplicate signal. On a second `SIGINT`, forwards `SIGTERM` to `child` and starts
    /// `timeout` (returning `TimedOut(Interrupt)` if `child` doesn't exit in time). On
    /// `SIGTERM` or `SIGHUP`, forwards the signal to `child` and starts `timeout`.
    pub async fn wait(
        &mut self,
        child: &mut SpawnedChild,
        timeout: Duration,
    ) -> io::Result<WaitOutcome> {
        // Capture the PID before polling `wait()` to completion: until `waitpid` reaps the
        // child, its PID stays reserved in the process table and cannot be reused.
        let child_pid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(Pid::from_raw);
        let child_exit = child.wait();
        tokio::pin!(child_exit);

        let mut interrupted_once = false;
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
                    if triggered.is_some() {
                        // A teardown deadline is already running; don't print the first-Ctrl-C
                        // hint or extend the existing deadline.
                    } else if !interrupted_once {
                        // dbvalet and the child share the terminal's process group, so Ctrl-C
                        // already reached the child; wait for it to exit cleanly.
                        interrupted_once = true;
                        let _ = writeln!(
                            io::stderr(),
                            "dbvalet: waiting for the command to exit; press Ctrl-C again to stop it and drop the temporary login"
                        );
                    } else {
                        // A second SIGINT (from the group or sent to dbvalet's PID alone)
                        // forces teardown the same way SIGTERM does.
                        forward_signal(child_pid, Signal::SIGTERM);
                        arm_deadline(&mut triggered, &mut deadline, TerminationSignal::Interrupt, timeout);
                    }
                }
                Some(()) = self.terminate.recv() => {
                    forward_signal(child_pid, Signal::SIGTERM);
                    arm_deadline(&mut triggered, &mut deadline, TerminationSignal::Terminate, timeout);
                }
                Some(()) = self.hangup.recv() => {
                    // Forward SIGHUP directly too, so a SIGHUP sent only to dbvalet's PID
                    // reaches the child before the grace-period teardown runs.
                    forward_signal(child_pid, Signal::SIGHUP);
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

fn forward_signal(child_pid: Option<Pid>, sig: Signal) {
    if let Some(pid) = child_pid {
        // `ESRCH` means the child already exited and `child.wait()` is about to return it.
        let _ = signal::kill(pid, sig);
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
        let mut child = SpawnedChild::from(child);

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
    async fn a_second_sigint_forwards_sigterm_to_the_child_and_returns_its_exit_status() {
        let (mut signals, int, _term, _hup) = test_signals();
        let mut child = tokio::process::Command::new("python3")
            .args([
                "-c",
                "import signal, sys; \
                 signal.signal(signal.SIGTERM, lambda *_: sys.exit(44)); \
                 print('READY', flush=True); \
                 signal.pause()",
            ])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        wait_for_ready(&mut child).await;
        let mut child = SpawnedChild::from(child);

        int.send(()).unwrap();
        let second = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let _ = int.send(());
        });
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            signals.wait(&mut child, Duration::from_secs(1)),
        )
        .await
        .expect("child should exit promptly after the second SIGINT forwards SIGTERM")
        .unwrap();
        second.await.unwrap();

        match outcome {
            WaitOutcome::Exited(status) => assert_eq!(status.code(), Some(44)),
            other => panic!("expected child to exit, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_second_sigint_to_a_child_that_ignores_sigterm_times_out_with_interrupt() {
        let (mut signals, int, _term, _hup) = test_signals();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "trap '' TERM; echo READY; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        wait_for_ready(&mut child).await;
        let mut child = SpawnedChild::from(child);

        int.send(()).unwrap();
        let second = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let _ = int.send(());
        });
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            signals.wait(&mut child, Duration::from_millis(150)),
        )
        .await
        .expect("wait should return after the grace period on a second SIGINT")
        .unwrap();
        second.await.unwrap();

        assert_eq!(outcome, WaitOutcome::TimedOut(TerminationSignal::Interrupt));
        drop(stdin);
        let _ = child.wait().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sigint_after_sigterm_does_not_extend_the_deadline_or_replace_the_signal() {
        let (mut signals, int, term, _hup) = test_signals();
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "trap '' INT TERM; echo READY; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        wait_for_ready(&mut child).await;
        let mut child = SpawnedChild::from(child);

        let started = Instant::now();
        term.send(()).unwrap();
        let follow_ups = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = int.send(());
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = int.send(());
        });
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            signals.wait(&mut child, Duration::from_millis(500)),
        )
        .await
        .expect("wait should keep the original SIGTERM deadline")
        .unwrap();
        follow_ups.await.unwrap();

        assert_eq!(outcome, WaitOutcome::TimedOut(TerminationSignal::Terminate));
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "SIGINT after SIGTERM extended the deadline: {:?}",
            started.elapsed()
        );
        drop(stdin);
        let _ = child.wait().await;
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
        let mut child = SpawnedChild::from(child);

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
        let mut child = SpawnedChild::from(child);

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
        let mut child = SpawnedChild::from(child);

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
        let mut child = SpawnedChild::from(child);

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
        let mut child = SpawnedChild::from(child);

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

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_child_on_linux_ends_the_child_when_the_spawning_thread_exits() {
        use std::io::{BufRead, Read};

        let (read_end, write_end) = std::io::pipe().unwrap();
        let (exit_tx, exit_rx) = std::sync::mpsc::channel();
        let spawner = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut cmd = tokio::process::Command::new("sh");
                cmd.args(["-c", "echo READY; exec sleep 60"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(write_end));
                let _child = spawn_child(cmd).unwrap();
                let _ = exit_rx.recv();
            });
        });

        let mut reader = std::io::BufReader::new(read_end);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "READY\n");

        exit_tx.send(()).unwrap();
        spawner.join().unwrap();

        let (eof_tx, eof_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = Vec::new();
            let _ = reader.read_to_end(&mut rest);
            let _ = eof_tx.send(());
        });
        assert!(
            eof_rx.recv_timeout(Duration::from_secs(3)).is_ok(),
            "child should exit via PR_SET_PDEATHSIG(SIGTERM) when the spawning thread exits"
        );
    }
}
