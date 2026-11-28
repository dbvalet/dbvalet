//! `dbvalet` against real SSL-enabled PostgreSQL in Docker and the real OS keychain.
//!
//! Expects:
//! - `DBVALET_E2E_CA_CERT`: path to the throwaway CA PEM certificate.
//! - `DBVALET_E2E_TLS_PORT` (default `5432`): SSL PostgreSQL whose leaf cert matches `localhost`
//!   and `127.0.0.1` and is signed by `DBVALET_E2E_CA_CERT`.
//! - `DBVALET_E2E_WRONG_HOST_PORT` (default `5433`): SSL PostgreSQL signed by the same CA whose
//!   leaf cert is for `wrong-host.example.test` (not `localhost`).

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use dbvalet::endpoint::{ChannelBinding, Endpoint, TrustRoot};
use dbvalet::proxy;
use dbvalet::source::{AccessDeadline, UpstreamLogin};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use secrecy::{ExposeSecret, SecretString};
use tokio_postgres::NoTls;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::{DbError, SqlState};

const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");

fn ca_cert() -> String {
    std::env::var("DBVALET_E2E_CA_CERT").expect("DBVALET_E2E_CA_CERT must be set for e2e_tls")
}

fn tls_port() -> String {
    std::env::var("DBVALET_E2E_TLS_PORT").unwrap_or_else(|_| "5432".to_owned())
}

fn wrong_host_port() -> String {
    std::env::var("DBVALET_E2E_WRONG_HOST_PORT").unwrap_or_else(|_| "5433".to_owned())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn superuser_psql(port: &str, sql: &str) -> String {
    let output = Command::new("psql")
        .env("PGHOST", "localhost")
        .env("PGPORT", port)
        .env("PGUSER", "postgres")
        .env("PGPASSWORD", "e2e-throwaway")
        .env("PGDATABASE", "postgres")
        .env("PGSSLMODE", "verify-full")
        .env("PGSSLROOTCERT", ca_cert())
        .args(["-v", "ON_ERROR_STOP=1", "-qAtc", sql])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "psql failed: stdout={} stderr={}",
        text(&output.stdout),
        text(&output.stderr)
    );
    text(&output.stdout)
}

fn login(alias: &str, connection_string: &str) -> Output {
    let mut login = Command::new(DBVALET)
        .args(["login", alias])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = login.stdin.take().unwrap();
    writeln!(stdin, "{connection_string}").unwrap();
    drop(stdin);
    login.wait_with_output().unwrap()
}

fn create_reader_group(port: &str) {
    superuser_psql(
        port,
        "DO $$ BEGIN
             CREATE ROLE dbvalet_reader NOLOGIN;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
         END $$;",
    );
}

fn write_project(alias: &str) -> PathBuf {
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
    dir
}

fn run_tls(dir: &Path, command: &[&str]) -> Output {
    Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--"])
        .args(command)
        .output()
        .unwrap()
}

async fn proxy_refusal(endpoint: Endpoint) -> DbError {
    let login = UpstreamLogin::new("postgres".to_owned(), SecretString::from("e2e-throwaway"));
    let token = SecretString::from("e2e-proxy-tls-token");
    let proxy = proxy::start(
        endpoint,
        login,
        token.clone(),
        None,
        AccessDeadline::after(Duration::from_secs(60)),
    )
    .await
    .unwrap();
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(proxy.port())
        .user("postgres")
        .dbname("postgres")
        .password(token.expose_secret())
        .ssl_mode(SslMode::Disable);
    let result = tokio::time::timeout(Duration::from_secs(10), config.connect(NoTls)).await;
    proxy.stop().await;
    result
        .expect("proxy connection timed out")
        .err()
        .expect("the proxy accepted the upstream connection")
        .as_db_error()
        .expect("expected a PostgreSQL error from the proxy")
        .clone()
}

#[tokio::test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
async fn the_proxy_refuses_a_certificate_for_the_wrong_hostname() {
    let endpoint = Endpoint::with_tls_options(
        "localhost".to_owned(),
        wrong_host_port().parse().unwrap(),
        "postgres".to_owned(),
        false,
        TrustRoot::PemFile(PathBuf::from(ca_cert())),
        ChannelBinding::Prefer,
    )
    .unwrap();

    let err = proxy_refusal(endpoint).await;
    assert_eq!(err.code(), &SqlState::CONNECTION_FAILURE);
    assert_eq!(
        err.message(),
        "TLS certificate doesn't match the host `localhost`"
    );
}

#[tokio::test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
async fn the_proxy_refuses_a_certificate_from_an_untrusted_issuer() {
    let endpoint = Endpoint::new(
        "localhost".to_owned(),
        tls_port().parse().unwrap(),
        "postgres".to_owned(),
        false,
    )
    .unwrap();

    let err = proxy_refusal(endpoint).await;
    assert_eq!(err.code(), &SqlState::CONNECTION_FAILURE);
    assert!(err.message().contains("certificate"), "{err}");
    assert!(err.message().contains("sslrootcert"), "{err}");
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn self_signed_ca_with_sslrootcert_passes_doctor_and_run_over_tls() {
    let port = tls_port();
    let ca = ca_cert();
    create_reader_group(&port);
    superuser_psql(
        &port,
        "DROP ROLE IF EXISTS e2e_tls_valid_admin;
         CREATE ROLE e2e_tls_valid_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-tls-valid-1a2b';",
    );
    let stored = login(
        "e2e-tls-valid",
        &format!(
            "postgresql://e2e_tls_valid_admin:pw-e2e-tls-valid-1a2b@localhost:{port}/postgres\
             ?sslmode=verify-full&sslrootcert={ca}"
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-valid"])
        .output()
        .unwrap();
    let doctor_stdout = text(&checked.stdout);
    let doctor_stderr = text(&checked.stderr);
    assert!(
        checked.status.success(),
        "doctor stdout: {doctor_stdout}\nstderr: {doctor_stderr}"
    );
    assert!(
        doctor_stdout.contains(&format!("ok   TLS verify-full using sslrootcert `{ca}`\n")),
        "doctor: {doctor_stdout}"
    );
    assert!(!doctor_stdout.contains("pw-e2e-tls-valid-1a2b"));
    assert!(!doctor_stderr.contains("pw-e2e-tls-valid-1a2b"));

    let dir = write_project("e2e-tls-valid");
    let run = run_tls(
        &dir,
        &[
            "psql",
            "-Atc",
            "SELECT ssl, current_user FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        ],
    );
    let run_stdout = text(&run.stdout);
    let run_stderr = text(&run.stderr);
    assert!(run.status.success(), "run stderr: {run_stderr}");
    let line = run_stdout.trim();
    let (ssl, login_name) = line
        .split_once('|')
        .unwrap_or_else(|| panic!("expected ssl|user, got: {run_stdout}"));
    assert_eq!(ssl, "t", "expected upstream TLS, got: {run_stdout}");
    assert!(login_name.starts_with("dbvalet_"), "{login_name}");
    assert!(!run_stdout.contains("pw-e2e-tls-valid-1a2b"));
    assert!(!run_stderr.contains("pw-e2e-tls-valid-1a2b"));

    let remaining = superuser_psql(
        &port,
        &format!("SELECT count(*) FROM pg_roles WHERE rolname = '{login_name}'"),
    );
    assert_eq!(remaining.trim(), "0");
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn channel_binding_require_succeeds_for_doctor_and_run_over_tls() {
    let port = tls_port();
    let ca = ca_cert();
    create_reader_group(&port);
    superuser_psql(
        &port,
        "DROP ROLE IF EXISTS e2e_tls_cb_admin;
         CREATE ROLE e2e_tls_cb_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-tls-cb-3c4d';",
    );
    let stored = login(
        "e2e-tls-cb",
        &format!(
            "postgresql://e2e_tls_cb_admin:pw-e2e-tls-cb-3c4d@localhost:{port}/postgres\
             ?sslmode=verify-full&sslrootcert={ca}&channel_binding=require"
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-cb"])
        .output()
        .unwrap();
    let doctor_stdout = text(&checked.stdout);
    assert!(
        checked.status.success(),
        "doctor stdout: {doctor_stdout}\nstderr: {}",
        text(&checked.stderr)
    );

    let dir = write_project("e2e-tls-cb");
    let run = run_tls(
        &dir,
        &[
            "psql",
            "-Atc",
            "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
        ],
    );
    assert!(run.status.success(), "run stderr: {}", text(&run.stderr));
    assert_eq!(text(&run.stdout).trim(), "t");
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn ssl_server_without_sslrootcert_fails_doctor_and_run_naming_sslrootcert() {
    let port = tls_port();
    create_reader_group(&port);
    superuser_psql(
        &port,
        "DROP ROLE IF EXISTS e2e_tls_untrusted_admin;
         CREATE ROLE e2e_tls_untrusted_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-tls-untrusted-5e6f';",
    );
    let stored = login(
        "e2e-tls-untrusted",
        &format!(
            "postgresql://e2e_tls_untrusted_admin:pw-e2e-tls-untrusted-5e6f@localhost:{port}/postgres"
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-untrusted"])
        .output()
        .unwrap();
    let doctor_stdout = text(&checked.stdout);
    let doctor_stderr = text(&checked.stderr);
    assert!(!checked.status.success(), "doctor: {doctor_stdout}");
    assert!(
        doctor_stdout.contains("certificate"),
        "doctor should name certificate error: {doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("sslrootcert"),
        "doctor should name sslrootcert: {doctor_stdout}"
    );
    assert!(!doctor_stdout.contains("pw-e2e-tls-untrusted-5e6f"));
    assert!(!doctor_stderr.contains("pw-e2e-tls-untrusted-5e6f"));

    let dir = write_project("e2e-tls-untrusted");
    let run = run_tls(&dir, &["sh", "-c", "echo child-should-not-run"]);
    let run_stdout = text(&run.stdout);
    let run_stderr = text(&run.stderr);
    assert!(!run.status.success(), "run should fail: {run_stdout}");
    assert!(run_stdout.is_empty(), "child must not run: {run_stdout}");
    assert!(
        run_stderr.contains("certificate"),
        "run should name certificate error: {run_stderr}"
    );
    assert!(
        run_stderr.contains("sslrootcert"),
        "run should name sslrootcert: {run_stderr}"
    );
    assert!(!run_stderr.contains("pw-e2e-tls-untrusted-5e6f"));
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn trusted_ca_with_wrong_hostname_is_refused_by_doctor_and_run() {
    let port = wrong_host_port();
    let ca = ca_cert();
    let stored = login(
        "e2e-tls-wronghost",
        &format!(
            "postgresql://e2e_tls_wronghost_admin:pw-e2e-tls-wrong-7g8h@localhost:{port}/postgres\
             ?sslmode=verify-full&sslrootcert={ca}"
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-wronghost"])
        .output()
        .unwrap();
    let doctor_stdout = text(&checked.stdout);
    let doctor_stderr = text(&checked.stderr);
    assert!(!checked.status.success(), "doctor: {doctor_stdout}");
    assert!(
        doctor_stdout.contains("doesn't match the host"),
        "doctor should report hostname mismatch: {doctor_stdout}"
    );
    assert!(!doctor_stdout.contains("pw-e2e-tls-wrong-7g8h"));
    assert!(!doctor_stderr.contains("pw-e2e-tls-wrong-7g8h"));

    let dir = write_project("e2e-tls-wronghost");
    let run = run_tls(&dir, &["sh", "-c", "echo child-should-not-run"]);
    let run_stdout = text(&run.stdout);
    let run_stderr = text(&run.stderr);
    assert!(!run.status.success(), "run should fail: {run_stdout}");
    assert!(run_stdout.is_empty(), "child must not run: {run_stdout}");
    assert!(
        run_stderr.contains("doesn't match the host"),
        "run should report hostname mismatch: {run_stderr}"
    );
    assert!(!run_stderr.contains("pw-e2e-tls-wrong-7g8h"));
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn sslmode_verify_ca_still_refuses_a_wrong_hostname() {
    let port = wrong_host_port();
    let ca = ca_cert();
    let stored = login(
        "e2e-tls-verify-ca",
        &format!(
            "postgresql://e2e_tls_wronghost_admin:pw-e2e-tls-wrong-7g8h@localhost:{port}/postgres\
             ?sslmode=verify-ca&sslrootcert={ca}"
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-verify-ca"])
        .output()
        .unwrap();
    let doctor_stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {doctor_stdout}");
    assert!(
        doctor_stdout.contains("doesn't match the host"),
        "verify-ca must not bypass hostname verification: {doctor_stdout}"
    );
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn login_refuses_missing_and_empty_sslrootcert_files_naming_the_path() {
    let port = tls_port();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-tls-bad-rootcert");
    std::fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("missing-ca.pem");
    let empty = dir.join("empty-ca.pem");
    std::fs::write(&empty, b"").unwrap();

    for (alias, path) in [
        ("e2e-tls-missing-ca", &missing),
        ("e2e-tls-empty-ca", &empty),
    ] {
        let stored = login(
            alias,
            &format!(
                "postgresql://e2e_tls_valid_admin:pw-e2e-tls-valid-1a2b@localhost:{port}/postgres\
                 ?sslmode=verify-full&sslrootcert={}",
                path.display()
            ),
        );
        let stderr = text(&stored.stderr);
        assert!(!stored.status.success(), "login {alias}: {stderr}");
        assert!(
            stderr.contains(&path.display().to_string()),
            "should name the path: {stderr}"
        );
        assert!(!stderr.contains("pw-e2e-tls-valid-1a2b"), "{stderr}");
    }
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn doctor_names_an_sslrootcert_file_removed_after_login() {
    let port = tls_port();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-tls-removed-rootcert");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("removed-ca.pem");
    std::fs::copy(ca_cert(), &path).unwrap();

    let stored = login(
        "e2e-tls-removed-ca",
        &format!(
            "postgresql://e2e_tls_valid_admin:pw-e2e-tls-valid-1a2b@localhost:{port}/postgres\
             ?sslmode=verify-full&sslrootcert={}",
            path.display()
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    std::fs::remove_file(&path).unwrap();

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-removed-ca"])
        .output()
        .unwrap();
    let stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "{stdout}");
    assert!(
        stdout.contains("removed-ca.pem"),
        "should name the path: {stdout}"
    );
}

#[test]
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn login_refuses_a_ca_bundle_with_an_invalid_certificate() {
    let port = tls_port();
    let project = write_project("e2e-tls-invalid-ca");
    let path = project.join("invalid-ca.pem");
    let mut bundle = std::fs::read(ca_cert()).unwrap();
    bundle.extend_from_slice(b"\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    std::fs::write(&path, bundle).unwrap();

    let stored = login(
        "e2e-tls-invalid-ca",
        &format!(
            "postgresql://test:throwaway@localhost:{port}/postgres?sslrootcert={}",
            path.display()
        ),
    );
    let stderr = text(&stored.stderr);
    assert!(!stored.status.success(), "login: {stderr}");
    assert!(stderr.contains("invalid-ca.pem"), "login: {stderr}");
    assert!(stderr.contains("invalid CA certificate"), "login: {stderr}");
}

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
#[ignore = "e2e_tls: needs SSL PostgreSQL and DBVALET_E2E_CA_CERT"]
fn sigint_to_psql_cancels_a_running_query_through_the_proxy_over_tls() {
    // Far longer than mint, the cancelled query and teardown take together.
    const RUN_DEADLINE: Duration = Duration::from_secs(60);
    // Well before the 30 s the query would sleep without the cancel.
    const CANCEL_WITHIN: Duration = Duration::from_secs(10);
    let port = tls_port();
    let ca = ca_cert();
    create_reader_group(&port);
    superuser_psql(
        &port,
        "DROP ROLE IF EXISTS e2e_tls_cancel_admin;
         CREATE ROLE e2e_tls_cancel_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-tls-cancel-5e6f';",
    );
    let stored = login(
        "e2e-tls-cancel",
        &format!(
            "postgresql://e2e_tls_cancel_admin:pw-e2e-tls-cancel-5e6f@localhost:{port}/postgres\
             ?sslmode=verify-full&sslrootcert={ca}"
        ),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = write_project("e2e-tls-cancel");
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--", "sh", "-c"])
        .arg(
            "echo \"login=$PGUSER\"; echo \"psql=$$\"; echo READY; \
             exec psql -Atc 'SELECT pg_sleep(30)'",
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
    let value = |key: &str| {
        seen.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .unwrap()
            .to_owned()
    };
    let active_query = format!(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = '{}' AND state = 'active'",
        value("login")
    );
    let waiting_until = Instant::now() + Duration::from_secs(10);
    while superuser_psql(&port, &active_query).trim() == "0" {
        assert!(Instant::now() < waiting_until, "the query never started");
    }

    let psql = Pid::from_raw(value("psql").parse().unwrap());
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
