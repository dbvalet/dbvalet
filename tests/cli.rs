//! The binary's behaviour that needs no database.
//!
//! `login` tests use only `cli-test-*` aliases and inputs refused before anything is stored.

use std::io::Write;
use std::process::{Command, Stdio};

const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");

#[test]
fn version_prints_the_crate_version_and_exits_zero() {
    let output = Command::new(DBVALET).arg("--version").output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!("dbvalet ", env!("CARGO_PKG_VERSION"), "\n")
    );
}

#[test]
fn login_with_a_malformed_connection_string_fails_without_printing_the_password() {
    let mut login = Command::new(DBVALET)
        .args(["login", "cli-test-malformed"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    login
        .stdin
        .take()
        .unwrap()
        .write_all(b"postgresql://admin:pw-cli-5be81d@localhost:port/postgres\n")
        .unwrap();
    let output = login.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!output.status.success());
    assert!(stderr.contains("can't be used: it isn't a PostgreSQL connection string"));
    assert!(!stdout.contains("pw-cli-5be81d"), "stdout: {stdout}");
    assert!(!stderr.contains("pw-cli-5be81d"), "stderr: {stderr}");
}

#[test]
fn login_refuses_multi_line_piped_stdin_without_printing_either_password() {
    let mut login = Command::new(DBVALET)
        .args(["login", "cli-test-multiline"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    login
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"postgresql://admin:pw-line-one-91a@localhost:5432/postgres\n\
              postgresql://other:pw-line-two-44b@localhost:5432/postgres\n",
        )
        .unwrap();
    let output = login.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !output.status.success(),
        "stdout: {stdout}, stderr: {stderr}"
    );
    assert!(!stdout.contains("pw-line-one-91a"), "stdout: {stdout}");
    assert!(!stderr.contains("pw-line-one-91a"), "stderr: {stderr}");
    assert!(!stdout.contains("pw-line-two-44b"), "stdout: {stdout}");
    assert!(!stderr.contains("pw-line-two-44b"), "stderr: {stderr}");
}

#[test]
fn login_refuses_unencoded_at_in_password_without_printing_it() {
    let mut login = Command::new(DBVALET)
        .args(["login", "cli-test-at"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    login
        .stdin
        .take()
        .unwrap()
        .write_all(b"postgresql://admin:se@cret-PART-9a1@localhost:5432/postgres\n")
        .unwrap();
    let output = login.wait_with_output().unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !output.status.success(),
        "stdout: {stdout}, stderr: {stderr}"
    );
    assert!(!stdout.contains("cret-PART-9a1"), "stdout: {stdout}");
    assert!(!stderr.contains("cret-PART-9a1"), "stderr: {stderr}");
}

fn project(name: &str, config: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    std::fs::write(dir.join("dbvalet.toml"), config).unwrap();
    dir
}

#[test]
fn run_with_an_unlisted_role_is_refused_before_reading_the_keychain_and_lists_the_allowed_roles() {
    let dir = project(
        "cli-test-unlisted-role",
        "[databases.cli-test-unstored.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    );

    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .args([
            "run",
            "--role",
            "writer",
            "--",
            "sh",
            "-c",
            "echo child-ran",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains(
            "the role `writer` isn't allowed for `cli-test-unstored`: dbvalet.toml allows reader"
        ),
        "stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn run_with_two_databases_and_no_db_flag_is_refused_and_lists_the_aliases() {
    let dir = project(
        "cli-test-two-databases",
        "[databases.cli-test-app.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.cli-test-analytics.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    );

    let output = Command::new(DBVALET)
        .current_dir(dir.join("nested"))
        .args(["run", "--", "sh", "-c", "echo child-ran"])
        .output()
        .unwrap();

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains(
            "dbvalet.toml lists more than one database: \
             pass --db with one of cli-test-analytics, cli-test-app"
        ),
        "stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

fn state_home(name: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn log_with_no_runs_prints_empty_notice_and_exits_zero() {
    let state = state_home("cli-test-log-empty");

    let output = Command::new(DBVALET)
        .env("XDG_STATE_HOME", &state)
        .args(["log"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "No runs logged yet.\n"
    );
}

#[test]
fn log_lists_runs_newest_first() {
    let state = state_home("cli-test-log-order");
    let runs = state.join("dbvalet").join("runs");
    std::fs::create_dir_all(&runs).unwrap();
    std::fs::write(
        runs.join("20261126T100000.000000000Z-aaaaaaaaaaaaaaaa.log"),
        "run_id: aaaaaaaaaaaaaaaa\n\
         started_at: 2026-11-26T10:00:00Z\n\
         database: app\n\
         role: reader\n\
         valid_until: 2026-11-26T10:15:00Z\n\
         max_ttl: 480m\n\
         sql_log: enabled\n\
         command: psql -c 'select 1'\n\
         \n\
         2026-11-26T10:00:01Z [Q] select 1\n",
    )
    .unwrap();
    std::fs::write(
        runs.join("20261126T100500.000000000Z-bbbbbbbbbbbbbbbb.log"),
        "run_id: bbbbbbbbbbbbbbbb\n\
         started_at: 2026-11-26T10:05:00Z\n\
         database: app\n\
         role: reader\n\
         valid_until: 2026-11-26T10:20:00Z\n\
         max_ttl: 480m\n\
         sql_log: enabled\n\
         command: psql -c 'select 2'\n\
         \n\
         2026-11-26T10:05:01Z [Q] select 2\n",
    )
    .unwrap();

    let output = Command::new(DBVALET)
        .env("XDG_STATE_HOME", &state)
        .args(["log"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "stdout: {stdout}");
    assert!(lines[0].contains("bbbbbbbbbbbbbbbb"), "stdout: {stdout}");
    assert!(lines[1].contains("aaaaaaaaaaaaaaaa"), "stdout: {stdout}");
}

#[test]
fn log_with_a_run_id_prints_that_run_log_and_fails_when_missing() {
    let state = state_home("cli-test-log-show");
    let runs = state.join("dbvalet").join("runs");
    std::fs::create_dir_all(&runs).unwrap();
    let body = "run_id: cccccccccccccccc\n\
                started_at: 2026-11-26T10:05:00Z\n\
                database: app\n\
                role: reader\n\
                valid_until: 2026-11-26T10:20:00Z\n\
                max_ttl: 480m\n\
                sql_log: enabled\n\
                command: psql -c 'select 1'\n\
                \n\
                2026-11-26T10:05:01Z [Q] select 1\n";
    std::fs::write(
        runs.join("20261126T100500.000000000Z-cccccccccccccccc.log"),
        body,
    )
    .unwrap();

    let found = Command::new(DBVALET)
        .env("XDG_STATE_HOME", &state)
        .args(["log", "cccccccccccccccc"])
        .output()
        .unwrap();
    assert!(
        found.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&found.stderr)
    );
    assert_eq!(String::from_utf8(found.stdout).unwrap(), body);

    let missing = Command::new(DBVALET)
        .env("XDG_STATE_HOME", &state)
        .args(["log", "dddddddddddddddd"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8(missing.stderr)
            .unwrap()
            .contains("no run log found for `dddddddddddddddd`")
    );
}
