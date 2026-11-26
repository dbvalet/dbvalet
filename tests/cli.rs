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
