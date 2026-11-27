//! `dbvalet` as a subprocess, against real PostgreSQL on localhost:5432 and the real OS
//! keychain. CI runs these with `cargo test --test e2e -- --ignored`.
//!
//! Every test uses its own alias and admin role, so they can run in parallel.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");
const SUPERUSER_URL: &str = "postgresql://postgres:e2e-throwaway@localhost:5432/postgres";

/// A test that makes an expired `dbvalet_` login holds this for writing until its own sweep has
/// run. Every other run and gc holds it for reading: their sweeps would otherwise drop that
/// login first, without its ledger entry. A test takes it at most once, so it never nests.
static EXPIRED_FIXTURE: RwLock<()> = RwLock::new(());

fn sweeping() -> RwLockReadGuard<'static, ()> {
    EXPIRED_FIXTURE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

fn sweeping_alone() -> RwLockWriteGuard<'static, ()> {
    EXPIRED_FIXTURE
        .write()
        .unwrap_or_else(PoisonError::into_inner)
}

fn superuser_sql(sql: &str) {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute(sql).await.unwrap();
    });
}

fn server_version_num() -> i32 {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        let row = client
            .query_one("SELECT current_setting('server_version_num')::int", &[])
            .await
            .unwrap();
        row.get(0)
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
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

fn doctor(alias: &str) -> Output {
    Command::new(DBVALET)
        .args(["doctor", "--allow-plaintext", alias])
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_superuser_admin_stored_from_stdin_passes_every_doctor_check() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_superuser_admin;
         CREATE ROLE e2e_superuser_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-super-1c4e';",
    );
    let stored = login(
        "e2e-superuser",
        "postgresql://e2e_superuser_admin:pw-e2e-super-1c4e@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-superuser");

    let stdout = text(&checked.stdout);
    assert!(checked.status.success(), "doctor: {stdout}");
    assert!(stdout.contains("ok   the keychain holds an admin login for `e2e-superuser`\n"));
    assert!(stdout.contains("ok   `e2e_superuser_admin` connects to localhost:5432/postgres\n"));
    assert!(stdout.contains(" is 15 or later\n"));
    assert!(stdout.contains("ok   `e2e_superuser_admin` is a superuser\n"));
    assert!(
        stdout
            .contains("ok   `e2e_superuser_admin` can end other roles' sessions, as a superuser\n")
    );
    assert!(!stdout.contains("FAIL"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_createrole_admin_on_postgresql_16_or_later_passes_every_doctor_check() {
    if server_version_num() < 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_createrole_admin;
         CREATE ROLE e2e_createrole_admin LOGIN CREATEROLE PASSWORD 'pw-e2e-createrole-8d02';",
    );
    let stored = login(
        "e2e-createrole",
        "postgresql://e2e_createrole_admin:pw-e2e-createrole-8d02@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-createrole");

    let stdout = text(&checked.stdout);
    assert!(checked.status.success(), "doctor: {stdout}");
    assert!(stdout.contains("ok   the keychain holds an admin login for `e2e-createrole`\n"));
    assert!(stdout.contains("ok   `e2e_createrole_admin` connects to localhost:5432/postgres\n"));
    assert!(stdout.contains(" is 15 or later\n"));
    assert!(stdout.contains("ok   `e2e_createrole_admin` has CREATEROLE\n"));
    assert!(stdout.contains(
        "ok   `e2e_createrole_admin` can end the sessions of logins it creates, \
         because dbvalet sets createrole_self_grant on PostgreSQL 16 and later\n"
    ));
    assert!(!stdout.contains("FAIL"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_createrole_admin_on_postgresql_15_passes_every_doctor_check() {
    if server_version_num() >= 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_createrole_15_admin;
         CREATE ROLE e2e_createrole_15_admin LOGIN CREATEROLE PASSWORD 'pw-e2e-pg15-55a7';",
    );
    let stored = login(
        "e2e-createrole-15",
        "postgresql://e2e_createrole_15_admin:pw-e2e-pg15-55a7@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-createrole-15");

    let stdout = text(&checked.stdout);
    assert!(checked.status.success(), "doctor: {stdout}");
    assert!(stdout.contains("ok   the keychain holds an admin login for `e2e-createrole-15`\n"));
    assert!(
        stdout.contains("ok   `e2e_createrole_15_admin` connects to localhost:5432/postgres\n")
    );
    assert!(stdout.contains(" is 15 or later\n"));
    assert!(stdout.contains("ok   `e2e_createrole_15_admin` has CREATEROLE\n"));
    assert!(stdout.contains(
        "ok   `e2e_createrole_15_admin` can end the sessions of logins it creates, \
         because dbvalet adds it as a member of each login\n"
    ));
    assert!(!stdout.contains("FAIL"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_admin_without_createrole_is_told_it_lacks_createrole() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_plain_admin;
         CREATE ROLE e2e_plain_admin LOGIN PASSWORD 'pw-e2e-plain-3b9f';",
    );
    let stored = login(
        "e2e-plain",
        "postgresql://e2e_plain_admin:pw-e2e-plain-3b9f@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-plain");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success());
    assert!(stdout.contains(
        "FAIL `e2e_plain_admin` has neither SUPERUSER nor CREATEROLE: as a superuser, \
         run ALTER ROLE \"e2e_plain_admin\" CREATEROLE, or use your provider's admin login\n"
    ));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_for_an_alias_with_no_keychain_entry_says_to_run_login() {
    let checked = doctor("e2e-never-stored");

    assert!(!checked.status.success());
    assert_eq!(
        text(&checked.stdout),
        "FAIL no admin login is stored for `e2e-never-stored`: \
         run `dbvalet login e2e-never-stored`\n"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_passing_login_and_doctor_never_print_the_admin_password() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_secret_admin;
         CREATE ROLE e2e_secret_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-secret-a61d';",
    );

    let stored = login(
        "e2e-secret",
        "postgresql://e2e_secret_admin:pw-e2e-secret-a61d@localhost:5432/postgres",
    );
    let checked = doctor("e2e-secret");

    assert!(stored.status.success() && checked.status.success());
    assert!(!text(&stored.stdout).contains("pw-e2e-secret-a61d"));
    assert!(!text(&stored.stderr).contains("pw-e2e-secret-a61d"));
    assert!(!text(&checked.stdout).contains("pw-e2e-secret-a61d"));
    assert!(!text(&checked.stderr).contains("pw-e2e-secret-a61d"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_with_a_wrong_stored_password_fails_without_printing_it() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_wrong_password_admin;
         CREATE ROLE e2e_wrong_password_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-right-0f6c';",
    );
    let stored = login(
        "e2e-wrong-password",
        "postgresql://e2e_wrong_password_admin:pw-e2e-wrong-77e3@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-wrong-password");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success());
    assert!(
        stdout.contains("password authentication failed"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("dbvalet login e2e-wrong-password"),
        "doctor: {stdout}"
    );
    assert!(stdout.contains("VALID UNTIL"), "doctor: {stdout}");
    assert!(!stdout.contains("FATAL:"), "doctor: {stdout}");
    assert!(!stdout.contains("pw-e2e-wrong-77e3"));
    assert!(!text(&checked.stderr).contains("pw-e2e-wrong-77e3"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_noinherit_createrole_admin_on_postgresql_15_is_told_to_enable_inherit() {
    if server_version_num() >= 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_noinh_15_admin;
         CREATE ROLE e2e_noinh_15_admin LOGIN CREATEROLE NOINHERIT PASSWORD 'pw-e2e-noinh15-2a9b';",
    );
    let stored = login(
        "e2e-noinh-15",
        "postgresql://e2e_noinh_15_admin:pw-e2e-noinh15-2a9b@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-noinh-15");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains(
            "FAIL `e2e_noinh_15_admin` can't end the sessions of logins it creates \
             because it has NOINHERIT: run ALTER ROLE \"e2e_noinh_15_admin\" INHERIT\n"
        ),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("pg_signal_backend"), "doctor: {stdout}");
    assert!(!stdout.contains("as a superuser"), "doctor: {stdout}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_noinherit_plain_admin_holding_pg_signal_backend_on_postgresql_16_or_later_is_told_with_inherit_true()
 {
    if server_version_num() < 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_noinh_16_admin;
         CREATE ROLE e2e_noinh_16_admin LOGIN NOINHERIT PASSWORD 'pw-e2e-noinh16-4c1d';
         GRANT pg_signal_backend TO e2e_noinh_16_admin;",
    );
    let stored = login(
        "e2e-noinh-16",
        "postgresql://e2e_noinh_16_admin:pw-e2e-noinh16-4c1d@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-noinh-16");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains("GRANT pg_signal_backend TO \"e2e_noinh_16_admin\" WITH INHERIT TRUE"),
        "doctor: {stdout}"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_names_the_fix_for_nologin_expired_and_missing_database_connections() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_nologin_admin;
         CREATE ROLE e2e_nologin_admin NOLOGIN SUPERUSER PASSWORD 'pw-e2e-nologin-11c2';
         DROP ROLE IF EXISTS e2e_expired_admin;
         CREATE ROLE e2e_expired_admin LOGIN SUPERUSER VALID UNTIL '2000-01-01' PASSWORD 'pw-e2e-expired-99e1';
         DROP ROLE IF EXISTS e2e_missingdb_admin;
         CREATE ROLE e2e_missingdb_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-missingdb-55f0';",
    );

    assert!(
        login(
            "e2e-nologin",
            "postgresql://e2e_nologin_admin:pw-e2e-nologin-11c2@localhost:5432/postgres",
        )
        .status
        .success()
    );
    let nologin_out = doctor("e2e-nologin");
    let nologin_stdout = text(&nologin_out.stdout);
    assert!(!nologin_out.status.success());
    assert!(
        nologin_stdout.contains("ALTER ROLE \"e2e_nologin_admin\" LOGIN"),
        "nologin: {nologin_stdout}"
    );
    assert!(
        !nologin_stdout.contains("FATAL:"),
        "nologin: {nologin_stdout}"
    );

    assert!(
        login(
            "e2e-expired",
            "postgresql://e2e_expired_admin:pw-e2e-expired-99e1@localhost:5432/postgres",
        )
        .status
        .success()
    );
    let expired_out = doctor("e2e-expired");
    let expired_stdout = text(&expired_out.stdout);
    assert!(!expired_out.status.success());
    assert!(
        expired_stdout.contains("ALTER ROLE \"e2e_expired_admin\" VALID UNTIL"),
        "expired: {expired_stdout}"
    );
    assert!(
        expired_stdout.contains("dbvalet login e2e-expired"),
        "expired: {expired_stdout}"
    );
    assert!(
        !expired_stdout.contains("FATAL:"),
        "expired: {expired_stdout}"
    );

    assert!(
        login(
            "e2e-missingdb",
            "postgresql://e2e_missingdb_admin:pw-e2e-missingdb-55f0@localhost:5432/no_such_db",
        )
        .status
        .success()
    );
    let missingdb_out = doctor("e2e-missingdb");
    let missingdb_stdout = text(&missingdb_out.stdout);
    assert!(!missingdb_out.status.success());
    assert!(
        missingdb_stdout.contains("dbvalet login e2e-missingdb"),
        "missingdb: {missingdb_stdout}"
    );
    assert!(
        !missingdb_stdout.contains("FATAL:"),
        "missingdb: {missingdb_stdout}"
    );
}

/// Creates the shared read-only group role; tests running in parallel may race to create it.
fn create_reader_group() {
    superuser_sql(
        "DO $$ BEGIN
             CREATE ROLE dbvalet_reader NOLOGIN;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
         END $$;",
    );
}

/// Stores a superuser admin login under `alias` and writes a `dbvalet.toml` that lists
/// `alias` with a read-only `reader` role. Returns the directory holding the file.
fn project_with_reader(alias: &str) -> PathBuf {
    project_with_reader_and_admin(alias, "SUPERUSER")
}

/// Like [`project_with_reader`], with an admin that has `attributes` and ADMIN OPTION on
/// `dbvalet_reader`, which `dbvalet init` will grant.
fn project_with_reader_and_admin(alias: &str, attributes: &str) -> PathBuf {
    create_reader_group();
    let admin = alias.replace('-', "_");
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {admin};
         CREATE ROLE {admin} LOGIN {attributes} PASSWORD 'pw-{alias}-admin';
         GRANT dbvalet_reader TO {admin} WITH ADMIN OPTION;"
    ));
    let stored = login(
        alias,
        &format!("postgresql://{admin}:pw-{alias}-admin@localhost:5432/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
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

fn run_command(dir: &Path, command: &[&str]) -> Command {
    let mut run = Command::new(DBVALET);
    run.current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--"])
        .args(command);
    run
}

fn run_in(dir: &Path, command: &[&str]) -> Output {
    let _sweeping = sweeping();
    run_command(dir, command).output().unwrap()
}

fn superuser_count(sql: &str, name: &str) -> i64 {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.query_one(sql, &[&name]).await.unwrap().get(0)
    })
}

/// A run whose child prints its login name and waits on stdin, so the test can copy the
/// login's SCRAM verifier from `pg_authid` into a `witness` role before the login is dropped.
/// Logging in as the witness then tells whether a string is the temporary login's password.
fn run_with_password_witness(dir: &Path, script: &str, witness: &str) -> Output {
    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(format!(
            "echo \"login=$PGUSER\"; {script}; echo READY; read line"
        ))
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
    assert!(verifier.starts_with("SCRAM-SHA-256$"), "{verifier}");
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {witness}; CREATE ROLE {witness} LOGIN PASSWORD '{verifier}';"
    ));
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let mut output = run.wait_with_output().unwrap();
    output.stdout = format!("{seen}{rest}").into_bytes();
    output
}

/// Every word of 16 or more letters and digits in `text` that logs in as `witness`.
fn passwords_of(witness: &str, text: &str) -> Vec<String> {
    let words: BTreeSet<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| word.len() >= 16)
        .collect();
    runtime().block_on(async {
        let mut found = Vec::new();
        for word in words {
            let url = format!("postgresql://{witness}:{word}@localhost:5432/postgres");
            if tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .is_ok()
            {
                found.push(word.to_owned());
            }
        }
        found
    })
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_read_through_a_run_returns_the_row() {
    let dir = project_with_reader("e2e-run-read");
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_run_notes;
         CREATE TABLE e2e_run_notes (note text);
         INSERT INTO e2e_run_notes VALUES ('read through the proxy');
         GRANT SELECT ON e2e_run_notes TO dbvalet_reader;",
    );

    let output = run_in(&dir, &["psql", "-Atc", "SELECT note FROM e2e_run_notes"]);

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "read through the proxy\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_write_through_a_read_only_run_is_refused_by_the_database() {
    let dir = project_with_reader("e2e-run-write");

    let output = run_in(
        &dir,
        &["psql", "-c", "CREATE TABLE e2e_run_written (id int)"],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("cannot execute CREATE TABLE in a read-only transaction"),
        "stderr: {}",
        text(&output.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn after_the_child_exits_the_login_and_its_sessions_are_gone() {
    let dir = project_with_reader("e2e-run-teardown");

    let output = run_in(
        &dir,
        &[
            "sh",
            "-c",
            "echo \"$PGUSER\"; psql -qc 'SELECT 1' >/dev/null",
        ],
    );

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    let login_name = text(&output.stdout).trim().to_owned();
    assert!(login_name.starts_with("dbvalet_"), "{login_name}");
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
fn the_child_environment_points_at_the_proxy_and_drops_the_parent_pg_values() {
    let dir = project_with_reader("e2e-run-env");
    let _sweeping = sweeping();

    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "env"])
        .env("PGHOST", "parent-host.example.com")
        .env("PGSSLMODE", "require")
        .env("PGSERVICE", "parent-service")
        .env("PGPASSFILE", "/parent/pgpass")
        .env(
            "DATABASE_URL",
            "postgresql://parent:parent-pw@db.example.com/parent",
        )
        .output()
        .unwrap();

    let env = text(&output.stdout);
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert!(env.lines().any(|line| line == "PGHOST=127.0.0.1"), "{env}");
    assert!(env.lines().any(|line| line == "PGSSLMODE=disable"), "{env}");
    assert!(
        env.lines().any(|line| line == "PGDATABASE=postgres"),
        "{env}"
    );
    assert!(
        env.lines().any(|line| line.starts_with("PGUSER=dbvalet_")),
        "{env}"
    );
    assert!(env.lines().any(|line| line.starts_with("PGPORT=")), "{env}");
    assert!(
        env.lines().any(|line| line.starts_with("PGPASSWORD=")),
        "{env}"
    );
    assert!(
        env.lines()
            .any(|line| line.starts_with("DATABASE_URL=postgresql://dbvalet_")),
        "{env}"
    );
    assert!(!env.contains("parent"), "{env}");
    assert!(!env.contains("PGSERVICE"), "{env}");
    assert!(!env.contains("PGPASSFILE"), "{env}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_child_environment_holds_the_token_and_not_the_login_password() {
    let dir = project_with_reader("e2e-run-env-token");

    let output = run_with_password_witness(
        &dir,
        "env; psql -qAtc 'SELECT 1'",
        "e2e_run_env_token_witness",
    );

    let stdout = text(&output.stdout);
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert!(stdout.contains("\nPGPASSWORD="), "{stdout}");
    assert!(stdout.contains("\n1\n"), "{stdout}");
    assert_eq!(
        passwords_of("e2e_run_env_token_witness", &stdout),
        Vec::<String>::new()
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_login_password_never_appears_in_the_run_stdout_or_stderr() {
    let dir = project_with_reader("e2e-run-output");

    let output = run_with_password_witness(
        &dir,
        "env; env >&2; psql -c 'SELECT current_user'; psql -c 'SELECT * FROM missing' ",
        "e2e_run_output_witness",
    );

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(stderr.contains("missing"), "{stderr}");
    assert_eq!(
        passwords_of("e2e_run_output_witness", &stdout),
        Vec::<String>::new()
    );
    assert_eq!(
        passwords_of("e2e_run_output_witness", &stderr),
        Vec::<String>::new()
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_proxy_connection_with_a_wrong_token_is_refused_with_an_authentication_error() {
    let dir = project_with_reader("e2e-run-wrong-token");

    let output = run_in(
        &dir,
        &[
            "sh",
            "-c",
            "PGPASSWORD=wrong-token-e2e-5d1 psql -c 'SELECT 1'",
        ],
    );

    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("FATAL:  password authentication failed"),
        "{stderr}"
    );
    assert!(!stderr.contains("wrong-token-e2e-5d1"), "{stderr}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_whose_child_exits_zero_exits_zero() {
    let dir = project_with_reader("e2e-run-exit-zero");

    let output = run_in(&dir, &["sh", "-c", "exit 0"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        text(&output.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_whose_child_exits_seven_exits_seven() {
    let dir = project_with_reader("e2e-run-exit-seven");

    let output = run_in(&dir, &["sh", "-c", "exit 7"]);

    assert_eq!(
        output.status.code(),
        Some(7),
        "stderr: {}",
        text(&output.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_child_can_hold_two_proxy_connections_at_once() {
    let dir = project_with_reader("e2e-run-two-connections");

    let output = run_in(
        &dir,
        &[
            "psql",
            "-Atc",
            "\\! psql -Atc \"SELECT count(*) FROM pg_stat_activity WHERE usename = current_user\"",
        ],
    );

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "2\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_with_a_createrole_admin_reads_and_leaves_no_login_or_session() {
    let dir = project_with_reader_and_admin("e2e-run-createrole", "CREATEROLE");

    let output = run_in(
        &dir,
        &["sh", "-c", "echo \"$PGUSER\"; psql -qAtc 'SELECT 1'"],
    );

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    // PostgreSQL 19 warns on stderr about the temporary login's short VALID UNTIL expiry;
    // a teardown failure from dbvalet itself is prefixed with `dbvalet:`.
    assert!(!stderr.contains("dbvalet:"), "stderr: {stderr}");
    let login_name = stdout.lines().next().unwrap().to_owned();
    assert_eq!(stdout, format!("{login_name}\n1\n"));
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
fn a_teardown_failure_is_printed_and_the_child_exit_code_is_still_returned() {
    let dir = project_with_reader("e2e-run-teardown-fails");
    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg("echo \"login=$PGUSER\"; read line; exit 7")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first_line = String::new();
    BufReader::new(run.stdout.take().unwrap())
        .read_line(&mut first_line)
        .unwrap();
    let login_name = first_line.trim().strip_prefix("login=").unwrap().to_owned();

    superuser_sql("ALTER ROLE e2e_run_teardown_fails NOLOGIN;");
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();
    superuser_sql(&format!("DROP ROLE {login_name};"));

    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "stderr: {stderr}");
    assert!(
        stderr.contains(&format!("couldn't drop the temporary login `{login_name}`")),
        "{stderr}"
    );
    assert!(
        !stderr.contains("pw-e2e-run-teardown-fails-admin"),
        "{stderr}"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_noinherit_createrole_admin_before_postgresql_16_is_refused_without_creating_a_login() {
    if server_version_num() >= 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_run_noinherit_old;
         DROP ROLE IF EXISTS e2e_noinherit_old_group;
         CREATE ROLE e2e_noinherit_old_group NOLOGIN;
         CREATE ROLE e2e_run_noinherit_old LOGIN CREATEROLE NOINHERIT
             PASSWORD 'pw-e2e-run-noinherit-old-admin';
         GRANT e2e_noinherit_old_group TO e2e_run_noinherit_old WITH ADMIN OPTION;",
    );
    let stored = login(
        "e2e-run-noinherit-old",
        "postgresql://e2e_run_noinherit_old:pw-e2e-run-noinherit-old-admin@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-run-noinherit-old");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-run-noinherit-old.roles]\n\
         reader = { member_of = \"e2e_noinherit_old_group\", read_only = true }\n",
    )
    .unwrap();

    let output = run_in(&dir, &["sh", "-c", "echo \"$PGUSER\""]);

    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(
        output.stdout.is_empty(),
        "child should not run, stdout: {}",
        text(&output.stdout)
    );
    assert!(
        stderr.contains("ALTER ROLE \"e2e_run_noinherit_old\" INHERIT"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("dbvalet doctor"), "stderr: {stderr}");
    assert_eq!(
        superuser_count(
            "SELECT count(*)
             FROM pg_roles r
             JOIN pg_auth_members m ON m.member = r.oid
             JOIN pg_roles g ON g.oid = m.roleid
             WHERE g.rolname = $1 AND r.rolname LIKE 'dbvalet_%'",
            "e2e_noinherit_old_group"
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_noinherit_createrole_admin_on_postgresql_16_or_later_runs_and_drops_its_login() {
    if server_version_num() < 160000 {
        return;
    }
    let dir = project_with_reader_and_admin("e2e-run-noinherit-16", "CREATEROLE NOINHERIT");

    let output = run_in(
        &dir,
        &["sh", "-c", "echo \"$PGUSER\"; psql -qAtc 'SELECT 1'"],
    );

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    // PostgreSQL 19 warns on stderr about the temporary login's short VALID UNTIL expiry;
    // a teardown failure from dbvalet itself is prefixed with `dbvalet:`.
    assert!(!stderr.contains("dbvalet:"), "stderr: {stderr}");
    let login_name = stdout.lines().next().unwrap().to_owned();
    assert_eq!(stdout, format!("{login_name}\n1\n"));
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
fn a_teardown_failure_with_a_closed_stderr_pipe_still_returns_the_child_exit_code() {
    let dir = project_with_reader("e2e-run-closed-stderr");
    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg("echo \"login=$PGUSER\"; read line; exit 7")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first_line = String::new();
    BufReader::new(run.stdout.take().unwrap())
        .read_line(&mut first_line)
        .unwrap();
    let login_name = first_line.trim().strip_prefix("login=").unwrap().to_owned();

    // Close dbvalet's stderr pipe so printing the teardown failure hits BrokenPipe.
    drop(run.stderr.take());
    superuser_sql("ALTER ROLE e2e_run_closed_stderr NOLOGIN;");
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let status = run.wait().unwrap();
    superuser_sql(&format!("DROP ROLE {login_name};"));

    assert_eq!(status.code(), Some(7));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_read_only_run_leaves_no_large_objects_after_teardown() {
    let dir = project_with_reader_and_admin("e2e-run-read-only-lo", "CREATEROLE");

    let output = run_in(
        &dir,
        &[
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; \
             psql -v ON_ERROR_STOP=1 -qAtc \
             \"SELECT lo_from_bytea(0, 'written by a read-only run')\"",
        ],
    );

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    let mut lines = stdout.lines();
    let login_name = lines
        .next()
        .unwrap()
        .strip_prefix("login=")
        .unwrap()
        .to_owned();

    if server_version_num() < 160000 {
        assert!(output.status.success(), "stderr: {stderr}");
        assert!(stderr.is_empty(), "stderr: {stderr}");
        let oid: u32 = lines.next().unwrap().parse().unwrap();
        let remaining_lo: i64 = runtime().block_on(async {
            let (client, connection) =
                tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
                    .await
                    .unwrap();
            tokio::spawn(connection);
            client
                .query_one(
                    "SELECT count(*) FROM pg_largeobject_metadata WHERE oid = $1",
                    &[&oid],
                )
                .await
                .unwrap()
                .get(0)
        });
        assert_eq!(remaining_lo, 0, "large object {oid} survived teardown");
    } else {
        assert!(!output.status.success(), "stdout: {stdout}");
        assert!(
            stderr.contains("cannot execute lo_from_bytea() in a read-only transaction"),
            "stderr: {stderr}"
        );
        let remaining_lo: i64 = runtime().block_on(async {
            let (client, connection) =
                tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
                    .await
                    .unwrap();
            tokio::spawn(connection);
            client
                .query_one(
                    "SELECT count(*) FROM pg_largeobject_metadata
                     WHERE lomowner = 'dbvalet_reader'::regrole",
                    &[],
                )
                .await
                .unwrap()
                .get(0)
        });
        assert_eq!(remaining_lo, 0);
    }

    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
}

fn gc_command(dir: &Path) -> Command {
    let mut gc = Command::new(DBVALET);
    gc.current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["gc", "--allow-plaintext"]);
    gc
}

fn gc_in(dir: &Path) -> Output {
    let _sweeping = sweeping();
    gc_command(dir).output().unwrap()
}

/// Runs `command` to the end, failing the test if it takes longer than `limit`.
fn output_within(mut command: Command, limit: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + limit;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("still running after {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// Starts `dbvalet run <run_args>` in `dir` with a child that runs `script`, prints READY if it
/// succeeded and then waits on stdin. Returns the run and what the child printed before READY.
fn start_run_until_ready(dir: &Path, run_args: &[&str], script: &str) -> (Child, String) {
    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .arg("run")
        .args(run_args)
        .args(["--allow-plaintext", "--", "sh", "-c"])
        .arg(format!("{script} && echo READY && read line"))
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
    (run, seen)
}

/// The value of the first `key=value` line the child printed.
fn printed<'a>(seen: &'a str, key: &str) -> &'a str {
    seen.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap()
}

/// A NOLOGIN group for a writable `writer` role, owning a schema of the same name, so tests
/// running in parallel never change the same schema's privileges at once.
fn create_writer_group(group: &str) {
    superuser_sql(&format!(
        "DO $$ BEGIN
             CREATE ROLE {group} NOLOGIN;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
         END $$;
         CREATE SCHEMA IF NOT EXISTS {group} AUTHORIZATION {group};"
    ));
}

/// Where a run in `dir` keeps the ledger entry for `login` on `alias`.
fn ledger_entry(dir: &Path, alias: &str, login: &str) -> PathBuf {
    dir.join("state/dbvalet/ledger")
        .join(format!("{alias}.{login}"))
}

/// Waits up to 10 s for a session of `login` to be running a query.
fn wait_for_active_query(login: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while superuser_count(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1 AND state = 'active'",
        login,
    ) == 0
    {
        assert!(Instant::now() < deadline, "no active query for {login}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Starts a run in `dir` whose child keeps a `pg_sleep` query running through the proxy and
/// then waits on stdin. Returns once the query runs, with the run and its login name.
fn start_run_with_busy_session(dir: &Path) -> (Child, String) {
    let sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(
            "echo \"login=$PGUSER\"; \
             psql -qAtXc 'SELECT pg_sleep(60)' >/dev/null 2>&1 & read line",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first_line = String::new();
    BufReader::new(run.stdout.take().unwrap())
        .read_line(&mut first_line)
        .unwrap();
    let login_name = first_line.trim().strip_prefix("login=").unwrap().to_owned();
    drop(sweeping);
    wait_for_active_query(&login_name);
    (run, login_name)
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_killed_run_leaves_no_login_or_session_after_gc() {
    let dir = project_with_reader("e2e-gc-after-kill");
    let (mut run, login_name) = start_run_with_busy_session(&dir);

    run.kill().unwrap();
    run.wait().unwrap();
    let swept = gc_in(&dir);
    // The orphaned child exits once its stdin closes.
    drop(run.stdin.take());

    let stdout = text(&swept.stdout);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(
        stdout.contains(&format!(
            "`e2e-gc-after-kill`: dropped the leftover login `{login_name}`\n"
        )),
        "{stdout}"
    );
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
fn a_killed_run_leaves_no_login_or_session_after_the_next_run() {
    let dir = project_with_reader("e2e-run-after-kill");
    let (mut run, first_login) = start_run_with_busy_session(&dir);

    run.kill().unwrap();
    run.wait().unwrap();
    let next = run_in(&dir, &["sh", "-c", "echo next"]);
    drop(run.stdin.take());

    assert!(next.status.success(), "stderr: {}", text(&next.stderr));
    assert_eq!(text(&next.stdout), "next\n");
    assert_eq!(text(&next.stderr), "");
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &first_login
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &first_login
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_while_another_run_is_live_leaves_its_login_and_session_alone() {
    let dir = project_with_reader("e2e-gc-live-run");
    let (mut run, login_name) = start_run_with_busy_session(&dir);

    let swept = gc_in(&dir);
    let logins_after_gc = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let sessions_after_gc = superuser_count(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
        &login_name,
    );
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let finished = run.wait_with_output().unwrap();

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!text(&swept.stdout).contains(&login_name));
    assert_eq!(logins_after_gc, 1);
    assert_eq!(sessions_after_gc, 1);
    assert!(
        finished.status.success(),
        "stderr: {}",
        text(&finished.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_never_touches_dbvalet_reader_or_another_group_role() {
    let dir = project_with_reader("e2e-gc-group-roles");
    superuser_sql(
        "DROP ROLE IF EXISTS dbvalet_grouproleexpired;
         CREATE ROLE dbvalet_grouproleexpired NOLOGIN VALID UNTIL '2000-01-01';",
    );
    let reader_entry = ledger_entry(&dir, "e2e-gc-group-roles", "dbvalet_reader");
    let group_entry = ledger_entry(&dir, "e2e-gc-group-roles", "dbvalet_grouproleexpired");
    std::fs::create_dir_all(reader_entry.parent().unwrap()).unwrap();
    std::fs::write(&reader_entry, "writable\n").unwrap();
    std::fs::write(&group_entry, "writable\n").unwrap();

    let swept = gc_in(&dir);
    let readers = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        "dbvalet_reader",
    );
    let groups = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        "dbvalet_grouproleexpired",
    );
    superuser_sql("DROP ROLE dbvalet_grouproleexpired;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(readers, 1);
    assert_eq!(groups, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_ledger_entry_whose_login_was_never_created_is_removed_by_gc() {
    let dir = project_with_reader("e2e-gc-never-created");
    superuser_sql("DROP ROLE IF EXISTS dbvalet_nevercreatedrole;");
    let entry = ledger_entry(&dir, "e2e-gc-never-created", "dbvalet_nevercreatedrole");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    // From outside any project, so gc finds the alias through the ledger alone.
    let _sweeping = sweeping();
    let swept = Command::new(DBVALET)
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["gc", "--allow-plaintext"])
        .output()
        .unwrap();

    let stdout = text(&swept.stdout);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(text(&swept.stderr), "");
    assert!(
        stdout.contains(
            "`e2e-gc-never-created`: removed the ledger entry for `dbvalet_nevercreatedrole`, \
             whose login was already gone\n"
        ),
        "{stdout}"
    );
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_keeps_the_ledger_until_the_creation_transaction_finishes() {
    let dir = project_with_reader("e2e-gc-unsettled-creation");
    let _sweeping = sweeping();
    let login = "dbvalet_pendingcreationa";
    superuser_sql("DROP ROLE IF EXISTS dbvalet_pendingcreationa;");
    let rt = runtime();
    let creator = rt.block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute("BEGIN").await.unwrap();
        client
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&login],
            )
            .await
            .unwrap();
        client
    });
    let entry = ledger_entry(&dir, "e2e-gc-unsettled-creation", login);
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    let swept = gc_command(&dir).output().unwrap();
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(entry.exists());

    rt.block_on(creator.batch_execute("ROLLBACK")).unwrap();
    let swept = gc_command(&dir).output().unwrap();
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_drops_an_expired_read_only_login_and_the_table_it_owns() {
    let dir = project_with_reader("e2e-gc-expired-read-only");
    let _alone = sweeping_alone();
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_gc_read_only_table;
         DROP ROLE IF EXISTS dbvalet_readonlyexpired2;
         CREATE ROLE dbvalet_readonlyexpired2 LOGIN VALID UNTIL '2000-01-01' IN ROLE dbvalet_reader;
         ALTER ROLE dbvalet_readonlyexpired2 SET default_transaction_read_only = on;
         CREATE TABLE e2e_gc_read_only_table ();
         ALTER TABLE e2e_gc_read_only_table OWNER TO dbvalet_readonlyexpired2;",
    );

    let swept = gc_command(&dir).output().unwrap();

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            "dbvalet_readonlyexpired2"
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_tables WHERE tablename = $1",
            "e2e_gc_read_only_table"
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_drops_an_expired_writable_login_and_gives_its_table_to_the_group_role() {
    let dir = project_with_reader("e2e-gc-expired-writable");
    let _alone = sweeping_alone();
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_gc_writable_table;
         DROP ROLE IF EXISTS dbvalet_writableexpired2;
         DROP ROLE IF EXISTS e2e_gc_writer_group;
         CREATE ROLE e2e_gc_writer_group NOLOGIN;
         CREATE ROLE dbvalet_writableexpired2 LOGIN VALID UNTIL '2000-01-01'
             IN ROLE e2e_gc_writer_group;
         CREATE TABLE e2e_gc_writable_table ();
         ALTER TABLE e2e_gc_writable_table OWNER TO dbvalet_writableexpired2;",
    );

    let swept = gc_command(&dir).output().unwrap();
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_writable_table' AND tableowner = $1",
        "e2e_gc_writer_group",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_writable_table;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            "dbvalet_writableexpired2"
        ),
        0
    );
    assert_eq!(owned_by_group, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_createrole_admin_drops_the_login_while_its_query_is_still_running() {
    let dir = project_with_reader_and_admin("e2e-run-createrole-busy", "CREATEROLE");
    let (mut run, login_name) = start_run_with_busy_session(&dir);

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();

    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
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
fn a_run_whose_login_a_sweep_already_dropped_ends_without_an_error() {
    let dir = project_with_reader("e2e-run-swept-early");
    let (mut run, login_name) = start_run_with_busy_session(&dir);
    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    // Another machine's sweep: it has no ledger entry for the login, so it drops it.
    let swept = gc_command(&dir)
        .env("XDG_STATE_HOME", dir.join("other-machine-state"))
        .output()
        .unwrap();
    drop(alone);

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();

    let stderr = text(&output.stderr);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(
        text(&swept.stdout).contains(&format!("dropped the leftover login `{login_name}`")),
        "stdout: {}",
        text(&swept.stdout)
    );
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(!ledger_entry(&dir, "e2e-run-swept-early", &login_name).exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_corrupt_ledger_entry_or_a_stray_directory_does_not_stop_gc() {
    let dir = project_with_reader("e2e-gc-corrupt-ledger");
    superuser_sql("DROP ROLE IF EXISTS dbvalet_corruptledgerent;");
    let corrupt = ledger_entry(&dir, "e2e-gc-corrupt-ledger", "dbvalet_corruptledgerent");
    let stray = ledger_entry(&dir, "e2e-gc-corrupt-ledger", "stray");
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(&corrupt, b"\xff\xfe").unwrap();

    let swept = gc_in(&dir);

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!corrupt.exists());
    assert!(stray.is_dir());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_with_a_closed_stdout_still_sweeps_every_database() {
    let dir = project_with_reader("e2e-gc-closed-stdout-a");
    project_with_reader("e2e-gc-closed-stdout-b");
    superuser_sql(
        "DROP ROLE IF EXISTS dbvalet_closedstdoutaaaa;
         DROP ROLE IF EXISTS dbvalet_closedstdoutbbbb;",
    );
    let entry_a = ledger_entry(&dir, "e2e-gc-closed-stdout-a", "dbvalet_closedstdoutaaaa");
    let entry_b = ledger_entry(&dir, "e2e-gc-closed-stdout-b", "dbvalet_closedstdoutbbbb");
    std::fs::create_dir_all(entry_a.parent().unwrap()).unwrap();
    std::fs::write(&entry_a, "read-only\n").unwrap();
    std::fs::write(&entry_b, "read-only\n").unwrap();
    let (closed_stdout, stdout) = std::io::pipe().unwrap();
    drop(closed_stdout);

    let _sweeping = sweeping();
    let swept = Command::new(DBVALET)
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["gc", "--allow-plaintext"])
        .stdout(stdout)
        .output()
        .unwrap();

    assert_eq!(
        swept.status.code(),
        Some(0),
        "stderr: {}",
        text(&swept.stderr)
    );
    assert!(!entry_a.exists());
    assert!(!entry_b.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_unreadable_ledger_entry_is_reported_and_the_run_still_runs() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project_with_reader("e2e-run-unreadable-entry");
    superuser_sql("DROP ROLE IF EXISTS dbvalet_unreadablebeside;");
    let entry = ledger_entry(&dir, "e2e-run-unreadable-entry", "dbvalet_unreadableentryz");
    let beside = ledger_entry(&dir, "e2e-run-unreadable-entry", "dbvalet_unreadablebeside");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();
    std::fs::write(&beside, "read-only\n").unwrap();
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o000)).unwrap();

    let output = run_in(&dir, &["sh", "-c", "echo ran"]);
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&entry).unwrap();

    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert_eq!(text(&output.stdout), "ran\n");
    assert!(
        stderr.contains("couldn't read the ledger entry")
            && stderr.contains("dbvalet_unreadableentryz"),
        "stderr: {stderr}"
    );
    assert!(!beside.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn files_in_the_ledger_that_arent_login_entries_are_never_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project_with_reader("e2e-gc-stray-files");
    let ledger = dir.join("state/dbvalet/ledger");
    let stray = ledger.join("e2e-gc-stray-files.stray");
    std::fs::create_dir_all(&ledger).unwrap();
    std::fs::write(ledger.join("README.md"), "notes\n").unwrap();
    std::fs::write(&stray, "x\n").unwrap();
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o000)).unwrap();

    let swept = gc_in(&dir);
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(text(&swept.stderr), "");
    assert_eq!(
        text(&swept.stdout),
        "`e2e-gc-stray-files`: nothing to clean up\n"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_expired_read_only_login_found_through_another_alias_still_has_its_objects_dropped() {
    let dir = project_with_reader("e2e-gc-two-aliases-a");
    project_with_reader("e2e-gc-two-aliases-z");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-two-aliases-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-two-aliases-z.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    // The login clears its own read-only default, so only the ledger still says read-only.
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--db", "e2e-gc-two-aliases-z"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtX \
         -c 'SET default_transaction_read_only = off' \
         -c 'ALTER ROLE current_user RESET default_transaction_read_only' \
         -c \"SELECT 'oid=' || lo_from_bytea(0, 'from a read-only run')\"",
    );
    let login_name = printed(&seen, "login").to_owned();
    let oid: u32 = printed(&seen, "oid").parse().unwrap();
    run.kill().unwrap();
    run.wait().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept = gc_command(&dir).output().unwrap();
    drop(alone);
    drop(run.stdin.take());

    let large_objects: i64 = runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query_one(
                "SELECT count(*) FROM pg_largeobject_metadata WHERE oid = $1",
                &[&oid],
            )
            .await
            .unwrap()
            .get(0)
    });
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(large_objects, 0, "large object {oid} survived the sweep");
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_leaves_an_expired_login_alone_while_another_process_holds_its_ledger_entry() {
    let dir = project_with_reader("e2e-gc-held-entry");
    let (mut run, seen) = start_run_until_ready(&dir, &[], "echo \"login=$PGUSER\"");
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();
    let held = std::fs::File::open(ledger_entry(&dir, "e2e-gc-held-entry", &login_name)).unwrap();
    held.lock().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept_while_held = gc_command(&dir).output().unwrap();
    let logins_while_held = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    drop(held);
    let swept_after = gc_command(&dir).output().unwrap();
    drop(alone);
    drop(run.stdin.take());

    assert!(
        swept_while_held.status.success(),
        "stderr: {}",
        text(&swept_while_held.stderr)
    );
    assert_eq!(logins_while_held, 1);
    assert!(
        text(&swept_after.stdout).contains(&format!("dropped the leftover login `{login_name}`")),
        "stdout: {}",
        text(&swept_after.stdout)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_lock_on_a_table_the_crashed_login_owns_fails_that_drop_without_stopping_gc_or_run() {
    create_writer_group("e2e_gc_locked_writer");
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_locked_writer.e2e_gc_locked_table;");
    let dir = project_with_reader("e2e-gc-locked-table");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-locked-table.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         writer = { member_of = \"e2e_gc_locked_writer\", read_only = false }\n",
    )
    .unwrap();
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtXc 'CREATE TABLE e2e_gc_locked_writer.e2e_gc_locked_table ()'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();
    superuser_sql("DROP ROLE IF EXISTS dbvalet_lockedtablenext2;");
    let beside = ledger_entry(&dir, "e2e-gc-locked-table", "dbvalet_lockedtablenext2");
    std::fs::write(&beside, "read-only\n").unwrap();
    let lock_holder = runtime();
    let holding = lock_holder.block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .batch_execute(
                "BEGIN; LOCK TABLE e2e_gc_locked_writer.e2e_gc_locked_table IN ACCESS SHARE MODE;",
            )
            .await
            .unwrap();
        client
    });

    let sweeping = sweeping();
    let swept = output_within(gc_command(&dir), Duration::from_secs(60));
    let next = output_within(
        run_command(&dir, &["sh", "-c", "echo ran"]),
        Duration::from_secs(60),
    );
    let logins_while_locked = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let beside_after_first_gc = beside.exists();
    drop(holding);
    drop(lock_holder);
    let swept_after = output_within(gc_command(&dir), Duration::from_secs(60));
    drop(sweeping);
    drop(run.stdin.take());
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_locked_table' AND tableowner = $1",
        "e2e_gc_locked_writer",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_locked_writer.e2e_gc_locked_table;");

    let stderr = text(&swept.stderr);
    assert_eq!(swept.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains(&login_name) && stderr.contains("lock timeout"),
        "stderr: {stderr}"
    );
    assert!(next.status.success(), "stderr: {}", text(&next.stderr));
    assert_eq!(text(&next.stdout), "ran\n");
    assert_eq!(logins_while_locked, 1);
    assert!(!beside_after_first_gc);
    assert!(
        swept_after.status.success(),
        "stderr: {}",
        text(&swept_after.stderr)
    );
    assert_eq!(owned_by_group, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_admin_endpoint_that_never_answers_is_reported_and_gc_sweeps_the_next_database() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    std::thread::spawn(move || silent.incoming().collect::<Vec<_>>());
    let stored = login(
        "e2e-gc-stall-a",
        &format!("postgresql://e2e_stall:pw-e2e-stall@127.0.0.1:{port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = project_with_reader("e2e-gc-stall-b");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-stall-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-stall-b.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    superuser_sql("DROP ROLE IF EXISTS dbvalet_stalledendpoint2;");
    let entry = ledger_entry(&dir, "e2e-gc-stall-b", "dbvalet_stalledendpoint2");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    let _sweeping = sweeping();
    let swept = output_within(gc_command(&dir), Duration::from_secs(60));

    let stderr = text(&swept.stderr);
    assert_eq!(swept.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("`e2e-gc-stall-a`"), "stderr: {stderr}");
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_writable_login_that_set_itself_read_only_keeps_its_table_after_a_crash() {
    create_writer_group("e2e_gc_self_read_only_writer");
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_self_read_only_writer.e2e_gc_self_read_only_table;");
    let dir = project_with_reader("e2e-gc-self-read-only");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-self-read-only.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         writer = { member_of = \"e2e_gc_self_read_only_writer\", read_only = false }\n",
    )
    .unwrap();
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtX \
         -c 'CREATE TABLE e2e_gc_self_read_only_writer.e2e_gc_self_read_only_table ()' \
         -c 'ALTER ROLE CURRENT_USER SET default_transaction_read_only = on'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let swept = gc_in(&dir);
    drop(run.stdin.take());
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_self_read_only_table' AND tableowner = $1",
        "e2e_gc_self_read_only_writer",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_self_read_only_writer.e2e_gc_self_read_only_table;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(owned_by_group, 1);
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_expired_login_owning_a_table_in_another_database_is_left_to_that_databases_sweep() {
    let other_db_url = "postgresql://postgres:e2e-throwaway@localhost:5432/e2e_gc_other_db";
    if superuser_count(
        "SELECT count(*) FROM pg_database WHERE datname = $1",
        "e2e_gc_other_db",
    ) == 0
    {
        superuser_sql("CREATE DATABASE e2e_gc_other_db;");
    }
    create_writer_group("e2e_gc_other_writer");
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(other_db_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .batch_execute(
                "CREATE SCHEMA IF NOT EXISTS e2e_gc_other_writer AUTHORIZATION e2e_gc_other_writer;
                 DROP TABLE IF EXISTS e2e_gc_other_writer.e2e_gc_other_table;",
            )
            .await
            .unwrap();
    });
    let dir = project_with_reader("e2e-gc-other-db-a");
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_gc_other_db_z;
         CREATE ROLE e2e_gc_other_db_z LOGIN SUPERUSER PASSWORD 'pw-e2e-gc-other-db-z';",
    );
    let stored = login(
        "e2e-gc-other-db-z",
        "postgresql://e2e_gc_other_db_z:pw-e2e-gc-other-db-z@localhost:5432/e2e_gc_other_db",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-other-db-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-other-db-z.roles]\n\
         writer = { member_of = \"e2e_gc_other_writer\", read_only = false }\n",
    )
    .unwrap();
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--db", "e2e-gc-other-db-z", "--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtXc \
         'CREATE TABLE e2e_gc_other_writer.e2e_gc_other_table ()'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept = gc_command(&dir).output().unwrap();
    drop(alone);
    drop(run.stdin.take());
    let owned_by_group: i64 = runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(other_db_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query_one(
                "SELECT count(*) FROM pg_tables
                 WHERE tablename = 'e2e_gc_other_table' AND tableowner = 'e2e_gc_other_writer'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    });

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(text(&swept.stderr), "");
    assert!(
        text(&swept.stdout).contains(&format!(
            "`e2e-gc-other-db-z`: dropped the leftover login `{login_name}`"
        )),
        "stdout: {}",
        text(&swept.stdout)
    );
    assert_eq!(owned_by_group, 1);
}

/// A server on 127.0.0.1 that lets every client log in, then never answers a query.
fn silent_after_login_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            stream.read_exact(&mut startup).unwrap();
            // AuthenticationOk, then ReadyForQuery with an idle transaction status.
            stream
                .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                .unwrap();
            held.push(stream);
        }
    });
    port
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_admin_endpoint_that_logs_in_and_then_never_answers_is_reported_and_gc_moves_on() {
    let port = silent_after_login_server();
    let stored = login(
        "e2e-gc-silent-after-login-a",
        &format!("postgresql://e2e_silent:pw-e2e-silent@127.0.0.1:{port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = project_with_reader("e2e-gc-silent-after-login-b");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-silent-after-login-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-silent-after-login-b.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    superuser_sql("DROP ROLE IF EXISTS dbvalet_silentafterlogin;");
    let entry = ledger_entry(
        &dir,
        "e2e-gc-silent-after-login-b",
        "dbvalet_silentafterlogin",
    );
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    let _sweeping = sweeping();
    let swept = output_within(gc_command(&dir), Duration::from_secs(60));

    let stderr = text(&swept.stderr);
    assert_eq!(swept.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("`e2e-gc-silent-after-login-a`"),
        "stderr: {stderr}"
    );
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_of_another_database_never_holds_this_databases_ledger_entries() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    let (accepted, connected) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in silent.incoming() {
            held.push(stream);
            let _ = accepted.send(());
        }
    });
    let stored = login(
        "e2e-gc-hold-x",
        &format!("postgresql://e2e_hold:pw-e2e-hold@127.0.0.1:{port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = project_with_reader("e2e-gc-hold-z");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-hold-x.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-hold-z.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    let (mut crashed, seen) =
        start_run_until_ready(&dir, &["--db", "e2e-gc-hold-z"], "echo \"login=$PGUSER\"");
    let login_name = printed(&seen, "login").to_owned();
    crashed.kill().unwrap();
    crashed.wait().unwrap();

    let _sweeping = sweeping();
    // A run on the other database, stuck connecting while its sweep has begun.
    let mut stuck = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "run",
            "--db",
            "e2e-gc-hold-x",
            "--allow-plaintext",
            "--",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    connected.recv_timeout(Duration::from_secs(10)).unwrap();
    let next = output_within(
        {
            let mut next = Command::new(DBVALET);
            next.current_dir(&dir)
                .env("XDG_STATE_HOME", dir.join("state"))
                .args([
                    "run",
                    "--db",
                    "e2e-gc-hold-z",
                    "--allow-plaintext",
                    "--",
                    "true",
                ]);
            next
        },
        Duration::from_secs(60),
    );
    let stuck_while_next_ran = stuck.try_wait().unwrap().is_none();
    let logins_after_next = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    stuck.kill().unwrap();
    stuck.wait().unwrap();
    drop(crashed.stdin.take());

    assert!(next.status.success(), "stderr: {}", text(&next.stderr));
    assert!(
        stuck_while_next_ran,
        "the stuck run ended before the next run did"
    );
    assert_eq!(logins_after_next, 0);
}

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
