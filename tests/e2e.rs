//! `dbvalet` as a subprocess, against real PostgreSQL on localhost:5432 and the real OS
//! keychain. CI runs these with `cargo test --test e2e -- --ignored`.
//!
//! Every test uses its own alias and admin role, so they can run in parallel.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");
const SUPERUSER_URL: &str = "postgresql://postgres:e2e-throwaway@localhost:5432/postgres";

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
    assert!(stdout.contains(" is 14 or later\n"));
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
    assert!(stdout.contains(" is 14 or later\n"));
    assert!(stdout.contains("ok   `e2e_createrole_admin` has CREATEROLE\n"));
    assert!(stdout.contains(
        "ok   `e2e_createrole_admin` can end the sessions of logins it creates, \
         because dbvalet sets createrole_self_grant on PostgreSQL 16 and later\n"
    ));
    assert!(!stdout.contains("FAIL"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_createrole_admin_before_postgresql_16_is_told_to_grant_pg_signal_backend() {
    if server_version_num() >= 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_createrole_old_admin;
         CREATE ROLE e2e_createrole_old_admin LOGIN CREATEROLE PASSWORD 'pw-e2e-old-55a7';",
    );
    let stored = login(
        "e2e-createrole-old",
        "postgresql://e2e_createrole_old_admin:pw-e2e-old-55a7@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-createrole-old");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success());
    assert!(stdout.contains("ok   `e2e_createrole_old_admin` has CREATEROLE\n"));
    assert!(
        stdout.contains(
            "FAIL `e2e_createrole_old_admin` can't end other roles' sessions: \
             run GRANT pg_signal_backend TO \"e2e_createrole_old_admin\"\n"
        ),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("as a superuser"), "doctor: {stdout}");
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
fn a_noinherit_createrole_admin_holding_pg_signal_backend_before_postgresql_16_is_told_to_enable_inherit()
 {
    if server_version_num() >= 160000 {
        return;
    }
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_noinh_14_admin;
         CREATE ROLE e2e_noinh_14_admin LOGIN CREATEROLE NOINHERIT PASSWORD 'pw-e2e-noinh14-2a9b';
         GRANT pg_signal_backend TO e2e_noinh_14_admin;",
    );
    let stored = login(
        "e2e-noinh-14",
        "postgresql://e2e_noinh_14_admin:pw-e2e-noinh14-2a9b@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = doctor("e2e-noinh-14");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains("ALTER ROLE \"e2e_noinh_14_admin\" INHERIT"),
        "doctor: {stdout}"
    );
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

fn run_in(dir: &Path, command: &[&str]) -> Output {
    Command::new(DBVALET)
        .current_dir(dir)
        .args(["run", "--allow-plaintext", "--"])
        .args(command)
        .output()
        .unwrap()
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
    let mut run = Command::new(DBVALET)
        .current_dir(dir)
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

    let output = Command::new(DBVALET)
        .current_dir(&dir)
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
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert!(
        text(&output.stderr).is_empty(),
        "stderr: {}",
        text(&output.stderr)
    );
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
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
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
    assert!(stderr.is_empty(), "stderr: {stderr}");
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
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
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
                .query_one("SELECT count(*) FROM pg_largeobject_metadata", &[])
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

fn pid_of(child: &std::process::Child) -> Pid {
    Pid::from_raw(i32::try_from(child.id()).unwrap())
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn sigint_to_dbvalet_waits_for_the_child_drops_the_login_and_returns_its_exit_code() {
    let dir = project_with_reader("e2e-run-sigint-trap");
    let mut run = Command::new("python3")
        .current_dir(&dir)
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
    let login_name = line_value(&seen, "login=");

    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();

    let status = run.wait().unwrap();
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(status.code(), Some(42), "stderr: {stderr_text}");
    assert!(rest.contains("after-sigint=1"), "stdout: {seen}{rest}");
    assert!(stderr_text.is_empty(), "stderr: {stderr_text}");
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
    let mut run = Command::new("python3")
        .current_dir(&dir)
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
    let login_name = line_value(&seen, "login=");

    signal::killpg(pid_of(&run), Signal::SIGINT).unwrap();

    let status = run.wait().unwrap();
    let mut stderr_text = String::new();
    stderr.read_to_string(&mut stderr_text).unwrap();

    assert_eq!(status.code(), Some(130), "stderr: {stderr_text}");
    assert!(stderr_text.is_empty(), "stderr: {stderr_text}");
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
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
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
    // Ignore TERM as well as HUP so Linux PR_SET_PDEATHSIG(SIGTERM) doesn't kill the
    // child when dbvalet exits before we check that the child outlived the SIGHUP timeout.
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
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
    use std::time::Duration;

    let dir = project_with_reader("e2e-run-sigkill-linux");
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
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

    // SIGKILL skips teardown, so clean up the temporary login for the rest of the suite.
    superuser_sql(&format!("DROP ROLE IF EXISTS {login_name};"));

    assert!(
        child_ended,
        "child should exit via PR_SET_PDEATHSIG(SIGTERM) when dbvalet is SIGKILLed"
    );
}
