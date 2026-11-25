//! `dbvalet` as a subprocess, against real PostgreSQL on localhost:5432 and the real OS
//! keychain. CI runs these with `cargo test --test e2e -- --ignored`.
//!
//! Every test uses its own alias and admin role, so they can run in parallel.

use std::io::Write;
use std::process::{Command, Output, Stdio};

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
