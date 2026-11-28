//! `dbvalet login` and `doctor`, including TLS refusal at login.

use std::process::Command;

use crate::support::{
    DBVALET, doctor, login, project_with_reader, server_version_num, superuser_sql, sweeping, text,
};

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

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_and_run_without_allow_plaintext_refuse_a_server_without_tls() {
    let dir = project_with_reader("e2e-tls-refused");
    let _sweeping = sweeping();

    let checked = Command::new(DBVALET)
        .args(["doctor", "e2e-tls-refused"])
        .output()
        .unwrap();
    let doctor_stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {doctor_stdout}");
    assert!(
        doctor_stdout.contains("the database refused TLS"),
        "doctor: {doctor_stdout}"
    );
    assert!(
        doctor_stdout.contains("--allow-plaintext"),
        "doctor: {doctor_stdout}"
    );

    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--", "sh", "-c", "echo child-should-not-run"])
        .output()
        .unwrap();
    let run_stdout = text(&run.stdout);
    let run_stderr = text(&run.stderr);
    assert!(!run.status.success(), "run should fail: {run_stdout}");
    assert!(run_stdout.is_empty(), "child must not run: {run_stdout}");
    assert!(
        run_stderr.contains("the database refused TLS"),
        "stderr: {run_stderr}"
    );

    let allowed = doctor("e2e-tls-refused");
    let allowed_stdout = text(&allowed.stdout);
    assert!(allowed.status.success(), "doctor: {allowed_stdout}");
    assert!(
        allowed_stdout.contains("ok   plaintext on localhost (--allow-plaintext)\n"),
        "doctor: {allowed_stdout}"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn login_accepts_sslmode_verify_full_and_sslrootcert() {
    // `login` loads the file, so it must hold real CA certificates: the Debian/Ubuntu bundle does.
    let stored = login(
        "e2e-login-sslrootcert",
        "postgresql://admin:pw-e2e-sslrootcert-12ab@db.example.com:5432/app\
         ?sslmode=verify-full&sslrootcert=/etc/ssl/certs/ca-certificates.crt",
    );
    assert!(
        stored.status.success(),
        "login stderr: {}",
        text(&stored.stderr)
    );
    assert!(!text(&stored.stdout).contains("pw-e2e-sslrootcert-12ab"));
    assert!(!text(&stored.stderr).contains("pw-e2e-sslrootcert-12ab"));
}
