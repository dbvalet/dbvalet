//! `dbvalet run` through the proxy: env, token, exit codes, teardown.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::support::{
    DBVALET, SUPERUSER_URL, login, passwords_of, project_with_reader,
    project_with_reader_and_admin, run_in, runtime, server_version_num, superuser_count,
    superuser_sql, sweeping, text,
};

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
