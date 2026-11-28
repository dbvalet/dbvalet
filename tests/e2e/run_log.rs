//! Run logs and `dbvalet log`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::support::{
    DBVALET, SUPERUSER_URL, login, passwords_of, project_with_reader, runtime, superuser_count,
    superuser_sql, sweeping, text,
};

fn isolated_state_home(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("state-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dbvalet_log(state_home: &Path, args: &[&str]) -> Output {
    Command::new(DBVALET)
        .env("XDG_STATE_HOME", state_home)
        .arg("log")
        .args(args)
        .output()
        .unwrap()
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn after_a_run_dbvalet_log_shows_the_header_and_simple_query_text() {
    let dir = project_with_reader("e2e-log-simple");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-log-simple]\n\
         max_ttl_minutes = 480\n\
         \n\
         [databases.e2e-log-simple.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    let state = isolated_state_home("e2e-log-simple");

    let _sweeping = sweeping();
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args(["run", "--allow-plaintext", "--", "psql", "-c", "select 1"])
        .output()
        .unwrap();
    drop(_sweeping);
    assert!(run.status.success(), "stderr: {}", text(&run.stderr));

    let listing = dbvalet_log(&state, &[]);
    assert!(
        listing.status.success(),
        "stderr: {}",
        text(&listing.stderr)
    );
    let listed = text(&listing.stdout);
    let first_line = listed.lines().next().unwrap();
    let run_id = first_line.split_whitespace().nth(1).unwrap();

    let shown = dbvalet_log(&state, &[run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains(&format!("run_id: {run_id}\n")), "{log}");
    assert!(log.contains("started_at: "), "{log}");
    assert!(log.contains("database: e2e-log-simple\n"), "{log}");
    assert!(log.contains("role: reader\n"), "{log}");
    assert!(log.contains("valid_until: "), "{log}");
    assert!(log.contains("max_ttl: 480m\n"), "{log}");
    assert!(log.contains("sql_log: enabled\n"), "{log}");
    assert!(log.contains("command: psql -c 'select 1'\n"), "{log}");
    assert!(log.contains(" [Q] select 1\n"), "{log}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_prepared_statement_sent_over_the_extended_protocol_appears_in_the_run_log() {
    let dir = project_with_reader("e2e-log-extended");
    let state = isolated_state_home("e2e-log-extended");

    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"login=$PGUSER\"; echo \"url=$DATABASE_URL\"; echo READY; read line",
        ])
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
    let run_id = login_name.strip_prefix("dbvalet_").unwrap().to_owned();
    let proxy_url = seen
        .lines()
        .find_map(|line| line.strip_prefix("url="))
        .unwrap()
        .to_owned();

    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(&proxy_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        let add_stmt = client.prepare("SELECT $1::int + 1 AS total").await.unwrap();
        let total: i32 = client.query_one(&add_stmt, &[&41i32]).await.unwrap().get(0);
        assert_eq!(total, 42);

        let echo_stmt = client.prepare("SELECT $1::text AS echo").await.unwrap();
        let echoed: String = client
            .query_one(&echo_stmt, &[&"bound-param-secret-7c3e"])
            .await
            .unwrap()
            .get(0);
        assert_eq!(echoed, "bound-param-secret-7c3e");
    });

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));

    let shown = dbvalet_log(&state, &[&run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains(" [P] SELECT $1::int + 1 AS total\n"), "{log}");
    assert!(log.contains(" [P] SELECT $1::text AS echo\n"), "{log}");
    assert!(!log.contains("bound-param-secret-7c3e"), "{log}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_run_with_no_sql_log_records_the_header_and_no_statements() {
    let dir = project_with_reader("e2e-log-no-sql");
    let state = isolated_state_home("e2e-log-no-sql");

    let _sweeping = sweeping();
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--no-sql-log",
            "--",
            "psql",
            "-Atc",
            "SELECT 'no-sql-log-marker-4a1f';",
        ])
        .output()
        .expect("run psql");
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "no-sql-log-marker-4a1f\n");

    let listing = dbvalet_log(&state, &[]);
    assert!(
        listing.status.success(),
        "stderr: {}",
        text(&listing.stderr)
    );
    let listed = text(&listing.stdout);
    let run_id = listed
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();

    let shown = dbvalet_log(&state, &[run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains(&format!("run_id: {run_id}\n")), "{log}");
    assert!(log.contains("database: e2e-log-no-sql\n"), "{log}");
    assert!(log.contains("role: reader\n"), "{log}");
    assert!(log.contains("sql_log: disabled (--no-sql-log)\n"), "{log}");
    assert!(log.contains("command: psql\n"), "{log}");
    assert!(!log.contains("no-sql-log-marker-4a1f"), "{log}");
    assert!(!log.contains(" [Q] "), "{log}");
    assert!(!log.contains(" [P] "), "{log}");
    let (_, after_header) = log.split_once("\n\n").unwrap();
    assert!(after_header.is_empty(), "body: {after_header:?}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_run_log_hides_the_token_login_password_and_sql_passwords() {
    let dir = project_with_reader("e2e-log-secrets");
    let state = isolated_state_home("e2e-log-secrets");
    let witness = "e2e_log_secrets_witness";

    let _sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(
            "echo \"login=$PGUSER\"; \
             echo \"token=$PGPASSWORD\"; \
             psql -c \"ALTER ROLE e2e_log_target PASSWORD 'pw-alter-role-8f3c'\" || true; \
             psql -c 'CREATE ROLE e2e_log_created LOGIN PASSWORD $$pw-create-role-4d9a$$' || true; \
             echo \"echoed=$(psql -Atc \"SELECT '$PGPASSWORD'\")\"; \
             echo READY; read line",
        )
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
    let run_id = login_name.strip_prefix("dbvalet_").unwrap().to_owned();
    let token = seen
        .lines()
        .find_map(|line| line.strip_prefix("token="))
        .unwrap()
        .to_owned();
    let echoed = seen
        .lines()
        .find_map(|line| line.strip_prefix("echoed="))
        .unwrap()
        .to_owned();
    // Proxy must not rewrite or block SQL on the wire (ADR-0002).
    assert_eq!(echoed, token);

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
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {witness}; CREATE ROLE {witness} LOGIN PASSWORD '{verifier}';"
    ));

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    // PostgreSQL itself refused ALTER ROLE in a read-only transaction, proving the proxy relayed it.
    assert!(
        stderr.contains("cannot execute ALTER ROLE in a read-only transaction"),
        "stderr: {stderr}"
    );

    let shown = dbvalet_log(&state, &[&run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(
        log.contains(" [Q] ALTER ROLE e2e_log_target PASSWORD '[REDACTED]'\n"),
        "{log}"
    );
    assert!(
        log.contains(" [Q] CREATE ROLE e2e_log_created LOGIN PASSWORD '[REDACTED]'\n"),
        "{log}"
    );
    assert!(log.contains(" [Q] SELECT '[REDACTED]'\n"), "{log}");
    assert!(!log.contains("pw-alter-role-8f3c"), "{log}");
    assert!(!log.contains("pw-create-role-4d9a"), "{log}");
    assert!(!log.contains(&token), "{log}");
    assert!(!log.contains("pw-e2e-log-secrets-admin"), "{log}");
    assert_eq!(passwords_of(witness, &log), Vec::<String>::new());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_run_log_header_redacts_sql_passwords_even_with_long_flags() {
    let dir = project_with_reader("e2e-log-header-pw");
    let state = isolated_state_home("e2e-log-header-pw");

    let _sweeping = sweeping();
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "psql",
            "--command=ALTER ROLE e2e_log_target PASSWORD 'pw-cli-arg-2b7e'",
        ])
        .output()
        .unwrap();
    drop(_sweeping);
    assert!(!run.status.success());

    let listed = text(&dbvalet_log(&state, &[]).stdout);
    let run_id = listed
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let log = text(&dbvalet_log(&state, &[run_id]).stdout);
    assert!(
        log.contains(" [Q] ALTER ROLE e2e_log_target PASSWORD '[REDACTED]'\n"),
        "{log}"
    );
    assert!(!log.contains("pw-cli-arg-2b7e"), "{log}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_failed_run_log_open_still_drops_the_temporary_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_log_open_fail_group;
         CREATE ROLE e2e_log_open_fail_group NOLOGIN;
         DROP ROLE IF EXISTS e2e_log_open_fail_admin;
         CREATE ROLE e2e_log_open_fail_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-log-open-fail';",
    );
    let stored = login(
        "e2e-log-open-fail",
        "postgresql://e2e_log_open_fail_admin:pw-e2e-log-open-fail@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-log-open-fail");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-log-open-fail.roles]\n\
         reader = { member_of = \"e2e_log_open_fail_group\", read_only = true }\n",
    )
    .unwrap();
    // Leave dbvalet/ledger writable so mint() creates the login, then block dbvalet/runs
    // with a regular file so opening the run log fails after mint().
    let state = isolated_state_home("e2e-log-open-fail");
    let app_state = state.join("dbvalet");
    std::fs::create_dir_all(&app_state).unwrap();
    std::fs::write(app_state.join("runs"), b"not a directory").unwrap();

    let _sweeping = sweeping();
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo child-ran",
        ])
        .output()
        .unwrap();
    drop(_sweeping);

    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stdout: {}", text(&output.stdout));
    assert!(
        output.stdout.is_empty(),
        "child should not run, stdout: {}",
        text(&output.stdout)
    );
    assert!(
        stderr.contains("couldn't create the run log directory"),
        "stderr: {stderr}"
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*)
             FROM pg_roles r
             JOIN pg_auth_members m ON m.member = r.oid
             JOIN pg_roles g ON g.oid = m.roleid
             WHERE g.rolname = $1 AND r.rolcanlogin AND r.rolname LIKE 'dbvalet\\_%' ESCAPE '\\'",
            "e2e_log_open_fail_group"
        ),
        0
    );
    let ledger_entries: Vec<_> = std::fs::read_dir(app_state.join("ledger"))
        .unwrap()
        .collect();
    assert!(ledger_entries.is_empty(), "ledger: {ledger_entries:?}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn dbvalet_log_lists_runs_newest_first() {
    let dir = project_with_reader("e2e-log-order");
    let state = isolated_state_home("e2e-log-order");

    let _sweeping = sweeping();
    let first = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"$PGUSER\"",
        ])
        .output()
        .unwrap();
    assert!(first.status.success(), "stderr: {}", text(&first.stderr));
    let first_id = text(&first.stdout)
        .trim()
        .strip_prefix("dbvalet_")
        .unwrap()
        .to_owned();

    let second = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            "echo \"$PGUSER\"",
        ])
        .output()
        .unwrap();
    assert!(second.status.success(), "stderr: {}", text(&second.stderr));
    let second_id = text(&second.stdout)
        .trim()
        .strip_prefix("dbvalet_")
        .unwrap()
        .to_owned();

    let listing = dbvalet_log(&state, &[]);
    assert!(
        listing.status.success(),
        "stderr: {}",
        text(&listing.stderr)
    );
    let listed = text(&listing.stdout);
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 2, "{listed}");
    assert!(lines[0].contains(&second_id), "{listed}");
    assert!(lines[1].contains(&first_id), "{listed}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_unicode_statement_containing_password_returns_the_same_result_with_and_without_sql_log() {
    let dir = project_with_reader("e2e-log-unicode-fwd");
    let state = isolated_state_home("e2e-log-unicode-fwd");
    let query = "SELECT 'Forgot your password? Réinitialisez-le'";

    let _sweeping = sweeping();
    let logged = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-AtXc",
            query,
        ])
        .output()
        .unwrap();
    let unlogged = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--no-sql-log",
            "--",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-AtXc",
            query,
        ])
        .output()
        .unwrap();

    assert!(logged.status.success(), "stderr: {}", text(&logged.stderr));
    assert!(
        unlogged.status.success(),
        "stderr: {}",
        text(&unlogged.stderr)
    );
    assert_eq!(logged.stdout, unlogged.stdout);
    assert_eq!(
        text(&logged.stdout),
        "Forgot your password? Réinitialisez-le\n"
    );

    let listed = text(&dbvalet_log(&state, &[]).stdout);
    let logged_id = listed
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let shown = text(&dbvalet_log(&state, &[logged_id]).stdout);
    assert!(shown.contains(&format!(" [Q] {query}\n")), "{shown}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn non_utf8_and_complex_password_statements_are_omitted_or_redacted_without_changing_results() {
    let dir = project_with_reader("e2e-log-hardening");
    let state = isolated_state_home("e2e-log-hardening");

    let script = concat!(
        "echo \"login=$PGUSER\"; ",
        "echo \"token=$PGPASSWORD\"; ",
        "printf \"SELECT 'caf\\351';\\n\" | PGCLIENTENCODING=LATIN1 psql -v ON_ERROR_STOP=1 -AtX | od -An -tx1 | tr -d ' \\n'; echo; ",
        "printf \"SELECT 'caf\\303\\251';\\n\" | PGCLIENTENCODING=LATIN1 psql -v ON_ERROR_STOP=1 -AtX >/dev/null; ",
        "printf \"ALTER ROLE CURRENT_USER PASSWORD -- note\\r'synthetic-e2e-cr';\\n\" | psql -X >/dev/null 2>&1 || true; ",
        "printf \"ALTER ROLE CURRENT_USER PASSWORD\\013'synthetic-e2e-vt';\\n\" | psql -X >/dev/null 2>&1 || true; ",
        "psql -X -c \"DO \\$a\\$ BEGIN EXECUTE \\$b\\$ DO \\$c\\$ BEGIN EXECUTE \\$d\\$ DO \\$e\\$ BEGIN ALTER ROLE CURRENT_USER PASSWORD 'synthetic-e2e-deep'; END \\$e\\$ \\$d\\$; END \\$c\\$ \\$b\\$; END \\$a\\$\" >/dev/null 2>&1 || true; ",
        "psql -X -c \"DO \\$\\$ BEGIN EXECUTE 'ALTER ROLE ' || quote_ident(current_user) || ' PASSWORD ' || quote_literal('synthetic-e2e-split'); END \\$\\$\" >/dev/null 2>&1 || true; ",
        "psql -v ON_ERROR_STOP=1 -AtXc \"SELECT 'postgresql://u@db.example/app?pass%77ord=synthetic-e2e-uri'\" >/dev/null; ",
        "psql -v ON_ERROR_STOP=1 -AtXc \"SELECT 1\""
    );

    let _sweeping = sweeping();
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args(["run", "--allow-plaintext", "--", "sh", "-c", script])
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", text(&output.stderr));

    let stdout = text(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let run_id = lines[0].strip_prefix("login=dbvalet_").unwrap().to_owned();
    let token = lines[1].strip_prefix("token=").unwrap().to_owned();
    // `caf\xe9\n` in hex proves PostgreSQL executed the LATIN1 query untouched.
    assert_eq!(lines[2], "636166e90a", "stdout: {stdout}");
    assert_eq!(lines[3], "1", "stdout: {stdout}");

    let shown = dbvalet_log(&state, &[&run_id]);
    assert!(shown.status.success(), "stderr: {}", text(&shown.stderr));
    let log = text(&shown.stdout);
    assert!(log.contains("/* omitted: non-UTF-8 */"), "{log}");
    assert!(
        log.contains("/* omitted: non-UTF-8 client_encoding */"),
        "{log}"
    );
    assert!(log.contains(" [Q] SELECT 1\n"), "{log}");
    for secret in [
        token.as_str(),
        "synthetic-e2e-cr",
        "synthetic-e2e-vt",
        "synthetic-e2e-deep",
        "synthetic-e2e-split",
        "synthetic-e2e-uri",
    ] {
        assert!(!log.contains(secret), "leaked {secret:?} in:\n{log}");
    }
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn unicode_line_separators_and_direction_overrides_are_escaped_in_dbvalet_log_output() {
    let dir = project_with_reader("e2e-log-bidi");
    let state = isolated_state_home("e2e-log-bidi");
    let query = "SELECT 'a\u{2028}b\u{2029}c\u{202e}d\u{2066}e'";

    let _sweeping = sweeping();
    let run = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", &state)
        .args([
            "run",
            "--allow-plaintext",
            "--",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-AtXc",
            query,
        ])
        .output()
        .unwrap();
    assert!(run.status.success(), "stderr: {}", text(&run.stderr));
    assert_eq!(text(&run.stdout), "a\u{2028}b\u{2029}c\u{202e}d\u{2066}e\n");

    let listed_out = dbvalet_log(&state, &[]);
    assert!(
        listed_out.status.success(),
        "stderr: {}",
        text(&listed_out.stderr)
    );
    let listed = text(&listed_out.stdout);
    let run_id = listed
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap();
    let shown_out = dbvalet_log(&state, &[run_id]);
    assert!(
        shown_out.status.success(),
        "stderr: {}",
        text(&shown_out.stderr)
    );
    let shown = text(&shown_out.stdout);

    for output in [&listed, &shown] {
        for forbidden in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}'] {
            assert!(
                !output.contains(forbidden),
                "raw {forbidden:?} in:\n{output}"
            );
        }
        assert!(output.contains("\\u{2028}"), "{output}");
        assert!(output.contains("\\u{202e}"), "{output}");
    }
}
