//! `dbvalet` against end-of-life PostgreSQL 14 on localhost:5432 and the real OS keychain.
//! CI runs these in a dedicated PostgreSQL 14 job with `cargo test --test e2e_pg14 -- --ignored`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");
const SUPERUSER_URL: &str = "postgresql://postgres:e2e-throwaway@localhost:5432/postgres";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
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
        client
            .query_one("SELECT current_setting('server_version_num')::int", &[])
            .await
            .unwrap()
            .get(0)
    })
}

fn superuser_count(sql: &str) -> i64 {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.query_one(sql, &[]).await.unwrap().get(0)
    })
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

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
#[ignore = "e2e: needs PostgreSQL 14 on localhost:5432 and a keychain"]
fn doctor_against_postgresql_14_fails_the_version_check_naming_15_and_end_of_life() {
    let version_num = server_version_num();
    assert!(
        (140000..150000).contains(&version_num),
        "expected PostgreSQL 14, got server_version_num={version_num}"
    );
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_pg14_doctor_admin;
         CREATE ROLE e2e_pg14_doctor_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-pg14-doc-1a2b';",
    );
    let stored = login(
        "e2e-pg14-doctor",
        "postgresql://e2e_pg14_doctor_admin:pw-e2e-pg14-doc-1a2b@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));

    let checked = Command::new(DBVALET)
        .args(["doctor", "--allow-plaintext", "e2e-pg14-doctor"])
        .output()
        .unwrap();

    let stdout = text(&checked.stdout);
    let stderr = text(&checked.stderr);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(stdout.contains("FAIL PostgreSQL 14."), "doctor: {stdout}");
    assert!(
        stdout.contains("is end-of-life: dbvalet needs 15 or later\n"),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("pw-e2e-pg14-doc-1a2b"));
    assert!(!stderr.contains("pw-e2e-pg14-doc-1a2b"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL 14 on localhost:5432 and a keychain"]
fn run_against_postgresql_14_is_refused_before_creating_a_login() {
    let version_num = server_version_num();
    assert!(
        (140000..150000).contains(&version_num),
        "expected PostgreSQL 14, got server_version_num={version_num}"
    );
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_pg14_run_admin;
         DROP ROLE IF EXISTS e2e_pg14_reader_group;
         CREATE ROLE e2e_pg14_reader_group NOLOGIN;
         CREATE ROLE e2e_pg14_run_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-pg14-run-3c4d';",
    );
    let stored = login(
        "e2e-pg14-run",
        "postgresql://e2e_pg14_run_admin:pw-e2e-pg14-run-3c4d@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-pg14-run");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-pg14-run.roles]\n\
         reader = { member_of = \"e2e_pg14_reader_group\", read_only = true }\n",
    )
    .unwrap();

    let output = Command::new(DBVALET)
        .current_dir(&dir)
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

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("PostgreSQL 14."), "stderr: {stderr}");
    assert!(
        stderr.contains("is end-of-life: dbvalet needs 15 or later"),
        "stderr: {stderr}"
    );
    assert!(!stderr.contains("pw-e2e-pg14-run-3c4d"));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'dbvalet_%' AND rolcanlogin"
        ),
        0
    );
}
