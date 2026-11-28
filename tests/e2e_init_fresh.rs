//! `dbvalet init` on a cluster where `dbvalet_reader` doesn't exist yet, so a non-superuser
//! CREATEROLE admin creates it. The role is cluster-wide and `tests/e2e` creates it, so CI runs
//! this with `cargo test --test e2e_init_fresh -- --ignored` on a fresh cluster, before `e2e`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");
const SUPERUSER_URL: &str = "postgresql://postgres:e2e-throwaway@localhost:5432/postgres";
const ADMIN_URL: &str =
    "postgresql://e2e_init_fresh:pw-e2e-init-fresh-7c1d@localhost:5432/e2e_init_fresh";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn sql(url: &str, sql: &str) {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute(sql).await.unwrap();
    });
}

fn superuser_text(sql: &str) -> String {
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

/// One test only: the first `init` on the cluster is the one that creates the role.
#[test]
#[ignore = "e2e: needs a fresh PostgreSQL cluster on localhost:5432 and a keychain"]
fn a_createrole_admin_creates_dbvalet_reader_with_init_and_runs_a_read() {
    assert_eq!(
        superuser_text("SELECT count(*)::text FROM pg_roles WHERE rolname = 'dbvalet_reader'"),
        "0",
        "dbvalet_reader already exists: run this test on a fresh cluster, before tests/e2e"
    );
    sql(
        SUPERUSER_URL,
        "CREATE ROLE e2e_init_fresh LOGIN CREATEROLE PASSWORD 'pw-e2e-init-fresh-7c1d'",
    );
    sql(
        SUPERUSER_URL,
        "CREATE DATABASE e2e_init_fresh OWNER e2e_init_fresh",
    );
    // So the run only connects through the CONNECT that init grants.
    sql(
        SUPERUSER_URL,
        "REVOKE CONNECT ON DATABASE e2e_init_fresh FROM PUBLIC",
    );
    sql(
        ADMIN_URL,
        "CREATE TABLE notes (note text);
         INSERT INTO notes VALUES ('read after a fresh init');",
    );
    let stored = login("e2e_init_fresh", ADMIN_URL);
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e_init_fresh");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let init = Command::new(DBVALET)
        .current_dir(&dir)
        .args(["init", "--allow-plaintext", "e2e_init_fresh"])
        .output()
        .unwrap();
    assert!(init.status.success(), "init: {}", text(&init.stderr));
    let output = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--"])
        .args(["psql", "-Atc", "SELECT note FROM notes"])
        .output()
        .unwrap();
    // SET is a privilege of its own from 16; before that, every member may SET ROLE.
    let rights = superuser_text(
        "SELECT concat_ws(' ',
             pg_has_role('e2e_init_fresh', 'dbvalet_reader', 'MEMBER WITH ADMIN OPTION')::text,
             pg_has_role('e2e_init_fresh', 'dbvalet_reader', 'USAGE')::text,
             CASE WHEN current_setting('server_version_num')::int >= 160000
                  THEN pg_has_role('e2e_init_fresh', 'dbvalet_reader', 'SET')
                  ELSE pg_has_role('e2e_init_fresh', 'dbvalet_reader', 'MEMBER') END::text)",
    );

    let reader_can_log_in =
        superuser_text("SELECT rolcanlogin::text FROM pg_roles WHERE rolname = 'dbvalet_reader'");
    let leftover_logins = superuser_text(
        "SELECT count(*)::text FROM pg_roles WHERE rolname ~ '^dbvalet_[a-z2-7]{16}$'",
    );

    assert!(output.status.success(), "run: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "read after a fresh init\n");
    assert_eq!(rights, "true true true");
    assert_eq!(reader_can_log_in, "false");
    assert_eq!(leftover_logins, "0");
}
