//! `run` and `doctor` refusing dangerous group roles.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::support::{
    DBVALET, create_reader_group, login, project_with_reader_and_admin, run_in, superuser_count,
    superuser_sql, text,
};

fn ledger_entries_in(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir.join("state/dbvalet/ledger"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect()
}

fn logins_in_group(group: &str) -> i64 {
    superuser_count(
        "SELECT count(*)
         FROM pg_roles r
         JOIN pg_auth_members m ON m.member = r.oid
         JOIN pg_roles g ON g.oid = m.roleid
         WHERE g.rolname = $1
           AND r.rolcanlogin
           AND starts_with(r.rolname::text, 'dbvalet_')",
        group,
    )
}

fn project_with_group(alias: &str, admin_attributes: &str, group: &str) -> PathBuf {
    let admin = format!("{}_admin", alias.replace('-', "_"));
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {admin};
         CREATE ROLE {admin} LOGIN {admin_attributes} PASSWORD 'pw-{alias}-admin';
         GRANT \"{group}\" TO {admin} WITH ADMIN OPTION;"
    ));
    let stored = login(
        alias,
        &format!("postgresql://{admin}:pw-{alias}-admin@localhost:5432/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(alias);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        format!(
            "[databases.{alias}.roles]\n\
             reader = {{ member_of = \"{group}\", read_only = true }}\n"
        ),
    )
    .unwrap();
    dir
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_superuser_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_super;
         CREATE ROLE e2e_danger_super NOLOGIN SUPERUSER;",
    );
    let dir = project_with_group("e2e-danger-super", "SUPERUSER", "e2e_danger_super");

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_super"), "stderr: {stderr}");
    assert!(stderr.contains("SUPERUSER"), "stderr: {stderr}");
    assert!(!stderr.contains("pw-e2e-danger-super-admin"));
    assert_eq!(logins_in_group("e2e_danger_super"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_createrole_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_createrole;
         CREATE ROLE e2e_danger_createrole NOLOGIN CREATEROLE;",
    );
    let dir = project_with_group(
        "e2e-danger-createrole",
        "SUPERUSER",
        "e2e_danger_createrole",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_createrole"), "stderr: {stderr}");
    assert!(stderr.contains("CREATEROLE"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_createrole"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_bypassrls_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_bypassrls;
         CREATE ROLE e2e_danger_bypassrls NOLOGIN BYPASSRLS;",
    );
    let dir = project_with_group("e2e-danger-bypassrls", "CREATEROLE", "e2e_danger_bypassrls");

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_bypassrls"), "stderr: {stderr}");
    assert!(stderr.contains("BYPASSRLS"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_bypassrls"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_replication_group_role_without_creating_a_login() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_replication;
         CREATE ROLE e2e_danger_replication NOLOGIN REPLICATION;",
    );
    let dir = project_with_group(
        "e2e-danger-replication",
        "CREATEROLE",
        "e2e_danger_replication",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("e2e_danger_replication"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("REPLICATION"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_replication"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_pg_execute_server_program_as_group_role_without_creating_a_login() {
    let dir = project_with_group(
        "e2e-danger-pg-exec",
        "SUPERUSER",
        "pg_execute_server_program",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("pg_execute_server_program"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pg_*"), "stderr: {stderr}");
    assert_eq!(logins_in_group("pg_execute_server_program"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_group_role_that_is_a_direct_member_of_pg_execute_server_program() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_direct_exec;
         CREATE ROLE e2e_danger_direct_exec NOLOGIN;
         GRANT pg_execute_server_program TO e2e_danger_direct_exec;",
    );
    let dir = project_with_group(
        "e2e-danger-direct-exec",
        "SUPERUSER",
        "e2e_danger_direct_exec",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("e2e_danger_direct_exec"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("pg_execute_server_program"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pg_*"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_direct_exec"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_group_role_that_is_a_transitive_member_of_pg_execute_server_program() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_leaf_exec;
         DROP ROLE IF EXISTS e2e_danger_mid_exec;
         CREATE ROLE e2e_danger_mid_exec NOLOGIN;
         CREATE ROLE e2e_danger_leaf_exec NOLOGIN;
         GRANT pg_execute_server_program TO e2e_danger_mid_exec;
         GRANT e2e_danger_mid_exec TO e2e_danger_leaf_exec;",
    );
    let dir = project_with_group("e2e-danger-leaf-exec", "CREATEROLE", "e2e_danger_leaf_exec");

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(stderr.contains("e2e_danger_leaf_exec"), "stderr: {stderr}");
    assert!(
        stderr.contains("pg_execute_server_program"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("pg_*"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_leaf_exec"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn run_refuses_a_group_role_that_is_a_member_of_a_superuser_role() {
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_danger_child_super;
         DROP ROLE IF EXISTS e2e_danger_parent_super;
         CREATE ROLE e2e_danger_parent_super NOLOGIN SUPERUSER;
         CREATE ROLE e2e_danger_child_super NOLOGIN;
         GRANT e2e_danger_parent_super TO e2e_danger_child_super;",
    );
    let dir = project_with_group(
        "e2e-danger-child-super",
        "SUPERUSER",
        "e2e_danger_child_super",
    );

    let output = run_in(&dir, &["sh", "-c", "echo CHILD_RAN"]);

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stdout.is_empty(), "child should not run, stdout: {stdout}");
    assert!(
        stderr.contains("e2e_danger_child_super"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("e2e_danger_parent_super"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("SUPERUSER"), "stderr: {stderr}");
    assert_eq!(logins_in_group("e2e_danger_child_super"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_reports_each_dangerous_configured_role_and_passes_dbvalet_reader() {
    create_reader_group();
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_doc_danger_admin;
         DROP ROLE IF EXISTS e2e_doc_super;
         DROP ROLE IF EXISTS e2e_doc_createrole;
         DROP ROLE IF EXISTS e2e_doc_leaf_exec;
         DROP ROLE IF EXISTS e2e_doc_mid_exec;
         CREATE ROLE e2e_doc_danger_admin LOGIN SUPERUSER PASSWORD 'pw-e2e-doc-danger-9a4b';
         CREATE ROLE e2e_doc_super NOLOGIN SUPERUSER;
         CREATE ROLE e2e_doc_createrole NOLOGIN CREATEROLE;
         CREATE ROLE e2e_doc_mid_exec NOLOGIN;
         CREATE ROLE e2e_doc_leaf_exec NOLOGIN;
         GRANT pg_execute_server_program TO e2e_doc_mid_exec;
         GRANT e2e_doc_mid_exec TO e2e_doc_leaf_exec;",
    );
    let stored = login(
        "e2e-doc-danger",
        "postgresql://e2e_doc_danger_admin:pw-e2e-doc-danger-9a4b@localhost:5432/postgres",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-doc-danger");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-doc-danger.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         bad_super = { member_of = \"e2e_doc_super\", read_only = true }\n\
         bad_createrole = { member_of = \"e2e_doc_createrole\", read_only = true }\n\
         bad_exec = { member_of = \"e2e_doc_leaf_exec\", read_only = true }\n",
    )
    .unwrap();

    let checked = Command::new(DBVALET)
        .current_dir(&dir)
        .args(["doctor", "--allow-plaintext", "e2e-doc-danger"])
        .output()
        .unwrap();

    let stdout = text(&checked.stdout);
    let stderr = text(&checked.stderr);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains("ok   role `reader` (`dbvalet_reader`)"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("FAIL role `bad_super` (`e2e_doc_super`)") && stdout.contains("SUPERUSER"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("FAIL role `bad_createrole` (`e2e_doc_createrole`)")
            && stdout.contains("CREATEROLE"),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains("FAIL role `bad_exec` (`e2e_doc_leaf_exec`)")
            && stdout.contains("pg_execute_server_program")
            && stdout.contains("pg_*"),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("pw-e2e-doc-danger-9a4b"));
    assert!(!stderr.contains("pw-e2e-doc-danger-9a4b"));
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_passes_when_dbvalet_toml_configures_only_dbvalet_reader() {
    let dir = project_with_reader_and_admin("e2e-doc-safe-reader", "CREATEROLE");

    let checked = Command::new(DBVALET)
        .current_dir(&dir)
        .args(["doctor", "--allow-plaintext", "e2e-doc-safe-reader"])
        .output()
        .unwrap();

    let stdout = text(&checked.stdout);
    assert!(checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains("ok   role `reader` (`dbvalet_reader`)"),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("FAIL"), "doctor: {stdout}");
}
