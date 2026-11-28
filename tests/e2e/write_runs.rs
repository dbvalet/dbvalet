//! Write runs for a `read_only = false` role, with a non-superuser CREATEROLE admin, and the
//! `doctor` checks on the admin's grants that they need.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::support::{
    DBVALET, gc_command, gc_in, printed, project_with_reader_and_admin, server_version_num,
    start_run_until_ready, superuser_count, superuser_sql, sweeping, sweeping_alone, text,
};

/// A CREATEROLE admin for `alias` holding `GRANT <group> TO <admin> <grant_options>`, and a
/// `dbvalet.toml` listing `reader` and a writable `writer` role. The writer group owns a schema
/// of its own name, so it can create tables there.
fn project_with_writer(alias: &str, group: &str, grant_options: &str) -> PathBuf {
    let dir = project_with_reader_and_admin(alias, "CREATEROLE");
    let admin = alias.replace('-', "_");
    superuser_sql(&format!(
        "DROP SCHEMA IF EXISTS {group} CASCADE;
         DROP ROLE IF EXISTS {group};
         CREATE ROLE {group} NOLOGIN;
         CREATE SCHEMA {group} AUTHORIZATION {group};
         GRANT {group} TO {admin} {grant_options};"
    ));
    std::fs::write(
        dir.join("dbvalet.toml"),
        format!(
            "[databases.{alias}.roles]\n\
             reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n\
             writer = {{ member_of = \"{group}\", read_only = false }}\n"
        ),
    )
    .unwrap();
    dir
}

fn run_as(dir: &Path, role: &str, script: &str) -> Output {
    let _sweeping = sweeping();
    Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "run",
            "--role",
            role,
            "--allow-plaintext",
            "--",
            "sh",
            "-c",
            script,
        ])
        .output()
        .unwrap()
}

fn doctor_in(dir: &Path, alias: &str) -> Output {
    Command::new(DBVALET)
        .current_dir(dir)
        .args(["doctor", "--allow-plaintext", alias])
        .output()
        .unwrap()
}

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

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_writer_run_inserts_a_row() {
    let dir = project_with_writer(
        "e2e-write-insert",
        "e2e_write_insert_group",
        "WITH ADMIN OPTION",
    );
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_write_insert_rows;
         CREATE TABLE e2e_write_insert_rows (note text);
         GRANT INSERT ON e2e_write_insert_rows TO e2e_write_insert_group;",
    );

    let output = run_as(
        &dir,
        "writer",
        "psql -v ON_ERROR_STOP=1 -qc \"INSERT INTO e2e_write_insert_rows VALUES ('written')\"",
    );

    assert!(output.status.success(), "stderr: {}", text(&output.stderr));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM e2e_write_insert_rows WHERE note = $1",
            "written"
        ),
        1
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn the_same_insert_through_a_reader_run_is_refused_as_read_only() {
    let dir = project_with_writer(
        "e2e-write-reader",
        "e2e_write_reader_group",
        "WITH ADMIN OPTION",
    );
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_write_reader_rows;
         CREATE TABLE e2e_write_reader_rows (note text);
         GRANT INSERT ON e2e_write_reader_rows TO dbvalet_reader, e2e_write_reader_group;",
    );

    let output = run_as(
        &dir,
        "reader",
        "psql -v ON_ERROR_STOP=1 -qc \"INSERT INTO e2e_write_reader_rows VALUES ('written')\"",
    );

    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("cannot execute INSERT in a read-only transaction"),
        "stderr: {}",
        text(&output.stderr)
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM e2e_write_reader_rows WHERE note = $1",
            "written"
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_write_run_that_creates_a_table_leaves_it_owned_by_the_group_role_and_no_login() {
    let dir = project_with_writer(
        "e2e-write-table",
        "e2e_write_table_group",
        "WITH ADMIN OPTION",
    );

    let output = run_as(
        &dir,
        "writer",
        "echo \"login=$PGUSER\"; \
         psql -v ON_ERROR_STOP=1 -qc 'CREATE TABLE e2e_write_table_group.created (id int)'",
    );

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    // PostgreSQL 19 warns on stderr about the temporary login's short VALID UNTIL expiry;
    // a teardown failure from dbvalet itself is prefixed with `dbvalet:`.
    assert!(!stderr.contains("dbvalet:"), "stderr: {stderr}");
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            printed(&stdout, "login")
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_tables
             WHERE schemaname = 'e2e_write_table_group' AND tablename = 'created'
               AND tableowner = $1",
            "e2e_write_table_group"
        ),
        1
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_killed_write_run_that_created_a_table_is_swept_without_error() {
    let dir = project_with_writer(
        "e2e-write-killed",
        "e2e_write_killed_group",
        "WITH ADMIN OPTION",
    );
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--role", "writer"],
        "echo \"login=$PGUSER\"; \
         psql -v ON_ERROR_STOP=1 -qc 'CREATE TABLE e2e_write_killed_group.created (id int)'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let swept = gc_in(&dir);
    drop(run.stdin.take());

    let stderr = text(&swept.stderr);
    assert!(swept.status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(
        text(&swept.stdout).contains(&format!(
            "`e2e-write-killed`: dropped the leftover login `{login_name}`\n"
        )),
        "stdout: {}",
        text(&swept.stdout)
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
            "SELECT count(*) FROM pg_tables
             WHERE schemaname = 'e2e_write_killed_group' AND tablename = 'created'
               AND tableowner = $1",
            "e2e_write_killed_group"
        ),
        1
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_without_the_ledger_keeps_the_table_of_a_write_login_that_set_itself_read_only() {
    let dir = project_with_writer(
        "e2e-write-ledgerless",
        "e2e_write_ledgerless_group",
        "WITH ADMIN OPTION",
    );
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qc \
         'CREATE TABLE e2e_write_ledgerless_group.kept (id int)' \
         -c 'ALTER ROLE CURRENT_USER SET default_transaction_read_only = on'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    // Another machine's sweep, with no ledger entry for the login.
    let swept = gc_command(&dir)
        .env("XDG_STATE_HOME", dir.join("other-machine-state"))
        .output()
        .unwrap();
    drop(alone);
    drop(run.stdin.take());

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &login_name
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_tables
             WHERE schemaname = 'e2e_write_ledgerless_group' AND tablename = 'kept'
               AND tableowner = $1",
            "e2e_write_ledgerless_group"
        ),
        1
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_without_the_ledger_drops_a_reader_login_whose_admin_lacks_set_on_the_reader_group() {
    if server_version_num() < 160000 {
        return;
    }
    let dir = project_with_writer(
        "e2e-write-ledgerless-reader",
        "e2e_write_ledgerless_reader_group",
        "WITH ADMIN OPTION",
    );
    superuser_sql("GRANT dbvalet_reader TO e2e_write_ledgerless_reader WITH SET FALSE;");
    let (mut run, seen) = start_run_until_ready(&dir, &[], "echo \"login=$PGUSER\"");
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept = gc_command(&dir)
        .env("XDG_STATE_HOME", dir.join("other-machine-state"))
        .output()
        .unwrap();
    drop(alone);
    drop(run.stdin.take());

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
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
fn a_write_run_whose_admin_lacks_set_on_postgresql_16_or_later_is_refused_before_any_login() {
    if server_version_num() < 160000 {
        return;
    }
    let dir = project_with_writer(
        "e2e-write-refused-no-set",
        "e2e_write_refused_no_set_group",
        "WITH ADMIN TRUE, SET FALSE",
    );

    let output = run_as(&dir, "writer", "echo CHILD_RAN");

    let stderr = text(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(text(&output.stdout).is_empty(), "the child must not run");
    assert!(
        stderr.contains(
            "the admin login `e2e_write_refused_no_set` lacks SET on group role \
             `e2e_write_refused_no_set_group`"
        ),
        "stderr: {stderr}"
    );
    assert_eq!(logins_in_group("e2e_write_refused_no_set_group"), 0);
    assert!(ledger_entries_in(&dir).is_empty());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_write_run_by_a_createrole_admin_outside_the_group_on_postgresql_15_still_hands_over_its_table()
{
    if server_version_num() >= 160000 {
        return;
    }
    let dir = project_with_writer(
        "e2e-write-outside-15",
        "e2e_write_outside_15_group",
        "WITH ADMIN OPTION",
    );
    superuser_sql("REVOKE e2e_write_outside_15_group FROM e2e_write_outside_15;");

    let output = run_as(
        &dir,
        "writer",
        "echo \"login=$PGUSER\"; \
         psql -v ON_ERROR_STOP=1 -qc 'CREATE TABLE e2e_write_outside_15_group.created (id int)'",
    );

    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(!stderr.contains("dbvalet:"), "stderr: {stderr}");
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            printed(&stdout, "login")
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_tables
             WHERE schemaname = 'e2e_write_outside_15_group' AND tablename = 'created'
               AND tableowner = $1",
            "e2e_write_outside_15_group"
        ),
        1
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_passes_a_createrole_admin_holding_everything_both_configured_groups_need() {
    let dir = project_with_writer(
        "e2e-write-doctor-ok",
        "e2e_write_doctor_ok_group",
        "WITH ADMIN OPTION",
    );

    let checked = doctor_in(&dir, "e2e-write-doctor-ok");

    let stdout = text(&checked.stdout);
    assert!(checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains(
            "ok   `e2e_write_doctor_ok` holds ADMIN on role `reader` (`dbvalet_reader`)\n"
        ),
        "doctor: {stdout}"
    );
    assert!(
        stdout.contains(
            "ok   `e2e_write_doctor_ok` holds ADMIN on role `writer` (`e2e_write_doctor_ok_group`)\n"
        ),
        "doctor: {stdout}"
    );
    assert!(!stdout.contains("FAIL"), "doctor: {stdout}");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_names_a_configured_group_role_the_admin_holds_without_admin() {
    let dir = project_with_writer("e2e-write-doctor-no-admin", "e2e_write_no_admin_group", "");

    let checked = doctor_in(&dir, "e2e-write-doctor-no-admin");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains(
            "FAIL `e2e_write_doctor_no_admin` doesn't hold ADMIN on role `writer` \
             (`e2e_write_no_admin_group`): as a superuser, run \
             GRANT \"e2e_write_no_admin_group\" TO \"e2e_write_doctor_no_admin\" \
             WITH ADMIN OPTION\n"
        ),
        "doctor: {stdout}"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn doctor_on_postgresql_16_or_later_names_the_write_group_held_without_set_and_not_the_reader() {
    if server_version_num() < 160000 {
        return;
    }
    let dir = project_with_writer(
        "e2e-write-doctor-no-set",
        "e2e_write_no_set_group",
        "WITH ADMIN TRUE, SET FALSE",
    );
    superuser_sql("GRANT dbvalet_reader TO e2e_write_doctor_no_set WITH SET FALSE;");

    let checked = doctor_in(&dir, "e2e-write-doctor-no-set");

    let stdout = text(&checked.stdout);
    assert!(!checked.status.success(), "doctor: {stdout}");
    assert!(
        stdout.contains(
            "FAIL `e2e_write_doctor_no_set` lacks SET on `e2e_write_no_set_group`, \
             which PostgreSQL 16.16, 17.12, 18.7 and later need to hand what role `writer`'s \
             logins create to it: as a superuser, run \
             GRANT \"e2e_write_no_set_group\" TO \"e2e_write_doctor_no_set\" WITH SET TRUE\n"
        ),
        "doctor: {stdout}"
    );
    assert_eq!(stdout.matches("FAIL").count(), 1, "doctor: {stdout}");
}
