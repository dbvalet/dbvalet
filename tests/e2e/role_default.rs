//! Teardown and `dbvalet gc` for an admin login whose connections switch to another role
//! (`ALTER ROLE <admin> SET role = ...`), so its effective role isn't the connection string's.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::support::{
    DBVALET, create_reader_group, gc_command, ledger_entry, login, output_within, printed,
    superuser_count, superuser_sql, sweeping, text,
};

/// Long enough for a run's mint and teardown on a loaded CI runner.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// Stores the admin login `<alias>` (with `-` as `_`), whose connections switch to the
/// CREATEROLE role `<admin>_provisioner`. That role holds ADMIN on `dbvalet_reader` and on the
/// writer group `<admin>_group`, which owns a schema of its own name. `dbvalet.toml` lists a
/// read-only `reader` and a writable `writer` role.
fn project_with_role_default(alias: &str) -> PathBuf {
    create_reader_group();
    let admin = alias.replace('-', "_");
    superuser_sql(&format!(
        "DROP SCHEMA IF EXISTS {admin}_group CASCADE;
         DROP ROLE IF EXISTS {admin};
         DROP ROLE IF EXISTS {admin}_provisioner;
         DROP ROLE IF EXISTS {admin}_group;
         CREATE ROLE {admin}_provisioner NOLOGIN CREATEROLE;
         CREATE ROLE {admin} LOGIN PASSWORD 'pw-{alias}-admin';
         GRANT {admin}_provisioner TO {admin};
         ALTER ROLE {admin} SET role = '{admin}_provisioner';
         GRANT dbvalet_reader TO {admin}_provisioner WITH ADMIN OPTION;
         CREATE ROLE {admin}_group NOLOGIN;
         CREATE SCHEMA {admin}_group AUTHORIZATION {admin}_group;
         GRANT {admin}_group TO {admin}_provisioner WITH ADMIN OPTION;"
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
             reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n\
             writer = {{ member_of = \"{admin}_group\", read_only = false }}\n"
        ),
    )
    .unwrap();
    dir
}

fn run_command_as(dir: &Path, role: &str, script: &str) -> Command {
    let mut run = Command::new(DBVALET);
    run.current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--role", role, "--allow-plaintext", "--", "sh", "-c"])
        .arg(script);
    run
}

fn logins_named(login: &str) -> i64 {
    superuser_count("SELECT count(*) FROM pg_roles WHERE rolname = $1", login)
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_read_only_run_by_an_admin_with_a_role_default_drops_its_login_and_its_large_object() {
    let dir = project_with_role_default("e2e-rd-reader");

    let out = {
        let _sweeping = sweeping();
        // PostgreSQL 16 and later refuse lo_from_bytea in a read-only transaction; 15 lets
        // the login own a large object, which its teardown must drop rather than hand over.
        output_within(
            run_command_as(
                &dir,
                "reader",
                "echo login=$PGUSER; \
                 psql -qAtXc \"SELECT lo_from_bytea(0, 'written by e2e-rd-reader')\" \
                 || echo refused",
            ),
            RUN_LIMIT,
        )
    };

    let stdout = text(&out.stdout);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let login_name = printed(&stdout, "login");
    assert_eq!(logins_named(login_name), 0);
    assert!(!ledger_entry(&dir, "e2e-rd-reader", login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_largeobject WHERE data = convert_to($1, 'UTF8')",
            "written by e2e-rd-reader"
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_write_run_by_an_admin_with_a_role_default_drops_its_login_and_hands_its_table_to_the_group() {
    let dir = project_with_role_default("e2e-rd-writer");

    let out = {
        let _sweeping = sweeping();
        output_within(
            run_command_as(
                &dir,
                "writer",
                "echo login=$PGUSER; \
                 psql -v ON_ERROR_STOP=1 -qAtXc 'CREATE TABLE e2e_rd_writer_group.made (id int)'",
            ),
            RUN_LIMIT,
        )
    };

    let stdout = text(&out.stdout);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let login_name = printed(&stdout, "login");
    assert_eq!(logins_named(login_name), 0);
    assert!(!ledger_entry(&dir, "e2e-rd-writer", login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_tables
             WHERE schemaname = $1 AND tablename = 'made' AND tableowner = $1",
            "e2e_rd_writer_group"
        ),
        1
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_after_a_killed_write_run_by_an_admin_with_a_role_default_drops_its_login() {
    let dir = project_with_role_default("e2e-rd-killed");

    let (killed, swept) = {
        let _sweeping = sweeping();
        // The child kills dbvalet itself, so the run ends without its teardown.
        let killed = output_within(
            run_command_as(
                &dir,
                "writer",
                "echo login=$PGUSER; \
                 psql -v ON_ERROR_STOP=1 -qAtXc 'CREATE TABLE e2e_rd_killed_group.made (id int)' \
                 && kill -9 $PPID",
            ),
            RUN_LIMIT,
        );
        (killed, output_within(gc_command(&dir), RUN_LIMIT))
    };

    let killed_stdout = text(&killed.stdout);
    let login_name = printed(&killed_stdout, "login");
    assert_eq!(killed.status.code(), None, "the run wasn't killed");
    let stdout = text(&swept.stdout);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(
        stdout.contains(&format!(
            "`e2e-rd-killed`: dropped the leftover login `{login_name}`\n"
        )),
        "{stdout}"
    );
    assert_eq!(logins_named(login_name), 0);
    assert!(!ledger_entry(&dir, "e2e-rd-killed", login_name).exists());
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_tables
             WHERE schemaname = $1 AND tablename = 'made' AND tableowner = $1",
            "e2e_rd_killed_group"
        ),
        1
    );
}
