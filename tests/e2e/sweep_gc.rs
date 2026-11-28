//! The ledger, the sweep and `dbvalet gc` after a crash.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::support::{
    DBVALET, SUPERUSER_URL, gc_command, gc_in, ledger_entry, login, output_within, printed,
    project_with_reader, project_with_reader_and_admin, run_command, run_in, runtime,
    start_run_until_ready, superuser_count, superuser_sql, sweeping, sweeping_alone, text,
    wait_for_active_query,
};

/// A NOLOGIN group for a writable `writer` role, owning a schema of the same name, so tests
/// running in parallel never change the same schema's privileges at once.
fn create_writer_group(group: &str) {
    superuser_sql(&format!(
        "DO $$ BEGIN
             CREATE ROLE {group} NOLOGIN;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
         END $$;
         CREATE SCHEMA IF NOT EXISTS {group} AUTHORIZATION {group};"
    ));
}

/// Starts a run in `dir` whose child keeps a `pg_sleep` query running through the proxy and
/// then waits on stdin. Returns once the query runs, with the run and its login name.
fn start_run_with_busy_session(dir: &Path) -> (Child, String) {
    let sweeping = sweeping();
    let mut run = Command::new(DBVALET)
        .current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--", "sh", "-c"])
        .arg(
            "echo \"login=$PGUSER\"; \
             psql -qAtXc 'SELECT pg_sleep(60)' >/dev/null 2>&1 & read line",
        )
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
    drop(sweeping);
    wait_for_active_query(&login_name);
    (run, login_name)
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_killed_run_leaves_no_login_or_session_after_gc() {
    let dir = project_with_reader("e2e-gc-after-kill");
    let (mut run, login_name) = start_run_with_busy_session(&dir);

    run.kill().unwrap();
    run.wait().unwrap();
    let swept = gc_in(&dir);
    // The orphaned child exits once its stdin closes.
    drop(run.stdin.take());

    let stdout = text(&swept.stdout);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(
        stdout.contains(&format!(
            "`e2e-gc-after-kill`: dropped the leftover login `{login_name}`\n"
        )),
        "{stdout}"
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
fn a_killed_run_leaves_no_login_or_session_after_the_next_run() {
    let dir = project_with_reader("e2e-run-after-kill");
    let (mut run, first_login) = start_run_with_busy_session(&dir);

    run.kill().unwrap();
    run.wait().unwrap();
    let next = run_in(&dir, &["sh", "-c", "echo next"]);
    drop(run.stdin.take());

    assert!(next.status.success(), "stderr: {}", text(&next.stderr));
    assert_eq!(text(&next.stdout), "next\n");
    assert_eq!(text(&next.stderr), "");
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            &first_login
        ),
        0
    );
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
            &first_login
        ),
        0
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_while_another_run_is_live_leaves_its_login_and_session_alone() {
    let dir = project_with_reader("e2e-gc-live-run");
    let (mut run, login_name) = start_run_with_busy_session(&dir);

    let swept = gc_in(&dir);
    let logins_after_gc = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let sessions_after_gc = superuser_count(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
        &login_name,
    );
    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let finished = run.wait_with_output().unwrap();

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!text(&swept.stdout).contains(&login_name));
    assert_eq!(logins_after_gc, 1);
    assert_eq!(sessions_after_gc, 1);
    assert!(
        finished.status.success(),
        "stderr: {}",
        text(&finished.stderr)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_never_touches_dbvalet_reader_or_another_group_role() {
    let dir = project_with_reader("e2e-gc-group-roles");
    superuser_sql(
        "DROP ROLE IF EXISTS dbvalet_grouproleexpired;
         CREATE ROLE dbvalet_grouproleexpired NOLOGIN VALID UNTIL '2000-01-01';",
    );
    let reader_entry = ledger_entry(&dir, "e2e-gc-group-roles", "dbvalet_reader");
    let group_entry = ledger_entry(&dir, "e2e-gc-group-roles", "dbvalet_grouproleexpired");
    std::fs::create_dir_all(reader_entry.parent().unwrap()).unwrap();
    std::fs::write(&reader_entry, "writable\n").unwrap();
    std::fs::write(&group_entry, "writable\n").unwrap();

    let swept = gc_in(&dir);
    let readers = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        "dbvalet_reader",
    );
    let groups = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        "dbvalet_grouproleexpired",
    );
    superuser_sql("DROP ROLE dbvalet_grouproleexpired;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(readers, 1);
    assert_eq!(groups, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_ledger_entry_whose_login_was_never_created_is_removed_by_gc() {
    let dir = project_with_reader("e2e-gc-never-created");
    superuser_sql("DROP ROLE IF EXISTS dbvalet_nevercreatedrole;");
    let entry = ledger_entry(&dir, "e2e-gc-never-created", "dbvalet_nevercreatedrole");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    // From outside any project, so gc finds the alias through the ledger alone.
    let _sweeping = sweeping();
    let swept = Command::new(DBVALET)
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["gc", "--allow-plaintext"])
        .output()
        .unwrap();

    let stdout = text(&swept.stdout);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(text(&swept.stderr), "");
    assert!(
        stdout.contains(
            "`e2e-gc-never-created`: removed the ledger entry for `dbvalet_nevercreatedrole`, \
             whose login was already gone\n"
        ),
        "{stdout}"
    );
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_keeps_the_ledger_until_the_creation_transaction_finishes() {
    let dir = project_with_reader("e2e-gc-unsettled-creation");
    let _sweeping = sweeping();
    let login = "dbvalet_pendingcreationa";
    superuser_sql("DROP ROLE IF EXISTS dbvalet_pendingcreationa;");
    let rt = runtime();
    let creator = rt.block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute("BEGIN").await.unwrap();
        client
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&login],
            )
            .await
            .unwrap();
        client
    });
    let entry = ledger_entry(&dir, "e2e-gc-unsettled-creation", login);
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    let swept = gc_command(&dir).output().unwrap();
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(entry.exists());

    rt.block_on(creator.batch_execute("ROLLBACK")).unwrap();
    let swept = gc_command(&dir).output().unwrap();
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_without_a_ledger_entry_gives_an_expired_read_only_logins_table_to_its_group() {
    let dir = project_with_reader("e2e-gc-expired-read-only");
    let _alone = sweeping_alone();
    // The read-only setting is the login's own word, which a sweep can't trust without the ledger.
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_gc_read_only_table;
         DROP ROLE IF EXISTS dbvalet_readonlyexpired2;
         CREATE ROLE dbvalet_readonlyexpired2 LOGIN VALID UNTIL '2000-01-01' IN ROLE dbvalet_reader;
         ALTER ROLE dbvalet_readonlyexpired2 SET default_transaction_read_only = on;
         CREATE TABLE e2e_gc_read_only_table ();
         ALTER TABLE e2e_gc_read_only_table OWNER TO dbvalet_readonlyexpired2;",
    );

    let swept = gc_command(&dir).output().unwrap();
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_read_only_table' AND tableowner = $1",
        "dbvalet_reader",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_read_only_table;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            "dbvalet_readonlyexpired2"
        ),
        0
    );
    assert_eq!(owned_by_group, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_drops_an_expired_writable_login_and_gives_its_table_to_the_group_role() {
    let dir = project_with_reader("e2e-gc-expired-writable");
    let _alone = sweeping_alone();
    superuser_sql(
        "DROP TABLE IF EXISTS e2e_gc_writable_table;
         DROP ROLE IF EXISTS dbvalet_writableexpired2;
         DROP ROLE IF EXISTS e2e_gc_writer_group;
         CREATE ROLE e2e_gc_writer_group NOLOGIN;
         CREATE ROLE dbvalet_writableexpired2 LOGIN VALID UNTIL '2000-01-01'
             IN ROLE e2e_gc_writer_group;
         CREATE TABLE e2e_gc_writable_table ();
         ALTER TABLE e2e_gc_writable_table OWNER TO dbvalet_writableexpired2;",
    );

    let swept = gc_command(&dir).output().unwrap();
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_writable_table' AND tableowner = $1",
        "e2e_gc_writer_group",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_writable_table;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(
        superuser_count(
            "SELECT count(*) FROM pg_roles WHERE rolname = $1",
            "dbvalet_writableexpired2"
        ),
        0
    );
    assert_eq!(owned_by_group, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_createrole_admin_drops_the_login_while_its_query_is_still_running() {
    let dir = project_with_reader_and_admin("e2e-run-createrole-busy", "CREATEROLE");
    let (mut run, login_name) = start_run_with_busy_session(&dir);

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();

    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
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
fn a_run_whose_login_a_sweep_already_dropped_ends_without_an_error() {
    let dir = project_with_reader("e2e-run-swept-early");
    let (mut run, login_name) = start_run_with_busy_session(&dir);
    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    // Another machine's sweep: it has no ledger entry for the login, so it drops it.
    let swept = gc_command(&dir)
        .env("XDG_STATE_HOME", dir.join("other-machine-state"))
        .output()
        .unwrap();
    drop(alone);

    run.stdin.take().unwrap().write_all(b"\n").unwrap();
    let output = run.wait_with_output().unwrap();

    let stderr = text(&output.stderr);
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(
        text(&swept.stdout).contains(&format!("dropped the leftover login `{login_name}`")),
        "stdout: {}",
        text(&swept.stdout)
    );
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
    assert!(!ledger_entry(&dir, "e2e-run-swept-early", &login_name).exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_corrupt_ledger_entry_or_a_stray_directory_does_not_stop_gc() {
    let dir = project_with_reader("e2e-gc-corrupt-ledger");
    superuser_sql("DROP ROLE IF EXISTS dbvalet_corruptledgerent;");
    let corrupt = ledger_entry(&dir, "e2e-gc-corrupt-ledger", "dbvalet_corruptledgerent");
    let stray = ledger_entry(&dir, "e2e-gc-corrupt-ledger", "stray");
    std::fs::create_dir_all(&stray).unwrap();
    std::fs::write(&corrupt, b"\xff\xfe").unwrap();

    let swept = gc_in(&dir);

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert!(!corrupt.exists());
    assert!(stray.is_dir());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn gc_with_a_closed_stdout_still_sweeps_every_database() {
    let dir = project_with_reader("e2e-gc-closed-stdout-a");
    project_with_reader("e2e-gc-closed-stdout-b");
    superuser_sql(
        "DROP ROLE IF EXISTS dbvalet_closedstdoutaaaa;
         DROP ROLE IF EXISTS dbvalet_closedstdoutbbbb;",
    );
    let entry_a = ledger_entry(&dir, "e2e-gc-closed-stdout-a", "dbvalet_closedstdoutaaaa");
    let entry_b = ledger_entry(&dir, "e2e-gc-closed-stdout-b", "dbvalet_closedstdoutbbbb");
    std::fs::create_dir_all(entry_a.parent().unwrap()).unwrap();
    std::fs::write(&entry_a, "read-only\n").unwrap();
    std::fs::write(&entry_b, "read-only\n").unwrap();
    let (closed_stdout, stdout) = std::io::pipe().unwrap();
    drop(closed_stdout);

    let _sweeping = sweeping();
    let swept = Command::new(DBVALET)
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["gc", "--allow-plaintext"])
        .stdout(stdout)
        .output()
        .unwrap();

    assert_eq!(
        swept.status.code(),
        Some(0),
        "stderr: {}",
        text(&swept.stderr)
    );
    assert!(!entry_a.exists());
    assert!(!entry_b.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_unreadable_ledger_entry_is_reported_and_the_run_still_runs() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project_with_reader("e2e-run-unreadable-entry");
    superuser_sql("DROP ROLE IF EXISTS dbvalet_unreadablebeside;");
    let entry = ledger_entry(&dir, "e2e-run-unreadable-entry", "dbvalet_unreadableentryz");
    let beside = ledger_entry(&dir, "e2e-run-unreadable-entry", "dbvalet_unreadablebeside");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();
    std::fs::write(&beside, "read-only\n").unwrap();
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o000)).unwrap();

    let output = run_in(&dir, &["sh", "-c", "echo ran"]);
    std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&entry).unwrap();

    let stderr = text(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert_eq!(text(&output.stdout), "ran\n");
    assert!(
        stderr.contains("couldn't read the ledger entry")
            && stderr.contains("dbvalet_unreadableentryz"),
        "stderr: {stderr}"
    );
    assert!(!beside.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn files_in_the_ledger_that_arent_login_entries_are_never_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project_with_reader("e2e-gc-stray-files");
    let ledger = dir.join("state/dbvalet/ledger");
    let stray = ledger.join("e2e-gc-stray-files.stray");
    std::fs::create_dir_all(&ledger).unwrap();
    std::fs::write(ledger.join("README.md"), "notes\n").unwrap();
    std::fs::write(&stray, "x\n").unwrap();
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o000)).unwrap();

    let swept = gc_in(&dir);
    std::fs::set_permissions(&stray, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(text(&swept.stderr), "");
    assert_eq!(
        text(&swept.stdout),
        "`e2e-gc-stray-files`: nothing to clean up\n"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_expired_read_only_login_found_through_another_alias_still_has_its_objects_dropped() {
    let dir = project_with_reader("e2e-gc-two-aliases-a");
    project_with_reader("e2e-gc-two-aliases-z");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-two-aliases-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-two-aliases-z.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    // The login clears its own read-only default, so only the ledger still says read-only.
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--db", "e2e-gc-two-aliases-z"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtX \
         -c 'SET default_transaction_read_only = off' \
         -c 'ALTER ROLE current_user RESET default_transaction_read_only' \
         -c \"SELECT 'oid=' || lo_from_bytea(0, 'from a read-only run')\"",
    );
    let login_name = printed(&seen, "login").to_owned();
    let oid: u32 = printed(&seen, "oid").parse().unwrap();
    run.kill().unwrap();
    run.wait().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept = gc_command(&dir).output().unwrap();
    drop(alone);
    drop(run.stdin.take());

    let large_objects: i64 = runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
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
    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(large_objects, 0, "large object {oid} survived the sweep");
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
fn a_sweep_leaves_an_expired_login_alone_while_another_process_holds_its_ledger_entry() {
    let dir = project_with_reader("e2e-gc-held-entry");
    let (mut run, seen) = start_run_until_ready(&dir, &[], "echo \"login=$PGUSER\"");
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();
    let held = std::fs::File::open(ledger_entry(&dir, "e2e-gc-held-entry", &login_name)).unwrap();
    held.lock().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept_while_held = gc_command(&dir).output().unwrap();
    let logins_while_held = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    drop(held);
    let swept_after = gc_command(&dir).output().unwrap();
    drop(alone);
    drop(run.stdin.take());

    assert!(
        swept_while_held.status.success(),
        "stderr: {}",
        text(&swept_while_held.stderr)
    );
    assert_eq!(logins_while_held, 1);
    assert!(
        text(&swept_after.stdout).contains(&format!("dropped the leftover login `{login_name}`")),
        "stdout: {}",
        text(&swept_after.stdout)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_lock_on_a_table_the_crashed_login_owns_fails_that_drop_without_stopping_gc_or_run() {
    create_writer_group("e2e_gc_locked_writer");
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_locked_writer.e2e_gc_locked_table;");
    let dir = project_with_reader("e2e-gc-locked-table");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-locked-table.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         writer = { member_of = \"e2e_gc_locked_writer\", read_only = false }\n",
    )
    .unwrap();
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtXc 'CREATE TABLE e2e_gc_locked_writer.e2e_gc_locked_table ()'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();
    superuser_sql("DROP ROLE IF EXISTS dbvalet_lockedtablenext2;");
    let beside = ledger_entry(&dir, "e2e-gc-locked-table", "dbvalet_lockedtablenext2");
    std::fs::write(&beside, "read-only\n").unwrap();
    let lock_holder = runtime();
    let holding = lock_holder.block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .batch_execute(
                "BEGIN; LOCK TABLE e2e_gc_locked_writer.e2e_gc_locked_table IN ACCESS SHARE MODE;",
            )
            .await
            .unwrap();
        client
    });

    let sweeping = sweeping();
    let swept = output_within(gc_command(&dir), Duration::from_secs(60));
    let next = output_within(
        run_command(&dir, &["sh", "-c", "echo ran"]),
        Duration::from_secs(60),
    );
    let logins_while_locked = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    let beside_after_first_gc = beside.exists();
    drop(holding);
    drop(lock_holder);
    let swept_after = output_within(gc_command(&dir), Duration::from_secs(60));
    drop(sweeping);
    drop(run.stdin.take());
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_locked_table' AND tableowner = $1",
        "e2e_gc_locked_writer",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_locked_writer.e2e_gc_locked_table;");

    let stderr = text(&swept.stderr);
    assert_eq!(swept.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains(&login_name) && stderr.contains("lock timeout"),
        "stderr: {stderr}"
    );
    assert!(next.status.success(), "stderr: {}", text(&next.stderr));
    assert_eq!(text(&next.stdout), "ran\n");
    assert_eq!(logins_while_locked, 1);
    assert!(!beside_after_first_gc);
    assert!(
        swept_after.status.success(),
        "stderr: {}",
        text(&swept_after.stderr)
    );
    assert_eq!(owned_by_group, 1);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_admin_endpoint_that_never_answers_is_reported_and_gc_sweeps_the_next_database() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    std::thread::spawn(move || silent.incoming().collect::<Vec<_>>());
    let stored = login(
        "e2e-gc-stall-a",
        &format!("postgresql://e2e_stall:pw-e2e-stall@127.0.0.1:{port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = project_with_reader("e2e-gc-stall-b");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-stall-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-stall-b.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    superuser_sql("DROP ROLE IF EXISTS dbvalet_stalledendpoint2;");
    let entry = ledger_entry(&dir, "e2e-gc-stall-b", "dbvalet_stalledendpoint2");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    let _sweeping = sweeping();
    let swept = output_within(gc_command(&dir), Duration::from_secs(60));

    let stderr = text(&swept.stderr);
    assert_eq!(swept.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("`e2e-gc-stall-a`"), "stderr: {stderr}");
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_writable_login_that_set_itself_read_only_keeps_its_table_after_a_crash() {
    create_writer_group("e2e_gc_self_read_only_writer");
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_self_read_only_writer.e2e_gc_self_read_only_table;");
    let dir = project_with_reader("e2e-gc-self-read-only");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-self-read-only.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         writer = { member_of = \"e2e_gc_self_read_only_writer\", read_only = false }\n",
    )
    .unwrap();
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtX \
         -c 'CREATE TABLE e2e_gc_self_read_only_writer.e2e_gc_self_read_only_table ()' \
         -c 'ALTER ROLE CURRENT_USER SET default_transaction_read_only = on'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let swept = gc_in(&dir);
    drop(run.stdin.take());
    let owned_by_group = superuser_count(
        "SELECT count(*) FROM pg_tables
         WHERE tablename = 'e2e_gc_self_read_only_table' AND tableowner = $1",
        "e2e_gc_self_read_only_writer",
    );
    superuser_sql("DROP TABLE IF EXISTS e2e_gc_self_read_only_writer.e2e_gc_self_read_only_table;");

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(owned_by_group, 1);
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
fn an_expired_login_owning_a_table_in_another_database_is_left_to_that_databases_sweep() {
    let other_db_url = "postgresql://postgres:e2e-throwaway@localhost:5432/e2e_gc_other_db";
    if superuser_count(
        "SELECT count(*) FROM pg_database WHERE datname = $1",
        "e2e_gc_other_db",
    ) == 0
    {
        superuser_sql("CREATE DATABASE e2e_gc_other_db;");
    }
    create_writer_group("e2e_gc_other_writer");
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(other_db_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .batch_execute(
                "CREATE SCHEMA IF NOT EXISTS e2e_gc_other_writer AUTHORIZATION e2e_gc_other_writer;
                 DROP TABLE IF EXISTS e2e_gc_other_writer.e2e_gc_other_table;",
            )
            .await
            .unwrap();
    });
    let dir = project_with_reader("e2e-gc-other-db-a");
    superuser_sql(
        "DROP ROLE IF EXISTS e2e_gc_other_db_z;
         CREATE ROLE e2e_gc_other_db_z LOGIN SUPERUSER PASSWORD 'pw-e2e-gc-other-db-z';",
    );
    let stored = login(
        "e2e-gc-other-db-z",
        "postgresql://e2e_gc_other_db_z:pw-e2e-gc-other-db-z@localhost:5432/e2e_gc_other_db",
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-other-db-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-other-db-z.roles]\n\
         writer = { member_of = \"e2e_gc_other_writer\", read_only = false }\n",
    )
    .unwrap();
    let (mut run, seen) = start_run_until_ready(
        &dir,
        &["--db", "e2e-gc-other-db-z", "--role", "writer"],
        "echo \"login=$PGUSER\"; psql -v ON_ERROR_STOP=1 -qAtXc \
         'CREATE TABLE e2e_gc_other_writer.e2e_gc_other_table ()'",
    );
    let login_name = printed(&seen, "login").to_owned();
    run.kill().unwrap();
    run.wait().unwrap();

    let alone = sweeping_alone();
    superuser_sql(&format!(
        "ALTER ROLE {login_name} VALID UNTIL '2000-01-01';"
    ));
    let swept = gc_command(&dir).output().unwrap();
    drop(alone);
    drop(run.stdin.take());
    let owned_by_group: i64 = runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(other_db_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
            .query_one(
                "SELECT count(*) FROM pg_tables
                 WHERE tablename = 'e2e_gc_other_table' AND tableowner = 'e2e_gc_other_writer'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    });

    assert!(swept.status.success(), "stderr: {}", text(&swept.stderr));
    assert_eq!(text(&swept.stderr), "");
    assert!(
        text(&swept.stdout).contains(&format!(
            "`e2e-gc-other-db-z`: dropped the leftover login `{login_name}`"
        )),
        "stdout: {}",
        text(&swept.stdout)
    );
    assert_eq!(owned_by_group, 1);
}

/// A server on 127.0.0.1 that lets every client log in, then never answers a query.
fn silent_after_login_server() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut length = [0; 4];
            stream.read_exact(&mut length).unwrap();
            let mut startup = vec![0; u32::from_be_bytes(length) as usize - 4];
            stream.read_exact(&mut startup).unwrap();
            // AuthenticationOk, then ReadyForQuery with an idle transaction status.
            stream
                .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'])
                .unwrap();
            held.push(stream);
        }
    });
    port
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn an_admin_endpoint_that_logs_in_and_then_never_answers_is_reported_and_gc_moves_on() {
    let port = silent_after_login_server();
    let stored = login(
        "e2e-gc-silent-after-login-a",
        &format!("postgresql://e2e_silent:pw-e2e-silent@127.0.0.1:{port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = project_with_reader("e2e-gc-silent-after-login-b");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-silent-after-login-a.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-silent-after-login-b.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    superuser_sql("DROP ROLE IF EXISTS dbvalet_silentafterlogin;");
    let entry = ledger_entry(
        &dir,
        "e2e-gc-silent-after-login-b",
        "dbvalet_silentafterlogin",
    );
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(&entry, "read-only\n").unwrap();

    let _sweeping = sweeping();
    let swept = output_within(gc_command(&dir), Duration::from_secs(60));

    let stderr = text(&swept.stderr);
    assert_eq!(swept.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("`e2e-gc-silent-after-login-a`"),
        "stderr: {stderr}"
    );
    assert!(!entry.exists());
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_sweep_of_another_database_never_holds_this_databases_ledger_entries() {
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    let (accepted, connected) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in silent.incoming() {
            held.push(stream);
            let _ = accepted.send(());
        }
    });
    let stored = login(
        "e2e-gc-hold-x",
        &format!("postgresql://e2e_hold:pw-e2e-hold@127.0.0.1:{port}/postgres"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = project_with_reader("e2e-gc-hold-z");
    std::fs::write(
        dir.join("dbvalet.toml"),
        "[databases.e2e-gc-hold-x.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n\
         [databases.e2e-gc-hold-z.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n",
    )
    .unwrap();
    let (mut crashed, seen) =
        start_run_until_ready(&dir, &["--db", "e2e-gc-hold-z"], "echo \"login=$PGUSER\"");
    let login_name = printed(&seen, "login").to_owned();
    crashed.kill().unwrap();
    crashed.wait().unwrap();

    let _sweeping = sweeping();
    // A run on the other database, stuck connecting while its sweep has begun.
    let mut stuck = Command::new(DBVALET)
        .current_dir(&dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args([
            "run",
            "--db",
            "e2e-gc-hold-x",
            "--allow-plaintext",
            "--",
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    connected.recv_timeout(Duration::from_secs(10)).unwrap();
    let next = output_within(
        {
            let mut next = Command::new(DBVALET);
            next.current_dir(&dir)
                .env("XDG_STATE_HOME", dir.join("state"))
                .args([
                    "run",
                    "--db",
                    "e2e-gc-hold-z",
                    "--allow-plaintext",
                    "--",
                    "true",
                ]);
            next
        },
        Duration::from_secs(60),
    );
    let stuck_while_next_ran = stuck.try_wait().unwrap().is_none();
    let logins_after_next = superuser_count(
        "SELECT count(*) FROM pg_roles WHERE rolname = $1",
        &login_name,
    );
    stuck.kill().unwrap();
    stuck.wait().unwrap();
    drop(crashed.stdin.take());

    assert!(next.status.success(), "stderr: {}", text(&next.stderr));
    assert!(
        stuck_while_next_ran,
        "the stuck run ended before the next run did"
    );
    assert_eq!(logins_after_next, 0);
}
