//! `dbvalet init`: the read-only group role, its grants and `dbvalet.toml`.
//!
//! Each test has its own database, owned by its own admin, so their grants don't mix.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use crate::support::{
    DBVALET, create_reader_group, login, run_in, runtime, server_version_num, superuser_sql, text,
};

/// Creates the login `name` with `attributes`, a database `name` it owns that PUBLIC can't
/// connect to, and a project directory without `dbvalet.toml`, and stores the login under the
/// alias `name`.
fn admin_with_own_database(name: &str, attributes: &str) -> PathBuf {
    superuser_sql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"));
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {name};
         CREATE ROLE {name} LOGIN {attributes} PASSWORD 'pw-{name}';"
    ));
    superuser_sql(&format!("CREATE DATABASE {name} OWNER {name}"));
    superuser_sql(&format!("REVOKE CONNECT ON DATABASE {name} FROM PUBLIC"));
    let stored = login(
        name,
        &format!("postgresql://{name}:pw-{name}@localhost:5432/{name}"),
    );
    assert!(stored.status.success(), "login: {}", text(&stored.stderr));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Like [`admin_with_own_database`] for a CREATEROLE admin. Another test's superuser may already
/// have created dbvalet_reader, and on 16+ only a superuser or a holder of ADMIN OPTION can then
/// give this admin ADMIN on it, so it gets that alone here and init must add INHERIT and SET.
fn createrole_admin_with_own_database(name: &str) -> PathBuf {
    let dir = admin_with_own_database(name, "CREATEROLE");
    create_reader_group();
    if server_version_num() >= 160000 {
        superuser_sql(&format!(
            "GRANT dbvalet_reader TO {name} WITH ADMIN OPTION, INHERIT FALSE, SET FALSE"
        ));
    }
    dir
}

/// Runs `sql` as the admin `name` in its own database.
fn admin_sql(name: &str, sql: &str) {
    let url = format!("postgresql://{name}:pw-{name}@localhost:5432/{name}");
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute(sql).await.unwrap();
    });
}

/// One text value from a superuser query in the database `name`.
fn superuser_text_in(name: &str, sql: &str) -> String {
    let url = format!("postgresql://postgres:e2e-throwaway@localhost:5432/{name}");
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.query_one(sql, &[]).await.unwrap().get(0)
    })
}

fn init_in(dir: &Path, alias: &str, schemas: &[&str]) -> Output {
    let mut init = Command::new(DBVALET);
    init.current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["init", "--allow-plaintext", alias]);
    for schema in schemas {
        init.args(["--schema", schema]);
    }
    init.output().unwrap()
}

/// Everything `init` can change, run in a test's database: dbvalet_reader, the membership in it
/// of the admin (named like its database), and the privileges on the database, its schemas,
/// tables and defaults.
const GRANTS_SNAPSHOT: &str = "
    SELECT concat_ws(E'\\n',
        (SELECT count(*) FROM pg_roles WHERE rolname = 'dbvalet_reader'),
        (SELECT string_agg(to_jsonb(m)::text, ',' ORDER BY m.grantor::regrole::text)
         FROM pg_auth_members m
         WHERE m.roleid = 'dbvalet_reader'::regrole AND m.member = current_database()::text::regrole),
        (SELECT datacl::text FROM pg_database WHERE datname = current_database()),
        (SELECT string_agg(nspname || ' ' || nspacl::text, ',' ORDER BY nspname)
         FROM pg_namespace WHERE nspname IN ('public', 'billing')),
        (SELECT string_agg(relname || ' ' || relacl::text, ',' ORDER BY relname)
         FROM pg_class WHERE relnamespace IN ('public'::regnamespace, 'billing'::regnamespace)),
        (SELECT string_agg(defaclnamespace::regnamespace::text || ' ' || defaclacl::text, ','
                           ORDER BY defaclnamespace::regnamespace::text)
         FROM pg_default_acl))";

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn init_on_an_empty_database_lets_a_run_read_a_table_in_each_chosen_schema() {
    let dir = admin_with_own_database("e2e_init_read", "SUPERUSER");
    admin_sql(
        "e2e_init_read",
        "CREATE SCHEMA billing;
         CREATE TABLE public.notes (note text);
         INSERT INTO public.notes VALUES ('from public');
         CREATE TABLE billing.invoices (note text);
         INSERT INTO billing.invoices VALUES ('from billing');",
    );

    let init = init_in(&dir, "e2e_init_read", &["public", "billing"]);
    let output = run_in(
        &dir,
        &[
            "psql",
            "-Atc",
            "SELECT note FROM public.notes UNION ALL SELECT note FROM billing.invoices",
        ],
    );

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert!(output.status.success(), "run: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "from public\nfrom billing\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn init_without_a_dbvalet_toml_creates_one_with_a_reader_role() {
    let dir = admin_with_own_database("e2e_init_creates_toml", "SUPERUSER");

    let init = init_in(&dir, "e2e_init_creates_toml", &[]);

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert_eq!(
        std::fs::read_to_string(dir.join("dbvalet.toml")).unwrap(),
        "[databases.e2e_init_creates_toml]\n\
         max_ttl_minutes = 480\n\
         \n\
         [databases.e2e_init_creates_toml.roles]\n\
         reader = { member_of = \"dbvalet_reader\", read_only = true }\n"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_table_the_admin_creates_after_init_is_readable_by_a_later_run() {
    let dir = admin_with_own_database("e2e_init_later_table", "SUPERUSER");

    let init = init_in(&dir, "e2e_init_later_table", &[]);
    admin_sql(
        "e2e_init_later_table",
        "CREATE TABLE created_after_init (note text);
         INSERT INTO created_after_init VALUES ('created after init');",
    );
    let output = run_in(
        &dir,
        &["psql", "-Atc", "SELECT note FROM created_after_init"],
    );

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert!(output.status.success(), "run: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "created after init\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn init_says_that_default_privileges_cover_only_tables_the_admin_creates_later() {
    let dir = admin_with_own_database("e2e_init_says_defaults", "SUPERUSER");

    let init = init_in(&dir, "e2e_init_says_defaults", &[]);

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert!(
        text(&init.stdout).contains(
            "Tables that `e2e_init_says_defaults` creates later in `public` will be readable too. \
             Tables another role creates need their own GRANT SELECT ... TO dbvalet_reader."
        ),
        "stdout: {}",
        text(&init.stdout)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn running_init_twice_succeeds_and_the_second_run_changes_nothing() {
    let dir = createrole_admin_with_own_database("e2e_init_twice");
    admin_sql(
        "e2e_init_twice",
        "CREATE SCHEMA billing;
         CREATE TABLE public.notes (note text);
         CREATE TABLE billing.invoices (note text);",
    );

    let first = init_in(&dir, "e2e_init_twice", &["public", "billing"]);
    let after_first = superuser_text_in("e2e_init_twice", GRANTS_SNAPSHOT);
    let second = init_in(&dir, "e2e_init_twice", &["public", "billing"]);
    let after_second = superuser_text_in("e2e_init_twice", GRANTS_SNAPSHOT);

    assert!(first.status.success(), "first: {}", text(&first.stderr));
    assert!(second.status.success(), "second: {}", text(&second.stderr));
    assert!(after_first.contains("dbvalet_reader=r/"), "{after_first}");
    assert_eq!(after_second, after_first);
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn two_inits_at_once_on_one_database_both_succeed_and_one_creates_dbvalet_toml() {
    let dir = admin_with_own_database("e2e_init_at_once", "SUPERUSER");
    admin_sql("e2e_init_at_once", "CREATE TABLE notes (note text);");
    let start = |dir: &Path| {
        Command::new(DBVALET)
            .current_dir(dir)
            .args(["init", "--allow-plaintext", "e2e_init_at_once"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };

    let first = start(&dir);
    let second = start(&dir);
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();

    let both_stdouts = format!("{}{}", text(&first.stdout), text(&second.stdout));

    assert!(first.status.success(), "first: {}", text(&first.stderr));
    assert!(second.status.success(), "second: {}", text(&second.stderr));
    assert!(both_stdouts.contains("Created "), "{both_stdouts}");
    assert!(
        both_stdouts.contains("already exists, so dbvalet left it unchanged"),
        "{both_stdouts}"
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn a_second_init_with_another_schema_makes_that_schema_readable_too() {
    let dir = admin_with_own_database("e2e_init_adds_schema", "SUPERUSER");
    admin_sql(
        "e2e_init_adds_schema",
        "CREATE SCHEMA billing;
         CREATE TABLE public.notes (note text);
         INSERT INTO public.notes VALUES ('from public');
         CREATE TABLE billing.invoices (note text);
         INSERT INTO billing.invoices VALUES ('from billing');",
    );

    let first = init_in(&dir, "e2e_init_adds_schema", &["public"]);
    let before_second = run_in(&dir, &["psql", "-Atc", "SELECT note FROM billing.invoices"]);
    let second = init_in(&dir, "e2e_init_adds_schema", &["billing"]);
    let output = run_in(
        &dir,
        &[
            "psql",
            "-Atc",
            "SELECT note FROM public.notes UNION ALL SELECT note FROM billing.invoices",
        ],
    );

    assert!(first.status.success(), "first: {}", text(&first.stderr));
    assert!(
        text(&before_second.stderr).contains("permission denied for schema billing"),
        "before the second init: {}",
        text(&before_second.stderr)
    );
    assert!(second.status.success(), "second: {}", text(&second.stderr));
    assert!(output.status.success(), "run: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "from public\nfrom billing\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn with_an_existing_dbvalet_toml_init_prints_the_block_and_leaves_the_file_unchanged() {
    let dir = admin_with_own_database("e2e_init_existing_toml", "SUPERUSER");
    let existing = "# hand-written\n[databases.other.roles]\n\
                    reader = { member_of = \"dbvalet_reader\", read_only = true }\n";
    std::fs::write(dir.join("dbvalet.toml"), existing).unwrap();

    let init = init_in(&dir, "e2e_init_existing_toml", &[]);

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert_eq!(
        std::fs::read_to_string(dir.join("dbvalet.toml")).unwrap(),
        existing
    );
    assert!(
        text(&init.stdout).contains(
            "[databases.e2e_init_existing_toml]\n\
             max_ttl_minutes = 480\n\
             \n\
             [databases.e2e_init_existing_toml.roles]\n\
             reader = { member_of = \"dbvalet_reader\", read_only = true }\n"
        ),
        "stdout: {}",
        text(&init.stdout)
    );
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn after_init_a_createrole_admin_runs_a_read_end_to_end() {
    let dir = createrole_admin_with_own_database("e2e_init_createrole");
    admin_sql(
        "e2e_init_createrole",
        "CREATE TABLE notes (note text);
         INSERT INTO notes VALUES ('read by a createrole admin');",
    );

    let init = init_in(&dir, "e2e_init_createrole", &[]);
    let output = run_in(&dir, &["psql", "-Atc", "SELECT note FROM notes"]);

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert!(output.status.success(), "run: {}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "read by a createrole admin\n");
}

#[test]
#[ignore = "e2e: needs PostgreSQL on localhost:5432 and a keychain"]
fn after_init_a_createrole_admin_holds_admin_inherit_and_set_on_dbvalet_reader() {
    let dir = createrole_admin_with_own_database("e2e_init_createrole_rights");

    let init = init_in(&dir, "e2e_init_createrole_rights", &[]);
    // SET is a privilege of its own from 16; before that, every member may SET ROLE.
    let rights = superuser_text_in(
        "e2e_init_createrole_rights",
        "SELECT concat_ws(' ',
             pg_has_role(current_database(), 'dbvalet_reader', 'MEMBER WITH ADMIN OPTION')::text,
             pg_has_role(current_database(), 'dbvalet_reader', 'USAGE')::text,
             CASE WHEN current_setting('server_version_num')::int >= 160000
                  THEN pg_has_role(current_database(), 'dbvalet_reader', 'SET')
                  ELSE pg_has_role(current_database(), 'dbvalet_reader', 'MEMBER') END::text)",
    );

    assert!(init.status.success(), "init: {}", text(&init.stderr));
    assert_eq!(rights, "true true true");
}
