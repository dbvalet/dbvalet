//! `dbvalet`, PostgreSQL and project helpers every group uses.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

pub(crate) const DBVALET: &str = env!("CARGO_BIN_EXE_dbvalet");
pub(crate) const SUPERUSER_URL: &str =
    "postgresql://postgres:e2e-throwaway@localhost:5432/postgres";

/// A test that makes an expired `dbvalet_` login holds this for writing until its own sweep has
/// run. Every other run and gc holds it for reading: their sweeps would otherwise drop that
/// login first, without its ledger entry. A test takes it at most once, so it never nests.
pub(crate) static EXPIRED_FIXTURE: RwLock<()> = RwLock::new(());

pub(crate) fn sweeping() -> RwLockReadGuard<'static, ()> {
    EXPIRED_FIXTURE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn sweeping_alone() -> RwLockWriteGuard<'static, ()> {
    EXPIRED_FIXTURE
        .write()
        .unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn superuser_sql(sql: &str) {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute(sql).await.unwrap();
    });
}

pub(crate) fn server_version_num() -> i32 {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        let row = client
            .query_one("SELECT current_setting('server_version_num')::int", &[])
            .await
            .unwrap();
        row.get(0)
    })
}

pub(crate) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub(crate) fn login(alias: &str, connection_string: &str) -> Output {
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

pub(crate) fn doctor(alias: &str) -> Output {
    Command::new(DBVALET)
        .args(["doctor", "--allow-plaintext", alias])
        .output()
        .unwrap()
}

pub(crate) fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Creates the shared read-only group role; tests running in parallel may race to create it.
pub(crate) fn create_reader_group() {
    superuser_sql(
        "DO $$ BEGIN
             CREATE ROLE dbvalet_reader NOLOGIN;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
         END $$;",
    );
}

/// Stores a superuser admin login under `alias` and writes a `dbvalet.toml` that lists
/// `alias` with a read-only `reader` role. Returns the directory holding the file.
pub(crate) fn project_with_reader(alias: &str) -> PathBuf {
    project_with_reader_and_admin(alias, "SUPERUSER")
}

/// Like [`project_with_reader`], with an admin that has `attributes` and ADMIN OPTION on
/// `dbvalet_reader`, which `dbvalet init` will grant.
pub(crate) fn project_with_reader_and_admin(alias: &str, attributes: &str) -> PathBuf {
    create_reader_group();
    let admin = alias.replace('-', "_");
    superuser_sql(&format!(
        "DROP ROLE IF EXISTS {admin};
         CREATE ROLE {admin} LOGIN {attributes} PASSWORD 'pw-{alias}-admin';
         GRANT dbvalet_reader TO {admin} WITH ADMIN OPTION;"
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
             reader = {{ member_of = \"dbvalet_reader\", read_only = true }}\n"
        ),
    )
    .unwrap();
    dir
}

pub(crate) fn run_command(dir: &Path, command: &[&str]) -> Command {
    let mut run = Command::new(DBVALET);
    run.current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["run", "--allow-plaintext", "--"])
        .args(command);
    run
}

pub(crate) fn run_in(dir: &Path, command: &[&str]) -> Output {
    let _sweeping = sweeping();
    run_command(dir, command).output().unwrap()
}

pub(crate) fn superuser_count(sql: &str, name: &str) -> i64 {
    runtime().block_on(async {
        let (client, connection) = tokio_postgres::connect(SUPERUSER_URL, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.query_one(sql, &[&name]).await.unwrap().get(0)
    })
}

/// Every word of 16 or more letters and digits in `text` that logs in as `witness`.
pub(crate) fn passwords_of(witness: &str, text: &str) -> Vec<String> {
    let words: BTreeSet<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| word.len() >= 16)
        .collect();
    runtime().block_on(async {
        let mut found = Vec::new();
        for word in words {
            let url = format!("postgresql://{witness}:{word}@localhost:5432/postgres");
            if tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .is_ok()
            {
                found.push(word.to_owned());
            }
        }
        found
    })
}

pub(crate) fn gc_command(dir: &Path) -> Command {
    let mut gc = Command::new(DBVALET);
    gc.current_dir(dir)
        .env("XDG_STATE_HOME", dir.join("state"))
        .args(["gc", "--allow-plaintext"]);
    gc
}

pub(crate) fn gc_in(dir: &Path) -> Output {
    let _sweeping = sweeping();
    gc_command(dir).output().unwrap()
}

/// The value of the first `key=value` line the child printed.
pub(crate) fn printed<'a>(seen: &'a str, key: &str) -> &'a str {
    seen.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap()
}

/// Where a run in `dir` keeps the ledger entry for `login` on `alias`.
pub(crate) fn ledger_entry(dir: &Path, alias: &str, login: &str) -> PathBuf {
    dir.join("state/dbvalet/ledger")
        .join(format!("{alias}.{login}"))
}

/// Waits up to 10 s for a session of `login` to be running a query.
pub(crate) fn wait_for_active_query(login: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while superuser_count(
        "SELECT count(*) FROM pg_stat_activity WHERE usename = $1 AND state = 'active'",
        login,
    ) == 0
    {
        assert!(Instant::now() < deadline, "no active query for {login}");
        std::thread::sleep(Duration::from_millis(50));
    }
}
