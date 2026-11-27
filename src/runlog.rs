//! Local per-run plain-text log files under `$XDG_STATE_HOME/dbvalet/runs/` (or
//! `~/.local/state/dbvalet/runs/`).
//!
//! ## How passwords and secrets are shown
//!
//! - **Runtime secrets (guaranteed):** Every occurrence of the per-run token and the temporary
//!   login's password is scrubbed verbatim and replaced with `[REDACTED]` before truncation and
//!   before writing to disk, in both the `command:` header and every statement line. Extended
//!   protocol `B` (Bind) frames are never logged.
//! - **SQL password redaction (lexical, best-effort):**
//!   - Any SQL string literal following a keyword ending in `password` (`PASSWORD`, `sslpassword`,
//!     etc.) or `CONNECTION` — including single-quoted, `E'...'`, `U&'...'`, `N'...'`, dollar-quoted
//!     (`$$...$$`, `$tag$...$tag$`), backslash-escaped (`standard_conforming_strings = off`),
//!     newline-continued, and unterminated literals — is replaced with `'[REDACTED]'`.
//!     Non-literal forms (`ALTER ROLE ... PASSWORD NULL`) and column references
//!     (`SELECT password FROM users`) are preserved.
//!   - Dollar-quoted bodies (such as `DO $$ ... $$`) and embedded single-quoted SQL statements
//!     (such as `EXECUTE 'ALTER ROLE ... PASSWORD ''...'''`) are redacted recursively, failing
//!     closed if nesting exceeds the recursion limit. When string literals in a statement form an
//!     `ALTER`/`CREATE` credential template (even split across concatenated literals), remaining
//!     string literals in that statement are replaced with `'[REDACTED]'`.
//!   - Inside string literals, URI userinfo secrets (`scheme://user:SECRET@`), URI query parameters
//!     whose decoded key ends in `password`, and libpq conninfo `password=` / `*password=` values
//!     (such as in `dblink`) are replaced with `[REDACTED]`.
//!   - Statements that are truncated, invalid UTF-8, or non-ASCII under a non-UTF-8
//!     `client_encoding` are omitted from the log rather than partially decoded.
//!   - Because SQL redaction is lexical, it cannot catch passwords constructed dynamically at
//!     runtime (such as `chr()`, `decode()`, or PL/pgSQL variables). Use `--no-sql-log` whenever
//!     query text must never be written to disk.
//! - **`command:` header redaction:** CLI arguments are never parsed as SQL (so `--long-flag` or
//!   `/*` globs cannot hide credentials). Non-UTF-8 arguments are omitted, URI userinfo and query
//!   password parameters are redacted, and on the first case-insensitive `password` or `connection`
//!   in an argument, everything after it (or the following argument when it ends with that keyword)
//!   is replaced with `[REDACTED]`.
//! - **Terminal safety:** Control characters, Unicode line/paragraph separators (`U+2028`,
//!   `U+2029`), and bidirectional control characters are escaped both when written and when shown
//!   by `dbvalet log`.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};

use crate::{DatabaseAlias, is_run_id, state_dir};

mod redact;
use redact::{redact_after_secret_keyword, redact_sql, redact_uri_passwords};

const RUNS_SUBDIR: &str = "runs";
const LOG_EXTENSION: &str = ".log";
const DIR_MODE_OWNER_ONLY: u32 = 0o700;
const FILE_MODE_OWNER_ONLY: u32 = 0o600;
const MAX_RECENT_RUNS: usize = 50;
const MAX_HEADER_LINES: usize = 32;
const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_MINUTE: u64 = 60;
const REDACTED_SECRET: &str = "[REDACTED]";
const OMITTED_ARG: &str = "[omitted]";
const TRUNCATED_MARKER: &str = "/* truncated */";

/// Maximum byte length of a single logged statement line before the truncation marker.
pub(crate) const MAX_LOGGED_QUERY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    Query,
    Parse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedSql<'a> {
    Text(&'a str),
    Truncated,
    Omitted(&'static str),
}

impl StatementKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Query => "Q",
            Self::Parse => "P",
        }
    }
}

#[derive(Clone)]
pub struct RunHeader {
    pub run_id: String,
    pub started_at: SystemTime,
    pub database: DatabaseAlias,
    pub role: String,
    pub valid_until: String,
    pub max_ttl: Option<Duration>,
    pub command: Vec<OsString>,
    pub sql_log: bool,
}

impl fmt::Debug for RunHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunHeader")
            .field("run_id", &self.run_id)
            .field("started_at", &self.started_at)
            .field("database", &self.database)
            .field("role", &self.role)
            .field("valid_until", &self.valid_until)
            .field("max_ttl", &self.max_ttl)
            .field("command", &REDACTED_SECRET)
            .field("sql_log", &self.sql_log)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RunSecrets {
    token: SecretString,
    login_password: SecretString,
}

impl RunSecrets {
    pub fn new(token: SecretString, login_password: SecretString) -> Self {
        Self {
            token,
            login_password,
        }
    }

    fn scrub(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for secret in [
            self.token.expose_secret(),
            self.login_password.expose_secret(),
        ] {
            if !secret.is_empty() {
                out = out.replace(secret, REDACTED_SECRET);
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    pub run_id: String,
    pub started_at: String,
    pub database: String,
    pub role: String,
    pub command: String,
}

impl fmt::Display for RunSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  {}  {}  {}  {}",
            self.started_at, self.run_id, self.database, self.role, self.command
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunLogError {
    #[error("can't find the state directory: set HOME or XDG_STATE_HOME")]
    NoStateDir,
    #[error("couldn't create the run log directory {}", path.display())]
    CreateDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("couldn't create the run log {}", path.display())]
    CreateFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("couldn't write the run log header to {}", path.display())]
    WriteHeader {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("couldn't read the run log directory {}", path.display())]
    ReadDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("couldn't read the run log {}", path.display())]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("couldn't write the run log output")]
    WriteOutput(#[source] io::Error),
    #[error("no run log found for `{run_id}`")]
    NotFound { run_id: String },
}

#[derive(Clone)]
pub struct RunLog {
    inner: Arc<RunLogInner>,
}

struct RunLogInner {
    file: Mutex<File>,
    secrets: RunSecrets,
    write_error_reported: AtomicBool,
}

impl fmt::Debug for RunLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunLog").finish_non_exhaustive()
    }
}

pub fn open(header: &RunHeader, secrets: RunSecrets) -> Result<RunLog, RunLogError> {
    let dir = default_runs_dir()?;
    open_in(&dir, header, secrets)
}

pub fn list() -> Result<Vec<RunSummary>, RunLogError> {
    let dir = default_runs_dir()?;
    list_in(&dir)
}

/// Streams the run log for `run_id` into `writer`.
pub fn copy_to(run_id: &str, writer: &mut impl Write) -> Result<(), RunLogError> {
    let dir = default_runs_dir()?;
    copy_to_in(&dir, run_id, writer)
}

impl RunLog {
    /// Redacts passwords and runtime secrets from `sql`, normalizes it onto one line,
    /// truncates if needed, and writes it to the run log file.
    pub fn statement(&self, kind: StatementKind, sql: ObservedSql<'_>) {
        let single_line = match sql {
            ObservedSql::Truncated => {
                // An incomplete statement can omit the context needed to identify a credential.
                TRUNCATED_MARKER.to_owned()
            }
            ObservedSql::Omitted(reason) => format!("/* omitted: {reason} */"),
            ObservedSql::Text(sql) => {
                if sql.trim().is_empty() {
                    return;
                }
                let scrubbed = self.inner.secrets.scrub(sql);
                let redacted = redact_sql(&scrubbed);
                let scrubbed = self.inner.secrets.scrub(&redacted);
                let mut line = sanitize_single_line(&scrubbed);
                if line.trim().is_empty() {
                    return;
                }
                if line.len() > MAX_LOGGED_QUERY_BYTES {
                    truncate_utf8(&mut line, MAX_LOGGED_QUERY_BYTES);
                    line.push(' ');
                    line.push_str(TRUNCATED_MARKER);
                }
                line
            }
        };
        let line = format!(
            "{} [{}] {single_line}\n",
            format_utc_rfc3339(SystemTime::now()),
            kind.tag()
        );
        let mut file = self
            .inner
            .file
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(err) = file.write_all(line.as_bytes())
            && !self
                .inner
                .write_error_reported
                .swap(true, Ordering::Relaxed)
        {
            // Logging failures must never break or block the database relay (ADR-0002).
            let _ = writeln!(
                io::stderr(),
                "dbvalet: couldn't write to the run log: {err}"
            );
        }
    }
}

fn truncate_utf8(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
}

fn default_runs_dir() -> Result<PathBuf, RunLogError> {
    state_dir()
        .map(|dir| dir.join(RUNS_SUBDIR))
        .ok_or(RunLogError::NoStateDir)
}

fn open_in(dir: &Path, header: &RunHeader, secrets: RunSecrets) -> Result<RunLog, RunLogError> {
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE_OWNER_ONLY)
        .create(dir)
        .map_err(|source| RunLogError::CreateDir {
            path: dir.to_owned(),
            source,
        })?;
    let file_name = format!(
        "{}-{}{LOG_EXTENSION}",
        format_utc_filename_prefix(header.started_at),
        header.run_id
    );
    let path = dir.join(file_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE_OWNER_ONLY)
        .open(&path)
        .map_err(|source| RunLogError::CreateFile {
            path: path.clone(),
            source,
        })?;

    let header_text = format_header(header, &secrets);
    file.write_all(header_text.as_bytes())
        .map_err(|source| RunLogError::WriteHeader { path, source })?;

    Ok(RunLog {
        inner: Arc::new(RunLogInner {
            file: Mutex::new(file),
            secrets,
            write_error_reported: AtomicBool::new(false),
        }),
    })
}

fn format_header(header: &RunHeader, secrets: &RunSecrets) -> String {
    let max_ttl = match header.max_ttl {
        Some(duration) => format_duration(duration),
        None => "not set".to_owned(),
    };
    let sql_log = if header.sql_log {
        "enabled"
    } else {
        "disabled (--no-sql-log)"
    };
    let command = if header.sql_log {
        header.command.as_slice()
    } else {
        &header.command[..header.command.len().min(1)]
    };
    let command = format_command(command, secrets);
    format!(
        "run_id: {}\n\
         started_at: {}\n\
         database: {}\n\
         role: {}\n\
         valid_until: {}\n\
         max_ttl: {max_ttl}\n\
         sql_log: {sql_log}\n\
         command: {command}\n\
         \n",
        sanitize_single_line(&header.run_id),
        format_utc_rfc3339(header.started_at),
        sanitize_single_line(header.database.as_str()),
        sanitize_single_line(&header.role),
        sanitize_single_line(&header.valid_until),
    )
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs > 0 && secs.is_multiple_of(SECONDS_PER_MINUTE) {
        format!("{}m", secs / SECONDS_PER_MINUTE)
    } else {
        format!("{secs}s")
    }
}

/// Formats CLI arguments for the `command:` header without parsing shell text as SQL.
fn format_command(command: &[OsString], secrets: &RunSecrets) -> String {
    let mut out = Vec::with_capacity(command.len());
    let mut redact_next = false;
    for arg in command {
        if redact_next {
            out.push(REDACTED_SECRET.to_owned());
            redact_next = false;
            continue;
        }
        let Some(text) = arg.to_str() else {
            out.push(OMITTED_ARG.to_owned());
            continue;
        };
        let uri_redacted = redact_uri_passwords(text);
        let (redacted, needs_next) = redact_after_secret_keyword(&uri_redacted);
        redact_next = needs_next;
        let scrubbed = secrets.scrub(&redacted);
        let single_line = sanitize_single_line(&scrubbed);
        out.push(quote_command_arg(&single_line));
    }
    out.join(" ")
}

fn quote_command_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_owned();
    }
    let needs_quoting = arg.bytes().any(|b| {
        !(b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'+' | b'@' | b'[' | b']'
            ))
    });
    if !needs_quoting {
        return arg.to_owned();
    }
    if !arg.contains('\'') {
        return format!("'{arg}'");
    }
    let escaped = arg.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn list_in(dir: &Path) -> Result<Vec<RunSummary>, RunLogError> {
    let entries = sorted_run_files(dir)?;
    let mut summaries = Vec::new();
    for (file_name, run_id, path) in entries.into_iter().take(MAX_RECENT_RUNS) {
        match read_summary(&path, &run_id) {
            Ok(summary) => summaries.push(summary),
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(RunLogError::ReadFile {
                    path: dir.join(file_name),
                    source,
                });
            }
        }
    }
    Ok(summaries)
}

fn copy_to_in(
    dir: &Path,
    requested_run_id: &str,
    writer: &mut impl Write,
) -> Result<(), RunLogError> {
    let normalized = requested_run_id
        .strip_prefix(crate::LOGIN_PREFIX)
        .unwrap_or(requested_run_id);
    if !is_run_id(normalized) {
        return Err(RunLogError::NotFound {
            run_id: requested_run_id.to_owned(),
        });
    }
    let entries = sorted_run_files(dir)?;
    let Some((_, _, path)) = entries.into_iter().find(|(_, id, _)| id == normalized) else {
        return Err(RunLogError::NotFound {
            run_id: requested_run_id.to_owned(),
        });
    };
    let mut file = File::open(&path).map_err(|source| RunLogError::ReadFile {
        path: path.clone(),
        source,
    })?;
    let mut buf = [0u8; 8 * 1024];
    let mut pending = 0usize;
    loop {
        let n = io::Read::read(&mut file, &mut buf[pending..]).map_err(|source| {
            RunLogError::ReadFile {
                path: path.clone(),
                source,
            }
        })?;
        if n == 0 {
            if pending > 0 {
                write_escaped_invalid_bytes(&buf[..pending], writer)
                    .map_err(RunLogError::WriteOutput)?;
            }
            return Ok(());
        }
        let total = pending + n;
        let mut offset = 0;
        pending = 0;
        while offset < total {
            match std::str::from_utf8(&buf[offset..total]) {
                Ok(valid) => {
                    write_terminal_safe(valid, writer).map_err(RunLogError::WriteOutput)?;
                    offset = total;
                }
                Err(err) => {
                    let valid_len = err.valid_up_to();
                    if valid_len > 0 {
                        let valid = std::str::from_utf8(&buf[offset..offset + valid_len])
                            .expect("valid_up_to guarantees valid UTF-8");
                        write_terminal_safe(valid, writer).map_err(RunLogError::WriteOutput)?;
                        offset += valid_len;
                    }
                    if let Some(bad_len) = err.error_len() {
                        write_escaped_invalid_bytes(&buf[offset..offset + bad_len], writer)
                            .map_err(RunLogError::WriteOutput)?;
                        offset += bad_len;
                    } else {
                        let rem = total - offset;
                        buf.copy_within(offset..total, 0);
                        pending = rem;
                        break;
                    }
                }
            }
        }
    }
}

fn write_terminal_safe(text: &str, writer: &mut impl Write) -> io::Result<()> {
    if !text.chars().any(|c| c != '\n' && needs_terminal_escape(c)) {
        return writer.write_all(text.as_bytes());
    }
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch != '\n' && needs_terminal_escape(ch) {
            for escaped in ch.escape_unicode() {
                out.push(escaped);
            }
        } else {
            out.push(ch);
        }
    }
    writer.write_all(out.as_bytes())
}

fn write_escaped_invalid_bytes(bytes: &[u8], writer: &mut impl Write) -> io::Result<()> {
    for &byte in bytes {
        write!(writer, "\\x{byte:02x}")?;
    }
    Ok(())
}

/// Returns `(file_name, run_id, full_path)` for every valid run log file in `dir`,
/// sorted newest first by filename.
fn sorted_run_files(dir: &Path) -> Result<Vec<(String, String, PathBuf)>, RunLogError> {
    let read_dir = match fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(RunLogError::ReadDir {
                path: dir.to_owned(),
                source,
            });
        }
    };
    let mut files = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|source| RunLogError::ReadDir {
            path: dir.to_owned(),
            source,
        })?;
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Some(run_id) = parse_run_id_from_file_name(&file_name).map(str::to_owned) else {
            continue;
        };
        files.push((file_name, run_id, entry.path()));
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(files)
}

fn parse_run_id_from_file_name(file_name: &str) -> Option<&str> {
    let stem = file_name.strip_suffix(LOG_EXTENSION)?;
    let (prefix, run_id) = stem.rsplit_once('-')?;
    if !is_valid_timestamp_prefix(prefix) || !is_run_id(run_id) {
        return None;
    }
    Some(run_id)
}

fn is_valid_timestamp_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.ends_with('Z')
        && prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'T' | b'.' | b'Z'))
}

fn read_summary(path: &Path, fallback_run_id: &str) -> io::Result<RunSummary> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut run_id = fallback_run_id.to_owned();
    let mut started_at = String::new();
    let mut database = String::new();
    let mut role = String::new();
    let mut command = String::new();

    for line in reader.lines().take(MAX_HEADER_LINES) {
        let line = line?;
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            match key {
                "run_id" => run_id = sanitize_single_line(value),
                "started_at" => started_at = sanitize_single_line(value),
                "database" => database = sanitize_single_line(value),
                "role" => role = sanitize_single_line(value),
                "command" => command = sanitize_single_line(value),
                _ => {}
            }
        }
    }

    Ok(RunSummary {
        run_id,
        started_at,
        database,
        role,
        command,
    })
}

/// Returns whether a character can forge lines, inject terminal escapes, or reorder
/// displayed text in a terminal or editor.
fn needs_terminal_escape(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Replaces newlines and tabs with spaces and escapes control, Unicode line-separator, and
/// bidirectional formatting characters so an entry stays on one safe terminal line.
fn sanitize_single_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut prev_space = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            }
            '\n' | '\t' => {
                if !prev_space {
                    out.push(' ');
                    prev_space = true;
                }
            }
            ' ' => {
                out.push(' ');
                prev_space = true;
            }
            c if needs_terminal_escape(c) => {
                for escaped in c.escape_unicode() {
                    out.push(escaped);
                }
                prev_space = false;
            }
            c => {
                out.push(c);
                prev_space = false;
            }
        }
    }
    out
}

struct UtcDateTime {
    year: i64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
    nanos: u32,
}

/// Converts a `SystemTime` into a UTC calendar timestamp using Howard Hinnant's
/// proleptic Gregorian `civil_from_days` algorithm.
fn utc_date_time(time: SystemTime) -> UtcDateTime {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = duration.as_secs();
    let days = (total_secs / SECONDS_PER_DAY) as i64;
    let secs_of_day = total_secs % SECONDS_PER_DAY;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);

    UtcDateTime {
        year,
        month,
        day,
        hour: secs_of_day / SECONDS_PER_HOUR,
        minute: (secs_of_day % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE,
        second: secs_of_day % SECONDS_PER_MINUTE,
        nanos: duration.subsec_nanos(),
    }
}

fn format_utc_rfc3339(time: SystemTime) -> String {
    let dt = utc_date_time(time);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    )
}

fn format_utc_filename_prefix(time: SystemTime) -> String {
    let dt = utc_date_time(time);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}.{:09}Z",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.nanos
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn temp_runs_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-runlog")
            .join(format!("{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn read_to_string(dir: &Path, run_id: &str) -> Result<String, RunLogError> {
        let mut buf = Vec::new();
        copy_to_in(dir, run_id, &mut buf)?;
        Ok(String::from_utf8(buf).unwrap())
    }

    fn sample_header(
        run_id: &str,
        started_secs: u64,
        command: &[&str],
        sql_log: bool,
    ) -> RunHeader {
        RunHeader {
            run_id: run_id.to_owned(),
            started_at: UNIX_EPOCH + Duration::from_secs(started_secs),
            database: "app".parse().unwrap(),
            role: "reader".to_owned(),
            valid_until: "2026-11-26T10:30:00Z".to_owned(),
            max_ttl: Some(Duration::from_secs(480 * 60)),
            command: command.iter().map(OsString::from).collect(),
            sql_log,
        }
    }

    fn sample_secrets() -> RunSecrets {
        RunSecrets::new(
            SecretString::from("toksecret1234567890abcdef1234567"),
            SecretString::from("pwloginsecret1234567890abcdef123"),
        )
    }

    #[test]
    fn utc_timestamps_format_known_dates_including_leap_days() {
        assert_eq!(format_utc_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 2024-02-29T23:59:59Z = 1709251199
        assert_eq!(
            format_utc_rfc3339(UNIX_EPOCH + Duration::from_secs(1_709_251_199)),
            "2024-02-29T23:59:59Z"
        );
        // 2026-11-26T10:15:30Z = 1795688130
        assert_eq!(
            format_utc_rfc3339(UNIX_EPOCH + Duration::from_secs(1_795_688_130)),
            "2026-11-26T10:15:30Z"
        );
        assert_eq!(
            format_utc_filename_prefix(UNIX_EPOCH + Duration::new(1_795_688_130, 42_000_005)),
            "20261126T101530.042000005Z"
        );
    }

    #[test]
    fn command_header_redacts_passwords_after_long_flags_and_globs() {
        let secrets = sample_secrets();
        for (args, leaked) in [
            (
                vec!["psql", "--command=ALTER ROLE a PASSWORD 'pw-long-35'"],
                "pw-long-35",
            ),
            (
                vec![
                    "sh",
                    "-c",
                    "psql --no-psqlrc -c \"ALTER ROLE a PASSWORD 'pw-dashdash-37'\"",
                ],
                "pw-dashdash-37",
            ),
            (
                vec![
                    "sh",
                    "-c",
                    "ls /*.txt; psql -c \"ALTER ROLE a PASSWORD 'pw-glob-38'\"",
                ],
                "pw-glob-38",
            ),
            (
                vec!["mytool", "--password", "pw-next-arg-39"],
                "pw-next-arg-39",
            ),
        ] {
            let cmd: Vec<OsString> = args.into_iter().map(OsString::from).collect();
            let formatted = format_command(&cmd, &secrets);
            assert!(!formatted.contains(leaked), "{formatted}");
            assert!(formatted.contains("[REDACTED]"), "{formatted}");
        }
    }

    #[test]
    fn command_header_redacts_uri_env_and_conninfo_passwords() {
        let secrets = sample_secrets();
        for (args, leaked) in [
            (
                vec![
                    "pg_dump",
                    "postgresql://admin:pw-url-31@prod.example.com/db",
                ],
                "pw-url-31",
            ),
            (vec!["env", "PGPASSWORD=pw-env-32", "psql"], "pw-env-32"),
            (
                vec!["psql", "host=h password=pw-conninfo-33"],
                "pw-conninfo-33",
            ),
        ] {
            let cmd: Vec<OsString> = args.into_iter().map(OsString::from).collect();
            let formatted = format_command(&cmd, &secrets);
            assert!(!formatted.contains(leaked), "{formatted}");
            assert!(formatted.contains("[REDACTED]"), "{formatted}");
        }
    }

    #[test]
    fn opening_a_run_log_writes_the_header_with_owner_only_permissions() {
        let dir = temp_runs_dir("open-header");
        let header = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_130,
            &["psql", "-c", "select 1"],
            true,
        );
        let _log = open_in(&dir, &header, sample_secrets()).unwrap();

        let content = read_to_string(&dir, "aaaaaaaaaaaaaaaa").unwrap();
        assert!(content.contains("run_id: aaaaaaaaaaaaaaaa\n"), "{content}");
        assert!(
            content.contains("started_at: 2026-11-26T10:15:30Z\n"),
            "{content}"
        );
        assert!(content.contains("database: app\n"), "{content}");
        assert!(content.contains("role: reader\n"), "{content}");
        assert!(
            content.contains("valid_until: 2026-11-26T10:30:00Z\n"),
            "{content}"
        );
        assert!(content.contains("max_ttl: 480m\n"), "{content}");
        assert!(content.contains("sql_log: enabled\n"), "{content}");
        assert!(
            content.contains("command: psql -c 'select 1'\n"),
            "{content}"
        );

        let path = dir.join("20261126T101530.000000000Z-aaaaaaaaaaaaaaaa.log");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn logged_statements_redact_sql_passwords_and_runtime_secrets() {
        let dir = temp_runs_dir("log-statements");
        let header = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_130,
            &["psql", "-c", "ALTER ROLE x PASSWORD 'cli-secret-99'"],
            true,
        );
        let log = open_in(&dir, &header, sample_secrets()).unwrap();
        log.statement(StatementKind::Query, ObservedSql::Text("select 1"));
        log.statement(
            StatementKind::Query,
            ObservedSql::Text(
                "SELECT 'toksecret1234567890abcdef1234567', 'pwloginsecret1234567890abcdef123'",
            ),
        );
        log.statement(
            StatementKind::Parse,
            ObservedSql::Text("SELECT $1::int\nFROM items"),
        );

        let content = read_to_string(&dir, "aaaaaaaaaaaaaaaa").unwrap();
        assert!(content.contains("[Q] select 1\n"), "{content}");
        assert!(
            content.contains("[P] SELECT $1::int FROM items\n"),
            "{content}"
        );
        assert!(!content.contains("cli-secret-99"), "{content}");
        assert!(
            !content.contains("toksecret1234567890abcdef1234567"),
            "{content}"
        );
        assert!(
            !content.contains("pwloginsecret1234567890abcdef123"),
            "{content}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_incomplete_statement_records_only_the_truncation_marker() {
        let dir = temp_runs_dir("omit-incomplete-statement");
        let header = sample_header("aaaaaaaaaaaaaaaa", 1_795_688_130, &["psql"], true);
        let log = open_in(&dir, &header, sample_secrets()).unwrap();

        log.statement(StatementKind::Query, ObservedSql::Truncated);

        let content = read_to_string(&dir, "aaaaaaaaaaaaaaaa").unwrap();
        assert!(content.ends_with("[Q] /* truncated */\n"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_header_with_sql_logging_disabled_records_only_the_executable() {
        let header = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_130,
            &["psql", "-c", "SELECT 'private note'"],
            false,
        );
        let text = format_header(&header, &sample_secrets());

        assert!(text.ends_with("command: psql\n\n"));
    }

    #[test]
    fn list_returns_runs_newest_first_and_ignores_unrelated_files() {
        let dir = temp_runs_dir("list-order");
        let older = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_100,
            &["psql", "-c", "select 1"],
            true,
        );
        let newer = sample_header(
            "bbbbbbbbbbbbbbbb",
            1_795_688_200,
            &["psql", "-c", "select 2"],
            true,
        );
        let _ = open_in(&dir, &older, sample_secrets()).unwrap();
        let _ = open_in(&dir, &newer, sample_secrets()).unwrap();
        fs::write(dir.join(".DS_Store"), b"junk").unwrap();
        fs::write(dir.join("notes.txt"), b"not a run log").unwrap();

        let summaries = list_in(&dir).unwrap();
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].run_id, "bbbbbbbbbbbbbbbb");
        assert_eq!(summaries[1].run_id, "aaaaaaaaaaaaaaaa");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_rejects_unknown_and_path_traversal_run_ids() {
        let dir = temp_runs_dir("read-not-found");
        fs::create_dir_all(&dir).unwrap();
        assert!(matches!(
            read_to_string(&dir, "zzzzzzzzzzzzzzzz"),
            Err(RunLogError::NotFound { .. })
        ));
        assert!(matches!(
            read_to_string(&dir, "../Cargo.toml"),
            Err(RunLogError::NotFound { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_header_and_run_log_debug_output_never_contain_passwords_or_tokens() {
        let dir = temp_runs_dir("debug-redaction");
        let secrets = sample_secrets();
        let header = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_130,
            &["psql", "--command=ALTER ROLE a PASSWORD 'pw-dbg-99'"],
            true,
        );
        let log = open_in(&dir, &header, secrets.clone()).unwrap();

        let combined = format!("{secrets:?}\n{header:?}\n{log:?}");
        assert!(
            !combined.contains("toksecret1234567890abcdef1234567"),
            "{combined}"
        );
        assert!(
            !combined.contains("pwloginsecret1234567890abcdef123"),
            "{combined}"
        );
        assert!(!combined.contains("pw-dbg-99"), "{combined}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_uri_without_whitespace_in_a_command_argument_is_redacted() {
        let secrets = sample_secrets();
        let cmd = vec![
            OsString::from("psql"),
            OsString::from("-c"),
            OsString::from("SELECT dblink('postgresql://a','postgresql://u:pw-r2-20@h/db')"),
        ];
        let formatted = format_command(&cmd, &secrets);
        assert_eq!(
            formatted,
            "psql -c \"SELECT dblink('postgresql://a','postgresql://u:[REDACTED]@h/db')\""
        );
    }

    #[test]
    fn a_percent_encoded_password_query_parameter_is_redacted_in_headers_and_sql() {
        let secrets = sample_secrets();
        let cmd = vec![
            OsString::from("psql"),
            OsString::from("postgresql://u@db.example/app?pass%77ord=synthetic-pw-pct1"),
        ];
        let header = format_command(&cmd, &secrets);
        assert!(!header.contains("synthetic-pw-pct1"), "{header}");
        assert!(header.contains("[REDACTED]"), "{header}");

        let sql = redact_sql(
            "SELECT dblink('postgresql://u@db.example/app?pass%77ord=synthetic-pw-pct2', 'SELECT 1')",
        );
        assert!(!sql.contains("synthetic-pw-pct2"), "{sql}");
        assert!(sql.contains("[REDACTED]"), "{sql}");
    }

    #[test]
    fn unicode_line_separators_and_direction_overrides_are_escaped_in_logs_and_output() {
        let dir = temp_runs_dir("unicode-display");
        let header = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_130,
            &[
                "psql",
                "-c",
                "SELECT 'a\u{2028}b\u{2029}c\u{202e}d\u{2066}e'",
            ],
            true,
        );
        let log = open_in(&dir, &header, sample_secrets()).unwrap();
        log.statement(
            StatementKind::Query,
            ObservedSql::Text(
                "SELECT 'ls:\u{2028}ps:\u{2029}rlo:\u{202e}lri:\u{2066}alm:\u{061c}'",
            ),
        );

        let displayed = read_to_string(&dir, "aaaaaaaaaaaaaaaa").unwrap();
        for forbidden in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}', '\u{061c}'] {
            assert!(
                !displayed.contains(forbidden),
                "raw {forbidden:?} in: {displayed}"
            );
        }
        assert!(displayed.contains("\\u{2028}"), "{displayed}");
        assert!(displayed.contains("\\u{2029}"), "{displayed}");
        assert!(displayed.contains("\\u{202e}"), "{displayed}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_utf8_command_arguments_are_omitted_from_the_header() {
        use std::os::unix::ffi::OsStringExt;

        let secrets = sample_secrets();
        let cmd = vec![
            OsString::from("psql"),
            OsString::from("-c"),
            OsString::from_vec(b"SELECT '\xff'; ALTER ROLE a PASSWORD 'synthetic-pw-raw'".to_vec()),
        ];
        let formatted = format_command(&cmd, &secrets);
        assert!(!formatted.contains("synthetic-pw-raw"), "{formatted}");
        assert!(!formatted.contains('\u{fffd}'), "{formatted}");
        assert!(formatted.contains("[omitted]"), "{formatted}");
    }

    #[test]
    fn copy_to_and_list_escape_unicode_separators_and_direction_overrides_already_in_a_log_file() {
        let dir = temp_runs_dir("unicode-preexisting");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("20261127T120000.000Z-bbbbbbbbbbbbbbbb.log");
        fs::write(
            &path,
            "run_id: bbbbbbbbbbbbbbbb\n\
             started_at: 2026-11-27T12:00:00Z\n\
             database: app\n\
             role: reader\n\
             valid_until: 2026-11-27T13:00:00Z\n\
             max_ttl: 60m\n\
             sql_log: enabled\n\
             command: psql -c 'hdr\u{202e}x\u{2028}y'\n\
             \n\
             2026-11-27T12:00:01Z [Q] SELECT 'body\u{2029}z\u{2066}w'\n",
        )
        .unwrap();

        let summaries = list_in(&dir).unwrap();
        assert_eq!(summaries.len(), 1);
        assert!(!summaries[0].command.contains('\u{202e}'));
        assert!(!summaries[0].command.contains('\u{2028}'));
        assert!(summaries[0].command.contains("\\u{202e}"));
        assert!(summaries[0].command.contains("\\u{2028}"));

        let displayed = read_to_string(&dir, "bbbbbbbbbbbbbbbb").unwrap();
        for forbidden in ['\u{2028}', '\u{2029}', '\u{202e}', '\u{2066}'] {
            assert!(
                !displayed.contains(forbidden),
                "raw {forbidden:?} in: {displayed}"
            );
        }
        assert!(displayed.contains("\\u{2029}"), "{displayed}");
        assert!(displayed.contains("\\u{2066}"), "{displayed}");
        let _ = fs::remove_dir_all(&dir);
    }
}
