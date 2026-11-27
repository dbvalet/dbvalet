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

const RUNS_SUBDIR: &str = "runs";
const LOG_EXTENSION: &str = ".log";
const DIR_MODE_OWNER_ONLY: u32 = 0o700;
const FILE_MODE_OWNER_ONLY: u32 = 0o600;
const MAX_RECENT_RUNS: usize = 50;
const MAX_HEADER_LINES: usize = 32;
const MAX_REDACT_DEPTH: usize = 4;
const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_MINUTE: u64 = 60;
const REDACTED_LITERAL: &str = "'[REDACTED]'";
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

/// Keeps text through the first case-insensitive `password` or `connection` in `arg` and
/// replaces the remainder with `[REDACTED]`. Returns whether the keyword stood at the end
/// of `arg` (such as `--password`), meaning the next argv element should also be redacted.
fn redact_after_secret_keyword(arg: &str) -> (String, bool) {
    let lower = arg.to_ascii_lowercase();
    let earliest = ["password", "connection"]
        .into_iter()
        .filter_map(|kw| lower.find(kw).map(|pos| (pos, kw.len())))
        .min_by_key(|&(pos, _)| pos);
    let Some((pos, kw_len)) = earliest else {
        if !arg.contains("://")
            && arg.contains('%')
            && percent_decode_bytes(arg).is_some_and(|decoded| {
                let decoded_lower = String::from_utf8_lossy(&decoded).to_ascii_lowercase();
                decoded_lower.contains("password") || decoded_lower.contains("connection")
            })
        {
            return (REDACTED_SECRET.to_owned(), false);
        }
        return (arg.to_owned(), false);
    };
    let after = pos + kw_len;
    let rest = &arg[after..];
    if rest.is_empty() {
        return (arg.to_owned(), true);
    }
    if rest.starts_with('=') || rest.starts_with(':') {
        return (format!("{}{}", &arg[..after + 1], REDACTED_SECRET), false);
    }
    (format!("{} {}", &arg[..after], REDACTED_SECRET), false)
}

/// Replaces `scheme://user:SECRET@` userinfo passwords and query parameters whose
/// percent-decoded key ends in `password` (or has malformed `%` escapes) with `[REDACTED]`.
fn redact_uri_passwords(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(rel_sep) = text[cursor..].find("://") {
        let authority_start = cursor + rel_sep + 3;
        out.push_str(&text[cursor..authority_start]);
        let rest = &text[authority_start..];
        // Stop before any following `://` as well as `/` or whitespace so a pathless URI
        // never swallows the scheme separator of a second URI in the same argument or string.
        let authority_end = [
            rest.find(|c: char| c.is_whitespace() || c == '\x0b' || c == '/'),
            rest.find("://"),
        ]
        .into_iter()
        .flatten()
        .min()
        .map_or(text.len(), |offset| authority_start + offset);
        let authority = &text[authority_start..authority_end];
        if let Some(at) = authority.rfind('@') {
            let userinfo = &authority[..at];
            if let Some(colon) = userinfo.find(':') {
                out.push_str(&userinfo[..colon + 1]);
                out.push_str(REDACTED_SECRET);
            } else {
                out.push_str(userinfo);
            }
            redact_host_and_query(&authority[at..], &mut out);
        } else {
            redact_host_and_query(authority, &mut out);
        }
        cursor = authority_end;
        if text[cursor..].starts_with('/') {
            let tail_rest = &text[cursor..];
            let tail_end = [
                tail_rest.find(|c: char| {
                    c.is_whitespace() || matches!(c, '\x0b' | '\'' | '"' | ')' | ',' | ';')
                }),
                tail_rest.find("://"),
            ]
            .into_iter()
            .flatten()
            .min()
            .map_or(text.len(), |offset| cursor + offset);
            redact_host_and_query(&text[cursor..tail_end], &mut out);
            cursor = tail_end;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

fn redact_host_and_query(segment: &str, out: &mut String) {
    let Some((before_q, after_q)) = segment.split_once('?') else {
        out.push_str(segment);
        return;
    };
    out.push_str(before_q);
    out.push('?');
    let query_end = after_q
        .find(['\'', '"', ')', ',', ';'])
        .unwrap_or(after_q.len());
    redact_uri_query(&after_q[..query_end], out);
    out.push_str(&after_q[query_end..]);
}

fn redact_uri_query(query: &str, out: &mut String) {
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        if let Some((key, _val)) = pair.split_once('=')
            && uri_query_key_is_secret(key)
        {
            out.push_str(key);
            out.push('=');
            out.push_str(REDACTED_SECRET);
        } else {
            out.push_str(pair);
        }
    }
}

fn uri_query_key_is_secret(key: &str) -> bool {
    match percent_decode_bytes(key) {
        Some(decoded) => {
            let lower: Vec<u8> = decoded.iter().map(u8::to_ascii_lowercase).collect();
            lower.ends_with(b"password") || lower == b"connection"
        }
        // Malformed percent-encoding in a query key fails closed.
        None => true,
    }
}

fn percent_decode_bytes(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex_nibble(*bytes.get(i + 1)?)?;
            let lo = hex_nibble(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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

/// Best-effort lexical redaction of password and connection-string literals in PostgreSQL SQL.
fn redact_sql(sql: &str) -> String {
    redact_sql_inner(sql, 0)
}

#[derive(Default)]
struct TemplateCues {
    has_ddl: bool,
    has_target: bool,
    has_secret_word: bool,
}

impl TemplateCues {
    fn record(&mut self, text: &str) {
        let lower = text.to_ascii_lowercase();
        if contains_ascii_word(&lower, "alter") || contains_ascii_word(&lower, "create") {
            self.has_ddl = true;
        }
        if contains_ascii_word(&lower, "role")
            || contains_ascii_word(&lower, "user")
            || contains_ascii_word(&lower, "group")
            || contains_ascii_word(&lower, "server")
            || contains_ascii_word(&lower, "mapping")
            || contains_ascii_word(&lower, "subscription")
        {
            self.has_target = true;
        }
        if contains_secret_word(&lower) {
            self.has_secret_word = true;
        }
    }

    fn is_complete(&self) -> bool {
        self.has_ddl && self.has_target && self.has_secret_word
    }
}

fn redact_sql_inner(sql: &str, depth: usize) -> String {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut expect_secret_literal = false;
    let mut redact_statement_literals = false;
    let mut template_cues = TemplateCues::default();
    let mut pos = 0;

    while pos < len {
        let byte = bytes[pos];

        if is_pg_whitespace(byte) {
            let start = pos;
            while pos < len && is_pg_whitespace(bytes[pos]) {
                pos += 1;
            }
            out.push_str(&sql[start..pos]);
            continue;
        }

        if byte == b'-' && bytes.get(pos + 1) == Some(&b'-') {
            let start = pos;
            pos = scan_line_comment(bytes, pos);
            out.push_str(&sql[start..pos]);
            continue;
        }

        if byte == b'/' && bytes.get(pos + 1) == Some(&b'*') {
            let start = pos;
            pos = scan_block_comment(bytes, pos);
            out.push_str(&sql[start..pos]);
            continue;
        }

        if let Some((prefix_len, is_escape_string)) = quoted_string_prefix(bytes, pos) {
            let redacting = expect_secret_literal || redact_statement_literals;
            let body_start = pos + prefix_len;
            let end = if is_escape_string {
                scan_quoted_string(sql, body_start, true)
            } else {
                // Scan under both `standard_conforming_strings = on` and `off`. If they disagree,
                // a backslash before a quote makes the boundary ambiguous; redact the rest of the
                // input whenever credentials could follow so neither server setting can leak.
                let end_std = scan_quoted_string(sql, body_start, false);
                let end_esc = scan_quoted_string(sql, body_start, true);
                if end_std != end_esc && (redacting || contains_potential_secret_cue(&sql[pos..])) {
                    out.push_str(REDACTED_LITERAL);
                    break;
                }
                end_std
            };
            if redacting {
                out.push_str(REDACTED_LITERAL);
                pos = if expect_secret_literal {
                    skip_continued_quoted_literals(sql, end)
                } else {
                    end
                };
                expect_secret_literal = false;
            } else {
                let slice = &sql[pos..end];
                if depth < MAX_REDACT_DEPTH {
                    if let Some(unescaped) = unescape_single_quoted_for_cues(slice) {
                        template_cues.record(&unescaped);
                        if template_cues.is_complete() {
                            redact_statement_literals = true;
                        }
                    }
                    let redacted = redact_single_quoted_content(slice, depth + 1);
                    out.push_str(&redacted);
                } else {
                    // Fail closed past the recursion limit so deeply nested SQL cannot hide secrets.
                    out.push_str(REDACTED_LITERAL);
                }
                pos = end;
            }
            continue;
        }

        if byte == b'$'
            && let Some(delimiter_len) = dollar_quote_delimiter_len(bytes, pos)
        {
            let (end, closed) = scan_dollar_string(bytes, pos, delimiter_len);
            if expect_secret_literal || redact_statement_literals {
                out.push_str(REDACTED_LITERAL);
                expect_secret_literal = false;
            } else if depth < MAX_REDACT_DEPTH {
                let delimiter = &sql[pos..pos + delimiter_len];
                let body_end = if closed { end - delimiter_len } else { end };
                let body = &sql[pos + delimiter_len..body_end];
                template_cues.record(body);
                if template_cues.is_complete() {
                    redact_statement_literals = true;
                }
                let body = redact_sql_inner(body, depth + 1);
                let body = redact_embedded_credentials(&body);
                out.push_str(delimiter);
                out.push_str(&body);
                if closed {
                    out.push_str(delimiter);
                }
            } else {
                // Fail closed past the recursion limit so deeply nested SQL cannot hide secrets.
                out.push_str(REDACTED_LITERAL);
            }
            pos = end;
            continue;
        }

        if byte == b'"' {
            let start = pos;
            pos = scan_double_quoted_ident(bytes, pos);
            let slice = &sql[start..pos];
            out.push_str(slice);
            expect_secret_literal = unquoted_ident_is_secret_key(slice);
            continue;
        }

        if is_ident_start(byte) {
            let start = pos;
            pos += 1;
            while pos < len && is_ident_continue(bytes[pos]) {
                pos += 1;
            }
            let word = &sql[start..pos];
            out.push_str(word);
            expect_secret_literal = word_is_secret_key(word);
            continue;
        }

        if byte == b';' {
            expect_secret_literal = false;
            redact_statement_literals = false;
            template_cues = TemplateCues::default();
            out.push(';');
            pos += 1;
            continue;
        }

        expect_secret_literal = false;
        let ch_len = sql[pos..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&sql[pos..pos + ch_len]);
        pos += ch_len;
    }

    out
}

fn unescape_single_quoted_for_cues(slice: &str) -> Option<String> {
    let (prefix_len, _) = quoted_string_prefix(slice.as_bytes(), 0)?;
    let body = slice.get(prefix_len..)?;
    let inner = body.strip_suffix('\'').unwrap_or(body);
    Some(inner.replace("''", "'"))
}

fn contains_potential_secret_cue(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("password") || lower.contains("connection") || text.contains("://")
}

fn word_is_secret_key(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    lower.ends_with("password") || lower == "connection"
}

fn unquoted_ident_is_secret_key(quoted: &str) -> bool {
    let Some(inner) = quoted.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return false;
    };
    word_is_secret_key(&inner.replace("\"\"", "\""))
}

/// Redacts embedded credentials (conninfo `password=...`, URI userinfo/query passwords, or
/// nested SQL `PASSWORD` clauses) inside a single-quoted string literal.
fn redact_single_quoted_content(slice: &str, depth: usize) -> String {
    let Some(inner) = slice.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) else {
        return redact_embedded_credentials(slice);
    };
    let lower = inner.to_ascii_lowercase();
    let has_keyword = lower.contains("password") || lower.contains("connection");
    let has_uri = inner.contains("://");
    if !has_keyword && !has_uri {
        return slice.to_owned();
    }
    let unescaped = inner.replace("''", "'");
    let mut redacted = if has_keyword {
        redact_sql_inner(&unescaped, depth)
    } else {
        unescaped.clone()
    };
    redacted = redact_embedded_credentials(&redacted);
    if redacted == unescaped {
        return slice.to_owned();
    }
    format!("'{}'", redacted.replace('\'', "''"))
}

fn contains_secret_word(lower: &str) -> bool {
    contains_ascii_word(lower, "connection") || contains_word_ending_with(lower, "password")
}

fn contains_word_ending_with(haystack: &str, suffix: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(suffix) {
        let pos = start + offset;
        let end = pos + suffix.len();
        let after_ok = end == bytes.len() || !is_ident_continue(bytes[end]);
        if after_ok {
            return true;
        }
        start = end;
    }
    false
}

fn contains_ascii_word(haystack: &str, word: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(word) {
        let pos = start + offset;
        let end = pos + word.len();
        let before_ok = pos == 0 || !is_ident_continue(bytes[pos - 1]);
        let after_ok = end == bytes.len() || !is_ident_continue(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        start = end;
    }
    false
}

/// Redacts URI userinfo/query passwords and libpq conninfo `password=` / `*password=` values.
fn redact_embedded_credentials(text: &str) -> String {
    let with_uris = if text.contains("://") {
        redact_uri_passwords(text)
    } else {
        text.to_owned()
    };
    if with_uris.to_ascii_lowercase().contains("password") {
        redact_conninfo_passwords(&with_uris)
    } else {
        with_uris
    }
}

/// Replaces `password=<val>` and `*password=<val>` (bare or single-quoted) in libpq conninfo
/// strings such as those passed to `dblink` or `dblink_connect`.
fn redact_conninfo_passwords(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut pos = 0;

    while pos < len {
        // libpq conninfo parameter names are strictly ASCII; non-ASCII text falls through
        // to the UTF-8 character step below so slicing never splits a multi-byte character.
        if bytes[pos].is_ascii_alphabetic() || bytes[pos] == b'_' {
            let start = pos;
            pos += 1;
            while pos < len && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_') {
                pos += 1;
            }
            let word = &text[start..pos];
            out.push_str(word);
            if word.to_ascii_lowercase().ends_with("password") {
                let mut cursor = pos;
                while cursor < len && is_pg_whitespace(bytes[cursor]) {
                    cursor += 1;
                }
                if cursor < len && bytes[cursor] == b'=' {
                    cursor += 1;
                    while cursor < len && is_pg_whitespace(bytes[cursor]) {
                        cursor += 1;
                    }
                    out.push_str(&text[pos..cursor]);
                    if cursor < len {
                        if bytes[cursor] == b'\'' {
                            pos = scan_quoted_string(text, cursor + 1, true);
                        } else {
                            let mut val_end = cursor;
                            while val_end < len {
                                if bytes[val_end] == b'\\' {
                                    val_end += 1;
                                    if val_end < len {
                                        val_end += text[val_end..]
                                            .chars()
                                            .next()
                                            .map_or(1, char::len_utf8);
                                    }
                                    continue;
                                }
                                if is_pg_whitespace(bytes[val_end]) {
                                    break;
                                }
                                val_end += text[val_end..].chars().next().map_or(1, char::len_utf8);
                            }
                            pos = val_end;
                        }
                        out.push_str(REDACTED_SECRET);
                    } else {
                        pos = cursor;
                    }
                }
            }
            continue;
        }
        let ch_len = text[pos..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&text[pos..pos + ch_len]);
        pos += ch_len;
    }

    out
}

fn quoted_string_prefix(bytes: &[u8], pos: usize) -> Option<(usize, bool)> {
    match bytes[pos] {
        b'\'' => Some((1, false)),
        b'E' | b'e' if bytes.get(pos + 1) == Some(&b'\'') => Some((2, true)),
        b'N' | b'n' if bytes.get(pos + 1) == Some(&b'\'') => Some((2, false)),
        b'U' | b'u' if bytes.get(pos + 1) == Some(&b'&') && bytes.get(pos + 2) == Some(&b'\'') => {
            Some((3, false))
        }
        _ => None,
    }
}

/// Skips PostgreSQL newline-separated string literal continuations after a redacted literal.
fn skip_continued_quoted_literals(sql: &str, mut pos: usize) -> usize {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    loop {
        let mut cursor = pos;
        let mut saw_newline = false;
        while cursor < len {
            let byte = bytes[cursor];
            if is_pg_whitespace(byte) {
                if matches!(byte, b'\n' | b'\r') {
                    saw_newline = true;
                }
                cursor += 1;
            } else if byte == b'-' && bytes.get(cursor + 1) == Some(&b'-') {
                let end = scan_line_comment(bytes, cursor);
                if bytes[cursor..end]
                    .iter()
                    .any(|&b| matches!(b, b'\n' | b'\r'))
                {
                    saw_newline = true;
                }
                cursor = end;
            } else if byte == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
                let end = scan_block_comment(bytes, cursor);
                if bytes[cursor..end]
                    .iter()
                    .any(|&b| matches!(b, b'\n' | b'\r'))
                {
                    saw_newline = true;
                }
                cursor = end;
            } else {
                break;
            }
        }
        if saw_newline
            && cursor < len
            && let Some((prefix_len, is_escape_string)) = quoted_string_prefix(bytes, cursor)
        {
            let body_start = cursor + prefix_len;
            if is_escape_string {
                pos = scan_quoted_string(sql, body_start, true);
            } else {
                let end_std = scan_quoted_string(sql, body_start, false);
                let end_esc = scan_quoted_string(sql, body_start, true);
                if end_std != end_esc {
                    return len;
                }
                pos = end_std;
            }
            continue;
        }
        return pos;
    }
}

fn scan_line_comment(bytes: &[u8], mut pos: usize) -> usize {
    let len = bytes.len();
    pos += 2;
    while pos < len {
        // PostgreSQL ends `--` comments at either LF or lone CR (`scan.l`).
        if matches!(bytes[pos], b'\n' | b'\r') {
            return pos + 1;
        }
        pos += 1;
    }
    pos
}

fn scan_block_comment(bytes: &[u8], mut pos: usize) -> usize {
    let len = bytes.len();
    pos += 2;
    let mut depth = 1usize;
    while pos < len && depth > 0 {
        if bytes[pos] == b'/' && bytes.get(pos + 1) == Some(&b'*') {
            depth += 1;
            pos += 2;
        } else if bytes[pos] == b'*' && bytes.get(pos + 1) == Some(&b'/') {
            depth -= 1;
            pos += 2;
        } else {
            pos += 1;
        }
    }
    pos
}

fn scan_double_quoted_ident(bytes: &[u8], mut pos: usize) -> usize {
    let len = bytes.len();
    pos += 1;
    while pos < len {
        if bytes[pos] == b'"' {
            pos += 1;
            if bytes.get(pos) == Some(&b'"') {
                pos += 1;
                continue;
            }
            break;
        }
        pos += 1;
    }
    pos
}

fn scan_dollar_string(bytes: &[u8], pos: usize, delimiter_len: usize) -> (usize, bool) {
    let len = bytes.len();
    let delimiter = &bytes[pos..pos + delimiter_len];
    let mut cursor = pos + delimiter_len;
    while cursor + delimiter_len <= len {
        if &bytes[cursor..cursor + delimiter_len] == delimiter {
            return (cursor + delimiter_len, true);
        }
        cursor += 1;
    }
    (len, false)
}

fn scan_quoted_string(sql: &str, mut pos: usize, backslash_escapes: bool) -> usize {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    while pos < len {
        let byte = bytes[pos];
        if backslash_escapes && byte == b'\\' {
            pos += 1;
            if pos < len {
                pos += sql[pos..].chars().next().map_or(1, char::len_utf8);
            }
            continue;
        }
        if byte == b'\'' {
            pos += 1;
            if bytes.get(pos) == Some(&b'\'') {
                pos += 1;
                continue;
            }
            break;
        }
        pos += sql[pos..].chars().next().map_or(1, char::len_utf8);
    }
    pos
}

/// PostgreSQL (`scan.l`) and libpq (`isspace`) treat vertical tab `0x0B` as whitespace,
/// unlike Rust's `u8::is_ascii_whitespace`.
fn is_pg_whitespace(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == 0x0B
}

/// Returns the byte length of a PostgreSQL `$tag$` delimiter at `pos`, or `None` for
/// positional parameters like `$1` or a stray `$`.
fn dollar_quote_delimiter_len(bytes: &[u8], pos: usize) -> Option<usize> {
    let len = bytes.len();
    let next = *bytes.get(pos + 1)?;
    if next == b'$' {
        return Some(2);
    }
    if !is_ident_start(next) {
        return None;
    }
    let mut cursor = pos + 2;
    while cursor < len {
        let byte = bytes[cursor];
        if byte == b'$' {
            return Some(cursor - pos + 1);
        }
        if !(byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80) {
            return None;
        }
        cursor += 1;
    }
    None
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte >= 0x80
}

fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
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
    fn alter_and_create_role_passwords_are_redacted_across_literal_styles() {
        assert_eq!(
            redact_sql("ALTER ROLE alice PASSWORD 'hunter2'"),
            "ALTER ROLE alice PASSWORD '[REDACTED]'"
        );
        assert_eq!(
            redact_sql(
                "CREATE ROLE bob WITH ENCRYPTED PASSWORD 'it''s secret' VALID UNTIL '2026-12-01'"
            ),
            "CREATE ROLE bob WITH ENCRYPTED PASSWORD '[REDACTED]' VALID UNTIL '2026-12-01'"
        );
        assert_eq!(
            redact_sql("ALTER USER carol PASSWORD $$dollar'secret$$"),
            "ALTER USER carol PASSWORD '[REDACTED]'"
        );
        assert_eq!(
            redact_sql("ALTER USER carol PASSWORD $tag$tagged secret$tag$"),
            "ALTER USER carol PASSWORD '[REDACTED]'"
        );
        assert_eq!(
            redact_sql("ALTER ROLE dave PASSWORD E'esc\\'aped\\\\pw'"),
            "ALTER ROLE dave PASSWORD '[REDACTED]'"
        );
        assert_eq!(
            redact_sql("ALTER ROLE eve PASSWORD U&'sec\\0072et'"),
            "ALTER ROLE eve PASSWORD '[REDACTED]'"
        );
    }

    #[test]
    fn passwords_with_comments_line_continuations_or_unterminated_quotes_are_redacted() {
        assert_eq!(
            redact_sql(
                "ALTER /* c1 /* nested */ */ ROLE alice -- c2\nPASSWORD /* c3 */ 'part1'\n'part2'"
            ),
            "ALTER /* c1 /* nested */ */ ROLE alice -- c2\nPASSWORD /* c3 */ '[REDACTED]'"
        );
        assert_eq!(
            redact_sql("ALTER ROLE alice PASSWORD 'unterminated-secret"),
            "ALTER ROLE alice PASSWORD '[REDACTED]'"
        );
    }

    #[test]
    fn user_mapping_subscription_connection_and_do_block_passwords_are_redacted() {
        assert_eq!(
            redact_sql(
                "CREATE USER MAPPING FOR alice SERVER s OPTIONS (user 'u', password 'fdw-pw')"
            ),
            "CREATE USER MAPPING FOR alice SERVER s OPTIONS (user 'u', password '[REDACTED]')"
        );
        assert_eq!(
            redact_sql(
                "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (password 'srv-pw', sslpassword 'srv-ssl-pw')"
            ),
            "CREATE SERVER s FOREIGN DATA WRAPPER postgres_fdw OPTIONS (password '[REDACTED]', sslpassword '[REDACTED]')"
        );
        assert_eq!(
            redact_sql(
                "CREATE SUBSCRIPTION sub CONNECTION 'host=db password=rep-pw' PUBLICATION pub"
            ),
            "CREATE SUBSCRIPTION sub CONNECTION '[REDACTED]' PUBLICATION pub"
        );
        assert_eq!(
            redact_sql("ALTER SUBSCRIPTION sub CONNECTION 'host=db password=rep-pw-2'"),
            "ALTER SUBSCRIPTION sub CONNECTION '[REDACTED]'"
        );
        assert_eq!(
            redact_sql("DO $$ BEGIN ALTER ROLE alice PASSWORD 'do-block-pw'; END $$;"),
            "DO $$ BEGIN ALTER ROLE alice PASSWORD '[REDACTED]'; END $$;"
        );
        assert_eq!(
            redact_sql("DO $$ BEGIN EXECUTE 'ALTER ROLE alice PASSWORD ''exec-pw'''; END $$;"),
            "DO $$ BEGIN EXECUTE 'ALTER ROLE alice PASSWORD ''[REDACTED]'''; END $$;"
        );
        assert_eq!(
            redact_sql("SELECT 'forgot my password'"),
            "SELECT 'forgot my password'"
        );
    }

    #[test]
    fn format_quote_literal_dblink_sslpassword_and_nonstandard_escapes_are_redacted() {
        let cases = [
            (
                "DO $$ BEGIN EXECUTE format('ALTER ROLE a PASSWORD %L', 'pw-format-03'); END $$",
                "pw-format-03",
            ),
            (
                "DO $$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD ' || quote_literal('pw-concat-04'); END $$",
                "pw-concat-04",
            ),
            (
                "SELECT dblink_connect('c', 'host=h user=u password=pw-dblink-05')",
                "pw-dblink-05",
            ),
            (
                "SELECT dblink('postgresql://u:pw-uri-07@host/db', 'SELECT 1')",
                "pw-uri-07",
            ),
            (
                "SET standard_conforming_strings = off; ALTER ROLE a PASSWORD 'ab\\'pw-scs-02'",
                "pw-scs-02",
            ),
            (
                "CREATE USER MAPPING FOR a SERVER s OPTIONS (sslpassword 'pw-ssl-06')",
                "pw-ssl-06",
            ),
        ];
        for (sql, leaked) in cases {
            let redacted = redact_sql(sql);
            assert!(
                !redacted.contains(leaked),
                "input: {sql}\nredacted: {redacted}"
            );
            assert!(
                redacted.contains("[REDACTED]"),
                "input: {sql}\nredacted: {redacted}"
            );
        }
    }

    #[test]
    fn non_password_sql_and_password_null_are_preserved() {
        assert_eq!(redact_sql("SELECT 1"), "SELECT 1");
        assert_eq!(
            redact_sql("SELECT password FROM users WHERE name = 'alice'"),
            "SELECT password FROM users WHERE name = 'alice'"
        );
        assert_eq!(
            redact_sql("ALTER ROLE alice PASSWORD NULL"),
            "ALTER ROLE alice PASSWORD NULL"
        );
        assert_eq!(
            redact_sql("SELECT 1; ALTER ROLE a PASSWORD 's1'; SELECT 2"),
            "SELECT 1; ALTER ROLE a PASSWORD '[REDACTED]'; SELECT 2"
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
    fn backslash_passwords_are_redacted_under_both_standard_and_nonstandard_strings() {
        let cases = [
            ("ALTER ROLE a PASSWORD 'ab\\''pw-tail-71'", "pw-tail-71"),
            (
                "ALTER ROLE a PASSWORD 'pw-1\\'; ALTER ROLE b PASSWORD 'pw-second-47'",
                "pw-second-47",
            ),
            (
                "CREATE ROLE a LOGIN PASSWORD 'x\\' VALID UNTIL 'infinity'; ALTER ROLE b PASSWORD 'pw-72'",
                "pw-72",
            ),
            ("SELECT '\\''; ALTER ROLE a PASSWORD 'pw-48'; -- '", "pw-48"),
        ];
        for (sql, leaked) in cases {
            let redacted = redact_sql(sql);
            assert!(
                !redacted.contains(leaked),
                "input: {sql}\nredacted: {redacted}"
            );
            assert!(
                redacted.contains("[REDACTED]"),
                "input: {sql}\nredacted: {redacted}"
            );
        }
        assert_eq!(redact_sql("SELECT 'C:\\'"), "SELECT 'C:\\'");
    }

    #[test]
    fn dollar_quoted_format_uri_delimiters_and_escaped_conninfo_spaces_are_redacted() {
        let cases = [
            (
                "DO $f$ BEGIN EXECUTE format($q$ALTER ROLE a PASSWORD %L$q$, 'pw-41'); END $f$",
                "pw-41",
            ),
            (
                "SELECT dblink('postgresql://u:pw?q#r''s@h/db', 'SELECT 1')",
                "pw?q",
            ),
            (
                "SELECT dblink_connect('c', 'host=h password=ab\\ pw-53 dbname=d')",
                "pw-53",
            ),
        ];
        for (sql, leaked) in cases {
            let redacted = redact_sql(sql);
            assert!(
                !redacted.contains(leaked),
                "input: {sql}\nredacted: {redacted}"
            );
            assert!(
                redacted.contains("[REDACTED]"),
                "input: {sql}\nredacted: {redacted}"
            );
        }
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
    fn a_second_uri_without_whitespace_in_a_sql_literal_is_redacted() {
        assert_eq!(
            redact_sql("SELECT 'postgresql://a,postgresql://u:pw-r2-11@h/db'"),
            "SELECT 'postgresql://a,postgresql://u:[REDACTED]@h/db'"
        );
        assert_eq!(
            redact_sql("SELECT 'postgresql://u1:pw1@h1,postgresql://u2:pw2@h2/db'"),
            "SELECT 'postgresql://u1:[REDACTED]@h1,postgresql://u2:[REDACTED]@h2/db'"
        );
    }

    #[test]
    fn a_non_ascii_character_after_password_in_a_literal_does_not_panic() {
        assert_eq!(
            redact_sql("SELECT 'Forgot your password? Réinitialisez-le'"),
            "SELECT 'Forgot your password? Réinitialisez-le'"
        );
        assert_eq!(
            redact_sql("SELECT 'password — em dash'"),
            "SELECT 'password — em dash'"
        );
        assert_eq!(
            redact_sql("ALTER ROLE alice PASSWORD E'a\\é'"),
            "ALTER ROLE alice PASSWORD '[REDACTED]'"
        );
        assert_eq!(
            redact_sql("SELECT dblink_connect('c', 'host=h password=a\\é dbname=d')"),
            "SELECT dblink_connect('c', 'host=h password=[REDACTED] dbname=d')"
        );
    }

    #[test]
    fn a_line_comment_ended_by_a_carriage_return_still_redacts_the_following_password() {
        let redacted = redact_sql("ALTER ROLE CURRENT_USER PASSWORD -- note\r'synthetic-pw-cr'");
        assert!(!redacted.contains("synthetic-pw-cr"), "{redacted}");
        assert!(redacted.contains("[REDACTED]"), "{redacted}");
    }

    #[test]
    fn a_vertical_tab_between_password_and_the_literal_is_redacted() {
        let redacted = redact_sql("ALTER ROLE CURRENT_USER PASSWORD\x0b'synthetic-pw-vt'");
        assert!(!redacted.contains("synthetic-pw-vt"), "{redacted}");
        assert!(redacted.contains("[REDACTED]"), "{redacted}");
    }

    #[test]
    fn deeply_nested_dollar_quoted_blocks_fail_closed() {
        let sql = "DO $a$ BEGIN EXECUTE $b$ DO $c$ BEGIN EXECUTE $d$ \
                   DO $e$ BEGIN ALTER ROLE CURRENT_USER PASSWORD 'synthetic-pw-deep'; END $e$ \
                   $d$; END $c$ $b$; END $a$";
        let redacted = redact_sql(sql);
        assert!(!redacted.contains("synthetic-pw-deep"), "{redacted}");
        assert!(redacted.contains("[REDACTED]"), "{redacted}");
    }

    #[test]
    fn conninfo_passwords_with_newlines_around_equals_are_redacted() {
        let after_eq = redact_sql(
            "SELECT dblink_connect('c', 'host=localhost user=u password=\n  synthetic-pw-nl1')",
        );
        assert!(!after_eq.contains("synthetic-pw-nl1"), "{after_eq}");
        assert!(after_eq.contains("[REDACTED]"), "{after_eq}");

        let before_eq = redact_sql(
            "SELECT dblink_connect('c', 'host=localhost user=u password\n = synthetic-pw-nl2')",
        );
        assert!(!before_eq.contains("synthetic-pw-nl2"), "{before_eq}");
        assert!(before_eq.contains("[REDACTED]"), "{before_eq}");
    }

    #[test]
    fn a_role_password_template_split_across_concatenated_literals_is_redacted() {
        let sql = "DO $$ BEGIN EXECUTE 'ALTER ROLE ' || quote_ident(current_user) \
                   || ' PASSWORD ' || quote_literal('synthetic-pw-split'); END $$";
        let redacted = redact_sql(sql);
        assert!(!redacted.contains("synthetic-pw-split"), "{redacted}");
        assert!(redacted.contains("[REDACTED]"), "{redacted}");
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
