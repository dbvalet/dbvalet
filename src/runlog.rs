//! Local per-run plain-text log files under `$XDG_STATE_HOME/dbvalet/runs/` (or
//! `~/.local/state/dbvalet/runs/`).
//!
//! ## How password-bearing SQL statements are shown
//!
//! Before a statement (from a simple-query `Q` frame or an extended-protocol `P` parse frame)
//! or a header `command` line is written to disk:
//! - Any SQL string literal following `PASSWORD` (for example in `ALTER ROLE ... PASSWORD '...'`,
//!   `CREATE ROLE ... WITH ENCRYPTED PASSWORD $$...$$`, `ALTER USER ... PASSWORD E'...'`,
//!   or `CREATE USER MAPPING ... OPTIONS (password '...')`) is replaced with `'[REDACTED]'`.
//!   Non-literal forms such as `ALTER ROLE ... PASSWORD NULL` and column references such as
//!   `SELECT password FROM users` are left intact.
//! - Any SQL string literal following `CONNECTION` (such as `CREATE SUBSCRIPTION ... CONNECTION '...'`)
//!   is replaced with `'[REDACTED]'`.
//! - Dollar-quoted SQL blocks (such as `DO $$ ... $$`) are redacted recursively so embedded
//!   `ALTER ROLE ... PASSWORD` statements are also redacted.
//! - Every occurrence of the run token or the temporary login's password is replaced with
//!   `[REDACTED]`, even outside a `PASSWORD` clause.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secrecy::{ExposeSecret, SecretString};

use crate::DatabaseAlias;

const STATE_APP_DIR: &str = "dbvalet";
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    Query,
    Parse,
}

impl StatementKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Query => "Q",
            Self::Parse => "P",
        }
    }
}

#[derive(Debug, Clone)]
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
    #[error("can't find the state directory: neither XDG_STATE_HOME nor HOME is set")]
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

pub fn read(run_id: &str) -> Result<String, RunLogError> {
    let dir = default_runs_dir()?;
    read_in(&dir, run_id)
}

impl RunLog {
    /// Redacts passwords and runtime secrets from `sql`, normalizes it onto one line,
    /// and writes it to the run log file.
    pub fn statement(&self, kind: StatementKind, sql: &str) {
        if sql.trim().is_empty() {
            return;
        }
        let redacted = redact_sql(sql);
        let scrubbed = self.inner.secrets.scrub(&redacted);
        let single_line = sanitize_single_line(&scrubbed);
        if single_line.trim().is_empty() {
            return;
        }
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

fn default_runs_dir() -> Result<PathBuf, RunLogError> {
    let xdg = std::env::var_os("XDG_STATE_HOME");
    let home = std::env::var_os("HOME");
    resolve_runs_dir(xdg.as_deref(), home.as_deref())
}

fn resolve_runs_dir(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Result<PathBuf, RunLogError> {
    if let Some(xdg) = xdg.filter(|value| !value.is_empty()) {
        let path = Path::new(xdg);
        if path.is_absolute() {
            return Ok(path.join(STATE_APP_DIR).join(RUNS_SUBDIR));
        }
    }
    let home = home
        .filter(|value| !value.is_empty())
        .ok_or(RunLogError::NoStateDir)?;
    Ok(Path::new(home)
        .join(".local")
        .join("state")
        .join(STATE_APP_DIR)
        .join(RUNS_SUBDIR))
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
    let command = format_command(&header.command, secrets);
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

fn format_command(command: &[OsString], secrets: &RunSecrets) -> String {
    command
        .iter()
        .map(|arg| {
            let lossy = arg.to_string_lossy();
            let redacted = redact_sql_inner(&lossy, 0, true);
            let scrubbed = secrets.scrub(&redacted);
            let single_line = sanitize_single_line(&scrubbed);
            quote_command_arg(&single_line)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_command_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_owned();
    }
    let needs_quoting = arg.bytes().any(|b| {
        !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'+'))
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

fn read_in(dir: &Path, requested_run_id: &str) -> Result<String, RunLogError> {
    let normalized = requested_run_id
        .strip_prefix("dbvalet_")
        .unwrap_or(requested_run_id);
    if !is_valid_run_id(normalized) {
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
    fs::read_to_string(&path).map_err(|source| RunLogError::ReadFile { path, source })
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
    if !is_valid_timestamp_prefix(prefix) || !is_valid_run_id(run_id) {
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

fn is_valid_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
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
                "run_id" => run_id = value.to_owned(),
                "started_at" => started_at = value.to_owned(),
                "database" => database = value.to_owned(),
                "role" => role = value.to_owned(),
                "command" => command = value.to_owned(),
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

/// Replaces newlines and tabs with spaces and escapes other control characters so a
/// statement or command argument stays on one safe terminal line.
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
            c if c.is_control() => {
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

/// Redacts password and connection-string literals from PostgreSQL SQL text.
pub fn redact_sql(sql: &str) -> String {
    redact_sql_inner(sql, 0, false)
}

#[derive(Debug, Clone, Copy)]
enum TokenKind {
    Trivia { has_newline: bool },
    Word,
    QuotedIdent,
    StringLiteral,
    DollarString { delimiter_len: usize, closed: bool },
    Other,
}

#[derive(Debug, Clone, Copy)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
}

fn redact_sql_inner(sql: &str, depth: usize, redact_double_quoted: bool) -> String {
    let tokens = tokenize_sql(sql);
    let mut out = String::with_capacity(sql.len());
    let mut expect_secret_literal = false;
    let mut index = 0;

    while index < tokens.len() {
        let token = tokens[index];
        let slice = &sql[token.start..token.end];

        match token.kind {
            TokenKind::Trivia { .. } => {
                out.push_str(slice);
                index += 1;
            }
            TokenKind::StringLiteral if expect_secret_literal => {
                out.push_str(REDACTED_LITERAL);
                expect_secret_literal = false;
                index += 1;
                // PostgreSQL concatenates adjacent quoted string literals separated by
                // whitespace/comments containing a newline; redact the whole continuation.
                index = skip_continued_string_literals(&tokens, index);
            }
            TokenKind::DollarString { .. } if expect_secret_literal => {
                out.push_str(REDACTED_LITERAL);
                expect_secret_literal = false;
                index += 1;
            }
            TokenKind::Word => {
                out.push_str(slice);
                expect_secret_literal = slice.eq_ignore_ascii_case("PASSWORD")
                    || slice.eq_ignore_ascii_case("CONNECTION");
                index += 1;
            }
            TokenKind::QuotedIdent => {
                if redact_double_quoted && depth < MAX_REDACT_DEPTH && slice.len() >= 2 {
                    let inner = &slice[1..slice.len() - 1];
                    out.push('"');
                    out.push_str(&redact_sql_inner(inner, depth + 1, false));
                    if slice.ends_with('"') {
                        out.push('"');
                    }
                } else {
                    out.push_str(slice);
                }
                expect_secret_literal = unquoted_ident_is_password(slice);
                index += 1;
            }
            TokenKind::DollarString {
                delimiter_len,
                closed,
            } => {
                expect_secret_literal = false;
                if depth < MAX_REDACT_DEPTH && slice.len() >= delimiter_len {
                    let delimiter = &slice[..delimiter_len];
                    let body_end = if closed {
                        slice.len() - delimiter_len
                    } else {
                        slice.len()
                    };
                    let body = &slice[delimiter_len..body_end];
                    out.push_str(delimiter);
                    out.push_str(&redact_sql_inner(body, depth + 1, false));
                    if closed {
                        out.push_str(delimiter);
                    }
                } else {
                    out.push_str(slice);
                }
                index += 1;
            }
            TokenKind::StringLiteral => {
                expect_secret_literal = false;
                if depth < MAX_REDACT_DEPTH {
                    out.push_str(&redact_nested_single_quoted(
                        slice,
                        depth + 1,
                        redact_double_quoted,
                    ));
                } else {
                    out.push_str(slice);
                }
                index += 1;
            }
            TokenKind::Other => {
                expect_secret_literal = false;
                out.push_str(slice);
                index += 1;
            }
        }
    }

    out
}

fn skip_continued_string_literals(tokens: &[Token], mut index: usize) -> usize {
    loop {
        let mut lookahead = index;
        let mut saw_newline = false;
        while let Some(token) = tokens.get(lookahead) {
            match token.kind {
                TokenKind::Trivia { has_newline } => {
                    saw_newline |= has_newline;
                    lookahead += 1;
                }
                TokenKind::StringLiteral if saw_newline => {
                    index = lookahead + 1;
                    break;
                }
                _ => return index,
            }
        }
        if lookahead >= tokens.len() {
            return index;
        }
    }
}

fn unquoted_ident_is_password(quoted: &str) -> bool {
    let Some(inner) = quoted.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return false;
    };
    inner.replace("\"\"", "\"").eq_ignore_ascii_case("password")
}

/// Redacts password clauses embedded inside a single-quoted string literal, such as
/// `EXECUTE 'ALTER ROLE a PASSWORD ''secret'''` or a shell argument `'psql -c ...'`.
fn redact_nested_single_quoted(slice: &str, depth: usize, redact_double_quoted: bool) -> String {
    let Some(inner) = slice.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) else {
        return slice.to_owned();
    };
    let lower = inner.to_ascii_lowercase();
    if !lower.contains("password") && !lower.contains("connection") {
        return slice.to_owned();
    }
    let unescaped = inner.replace("''", "'");
    let redacted = redact_sql_inner(&unescaped, depth, redact_double_quoted);
    if redacted == unescaped {
        return slice.to_owned();
    }
    format!("'{}'", redacted.replace('\'', "''"))
}

fn tokenize_sql(sql: &str) -> Vec<Token> {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut tokens = Vec::new();
    let mut pos = 0;

    while pos < len {
        let byte = bytes[pos];

        if byte.is_ascii_whitespace() {
            let start = pos;
            let mut has_newline = false;
            while pos < len && bytes[pos].is_ascii_whitespace() {
                if matches!(bytes[pos], b'\n' | b'\r') {
                    has_newline = true;
                }
                pos += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Trivia { has_newline },
                start,
                end: pos,
            });
            continue;
        }

        if byte == b'-' && bytes.get(pos + 1) == Some(&b'-') {
            let start = pos;
            pos += 2;
            let mut has_newline = false;
            while pos < len {
                if bytes[pos] == b'\n' {
                    has_newline = true;
                    pos += 1;
                    break;
                }
                pos += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Trivia { has_newline },
                start,
                end: pos,
            });
            continue;
        }

        if byte == b'/' && bytes.get(pos + 1) == Some(&b'*') {
            let start = pos;
            pos += 2;
            let mut depth = 1usize;
            let mut has_newline = false;
            while pos < len && depth > 0 {
                if bytes[pos] == b'/' && bytes.get(pos + 1) == Some(&b'*') {
                    depth += 1;
                    pos += 2;
                } else if bytes[pos] == b'*' && bytes.get(pos + 1) == Some(&b'/') {
                    depth -= 1;
                    pos += 2;
                } else {
                    if matches!(bytes[pos], b'\n' | b'\r') {
                        has_newline = true;
                    }
                    pos += 1;
                }
            }
            tokens.push(Token {
                kind: TokenKind::Trivia { has_newline },
                start,
                end: pos,
            });
            continue;
        }

        if byte == b'\'' {
            let start = pos;
            pos = scan_quoted_string(bytes, pos + 1, false);
            tokens.push(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: pos,
            });
            continue;
        }

        if matches!(byte, b'E' | b'e' | b'N' | b'n') && bytes.get(pos + 1) == Some(&b'\'') {
            let start = pos;
            let backslash_escapes = matches!(byte, b'E' | b'e');
            pos = scan_quoted_string(bytes, pos + 2, backslash_escapes);
            tokens.push(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: pos,
            });
            continue;
        }

        if matches!(byte, b'U' | b'u')
            && bytes.get(pos + 1) == Some(&b'&')
            && bytes.get(pos + 2) == Some(&b'\'')
        {
            let start = pos;
            pos = scan_quoted_string(bytes, pos + 3, false);
            tokens.push(Token {
                kind: TokenKind::StringLiteral,
                start,
                end: pos,
            });
            continue;
        }

        if byte == b'$'
            && let Some(delimiter_len) = dollar_quote_delimiter_len(bytes, pos)
        {
            let start = pos;
            let delimiter = &bytes[pos..pos + delimiter_len];
            pos += delimiter_len;
            let mut closed = false;
            while pos + delimiter_len <= len {
                if &bytes[pos..pos + delimiter_len] == delimiter {
                    pos += delimiter_len;
                    closed = true;
                    break;
                }
                pos += 1;
            }
            if !closed {
                pos = len;
            }
            tokens.push(Token {
                kind: TokenKind::DollarString {
                    delimiter_len,
                    closed,
                },
                start,
                end: pos,
            });
            continue;
        }

        if byte == b'"' {
            let start = pos;
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
            tokens.push(Token {
                kind: TokenKind::QuotedIdent,
                start,
                end: pos,
            });
            continue;
        }

        if is_ident_start(byte) {
            let start = pos;
            pos += 1;
            while pos < len && is_ident_continue(bytes[pos]) {
                pos += 1;
            }
            tokens.push(Token {
                kind: TokenKind::Word,
                start,
                end: pos,
            });
            continue;
        }

        let start = pos;
        let ch_len = sql[pos..].chars().next().map_or(1, char::len_utf8);
        pos += ch_len;
        tokens.push(Token {
            kind: TokenKind::Other,
            start,
            end: pos,
        });
    }

    tokens
}

fn scan_quoted_string(bytes: &[u8], mut pos: usize, backslash_escapes: bool) -> usize {
    let len = bytes.len();
    while pos < len {
        let byte = bytes[pos];
        if backslash_escapes && byte == b'\\' {
            pos = (pos + 2).min(len);
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
        pos += 1;
    }
    pos
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
    fn xdg_state_home_takes_precedence_over_home() {
        let dir = resolve_runs_dir(
            Some(OsStr::new("/var/tmp/state")),
            Some(OsStr::new("/Users/alice")),
        )
        .unwrap();
        assert_eq!(dir, PathBuf::from("/var/tmp/state/dbvalet/runs"));
    }

    #[test]
    fn empty_or_relative_xdg_state_home_falls_back_to_home() {
        let empty =
            resolve_runs_dir(Some(OsStr::new("")), Some(OsStr::new("/Users/alice"))).unwrap();
        assert_eq!(
            empty,
            PathBuf::from("/Users/alice/.local/state/dbvalet/runs")
        );

        let relative = resolve_runs_dir(
            Some(OsStr::new("relative/state")),
            Some(OsStr::new("/Users/alice")),
        )
        .unwrap();
        assert_eq!(
            relative,
            PathBuf::from("/Users/alice/.local/state/dbvalet/runs")
        );
    }

    #[test]
    fn missing_state_and_home_environment_variables_returns_an_error() {
        let err = resolve_runs_dir(None, None).unwrap_err();
        assert!(matches!(err, RunLogError::NoStateDir));
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
                "CREATE SUBSCRIPTION sub CONNECTION 'host=db password=rep-pw' PUBLICATION pub"
            ),
            "CREATE SUBSCRIPTION sub CONNECTION '[REDACTED]' PUBLICATION pub"
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
    fn non_password_sql_and_password_null_are_preserved() {
        assert_eq!(redact_sql("SELECT 1"), "SELECT 1");
        assert_eq!(
            redact_sql("SELECT password FROM users"),
            "SELECT password FROM users"
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
    fn opening_a_run_log_writes_header_redacts_secrets_and_sets_owner_only_permissions() {
        let dir = temp_runs_dir("open-and-write");
        let header = sample_header(
            "aaaaaaaaaaaaaaaa",
            1_795_688_130,
            &["psql", "-c", "ALTER ROLE x PASSWORD 'cli-secret-99'"],
            true,
        );
        let log = open_in(&dir, &header, sample_secrets()).unwrap();
        log.statement(StatementKind::Query, "select 1");
        log.statement(
            StatementKind::Query,
            "SELECT 'toksecret1234567890abcdef1234567', 'pwloginsecret1234567890abcdef123'",
        );
        log.statement(StatementKind::Parse, "SELECT $1::int\nFROM items");

        let content = read_in(&dir, "aaaaaaaaaaaaaaaa").unwrap();
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

        let path = dir.join("20261126T101530.000000000Z-aaaaaaaaaaaaaaaa.log");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
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
            read_in(&dir, "nonexistent12345"),
            Err(RunLogError::NotFound { .. })
        ));
        assert!(matches!(
            read_in(&dir, "../Cargo.toml"),
            Err(RunLogError::NotFound { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_and_run_log_debug_output_never_contain_passwords_or_tokens() {
        let secrets = sample_secrets();
        let debug = format!("{secrets:?}");
        assert!(
            !debug.contains("toksecret1234567890abcdef1234567"),
            "{debug}"
        );
        assert!(
            !debug.contains("pwloginsecret1234567890abcdef123"),
            "{debug}"
        );
    }

    #[test]
    fn shell_wrapped_sql_passwords_in_command_header_are_redacted() {
        let secrets = sample_secrets();
        let cmd = vec![
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from(
                "psql -c \"ALTER ROLE a PASSWORD 'pw-dq-111'\" || true; \
                 psql -c 'CREATE ROLE b LOGIN PASSWORD $$pw-sq-222$$' || true",
            ),
        ];
        let formatted = format_command(&cmd, &secrets);
        assert!(!formatted.contains("pw-dq-111"), "{formatted}");
        assert!(!formatted.contains("pw-sq-222"), "{formatted}");
        assert!(formatted.contains("[REDACTED]"), "{formatted}");
    }
}
