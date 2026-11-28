//! Removes passwords from command lines, URIs and SQL text.

use super::REDACTED_SECRET;

const MAX_REDACT_DEPTH: usize = 4;

const REDACTED_LITERAL: &str = "'[REDACTED]'";

/// Keeps text through the first case-insensitive `password` or `connection` in `arg` and
/// replaces the remainder with `[REDACTED]`. Returns whether the keyword stood at the end
/// of `arg` (such as `--password`), meaning the next argv element should also be redacted.
pub(super) fn redact_after_secret_keyword(arg: &str) -> (String, bool) {
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
pub(super) fn redact_uri_passwords(text: &str) -> String {
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

/// Best-effort lexical redaction of password and connection-string literals in PostgreSQL SQL.
pub(super) fn redact_sql(sql: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
