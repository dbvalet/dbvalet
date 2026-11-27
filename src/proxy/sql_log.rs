//! Relays a connection while copying its statement text to the run log.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::LeaseStream;
use crate::runlog::{MAX_LOGGED_QUERY_BYTES, ObservedSql, RunLog, StatementKind};
use crate::source::AccessDeadline;

const RELAY_BUFFER_BYTES: usize = 8 * 1024;
const FRONTEND_HEADER_LEN: usize = 5;
const SIMPLE_QUERY_TAG: u8 = b'Q';
const PARSE_TAG: u8 = b'P';
const PARAMETER_STATUS_TAG: u8 = b'S';
const MAX_PARAMETER_STATUS_BYTES: usize = 256;

pub(super) async fn relay_with_log<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut TcpStream,
    server: S,
    deadline: &AccessDeadline,
    startup_parameters: &[(String, String)],
    initial_server_bytes: &[u8],
    sql_log: &RunLog,
) -> io::Result<()> {
    let (mut client_read, client_write) = client.split();
    let (mut server_read, server_write) = tokio::io::split(server);
    let mut client_write = LeaseStream {
        socket: client_write,
        deadline: deadline.clone(),
    };
    let mut server_write = LeaseStream {
        socket: server_write,
        deadline: deadline.clone(),
    };
    let non_utf8_encoding = AtomicBool::new(startup_requests_non_utf8(startup_parameters));
    let mut encoding_observer = EncodingObserver::new();
    encoding_observer.observe(initial_server_bytes, &non_utf8_encoding);

    let client_to_server = async {
        let mut buf = [0u8; RELAY_BUFFER_BYTES];
        let mut observer = FrameObserver::new();
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                let _ = server_write.shutdown().await;
                return Ok::<(), io::Error>(());
            }
            if deadline.has_passed() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            // Synchronous local file write before forwarding is intentional: it guarantees
            // every statement is on disk before PostgreSQL can reply and let the child exit.
            observer.observe(&buf[..n], &non_utf8_encoding, |kind, sql| {
                sql_log.statement(kind, sql);
            });
            server_write.write_all(&buf[..n]).await?;
            server_write.flush().await?;
        }
    };

    let server_to_client = async {
        let mut buf = [0u8; RELAY_BUFFER_BYTES];
        loop {
            let n = server_read.read(&mut buf).await?;
            if n == 0 {
                let _ = client_write.shutdown().await;
                return Ok::<(), io::Error>(());
            }
            encoding_observer.observe(&buf[..n], &non_utf8_encoding);
            client_write.write_all(&buf[..n]).await?;
        }
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

fn startup_requests_non_utf8(parameters: &[(String, String)]) -> bool {
    parameters.iter().any(|(name, value)| {
        (name.eq_ignore_ascii_case("client_encoding") && !is_utf8_encoding(value))
            || (name.eq_ignore_ascii_case("options")
                && value.to_ascii_lowercase().contains("client_encoding"))
    })
}

fn is_utf8_encoding(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_uppercase().as_str(),
        "UTF8" | "UTF-8" | "UNICODE"
    )
}

/// Passive, bounded-memory observer of backend `ParameterStatus` (`S`) frames so the logger
/// knows when the session's `client_encoding` is not UTF-8.
struct EncodingObserver {
    state: EncodingState,
}

enum EncodingState {
    Header {
        buf: [u8; FRONTEND_HEADER_LEN],
        filled: usize,
    },
    ParameterPayload {
        remaining: usize,
        buf: Vec<u8>,
    },
    Skip {
        remaining: usize,
    },
    Desynced,
}

impl EncodingObserver {
    fn new() -> Self {
        Self {
            state: EncodingState::Header {
                buf: [0; FRONTEND_HEADER_LEN],
                filled: 0,
            },
        }
    }

    fn observe(&mut self, mut input: &[u8], non_utf8_encoding: &AtomicBool) {
        while !input.is_empty() {
            match &mut self.state {
                EncodingState::Header { buf, filled } => {
                    let take = (FRONTEND_HEADER_LEN - *filled).min(input.len());
                    buf[*filled..*filled + take].copy_from_slice(&input[..take]);
                    *filled += take;
                    input = &input[take..];
                    if *filled < FRONTEND_HEADER_LEN {
                        return;
                    }
                    let tag = buf[0];
                    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                    if len < 4 {
                        self.state = EncodingState::Desynced;
                        return;
                    }
                    let payload_len = len - 4;
                    self.state = if payload_len == 0 {
                        EncodingState::Header {
                            buf: [0; FRONTEND_HEADER_LEN],
                            filled: 0,
                        }
                    } else if tag == PARAMETER_STATUS_TAG
                        && payload_len <= MAX_PARAMETER_STATUS_BYTES
                    {
                        EncodingState::ParameterPayload {
                            remaining: payload_len,
                            buf: Vec::with_capacity(payload_len),
                        }
                    } else {
                        EncodingState::Skip {
                            remaining: payload_len,
                        }
                    };
                }
                EncodingState::ParameterPayload { remaining, buf } => {
                    let take = (*remaining).min(input.len());
                    buf.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    *remaining -= take;
                    if *remaining == 0 {
                        if let Some(name_end) = buf.iter().position(|&b| b == 0)
                            && &buf[..name_end] == b"client_encoding"
                        {
                            let rest = &buf[name_end + 1..];
                            let value_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                            let non_utf8 = std::str::from_utf8(&rest[..value_end])
                                .map_or(true, |enc| !is_utf8_encoding(enc));
                            non_utf8_encoding.store(non_utf8, Ordering::Release);
                        }
                        self.state = EncodingState::Header {
                            buf: [0; FRONTEND_HEADER_LEN],
                            filled: 0,
                        };
                    }
                }
                EncodingState::Skip { remaining } => {
                    let take = (*remaining).min(input.len());
                    input = &input[take..];
                    *remaining -= take;
                    if *remaining == 0 {
                        self.state = EncodingState::Header {
                            buf: [0; FRONTEND_HEADER_LEN],
                            filled: 0,
                        };
                    }
                }
                EncodingState::Desynced => return,
            }
        }
    }
}

/// Passive, bounded-memory observer of PostgreSQL v3.0 frontend frames (`Q` and `P`).
struct FrameObserver {
    state: FrameState,
}

enum FrameState {
    Header {
        buf: [u8; FRONTEND_HEADER_LEN],
        filled: usize,
    },
    QueryPayload {
        remaining: usize,
        buf: Vec<u8>,
        truncated: bool,
        nul_seen: bool,
    },
    ParseStmtName {
        remaining: usize,
    },
    ParseQuery {
        remaining: usize,
        buf: Vec<u8>,
        truncated: bool,
    },
    Skip {
        remaining: usize,
    },
    Desynced,
}

impl FrameObserver {
    fn new() -> Self {
        Self {
            state: FrameState::Header {
                buf: [0; FRONTEND_HEADER_LEN],
                filled: 0,
            },
        }
    }

    fn observe(
        &mut self,
        mut input: &[u8],
        non_utf8_encoding: &AtomicBool,
        mut on_statement: impl FnMut(StatementKind, ObservedSql<'_>),
    ) {
        while !input.is_empty() {
            match &mut self.state {
                FrameState::Header { buf, filled } => {
                    let take = (FRONTEND_HEADER_LEN - *filled).min(input.len());
                    buf[*filled..*filled + take].copy_from_slice(&input[..take]);
                    *filled += take;
                    input = &input[take..];
                    if *filled < FRONTEND_HEADER_LEN {
                        return;
                    }
                    let tag = buf[0];
                    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
                    if len < 4 {
                        self.state = FrameState::Desynced;
                        return;
                    }
                    let payload_len = len - 4;
                    self.state = if payload_len == 0 {
                        FrameState::Header {
                            buf: [0; FRONTEND_HEADER_LEN],
                            filled: 0,
                        }
                    } else if tag == SIMPLE_QUERY_TAG {
                        FrameState::QueryPayload {
                            remaining: payload_len,
                            buf: Vec::new(),
                            truncated: false,
                            nul_seen: false,
                        }
                    } else if tag == PARSE_TAG {
                        FrameState::ParseStmtName {
                            remaining: payload_len,
                        }
                    } else {
                        FrameState::Skip {
                            remaining: payload_len,
                        }
                    };
                }
                FrameState::QueryPayload {
                    remaining,
                    buf,
                    truncated,
                    nul_seen,
                } => {
                    let take = (*remaining).min(input.len());
                    let chunk = &input[..take];
                    if !*nul_seen {
                        if let Some(nul) = chunk.iter().position(|&b| b == 0) {
                            push_query_bytes(buf, truncated, &chunk[..nul]);
                            *nul_seen = true;
                        } else {
                            push_query_bytes(buf, truncated, chunk);
                        }
                    }
                    input = &input[take..];
                    *remaining -= take;
                    if *remaining == 0 {
                        emit_observed(
                            StatementKind::Query,
                            buf,
                            *truncated,
                            non_utf8_encoding,
                            &mut on_statement,
                        );
                        self.state = FrameState::Header {
                            buf: [0; FRONTEND_HEADER_LEN],
                            filled: 0,
                        };
                    }
                }
                FrameState::ParseStmtName { remaining } => {
                    let take = (*remaining).min(input.len());
                    let chunk = &input[..take];
                    if let Some(nul) = chunk.iter().position(|&b| b == 0) {
                        let consumed = nul + 1;
                        input = &input[consumed..];
                        let left = *remaining - consumed;
                        self.state = if left == 0 {
                            FrameState::Header {
                                buf: [0; FRONTEND_HEADER_LEN],
                                filled: 0,
                            }
                        } else {
                            FrameState::ParseQuery {
                                remaining: left,
                                buf: Vec::new(),
                                truncated: false,
                            }
                        };
                    } else {
                        input = &input[take..];
                        *remaining -= take;
                        if *remaining == 0 {
                            self.state = FrameState::Header {
                                buf: [0; FRONTEND_HEADER_LEN],
                                filled: 0,
                            };
                        }
                    }
                }
                FrameState::ParseQuery {
                    remaining,
                    buf,
                    truncated,
                } => {
                    let take = (*remaining).min(input.len());
                    let chunk = &input[..take];
                    if let Some(nul) = chunk.iter().position(|&b| b == 0) {
                        push_query_bytes(buf, truncated, &chunk[..nul]);
                        emit_observed(
                            StatementKind::Parse,
                            buf,
                            *truncated,
                            non_utf8_encoding,
                            &mut on_statement,
                        );
                        let consumed = nul + 1;
                        input = &input[consumed..];
                        let left = *remaining - consumed;
                        self.state = if left == 0 {
                            FrameState::Header {
                                buf: [0; FRONTEND_HEADER_LEN],
                                filled: 0,
                            }
                        } else {
                            FrameState::Skip { remaining: left }
                        };
                    } else {
                        push_query_bytes(buf, truncated, chunk);
                        input = &input[take..];
                        *remaining -= take;
                        if *remaining == 0 {
                            emit_observed(
                                StatementKind::Parse,
                                buf,
                                *truncated,
                                non_utf8_encoding,
                                &mut on_statement,
                            );
                            self.state = FrameState::Header {
                                buf: [0; FRONTEND_HEADER_LEN],
                                filled: 0,
                            };
                        }
                    }
                }
                FrameState::Skip { remaining } => {
                    let take = (*remaining).min(input.len());
                    input = &input[take..];
                    *remaining -= take;
                    if *remaining == 0 {
                        self.state = FrameState::Header {
                            buf: [0; FRONTEND_HEADER_LEN],
                            filled: 0,
                        };
                    }
                }
                FrameState::Desynced => return,
            }
        }
    }
}

fn emit_observed(
    kind: StatementKind,
    buf: &[u8],
    truncated: bool,
    non_utf8_encoding: &AtomicBool,
    on_statement: &mut impl FnMut(StatementKind, ObservedSql<'_>),
) {
    if truncated {
        on_statement(kind, ObservedSql::Truncated);
        return;
    }
    match std::str::from_utf8(buf) {
        Ok(sql) => {
            if non_utf8_encoding.load(Ordering::Acquire) && !sql.is_ascii() {
                on_statement(kind, ObservedSql::Omitted("non-UTF-8 client_encoding"));
            } else {
                on_statement(kind, ObservedSql::Text(sql));
            }
        }
        Err(_) => on_statement(kind, ObservedSql::Omitted("non-UTF-8")),
    }
}

fn push_query_bytes(buf: &mut Vec<u8>, truncated: &mut bool, chunk: &[u8]) {
    let available = MAX_LOGGED_QUERY_BYTES.saturating_sub(buf.len());
    if chunk.len() <= available {
        buf.extend_from_slice(chunk);
    } else {
        buf.extend_from_slice(&chunk[..available]);
        *truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len() + 4).unwrap();
        let mut out = vec![tag];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[derive(Debug, PartialEq, Eq)]
    enum RecordedSql {
        Text(String),
        Truncated,
        Omitted(&'static str),
    }

    fn record(sql: ObservedSql<'_>) -> RecordedSql {
        match sql {
            ObservedSql::Text(text) => RecordedSql::Text(text.to_owned()),
            ObservedSql::Truncated => RecordedSql::Truncated,
            ObservedSql::Omitted(reason) => RecordedSql::Omitted(reason),
        }
    }

    #[test]
    fn frame_observer_extracts_simple_query_and_parse_messages_across_one_byte_chunks() {
        let mut wire = Vec::new();
        wire.extend(frame(b'Q', b"select 1\0"));
        wire.extend(frame(b'B', b"\0s0\0\0\0\0\x01\0\0\0\x06secret\0\0"));
        wire.extend(frame(b'P', b"s0\0SELECT $1::int + 1\0\0\x01\0\0\0\x17"));
        wire.extend(frame(b'P', b"\0SELECT 2\0\0\0"));
        wire.extend(frame(b'E', b"\0\0\0\0\0"));
        wire.extend(frame(b'S', b""));
        wire.extend(frame(b'd', b"copied row data\n"));
        wire.extend(frame(b'X', b""));

        let non_utf8 = AtomicBool::new(false);
        let mut observer = FrameObserver::new();
        let mut seen = Vec::new();
        for chunk in wire.chunks(1) {
            observer.observe(chunk, &non_utf8, |kind, sql| {
                seen.push((kind, record(sql)));
            });
        }

        assert_eq!(
            seen,
            vec![
                (
                    crate::runlog::StatementKind::Query,
                    RecordedSql::Text("select 1".to_owned()),
                ),
                (
                    crate::runlog::StatementKind::Parse,
                    RecordedSql::Text("SELECT $1::int + 1".to_owned()),
                ),
                (
                    crate::runlog::StatementKind::Parse,
                    RecordedSql::Text("SELECT 2".to_owned()),
                ),
            ]
        );
    }

    #[test]
    fn an_oversized_query_is_marked_truncated_and_later_queries_still_log() {
        let huge = format!("SELECT '{}'\0", "a".repeat(MAX_LOGGED_QUERY_BYTES + 100));
        let mut wire = frame(b'Q', huge.as_bytes());
        wire.extend(frame(b'Q', b"SELECT 'after-huge'\0"));

        let non_utf8 = AtomicBool::new(false);
        let mut observer = FrameObserver::new();
        let mut seen = Vec::new();
        observer.observe(&wire, &non_utf8, |kind, sql| {
            seen.push((kind, record(sql)));
        });

        assert_eq!(
            seen,
            vec![
                (crate::runlog::StatementKind::Query, RecordedSql::Truncated),
                (
                    crate::runlog::StatementKind::Query,
                    RecordedSql::Text("SELECT 'after-huge'".to_owned()),
                ),
            ]
        );
    }

    #[test]
    fn a_frame_with_a_bad_length_stops_logging_for_that_connection() {
        let mut wire = frame(b'Q', b"SELECT 'before-bad'\0");
        // Malformed frame with length 2 (< 4) followed by another Q frame.
        wire.extend([b'Q', 0, 0, 0, 2]);
        wire.extend(frame(b'Q', b"SELECT 'after-bad'\0"));

        let non_utf8 = AtomicBool::new(false);
        let mut observer = FrameObserver::new();
        let mut seen = Vec::new();
        observer.observe(&wire, &non_utf8, |kind, sql| {
            seen.push((kind, record(sql)));
        });

        assert_eq!(
            seen,
            vec![(
                crate::runlog::StatementKind::Query,
                RecordedSql::Text("SELECT 'before-bad'".to_owned()),
            )]
        );
    }

    #[test]
    fn frame_observer_does_not_pass_non_utf8_sql_text_to_the_logger() {
        // Under SJIS, 0x81 0x5c is a single character, not a backslash; decoding it lossily
        // leaves a bare backslash before the quote and confuses SQL lexing.
        let wire = frame(
            b'Q',
            b"SELECT '\x81\\' ; ALTER ROLE a PASSWORD 'synthetic-pw-sjis'\0",
        );

        let non_utf8 = AtomicBool::new(false);
        let mut observer = FrameObserver::new();
        let mut seen = Vec::new();
        observer.observe(&wire, &non_utf8, |kind, sql| {
            seen.push((kind, record(sql)));
        });

        assert_eq!(
            seen,
            vec![(
                crate::runlog::StatementKind::Query,
                RecordedSql::Omitted("non-UTF-8"),
            )]
        );
    }

    #[test]
    fn encoding_observer_tracks_non_utf8_client_encoding_updates() {
        let non_utf8 = AtomicBool::new(false);
        let mut enc_observer = EncodingObserver::new();
        let mut frame_observer = FrameObserver::new();

        let switch_to_latin1 = frame(b'S', b"client_encoding\0LATIN1\0");
        for chunk in switch_to_latin1.chunks(1) {
            enc_observer.observe(chunk, &non_utf8);
        }
        assert!(non_utf8.load(Ordering::Acquire));

        let mut seen = Vec::new();
        let mut queries = frame(b'Q', b"SELECT 1\0");
        // Valid UTF-8 bytes (`café`) that mean two different characters under LATIN1.
        queries.extend(frame(b'Q', "SELECT 'café'\0".as_bytes()));
        frame_observer.observe(&queries, &non_utf8, |kind, sql| {
            seen.push((kind, record(sql)));
        });

        let switch_to_utf8 = frame(b'S', b"client_encoding\0UTF8\0");
        enc_observer.observe(&switch_to_utf8, &non_utf8);
        assert!(!non_utf8.load(Ordering::Acquire));

        let utf8_query = frame(b'Q', "SELECT 'café'\0".as_bytes());
        frame_observer.observe(&utf8_query, &non_utf8, |kind, sql| {
            seen.push((kind, record(sql)));
        });

        assert_eq!(
            seen,
            vec![
                (
                    crate::runlog::StatementKind::Query,
                    RecordedSql::Text("SELECT 1".to_owned()),
                ),
                (
                    crate::runlog::StatementKind::Query,
                    RecordedSql::Omitted("non-UTF-8 client_encoding"),
                ),
                (
                    crate::runlog::StatementKind::Query,
                    RecordedSql::Text("SELECT 'café'".to_owned()),
                ),
            ]
        );
    }
}
