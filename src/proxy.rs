//! The local endpoint the child connects to. Each client connection must present the run
//! token; it then gets its own upstream connection as the temporary login. When SQL logging
//! is enabled, the proxy passively copies `Q` (simple query) and `P` (parse) statement text
//! to the run log without ever blocking or modifying the wire stream (ADR-0002).

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::BytesMut;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
use postgres_protocol::message::{backend, frontend};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

use crate::endpoint::{Endpoint, Tls};
use crate::runlog::{MAX_LOGGED_QUERY_BYTES, ObservedSql, RunLog, StatementKind};
use crate::source::{AccessDeadline, UpstreamLogin};

/// PostgreSQL refuses longer startup packets too.
const MAX_STARTUP_PACKET_LEN: usize = 10_000;
const MAX_PASSWORD_MESSAGE_LEN: usize = 1_000;
/// Far above any authentication message, so a non-PostgreSQL peer can't make dbvalet
/// reserve gigabytes.
const MAX_UPSTREAM_LOGIN_MESSAGE_LEN: usize = 64 * 1024;
const RELAY_BUFFER_BYTES: usize = 8 * 1024;
const FRONTEND_HEADER_LEN: usize = 5;
const SIMPLE_QUERY_TAG: u8 = b'Q';
const PARSE_TAG: u8 = b'P';
const PARAMETER_STATUS_TAG: u8 = b'S';
const MAX_PARAMETER_STATUS_BYTES: usize = 256;
/// SSL and GSS encryption requests are a length and a code, nothing more.
const ENCRYPTION_REQUEST_LEN: usize = 8;
const PROTOCOL_VERSION_3_0: u32 = 3 << 16;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;
const SSL_REQUEST_CODE: u32 = 80_877_103;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;
const AUTHENTICATION_OK: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0];
const AUTHENTICATION_CLEARTEXT_PASSWORD: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 3];
const PASSWORD_MESSAGE_TAG: u8 = b'p';
const ERROR_RESPONSE_TAG: u8 = b'E';
const SCRAM_SHA_256: &str = "SCRAM-SHA-256";
const INVALID_PASSWORD_SQLSTATE: &str = "28P01";
const CONNECTION_FAILURE_SQLSTATE: &str = "08006";

#[derive(Debug)]
pub struct Proxy {
    port: u16,
    stop: oneshot::Sender<()>,
    accept_loop: JoinHandle<()>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error(
        "TLS connections to the database aren't supported yet: \
         use --allow-plaintext with a database on localhost"
    )]
    TlsNotSupported,
    #[error("couldn't listen on 127.0.0.1")]
    Listen(#[source] io::Error),
}

/// What every client connection is checked against and relayed as.
struct Access {
    token: SecretString,
    endpoint: Endpoint,
    login: UpstreamLogin,
    sql_log: Option<RunLog>,
    deadline: AccessDeadline,
}

/// Listens on a random port of 127.0.0.1 until [`Proxy::stop`].
pub async fn start(
    endpoint: Endpoint,
    login: UpstreamLogin,
    token: SecretString,
    sql_log: Option<RunLog>,
    deadline: AccessDeadline,
) -> Result<Proxy, ProxyError> {
    if endpoint.tls() != Tls::Plaintext {
        return Err(ProxyError::TlsNotSupported);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(ProxyError::Listen)?;
    let port = listener.local_addr().map_err(ProxyError::Listen)?.port();
    let access = Arc::new(Access {
        token,
        endpoint,
        login,
        sql_log,
        deadline,
    });
    let (stop, stopped) = oneshot::channel();
    let accept_loop = tokio::spawn(accept(listener, access, stopped));
    Ok(Proxy {
        port,
        stop,
        accept_loop,
    })
}

impl Proxy {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Closes the listener and every client and upstream connection before it returns.
    pub async fn stop(self) {
        // The loop ends on either a message or a dropped sender, so a failed send is fine.
        let _ = self.stop.send(());
        // A panicked loop has already dropped its connections, and teardown must go on.
        let _ = self.accept_loop.await;
    }
}

async fn accept(listener: TcpListener, access: Arc<Access>, mut stopped: oneshot::Receiver<()>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            accepted = listener.accept() => {
                // shortcut: accept errors (such as running out of file descriptors) are
                // retried at once; add a backoff if that ever spins.
                if let Ok((client, _)) = accepted {
                    connections.spawn(serve(client, Arc::clone(&access)));
                }
            }
            Some(_) = connections.join_next() => {}
        }
    }
    connections.shutdown().await;
}

async fn serve(mut client: TcpStream, access: Arc<Access>) {
    // A broken connection ends only itself; the client sees its socket close.
    let _ = relay(&mut client, &access).await;
}

async fn relay(client: &mut TcpStream, access: &Access) -> io::Result<()> {
    let Some(parameters) = read_startup(client).await? else {
        return Ok(());
    };
    client.write_all(&AUTHENTICATION_CLEARTEXT_PASSWORD).await?;
    let password = read_password(client).await?;
    if !token_matches(&password, &access.token) {
        return refuse(
            client,
            INVALID_PASSWORD_SQLSTATE,
            "password authentication failed: the dbvalet proxy accepts only this run's token",
        )
        .await;
    }
    if access.deadline.has_passed() {
        return refuse(
            client,
            CONNECTION_FAILURE_SQLSTATE,
            "this run reached its max_ttl",
        )
        .await;
    }
    let (mut server, unread) = match connect_upstream(access, &parameters).await {
        Ok(connected) => connected,
        Err(UpstreamRefusal::ErrorResponse(error)) => return client.write_all(&error).await,
        Err(UpstreamRefusal::Failed(reason)) => {
            return refuse(client, CONNECTION_FAILURE_SQLSTATE, &reason).await;
        }
    };
    client.write_all(&AUTHENTICATION_OK).await?;
    client.write_all(&unread).await?;
    match &access.sql_log {
        Some(log) => {
            relay_with_log(
                client,
                &mut server,
                &access.deadline,
                &parameters,
                &unread,
                log,
            )
            .await?;
        }
        None => {
            let mut client = LeaseStream {
                socket: client,
                deadline: access.deadline.clone(),
            };
            let mut server = LeaseStream {
                socket: &mut server,
                deadline: access.deadline.clone(),
            };
            tokio::io::copy_bidirectional(&mut client, &mut server).await?;
        }
    }
    Ok(())
}

// Guard writes as well as the teardown timer: an already-ready socket may be
// polled before the timer on resume, including a write that was pending at suspend.
struct LeaseStream<T> {
    socket: T,
    deadline: AccessDeadline,
}

impl<T: AsyncRead + Unpin> AsyncRead for LeaseStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for LeaseStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.deadline.has_passed() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

async fn relay_with_log(
    client: &mut TcpStream,
    server: &mut TcpStream,
    deadline: &AccessDeadline,
    startup_parameters: &[(String, String)],
    initial_server_bytes: &[u8],
    sql_log: &RunLog,
) -> io::Result<()> {
    let (mut client_read, client_write) = client.split();
    let (mut server_read, server_write) = server.split();
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

/// Answers each SSL or GSS encryption request with `N` until the startup message comes,
/// and returns its parameters. Returns `None` for a cancel request, which isn't relayed.
async fn read_startup(client: &mut TcpStream) -> io::Result<Option<Vec<(String, String)>>> {
    loop {
        let len = client.read_u32().await? as usize;
        if !(8..=MAX_STARTUP_PACKET_LEN).contains(&len) {
            return Err(invalid_data("a startup packet has an invalid length"));
        }
        let mut packet = vec![0; len - 4];
        client.read_exact(&mut packet).await?;
        let (code, rest) = packet.split_at(4);
        match u32::from_be_bytes([code[0], code[1], code[2], code[3]]) {
            SSL_REQUEST_CODE | GSSENC_REQUEST_CODE if len == ENCRYPTION_REQUEST_LEN => {
                client.write_all(b"N").await?;
            }
            CANCEL_REQUEST_CODE => return Ok(None),
            PROTOCOL_VERSION_3_0 => return parse_parameters(rest).map(Some),
            _ => return Err(invalid_data("the client asked for an unsupported protocol")),
        }
    }
}

/// Parses the startup message's `name\0value\0…\0` list.
fn parse_parameters(bytes: &[u8]) -> io::Result<Vec<(String, String)>> {
    let text = |field: &[u8]| {
        String::from_utf8(field.to_vec())
            .map_err(|_| invalid_data("a startup parameter isn't UTF-8"))
    };
    let unterminated = || invalid_data("the startup parameters aren't terminated");
    let list = bytes.strip_suffix(&[0]).ok_or_else(unterminated)?;
    if list.is_empty() {
        return Ok(Vec::new());
    }
    let fields: Vec<&[u8]> = list
        .strip_suffix(&[0])
        .ok_or_else(unterminated)?
        .split(|&byte| byte == 0)
        .collect();
    if !fields.len().is_multiple_of(2) {
        return Err(invalid_data("a startup parameter has no value"));
    }
    fields
        .chunks(2)
        .map(|pair| match pair {
            [[], _] => Err(invalid_data("a startup parameter has an empty name")),
            [name, value] => Ok((text(name)?, text(value)?)),
            _ => unreachable!("chunks(2) of an even-length list are pairs"),
        })
        .collect()
}

async fn read_password(client: &mut TcpStream) -> io::Result<SecretSlice<u8>> {
    if client.read_u8().await? != PASSWORD_MESSAGE_TAG {
        return Err(invalid_data("the client didn't send a password"));
    }
    let len = client.read_u32().await? as usize;
    if !(5..=MAX_PASSWORD_MESSAGE_LEN).contains(&len) {
        return Err(invalid_data("a password message has an invalid length"));
    }
    let mut password: SecretSlice<u8> = vec![0; len - 4].into();
    client.read_exact(password.expose_secret_mut()).await?;
    Ok(password)
}

/// Compares in time that doesn't depend on how much of the token matches.
fn token_matches(password_message: &SecretSlice<u8>, token: &SecretString) -> bool {
    let presented = password_message.expose_secret();
    let Some(presented) = presented.strip_suffix(&[0]) else {
        return false;
    };
    presented.ct_eq(token.expose_secret().as_bytes()).into()
}

/// Sends a FATAL `ErrorResponse`, after which the client closes the connection.
async fn refuse(client: &mut TcpStream, sqlstate: &str, message: &str) -> io::Result<()> {
    let mut fields = Vec::new();
    for (field, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        fields.push(field);
        fields.extend_from_slice(value.as_bytes());
        fields.push(0);
    }
    fields.push(0);
    let len = u32::try_from(fields.len() + 4).expect("an error message is far below 4 GiB");
    let mut frame = vec![ERROR_RESPONSE_TAG];
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&fields);
    client.write_all(&frame).await
}

enum UpstreamRefusal {
    /// The server's own `ErrorResponse`, passed to the client unchanged.
    ErrorResponse(BytesMut),
    Failed(String),
}

/// Starts an upstream session as the temporary login with the client's parameters, except
/// `user` and `database`. Returns it after `AuthenticationOk`, with the bytes read past it.
async fn connect_upstream(
    access: &Access,
    client_parameters: &[(String, String)],
) -> Result<(TcpStream, BytesMut), UpstreamRefusal> {
    let endpoint = &access.endpoint;
    let login = &access.login;
    let mut server = TcpStream::connect((endpoint.host(), endpoint.port()))
        .await
        .map_err(|err| {
            UpstreamRefusal::Failed(format!(
                "dbvalet couldn't reach the database at {endpoint}: {err}"
            ))
        })?;
    let parameters = client_parameters
        .iter()
        .filter(|(name, _)| name != "user" && name != "database")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .chain([("user", login.user()), ("database", endpoint.database())]);
    let mut out = BytesMut::new();
    frontend::startup_message(parameters, &mut out).map_err(failed)?;
    server.write_all(&out).await.map_err(failed)?;

    let mut unread = BytesMut::new();
    let mut scram: Option<ScramSha256> = None;
    let mut server_verified = false;
    loop {
        out.clear();
        match read_backend_message(&mut server, &mut unread).await? {
            backend::Message::AuthenticationSasl(_) if scram.is_none() => {
                let started = ScramSha256::new(
                    login.password().expose_secret().as_bytes(),
                    ChannelBinding::unsupported(),
                );
                frontend::sasl_initial_response(SCRAM_SHA_256, started.message(), &mut out)
                    .map_err(failed)?;
                scram = Some(started);
            }
            backend::Message::AuthenticationSaslContinue(body) => {
                let scram = scram.as_mut().ok_or_else(out_of_order)?;
                scram.update(body.data()).map_err(failed)?;
                frontend::sasl_response(scram.message(), &mut out).map_err(failed)?;
            }
            backend::Message::AuthenticationSaslFinal(body) => {
                let scram = scram.as_mut().ok_or_else(out_of_order)?;
                scram.finish(body.data()).map_err(failed)?;
                server_verified = true;
            }
            backend::Message::AuthenticationOk if scram.is_none() || server_verified => {
                return Ok((server, unread));
            }
            backend::Message::AuthenticationSasl(_) | backend::Message::AuthenticationOk => {
                return Err(out_of_order());
            }
            _ => {
                return Err(UpstreamRefusal::Failed(
                    "the database asked for an authentication other than SCRAM-SHA-256".to_owned(),
                ));
            }
        }
        server.write_all(&out).await.map_err(failed)?;
    }
}

async fn read_backend_message(
    server: &mut TcpStream,
    unread: &mut BytesMut,
) -> Result<backend::Message, UpstreamRefusal> {
    loop {
        if let Some(header) = backend::Header::parse(unread).map_err(failed)? {
            let frame_len = 1 + header.len() as usize;
            if frame_len > MAX_UPSTREAM_LOGIN_MESSAGE_LEN {
                return Err(UpstreamRefusal::Failed(
                    "the database sent an oversized message during login".to_owned(),
                ));
            }
            if header.tag() == ERROR_RESPONSE_TAG && unread.len() >= frame_len {
                return Err(UpstreamRefusal::ErrorResponse(unread.split_to(frame_len)));
            }
        }
        if let Some(message) = backend::Message::parse(unread).map_err(failed)? {
            return Ok(message);
        }
        if server.read_buf(unread).await.map_err(failed)? == 0 {
            return Err(UpstreamRefusal::Failed(
                "the database closed the connection during login".to_owned(),
            ));
        }
    }
}

fn failed(err: io::Error) -> UpstreamRefusal {
    UpstreamRefusal::Failed(format!("the connection to the database failed: {err}"))
}

fn out_of_order() -> UpstreamRefusal {
    UpstreamRefusal::Failed("the database sent its SCRAM messages out of order".to_owned())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_expired_proxy_connection_cannot_write_to_its_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let mut stream = LeaseStream {
            socket: &mut socket,
            deadline: AccessDeadline::at(std::time::Duration::ZERO),
        };

        let error = stream.write_all(b"test").await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            peer.try_read(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn an_expired_split_write_half_cannot_write_to_its_peer() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let (_, write_half) = socket.split();
        let mut stream = LeaseStream {
            socket: write_half,
            deadline: AccessDeadline::at(std::time::Duration::ZERO),
        };

        let error = stream.write_all(b"test").await.unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            peer.try_read(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn startup_parameters_are_parsed_in_order_including_empty_values() {
        let parameters =
            parse_parameters(b"user\0agent\0database\0app\0application_name\0\0\0").unwrap();
        assert_eq!(
            parameters,
            [
                ("user".to_owned(), "agent".to_owned()),
                ("database".to_owned(), "app".to_owned()),
                ("application_name".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn startup_parameters_without_the_final_terminator_are_refused() {
        assert!(parse_parameters(b"user\0agent").is_err());
        assert!(parse_parameters(b"user\0agent\0").is_err());
    }

    #[test]
    fn a_startup_parameter_with_an_empty_name_is_refused() {
        assert!(parse_parameters(b"\0\0\0").is_err());
    }

    #[test]
    fn a_password_message_without_its_terminator_does_not_match() {
        let token = SecretString::from("tokenabcdefghijk");
        assert!(!token_matches(&b"tokenabcdefghijk".to_vec().into(), &token));
    }

    #[test]
    fn only_the_exact_token_matches() {
        let token = SecretString::from("tokenabcdefghijk");
        assert!(token_matches(
            &b"tokenabcdefghijk\0".to_vec().into(),
            &token
        ));
        assert!(!token_matches(
            &b"tokenabcdefghijx\0".to_vec().into(),
            &token
        ));
        assert!(!token_matches(
            &b"tokenabcdefghij\0".to_vec().into(),
            &token
        ));
        assert!(!token_matches(&b"\0".to_vec().into(), &token));
    }

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
