//! The local endpoint the child connects to. Each client connection must present the run
//! token; it then gets its own upstream connection as the temporary login. When SQL logging
//! is enabled, the proxy passively copies `Q` (simple query) and `P` (parse) statement text
//! to the run log without ever blocking or modifying the wire stream (ADR-0002).

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use postgres_protocol::authentication::sasl::{self, ChannelBinding, ScramSha256};
use postgres_protocol::message::{backend, frontend};
use rustls_pki_types::ServerName;
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::either::Either;

use crate::endpoint::{ChannelBinding as ChannelBindingMode, Endpoint, Tls};
use crate::runlog::RunLog;
use crate::source::{AccessDeadline, UpstreamLogin};
use crate::tls::{self, TlsError};

mod client;
mod sql_log;
use client::{read_password, read_startup, refuse, token_matches};
use sql_log::relay_with_log;
/// Far above any authentication message, so a non-PostgreSQL peer can't make dbvalet
/// reserve gigabytes.
const MAX_UPSTREAM_LOGIN_MESSAGE_LEN: usize = 64 * 1024;
/// SSL and GSS encryption requests are a length and a code, nothing more.
const ENCRYPTION_REQUEST_LEN: usize = 8;
const AUTHENTICATION_OK: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0];
const AUTHENTICATION_CLEARTEXT_PASSWORD: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 3];
const ERROR_RESPONSE_TAG: u8 = b'E';
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
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("couldn't listen on 127.0.0.1")]
    Listen(#[source] io::Error),
}

struct UpstreamTls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// What every client connection is checked against and relayed as.
struct Access {
    token: SecretString,
    endpoint: Endpoint,
    tls: Option<UpstreamTls>,
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
    let tls = match endpoint.tls() {
        Tls::Plaintext => None,
        Tls::VerifyFull(trust_root) => {
            let config = tls::client_config(trust_root)?;
            let server_name = tls::server_name(endpoint.host())?;
            Some(UpstreamTls {
                connector: TlsConnector::from(Arc::new(config)),
                server_name,
            })
        }
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(ProxyError::Listen)?;
    let port = listener.local_addr().map_err(ProxyError::Listen)?.port();
    let access = Arc::new(Access {
        token,
        endpoint,
        tls,
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
            relay_with_log(client, server, &access.deadline, &parameters, &unread, log).await?;
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
enum UpstreamRefusal {
    /// The server's own `ErrorResponse`, passed to the client unchanged.
    ErrorResponse(BytesMut),
    Failed(String),
}

type UpstreamStream = Either<TcpStream, Box<TlsStream<TcpStream>>>;

/// Starts an upstream session as the temporary login with the client's parameters, except
/// `user` and `database`. Returns it after `AuthenticationOk`, with the bytes read past it.
async fn connect_upstream(
    access: &Access,
    client_parameters: &[(String, String)],
) -> Result<(UpstreamStream, BytesMut), UpstreamRefusal> {
    let endpoint = &access.endpoint;
    let login = &access.login;
    let mut first_err = None;
    let mut tcp = None;
    for host in endpoint.dial_hosts() {
        match TcpStream::connect((host, endpoint.port())).await {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(err) => {
                first_err.get_or_insert(err);
            }
        }
    }
    let tcp = tcp.ok_or_else(|| {
        let err = first_err.expect("dial_hosts is never empty");
        UpstreamRefusal::Failed(format!(
            "dbvalet couldn't reach the database at {endpoint}: {err}"
        ))
    })?;
    let (mut server, peer_cert_digest) = negotiate_upstream_tls(tcp, access).await?;
    let parameters = client_parameters
        .iter()
        .filter(|(name, _)| name != "user" && name != "database")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .chain([("user", login.user()), ("database", endpoint.database())]);
    let mut out = BytesMut::new();
    frontend::startup_message(parameters, &mut out).map_err(failed)?;
    server.write_all(&out).await.map_err(failed)?;
    server.flush().await.map_err(failed)?;

    let mut unread = BytesMut::new();
    let mut scram: Option<ScramSha256> = None;
    let mut server_verified = false;
    loop {
        out.clear();
        match read_backend_message(&mut server, &mut unread).await? {
            backend::Message::AuthenticationSasl(body) if scram.is_none() => {
                let (mechanism, binding) = choose_sasl_mechanism(
                    body,
                    endpoint.channel_binding(),
                    peer_cert_digest.as_deref(),
                )?;
                let started =
                    ScramSha256::new(login.password().expose_secret().as_bytes(), binding);
                frontend::sasl_initial_response(mechanism, started.message(), &mut out)
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
                if scram.is_none() && endpoint.channel_binding() == ChannelBindingMode::Require {
                    return Err(UpstreamRefusal::Failed(
                        "the database didn't complete SCRAM-SHA-256-PLUS channel binding, \
                         which channel_binding=require needs"
                            .to_owned(),
                    ));
                }
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
        server.flush().await.map_err(failed)?;
    }
}

/// Runs PostgreSQL `SSLRequest` and the rustls `verify-full` handshake when TLS is enabled,
/// returning the stream and any RFC 5929 `tls-server-end-point` peer certificate digest.
async fn negotiate_upstream_tls(
    mut tcp: TcpStream,
    access: &Access,
) -> Result<(UpstreamStream, Option<Vec<u8>>), UpstreamRefusal> {
    let Some(tls) = &access.tls else {
        return Ok((Either::Left(tcp), None));
    };
    let mut request = BytesMut::with_capacity(ENCRYPTION_REQUEST_LEN);
    frontend::ssl_request(&mut request);
    tcp.write_all(&request).await.map_err(failed)?;
    let mut reply = [0u8; 1];
    tcp.read_exact(&mut reply).await.map_err(failed)?;
    match reply[0] {
        b'S' => {}
        b'N' => {
            return Err(UpstreamRefusal::Failed(tls::describe_tls_refused(
                &access.endpoint,
            )));
        }
        _ => {
            return Err(UpstreamRefusal::Failed(
                "the database sent an unexpected reply to SSLRequest".to_owned(),
            ));
        }
    }
    let tls_stream = tls
        .connector
        .connect(tls.server_name.clone(), tcp)
        .await
        .map_err(|err| {
            UpstreamRefusal::Failed(tls::describe_tls_io_error(&access.endpoint, &err))
        })?;
    let digest = tls::peer_end_point_digest(tls_stream.get_ref().1);
    Ok((Either::Right(Box::new(tls_stream)), digest))
}

fn choose_sasl_mechanism(
    body: backend::AuthenticationSaslBody,
    mode: ChannelBindingMode,
    peer_cert_digest: Option<&[u8]>,
) -> Result<(&'static str, ChannelBinding), UpstreamRefusal> {
    let mut offered = Vec::new();
    let mut mechanisms = body.mechanisms();
    while let Some(mechanism) = mechanisms.next().map_err(failed)? {
        offered.push(mechanism);
    }
    select_sasl_mechanism(&offered, mode, peer_cert_digest)
}

fn select_sasl_mechanism(
    offered: &[&str],
    mode: ChannelBindingMode,
    peer_cert_digest: Option<&[u8]>,
) -> Result<(&'static str, ChannelBinding), UpstreamRefusal> {
    let has_scram = offered.contains(&sasl::SCRAM_SHA_256);
    let has_scram_plus = offered.contains(&sasl::SCRAM_SHA_256_PLUS);
    let usable_digest = match mode {
        ChannelBindingMode::Disable => None,
        ChannelBindingMode::Prefer | ChannelBindingMode::Require => peer_cert_digest,
    };
    if has_scram_plus && let Some(digest) = usable_digest {
        return Ok((
            sasl::SCRAM_SHA_256_PLUS,
            ChannelBinding::tls_server_end_point(digest.to_vec()),
        ));
    }
    if mode == ChannelBindingMode::Require {
        return Err(UpstreamRefusal::Failed(
            "the database didn't complete SCRAM-SHA-256-PLUS channel binding, \
             which channel_binding=require needs"
                .to_owned(),
        ));
    }
    if has_scram {
        return Ok((sasl::SCRAM_SHA_256, ChannelBinding::unsupported()));
    }
    Err(UpstreamRefusal::Failed(
        "the database didn't offer SCRAM-SHA-256 or SCRAM-SHA-256-PLUS authentication".to_owned(),
    ))
}

async fn read_backend_message(
    server: &mut UpstreamStream,
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
    fn sasl_selection_uses_scram_plus_when_offered_with_a_peer_cert_digest() {
        let (mechanism, binding) = select_sasl_mechanism(
            &[sasl::SCRAM_SHA_256, sasl::SCRAM_SHA_256_PLUS],
            ChannelBindingMode::Prefer,
            Some(&[0xAB; 32]),
        )
        .ok()
        .unwrap();
        assert_eq!(mechanism, sasl::SCRAM_SHA_256_PLUS);
        let msg = ScramSha256::new(b"pw", binding);
        assert!(msg.message().starts_with(b"p=tls-server-end-point,,"));
    }

    #[test]
    fn sasl_selection_falls_back_to_scram_sha_256_when_channel_binding_is_unavailable_or_disabled()
    {
        let (mechanism, binding) = select_sasl_mechanism(
            &[sasl::SCRAM_SHA_256, sasl::SCRAM_SHA_256_PLUS],
            ChannelBindingMode::Prefer,
            None,
        )
        .ok()
        .unwrap();
        assert_eq!(mechanism, sasl::SCRAM_SHA_256);
        assert!(
            ScramSha256::new(b"pw", binding)
                .message()
                .starts_with(b"n,,")
        );

        let (mechanism, binding) = select_sasl_mechanism(
            &[sasl::SCRAM_SHA_256, sasl::SCRAM_SHA_256_PLUS],
            ChannelBindingMode::Disable,
            Some(&[0xAB; 32]),
        )
        .ok()
        .unwrap();
        assert_eq!(mechanism, sasl::SCRAM_SHA_256);
        assert!(
            ScramSha256::new(b"pw", binding)
                .message()
                .starts_with(b"n,,")
        );

        let (mechanism, binding) = select_sasl_mechanism(
            &[sasl::SCRAM_SHA_256],
            ChannelBindingMode::Prefer,
            Some(&[0xAB; 32]),
        )
        .ok()
        .unwrap();
        assert_eq!(mechanism, sasl::SCRAM_SHA_256);
        assert!(
            ScramSha256::new(b"pw", binding)
                .message()
                .starts_with(b"n,,")
        );
    }

    #[test]
    fn sasl_selection_refuses_missing_channel_binding_when_required_and_unknown_mechanisms() {
        assert!(
            select_sasl_mechanism(
                &[sasl::SCRAM_SHA_256],
                ChannelBindingMode::Require,
                Some(&[0xAB; 32]),
            )
            .is_err()
        );
        assert!(
            select_sasl_mechanism(
                &[sasl::SCRAM_SHA_256, sasl::SCRAM_SHA_256_PLUS],
                ChannelBindingMode::Require,
                None,
            )
            .is_err()
        );
        assert!(select_sasl_mechanism(&["GSSAPI"], ChannelBindingMode::Prefer, None).is_err());
    }
}
