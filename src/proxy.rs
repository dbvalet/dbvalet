//! The local endpoint the child connects to. Each client connection must present the run
//! token; it then gets its own upstream connection as the temporary login. When SQL logging
//! is enabled, the proxy passively copies `Q` (simple query) and `P` (parse) statement text
//! to the run log without ever blocking or modifying the wire stream (ADR-0002).

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls_pki_types::ServerName;
use secrecy::SecretString;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsConnector;

use crate::endpoint::{Endpoint, Tls};
use crate::runlog::RunLog;
use crate::source::{AccessDeadline, UpstreamLogin};
use crate::tls::{self, TlsError};

mod client;
mod sql_log;
mod upstream;
use client::{read_password, read_startup, refuse, token_matches};
use sql_log::relay_with_log;
use upstream::{UpstreamRefusal, connect_upstream};

/// SSL and GSS encryption requests are a length and a code, nothing more.
const ENCRYPTION_REQUEST_LEN: usize = 8;
const AUTHENTICATION_OK: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0];
const AUTHENTICATION_CLEARTEXT_PASSWORD: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 3];
const ERROR_RESPONSE_TAG: u8 = b'E';
const NEGOTIATE_PROTOCOL_VERSION_TAG: u8 = b'v';
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
}
