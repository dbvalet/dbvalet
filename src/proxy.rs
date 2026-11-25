//! The local endpoint the child connects to. Each client connection must present the run
//! token; it then gets its own upstream connection as the temporary login, and the proxy
//! copies bytes both ways without reading them.

use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::BytesMut;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
use postgres_protocol::message::{backend, frontend};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

use crate::endpoint::{Endpoint, Tls};
use crate::source::UpstreamLogin;

/// PostgreSQL refuses longer startup packets too.
const MAX_STARTUP_PACKET_LEN: usize = 10_000;
const MAX_PASSWORD_MESSAGE_LEN: usize = 1_000;
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
}

/// Listens on a random port of 127.0.0.1 until [`Proxy::stop`].
pub async fn start(
    endpoint: Endpoint,
    login: UpstreamLogin,
    token: SecretString,
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
    let (mut server, unread) = match connect_upstream(access, &parameters).await {
        Ok(connected) => connected,
        Err(UpstreamRefusal::ErrorResponse(error)) => return client.write_all(&error).await,
        Err(UpstreamRefusal::Failed(reason)) => {
            return refuse(client, CONNECTION_FAILURE_SQLSTATE, &reason).await;
        }
    };
    client.write_all(&AUTHENTICATION_OK).await?;
    client.write_all(&unread).await?;
    tokio::io::copy_bidirectional(client, &mut server).await?;
    Ok(())
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
            SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => client.write_all(b"N").await?,
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
        .map(|pair| Ok((text(pair[0])?, text(pair[1])?)))
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
    let presented = presented.strip_suffix(&[0]).unwrap_or(presented);
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
            backend::Message::AuthenticationSasl(_) => {
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
}
