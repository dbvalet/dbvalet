//! TLS, startup and SCRAM login upstream as the temporary login.

use std::io;

use bytes::{Buf, BytesMut};
use fallible_iterator::FallibleIterator;
use postgres_protocol::authentication::sasl::{self, ChannelBinding, ScramSha256};
use postgres_protocol::message::{backend, frontend};
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_util::either::Either;

use super::{Access, ENCRYPTION_REQUEST_LEN, ERROR_RESPONSE_TAG, NEGOTIATE_PROTOCOL_VERSION_TAG};
use crate::endpoint::ChannelBinding as ChannelBindingMode;
use crate::tls;

/// Far above any authentication message, so a non-PostgreSQL peer can't make dbvalet
/// reserve gigabytes.
const MAX_UPSTREAM_LOGIN_MESSAGE_LEN: usize = 64 * 1024;

pub(super) enum UpstreamRefusal {
    /// The server's own `ErrorResponse`, passed to the client unchanged.
    ErrorResponse(BytesMut),
    Failed(String),
}

type UpstreamStream = Either<TcpStream, Box<TlsStream<TcpStream>>>;

/// Starts an upstream session as the temporary login with the client's parameters, except
/// `user` and `database`. Returns it after `AuthenticationOk`, with the bytes read past it.
pub(super) async fn connect_upstream(
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
        if let Some(message) = take_login_message(unread)? {
            return Ok(message);
        }
        if server.read_buf(unread).await.map_err(failed)? == 0 {
            return Err(UpstreamRefusal::Failed(
                "the database closed the connection during login".to_owned(),
            ));
        }
    }
}

/// Takes the next whole login message off `unread`, or `None` until more bytes arrive.
/// Drops any `NegotiateProtocolVersion`: the upstream startup is already 3.0 without
/// protocol options, so it can only confirm that, and `Message::parse` can't read it.
fn take_login_message(unread: &mut BytesMut) -> Result<Option<backend::Message>, UpstreamRefusal> {
    while let Some(header) = backend::Header::parse(unread).map_err(failed)? {
        let frame_len = 1 + header.len() as usize;
        if frame_len > MAX_UPSTREAM_LOGIN_MESSAGE_LEN {
            return Err(UpstreamRefusal::Failed(
                "the database sent an oversized message during login".to_owned(),
            ));
        }
        if unread.len() < frame_len {
            return Ok(None);
        }
        match header.tag() {
            ERROR_RESPONSE_TAG => {
                return Err(UpstreamRefusal::ErrorResponse(unread.split_to(frame_len)));
            }
            NEGOTIATE_PROTOCOL_VERSION_TAG => unread.advance(frame_len),
            _ => break,
        }
    }
    backend::Message::parse(unread).map_err(failed)
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

    #[test]
    fn a_negotiate_protocol_version_before_authentication_ok_is_skipped() {
        let mut unread =
            BytesMut::from(&b"v\0\0\0\x15\0\x03\0\0\0\0\0\x01_pq_.foo\0R\0\0\0\x08\0\0\0\0"[..]);

        let message = take_login_message(&mut unread).ok().unwrap();

        assert!(matches!(message, Some(backend::Message::AuthenticationOk)));
        assert!(unread.is_empty());
    }

    #[test]
    fn a_partly_read_negotiate_protocol_version_waits_for_the_rest() {
        let mut unread = BytesMut::from(&b"v\0\0\0\x15\0\x03\0\0\0\0"[..]);

        let message = take_login_message(&mut unread).ok().unwrap();

        assert!(message.is_none());
        assert_eq!(unread.len(), 11);
    }
}
