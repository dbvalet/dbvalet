//! The child's side of the handshake: startup, token check, refusals.

use std::io;

use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{ENCRYPTION_REQUEST_LEN, ERROR_RESPONSE_TAG, NEGOTIATE_PROTOCOL_VERSION_TAG};

/// PostgreSQL refuses longer startup packets too.
const MAX_STARTUP_PACKET_LEN: usize = 10_000;
const MAX_PASSWORD_MESSAGE_LEN: usize = 1_000;

const PROTOCOL_MAJOR_3: u32 = 3;
const PROTOCOL_VERSION_3_0: u32 = PROTOCOL_MAJOR_3 << 16;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;
const SSL_REQUEST_CODE: u32 = 80_877_103;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;
/// Startup parameters with this prefix are protocol options, which only the hop that
/// receives them may act on.
const PROTOCOL_OPTION_PREFIX: &str = "_pq_.";

const PASSWORD_MESSAGE_TAG: u8 = b'p';

/// Answers each SSL or GSS encryption request with `N` until the startup message comes,
/// and returns its parameters. A protocol 3 client asking for a newer minor version or for
/// protocol options is told, as PostgreSQL would, that only 3.0 without options is spoken.
/// Returns `None` for a cancel request, which isn't relayed.
pub(super) async fn read_startup(
    client: &mut TcpStream,
) -> io::Result<Option<Vec<(String, String)>>> {
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
            version if version >> 16 == PROTOCOL_MAJOR_3 => {
                let (options, parameters): (Vec<_>, Vec<_>) = parse_parameters(rest)?
                    .into_iter()
                    .partition(|(name, _)| name.starts_with(PROTOCOL_OPTION_PREFIX));
                if version != PROTOCOL_VERSION_3_0 || !options.is_empty() {
                    client
                        .write_all(&negotiate_protocol_version_3_0(&options))
                        .await?;
                }
                return Ok(Some(parameters));
            }
            _ => return Err(invalid_data("the client asked for an unsupported protocol")),
        }
    }
}

/// A `NegotiateProtocolVersion` naming 3.0 and every option as unrecognized. PostgreSQL
/// puts the whole version number in the field the docs call the newest minor version.
fn negotiate_protocol_version_3_0(options: &[(String, String)]) -> Vec<u8> {
    let mut body = PROTOCOL_VERSION_3_0.to_be_bytes().to_vec();
    let count = u32::try_from(options.len()).expect("a startup packet is far below 4 GiB");
    body.extend_from_slice(&count.to_be_bytes());
    for (name, _) in options {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
    }
    let len = u32::try_from(body.len() + 4).expect("a startup packet is far below 4 GiB");
    let mut frame = vec![NEGOTIATE_PROTOCOL_VERSION_TAG];
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    frame
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

pub(super) async fn read_password(client: &mut TcpStream) -> io::Result<SecretSlice<u8>> {
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
pub(super) fn token_matches(password_message: &SecretSlice<u8>, token: &SecretString) -> bool {
    let presented = password_message.expose_secret();
    let Some(presented) = presented.strip_suffix(&[0]) else {
        return false;
    };
    presented.ct_eq(token.expose_secret().as_bytes()).into()
}

/// Sends a FATAL `ErrorResponse`, after which the client closes the connection.
pub(super) async fn refuse(
    client: &mut TcpStream,
    sqlstate: &str,
    message: &str,
) -> io::Result<()> {
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

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;

    /// Far longer than a loopback exchange takes, so only a proxy that never answers fails.
    const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5);

    /// The proxy's end of a loopback connection, and the client's.
    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (proxy_end, _) = listener.accept().await.unwrap();
        (proxy_end, client)
    }

    #[tokio::test]
    async fn a_protocol_3_2_startup_is_told_to_use_3_0_and_its_parameters_are_returned() {
        let (mut proxy_end, mut client) = loopback_pair().await;
        client
            .write_all(b"\0\0\0\x14\0\x03\0\x02user\0agent\0\0")
            .await
            .unwrap();

        let parameters = timeout(LOOPBACK_TIMEOUT, read_startup(&mut proxy_end))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            parameters,
            Some(vec![("user".to_owned(), "agent".to_owned())])
        );
        let mut reply = [0; 13];
        timeout(LOOPBACK_TIMEOUT, client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"v\0\0\0\x0c\0\x03\0\0\0\0\0\0");
    }

    #[tokio::test]
    async fn protocol_options_are_named_as_unrecognized_and_left_out_of_the_parameters() {
        let (mut proxy_end, mut client) = loopback_pair().await;
        client
            .write_all(b"\0\0\0\x21\0\x03\0\0user\0agent\0_pq_.foo\0bar\0\0")
            .await
            .unwrap();

        let parameters = timeout(LOOPBACK_TIMEOUT, read_startup(&mut proxy_end))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            parameters,
            Some(vec![("user".to_owned(), "agent".to_owned())])
        );
        let mut reply = [0; 22];
        timeout(LOOPBACK_TIMEOUT, client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"v\0\0\0\x15\0\x03\0\0\0\0\0\x01_pq_.foo\0");
    }

    #[tokio::test]
    async fn a_plain_protocol_3_0_startup_gets_no_negotiation_reply() {
        let (mut proxy_end, mut client) = loopback_pair().await;
        client
            .write_all(b"\0\0\0\x14\0\x03\0\0user\0agent\0\0")
            .await
            .unwrap();

        timeout(LOOPBACK_TIMEOUT, read_startup(&mut proxy_end))
            .await
            .unwrap()
            .unwrap();
        drop(proxy_end);

        let mut reply = Vec::new();
        timeout(LOOPBACK_TIMEOUT, client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"");
    }

    #[tokio::test]
    async fn a_protocol_4_startup_is_refused() {
        let (mut proxy_end, mut client) = loopback_pair().await;
        client
            .write_all(b"\0\0\0\x14\0\x04\0\0user\0agent\0\0")
            .await
            .unwrap();

        let error = timeout(LOOPBACK_TIMEOUT, read_startup(&mut proxy_end))
            .await
            .unwrap()
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
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
}
