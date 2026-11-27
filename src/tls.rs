//! Verified TLS configuration, error messages and RFC 5929 channel-binding digests shared by
//! the admin connection and the proxy's upstream connections.

use std::error::Error as StdError;
use std::fs::{self, File};
use std::future::Future;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::{CertificateError, ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, ServerName};
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{
    ChannelBinding as PgChannelBinding, MakeTlsConnect, TlsConnect, TlsStream as PgTlsStream,
};
use tokio_rustls::TlsConnector;
use x509_cert::Certificate;
use x509_cert::der::asn1::{ContextSpecific, UintRef};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_MD_5, ID_RSASSA_PSS, ID_SHA_1,
    ID_SHA_256, ID_SHA_384, ID_SHA_512, MD_5_WITH_RSA_ENCRYPTION, SHA_1_WITH_RSA_ENCRYPTION,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};
use x509_cert::der::{Decode, DecodeValue, FixedTag, Header, Reader, Tag, TagNumber};
use x509_cert::spki::{AlgorithmIdentifierOwned, AlgorithmIdentifierRef};

use crate::endpoint::{Endpoint, Tls, TrustRoot};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("couldn't read the sslrootcert file `{path}`: {source}")]
    ReadRootCert {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the sslrootcert file `{path}` isn't a regular file")]
    RootCertNotAFile { path: PathBuf },
    #[error("the sslrootcert file `{path}` is larger than {limit} bytes")]
    RootCertTooLarge { path: PathBuf, limit: u64 },
    #[error("the sslrootcert file `{path}` isn't valid PEM")]
    InvalidRootCertPem { path: PathBuf },
    #[error("the sslrootcert file `{path}` contains an invalid CA certificate: {source}")]
    InvalidRootCertificate {
        path: PathBuf,
        #[source]
        source: rustls::Error,
    },
    #[error("the sslrootcert file `{path}` contains no usable CA certificates")]
    EmptyRootCert { path: PathBuf },
    #[error("couldn't initialise the OS TLS trust store: {0}")]
    PlatformVerifier(#[source] rustls::Error),
    #[error("couldn't configure TLS protocol versions: {0}")]
    ProtocolVersions(#[source] rustls::Error),
    #[error("`{host}` isn't a valid TLS server name")]
    InvalidServerName { host: String },
}

/// Builds a `verify-full` rustls [`ClientConfig`] for `trust_root`.
///
/// [`TrustRoot::System`] verifies against the OS trust store; [`TrustRoot::PemFile`] loads only
/// the PEM CA certificates in that file, replacing the OS store.
pub fn client_config(trust_root: &TrustRoot) -> Result<ClientConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::ProtocolVersions)?;
    let builder = match trust_root {
        TrustRoot::System => builder
            .with_platform_verifier()
            .map_err(TlsError::PlatformVerifier)?,
        TrustRoot::PemFile(path) => {
            let roots = load_root_certs(path)?;
            builder.with_root_certificates(roots)
        }
    };
    Ok(builder.with_no_client_auth())
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(host.to_owned()).map_err(|_| TlsError::InvalidServerName {
        host: host.to_owned(),
    })
}

/// Real CA bundles are a few hundred KB (Debian's `ca-certificates.crt`, the AWS RDS global
/// bundle), so 1 MiB leaves headroom while keeping a wrong path from exhausting memory.
const MAX_ROOT_CERT_BYTES: u64 = 1024 * 1024;

fn load_root_certs(path: &Path) -> Result<RootCertStore, TlsError> {
    let read_error = |source| TlsError::ReadRootCert {
        path: path.to_path_buf(),
        source,
    };
    // Checked on the path before opening, because opening a FIFO blocks until a writer appears.
    // A swap between this check and the open needs a hostile same-user process (ADR-0003).
    if !fs::metadata(path).map_err(read_error)?.is_file() {
        return Err(TlsError::RootCertNotAFile {
            path: path.to_path_buf(),
        });
    }
    let mut pem = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_ROOT_CERT_BYTES + 1).read_to_end(&mut pem))
        .map_err(read_error)?;
    if pem.len() as u64 > MAX_ROOT_CERT_BYTES {
        return Err(TlsError::RootCertTooLarge {
            path: path.to_path_buf(),
            limit: MAX_ROOT_CERT_BYTES,
        });
    }
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|err| map_pem_error(path, err))?;
        roots
            .add(cert)
            .map_err(|source| TlsError::InvalidRootCertificate {
                path: path.to_path_buf(),
                source,
            })?;
    }
    if roots.is_empty() {
        return Err(TlsError::EmptyRootCert {
            path: path.to_path_buf(),
        });
    }
    Ok(roots)
}

fn map_pem_error(path: &Path, err: pem::Error) -> TlsError {
    match err {
        pem::Error::Io(source) => TlsError::ReadRootCert {
            path: path.to_path_buf(),
            source,
        },
        // PEM parse errors can quote raw file contents.
        _ => TlsError::InvalidRootCertPem {
            path: path.to_path_buf(),
        },
    }
}

pub fn describe_tls_refused(endpoint: &Endpoint) -> String {
    if endpoint.is_loopback() {
        "the database refused TLS: enable TLS on the server, \
         or pass --allow-plaintext for a database on localhost"
            .to_owned()
    } else {
        "the database refused TLS: dbvalet requires verified TLS for non-localhost databases"
            .to_owned()
    }
}

pub fn describe_rustls_error(endpoint: &Endpoint, err: &rustls::Error) -> String {
    let custom_root = match endpoint.tls() {
        Tls::VerifyFull(TrustRoot::PemFile(path)) => Some(path.as_path()),
        Tls::VerifyFull(TrustRoot::System) | Tls::Plaintext => None,
    };
    match err {
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
        ) => format!(
            "TLS certificate doesn't match the host `{}`",
            endpoint.host()
        ),
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer) => match custom_root {
            None => "TLS certificate isn't trusted by the OS trust store: \
                     if the database uses a private or provider CA (such as AWS RDS), \
                     set sslrootcert=<path> in the connection string"
                .to_owned(),
            Some(path) => format!(
                "TLS certificate isn't trusted by the CA file at `{}` (sslrootcert)",
                path.display()
            ),
        },
        rustls::Error::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. },
        ) => "TLS certificate has expired".to_owned(),
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. },
        ) => "TLS certificate isn't valid yet".to_owned(),
        rustls::Error::InvalidCertificate(CertificateError::Revoked) => {
            "TLS certificate has been revoked".to_owned()
        }
        rustls::Error::InvalidCertificate(other) => match custom_root {
            None => format!(
                "TLS certificate verification failed ({other}): \
                 if the database uses a private or provider CA (such as AWS RDS), \
                 set sslrootcert=<path> in the connection string"
            ),
            Some(path) => format!(
                "TLS certificate verification failed against `{}` ({other})",
                path.display()
            ),
        },
        other => format!("TLS handshake failed: {other}"),
    }
}

/// Classifies a TLS or channel-binding failure buried in an error chain (from `tokio-postgres`
/// or `tokio-rustls`). Returns `None` for non-TLS errors such as TCP connection refused.
pub fn describe_error_chain(endpoint: &Endpoint, err: &(dyn StdError + 'static)) -> Option<String> {
    let mut current: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(source) = current {
        if let Some(rustls_err) = source.downcast_ref::<rustls::Error>() {
            return Some(describe_rustls_error(endpoint, rustls_err));
        }
        if let Some(io_err) = source.downcast_ref::<io::Error>()
            && let Some(inner) = io_err.get_ref()
            && let Some(rustls_err) = inner.downcast_ref::<rustls::Error>()
        {
            return Some(describe_rustls_error(endpoint, rustls_err));
        }
        current = source.source();
    }
    if let Some(source) = err.source() {
        let message = source.to_string();
        if message == "server does not support TLS" {
            return Some(describe_tls_refused(endpoint));
        }
        if message == "server did not use channel binding" {
            return Some(
                "the database didn't complete SCRAM-SHA-256-PLUS channel binding, \
                 which channel_binding=require needs"
                    .to_owned(),
            );
        }
    }
    None
}

pub fn describe_tls_io_error(endpoint: &Endpoint, err: &io::Error) -> String {
    if let Some(reason) = describe_error_chain(endpoint, err) {
        return reason;
    }
    format!("TLS handshake failed: {err}")
}

/// `tokio-postgres` TLS connector backed by `tokio-rustls` and [`server_end_point_digest`].
#[derive(Clone)]
pub struct MakeRustlsConnect {
    config: Arc<ClientConfig>,
}

impl MakeRustlsConnect {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

pub struct RustlsConnect {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

pub struct RustlsConnectFuture<S>(tokio_rustls::Connect<S>);

pub struct RustlsStream<S>(tokio_rustls::client::TlsStream<S>);

impl<S> MakeTlsConnect<S> for MakeRustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type TlsConnect = RustlsConnect;
    type Error = TlsError;

    fn make_tls_connect(&mut self, domain: &str) -> Result<Self::TlsConnect, Self::Error> {
        let server_name = server_name(domain)?;
        Ok(RustlsConnect {
            connector: TlsConnector::from(Arc::clone(&self.config)),
            server_name,
        })
    }
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = io::Error;
    type Future = RustlsConnectFuture<S>;

    fn connect(self, stream: S) -> Self::Future {
        RustlsConnectFuture(self.connector.connect(self.server_name, stream))
    }
}

impl<S> Future for RustlsConnectFuture<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<RustlsStream<S>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_ok(RustlsStream)
    }
}

impl<S> PgTlsStream for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> PgChannelBinding {
        let (_, session) = self.0.get_ref();
        match peer_end_point_digest(session) {
            Some(digest) => PgChannelBinding::tls_server_end_point(digest),
            None => PgChannelBinding::none(),
        }
    }
}

impl<S> AsyncRead for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for RustlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// RFC 5929 `tls-server-end-point` digest of the leaf certificate presented by `session`.
pub fn peer_end_point_digest(session: &ClientConnection) -> Option<Vec<u8>> {
    session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| server_end_point_digest(cert.as_ref()))
}

/// Hash of the peer's DER-encoded leaf certificate for RFC 5929 §4.1 `tls-server-end-point`
/// SCRAM-SHA-256-PLUS channel binding. Returns `None` for certificates using pure signature
/// algorithms (such as Ed25519) or malformed parameters that define no usable hash function.
pub fn server_end_point_digest(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let algorithm = channel_binding_hash(&cert.signature_algorithm)?;
    Some(algorithm.digest(cert_der))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelBindingHash {
    Sha256,
    Sha384,
    Sha512,
}

impl ChannelBindingHash {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// RFC 4055 §3.1 `RSASSA-PSS-params`; all fields are optional explicit context-specific tags.
struct RsaPssParams<'a> {
    hash_algorithm: Option<AlgorithmIdentifierRef<'a>>,
}

impl<'a> DecodeValue<'a> for RsaPssParams<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> x509_cert::der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let hash_algorithm = decode_optional_explicit(reader, TagNumber::N0)?;
            let _mask_gen: Option<AlgorithmIdentifierRef<'a>> =
                decode_optional_explicit(reader, TagNumber::N1)?;
            let _salt_length: Option<UintRef<'a>> =
                decode_optional_explicit(reader, TagNumber::N2)?;
            let _trailer_field: Option<UintRef<'a>> =
                decode_optional_explicit(reader, TagNumber::N3)?;
            Ok(Self { hash_algorithm })
        })
    }
}

impl FixedTag for RsaPssParams<'_> {
    const TAG: Tag = Tag::Sequence;
}

/// Decodes an optional explicit context-specific field without skipping unexpected earlier tags.
fn decode_optional_explicit<'a, R: Reader<'a>, T: Decode<'a>>(
    reader: &mut R,
    tag_number: TagNumber,
) -> x509_cert::der::Result<Option<T>> {
    let expected = Tag::ContextSpecific {
        number: tag_number,
        constructed: true,
    };
    if reader.is_finished() || reader.peek_tag()? != expected {
        return Ok(None);
    }
    let field = ContextSpecific::<T>::decode(reader)?;
    Ok(Some(field.value))
}

/// Maps a certificate's signature algorithm to its RFC 5929 §4.1 channel-binding hash.
/// MD5 and SHA-1 are upgraded to SHA-256 per RFC 5929 §4.1.
fn channel_binding_hash(
    signature_algorithm: &AlgorithmIdentifierOwned,
) -> Option<ChannelBindingHash> {
    match signature_algorithm.oid {
        ID_MD_5
        | MD_5_WITH_RSA_ENCRYPTION
        | ID_SHA_1
        | SHA_1_WITH_RSA_ENCRYPTION
        | ID_SHA_256
        | SHA_256_WITH_RSA_ENCRYPTION
        | ECDSA_WITH_SHA_256 => Some(ChannelBindingHash::Sha256),
        ID_SHA_384 | SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => {
            Some(ChannelBindingHash::Sha384)
        }
        ID_SHA_512 | SHA_512_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_512 => {
            Some(ChannelBindingHash::Sha512)
        }
        ID_RSASSA_PSS => {
            let params = signature_algorithm
                .parameters
                .as_ref()?
                .decode_as::<RsaPssParams<'_>>()
                .ok()?;
            // RFC 4055 §3.1 defaults omitted hashAlgorithm to SHA-1.
            let hash_oid = params.hash_algorithm.map_or(ID_SHA_1, |alg| alg.oid);
            digest_oid_to_channel_binding_hash(hash_oid)
        }
        _ => None,
    }
}

fn digest_oid_to_channel_binding_hash(oid: ObjectIdentifier) -> Option<ChannelBindingHash> {
    match oid {
        ID_MD_5 | ID_SHA_1 | ID_SHA_256 => Some(ChannelBindingHash::Sha256),
        ID_SHA_384 => Some(ChannelBindingHash::Sha384),
        ID_SHA_512 => Some(ChannelBindingHash::Sha512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ChannelBinding;
    use tokio::io::DuplexStream;
    use x509_cert::der::asn1::{BitString, Null};
    use x509_cert::der::oid::db::rfc5912::{ID_MGF_1, ID_SHA_224};
    use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
    use x509_cert::der::{Any, Encode, TagMode};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};

    fn sig_alg(oid: ObjectIdentifier, parameters: Option<Any>) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned { oid, parameters }
    }

    fn minimal_cert_der_with_alg(alg: AlgorithmIdentifierOwned) -> Vec<u8> {
        let cert = Certificate {
            tbs_certificate: x509_cert::certificate::TbsCertificate {
                version: x509_cert::certificate::Version::V3,
                serial_number: SerialNumber::from(1u8),
                signature: alg.clone(),
                issuer: Name::default(),
                validity: Validity {
                    not_before: Time::UtcTime(
                        x509_cert::der::asn1::UtcTime::from_unix_duration(
                            std::time::Duration::from_secs(1_700_000_000),
                        )
                        .unwrap(),
                    ),
                    not_after: Time::UtcTime(
                        x509_cert::der::asn1::UtcTime::from_unix_duration(
                            std::time::Duration::from_secs(1_800_000_000),
                        )
                        .unwrap(),
                    ),
                },
                subject: Name::default(),
                subject_public_key_info: SubjectPublicKeyInfoOwned {
                    algorithm: alg.clone(),
                    subject_public_key: BitString::from_bytes(&[0u8; 32]).unwrap(),
                },
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: None,
            },
            signature_algorithm: alg,
            signature: BitString::from_bytes(&[0u8; 32]).unwrap(),
        };
        cert.to_der().unwrap()
    }

    fn minimal_cert_der(sig_oid: ObjectIdentifier) -> Vec<u8> {
        minimal_cert_der_with_alg(sig_alg(sig_oid, None))
    }

    fn encode_sequence(body: &[u8]) -> Any {
        let mut der = vec![0x30];
        assert!(body.len() < 128, "test helper expects short-form DER");
        der.push(u8::try_from(body.len()).unwrap());
        der.extend_from_slice(body);
        Any::from_der(&der).unwrap()
    }

    fn rsassa_pss_params(hash_oid: ObjectIdentifier, salt_len: u8) -> Any {
        let hash_alg = sig_alg(hash_oid, Some(Any::from(Null)));
        let hash_field = ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: hash_alg.clone(),
        };
        let mgf_alg = sig_alg(
            ID_MGF_1,
            Some(Any::from_der(&hash_alg.to_der().unwrap()).unwrap()),
        );
        let mgf_field = ContextSpecific {
            tag_number: TagNumber::N1,
            tag_mode: TagMode::Explicit,
            value: mgf_alg,
        };
        let salt_field = ContextSpecific {
            tag_number: TagNumber::N2,
            tag_mode: TagMode::Explicit,
            value: salt_len,
        };
        let trailer_field = ContextSpecific {
            tag_number: TagNumber::N3,
            tag_mode: TagMode::Explicit,
            value: 1u8,
        };
        let mut body = Vec::new();
        body.extend_from_slice(&hash_field.to_der().unwrap());
        body.extend_from_slice(&mgf_field.to_der().unwrap());
        body.extend_from_slice(&salt_field.to_der().unwrap());
        body.extend_from_slice(&trailer_field.to_der().unwrap());
        encode_sequence(&body)
    }

    #[test]
    fn rfc_5929_maps_sha256_sha384_sha512_and_upgrades_sha1_and_md5_to_sha256() {
        assert_eq!(
            channel_binding_hash(&sig_alg(SHA_256_WITH_RSA_ENCRYPTION, None)),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(ECDSA_WITH_SHA_256, None)),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(SHA_1_WITH_RSA_ENCRYPTION, None)),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(MD_5_WITH_RSA_ENCRYPTION, None)),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(SHA_384_WITH_RSA_ENCRYPTION, None)),
            Some(ChannelBindingHash::Sha384)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(ECDSA_WITH_SHA_384, None)),
            Some(ChannelBindingHash::Sha384)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(SHA_512_WITH_RSA_ENCRYPTION, None)),
            Some(ChannelBindingHash::Sha512)
        );
        assert_eq!(
            channel_binding_hash(&sig_alg(ECDSA_WITH_SHA_512, None)),
            Some(ChannelBindingHash::Sha512)
        );
        assert_eq!(channel_binding_hash(&sig_alg(ID_ED_25519, None)), None);
    }

    #[test]
    fn server_end_point_digest_hashes_der_with_the_matching_rfc_5929_algorithm() {
        let sha1_der = minimal_cert_der(SHA_1_WITH_RSA_ENCRYPTION);
        assert_eq!(
            server_end_point_digest(&sha1_der).unwrap(),
            Sha256::digest(&sha1_der).to_vec()
        );

        let sha256_der = minimal_cert_der(SHA_256_WITH_RSA_ENCRYPTION);
        assert_eq!(
            server_end_point_digest(&sha256_der).unwrap(),
            Sha256::digest(&sha256_der).to_vec()
        );

        let sha384_der = minimal_cert_der(ECDSA_WITH_SHA_384);
        assert_eq!(
            server_end_point_digest(&sha384_der).unwrap(),
            Sha384::digest(&sha384_der).to_vec()
        );

        let sha512_der = minimal_cert_der(SHA_512_WITH_RSA_ENCRYPTION);
        assert_eq!(
            server_end_point_digest(&sha512_der).unwrap(),
            Sha512::digest(&sha512_der).to_vec()
        );

        let ec512_der = minimal_cert_der(ECDSA_WITH_SHA_512);
        assert_eq!(
            server_end_point_digest(&ec512_der).unwrap(),
            Sha512::digest(&ec512_der).to_vec()
        );

        let ed25519_der = minimal_cert_der(ID_ED_25519);
        assert_eq!(server_end_point_digest(&ed25519_der), None);
        assert_eq!(server_end_point_digest(b"not-a-der-cert"), None);
    }

    #[test]
    fn server_end_point_digest_uses_the_hash_from_rsassa_pss_parameters() {
        let pss_sha256 = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(rsassa_pss_params(ID_SHA_256, 32)),
        ));
        assert_eq!(
            server_end_point_digest(&pss_sha256).unwrap(),
            Sha256::digest(&pss_sha256).to_vec()
        );

        let pss_sha384 = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(rsassa_pss_params(ID_SHA_384, 48)),
        ));
        assert_eq!(
            server_end_point_digest(&pss_sha384).unwrap(),
            Sha384::digest(&pss_sha384).to_vec()
        );

        let pss_sha512 = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(rsassa_pss_params(ID_SHA_512, 64)),
        ));
        assert_eq!(
            server_end_point_digest(&pss_sha512).unwrap(),
            Sha512::digest(&pss_sha512).to_vec()
        );

        let pss_sha1 = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(rsassa_pss_params(ID_SHA_1, 20)),
        ));
        assert_eq!(
            server_end_point_digest(&pss_sha1).unwrap(),
            Sha256::digest(&pss_sha1).to_vec()
        );

        let pss_default_empty_seq =
            minimal_cert_der_with_alg(sig_alg(ID_RSASSA_PSS, Some(encode_sequence(&[]))));
        assert_eq!(
            server_end_point_digest(&pss_default_empty_seq).unwrap(),
            Sha256::digest(&pss_default_empty_seq).to_vec()
        );
    }

    #[test]
    fn rsassa_pss_with_missing_malformed_or_unsupported_parameters_returns_none() {
        let missing_params = minimal_cert_der_with_alg(sig_alg(ID_RSASSA_PSS, None));
        assert_eq!(server_end_point_digest(&missing_params), None);

        let null_params = minimal_cert_der_with_alg(sig_alg(ID_RSASSA_PSS, Some(Any::from(Null))));
        assert_eq!(server_end_point_digest(&null_params), None);

        let sha224_params = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(rsassa_pss_params(ID_SHA_224, 28)),
        ));
        assert_eq!(server_end_point_digest(&sha224_params), None);

        let non_digest_oid = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(rsassa_pss_params(SHA_256_WITH_RSA_ENCRYPTION, 32)),
        ));
        assert_eq!(server_end_point_digest(&non_digest_oid), None);

        let first = ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: sig_alg(ID_SHA_256, None),
        };
        let second = ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: sig_alg(ID_SHA_512, None),
        };
        let mut duplicate_body = first.to_der().unwrap();
        duplicate_body.extend_from_slice(&second.to_der().unwrap());
        let duplicate_tag = minimal_cert_der_with_alg(sig_alg(
            ID_RSASSA_PSS,
            Some(encode_sequence(&duplicate_body)),
        ));
        assert_eq!(server_end_point_digest(&duplicate_tag), None);
    }

    #[test]
    fn make_rustls_connect_accepts_valid_hostnames_and_refuses_invalid_ones() {
        let config = client_config(&TrustRoot::System).unwrap();
        let mut connector = MakeRustlsConnect::new(config);
        assert!(
            <MakeRustlsConnect as MakeTlsConnect<DuplexStream>>::make_tls_connect(
                &mut connector,
                "localhost",
            )
            .is_ok()
        );
        assert!(
            <MakeRustlsConnect as MakeTlsConnect<DuplexStream>>::make_tls_connect(
                &mut connector,
                "127.0.0.1",
            )
            .is_ok()
        );
        assert!(
            <MakeRustlsConnect as MakeTlsConnect<DuplexStream>>::make_tls_connect(
                &mut connector,
                "",
            )
            .is_err()
        );
    }

    const TWO_TEST_CAS: &[u8] = include_bytes!("../tests/fixtures/two-test-cas.pem");

    fn temp_rootcert_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-tls")
            .join(format!("{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sslrootcert_naming_a_directory_is_refused_as_not_a_regular_file() {
        let dir = temp_rootcert_dir("directory");
        let err = load_root_certs(&dir).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "the sslrootcert file `{}` isn't a regular file",
                dir.display()
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sslrootcert_naming_a_fifo_is_refused_without_waiting_for_a_writer() {
        let dir = temp_rootcert_dir("fifo");
        let fifo = dir.join("ca.fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || sender.send(load_root_certs(&fifo)));
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("loading the FIFO should not block");
        let err = result.unwrap_err();
        assert!(matches!(err, TlsError::RootCertNotAFile { .. }), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sslrootcert_naming_a_character_device_is_refused_as_not_a_regular_file() {
        let err = load_root_certs(Path::new("/dev/null")).unwrap_err();
        assert!(matches!(err, TlsError::RootCertNotAFile { .. }), "{err}");
    }

    #[test]
    fn sslrootcert_one_byte_over_the_cap_is_refused_as_too_large() {
        let dir = temp_rootcert_dir("over-cap");
        let path = dir.join("ca.pem");
        let mut bundle = TWO_TEST_CAS.to_vec();
        bundle.resize(1_048_577, b'\n');
        std::fs::write(&path, bundle).unwrap();
        let err = load_root_certs(&path).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "the sslrootcert file `{}` is larger than 1048576 bytes",
                path.display()
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sslrootcert_bundle_exactly_at_the_cap_loads_every_certificate() {
        let dir = temp_rootcert_dir("at-cap");
        let path = dir.join("ca.pem");
        let mut bundle = TWO_TEST_CAS.to_vec();
        bundle.resize(1_048_576, b'\n');
        std::fs::write(&path, bundle).unwrap();
        assert_eq!(load_root_certs(&path).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn system_trust_root_builds_a_client_config() {
        assert!(client_config(&TrustRoot::System).is_ok());
    }

    #[test]
    fn server_name_accepts_dns_names_and_ip_addresses() {
        assert!(server_name("db.example.com").is_ok());
        assert!(server_name("localhost").is_ok());
        assert!(server_name("127.0.0.1").is_ok());
        assert!(server_name("::1").is_ok());
    }

    #[test]
    fn untrusted_issuer_without_sslrootcert_names_sslrootcert() {
        let endpoint =
            Endpoint::new("db.example.com".to_owned(), 5432, "app".to_owned(), false).unwrap();
        let msg = describe_rustls_error(
            &endpoint,
            &rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
        );
        assert!(msg.contains("certificate"), "{msg}");
        assert!(msg.contains("sslrootcert"), "{msg}");
    }

    #[test]
    fn hostname_mismatch_reports_the_expected_host_without_suggesting_sslrootcert() {
        let endpoint = Endpoint::with_tls_options(
            "db.example.com".to_owned(),
            5432,
            "app".to_owned(),
            false,
            TrustRoot::PemFile(PathBuf::from("/etc/ssl/rds.pem")),
            ChannelBinding::Prefer,
        )
        .unwrap();
        let msg = describe_rustls_error(
            &endpoint,
            &rustls::Error::InvalidCertificate(CertificateError::NotValidForName),
        );
        assert_eq!(
            msg,
            "TLS certificate doesn't match the host `db.example.com`"
        );
    }

    #[test]
    fn tls_refused_mentions_allow_plaintext_only_for_localhost() {
        let local =
            Endpoint::new("localhost".to_owned(), 5432, "postgres".to_owned(), false).unwrap();
        assert!(describe_tls_refused(&local).contains("--allow-plaintext"));

        let remote =
            Endpoint::new("db.example.com".to_owned(), 5432, "app".to_owned(), false).unwrap();
        assert!(!describe_tls_refused(&remote).contains("--allow-plaintext"));
    }
}
