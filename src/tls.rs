//! Verified TLS configuration, error messages and RFC 5929 channel-binding digests shared by
//! the admin connection and the proxy's upstream connections.

use std::error::Error as StdError;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::{CertificateError, ClientConfig, RootCertStore};
use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, ServerName};
use rustls_platform_verifier::BuilderVerifierExt;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::oid::db::rfc5912::{
    ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, ID_MD_5, ID_SHA_1, ID_SHA_256,
    ID_SHA_384, ID_SHA_512, MD_5_WITH_RSA_ENCRYPTION, SHA_1_WITH_RSA_ENCRYPTION,
    SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
};

use crate::endpoint::{Endpoint, Tls, TrustRoot};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("couldn't read the sslrootcert file `{path}`: {source}")]
    ReadRootCert {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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

fn load_root_certs(path: &Path) -> Result<RootCertStore, TlsError> {
    let certs = CertificateDer::pem_file_iter(path).map_err(|err| map_pem_error(path, err))?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
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

/// Hash of the peer's DER-encoded leaf certificate for RFC 5929 §4.1 `tls-server-end-point`
/// SCRAM-SHA-256-PLUS channel binding. Returns `None` for certificates using pure signature
/// algorithms (such as Ed25519) that define no hash function.
pub fn server_end_point_digest(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = Certificate::from_der(cert_der).ok()?;
    let algorithm = channel_binding_hash(cert.signature_algorithm.oid)?;
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

/// Maps a certificate's signature algorithm OID to its RFC 5929 §4.1 channel-binding hash.
/// MD5 and SHA-1 are upgraded to SHA-256 per RFC 5929 §4.1.
fn channel_binding_hash(oid: ObjectIdentifier) -> Option<ChannelBindingHash> {
    match oid {
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::ChannelBinding;
    use x509_cert::der::Encode;
    use x509_cert::der::asn1::BitString;
    use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};

    fn minimal_cert_der(sig_oid: ObjectIdentifier) -> Vec<u8> {
        let alg = AlgorithmIdentifierOwned {
            oid: sig_oid,
            parameters: None,
        };
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

    #[test]
    fn rfc_5929_maps_sha256_sha384_sha512_and_upgrades_sha1_and_md5_to_sha256() {
        assert_eq!(
            channel_binding_hash(SHA_256_WITH_RSA_ENCRYPTION),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(ECDSA_WITH_SHA_256),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(SHA_1_WITH_RSA_ENCRYPTION),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(MD_5_WITH_RSA_ENCRYPTION),
            Some(ChannelBindingHash::Sha256)
        );
        assert_eq!(
            channel_binding_hash(SHA_384_WITH_RSA_ENCRYPTION),
            Some(ChannelBindingHash::Sha384)
        );
        assert_eq!(
            channel_binding_hash(ECDSA_WITH_SHA_384),
            Some(ChannelBindingHash::Sha384)
        );
        assert_eq!(
            channel_binding_hash(SHA_512_WITH_RSA_ENCRYPTION),
            Some(ChannelBindingHash::Sha512)
        );
        assert_eq!(
            channel_binding_hash(ECDSA_WITH_SHA_512),
            Some(ChannelBindingHash::Sha512)
        );
        assert_eq!(channel_binding_hash(ID_ED_25519), None);
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

        let ed25519_der = minimal_cert_der(ID_ED_25519);
        assert_eq!(server_end_point_digest(&ed25519_der), None);
        assert_eq!(server_end_point_digest(b"not-a-der-cert"), None);
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
