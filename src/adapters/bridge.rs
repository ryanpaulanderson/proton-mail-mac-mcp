use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;
use zeroize::{Zeroize, Zeroizing};

use crate::domain::error::{AppError, ErrorCode};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) type BridgeTlsStream = TlsStream<TcpStream>;

/// Opens only loopback connections and authenticates Bridge with both normal
/// certificate validation and the certificate fingerprint enrolled by the user.
pub(crate) struct PinnedBridgeTls {
    connector: tokio_native_tls::TlsConnector,
    server_name: String,
    certificate_sha256: [u8; 32],
}

impl PinnedBridgeTls {
    pub(crate) fn new(
        certificate_der: &[u8],
        certificate_sha256: [u8; 32],
        server_name: String,
    ) -> Result<Self, AppError> {
        let certificate = native_tls::Certificate::from_der(certificate_der).map_err(|error| {
            AppError::with_source(
                ErrorCode::TlsValidationFailed,
                "parse enrolled Bridge certificate",
                "The enrolled Bridge certificate is invalid; run configure again.",
                error,
            )
        })?;
        let mut builder = native_tls::TlsConnector::builder();
        builder.disable_built_in_roots(true);
        builder.add_root_certificate(certificate);
        let connector = builder.build().map_err(|error| {
            AppError::with_source(
                ErrorCode::TlsValidationFailed,
                "build Bridge TLS connector",
                "A strict TLS connection to Proton Mail Bridge could not be prepared.",
                error,
            )
        })?;
        Ok(Self {
            connector: tokio_native_tls::TlsConnector::from(connector),
            server_name,
            certificate_sha256,
        })
    }

    pub(crate) async fn open_loopback(&self, port: u16) -> Result<TcpStream, AppError> {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| {
                AppError::new(
                    ErrorCode::BridgeUnavailable,
                    "connect to Proton Mail Bridge",
                    "Proton Mail Bridge did not respond before the connection timeout.",
                )
            })?
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::BridgeUnavailable,
                    "open Bridge TCP connection",
                    "Proton Mail Bridge is unavailable on the configured loopback port.",
                    error,
                )
            })
    }

    pub(crate) async fn negotiate(&self, tcp: TcpStream) -> Result<BridgeTlsStream, AppError> {
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.connector.connect(&self.server_name, tcp),
        )
            .await
            .map_err(|_| {
                AppError::new(
                    ErrorCode::TlsValidationFailed,
                    "negotiate Bridge TLS",
                    "Proton Mail Bridge TLS negotiation timed out.",
                )
            })?
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::TlsValidationFailed,
                    "negotiate Bridge TLS",
                    "Proton Mail Bridge TLS verification failed; run configure if its certificate changed.",
                    error,
                )
            })?;
        verify_peer_certificate(&tls, self.certificate_sha256)?;
        Ok(tls)
    }
}

fn verify_peer_certificate(
    stream: &BridgeTlsStream,
    expected_sha256: [u8; 32],
) -> Result<(), AppError> {
    let certificate = stream
        .get_ref()
        .peer_certificate()
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::TlsValidationFailed,
                "read Bridge peer certificate",
                "Proton Mail Bridge certificate could not be verified.",
                error,
            )
        })?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::TlsValidationFailed,
                "read Bridge peer certificate",
                "Proton Mail Bridge did not present a certificate.",
            )
        })?;
    let der = certificate.to_der().map_err(|error| {
        AppError::with_source(
            ErrorCode::TlsValidationFailed,
            "encode Bridge peer certificate",
            "Proton Mail Bridge certificate could not be verified.",
            error,
        )
    })?;
    let actual: [u8; 32] = Sha256::digest(&der).into();
    if actual != expected_sha256 {
        return Err(AppError::new(
            ErrorCode::TlsValidationFailed,
            "pin Bridge peer certificate",
            "Proton Mail Bridge certificate changed; run configure to review it.",
        ));
    }
    Ok(())
}

pub(crate) fn decode_certificate_sha256(value: &str) -> Result<[u8; 32], AppError> {
    if value.len() != 64 {
        return Err(AppError::validation(
            "Bridge certificate fingerprint is malformed.",
        ));
    }
    let mut output = [0_u8; 32];
    let mut chunks = value.as_bytes().chunks_exact(2);
    for (index, pair) in chunks.by_ref().enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| AppError::validation("Bridge certificate fingerprint is malformed."))?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| AppError::validation("Bridge certificate fingerprint is malformed."))?;
        let destination = output
            .get_mut(index)
            .ok_or_else(|| AppError::validation("Bridge certificate fingerprint is malformed."))?;
        *destination = byte;
    }
    if !chunks.remainder().is_empty() {
        output.zeroize();
        return Err(AppError::validation(
            "Bridge certificate fingerprint is malformed.",
        ));
    }
    Ok(output)
}

pub(crate) fn decode_bridge_password(
    mut password_bytes: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<String>, AppError> {
    let password = String::from_utf8(password_bytes.to_vec()).map_err(|error| {
        AppError::with_source(
            ErrorCode::NotConfigured,
            "decode Bridge password",
            "Bridge password in Keychain is malformed; run configure again.",
            error,
        )
    })?;
    password_bytes.zeroize();
    if password.is_empty()
        || password.len() > 4_096
        || password
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(AppError::new(
            ErrorCode::NotConfigured,
            "validate Bridge password",
            "Bridge password in Keychain is malformed; run configure again.",
        ));
    }
    Ok(Zeroizing::new(password))
}
