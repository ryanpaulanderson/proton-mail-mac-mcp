use std::{
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;
use zeroize::Zeroizing;

use crate::domain::error::{AppError, ErrorCode};

use super::BridgeEndpoint;

pub(super) type ImapSession = async_imap::Session<TlsStream<TcpStream>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct BridgeConnector {
    endpoint: BridgeEndpoint,
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    username: String,
    password: Zeroizing<String>,
}

impl BridgeConnector {
    pub(super) fn new(
        endpoint: BridgeEndpoint,
        certificate_der: Vec<u8>,
        certificate_sha256: [u8; 32],
        username: String,
        password: Zeroizing<String>,
    ) -> Self {
        Self {
            endpoint,
            certificate_der,
            certificate_sha256,
            username,
            password,
        }
    }

    pub(super) async fn connect(&self) -> Result<ImapSession, AppError> {
        tokio::time::timeout(CONNECT_TIMEOUT, self.connect_inner())
            .await
            .map_err(|_| {
                AppError::new(
                    ErrorCode::BridgeUnavailable,
                    "connect to Proton Mail Bridge",
                    "Proton Mail Bridge did not respond before the connection timeout.",
                )
            })?
    }

    async fn connect_inner(&self) -> Result<ImapSession, AppError> {
        let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.endpoint.port);
        let tcp = TcpStream::connect(address).await.map_err(|error| {
            AppError::with_source(
                ErrorCode::BridgeUnavailable,
                "open Bridge TCP connection",
                "Proton Mail Bridge is unavailable on the configured loopback port.",
                error,
            )
        })?;

        let certificate =
            native_tls::Certificate::from_der(&self.certificate_der).map_err(|error| {
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
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let client = match self.endpoint.tls_mode {
            crate::adapters::config::BridgeTlsMode::StartTls => {
                let mut plaintext_client = async_imap::Client::new(tcp);
                require_greeting(&mut plaintext_client).await?;
                plaintext_client
                    .run_command_and_check_ok("STARTTLS", None)
                    .await
                    .map_err(|error| {
                        AppError::with_source(
                            ErrorCode::TlsValidationFailed,
                            "upgrade Bridge connection with STARTTLS",
                            "Proton Mail Bridge did not accept the required STARTTLS upgrade.",
                            error,
                        )
                    })?;
                let tcp = plaintext_client.into_inner();
                let tls = negotiate_tls(
                    &connector,
                    &self.endpoint.tls_server_name,
                    tcp,
                    self.certificate_sha256,
                )
                .await?;
                async_imap::Client::new(tls)
            }
            crate::adapters::config::BridgeTlsMode::ImplicitTls => {
                let tls = negotiate_tls(
                    &connector,
                    &self.endpoint.tls_server_name,
                    tcp,
                    self.certificate_sha256,
                )
                .await?;
                let mut client = async_imap::Client::new(tls);
                require_greeting(&mut client).await?;
                client
            }
        };
        let client = client;
        client
            .login(&self.username, self.password.as_str())
            .await
            .map_err(|(error, _client)| {
                AppError::with_source(
                    ErrorCode::AuthenticationFailed,
                    "authenticate to Proton Mail Bridge",
                    "Proton Mail Bridge rejected the configured credentials; run configure again.",
                    error,
                )
            })
    }
}

async fn negotiate_tls(
    connector: &tokio_native_tls::TlsConnector,
    server_name: &str,
    tcp: TcpStream,
    certificate_sha256: [u8; 32],
) -> Result<TlsStream<TcpStream>, AppError> {
    let tls = connector.connect(server_name, tcp).await.map_err(|error| {
        AppError::with_source(
            ErrorCode::TlsValidationFailed,
            "negotiate Bridge TLS",
            "Proton Mail Bridge TLS verification failed; run configure if its certificate changed.",
            error,
        )
    })?;
    verify_peer_certificate(&tls, certificate_sha256)?;
    Ok(tls)
}

async fn require_greeting<T>(client: &mut async_imap::Client<T>) -> Result<(), AppError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + std::fmt::Debug,
{
    let greeting = client.read_response().await.map_err(|error| {
        AppError::with_source(
            ErrorCode::BridgeUnavailable,
            "read Bridge greeting",
            "Proton Mail Bridge ended the connection before greeting.",
            error,
        )
    })?;
    if greeting.is_none() {
        return Err(AppError::new(
            ErrorCode::BridgeUnavailable,
            "read Bridge greeting",
            "Proton Mail Bridge ended the connection before greeting.",
        ));
    }
    Ok(())
}

fn verify_peer_certificate(
    stream: &TlsStream<TcpStream>,
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
