use std::time::Duration;

use tokio::net::TcpStream;
use tokio_native_tls::TlsStream;
use zeroize::Zeroizing;

use crate::{
    adapters::bridge::PinnedBridgeTls,
    domain::error::{AppError, ErrorCode},
};

use super::BridgeEndpoint;

pub(super) type ImapSession = async_imap::Session<TlsStream<TcpStream>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct BridgeConnector {
    endpoint: BridgeEndpoint,
    tls: PinnedBridgeTls,
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
    ) -> Result<Self, AppError> {
        let tls = PinnedBridgeTls::new(
            &certificate_der,
            certificate_sha256,
            endpoint.tls_server_name.clone(),
        )?;
        Ok(Self {
            endpoint,
            tls,
            username,
            password,
        })
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
        let tcp = self.tls.open_loopback(self.endpoint.port).await?;
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
                let tls = self.tls.negotiate(tcp).await?;
                async_imap::Client::new(tls)
            }
            crate::adapters::config::BridgeTlsMode::ImplicitTls => {
                let tls = self.tls.negotiate(tcp).await?;
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
