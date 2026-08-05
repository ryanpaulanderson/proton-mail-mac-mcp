use std::{fs, io::IsTerminal, path::PathBuf, sync::Arc};

use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::BaseDirs;
use rmcp::{ServiceExt, service::QuitReason};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    adapters::{
        applescript::{AppleScriptUi, OsascriptRunner, install_embedded_script},
        attachments::FileAttachmentManager,
        config::{
            AppConfig, AppPaths, AttachmentPolicyConfig, BridgeConfig, BridgeTlsMode, FolderRoles,
            TomlConfigStore, enroll_certificate,
        },
        imap::BridgeImapRepository,
        keychain::KeychainSecretStore,
        platform::{SystemClock, SystemSecureRandom},
        references::EncryptedReferenceCodec,
    },
    application::{
        ports::{ConfigStore, SecretStore, SecureRandom},
        service::MailApplication,
    },
    domain::{
        error::{AppError, ErrorCode},
        value::{EmailAddress, MailboxName},
    },
    mcp::MailMcpServer,
};

const KEYCHAIN_SERVICE: &str = "io.github.ryanpaulanderson.proton-mail-mac-mcp";
const REFERENCE_KEY_BYTES: usize = 32;
const MAX_BRIDGE_PASSWORD_BYTES: usize = 4_096;

#[derive(Debug, Parser)]
#[command(
    name = "proton-mail-mac-mcp",
    version,
    about = "Local, confirmation-gated Proton Mail MCP server for macOS"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the stdio MCP server. Stdout is reserved for MCP frames.
    Serve,
    /// Enroll Proton Mail Bridge, Keychain credentials, and local safety policy.
    Configure(Box<ConfigureArgs>),
}

#[derive(Debug, Args)]
struct ConfigureArgs {
    /// Stable local profile name used to scope Keychain secrets and opaque references.
    #[arg(long, default_value = "primary")]
    profile: String,
    /// Proton account address represented by this profile.
    #[arg(long)]
    account: String,
    /// IMAP username shown by Proton Mail Bridge.
    #[arg(long)]
    bridge_username: String,
    /// From address used for drafts; defaults to --account.
    #[arg(long)]
    default_from: Option<String>,
    /// Proton Mail Bridge IMAP port.
    #[arg(long, default_value_t = 1143)]
    imap_port: u16,
    /// Bridge IMAP transport mode shown in Bridge settings.
    #[arg(long, value_enum, default_value_t = TlsModeArgument::StartTls)]
    tls_mode: TlsModeArgument,
    /// Hostname validated against the enrolled Bridge certificate.
    #[arg(long, default_value = "localhost")]
    tls_server_name: String,
    /// PEM or DER certificate exported from Proton Mail Bridge.
    #[arg(long)]
    certificate: PathBuf,
    /// Allowed root for outgoing attachments; repeat for multiple roots.
    #[arg(long = "allowed-root")]
    allowed_roots: Vec<PathBuf>,
    /// Configured Drafts mailbox name.
    #[arg(long, default_value = "Drafts")]
    drafts_folder: String,
    /// Configured Sent mailbox name.
    #[arg(long, default_value = "Sent")]
    sent_folder: String,
    /// Configured Trash mailbox name.
    #[arg(long, default_value = "Trash")]
    trash_folder: String,
    /// Configured Archive mailbox name.
    #[arg(long, default_value = "Archive")]
    archive_folder: String,
    /// Rotate the profile's opaque-reference key, invalidating all prior references.
    #[arg(long)]
    rotate_reference_key: bool,
}

pub async fn run() -> Result<(), AppError> {
    match Cli::parse().command {
        Command::Serve => serve().await,
        Command::Configure(arguments) => configure(*arguments).await,
    }
}

async fn configure(arguments: ConfigureArgs) -> Result<(), AppError> {
    let paths = AppPaths::discover()?;
    paths.create_private_directories()?;

    EmailAddress::parse(arguments.account.clone())?;
    EmailAddress::parse(arguments.bridge_username.clone())?;
    let default_from = arguments
        .default_from
        .unwrap_or_else(|| arguments.account.clone());
    EmailAddress::parse(default_from.clone())?;
    validate_profile(&arguments.profile)?;
    for folder in [
        &arguments.drafts_folder,
        &arguments.sent_folder,
        &arguments.trash_folder,
        &arguments.archive_folder,
    ] {
        MailboxName::parse(folder.clone())?;
    }
    let allowed_roots = canonical_allowed_roots(arguments.allowed_roots)?;
    let password = read_bridge_password().await?;
    validate_bridge_password(&password)?;

    let certificate_sha256 = enroll_certificate(&arguments.certificate, &paths)?;
    let attachments = AttachmentPolicyConfig {
        allowed_outgoing_roots: allowed_roots,
        ..default_attachment_policy()?
    };
    let config = AppConfig::new(
        BridgeConfig {
            profile: arguments.profile.clone(),
            account: arguments.account,
            username: arguments.bridge_username,
            default_from,
            host: "127.0.0.1".to_owned(),
            imap_port: arguments.imap_port,
            tls_mode: arguments.tls_mode.into(),
            tls_server_name: arguments.tls_server_name,
            certificate_sha256,
        },
        FolderRoles {
            drafts: arguments.drafts_folder,
            sent: arguments.sent_folder,
            trash: arguments.trash_folder,
            archive: arguments.archive_folder,
        },
        attachments,
    )?;

    let secrets = KeychainSecretStore::new(KEYCHAIN_SERVICE)?;
    secrets
        .set(
            &bridge_password_key(&arguments.profile),
            password.as_bytes(),
        )
        .await?;
    ensure_reference_key(
        &secrets,
        &arguments.profile,
        arguments.rotate_reference_key,
        &SystemSecureRandom,
    )
    .await?;

    let store = TomlConfigStore::new(paths.config_file.clone());
    store.save(&config).await?;
    install_embedded_script(&paths.ui_script)?;
    tracing::info!(
        "configuration installed; Bridge password and reference key are in macOS Keychain"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TlsModeArgument {
    StartTls,
    ImplicitTls,
}

impl From<TlsModeArgument> for BridgeTlsMode {
    fn from(value: TlsModeArgument) -> Self {
        match value {
            TlsModeArgument::StartTls => Self::StartTls,
            TlsModeArgument::ImplicitTls => Self::ImplicitTls,
        }
    }
}

async fn serve() -> Result<(), AppError> {
    let paths = AppPaths::discover()?;
    paths.create_private_directories()?;
    install_embedded_script(&paths.ui_script)?;

    let config_store = TomlConfigStore::new(paths.config_file.clone());
    let config = config_store.load().await?;
    let secrets = KeychainSecretStore::new(KEYCHAIN_SERVICE)?;
    let bridge_password = secrets
        .get(&bridge_password_key(&config.bridge.profile))
        .await?;
    let reference_key = secrets
        .get(&reference_key_name(&config.bridge.profile))
        .await?;
    let random: Arc<dyn SecureRandom> = Arc::new(SystemSecureRandom);
    let certificate = paths.bridge_certificate(&config.bridge.certificate_sha256);

    let repository = Arc::new(BridgeImapRepository::new(
        &config,
        &certificate,
        bridge_password,
        random.clone(),
    )?);
    let references = Arc::new(EncryptedReferenceCodec::new(
        reference_key,
        &config.bridge.profile,
        random.clone(),
    )?);
    let attachments = Arc::new(FileAttachmentManager::new(
        &config.attachments,
        paths.downloads_dir,
        random.clone(),
    )?);
    let ui = Arc::new(AppleScriptUi::new(
        paths.ui_script,
        Arc::new(OsascriptRunner),
    )?);
    let account = config.account()?;
    let application = Arc::new(MailApplication::new(
        repository,
        ui,
        references,
        attachments,
        Arc::new(SystemClock),
        random,
        account,
    ));
    let server = MailMcpServer::new(application);
    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::Internal,
                "initialize MCP stdio transport",
                "The MCP stdio session could not be initialized.",
                error,
            )
        })?;
    tracing::info!(transport = "stdio", "MCP server started");

    let cancellation = running.cancellation_token();
    let mut waiting = Box::pin(running.waiting());
    let reason = tokio::select! {
        result = &mut waiting => result.map_err(join_server_error)?,
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|error| AppError::with_source(
                ErrorCode::Internal,
                "listen for shutdown signal",
                "The shutdown signal listener failed.",
                error,
            ))?;
            cancellation.cancel();
            waiting.await.map_err(join_server_error)?
        }
    };
    match reason {
        QuitReason::Cancelled | QuitReason::Closed => Ok(()),
        QuitReason::JoinError(error) => Err(join_server_error(error)),
        _ => Err(AppError::new(
            ErrorCode::Internal,
            "stop MCP server",
            "The MCP server stopped for an unsupported reason.",
        )),
    }
}

async fn read_bridge_password() -> Result<Zeroizing<String>, AppError> {
    if !std::io::stdin().is_terminal() {
        return Err(AppError::new(
            ErrorCode::PermissionDenied,
            "read Bridge password",
            "Configure must run in an interactive terminal so the Bridge password is never passed in arguments or environment variables.",
        ));
    }
    tokio::task::spawn_blocking(|| {
        rpassword::prompt_password("Proton Mail Bridge IMAP password: ")
            .map(Zeroizing::new)
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::PermissionDenied,
                    "read Bridge password",
                    "Bridge password could not be read from the terminal.",
                    error,
                )
            })
    })
    .await
    .map_err(|error| {
        AppError::with_source(
            ErrorCode::Internal,
            "join Bridge password reader",
            "Bridge password input stopped unexpectedly.",
            error,
        )
    })?
}

fn validate_bridge_password(password: &str) -> Result<(), AppError> {
    if password.is_empty()
        || password.len() > MAX_BRIDGE_PASSWORD_BYTES
        || password
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(AppError::validation(
            "Bridge password is empty, malformed, or exceeds 4,096 bytes.",
        ));
    }
    Ok(())
}

async fn ensure_reference_key(
    secrets: &dyn SecretStore,
    profile: &str,
    rotate: bool,
    random: &dyn SecureRandom,
) -> Result<(), AppError> {
    let name = reference_key_name(profile);
    if !rotate && secrets.exists(&name).await? {
        let existing = secrets.get(&name).await?;
        if existing.len() != REFERENCE_KEY_BYTES {
            return Err(AppError::new(
                ErrorCode::NotConfigured,
                "validate opaque-reference key",
                "Opaque-reference Keychain material is malformed; rerun configure with --rotate-reference-key.",
            ));
        }
        return Ok(());
    }
    let mut key = [0_u8; REFERENCE_KEY_BYTES];
    random.fill(&mut key)?;
    let result = secrets.set(&name, &key).await;
    key.zeroize();
    result
}

fn canonical_allowed_roots(configured: Vec<PathBuf>) -> Result<Vec<PathBuf>, AppError> {
    let using_defaults = configured.is_empty();
    let roots = if using_defaults {
        default_attachment_policy()?.allowed_outgoing_roots
    } else {
        configured
    };
    canonicalize_allowed_roots(roots, using_defaults)
}

fn canonicalize_allowed_roots(
    roots: Vec<PathBuf>,
    skip_missing: bool,
) -> Result<Vec<PathBuf>, AppError> {
    if roots.len() > 16 {
        return Err(AppError::resource_limit(
            "Configure between 1 and 16 allowed attachment roots.",
        ));
    }
    let mut canonical = Vec::with_capacity(roots.len());
    for root in roots {
        let metadata = match fs::symlink_metadata(&root) {
            Ok(metadata) => metadata,
            Err(error) if skip_missing && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => {
                return Err(AppError::with_source(
                    ErrorCode::ValidationFailed,
                    "inspect allowed attachment root",
                    "An allowed attachment root is unavailable.",
                    error,
                ));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AppError::validation(
                "Allowed attachment roots must be existing directories, not symbolic links.",
            ));
        }
        let resolved = fs::canonicalize(root).map_err(|error| {
            AppError::with_source(
                ErrorCode::ValidationFailed,
                "canonicalize allowed attachment root",
                "An allowed attachment root cannot be resolved.",
                error,
            )
        })?;
        if !canonical.contains(&resolved) {
            canonical.push(resolved);
        }
    }
    if canonical.is_empty() || canonical.len() > 16 {
        return Err(AppError::resource_limit(
            "Configure between 1 and 16 allowed attachment roots.",
        ));
    }
    Ok(canonical)
}

fn default_attachment_policy() -> Result<AttachmentPolicyConfig, AppError> {
    let base = BaseDirs::new().ok_or_else(|| {
        AppError::new(
            ErrorCode::NotConfigured,
            "discover default attachment roots",
            "Unable to locate the macOS home directory.",
        )
    })?;
    Ok(AttachmentPolicyConfig::defaults(base.home_dir()))
}

fn validate_profile(profile: &str) -> Result<(), AppError> {
    if profile.is_empty() || profile.len() > 128 || profile.chars().any(char::is_control) {
        return Err(AppError::validation("Bridge profile name is invalid."));
    }
    Ok(())
}

fn bridge_password_key(profile: &str) -> String {
    format!("bridge-password/{profile}")
}

fn reference_key_name(profile: &str) -> String {
    format!("opaque-reference-key/{profile}")
}

fn join_server_error(error: tokio::task::JoinError) -> AppError {
    AppError::with_source(
        ErrorCode::Internal,
        "join MCP server",
        "The MCP server stopped unexpectedly.",
        error,
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use async_trait::async_trait;
    use zeroize::Zeroizing;

    use crate::{
        application::ports::{SecretStore, SecureRandom},
        domain::error::AppError,
    };

    use super::{
        canonical_allowed_roots, canonicalize_allowed_roots, ensure_reference_key,
        reference_key_name, validate_bridge_password, validate_profile,
    };

    #[test]
    fn configuration_secrets_and_profiles_are_bounded() {
        assert!(validate_profile("primary").is_ok());
        assert!(validate_profile("bad\nprofile").is_err());
        assert!(validate_bridge_password("bridge-secret").is_ok());
        assert!(validate_bridge_password("bridge\nsecret").is_err());
    }

    #[test]
    fn allowed_roots_are_canonical_and_deduplicated() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let roots = canonical_allowed_roots(vec![
            temporary.path().to_path_buf(),
            temporary.path().to_path_buf(),
        ])
        .expect("canonicalize roots");
        assert_eq!(
            roots,
            vec![std::fs::canonicalize(temporary.path()).expect("canonical temporary path")]
        );
    }

    #[test]
    fn absent_default_root_is_skipped_but_absent_explicit_root_is_rejected() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let missing = temporary.path().join("not-created");
        let roots =
            canonicalize_allowed_roots(vec![missing.clone(), temporary.path().to_path_buf()], true)
                .expect("skip absent default root");
        assert_eq!(roots.len(), 1);
        assert!(canonicalize_allowed_roots(vec![missing], false).is_err());
    }

    #[tokio::test]
    async fn reference_key_is_created_once_and_rotated_only_explicitly() {
        let secrets = MemorySecrets::default();
        let random = FixedRandom;
        ensure_reference_key(&secrets, "primary", false, &random)
            .await
            .expect("create reference key");
        let name = reference_key_name("primary");
        assert_eq!(
            secrets.get(&name).await.expect("read key").as_slice(),
            &[7; 32]
        );

        secrets
            .set(&name, &[9; 32])
            .await
            .expect("replace test key");
        ensure_reference_key(&secrets, "primary", false, &random)
            .await
            .expect("preserve key");
        assert_eq!(
            secrets
                .get(&name)
                .await
                .expect("read preserved key")
                .as_slice(),
            &[9; 32]
        );
        ensure_reference_key(&secrets, "primary", true, &random)
            .await
            .expect("rotate key");
        assert_eq!(
            secrets
                .get(&name)
                .await
                .expect("read rotated key")
                .as_slice(),
            &[7; 32]
        );
    }

    #[derive(Default)]
    struct MemorySecrets(Mutex<HashMap<String, Vec<u8>>>);

    #[async_trait]
    impl SecretStore for MemorySecrets {
        async fn get(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
            self.0
                .lock()
                .map_err(|_| AppError::validation("fake secret lock failed"))?
                .get(key)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| AppError::validation("fake secret is missing"))
        }

        async fn set(&self, key: &str, value: &[u8]) -> Result<(), AppError> {
            self.0
                .lock()
                .map_err(|_| AppError::validation("fake secret lock failed"))?
                .insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool, AppError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| AppError::validation("fake secret lock failed"))?
                .contains_key(key))
        }
    }

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), AppError> {
            destination.fill(7);
            Ok(())
        }
    }
}
