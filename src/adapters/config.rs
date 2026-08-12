use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    application::ports::ConfigStore,
    domain::{
        error::{AppError, ErrorCode},
        value::{EmailAddress, MailboxName},
    },
};

const CONFIG_VERSION: u16 = 1;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_ALLOWED_ATTACHMENT_ROOTS: usize = 16;
const MAX_OUTGOING_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_OUTGOING_TOTAL_BYTES: u64 = 18 * 1024 * 1024;
const MAX_INCOMING_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub support_dir: PathBuf,
    pub config_file: PathBuf,
    pub bridge_certificates_dir: PathBuf,
    pub downloads_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self, AppError> {
        let base = BaseDirs::new().ok_or_else(|| {
            AppError::new(
                ErrorCode::NotConfigured,
                "discover application directories",
                "Unable to locate the macOS user directories.",
            )
        })?;
        let support_dir = base
            .home_dir()
            .join("Library/Application Support/proton-mail-mac-mcp");
        Ok(Self::for_support_directory(support_dir))
    }

    pub fn for_root(root: PathBuf) -> Self {
        Self::for_support_directory(root)
    }

    fn for_support_directory(support_dir: PathBuf) -> Self {
        Self {
            config_file: support_dir.join("config.toml"),
            bridge_certificates_dir: support_dir.join("bridge-certificates"),
            downloads_dir: support_dir.join("downloads"),
            support_dir,
        }
    }

    pub fn create_private_directories(&self) -> Result<(), AppError> {
        for directory in [
            &self.support_dir,
            &self.bridge_certificates_dir,
            &self.downloads_dir,
        ] {
            secure_private_directory(directory)?;
        }
        Ok(())
    }

    pub fn bridge_certificate(&self, sha256: &str) -> PathBuf {
        self.bridge_certificates_dir.join(format!("{sha256}.der"))
    }

    pub fn remove_legacy_ui_artifact(&self) -> Result<(), AppError> {
        let path = self.support_dir.join("proton_mail_ui.applescript");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(AppError::with_source(
                    ErrorCode::PermissionDenied,
                    "inspect legacy UI artifact",
                    "The obsolete UI automation artifact could not be inspected.",
                    error,
                ));
            }
        };
        if metadata.is_dir() {
            return Err(AppError::new(
                ErrorCode::PermissionDenied,
                "remove legacy UI artifact",
                "The obsolete UI automation artifact path is unexpectedly a directory.",
            ));
        }
        fs::remove_file(path).map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "remove legacy UI artifact",
                "The obsolete UI automation artifact could not be removed.",
                error,
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub version: u16,
    pub bridge: BridgeConfig,
    pub folders: FolderRoles,
    pub attachments: AttachmentPolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    pub profile: String,
    pub account: String,
    pub username: String,
    pub default_from: String,
    pub host: String,
    pub imap_port: u16,
    #[serde(default)]
    pub tls_mode: BridgeTlsMode,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default = "default_smtp_tls_mode")]
    pub smtp_tls_mode: BridgeTlsMode,
    pub tls_server_name: String,
    pub certificate_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeTlsMode {
    StartTls,
    ImplicitTls,
}

impl Default for BridgeTlsMode {
    fn default() -> Self {
        Self::StartTls
    }
}

const fn default_smtp_port() -> u16 {
    1025
}

const fn default_smtp_tls_mode() -> BridgeTlsMode {
    BridgeTlsMode::StartTls
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderRoles {
    pub drafts: String,
    pub sent: String,
    pub trash: String,
    pub archive: String,
}

impl Default for FolderRoles {
    fn default() -> Self {
        Self {
            drafts: "Drafts".to_owned(),
            sent: "Sent".to_owned(),
            trash: "Trash".to_owned(),
            archive: "Archive".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentPolicyConfig {
    pub allowed_outgoing_roots: Vec<PathBuf>,
    pub maximum_files: u16,
    pub maximum_file_bytes: u64,
    pub maximum_total_bytes: u64,
    pub maximum_download_bytes: u64,
    pub download_ttl_hours: u16,
}

impl AttachmentPolicyConfig {
    pub fn defaults(home: &Path) -> Self {
        Self {
            allowed_outgoing_roots: vec![
                home.join("Desktop"),
                home.join("Documents"),
                home.join("Downloads"),
            ],
            maximum_files: 10,
            maximum_file_bytes: 10 * 1024 * 1024,
            maximum_total_bytes: 18 * 1024 * 1024,
            maximum_download_bytes: 50 * 1024 * 1024,
            download_ttl_hours: 24,
        }
    }
}

impl AppConfig {
    pub fn new(
        bridge: BridgeConfig,
        folders: FolderRoles,
        attachments: AttachmentPolicyConfig,
    ) -> Result<Self, AppError> {
        let config = Self {
            version: CONFIG_VERSION,
            bridge,
            folders,
            attachments,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), AppError> {
        if self.version != CONFIG_VERSION {
            return Err(AppError::new(
                ErrorCode::NotConfigured,
                "load configuration",
                "Configuration version is unsupported; run configure again.",
            ));
        }
        if self.bridge.profile.is_empty()
            || self.bridge.profile.len() > 128
            || self.bridge.profile.chars().any(char::is_control)
        {
            return Err(AppError::validation("Bridge profile name is invalid."));
        }
        EmailAddress::parse(self.bridge.account.clone())?;
        EmailAddress::parse(self.bridge.username.clone())?;
        EmailAddress::parse(self.bridge.default_from.clone())?;
        if self.bridge.host != "127.0.0.1"
            || self.bridge.imap_port == 0
            || self.bridge.smtp_port == 0
            || self.bridge.imap_port == self.bridge.smtp_port
        {
            return Err(AppError::validation(
                "Bridge must use nonzero IMAP and SMTP ports on 127.0.0.1.",
            ));
        }
        if !matches!(
            self.bridge.tls_server_name.as_str(),
            "127.0.0.1" | "localhost"
        ) {
            return Err(AppError::validation(
                "Bridge TLS server name must be localhost or 127.0.0.1.",
            ));
        }
        if self.bridge.certificate_sha256.len() != 64
            || !self
                .bridge
                .certificate_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(AppError::validation(
                "Bridge certificate fingerprint is malformed.",
            ));
        }
        for folder in [
            &self.folders.drafts,
            &self.folders.sent,
            &self.folders.trash,
            &self.folders.archive,
        ] {
            MailboxName::parse(folder.clone())?;
        }
        let folder_roles = [
            self.folders.drafts.to_lowercase(),
            self.folders.sent.to_lowercase(),
            self.folders.trash.to_lowercase(),
            self.folders.archive.to_lowercase(),
        ];
        for (position, folder) in folder_roles.iter().enumerate() {
            if folder_roles
                .iter()
                .skip(position + 1)
                .any(|other| other == folder)
            {
                return Err(AppError::validation(
                    "Drafts, Sent, Trash, and Archive must be distinct mailboxes.",
                ));
            }
        }
        if self.attachments.allowed_outgoing_roots.is_empty()
            || self.attachments.allowed_outgoing_roots.len() > MAX_ALLOWED_ATTACHMENT_ROOTS
            || self.attachments.maximum_files == 0
            || self.attachments.maximum_files > 10
            || self.attachments.maximum_file_bytes == 0
            || self.attachments.maximum_file_bytes > MAX_OUTGOING_ATTACHMENT_BYTES
            || self.attachments.maximum_total_bytes < self.attachments.maximum_file_bytes
            || self.attachments.maximum_total_bytes > MAX_OUTGOING_TOTAL_BYTES
            || self.attachments.maximum_download_bytes == 0
            || self.attachments.maximum_download_bytes > MAX_INCOMING_ATTACHMENT_BYTES
            || self.attachments.download_ttl_hours != 24
        {
            return Err(AppError::validation(
                "Attachment policy is invalid or exceeds the supported safety contract.",
            ));
        }
        Ok(())
    }

    pub fn account(&self) -> Result<EmailAddress, AppError> {
        EmailAddress::parse(self.bridge.default_from.clone())
    }
}

#[derive(Debug, Clone)]
pub struct TomlConfigStore {
    path: PathBuf,
}

impl TomlConfigStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl ConfigStore for TomlConfigStore {
    type Config = AppConfig;

    async fn load(&self) -> Result<Self::Config, AppError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || read_config(&path))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join configuration reader",
                    "Configuration reader stopped unexpectedly.",
                    error,
                )
            })?
    }

    async fn save(&self, config: &Self::Config) -> Result<(), AppError> {
        config.validate()?;
        let path = self.path.clone();
        let config = config.clone();
        tokio::task::spawn_blocking(move || write_config(&path, &config))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join configuration writer",
                    "Configuration writer stopped unexpectedly.",
                    error,
                )
            })?
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

pub fn install_certificate(source: &Path, destination: &Path) -> Result<String, AppError> {
    let (der, digest) = read_certificate(source)?;
    atomic_write(destination, &der)?;
    Ok(digest)
}

pub fn enroll_certificate(source: &Path, paths: &AppPaths) -> Result<String, AppError> {
    let (der, digest) = read_certificate(source)?;
    let destination = paths.bridge_certificate(&digest);
    atomic_write(&destination, &der)?;
    Ok(digest)
}

fn read_certificate(source: &Path) -> Result<(Vec<u8>, String), AppError> {
    let metadata = fs::symlink_metadata(source).map_err(|error| {
        AppError::with_source(
            ErrorCode::ValidationFailed,
            "inspect Bridge certificate",
            "Bridge certificate file cannot be read.",
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(AppError::validation(
            "Bridge certificate must be a regular file no larger than one megabyte.",
        ));
    }
    let bytes = fs::read(source).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "read Bridge certificate",
            "Bridge certificate file cannot be read.",
            error,
        )
    })?;
    let certificate = native_tls::Certificate::from_pem(&bytes)
        .or_else(|_| native_tls::Certificate::from_der(&bytes))
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::TlsValidationFailed,
                "parse Bridge certificate",
                "Bridge certificate is not valid PEM or DER.",
                error,
            )
        })?;
    let der = certificate.to_der().map_err(|error| {
        AppError::with_source(
            ErrorCode::TlsValidationFailed,
            "normalize Bridge certificate",
            "Bridge certificate could not be normalized safely.",
            error,
        )
    })?;
    let digest = hex_digest(&der);
    Ok((der, digest))
}

pub fn verify_certificate(path: &Path, expected_sha256: &str) -> Result<Vec<u8>, AppError> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::TlsValidationFailed,
            "read enrolled Bridge certificate",
            "Enrolled Bridge certificate is unavailable; run configure again.",
            error,
        )
    })?;
    if hex_digest(&bytes) != expected_sha256.to_ascii_lowercase() {
        return Err(AppError::new(
            ErrorCode::TlsValidationFailed,
            "verify enrolled Bridge certificate",
            "Bridge certificate changed; run configure to trust the new certificate.",
        ));
    }
    native_tls::Certificate::from_der(&bytes).map_err(|error| {
        AppError::with_source(
            ErrorCode::TlsValidationFailed,
            "parse enrolled Bridge certificate",
            "Enrolled Bridge certificate is invalid; run configure again.",
            error,
        )
    })?;
    Ok(bytes)
}

fn read_config(path: &Path) -> Result<AppConfig, AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotConfigured
        } else {
            ErrorCode::PermissionDenied
        };
        AppError::with_source(
            code,
            "open configuration",
            "Configuration is unavailable; run configure.",
            error,
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CONFIG_BYTES
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AppError::new(
            ErrorCode::NotConfigured,
            "validate configuration file",
            "Configuration file is not a safe regular file.",
        ));
    }
    let file = OpenOptions::new().read(true).open(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "read configuration",
            "Configuration cannot be read.",
            error,
        )
    })?;
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::ValidationFailed,
                "decode configuration",
                "Configuration is not valid UTF-8 text.",
                error,
            )
        })?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return Err(AppError::resource_limit("Configuration file is too large."));
    }
    let config: AppConfig = toml::from_str(&contents).map_err(|error| {
        AppError::with_source(
            ErrorCode::ValidationFailed,
            "parse configuration",
            "Configuration is malformed; run configure again.",
            error,
        )
    })?;
    config.validate()?;
    Ok(config)
}

fn write_config(path: &Path, config: &AppConfig) -> Result<(), AppError> {
    let encoded = toml::to_string_pretty(config).map_err(|error| {
        AppError::with_source(
            ErrorCode::Internal,
            "encode configuration",
            "Configuration could not be encoded.",
            error,
        )
    })?;
    if encoded.len() as u64 > MAX_CONFIG_BYTES {
        return Err(AppError::resource_limit("Configuration is too large."));
    }
    atomic_write(path, encoded.as_bytes())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let parent = path.parent().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "resolve configuration directory",
            "Configuration path has no parent directory.",
        )
    })?;
    secure_private_directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "create temporary configuration",
            "Secure temporary configuration cannot be created.",
            error,
        )
    })?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "secure temporary configuration",
                "Secure temporary configuration cannot be protected.",
                error,
            )
        })?;
    temporary.write_all(bytes).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "write temporary configuration",
            "Configuration cannot be written.",
            error,
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "sync temporary configuration",
            "Configuration cannot be synchronized to disk.",
            error,
        )
    })?;
    temporary.persist(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "replace configuration",
            "Configuration cannot be installed atomically.",
            error.error,
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "sync configuration directory",
                "Configuration directory cannot be synchronized.",
                error,
            )
        })?;
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn secure_private_directory(path: &Path) -> Result<(), AppError> {
    fs::create_dir_all(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "create private application directory",
            "Unable to create a private application directory.",
            error,
        )
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "inspect private application directory",
            "Unable to inspect a private application directory.",
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::new(
            ErrorCode::PermissionDenied,
            "validate private application directory",
            "A private application directory is not a safe directory.",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "secure private application directory",
            "Unable to secure a private application directory.",
            error,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config(root: &Path) -> AppConfig {
        AppConfig::new(
            BridgeConfig {
                profile: "primary".to_owned(),
                account: "alice@example.com".to_owned(),
                username: "alice@example.com".to_owned(),
                default_from: "alice@example.com".to_owned(),
                host: "127.0.0.1".to_owned(),
                imap_port: 1143,
                tls_mode: BridgeTlsMode::StartTls,
                smtp_port: 1025,
                smtp_tls_mode: BridgeTlsMode::ImplicitTls,
                tls_server_name: "127.0.0.1".to_owned(),
                certificate_sha256: "a".repeat(64),
            },
            FolderRoles::default(),
            AttachmentPolicyConfig::defaults(root),
        )
        .expect("valid configuration")
    }

    #[tokio::test]
    async fn configuration_round_trip_and_unknown_version_rejection() {
        let directory = tempfile::tempdir().expect("create test directory");
        let paths = AppPaths::for_root(directory.path().to_path_buf());
        paths
            .create_private_directories()
            .expect("create private test directories");
        let config = valid_config(directory.path());
        let store = TomlConfigStore::new(paths.config_file);
        store.save(&config).await.expect("save configuration");
        let loaded = store.load().await.expect("load configuration");
        assert_eq!(loaded.version, CONFIG_VERSION);

        let mut unsupported = config;
        unsupported.version = CONFIG_VERSION.saturating_add(1);
        let encoded = toml::to_string_pretty(&unsupported).expect("encode unsupported config");
        std::fs::write(store.path(), encoded).expect("write unsupported config");
        std::fs::set_permissions(
            store.path(),
            std::fs::Permissions::from_mode(PRIVATE_FILE_MODE),
        )
        .expect("secure unsupported config");
        let error = store.load().await.expect_err("reject unknown version");
        assert_eq!(error.code(), ErrorCode::NotConfigured);
    }

    #[tokio::test]
    async fn configuration_rejects_broad_permissions_and_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("create test directory");
        let paths = AppPaths::for_root(directory.path().join("support"));
        paths
            .create_private_directories()
            .expect("create private test directories");
        let store = TomlConfigStore::new(paths.config_file.clone());
        store
            .save(&valid_config(directory.path()))
            .await
            .expect("save configuration");

        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o640))
            .expect("broaden configuration permissions");
        let error = store
            .load()
            .await
            .expect_err("reject group-readable configuration");
        assert_eq!(error.code(), ErrorCode::NotConfigured);

        let target = directory.path().join("external-config.toml");
        std::fs::rename(store.path(), &target).expect("move real configuration");
        symlink(&target, store.path()).expect("create configuration symlink");
        let error = store
            .load()
            .await
            .expect_err("reject configuration symlink");
        assert_eq!(error.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn legacy_ui_artifact_is_removed_without_recursive_deletion() {
        let directory = tempfile::tempdir().expect("create test directory");
        let paths = AppPaths::for_root(directory.path().join("support"));
        paths
            .create_private_directories()
            .expect("create private directories");
        let artifact = paths.support_dir.join("proton_mail_ui.applescript");
        std::fs::write(&artifact, "legacy generated source").expect("write legacy artifact");
        paths
            .remove_legacy_ui_artifact()
            .expect("remove legacy artifact");
        assert!(!artifact.exists());

        std::fs::create_dir(&artifact).expect("create unexpected directory");
        assert!(paths.remove_legacy_ui_artifact().is_err());
        assert!(artifact.is_dir());
    }

    #[test]
    fn legacy_version_one_config_defaults_both_transports_to_starttls() {
        let directory = tempfile::tempdir().expect("create test directory");
        let encoded = toml::to_string_pretty(&valid_config(directory.path()))
            .expect("encode configuration")
            .lines()
            .filter(|line| {
                !line.starts_with("tls_mode = ")
                    && !line.starts_with("smtp_port = ")
                    && !line.starts_with("smtp_tls_mode = ")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let decoded: AppConfig = toml::from_str(&encoded).expect("decode legacy configuration");
        assert_eq!(decoded.bridge.tls_mode, BridgeTlsMode::StartTls);
        assert_eq!(decoded.bridge.smtp_port, 1025);
        assert_eq!(decoded.bridge.smtp_tls_mode, BridgeTlsMode::StartTls);
        decoded.validate().expect("validate legacy configuration");
    }

    #[test]
    fn security_sensitive_configuration_limits_fail_closed() {
        let directory = tempfile::tempdir().expect("create test directory");

        let mut duplicate_roles = valid_config(directory.path());
        duplicate_roles.folders.trash = "drafts".to_owned();
        assert!(duplicate_roles.validate().is_err());

        let mut uppercase_fingerprint = valid_config(directory.path());
        uppercase_fingerprint.bridge.certificate_sha256 = "A".repeat(64);
        assert!(uppercase_fingerprint.validate().is_err());

        let mut oversized_attachment = valid_config(directory.path());
        oversized_attachment.attachments.maximum_file_bytes =
            MAX_OUTGOING_ATTACHMENT_BYTES.saturating_add(1);
        assert!(oversized_attachment.validate().is_err());
    }
}
