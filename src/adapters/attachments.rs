use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{
    application::ports::{AttachmentManager, SecureRandom},
    domain::{
        error::{AppError, ErrorCode},
        mail::{OutgoingAttachment, StoredAttachment},
    },
};

use super::config::AttachmentPolicyConfig;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const INSPECTION_BYTES: usize = 8 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_OUTGOING_FILENAME_BYTES: usize = 255;
const MAX_MANAGED_FILENAME_BYTES: usize = 160;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_MANAGED_DOWNLOAD_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
struct Limits {
    maximum_files: usize,
    maximum_file_bytes: u64,
    maximum_total_bytes: u64,
    maximum_download_bytes: u64,
    download_ttl: TimeDelta,
}

pub struct FileAttachmentManager {
    allowed_roots: Vec<PathBuf>,
    downloads_dir: PathBuf,
    limits: Limits,
    random: Arc<dyn SecureRandom>,
}

impl FileAttachmentManager {
    pub fn new(
        policy: &AttachmentPolicyConfig,
        downloads_dir: PathBuf,
        random: Arc<dyn SecureRandom>,
    ) -> Result<Self, AppError> {
        let mut allowed_roots = Vec::with_capacity(policy.allowed_outgoing_roots.len());
        for root in &policy.allowed_outgoing_roots {
            let metadata = fs::symlink_metadata(root).map_err(|error| {
                AppError::with_source(
                    ErrorCode::NotConfigured,
                    "inspect allowed attachment root",
                    "An allowed attachment root is unavailable; update configuration.",
                    error,
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::new(
                    ErrorCode::NotConfigured,
                    "validate allowed attachment root",
                    "An allowed attachment root is not a safe directory.",
                ));
            }
            allowed_roots.push(fs::canonicalize(root).map_err(|error| {
                AppError::with_source(
                    ErrorCode::NotConfigured,
                    "canonicalize allowed attachment root",
                    "An allowed attachment root cannot be resolved.",
                    error,
                )
            })?);
        }
        create_private_directory(&downloads_dir)?;
        let downloads_dir = fs::canonicalize(downloads_dir).map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "canonicalize attachment download directory",
                "Attachment download directory cannot be resolved.",
                error,
            )
        })?;
        Ok(Self {
            allowed_roots,
            downloads_dir,
            limits: Limits {
                maximum_files: usize::from(policy.maximum_files),
                maximum_file_bytes: policy.maximum_file_bytes,
                maximum_total_bytes: policy.maximum_total_bytes,
                maximum_download_bytes: policy.maximum_download_bytes,
                download_ttl: TimeDelta::hours(i64::from(policy.download_ttl_hours)),
            },
            random,
        })
    }
}

#[async_trait]
impl AttachmentManager for FileAttachmentManager {
    async fn validate_outgoing(
        &self,
        paths: &[String],
    ) -> Result<Vec<OutgoingAttachment>, AppError> {
        if paths.len() > self.limits.maximum_files {
            return Err(AppError::resource_limit(
                "Outgoing attachment count exceeds the configured limit.",
            ));
        }
        if paths
            .iter()
            .any(|path| path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0'))
        {
            return Err(AppError::validation("Attachment path is invalid."));
        }
        let paths = paths.to_vec();
        let roots = self.allowed_roots.clone();
        let limits = self.limits.clone();
        tokio::task::spawn_blocking(move || validate_outgoing_files(&paths, &roots, &limits))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join attachment validator",
                    "Attachment validation stopped unexpectedly.",
                    error,
                )
            })?
    }

    async fn save_incoming(&self, attachment: StoredAttachment) -> Result<PathBuf, AppError> {
        if attachment.metadata.size_bytes != attachment.bytes.len() as u64 {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "validate downloaded attachment size",
                "Attachment changed while it was downloaded.",
            ));
        }
        if attachment.metadata.size_bytes > self.limits.maximum_download_bytes {
            return Err(AppError::resource_limit(
                "Attachment exceeds the configured download limit.",
            ));
        }
        let mut random_bytes = [0_u8; 18];
        self.random.fill(&mut random_bytes)?;
        let identifier = URL_SAFE_NO_PAD.encode(random_bytes);
        let filename = sanitize_filename(&attachment.metadata.filename);
        let destination = self
            .downloads_dir
            .join(format!("attachment-{identifier}-{filename}"));
        let bytes = attachment.bytes;
        let expected_length = attachment.metadata.size_bytes;
        tokio::task::spawn_blocking(move || {
            write_new_private_file(&destination, &bytes, expected_length)?;
            Ok(destination)
        })
        .await
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::Internal,
                "join attachment writer",
                "Attachment download stopped unexpectedly.",
                error,
            )
        })?
    }

    async fn cleanup_expired(&self, now: DateTime<Utc>) -> Result<u64, AppError> {
        let directory = self.downloads_dir.clone();
        let cutoff = now
            .checked_sub_signed(self.limits.download_ttl)
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::Internal,
                    "calculate attachment cleanup cutoff",
                    "Attachment cleanup cutoff could not be calculated.",
                )
            })?;
        tokio::task::spawn_blocking(move || cleanup_managed_files(&directory, cutoff))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join attachment cleanup",
                    "Attachment cleanup stopped unexpectedly.",
                    error,
                )
            })?
    }
}

fn validate_outgoing_files(
    paths: &[String],
    allowed_roots: &[PathBuf],
    limits: &Limits,
) -> Result<Vec<OutgoingAttachment>, AppError> {
    let mut validated = Vec::with_capacity(paths.len());
    let mut total_bytes = 0_u64;
    for value in paths {
        if value.is_empty() || value.len() > MAX_PATH_BYTES || value.contains('\0') {
            return Err(AppError::validation("Attachment path is invalid."));
        }
        let path = Path::new(value);
        if !path.is_absolute() {
            return Err(AppError::validation("Attachment paths must be absolute."));
        }
        let before = fs::symlink_metadata(path).map_err(|error| {
            AppError::with_source(
                ErrorCode::NotFound,
                "inspect outgoing attachment",
                "An outgoing attachment is unavailable.",
                error,
            )
        })?;
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(AppError::validation(
                "Attachments must be regular files, not links or directories.",
            ));
        }
        if before.len() > limits.maximum_file_bytes {
            return Err(AppError::resource_limit(
                "An outgoing attachment exceeds the per-file limit.",
            ));
        }
        total_bytes = total_bytes
            .checked_add(before.len())
            .ok_or_else(|| AppError::resource_limit("Attachment total size is too large."))?;
        if total_bytes > limits.maximum_total_bytes {
            return Err(AppError::resource_limit(
                "Outgoing attachments exceed the total-size limit.",
            ));
        }
        let canonical_path = fs::canonicalize(path).map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "canonicalize outgoing attachment",
                "An outgoing attachment path cannot be resolved.",
                error,
            )
        })?;
        if !allowed_roots
            .iter()
            .any(|root| canonical_path.starts_with(root))
        {
            return Err(AppError::new(
                ErrorCode::PermissionDenied,
                "authorize outgoing attachment path",
                "An outgoing attachment is outside the configured allowlist.",
            ));
        }
        let inspected = inspect_file(&canonical_path, &before, limits.maximum_file_bytes)?;
        if validated.iter().any(|existing: &OutgoingAttachment| {
            existing.display_name.to_lowercase() == inspected.display_name.to_lowercase()
        }) {
            return Err(AppError::validation(
                "Outgoing attachments must have unique display filenames.",
            ));
        }
        validated.push(inspected);
    }
    Ok(validated)
}

fn inspect_file(
    path: &Path,
    before: &fs::Metadata,
    maximum_bytes: u64,
) -> Result<OutgoingAttachment, AppError> {
    let mut file = File::open(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "open outgoing attachment",
            "An outgoing attachment cannot be read.",
            error,
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut first_bytes = Vec::with_capacity(INSPECTION_BYTES);
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "read outgoing attachment",
                "An outgoing attachment cannot be read.",
                error,
            )
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| AppError::resource_limit("Attachment is too large."))?;
        if total > maximum_bytes {
            return Err(AppError::resource_limit(
                "An outgoing attachment exceeds the per-file limit.",
            ));
        }
        let needed = INSPECTION_BYTES.saturating_sub(first_bytes.len());
        first_bytes.extend(buffer.iter().take(read).take(needed).copied());
        let chunk = buffer.get(..read).ok_or_else(|| {
            AppError::new(
                ErrorCode::Internal,
                "slice attachment read buffer",
                "Attachment could not be inspected safely.",
            )
        })?;
        hasher.update(chunk);
    }
    let after = file.metadata().map_err(|error| {
        AppError::with_source(
            ErrorCode::Conflict,
            "reinspect outgoing attachment",
            "An outgoing attachment changed during validation.",
            error,
        )
    })?;
    if !same_file_snapshot(before, &after) || total != before.len() {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "validate outgoing attachment snapshot",
            "An outgoing attachment changed during validation.",
        ));
    }
    if is_mach_o(&first_bytes) {
        return Err(AppError::validation(
            "Mach-O executable attachments are not supported.",
        ));
    }
    let display_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| {
            !name.is_empty()
                && name.len() <= MAX_OUTGOING_FILENAME_BYTES
                && !name.chars().any(char::is_control)
        })
        .ok_or_else(|| AppError::validation("Attachment filename is invalid."))?
        .nfc()
        .collect::<String>();
    if display_name.len() > MAX_OUTGOING_FILENAME_BYTES {
        return Err(AppError::validation("Attachment filename is invalid."));
    }
    let media_type = infer_media_type(path, &first_bytes);
    let warning = attachment_warning(path, before.mode(), &media_type);
    Ok(OutgoingAttachment {
        canonical_path: path.to_path_buf(),
        display_name,
        media_type,
        size_bytes: total,
        digest: hasher.finalize().into(),
        warning,
    })
}

fn same_file_snapshot(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

fn infer_media_type(path: &Path, first_bytes: &[u8]) -> String {
    if let Some(kind) = infer::get(first_bytes) {
        return kind.mime_type().to_owned();
    }
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt" | "md" | "csv" | "log") => "text/plain",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
    .to_owned()
}

fn attachment_warning(path: &Path, mode: u32, media_type: &str) -> Option<&'static str> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if mode & 0o111 != 0
        || matches!(
            extension.as_deref(),
            Some("sh" | "command" | "workflow" | "scpt" | "js" | "py")
        )
    {
        Some("Attachment appears executable or script-like; verify it before sending.")
    } else if media_type == "application/zip"
        || matches!(
            extension.as_deref(),
            Some("zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar")
        )
    {
        Some("Archive contents were not inspected; verify them before sending.")
    } else {
        None
    }
}

fn is_mach_o(bytes: &[u8]) -> bool {
    let magic = bytes.get(..4);
    matches!(
        magic,
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xbe, 0xba, 0xfe, 0xca])
            | Some([0xca, 0xfe, 0xba, 0xbf])
            | Some([0xbf, 0xba, 0xfe, 0xca])
    )
}

fn sanitize_filename(value: &str) -> String {
    let leaf = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment.bin");
    let mut sanitized = String::new();
    for character in leaf.chars() {
        if sanitized.len().saturating_add(character.len_utf8()) > MAX_MANAGED_FILENAME_BYTES {
            break;
        }
        if character.is_alphanumeric() || matches!(character, '.' | '-' | '_' | ' ') {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }
    let sanitized = sanitized.trim_matches([' ', '.']);
    if sanitized.is_empty() {
        "attachment.bin".to_owned()
    } else {
        sanitized.to_owned()
    }
}

fn create_private_directory(path: &Path) -> Result<(), AppError> {
    fs::create_dir_all(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "create attachment download directory",
            "Attachment download directory cannot be created.",
            error,
        )
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "inspect attachment download directory",
            "Attachment download directory cannot be inspected.",
            error,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::new(
            ErrorCode::PermissionDenied,
            "validate attachment download directory",
            "Attachment download directory is not a safe directory.",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "secure attachment download directory",
            "Attachment download directory cannot be protected.",
            error,
        )
    })
}

fn write_new_private_file(
    destination: &Path,
    bytes: &[u8],
    expected_length: u64,
) -> Result<(), AppError> {
    if bytes.len() as u64 != expected_length {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "write downloaded attachment",
            "Attachment changed while it was downloaded.",
        ));
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(PRIVATE_FILE_MODE)
        .open(destination)
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "create downloaded attachment",
                "Attachment file cannot be created safely.",
                error,
            )
        })?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let cleanup_result = fs::remove_file(destination);
        if let Err(cleanup_error) = cleanup_result {
            tracing::warn!(
                operation = "remove_partial_attachment",
                error_kind = ?cleanup_error.kind(),
                "unable to remove a partial attachment"
            );
        }
        return Err(AppError::with_source(
            ErrorCode::PermissionDenied,
            "write downloaded attachment",
            "Attachment file could not be written completely.",
            error,
        ));
    }
    Ok(())
}

fn cleanup_managed_files(directory: &Path, cutoff: DateTime<Utc>) -> Result<u64, AppError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "enumerate managed attachments",
            "Managed attachment directory cannot be read.",
            error,
        )
    })?;
    let mut removed = 0_u64;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_MANAGED_DOWNLOAD_ENTRIES {
            return Err(AppError::resource_limit(
                "Managed attachment directory contains too many entries.",
            ));
        }
        let entry = entry.map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "read managed attachment entry",
                "A managed attachment entry cannot be inspected.",
                error,
            )
        })?;
        let name = entry.file_name();
        let managed = name
            .to_str()
            .is_some_and(|name| name.starts_with("attachment-"));
        if !managed {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "inspect managed attachment",
                "A managed attachment cannot be inspected.",
                error,
            )
        })?;
        if !(metadata.is_file() || metadata.file_type().is_symlink()) {
            continue;
        }
        let modified = metadata
            .modified()
            .map(DateTime::<Utc>::from)
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::PermissionDenied,
                    "read managed attachment timestamp",
                    "A managed attachment timestamp cannot be read.",
                    error,
                )
            })?;
        if modified <= cutoff {
            fs::remove_file(entry.path()).map_err(|error| {
                AppError::with_source(
                    ErrorCode::PermissionDenied,
                    "remove expired attachment",
                    "An expired managed attachment cannot be removed.",
                    error,
                )
            })?;
            removed = removed.checked_add(1).ok_or_else(|| {
                AppError::resource_limit("Managed attachment count exceeds the supported size.")
            })?;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};

    use crate::{
        adapters::config::AttachmentPolicyConfig,
        application::ports::{AttachmentManager, SecureRandom},
        domain::error::AppError,
    };

    use super::{FileAttachmentManager, is_mach_o};

    #[derive(Debug)]
    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), AppError> {
            destination.fill(11);
            Ok(())
        }
    }

    #[tokio::test]
    async fn outgoing_paths_are_canonicalized_and_confined() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let allowed = temporary.path().join("allowed");
        let downloads = temporary.path().join("downloads");
        fs::create_dir(&allowed).expect("create allowed directory");
        let attachment = allowed.join("notes.txt");
        fs::write(&attachment, b"safe text").expect("write attachment");
        fs::set_permissions(&attachment, fs::Permissions::from_mode(0o600))
            .expect("set attachment permissions");
        let policy = AttachmentPolicyConfig {
            allowed_outgoing_roots: vec![allowed],
            maximum_files: 10,
            maximum_file_bytes: 1024,
            maximum_total_bytes: 2048,
            maximum_download_bytes: 4096,
            download_ttl_hours: 24,
        };
        let manager = FileAttachmentManager::new(&policy, downloads, Arc::new(FixedRandom))
            .expect("create attachment manager");
        let result = manager
            .validate_outgoing(&[attachment.to_string_lossy().into_owned()])
            .await
            .expect("validate attachment");
        assert_eq!(result.len(), 1);
        assert_eq!(result.first().map(|item| item.size_bytes), Some(9));
        let denied = manager.validate_outgoing(&["/etc/hosts".to_owned()]).await;
        assert!(denied.is_err());
    }

    #[test]
    fn all_mach_o_container_magics_are_rejected() {
        for magic in [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ] {
            assert!(is_mach_o(&magic));
        }
    }
}
