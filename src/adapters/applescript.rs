use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use crate::{
    application::ports::{UiAutomation, UiHealth},
    domain::{
        error::{AppError, ErrorCode},
        mail::{SendOutcome, StoredDraft},
    },
};

const SCRIPT_SOURCE: &[u8] = include_bytes!("../../applescript/proton_mail_ui.applescript");
const SCRIPT_PROTOCOL_VERSION: u8 = 1;
const DEFAULT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(20);
const HEALTH_SCRIPT_TIMEOUT: Duration = Duration::from_secs(15);
const OPEN_DRAFT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(25);
const CONFIRM_SEND_SCRIPT_TIMEOUT: Duration = Duration::from_secs(140);
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDOUT_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 16 * 1024;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[async_trait]
pub trait ScriptRunner: Send + Sync {
    async fn run(&self, script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError>;
}

#[derive(Debug, Default)]
pub struct OsascriptRunner;

#[async_trait]
impl ScriptRunner for OsascriptRunner {
    async fn run(&self, script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError> {
        if request.len() > MAX_REQUEST_BYTES {
            return Err(AppError::resource_limit(
                "AppleScript request exceeds the supported size.",
            ));
        }
        let result =
            tokio::time::timeout(request_timeout(request), run_process(script, request)).await;
        match result {
            Ok(result) => result,
            Err(_) => Err(AppError::new(
                ErrorCode::UiUnavailable,
                "run Proton Mail AppleScript",
                "Proton Mail UI operation timed out; inspect the app before retrying.",
            )),
        }
    }
}

fn request_timeout(request: &[u8]) -> Duration {
    let operation = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| {
            value
                .get("operation")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    match operation.as_deref() {
        Some("health") => HEALTH_SCRIPT_TIMEOUT,
        Some("open_draft") => OPEN_DRAFT_SCRIPT_TIMEOUT,
        Some("confirm_and_send") => CONFIRM_SEND_SCRIPT_TIMEOUT,
        _ => DEFAULT_SCRIPT_TIMEOUT,
    }
}

pub struct AppleScriptUi {
    script: PathBuf,
    runner: std::sync::Arc<dyn ScriptRunner>,
}

impl AppleScriptUi {
    pub fn new(
        script: PathBuf,
        runner: std::sync::Arc<dyn ScriptRunner>,
    ) -> Result<Self, AppError> {
        validate_installed_script(&script)?;
        Ok(Self { script, runner })
    }

    async fn request<T: Serialize>(&self, request: &T) -> Result<ScriptResponse, AppError> {
        validate_installed_script(&self.script)?;
        let encoded = serde_json::to_vec(request).map_err(|error| {
            AppError::with_source(
                ErrorCode::Internal,
                "encode AppleScript request",
                "Proton Mail UI request could not be encoded.",
                error,
            )
        })?;
        if encoded.len() > MAX_REQUEST_BYTES {
            return Err(AppError::resource_limit(
                "AppleScript request exceeds the supported size.",
            ));
        }
        let response = self.runner.run(&self.script, &encoded).await?;
        let decoded: ScriptResponse = serde_json::from_slice(&response).map_err(|error| {
            AppError::with_source(
                ErrorCode::UiUnavailable,
                "decode AppleScript response",
                "Proton Mail UI returned an invalid adapter response.",
                error,
            )
        })?;
        if decoded.version != SCRIPT_PROTOCOL_VERSION {
            return Err(AppError::new(
                ErrorCode::UiUnavailable,
                "validate AppleScript protocol version",
                "Installed Proton Mail UI adapter version is incompatible; restart the server.",
            ));
        }
        match decoded.status {
            ScriptStatus::Ok => Ok(decoded),
            ScriptStatus::Error => Err(script_error(decoded.code.as_deref())),
        }
    }
}

#[async_trait]
impl UiAutomation for AppleScriptUi {
    async fn health(&self) -> Result<UiHealth, AppError> {
        let response = self
            .request(&HealthRequest {
                version: SCRIPT_PROTOCOL_VERSION,
                operation: "health",
            })
            .await?;
        let facts = response.facts.ok_or_else(|| {
            AppError::new(
                ErrorCode::UiUnavailable,
                "read AppleScript health facts",
                "Proton Mail UI health response omitted required facts.",
            )
        })?;
        if facts
            .application_version
            .as_ref()
            .is_some_and(|version| version.len() > 128 || version.chars().any(char::is_control))
        {
            return Err(AppError::new(
                ErrorCode::UiUnavailable,
                "validate Proton Mail application version",
                "Proton Mail UI returned an invalid application version.",
            ));
        }
        Ok(UiHealth {
            application_installed: facts
                .application_installed
                .ok_or_else(missing_health_fact)?,
            application_running: facts.application_running.ok_or_else(missing_health_fact)?,
            accessibility_authorized: facts
                .accessibility_authorized
                .ok_or_else(missing_health_fact)?,
            capability_probe_passed: facts
                .capability_probe_passed
                .ok_or_else(missing_health_fact)?,
            application_version: facts.application_version,
        })
    }

    async fn open_draft(&self, draft: &StoredDraft) -> Result<(), AppError> {
        let internal_id = required_internal_id(draft)?;
        self.request(&OpenDraftRequest {
            version: SCRIPT_PROTOCOL_VERSION,
            operation: "open_draft",
            internal_id,
            row_subject: draft.content.subject.as_str(),
        })
        .await?;
        Ok(())
    }

    async fn confirm_and_send(
        &self,
        draft: &StoredDraft,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<SendOutcome, AppError> {
        let internal_id = required_internal_id(draft)?;
        let response = match self
            .request(&ConfirmSendRequest {
                version: SCRIPT_PROTOCOL_VERSION,
                operation: "confirm_and_send",
                internal_id,
                expires_at_millis: expires_at.timestamp_millis(),
                from: draft.content.account.as_str(),
                to: addresses(draft.content.recipients.to()),
                cc: addresses(draft.content.recipients.cc()),
                bcc: addresses(draft.content.recipients.bcc()),
                subject: draft.content.subject.as_str(),
                body: draft.content.body.as_str(),
                attachment_names: draft
                    .content
                    .attachments
                    .iter()
                    .map(|attachment| attachment.display_name.as_str())
                    .collect(),
            })
            .await
        {
            Ok(response) => response,
            Err(error) if error.code() == ErrorCode::Cancelled => {
                return Ok(SendOutcome::Cancelled);
            }
            Err(error) if error.code() == ErrorCode::UiUnavailable => {
                return Err(AppError::with_source(
                    ErrorCode::SendUnknown,
                    "complete Proton Mail UI send",
                    "Send outcome is uncertain. Check Sent before attempting another send.",
                    error,
                ));
            }
            Err(error) => return Err(error),
        };
        match response.facts.and_then(|facts| facts.outcome) {
            Some(ScriptOutcome::Sent) => Ok(SendOutcome::Sent),
            Some(ScriptOutcome::Cancelled) => Ok(SendOutcome::Cancelled),
            None => Err(AppError::new(
                ErrorCode::SendUnknown,
                "read AppleScript send result",
                "Proton Mail UI did not report a verifiable send outcome.",
            )),
        }
    }
}

#[derive(Debug, Serialize)]
struct HealthRequest {
    version: u8,
    operation: &'static str,
}

#[derive(Debug, Serialize)]
struct OpenDraftRequest<'a> {
    version: u8,
    operation: &'static str,
    internal_id: &'a str,
    row_subject: &'a str,
}

#[derive(Debug, Serialize)]
struct ConfirmSendRequest<'a> {
    version: u8,
    operation: &'static str,
    internal_id: &'a str,
    expires_at_millis: i64,
    from: &'a str,
    to: Vec<&'a str>,
    cc: Vec<&'a str>,
    bcc: Vec<&'a str>,
    subject: &'a str,
    body: &'a str,
    attachment_names: Vec<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptResponse {
    version: u8,
    status: ScriptStatus,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    facts: Option<ScriptFacts>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScriptStatus {
    Ok,
    Error,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptFacts {
    #[serde(default)]
    application_installed: Option<bool>,
    #[serde(default)]
    application_running: Option<bool>,
    #[serde(default)]
    accessibility_authorized: Option<bool>,
    #[serde(default)]
    capability_probe_passed: Option<bool>,
    #[serde(default)]
    application_version: Option<String>,
    #[serde(default)]
    outcome: Option<ScriptOutcome>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScriptOutcome {
    Sent,
    Cancelled,
}

pub fn install_embedded_script(path: &Path) -> Result<(), AppError> {
    let parent = path.parent().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "resolve UI adapter directory",
            "UI adapter path has no parent directory.",
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "create UI adapter directory",
            "UI adapter directory cannot be created.",
            error,
        )
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "inspect UI adapter directory",
            "UI adapter directory cannot be inspected.",
            error,
        )
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(AppError::new(
            ErrorCode::PermissionDenied,
            "validate UI adapter directory",
            "UI adapter directory is not a safe directory.",
        ));
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).map_err(
        |error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "secure UI adapter directory",
                "UI adapter directory cannot be protected.",
                error,
            )
        },
    )?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "create temporary UI adapter",
            "UI adapter cannot be installed safely.",
            error,
        )
    })?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "secure temporary UI adapter",
                "UI adapter cannot be protected.",
                error,
            )
        })?;
    temporary.write_all(SCRIPT_SOURCE).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "write UI adapter",
            "UI adapter cannot be installed.",
            error,
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "sync UI adapter",
            "UI adapter cannot be synchronized.",
            error,
        )
    })?;
    temporary.persist(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "replace UI adapter",
            "UI adapter cannot be installed atomically.",
            error.error,
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "sync UI adapter directory",
                "UI adapter directory cannot be synchronized.",
                error,
            )
        })?;
    Ok(())
}

fn validate_installed_script(path: &Path) -> Result<(), AppError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::NotConfigured,
            "inspect installed UI adapter",
            "Installed UI adapter is unavailable; run configure or restart the server.",
            error,
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() as usize != SCRIPT_SOURCE.len()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AppError::new(
            ErrorCode::NotConfigured,
            "validate installed UI adapter",
            "Installed UI adapter is not a safe regular file.",
        ));
    }
    let contents = fs::read(path).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "read installed UI adapter",
            "Installed UI adapter cannot be verified.",
            error,
        )
    })?;
    if contents != SCRIPT_SOURCE {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify installed UI adapter",
            "Installed UI adapter was modified; restart the server to restore it.",
        ));
    }
    Ok(())
}

async fn run_process(script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut child = Command::new("/usr/bin/osascript")
        .arg(script)
        .env_clear()
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::UiUnavailable,
                "launch AppleScript interpreter",
                "AppleScript interpreter could not be launched.",
                error,
            )
        })?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "open AppleScript input pipe",
            "AppleScript input channel could not be opened.",
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "open AppleScript output pipe",
            "AppleScript output channel could not be opened.",
        )
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "open AppleScript diagnostic pipe",
            "AppleScript diagnostic channel could not be opened.",
        )
    })?;
    let write_request = async {
        stdin.write_all(request).await?;
        stdin.shutdown().await
    };
    let read_stdout = read_bounded(stdout, MAX_STDOUT_BYTES);
    let read_stderr = read_bounded(stderr, MAX_STDERR_BYTES);
    let wait = child.wait();
    let ((), stdout_bytes, stderr_bytes, status) =
        tokio::try_join!(write_request, read_stdout, read_stderr, wait).map_err(|error| {
            AppError::with_source(
                ErrorCode::UiUnavailable,
                "communicate with AppleScript interpreter",
                "AppleScript interpreter communication failed.",
                error,
            )
        })?;
    if !status.success() {
        return Err(AppError::new(
            ErrorCode::UiUnavailable,
            "run AppleScript interpreter",
            "Proton Mail UI adapter exited unexpectedly.",
        ));
    }
    if !stderr_bytes.is_empty() {
        tracing::warn!(
            operation = "applescript_stderr",
            byte_count = stderr_bytes.len(),
            "AppleScript produced redacted diagnostics"
        );
    }
    Ok(stdout_bytes)
}

async fn read_bounded(
    reader: impl AsyncRead + Unpin,
    maximum_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let limit = u64::try_from(maximum_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut limited = reader.take(limit);
    let mut output = Vec::with_capacity(maximum_bytes.min(8 * 1024));
    limited.read_to_end(&mut output).await?;
    if output.len() > maximum_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "subprocess output exceeded the configured limit",
        ));
    }
    Ok(output)
}

fn required_internal_id(draft: &StoredDraft) -> Result<&str, AppError> {
    draft
        .locator
        .proton_internal_id
        .as_deref()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 512
                && !value.contains('/')
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::UiUnavailable,
                "read Proton internal draft identifier",
                "Draft has no safe Proton UI identifier and cannot be opened automatically.",
            )
        })
}

fn addresses(values: &[crate::domain::value::EmailAddress]) -> Vec<&str> {
    values.iter().map(|value| value.as_str()).collect()
}

fn missing_health_fact() -> AppError {
    AppError::new(
        ErrorCode::UiUnavailable,
        "read AppleScript health facts",
        "Proton Mail UI health response omitted required facts.",
    )
}

fn script_error(code: Option<&str>) -> AppError {
    match code {
        Some("validation_failed") => AppError::new(
            ErrorCode::ValidationFailed,
            "validate AppleScript request",
            "Proton Mail UI request was rejected as invalid.",
        ),
        Some("permission_denied") => AppError::new(
            ErrorCode::PermissionDenied,
            "access Proton Mail UI",
            "Grant Accessibility and Automation access to the terminal or Codex host, then retry.",
        ),
        Some("ambiguous_ui") => AppError::new(
            ErrorCode::AmbiguousUi,
            "identify Proton Mail UI",
            "Proton Mail UI could not be identified unambiguously; close extra windows or dialogs.",
        ),
        Some("not_found") => AppError::new(
            ErrorCode::NotFound,
            "locate Proton Mail draft",
            "Draft did not appear in Proton Mail before the UI timeout.",
        ),
        Some("conflict") => AppError::new(
            ErrorCode::Conflict,
            "verify Proton Mail composer",
            "Visible Proton Mail composer no longer matches the prepared draft.",
        ),
        Some("cancelled") => AppError::new(
            ErrorCode::Cancelled,
            "confirm Proton Mail send",
            "Send was cancelled in the native confirmation dialog.",
        ),
        Some("send_unknown") => AppError::new(
            ErrorCode::SendUnknown,
            "verify Proton Mail send action",
            "Send outcome is uncertain. Check Sent before attempting another send.",
        ),
        _ => AppError::new(
            ErrorCode::UiUnavailable,
            "run Proton Mail UI adapter",
            "Proton Mail UI is unavailable or incompatible with the installed adapter.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc};

    use async_trait::async_trait;
    use chrono::{DateTime, TimeDelta, Utc};

    use crate::{
        application::ports::{UiAutomation, UiHealth},
        domain::{
            error::AppError,
            mail::{DraftContent, DraftMode, RecipientSet, SendOutcome, StoredDraft},
            value::{EmailAddress, MailboxName, PlainTextBody, Subject},
        },
    };

    use super::{
        AppleScriptUi, CONFIRM_SEND_SCRIPT_TIMEOUT, HEALTH_SCRIPT_TIMEOUT,
        OPEN_DRAFT_SCRIPT_TIMEOUT, SCRIPT_SOURCE, ScriptRunner, install_embedded_script,
        request_timeout,
    };

    struct HealthRunner;

    #[async_trait]
    impl ScriptRunner for HealthRunner {
        async fn run(&self, _script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError> {
            let request: serde_json::Value =
                serde_json::from_slice(request).expect("valid test request");
            assert_eq!(
                request.get("operation").and_then(|value| value.as_str()),
                Some("health")
            );
            Ok(br#"{"version":1,"status":"ok","facts":{"application_installed":true,"application_running":true,"accessibility_authorized":true,"capability_probe_passed":true,"application_version":"1.13.3"}}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn health_contract_decodes_only_structured_facts() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        let adapter = AppleScriptUi::new(script, Arc::new(HealthRunner)).expect("create adapter");
        assert_eq!(
            adapter.health().await.expect("read health"),
            UiHealth {
                application_installed: true,
                application_running: true,
                accessibility_authorized: true,
                capability_probe_passed: true,
                application_version: Some("1.13.3".to_owned()),
            }
        );
    }

    struct HealthProbeFailureRunner;

    #[async_trait]
    impl ScriptRunner for HealthProbeFailureRunner {
        async fn run(&self, _script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError> {
            let request: serde_json::Value =
                serde_json::from_slice(request).expect("valid test request");
            assert_eq!(
                request.get("operation").and_then(|value| value.as_str()),
                Some("health")
            );
            Ok(br#"{"version":1,"status":"ok","facts":{"application_installed":true,"application_running":true,"accessibility_authorized":true,"capability_probe_passed":false,"application_version":"1.13.3"}}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn health_keeps_accessibility_state_when_capability_probe_fails() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        let adapter =
            AppleScriptUi::new(script, Arc::new(HealthProbeFailureRunner)).expect("create adapter");

        let health = adapter.health().await.expect("read health");

        assert!(health.accessibility_authorized);
        assert!(!health.capability_probe_passed);
    }

    #[test]
    fn script_timeouts_are_operation_specific_and_bounded() {
        assert_eq!(
            request_timeout(br#"{"operation":"health"}"#),
            HEALTH_SCRIPT_TIMEOUT
        );
        assert_eq!(
            request_timeout(br#"{"operation":"open_draft"}"#),
            OPEN_DRAFT_SCRIPT_TIMEOUT
        );
        assert_eq!(
            request_timeout(br#"{"operation":"confirm_and_send"}"#),
            CONFIRM_SEND_SCRIPT_TIMEOUT
        );
    }

    struct SendRunner;

    #[async_trait]
    impl ScriptRunner for SendRunner {
        async fn run(&self, script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError> {
            assert_eq!(
                std::fs::read(script).expect("read installed script"),
                SCRIPT_SOURCE
            );
            let request: serde_json::Value =
                serde_json::from_slice(request).expect("valid test request");
            assert_eq!(
                request.get("operation").and_then(serde_json::Value::as_str),
                Some("confirm_and_send")
            );
            assert_eq!(
                request
                    .get("internal_id")
                    .and_then(serde_json::Value::as_str),
                Some("internal-id")
            );
            assert_eq!(
                request.get("subject").and_then(serde_json::Value::as_str),
                Some("Exact subject")
            );
            Ok(br#"{"version":1,"status":"ok","facts":{"outcome":"cancelled"}}"#.to_vec())
        }
    }

    struct OpenDraftRunner;

    #[async_trait]
    impl ScriptRunner for OpenDraftRunner {
        async fn run(&self, _script: &Path, request: &[u8]) -> Result<Vec<u8>, AppError> {
            let request: serde_json::Value =
                serde_json::from_slice(request).expect("valid test request");
            assert_eq!(
                request.get("operation").and_then(serde_json::Value::as_str),
                Some("open_draft")
            );
            assert_eq!(
                request
                    .get("row_subject")
                    .and_then(serde_json::Value::as_str),
                Some("")
            );
            Ok(br#"{"version":1,"status":"ok"}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn empty_subject_draft_discovery_does_not_assume_a_localized_label() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        let adapter =
            AppleScriptUi::new(script, Arc::new(OpenDraftRunner)).expect("create adapter");
        let mut draft = test_draft();
        draft.content.subject = Subject::parse("").expect("valid empty subject");

        adapter
            .open_draft(&draft)
            .await
            .expect("open empty subject draft");
    }

    #[tokio::test]
    async fn send_contract_uses_static_script_and_returns_native_cancellation() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        assert_eq!(
            std::fs::metadata(&script)
                .expect("read script metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let adapter = AppleScriptUi::new(script, Arc::new(SendRunner)).expect("create adapter");
        let draft = test_draft();
        let now = DateTime::parse_from_rfc3339("2026-08-01T12:00:00Z")
            .expect("valid fixed date")
            .with_timezone(&Utc);
        let outcome = adapter
            .confirm_and_send(&draft, now + TimeDelta::minutes(5))
            .await
            .expect("read cancellation");
        assert_eq!(outcome, SendOutcome::Cancelled);
    }

    struct CancellationErrorRunner;

    #[async_trait]
    impl ScriptRunner for CancellationErrorRunner {
        async fn run(&self, _script: &Path, _request: &[u8]) -> Result<Vec<u8>, AppError> {
            Ok(br#"{"version":1,"status":"error","code":"cancelled"}"#.to_vec())
        }
    }

    #[tokio::test]
    async fn native_dialog_cancel_error_is_a_cancelled_outcome() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        let adapter =
            AppleScriptUi::new(script, Arc::new(CancellationErrorRunner)).expect("create adapter");
        let now = DateTime::parse_from_rfc3339("2026-08-01T12:00:00Z")
            .expect("valid fixed date")
            .with_timezone(&Utc);
        assert_eq!(
            adapter
                .confirm_and_send(&test_draft(), now + TimeDelta::minutes(5))
                .await
                .expect("map native cancellation"),
            SendOutcome::Cancelled
        );
    }

    struct TransportFailureRunner;

    #[async_trait]
    impl ScriptRunner for TransportFailureRunner {
        async fn run(&self, _script: &Path, _request: &[u8]) -> Result<Vec<u8>, AppError> {
            Err(AppError::new(
                crate::domain::error::ErrorCode::UiUnavailable,
                "run fake AppleScript",
                "fake transport failure",
            ))
        }
    }

    #[tokio::test]
    async fn confirm_transport_failure_is_an_uncertain_send() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        let adapter =
            AppleScriptUi::new(script, Arc::new(TransportFailureRunner)).expect("create adapter");
        let now = DateTime::parse_from_rfc3339("2026-08-01T12:00:00Z")
            .expect("valid fixed date")
            .with_timezone(&Utc);
        let error = adapter
            .confirm_and_send(&test_draft(), now + TimeDelta::minutes(5))
            .await
            .expect_err("transport loss cannot prove whether the press occurred");
        assert_eq!(error.code(), crate::domain::error::ErrorCode::SendUnknown);
    }

    #[tokio::test]
    async fn modified_installed_script_is_rejected_before_each_request() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let script = directory.path().join("ui.applescript");
        install_embedded_script(&script).expect("install embedded script");
        let adapter = AppleScriptUi::new(script.clone(), Arc::new(HealthRunner))
            .expect("create adapter before modification");
        std::fs::write(&script, b"modified").expect("modify script");
        assert!(adapter.health().await.is_err());
        assert!(AppleScriptUi::new(script, Arc::new(HealthRunner)).is_err());
    }

    #[test]
    fn embedded_script_preserves_the_reviewed_safety_contract() {
        let source = std::str::from_utf8(SCRIPT_SOURCE).expect("AppleScript is UTF-8");

        assert!(source.contains("fileHandleWithStandardInput"));
        assert!(source.contains("URLForApplicationWithBundleIdentifier:bundleIdentifier"));
        assert!(source.contains("requireExactKeys"));
        assert!(source.contains("Remove "));
        assert!(source.contains("if visibleBody is not expectedNormalizedBody"));
        assert!(source.contains("precomposedStringWithCanonicalMapping"));
        assert!(source.contains("if errorNumber is not 1702 then"));
        assert!(
            source
                .contains("if errorNumber is not 1703 then error errorMessage number errorNumber")
        );
        assert!(source.contains("if my subjectMatches(subjectText, candidateSubject) then"));
        assert!(source.contains("on subjectMatches(subjectText, candidateSubject)"));
        assert!(source.contains("return subjectText begins with prefixText"));
        assert!(source.contains("if candidateSubject is \"\" then return false"));
        assert!(source.contains("set fallbackRows to {}"));
        assert!(source.contains(
            "if subjectText is \"\" and (count of candidates) is 0 then return fallbackRows"
        ));
        assert!(!source.contains("subjectText is \"\" or candidateSubject is subjectText"));
        assert!(!source.contains("(No Subject)"));
        assert!(source.contains("display dialog"));
        assert!(source.contains("default button \"Cancel\""));
        assert!(source.contains("my raiseAdapterError(1706)"));
        assert!(!source.contains("do shell script"));
        assert!(!source.contains("the clipboard"));
        assert!(!source.contains("keystroke"));
        assert!(!source.contains("key code"));
    }

    fn test_draft() -> StoredDraft {
        StoredDraft {
            locator: crate::domain::mail::MessageLocator {
                mailbox: MailboxName::parse("Drafts").expect("valid mailbox"),
                uid_validity: 1,
                uid: 7,
                fingerprint: [3; 32],
                proton_internal_id: Some("internal-id".to_owned()),
            },
            message_id: "draft@example.invalid".to_owned(),
            integrity_digest: [4; 32],
            content: DraftContent {
                mode: DraftMode::New,
                account: EmailAddress::parse("sender@example.com").expect("valid sender"),
                recipients: RecipientSet::new(
                    vec![EmailAddress::parse("recipient@example.com").expect("valid recipient")],
                    Vec::new(),
                    Vec::new(),
                )
                .expect("valid recipients"),
                subject: Subject::parse("Exact subject").expect("valid subject"),
                body: PlainTextBody::parse("Exact body").expect("valid body"),
                attachments: Vec::new(),
                in_reply_to: None,
            },
        }
    }
}
