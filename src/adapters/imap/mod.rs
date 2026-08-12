mod mime;
mod transport;

use std::{future::Future, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, TimeDelta, Utc};
use futures::{StreamExt, TryStreamExt};
use zeroize::Zeroizing;

use crate::{
    adapters::bridge::{decode_bridge_password, decode_certificate_sha256},
    application::ports::{
        BridgeHealth, EXTERNAL_TIMEOUT, MailMutation, MailRepository, RepositoryPage, SecureRandom,
    },
    domain::{
        error::{AppError, ErrorCode},
        mail::{
            AttachmentLocator, DraftContent, FolderSummary, MailFlag, MessageLocator,
            SearchCriteria, StoredAttachment, StoredDraft, StoredMessage, StoredMessageSummary,
            SubmissionDraft,
        },
        value::{EmailAddress, MailboxName},
    },
};

use self::{
    mime::{
        MAX_RAW_HEADER_BYTES, MAX_RAW_MESSAGE_BYTES, ParsedSummary, ThreadHeaders,
        build_draft_message, extract_existing_thread_headers, extract_thread_headers,
        parse_stored_attachment, parse_stored_draft, parse_stored_message, parse_summary,
    },
    transport::{BridgeConnector, ImapSession},
};
use super::config::{AppConfig, BridgeTlsMode, verify_certificate};

const MAX_UID_SCAN: u32 = 5_000;
const MAX_FOLDER_COUNT: usize = 512;
const MAX_CAPABILITY_COUNT: usize = 128;
const MAX_CAPABILITY_BYTES: usize = 128;
const MAX_DRAFT_CANDIDATES: usize = 20;
const MAX_DRAFT_SCAN: u32 = 500;
const MAX_SENT_CANDIDATES: usize = 20;
const DRAFT_SYNC_TIMEOUT: Duration = Duration::from_secs(15);
const DRAFT_SYNC_POLL: Duration = Duration::from_millis(500);
const DRAFT_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct BridgeEndpoint {
    port: u16,
    tls_mode: BridgeTlsMode,
    tls_server_name: String,
}

pub struct BridgeImapRepository {
    connector: BridgeConnector,
    folders: FolderMapping,
    account: EmailAddress,
    random: Arc<dyn SecureRandom>,
}

#[derive(Debug, Clone)]
struct FolderMapping {
    drafts: MailboxName,
    sent: MailboxName,
    trash: MailboxName,
    archive: MailboxName,
}

impl BridgeImapRepository {
    pub fn new(
        config: &AppConfig,
        certificate_path: &std::path::Path,
        password_bytes: Zeroizing<Vec<u8>>,
        random: Arc<dyn SecureRandom>,
    ) -> Result<Self, AppError> {
        config.validate()?;
        let certificate_der =
            verify_certificate(certificate_path, &config.bridge.certificate_sha256)?;
        let certificate_sha256 = decode_certificate_sha256(&config.bridge.certificate_sha256)?;
        let password = decode_bridge_password(password_bytes)?;
        Ok(Self {
            connector: BridgeConnector::new(
                BridgeEndpoint {
                    port: config.bridge.imap_port,
                    tls_mode: config.bridge.tls_mode,
                    tls_server_name: config.bridge.tls_server_name.clone(),
                },
                certificate_der,
                certificate_sha256,
                config.bridge.username.clone(),
                password,
            )?,
            folders: FolderMapping {
                drafts: MailboxName::parse(config.folders.drafts.clone())?,
                sent: MailboxName::parse(config.folders.sent.clone())?,
                trash: MailboxName::parse(config.folders.trash.clone())?,
                archive: MailboxName::parse(config.folders.archive.clone())?,
            },
            account: config.account()?,
            random,
        })
    }

    async fn timed<T>(
        &self,
        operation: &'static str,
        future: impl Future<Output = Result<T, AppError>>,
    ) -> Result<T, AppError> {
        tokio::time::timeout(EXTERNAL_TIMEOUT, future)
            .await
            .map_err(|_| {
                AppError::new(
                    ErrorCode::BridgeUnavailable,
                    operation,
                    "Proton Mail Bridge operation timed out.",
                )
            })?
    }

    async fn timed_draft<T>(
        &self,
        operation: &'static str,
        future: impl Future<Output = Result<T, AppError>>,
    ) -> Result<T, AppError> {
        tokio::time::timeout(DRAFT_OPERATION_TIMEOUT, future)
            .await
            .map_err(|_| {
                AppError::new(
                    ErrorCode::Conflict,
                    operation,
                    "Draft operation outcome is uncertain; inspect Drafts and Trash before retrying.",
                )
            })?
    }

    async fn list_messages_inner(
        &self,
        criteria: &SearchCriteria,
        page_size: u16,
        before_uid: Option<u32>,
    ) -> Result<RepositoryPage, AppError> {
        let mailbox = criteria
            .folder
            .as_ref()
            .ok_or_else(|| AppError::validation("Search folder is required."))?;
        let mut session = self.connector.connect().await?;
        let selected = session.examine(mailbox.as_str()).await.map_err(imap_error(
            "select message folder",
            "Message folder could not be selected.",
        ))?;
        let uid_validity = selected.uid_validity.ok_or_else(|| {
            AppError::new(
                ErrorCode::BridgeUnavailable,
                "read mailbox UIDVALIDITY",
                "Proton Mail Bridge did not provide stable mailbox identifiers.",
            )
        })?;
        let first_unassigned_uid = selected.uid_next.unwrap_or(1);
        let upper_exclusive = before_uid
            .unwrap_or(first_unassigned_uid)
            .min(first_unassigned_uid);
        let upper = upper_exclusive.saturating_sub(1);
        if upper == 0 {
            close_session(&mut session).await;
            return Ok(RepositoryPage {
                messages: Vec::new(),
                next_before_uid: None,
                uid_validity,
            });
        }
        let lower = upper.saturating_sub(MAX_UID_SCAN.saturating_sub(1)).max(1);
        let query = build_search_query(criteria, lower, upper)?;
        let found = session.uid_search(query).await.map_err(imap_error(
            "search messages",
            "Message search could not be completed.",
        ))?;
        let mut uids = found
            .into_iter()
            .filter(|uid| *uid >= lower && *uid <= upper)
            .collect::<Vec<_>>();
        uids.sort_unstable_by(|left, right| right.cmp(left));
        let requested = usize::from(page_size);
        let has_more_matches = uids.len() > requested;
        uids.truncate(requested);

        let messages = if uids.is_empty() {
            Vec::new()
        } else {
            fetch_summaries(&mut session, mailbox, uid_validity, &uids).await?
        };
        let next_before_uid = if has_more_matches {
            uids.last().copied()
        } else if lower > 1 {
            Some(lower)
        } else {
            None
        };
        close_session(&mut session).await;
        Ok(RepositoryPage {
            messages,
            next_before_uid,
            uid_validity,
        })
    }

    async fn fetch_message_inner(
        &self,
        locator: &MessageLocator,
    ) -> Result<StoredMessage, AppError> {
        let mut session = self.connector.connect().await?;
        let raw = fetch_validated_raw(&mut session, locator, true).await?;
        let result = parse_stored_message(locator.clone(), &raw.bytes, raw.date);
        close_session(&mut session).await;
        result
    }

    async fn fetch_attachment_inner(
        &self,
        locator: &AttachmentLocator,
    ) -> Result<StoredAttachment, AppError> {
        let mut session = self.connector.connect().await?;
        let raw = fetch_validated_raw(&mut session, &locator.message, true).await?;
        let result =
            parse_stored_attachment(&locator.message, locator.part_index, &raw.bytes, raw.date);
        close_session(&mut session).await;
        result
    }

    async fn mutate_inner(
        &self,
        locator: &MessageLocator,
        mutation: &MailMutation,
    ) -> Result<(), AppError> {
        let mut session = self.connector.connect().await?;
        select_and_validate(&mut session, locator, false).await?;
        let uid = locator.uid.to_string();
        let result = match mutation {
            MailMutation::SetFlag(flag) => mutate_flag(&mut session, &uid, *flag).await,
            MailMutation::Move(mailbox) => move_message(&mut session, locator, mailbox).await,
            MailMutation::Archive => {
                move_message(&mut session, locator, &self.folders.archive).await
            }
            MailMutation::Trash => move_message(&mut session, locator, &self.folders.trash).await,
        };
        close_session(&mut session).await;
        result
    }

    async fn create_new_draft_inner(
        &self,
        content: &DraftContent,
    ) -> Result<StoredDraft, AppError> {
        let thread = match content.in_reply_to.as_ref() {
            Some(original) => {
                let mut source_session = self.connector.connect().await?;
                let source = fetch_validated_raw(&mut source_session, original, true).await?;
                close_session(&mut source_session).await;
                extract_thread_headers(&source.bytes, content.mode)?
            }
            None => None,
        };
        self.append_draft_inner(content, thread).await
    }

    async fn append_draft_inner(
        &self,
        content: &DraftContent,
        thread: Option<ThreadHeaders>,
    ) -> Result<StoredDraft, AppError> {
        let message_id = self.generate_message_id()?;
        let raw = build_draft_message(content, &message_id, thread.as_ref()).await?;
        let mut session = self.connector.connect().await?;
        let append_result = session
            .append(self.folders.drafts.as_str(), Some("(\\Draft)"), None, &raw)
            .await
            .map_err(imap_error(
                "append draft",
                "Draft could not be stored in Proton Mail Bridge.",
            ));
        close_session(&mut session).await;
        if let Err(append_error) = append_result {
            return match self.find_draft_by_message_id(&message_id, content).await {
                Ok(recovered) => Ok(recovered),
                Err(_) => Err(AppError::with_source(
                    ErrorCode::Conflict,
                    "recover uncertain draft append",
                    "Draft append outcome is uncertain; inspect Drafts before retrying.",
                    append_error,
                )),
            };
        }
        self.find_draft_by_message_id(&message_id, content).await
    }

    async fn find_draft_by_message_id(
        &self,
        message_id: &str,
        template: &DraftContent,
    ) -> Result<StoredDraft, AppError> {
        let query = format!("HEADER \"Message-ID\" {}", quote_search(message_id)?);
        let started = tokio::time::Instant::now();
        loop {
            let mut session = self.connector.connect().await?;
            let candidates = find_draft_candidates(
                &mut session,
                &self.folders.drafts,
                &query,
                MAX_DRAFT_CANDIDATES,
            )
            .await?;
            if candidates.len() > 1 {
                close_session(&mut session).await;
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "locate appended draft",
                    "More than one draft has the generated identity.",
                ));
            }
            if let Some(locator) = candidates.first() {
                let raw = fetch_selected_raw(&mut session, locator).await?;
                let result = parse_stored_draft(
                    locator.clone(),
                    &raw.bytes,
                    raw.date,
                    &self.account,
                    Some(template),
                );
                close_session(&mut session).await;
                let stored = result?;
                if stored.message_id != message_id {
                    return Err(AppError::new(
                        ErrorCode::Conflict,
                        "verify appended draft identity",
                        "Draft search returned a non-exact Message-ID match.",
                    ));
                }
                return Ok(stored);
            }
            close_session(&mut session).await;
            if started.elapsed() >= DRAFT_SYNC_TIMEOUT {
                return Err(AppError::new(
                    ErrorCode::NotFound,
                    "locate appended draft",
                    "Draft was stored but did not become visible before the synchronization timeout.",
                ));
            }
            tokio::time::sleep(DRAFT_SYNC_POLL).await;
        }
    }

    fn generate_message_id(&self) -> Result<String, AppError> {
        let mut random = Zeroizing::new([0_u8; 24]);
        self.random.fill(random.as_mut())?;
        let encoded = URL_SAFE_NO_PAD.encode(random.as_ref());
        let domain = self
            .account
            .as_str()
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .filter(|domain| !domain.is_empty())
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::Internal,
                    "derive draft Message-ID domain",
                    "Draft identity could not be generated.",
                )
            })?;
        Ok(format!("{encoded}@{domain}"))
    }
}

#[async_trait]
impl MailRepository for BridgeImapRepository {
    async fn health(&self) -> Result<BridgeHealth, AppError> {
        self.timed("check Bridge health", async {
            let mut session = self.connector.connect().await?;
            let capabilities = session.capabilities().await.map_err(imap_error(
                "read Bridge capabilities",
                "Proton Mail Bridge capabilities could not be read.",
            ))?;
            if capabilities.len() > MAX_CAPABILITY_COUNT {
                return Err(AppError::resource_limit(
                    "Proton Mail Bridge returned too many capabilities.",
                ));
            }
            let mut names = Vec::with_capacity(capabilities.len());
            for capability in capabilities.iter() {
                let name = capability_name(capability);
                if name.len() > MAX_CAPABILITY_BYTES || name.chars().any(char::is_control) {
                    return Err(AppError::resource_limit(
                        "Proton Mail Bridge returned an invalid capability.",
                    ));
                }
                names.push(name);
            }
            names.sort();
            close_session(&mut session).await;
            Ok(BridgeHealth {
                reachable: true,
                authenticated: true,
                capabilities: names,
            })
        })
        .await
    }

    async fn list_folders(&self) -> Result<Vec<FolderSummary>, AppError> {
        self.timed("list Bridge folders", async {
            let mut session = self.connector.connect().await?;
            let stream = session.list(None, Some("*")).await.map_err(imap_error(
                "list mail folders",
                "Mail folders could not be listed.",
            ))?;
            let names = stream
                .take(MAX_FOLDER_COUNT.saturating_add(1))
                .try_collect::<Vec<_>>()
                .await
                .map_err(imap_error(
                    "read mail folders",
                    "Mail folder listing was malformed.",
                ))?;
            if names.len() > MAX_FOLDER_COUNT {
                return Err(AppError::resource_limit(
                    "Mail folder count exceeds the supported limit.",
                ));
            }
            let mut folders = Vec::with_capacity(names.len());
            for name in names {
                let mailbox = MailboxName::parse(name.name().to_owned())?;
                folders.push(FolderSummary {
                    name: mailbox.as_str().to_owned(),
                    selectable: !name.attributes().iter().any(|attribute| {
                        matches!(attribute, async_imap::types::NameAttribute::NoSelect)
                    }),
                });
            }
            folders.sort_by(|left, right| left.name.cmp(&right.name));
            close_session(&mut session).await;
            Ok(folders)
        })
        .await
    }

    async fn list_messages(
        &self,
        criteria: &SearchCriteria,
        page_size: u16,
        before_uid: Option<u32>,
    ) -> Result<RepositoryPage, AppError> {
        self.timed(
            "list Bridge messages",
            self.list_messages_inner(criteria, page_size, before_uid),
        )
        .await
    }

    async fn get_message(&self, locator: &MessageLocator) -> Result<StoredMessage, AppError> {
        self.timed("read Bridge message", self.fetch_message_inner(locator))
            .await
    }

    async fn get_attachment(
        &self,
        locator: &AttachmentLocator,
    ) -> Result<StoredAttachment, AppError> {
        self.timed(
            "read Bridge attachment",
            self.fetch_attachment_inner(locator),
        )
        .await
    }

    async fn mutate(
        &self,
        locator: &MessageLocator,
        mutation: &MailMutation,
    ) -> Result<(), AppError> {
        self.timed(
            "mutate Bridge message",
            self.mutate_inner(locator, mutation),
        )
        .await
    }

    async fn create_draft(&self, content: &DraftContent) -> Result<StoredDraft, AppError> {
        self.timed_draft("create Bridge draft", self.create_new_draft_inner(content))
            .await
    }

    async fn replace_draft(
        &self,
        previous: &MessageLocator,
        content: &DraftContent,
    ) -> Result<StoredDraft, AppError> {
        self.timed_draft("replace Bridge draft", async {
            if previous.mailbox != self.folders.drafts {
                return Err(AppError::new(
                    ErrorCode::PermissionDenied,
                    "authorize draft replacement",
                    "Only messages in the configured Drafts folder can be replaced.",
                ));
            }
            let mut previous_session = self.connector.connect().await?;
            let previous_raw = fetch_validated_raw(&mut previous_session, previous, true).await?;
            close_session(&mut previous_session).await;
            let thread = extract_existing_thread_headers(&previous_raw.bytes)?;
            let replacement = self.append_draft_inner(content, thread).await?;
            match self.mutate_inner(previous, &MailMutation::Trash).await {
                Ok(()) => Ok(replacement),
                Err(error) => {
                    if self
                        .mutate_inner(&replacement.locator, &MailMutation::Trash)
                        .await
                        .is_err()
                    {
                        tracing::warn!(
                            operation = "cleanup_replacement_draft",
                            error_code = "conflict",
                            "replacement rollback could not move the new draft to Trash"
                        );
                    }
                    Err(error)
                }
            }
        })
        .await
    }

    async fn load_draft(&self, locator: &MessageLocator) -> Result<StoredDraft, AppError> {
        self.timed("load Bridge draft", async {
            if locator.mailbox != self.folders.drafts {
                return Err(AppError::new(
                    ErrorCode::PermissionDenied,
                    "authorize draft mailbox",
                    "Draft reference does not identify the configured Drafts folder.",
                ));
            }
            let mut session = self.connector.connect().await?;
            let raw = fetch_validated_raw(&mut session, locator, true).await?;
            let result =
                parse_stored_draft(locator.clone(), &raw.bytes, raw.date, &self.account, None);
            close_session(&mut session).await;
            result
        })
        .await
    }

    async fn load_submission(&self, locator: &MessageLocator) -> Result<SubmissionDraft, AppError> {
        self.timed("load Bridge draft for submission", async {
            if locator.mailbox != self.folders.drafts {
                return Err(AppError::new(
                    ErrorCode::PermissionDenied,
                    "authorize draft submission mailbox",
                    "Draft reference does not identify the configured Drafts folder.",
                ));
            }
            let mut session = self.connector.connect().await?;
            let raw = fetch_validated_raw(&mut session, locator, true).await?;
            let parsed =
                parse_stored_draft(locator.clone(), &raw.bytes, raw.date, &self.account, None)?;
            close_session(&mut session).await;
            SubmissionDraft::new(parsed, raw.bytes)
        })
        .await
    }

    async fn draft_exists(&self, locator: &MessageLocator) -> Result<bool, AppError> {
        self.timed("verify Bridge draft presence", async {
            if locator.mailbox != self.folders.drafts {
                return Err(AppError::new(
                    ErrorCode::PermissionDenied,
                    "authorize draft presence check",
                    "Draft reference does not identify the configured Drafts folder.",
                ));
            }
            let mut session = self.connector.connect().await?;
            let selected = session
                .examine(locator.mailbox.as_str())
                .await
                .map_err(imap_error(
                    "select Drafts for presence check",
                    "Configured Drafts folder could not be selected.",
                ))?;
            if selected.uid_validity != Some(locator.uid_validity) {
                close_session(&mut session).await;
                return Err(AppError::new(
                    ErrorCode::StaleRef,
                    "validate draft mailbox UIDVALIDITY",
                    "Draft presence cannot be verified because the mailbox identity changed.",
                ));
            }
            let result = match validate_selected_message(&mut session, locator).await {
                Ok(()) => Ok(true),
                Err(error) if error.code() == ErrorCode::StaleRef => Ok(false),
                Err(error) => Err(error),
            };
            close_session(&mut session).await;
            result
        })
        .await
    }

    async fn discard_draft(&self, locator: &MessageLocator) -> Result<(), AppError> {
        self.timed("discard Bridge draft", async {
            if locator.mailbox != self.folders.drafts {
                return Err(AppError::new(
                    ErrorCode::PermissionDenied,
                    "authorize draft discard",
                    "Only messages in the configured Drafts folder can be discarded.",
                ));
            }
            self.mutate_inner(locator, &MailMutation::Trash).await
        })
        .await
    }

    async fn sent_contains_message_id(
        &self,
        message_id: &str,
        sent_after: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.timed("verify Bridge sent message", async {
            let mut session = self.connector.connect().await?;
            let selected =
                session
                    .examine(self.folders.sent.as_str())
                    .await
                    .map_err(imap_error(
                        "select Sent folder",
                        "Configured Sent folder could not be selected.",
                    ))?;
            let upper = selected.uid_next.unwrap_or(1).saturating_sub(1);
            if upper == 0 {
                close_session(&mut session).await;
                return Ok(false);
            }
            let lower = upper.saturating_sub(MAX_UID_SCAN.saturating_sub(1)).max(1);
            let since = sent_after
                .checked_sub_signed(TimeDelta::days(1))
                .ok_or_else(|| AppError::validation("Sent verification timestamp is invalid."))?;
            let query = format!(
                "UID {lower}:{upper} SINCE {} HEADER \"Message-ID\" {}",
                imap_date(since),
                quote_search(message_id)?
            );
            let found = session.uid_search(query).await.map_err(imap_error(
                "search Sent folder",
                "Sent message could not be verified.",
            ))?;
            if found.len() > MAX_SENT_CANDIDATES {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "bound Sent verification candidates",
                    "Sent message identity was not unique enough to verify safely.",
                ));
            }
            if found.is_empty() {
                close_session(&mut session).await;
                return Ok(false);
            }
            let mut uids = found.into_iter().collect::<Vec<_>>();
            uids.sort_unstable();
            let sequence = uid_sequence(&uids)?;
            let stream = session
                .uid_fetch(sequence, metadata_fetch_query())
                .await
                .map_err(imap_error(
                    "fetch Sent verification headers",
                    "Sent message identity could not be verified.",
                ))?;
            let fetches = stream
                .take(uids.len().saturating_add(1))
                .try_collect::<Vec<_>>()
                .await
                .map_err(imap_error(
                    "read Sent verification headers",
                    "Sent message identity response was malformed.",
                ))?;
            if fetches.len() > uids.len() {
                return Err(AppError::resource_limit(
                    "Sent verification response exceeds its candidate bound.",
                ));
            }
            let cutoff = sent_after
                .checked_sub_signed(TimeDelta::minutes(5))
                .ok_or_else(|| AppError::validation("Sent verification timestamp is invalid."))?;
            let mut exact_matches = 0_usize;
            for fetch in &fetches {
                let uid = fetch.uid.ok_or_else(missing_uid)?;
                if !uids.contains(&uid) {
                    return Err(AppError::new(
                        ErrorCode::BridgeUnavailable,
                        "validate Sent verification UID",
                        "Proton Mail Bridge returned an unexpected Sent candidate.",
                    ));
                }
                let header = fetch.header().ok_or_else(|| {
                    AppError::new(
                        ErrorCode::BridgeUnavailable,
                        "read Sent verification header",
                        "Proton Mail Bridge omitted a Sent candidate header.",
                    )
                })?;
                let observed_date = optional_fetch_date(fetch);
                let summary = parse_summary(header, observed_date.unwrap_or(sent_after))?;
                if is_exact_sent_candidate(
                    summary.message_id.as_deref(),
                    message_id,
                    observed_date.as_ref(),
                    &cutoff,
                ) {
                    exact_matches = exact_matches.saturating_add(1);
                }
            }
            close_session(&mut session).await;
            if exact_matches > 1 {
                return Err(AppError::new(
                    ErrorCode::Conflict,
                    "verify exact Sent identity",
                    "More than one exact Sent message identity was found.",
                ));
            }
            Ok(exact_matches == 1)
        })
        .await
    }
}

struct RawMessage {
    bytes: Vec<u8>,
    date: DateTime<Utc>,
}

async fn fetch_summaries(
    session: &mut ImapSession,
    mailbox: &MailboxName,
    uid_validity: u32,
    uids: &[u32],
) -> Result<Vec<StoredMessageSummary>, AppError> {
    let sequence = uid_sequence(uids)?;
    let stream = session
        .uid_fetch(sequence, metadata_fetch_query())
        .await
        .map_err(imap_error(
            "fetch message metadata",
            "Message metadata could not be fetched.",
        ))?;
    let fetches = stream
        .take(uids.len().saturating_add(1))
        .try_collect::<Vec<_>>()
        .await
        .map_err(imap_error(
            "read message metadata",
            "Message metadata response was malformed.",
        ))?;
    if fetches.len() > uids.len() {
        return Err(AppError::resource_limit(
            "Message metadata response exceeds the requested batch.",
        ));
    }
    let mut messages = Vec::with_capacity(fetches.len());
    for fetch in fetches {
        let uid = fetch.uid.ok_or_else(missing_uid)?;
        if !uids.contains(&uid) {
            return Err(AppError::new(
                ErrorCode::BridgeUnavailable,
                "validate message metadata UID",
                "Proton Mail Bridge returned unexpected message metadata.",
            ));
        }
        let header = fetch.header().ok_or_else(|| {
            AppError::new(
                ErrorCode::BridgeUnavailable,
                "read message header",
                "Proton Mail Bridge omitted requested message headers.",
            )
        })?;
        let fallback = fetch_date(&fetch)?;
        let summary = parse_summary(header, fallback)?;
        messages.push(stored_summary(mailbox, uid_validity, uid, summary));
    }
    messages.sort_by(|left, right| right.locator.uid.cmp(&left.locator.uid));
    Ok(messages)
}

async fn fetch_validated_raw(
    session: &mut ImapSession,
    locator: &MessageLocator,
    read_only: bool,
) -> Result<RawMessage, AppError> {
    select_and_validate(session, locator, read_only).await?;
    fetch_selected_raw(session, locator).await
}

async fn select_and_validate(
    session: &mut ImapSession,
    locator: &MessageLocator,
    read_only: bool,
) -> Result<(), AppError> {
    let selected = if read_only {
        session.examine(locator.mailbox.as_str()).await
    } else {
        session.select(locator.mailbox.as_str()).await
    }
    .map_err(imap_error(
        "select referenced mailbox",
        "Referenced mailbox could not be selected.",
    ))?;
    if selected.uid_validity != Some(locator.uid_validity) {
        return Err(AppError::new(
            ErrorCode::StaleRef,
            "validate mailbox UIDVALIDITY",
            "Message reference is stale because the mailbox identity changed.",
        ));
    }
    validate_selected_message(session, locator).await
}

async fn validate_selected_message(
    session: &mut ImapSession,
    locator: &MessageLocator,
) -> Result<(), AppError> {
    let sequence = locator.uid.to_string();
    let stream = session
        .uid_fetch(sequence, metadata_fetch_query())
        .await
        .map_err(imap_error(
            "revalidate message metadata",
            "Referenced message could not be revalidated.",
        ))?;
    let fetches = stream
        .take(2)
        .try_collect::<Vec<_>>()
        .await
        .map_err(imap_error(
            "read revalidated message metadata",
            "Referenced message metadata was malformed.",
        ))?;
    let fetch = single_fetch(&fetches)?;
    if fetch.uid != Some(locator.uid) {
        return Err(stale_message());
    }
    let size = fetch.size.ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read message size",
            "Proton Mail Bridge omitted the requested message size.",
        )
    })?;
    if u64::from(size) > MAX_RAW_MESSAGE_BYTES {
        return Err(AppError::resource_limit(
            "Message exceeds the supported raw size.",
        ));
    }
    let header = fetch.header().ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read revalidated message header",
            "Proton Mail Bridge omitted the requested message header.",
        )
    })?;
    let summary = parse_summary(header, fetch_date(fetch)?)?;
    if summary.fingerprint != locator.fingerprint
        || (locator.proton_internal_id.is_some()
            && summary.proton_internal_id != locator.proton_internal_id)
    {
        return Err(stale_message());
    }
    Ok(())
}

async fn fetch_selected_raw(
    session: &mut ImapSession,
    locator: &MessageLocator,
) -> Result<RawMessage, AppError> {
    let stream = session
        .uid_fetch(locator.uid.to_string(), full_message_fetch_query())
        .await
        .map_err(imap_error(
            "fetch full message",
            "Message content could not be fetched.",
        ))?;
    let fetches = stream
        .take(2)
        .try_collect::<Vec<_>>()
        .await
        .map_err(imap_error(
            "read full message",
            "Message content response was malformed.",
        ))?;
    let fetch = single_fetch(&fetches)?;
    if fetch.uid != Some(locator.uid) {
        return Err(stale_message());
    }
    let size = fetch.size.ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read full message size",
            "Proton Mail Bridge omitted the requested message size.",
        )
    })?;
    if u64::from(size) > MAX_RAW_MESSAGE_BYTES {
        return Err(AppError::resource_limit(
            "Message exceeds the supported raw size.",
        ));
    }
    let body = fetch.body().ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read full message body",
            "Proton Mail Bridge omitted the requested message body.",
        )
    })?;
    if body.len() as u64 > MAX_RAW_MESSAGE_BYTES {
        return Err(AppError::resource_limit(
            "Message exceeds the supported raw size.",
        ));
    }
    Ok(RawMessage {
        bytes: body.to_vec(),
        date: fetch_date(fetch)?,
    })
}

async fn find_draft_candidates(
    session: &mut ImapSession,
    drafts: &MailboxName,
    criteria: &str,
    limit: usize,
) -> Result<Vec<MessageLocator>, AppError> {
    let selected = session.examine(drafts.as_str()).await.map_err(imap_error(
        "select Drafts folder",
        "Configured Drafts folder could not be selected.",
    ))?;
    let uid_validity = selected.uid_validity.ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read Drafts UIDVALIDITY",
            "Proton Mail Bridge did not provide stable draft identifiers.",
        )
    })?;
    let upper = selected.uid_next.unwrap_or(1).saturating_sub(1);
    if upper == 0 {
        return Ok(Vec::new());
    }
    let lower = upper
        .saturating_sub(MAX_DRAFT_SCAN.saturating_sub(1))
        .max(1);
    let query = format!("UID {lower}:{upper} {criteria}");
    let found = session.uid_search(query).await.map_err(imap_error(
        "search Drafts folder",
        "Recent drafts could not be searched.",
    ))?;
    let mut uids = found.into_iter().collect::<Vec<_>>();
    uids.sort_unstable_by(|left, right| right.cmp(left));
    uids.truncate(limit);
    if uids.is_empty() {
        return Ok(Vec::new());
    }
    let summaries = fetch_summaries(session, drafts, uid_validity, &uids).await?;
    Ok(summaries
        .into_iter()
        .map(|summary| summary.locator)
        .collect())
}

async fn mutate_flag(session: &mut ImapSession, uid: &str, flag: MailFlag) -> Result<(), AppError> {
    let (command, expected, should_exist) = match flag {
        MailFlag::Read => (
            "+FLAGS.SILENT (\\Seen)",
            async_imap::types::Flag::Seen,
            true,
        ),
        MailFlag::Unread => (
            "-FLAGS.SILENT (\\Seen)",
            async_imap::types::Flag::Seen,
            false,
        ),
        MailFlag::Starred => (
            "+FLAGS.SILENT (\\Flagged)",
            async_imap::types::Flag::Flagged,
            true,
        ),
        MailFlag::Unstarred => (
            "-FLAGS.SILENT (\\Flagged)",
            async_imap::types::Flag::Flagged,
            false,
        ),
    };
    let stream = session.uid_store(uid, command).await.map_err(imap_error(
        "set message flag",
        "Message flag could not be changed.",
    ))?;
    let responses = stream
        .take(2)
        .try_collect::<Vec<_>>()
        .await
        .map_err(imap_error(
            "complete message flag update",
            "Message flag update response was malformed.",
        ))?;
    if responses.len() > 1 {
        return Err(AppError::new(
            ErrorCode::BridgeUnavailable,
            "validate message flag response count",
            "Proton Mail Bridge returned an ambiguous flag update response.",
        ));
    }
    drop(responses);
    let stream = session
        .uid_fetch(uid, "(UID FLAGS)")
        .await
        .map_err(imap_error(
            "verify message flag",
            "Message flag change could not be verified.",
        ))?;
    let fetches = stream
        .take(2)
        .try_collect::<Vec<_>>()
        .await
        .map_err(imap_error(
            "read verified message flag",
            "Message flag verification response was malformed.",
        ))?;
    let fetch = single_fetch(&fetches)?;
    let exists = fetch.flags().any(|actual| actual == expected);
    if exists != should_exist {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify message flag postcondition",
            "Proton Mail Bridge did not preserve the requested flag change.",
        ));
    }
    Ok(())
}

async fn move_message(
    session: &mut ImapSession,
    locator: &MessageLocator,
    target: &MailboxName,
) -> Result<(), AppError> {
    if locator
        .mailbox
        .as_str()
        .eq_ignore_ascii_case(target.as_str())
    {
        return Err(AppError::validation(
            "Move destination must differ from the source mailbox.",
        ));
    }
    let internal_id = locator.proton_internal_id.as_deref().ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "identify move destination message",
            "Message has no Proton internal identifier, so MOVE cannot be verified safely.",
        )
    })?;
    let uid = locator.uid.to_string();
    let capabilities = session.capabilities().await.map_err(imap_error(
        "read MOVE capability",
        "Proton Mail Bridge capabilities could not be read.",
    ))?;
    if !capabilities.has_str("MOVE") {
        return Err(AppError::new(
            ErrorCode::BridgeUnavailable,
            "require safe MOVE capability",
            "Proton Mail Bridge does not advertise atomic MOVE; no copy-and-delete fallback is permitted.",
        ));
    }
    session
        .uid_mv(&uid, target.as_str())
        .await
        .map_err(imap_error(
            "move message",
            "Message could not be moved to the requested folder.",
        ))?;
    let remaining = session
        .uid_search(format!("UID {uid}"))
        .await
        .map_err(imap_error(
            "verify message move",
            "Message move could not be verified.",
        ))?;
    if !remaining.is_empty() {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify message move postcondition",
            "Message remained in the source folder after MOVE.",
        ));
    }
    let selected = session.examine(target.as_str()).await.map_err(imap_error(
        "select move destination",
        "Move destination could not be selected for verification.",
    ))?;
    let upper = selected.uid_next.unwrap_or(1).saturating_sub(1);
    if upper == 0 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify move destination postcondition",
            "Moved message was not found in the destination folder.",
        ));
    }
    let lower = upper.saturating_sub(MAX_UID_SCAN.saturating_sub(1)).max(1);
    let destination_matches = session
        .uid_search(format!(
            "UID {lower}:{upper} HEADER \"X-Pm-Internal-Id\" {}",
            quote_search(internal_id)?
        ))
        .await
        .map_err(imap_error(
            "verify move destination",
            "Moved message could not be verified in the destination folder.",
        ))?;
    if destination_matches.len() != 1 {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify move destination postcondition",
            "Moved message was not identified unambiguously in the destination folder.",
        ));
    }
    let destination_uid = destination_matches.iter().next().copied().ok_or_else(|| {
        AppError::new(
            ErrorCode::Conflict,
            "read move destination UID",
            "Moved message destination identity was unavailable.",
        )
    })?;
    let stream = session
        .uid_fetch(destination_uid.to_string(), metadata_fetch_query())
        .await
        .map_err(imap_error(
            "fetch move destination identity",
            "Moved message destination identity could not be fetched.",
        ))?;
    let fetches = stream
        .take(2)
        .try_collect::<Vec<_>>()
        .await
        .map_err(imap_error(
            "read move destination identity",
            "Moved message destination identity response was malformed.",
        ))?;
    let fetch = single_fetch(&fetches)?;
    if fetch.uid != Some(destination_uid) {
        return Err(stale_message());
    }
    let header = fetch.header().ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read move destination header",
            "Proton Mail Bridge omitted the moved message header.",
        )
    })?;
    let summary = parse_summary(header, fetch_date(fetch)?)?;
    if summary.proton_internal_id.as_deref() != Some(internal_id)
        || summary.fingerprint != locator.fingerprint
    {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify exact move destination identity",
            "Moved message destination did not preserve the exact message identity.",
        ));
    }
    Ok(())
}

fn metadata_fetch_query() -> String {
    format!(
        "(UID RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER]<0.{}>)",
        MAX_RAW_HEADER_BYTES.saturating_add(1)
    )
}

fn full_message_fetch_query() -> String {
    format!(
        "(UID RFC822.SIZE INTERNALDATE BODY.PEEK[]<0.{}>)",
        MAX_RAW_MESSAGE_BYTES.saturating_add(1)
    )
}

fn stored_summary(
    mailbox: &MailboxName,
    uid_validity: u32,
    uid: u32,
    summary: ParsedSummary,
) -> StoredMessageSummary {
    StoredMessageSummary {
        locator: MessageLocator {
            mailbox: mailbox.clone(),
            uid_validity,
            uid,
            fingerprint: summary.fingerprint,
            proton_internal_id: summary.proton_internal_id,
        },
        sender: summary.sender,
        subject: summary.subject,
        date: summary.date,
    }
}

fn build_search_query(
    criteria: &SearchCriteria,
    lower_uid: u32,
    upper_uid: u32,
) -> Result<String, AppError> {
    let mut terms = vec![format!("UID {lower_uid}:{upper_uid}")];
    if let Some(text) = &criteria.text {
        terms.push(format!("TEXT {}", quote_search(text.as_str())?));
    }
    if let Some(from) = &criteria.from {
        terms.push(format!("FROM {}", quote_search(from.as_str())?));
    }
    if let Some(to) = &criteria.to {
        terms.push(format!("TO {}", quote_search(to.as_str())?));
    }
    if let Some(subject) = &criteria.subject {
        terms.push(format!("SUBJECT {}", quote_search(subject.as_str())?));
    }
    if let Some(date) = criteria.date_from {
        terms.push(format!("SINCE {}", imap_date(date)));
    }
    if let Some(date) = criteria.date_to {
        terms.push(format!("BEFORE {}", imap_date(date)));
    }
    if let Some(unread) = criteria.unread {
        terms.push(if unread { "UNSEEN" } else { "SEEN" }.to_owned());
    }
    Ok(terms.join(" "))
}

fn quote_search(value: &str) -> Result<String, AppError> {
    if value.len() > 2_048
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        return Err(AppError::validation(
            "Search value is invalid or exceeds the supported size.",
        ));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn imap_date(value: DateTime<Utc>) -> String {
    value.format("%d-%b-%Y").to_string()
}

fn uid_sequence(uids: &[u32]) -> Result<String, AppError> {
    if uids.is_empty() || uids.len() > 100 {
        return Err(AppError::resource_limit(
            "Message metadata batch size is unsupported.",
        ));
    }
    Ok(uids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(","))
}

fn single_fetch(
    fetches: &[async_imap::types::Fetch],
) -> Result<&async_imap::types::Fetch, AppError> {
    if fetches.len() != 1 {
        return Err(stale_message());
    }
    fetches.first().ok_or_else(stale_message)
}

fn fetch_date(fetch: &async_imap::types::Fetch) -> Result<DateTime<Utc>, AppError> {
    optional_fetch_date(fetch).ok_or_else(|| {
        AppError::new(
            ErrorCode::BridgeUnavailable,
            "read message internal date",
            "Proton Mail Bridge omitted a requested message date.",
        )
    })
}

fn optional_fetch_date(fetch: &async_imap::types::Fetch) -> Option<DateTime<Utc>> {
    fetch.internal_date().map(|date| date.with_timezone(&Utc))
}

fn is_exact_sent_candidate(
    observed_message_id: Option<&str>,
    expected_message_id: &str,
    observed_internal_date: Option<&DateTime<Utc>>,
    cutoff: &DateTime<Utc>,
) -> bool {
    // Without INTERNALDATE there is no proof that a duplicate Message-ID is the
    // message created by the just-completed send, so verification must fail closed.
    observed_message_id == Some(expected_message_id)
        && observed_internal_date.is_some_and(|date| date >= cutoff)
}

fn capability_name(capability: &async_imap::types::Capability) -> String {
    match capability {
        async_imap::types::Capability::Imap4rev1 => "IMAP4rev1".to_owned(),
        async_imap::types::Capability::Auth(value) => format!("AUTH={value}"),
        async_imap::types::Capability::Atom(value) => value.clone(),
    }
}

fn imap_error(
    operation: &'static str,
    public_message: &'static str,
) -> impl FnOnce(async_imap::error::Error) -> AppError {
    move |error| {
        AppError::with_source(
            ErrorCode::BridgeUnavailable,
            operation,
            public_message,
            error,
        )
    }
}

fn missing_uid() -> AppError {
    AppError::new(
        ErrorCode::BridgeUnavailable,
        "read message UID",
        "Proton Mail Bridge omitted a requested stable message identifier.",
    )
}

fn stale_message() -> AppError {
    AppError::new(
        ErrorCode::StaleRef,
        "locate referenced message",
        "Message no longer exists or its reference is stale.",
    )
}

async fn close_session(session: &mut ImapSession) {
    if session.logout().await.is_err() {
        tracing::warn!(
            operation = "bridge_logout",
            error_code = "bridge_unavailable",
            "Bridge logout did not complete"
        );
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use crate::{
        adapters::bridge::decode_certificate_sha256,
        domain::{mail::SearchCriteria, value::EmailAddress},
    };

    use super::{build_search_query, is_exact_sent_candidate, quote_search};

    #[test]
    fn search_values_are_quoted_without_command_injection() {
        assert_eq!(
            quote_search("hello \\\"world").expect("quote search"),
            "\"hello \\\\\\\"world\""
        );
        assert!(quote_search("hello\r\nUID 1:*").is_err());
    }

    #[test]
    fn structured_search_builds_a_bounded_uid_query() {
        let criteria = SearchCriteria {
            from: Some(EmailAddress::parse("sender@example.com").expect("valid address")),
            unread: Some(true),
            date_from: Some(
                Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
                    .single()
                    .expect("valid date"),
            ),
            ..SearchCriteria::default()
        };
        let query = build_search_query(&criteria, 5, 25).expect("build search");
        assert_eq!(
            query,
            "UID 5:25 FROM \"sender@example.com\" SINCE 01-Aug-2026 UNSEEN"
        );
    }

    #[test]
    fn certificate_digest_parser_rejects_malformed_input() {
        assert_eq!(
            decode_certificate_sha256(&"ab".repeat(32)).expect("valid digest"),
            [0xab; 32]
        );
        assert!(decode_certificate_sha256(&"gg".repeat(32)).is_err());
    }

    #[test]
    fn exact_sent_identity_requires_a_recent_internal_date() {
        let cutoff = Utc
            .with_ymd_and_hms(2026, 8, 1, 12, 0, 0)
            .single()
            .expect("valid cutoff");
        let older = Utc
            .with_ymd_and_hms(2026, 8, 1, 11, 59, 59)
            .single()
            .expect("valid older date");

        assert!(!is_exact_sent_candidate(
            Some("draft@example.com"),
            "draft@example.com",
            None,
            &cutoff,
        ));
        assert!(is_exact_sent_candidate(
            Some("draft@example.com"),
            "draft@example.com",
            Some(&cutoff),
            &cutoff,
        ));
        assert!(!is_exact_sent_candidate(
            Some("other@example.com"),
            "draft@example.com",
            None,
            &cutoff,
        ));
        assert!(!is_exact_sent_candidate(
            Some("draft@example.com"),
            "draft@example.com",
            Some(&older),
            &cutoff,
        ));
    }
}
