use std::{collections::HashSet, path::PathBuf};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    error::AppError,
    value::{
        AttachmentRef, DraftRef, EmailAddress, MAX_RECIPIENTS, MailboxName, MessageRef,
        PlainTextBody, PreparedSendToken, SearchTerm, Subject,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct FolderSummary {
    pub name: String,
    pub selectable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct MessageSummary {
    pub message_ref: MessageRef,
    pub sender: String,
    pub subject: String,
    pub date: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct AttachmentSummary {
    pub attachment_ref: AttachmentRef,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct MessageContentPage {
    pub message_ref: MessageRef,
    pub sender: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub date: DateTime<Utc>,
    pub untrusted_plain_text: String,
    pub offset_chars: u32,
    pub next_offset_chars: Option<u32>,
    pub attachments: Vec<AttachmentSummary>,
    pub safety_notice: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageLocator {
    pub mailbox: MailboxName,
    pub uid_validity: u32,
    pub uid: u32,
    pub fingerprint: [u8; 32],
    pub proton_internal_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentLocator {
    pub message: MessageLocator,
    pub part_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessageSummary {
    pub locator: MessageLocator,
    pub sender: String,
    pub subject: String,
    pub date: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttachmentMetadata {
    pub part_index: u32,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttachment {
    pub metadata: StoredAttachmentMetadata,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub locator: MessageLocator,
    pub sender: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: String,
    pub date: DateTime<Utc>,
    pub plain_text: String,
    pub attachments: Vec<StoredAttachmentMetadata>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchCriteria {
    pub folder: Option<MailboxName>,
    pub text: Option<SearchTerm>,
    pub from: Option<EmailAddress>,
    pub to: Option<EmailAddress>,
    pub subject: Option<SearchTerm>,
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    pub unread: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailFlag {
    Read,
    Unread,
    Starred,
    Unstarred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ItemOutcome {
    pub message_ref: MessageRef,
    pub success: bool,
    pub error_code: Option<super::error::ErrorCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DraftMode {
    New,
    Reply,
    ReplyAll,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSet {
    to: Vec<EmailAddress>,
    cc: Vec<EmailAddress>,
    bcc: Vec<EmailAddress>,
}

impl RecipientSet {
    pub fn new(
        to: Vec<EmailAddress>,
        cc: Vec<EmailAddress>,
        bcc: Vec<EmailAddress>,
    ) -> Result<Self, AppError> {
        let count = to
            .len()
            .checked_add(cc.len())
            .and_then(|subtotal| subtotal.checked_add(bcc.len()))
            .ok_or_else(|| AppError::resource_limit("Recipient count exceeds the limit."))?;
        if count == 0 || count > MAX_RECIPIENTS {
            return Err(AppError::resource_limit(
                "A message requires 1 to 20 combined recipients.",
            ));
        }
        let mut unique = HashSet::with_capacity(count);
        for recipient in to.iter().chain(&cc).chain(&bcc) {
            if !unique.insert(recipient.as_str().to_lowercase()) {
                return Err(AppError::validation(
                    "Each recipient may appear only once across To, CC, and BCC.",
                ));
            }
        }
        Ok(Self { to, cc, bcc })
    }

    pub fn to(&self) -> &[EmailAddress] {
        &self.to
    }

    pub fn cc(&self) -> &[EmailAddress] {
        &self.cc
    }

    pub fn bcc(&self) -> &[EmailAddress] {
        &self.bcc
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingAttachment {
    pub canonical_path: PathBuf,
    pub display_name: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub digest: [u8; 32],
    pub warning: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftContent {
    pub mode: DraftMode,
    pub account: EmailAddress,
    pub recipients: RecipientSet,
    pub subject: Subject,
    pub body: PlainTextBody,
    pub attachments: Vec<OutgoingAttachment>,
    pub in_reply_to: Option<MessageLocator>,
}

impl DraftContent {
    pub fn confirmation_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"proton-mail-mac-mcp/send-preview/v1\0");
        update_field(&mut digest, self.account.as_str().as_bytes());
        for recipient in self.recipients.to() {
            digest.update(b"to\0");
            update_field(&mut digest, recipient.as_str().as_bytes());
        }
        for recipient in self.recipients.cc() {
            digest.update(b"cc\0");
            update_field(&mut digest, recipient.as_str().as_bytes());
        }
        for recipient in self.recipients.bcc() {
            digest.update(b"bcc\0");
            update_field(&mut digest, recipient.as_str().as_bytes());
        }
        update_field(&mut digest, self.subject.as_str().as_bytes());
        update_field(&mut digest, self.body.as_str().as_bytes());
        for attachment in &self.attachments {
            update_field(&mut digest, attachment.display_name.as_bytes());
            update_field(&mut digest, attachment.media_type.as_bytes());
            digest.update(attachment.size_bytes.to_be_bytes());
            digest.update(attachment.digest);
        }
        digest.finalize().into()
    }
}

fn update_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(value.len().to_be_bytes());
    digest.update(value);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDraft {
    pub locator: MessageLocator,
    pub message_id: String,
    pub integrity_digest: [u8; 32],
    pub content: DraftContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DraftPreview {
    pub draft_ref: DraftRef,
    pub prepared_send_token: PreparedSendToken,
    pub expires_at: DateTime<Utc>,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_preview: String,
    pub body_char_count: u32,
    pub body_preview_truncated: bool,
    pub attachment_names: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    Sent,
    Cancelled,
    Unknown,
}
