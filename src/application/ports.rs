use std::{path::Path, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::domain::{
    error::AppError,
    mail::{
        AttachmentLocator, DraftContent, FolderSummary, MailFlag, MessageLocator,
        OutgoingAttachment, SearchCriteria, StoredAttachment, StoredDraft, StoredMessage,
        StoredMessageSummary, SubmissionDraft,
    },
    value::{DraftRef, MailboxName, MessageRef},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryPage {
    pub messages: Vec<StoredMessageSummary>,
    pub next_before_uid: Option<u32>,
    pub uid_validity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeHealth {
    pub reachable: bool,
    pub authenticated: bool,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailMutation {
    SetFlag(MailFlag),
    Move(MailboxName),
    Archive,
    Trash,
}

#[async_trait]
pub trait MailRepository: Send + Sync {
    async fn health(&self) -> Result<BridgeHealth, AppError>;

    async fn list_folders(&self) -> Result<Vec<FolderSummary>, AppError>;

    async fn list_messages(
        &self,
        criteria: &SearchCriteria,
        page_size: u16,
        before_uid: Option<u32>,
    ) -> Result<RepositoryPage, AppError>;

    async fn get_message(&self, locator: &MessageLocator) -> Result<StoredMessage, AppError>;

    async fn get_attachment(
        &self,
        locator: &AttachmentLocator,
    ) -> Result<StoredAttachment, AppError>;

    async fn mutate(
        &self,
        locator: &MessageLocator,
        mutation: &MailMutation,
    ) -> Result<(), AppError>;

    async fn create_draft(&self, content: &DraftContent) -> Result<StoredDraft, AppError>;

    async fn replace_draft(
        &self,
        previous: &MessageLocator,
        content: &DraftContent,
    ) -> Result<StoredDraft, AppError>;

    async fn load_draft(&self, locator: &MessageLocator) -> Result<StoredDraft, AppError>;

    async fn load_submission(&self, locator: &MessageLocator) -> Result<SubmissionDraft, AppError>;

    async fn discard_draft(&self, locator: &MessageLocator) -> Result<(), AppError>;

    async fn sent_contains_message_id(
        &self,
        message_id: &str,
        sent_after: DateTime<Utc>,
    ) -> Result<bool, AppError>;
}

#[async_trait]
pub trait MailSender: Send + Sync {
    async fn health(&self) -> Result<BridgeHealth, AppError>;

    /// Submits the message at most once. An adapter must return `SendUnknown`
    /// whenever it cannot prove that Bridge rejected or accepted the message.
    async fn submit(&self, draft: &SubmissionDraft) -> Result<(), AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorClaims {
    pub mailbox: MailboxName,
    pub uid_validity: u32,
    pub before_uid: u32,
    pub query_digest: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait ReferenceCodec: Send + Sync {
    async fn encode_message(&self, locator: &MessageLocator) -> Result<MessageRef, AppError>;
    async fn decode_message(&self, value: &MessageRef) -> Result<MessageLocator, AppError>;
    async fn encode_attachment(
        &self,
        locator: &AttachmentLocator,
    ) -> Result<crate::domain::value::AttachmentRef, AppError>;
    async fn decode_attachment(
        &self,
        value: &crate::domain::value::AttachmentRef,
    ) -> Result<AttachmentLocator, AppError>;
    async fn encode_draft(&self, locator: &MessageLocator) -> Result<DraftRef, AppError>;
    async fn decode_draft(&self, value: &DraftRef) -> Result<MessageLocator, AppError>;
    async fn encode_cursor(&self, claims: &CursorClaims) -> Result<String, AppError>;
    async fn decode_cursor(&self, value: &str) -> Result<CursorClaims, AppError>;
}

#[async_trait]
pub trait AttachmentManager: Send + Sync {
    async fn validate_outgoing(
        &self,
        paths: &[String],
    ) -> Result<Vec<OutgoingAttachment>, AppError>;

    async fn save_incoming(
        &self,
        attachment: StoredAttachment,
    ) -> Result<std::path::PathBuf, AppError>;

    async fn cleanup_expired(&self, now: DateTime<Utc>) -> Result<u64, AppError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait SecureRandom: Send + Sync {
    fn fill(&self, destination: &mut [u8]) -> Result<(), AppError>;
}

#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, AppError>;
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), AppError>;
    async fn exists(&self, key: &str) -> Result<bool, AppError>;
}

#[async_trait]
pub trait ConfigStore: Send + Sync {
    type Config: Clone + Send + Sync + 'static;

    async fn load(&self) -> Result<Self::Config, AppError>;
    async fn save(&self, config: &Self::Config) -> Result<(), AppError>;
    fn path(&self) -> &Path;
}

pub const EXTERNAL_TIMEOUT: Duration = Duration::from_secs(20);
