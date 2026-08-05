use std::path::PathBuf;

use chrono::{DateTime, Utc};
use mail_builder::{MessageBuilder, headers::raw::Raw};
use mail_parser::{Address, Message, MessageParser, MimeHeaders};
use sha2::{Digest, Sha256};

use crate::domain::{
    error::{AppError, ErrorCode},
    mail::{
        DraftContent, DraftMode, OutgoingAttachment, RecipientSet, StoredAttachment,
        StoredAttachmentMetadata, StoredDraft, StoredMessage,
    },
    value::{EmailAddress, MAX_RECIPIENTS, PlainTextBody, Subject},
};

use super::MessageLocator;

pub(super) const MAX_RAW_MESSAGE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_RAW_HEADER_BYTES: u64 = 256 * 1024;
const MAX_MIME_PARTS: usize = 256;
const MAX_ATTACHMENTS: usize = 50;
const MAX_DECODED_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;
const MAX_DECODED_TOTAL_BYTES: u64 = 60 * 1024 * 1024;
const MAX_READ_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_INCOMING_SUBJECT_BYTES: usize = 4 * 1024;
const MAX_HEADER_ID_BYTES: usize = 998;
const MAX_RETURNED_ADDRESSES_PER_FIELD: usize = 100;

pub(super) struct ParsedSummary {
    pub(super) sender: String,
    pub(super) subject: String,
    pub(super) date: DateTime<Utc>,
    pub(super) message_id: Option<String>,
    pub(super) fingerprint: [u8; 32],
    pub(super) proton_internal_id: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ThreadHeaders {
    in_reply_to: String,
    references: Vec<String>,
}

pub(super) fn parse_summary(
    raw_headers: &[u8],
    fallback_date: DateTime<Utc>,
) -> Result<ParsedSummary, AppError> {
    if raw_headers.len() as u64 > MAX_RAW_HEADER_BYTES {
        return Err(AppError::resource_limit(
            "Message headers exceed the supported size.",
        ));
    }
    let parsed = MessageParser::default().parse(raw_headers).ok_or_else(|| {
        AppError::new(
            ErrorCode::ValidationFailed,
            "parse message headers",
            "Message headers are malformed.",
        )
    })?;
    summary_from_parsed(&parsed, fallback_date)
}

pub(super) fn parse_stored_message(
    locator: MessageLocator,
    raw: &[u8],
    fallback_date: DateTime<Utc>,
) -> Result<StoredMessage, AppError> {
    validate_raw_size(raw)?;
    let parsed = parse(raw)?;
    validate_mime_shape(&parsed)?;
    let summary = summary_from_parsed(&parsed, fallback_date)?;
    validate_locator(&locator, &summary)?;
    let plain_text = extract_plain_text(&parsed)?;
    let attachments = attachment_metadata(&parsed)?;
    Ok(StoredMessage {
        locator,
        sender: summary.sender,
        to: address_strings(parsed.to())?,
        cc: address_strings(parsed.cc())?,
        subject: summary.subject,
        date: summary.date,
        plain_text,
        attachments,
    })
}

pub(super) fn parse_stored_attachment(
    locator: &MessageLocator,
    part_index: u32,
    raw: &[u8],
    fallback_date: DateTime<Utc>,
) -> Result<StoredAttachment, AppError> {
    validate_raw_size(raw)?;
    let parsed = parse(raw)?;
    validate_mime_shape(&parsed)?;
    let summary = summary_from_parsed(&parsed, fallback_date)?;
    validate_locator(locator, &summary)?;
    let part = parsed.attachment(part_index).ok_or_else(|| {
        AppError::new(
            ErrorCode::NotFound,
            "locate MIME attachment",
            "Attachment no longer exists in this message.",
        )
    })?;
    let size_bytes = part.len() as u64;
    if size_bytes > MAX_DECODED_ATTACHMENT_BYTES {
        return Err(AppError::resource_limit(
            "Attachment exceeds the supported download size.",
        ));
    }
    Ok(StoredAttachment {
        metadata: attachment_metadata_for_part(part, part_index)?,
        bytes: part.contents().to_vec(),
    })
}

pub(super) fn parse_stored_draft(
    locator: MessageLocator,
    raw: &[u8],
    fallback_date: DateTime<Utc>,
    account: &EmailAddress,
    template: Option<&DraftContent>,
) -> Result<StoredDraft, AppError> {
    validate_raw_size(raw)?;
    let parsed = parse(raw)?;
    validate_mime_shape(&parsed)?;
    let summary = summary_from_parsed(&parsed, fallback_date)?;
    validate_locator(&locator, &summary)?;
    let observed_account = parse_single_address(parsed.from(), "Draft From address is invalid.")?;
    if &observed_account != account {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "revalidate draft From address",
            "Draft From address changed after it was prepared.",
        ));
    }
    let to = parse_addresses(parsed.to())?;
    let cc = parse_addresses(parsed.cc())?;
    let bcc = parse_addresses(parsed.bcc())?;
    let recipients = RecipientSet::new(to, cc, bcc)?;
    let subject = Subject::parse(summary.subject)?;
    let body = PlainTextBody::parse(extract_plain_text(&parsed)?)?;
    let mut attachments = Vec::new();
    let mut total = 0_u64;
    for (position, part) in parsed.attachments().enumerate() {
        let part_index = u32::try_from(position)
            .map_err(|_| AppError::resource_limit("MIME attachment count is too large."))?;
        let metadata = attachment_metadata_for_part(part, part_index)?;
        total = total
            .checked_add(metadata.size_bytes)
            .ok_or_else(|| AppError::resource_limit("Decoded attachment total is too large."))?;
        if total > MAX_DECODED_TOTAL_BYTES {
            return Err(AppError::resource_limit(
                "Decoded attachments exceed the supported total size.",
            ));
        }
        attachments.push(OutgoingAttachment {
            canonical_path: PathBuf::new(),
            display_name: metadata.filename,
            media_type: metadata.media_type,
            size_bytes: metadata.size_bytes,
            digest: Sha256::digest(part.contents()).into(),
            warning: template
                .and_then(|value| value.attachments.get(position))
                .and_then(|attachment| attachment.warning),
        });
    }
    let mode = template.map_or(crate::domain::mail::DraftMode::New, |value| value.mode);
    let in_reply_to = template.and_then(|value| value.in_reply_to.clone());
    let message_id = parsed.message_id().ok_or_else(|| {
        AppError::new(
            ErrorCode::ValidationFailed,
            "read draft Message-ID",
            "Draft has no stable Message-ID and cannot be sent safely.",
        )
    })?;
    validate_header_identifier(message_id, "Draft Message-ID is invalid.")?;
    let content = DraftContent {
        mode,
        account: account.clone(),
        recipients,
        subject,
        body,
        attachments,
        in_reply_to,
    };
    if template
        .is_some_and(|expected| content.confirmation_digest() != expected.confirmation_digest())
    {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "verify synchronized draft content",
            "Synchronized draft content differs from the requested draft.",
        ));
    }
    let integrity_digest = draft_integrity_digest(&parsed, &content, message_id)?;
    Ok(StoredDraft {
        locator,
        message_id: message_id.to_owned(),
        integrity_digest,
        content,
    })
}

pub(super) async fn build_draft_message(
    content: &DraftContent,
    message_id: &str,
    thread: Option<&ThreadHeaders>,
) -> Result<Vec<u8>, AppError> {
    validate_header_identifier(message_id, "Generated Message-ID is invalid.")?;
    let mut builder = MessageBuilder::new()
        .from(content.account.as_str().to_owned())
        .to(address_values(content.recipients.to()))
        .subject(content.subject.as_str().to_owned())
        .message_id(message_id.to_owned())
        .header("X-Unsent", Raw::new("1"))
        .text_body(content.body.as_str().to_owned());
    if let Some(thread) = thread {
        builder = builder
            .in_reply_to(thread.in_reply_to.clone())
            .references(thread.references.clone());
    }
    if !content.recipients.cc().is_empty() {
        builder = builder.cc(address_values(content.recipients.cc()));
    }
    if !content.recipients.bcc().is_empty() {
        builder = builder.bcc(address_values(content.recipients.bcc()));
    }
    for attachment in &content.attachments {
        let bytes = read_validated_attachment(attachment).await?;
        builder = builder.attachment(
            attachment.media_type.clone(),
            attachment.display_name.clone(),
            bytes,
        );
    }
    let raw = builder.write_to_vec().map_err(|error| {
        AppError::with_source(
            ErrorCode::Internal,
            "build MIME draft",
            "Draft could not be encoded.",
            error,
        )
    })?;
    validate_raw_size(&raw)?;
    Ok(raw)
}

pub(super) fn extract_thread_headers(
    raw: &[u8],
    mode: DraftMode,
) -> Result<Option<ThreadHeaders>, AppError> {
    if !matches!(mode, DraftMode::Reply | DraftMode::ReplyAll) {
        return Ok(None);
    }
    validate_raw_size(raw)?;
    let parsed = parse(raw)?;
    let message_id = parsed.message_id().ok_or_else(|| {
        AppError::new(
            ErrorCode::ValidationFailed,
            "read source Message-ID",
            "Source message has no Message-ID and cannot be replied to safely.",
        )
    })?;
    validate_header_identifier(message_id, "Source Message-ID is invalid.")?;
    let mut references = parsed
        .references()
        .as_text_list()
        .unwrap_or_default()
        .iter()
        .take(51)
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    references.push(message_id.to_owned());
    if references.len() > 50
        || references
            .iter()
            .map(String::len)
            .try_fold(0_usize, usize::checked_add)
            .is_none_or(|total| total > 16 * 1024)
    {
        return Err(AppError::resource_limit(
            "Reply References header exceeds the supported size.",
        ));
    }
    for reference in &references {
        validate_header_identifier(reference, "Reply reference identifier is invalid.")?;
    }
    Ok(Some(ThreadHeaders {
        in_reply_to: message_id.to_owned(),
        references,
    }))
}

pub(super) fn extract_existing_thread_headers(
    raw: &[u8],
) -> Result<Option<ThreadHeaders>, AppError> {
    validate_raw_size(raw)?;
    let parsed = parse(raw)?;
    let Some(in_reply_to) = parsed.in_reply_to().as_text() else {
        return Ok(None);
    };
    validate_header_identifier(in_reply_to, "Draft In-Reply-To identifier is invalid.")?;
    let references = parsed
        .references()
        .as_text_list()
        .unwrap_or_default()
        .iter()
        .take(51)
        .map(|value| value.as_ref().to_owned())
        .collect::<Vec<_>>();
    if references.len() > 50 {
        return Err(AppError::resource_limit(
            "Draft References header exceeds the supported size.",
        ));
    }
    for reference in &references {
        validate_header_identifier(reference, "Draft reference identifier is invalid.")?;
    }
    Ok(Some(ThreadHeaders {
        in_reply_to: in_reply_to.to_owned(),
        references,
    }))
}

fn parse(raw: &[u8]) -> Result<Message<'_>, AppError> {
    MessageParser::default().parse(raw).ok_or_else(|| {
        AppError::new(
            ErrorCode::ValidationFailed,
            "parse MIME message",
            "Message MIME structure is malformed.",
        )
    })
}

fn validate_raw_size(raw: &[u8]) -> Result<(), AppError> {
    if raw.len() as u64 > MAX_RAW_MESSAGE_BYTES {
        return Err(AppError::resource_limit(
            "Message exceeds the supported raw size.",
        ));
    }
    Ok(())
}

fn validate_mime_shape(parsed: &Message<'_>) -> Result<(), AppError> {
    if parsed.parts.len() > MAX_MIME_PARTS || parsed.attachment_count() > MAX_ATTACHMENTS {
        return Err(AppError::resource_limit(
            "Message MIME structure exceeds the supported part count.",
        ));
    }
    if parsed.parts.iter().any(|part| part.is_encoding_problem) {
        return Err(AppError::new(
            ErrorCode::ValidationFailed,
            "decode MIME message",
            "Message contains an invalid transfer encoding.",
        ));
    }
    Ok(())
}

fn summary_from_parsed(
    parsed: &Message<'_>,
    fallback_date: DateTime<Utc>,
) -> Result<ParsedSummary, AppError> {
    let sender = parsed
        .from()
        .and_then(Address::first)
        .map(format_address)
        .unwrap_or_else(|| "Unknown sender".to_owned());
    let subject = sanitize_header_text(parsed.subject().unwrap_or("(no subject)"))?;
    if subject.len() > MAX_INCOMING_SUBJECT_BYTES {
        return Err(AppError::resource_limit("Message subject is too large."));
    }
    let date = parsed
        .date()
        .and_then(|date| DateTime::from_timestamp(date.to_timestamp(), 0))
        .unwrap_or(fallback_date);
    let message_id = parsed.message_id().filter(|value| !value.is_empty());
    if let Some(message_id) = message_id {
        validate_header_identifier(message_id, "Message-ID is invalid.")?;
    }
    let proton_internal_id = parsed
        .header_raw("X-Pm-Internal-Id")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_header_identifier(value, "Proton message identifier is invalid.")?;
            Ok::<String, AppError>(value.to_owned())
        })
        .transpose()?;
    let fingerprint = message_fingerprint(
        &sender,
        &subject,
        date,
        message_id.unwrap_or(""),
        proton_internal_id.as_deref(),
    );
    Ok(ParsedSummary {
        sender,
        subject,
        date,
        message_id: message_id.map(str::to_owned),
        fingerprint,
        proton_internal_id,
    })
}

fn validate_locator(locator: &MessageLocator, summary: &ParsedSummary) -> Result<(), AppError> {
    if locator.fingerprint != summary.fingerprint
        || (locator.proton_internal_id.is_some()
            && locator.proton_internal_id != summary.proton_internal_id)
    {
        return Err(AppError::new(
            ErrorCode::StaleRef,
            "revalidate message identity",
            "Message changed or the reference is stale.",
        ));
    }
    Ok(())
}

fn message_fingerprint(
    sender: &str,
    subject: &str,
    date: DateTime<Utc>,
    message_id: &str,
    proton_internal_id: Option<&str>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"proton-mail-mac-mcp/message-fingerprint/v1\0");
    for value in [
        sender,
        subject,
        message_id,
        proton_internal_id.unwrap_or(""),
    ] {
        digest.update(value.len().to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(date.timestamp_millis().to_be_bytes());
    digest.finalize().into()
}

fn extract_plain_text(parsed: &Message<'_>) -> Result<String, AppError> {
    let body = parsed.body_text(0).unwrap_or_default().into_owned();
    if body.len() > MAX_READ_BODY_BYTES {
        return Err(AppError::resource_limit(
            "Decoded message body exceeds the supported size.",
        ));
    }
    Ok(body.replace("\r\n", "\n").replace('\r', "\n"))
}

fn attachment_metadata(parsed: &Message<'_>) -> Result<Vec<StoredAttachmentMetadata>, AppError> {
    let mut attachments = Vec::with_capacity(parsed.attachment_count());
    let mut total = 0_u64;
    for (position, part) in parsed.attachments().enumerate() {
        let part_index = u32::try_from(position)
            .map_err(|_| AppError::resource_limit("MIME attachment count is too large."))?;
        let metadata = attachment_metadata_for_part(part, part_index)?;
        total = total
            .checked_add(metadata.size_bytes)
            .ok_or_else(|| AppError::resource_limit("Decoded attachment total is too large."))?;
        if total > MAX_DECODED_TOTAL_BYTES {
            return Err(AppError::resource_limit(
                "Decoded attachments exceed the supported total size.",
            ));
        }
        attachments.push(metadata);
    }
    Ok(attachments)
}

fn attachment_metadata_for_part(
    part: &mail_parser::MessagePart<'_>,
    part_index: u32,
) -> Result<StoredAttachmentMetadata, AppError> {
    let size_bytes = part.len() as u64;
    if size_bytes > MAX_DECODED_ATTACHMENT_BYTES {
        return Err(AppError::resource_limit(
            "Attachment exceeds the supported decoded size.",
        ));
    }
    let fallback = format!("attachment-{}", part_index.saturating_add(1));
    let filename = sanitize_filename(part.attachment_name().unwrap_or(&fallback));
    let media_type = part
        .content_type()
        .map(|content_type| {
            format!(
                "{}/{}",
                content_type.ctype(),
                content_type.subtype().unwrap_or("octet-stream")
            )
        })
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    Ok(StoredAttachmentMetadata {
        part_index,
        filename,
        media_type,
        size_bytes,
    })
}

fn parse_addresses(value: Option<&Address<'_>>) -> Result<Vec<EmailAddress>, AppError> {
    let mut parsed = Vec::new();
    for address in value.into_iter().flat_map(Address::iter) {
        if parsed.len() >= MAX_RECIPIENTS {
            return Err(AppError::resource_limit(
                "Draft recipient count exceeds the supported limit.",
            ));
        }
        let value = address
            .address()
            .ok_or_else(|| AppError::validation("Draft recipient has no address."))?;
        parsed.push(EmailAddress::parse(value.to_owned())?);
    }
    Ok(parsed)
}

fn parse_single_address(
    value: Option<&Address<'_>>,
    message: &'static str,
) -> Result<EmailAddress, AppError> {
    let mut addresses = value
        .into_iter()
        .flat_map(Address::iter)
        .filter_map(|address| address.address());
    let address = addresses
        .next()
        .ok_or_else(|| AppError::validation(message))?;
    if addresses.next().is_some() {
        return Err(AppError::validation(message));
    }
    EmailAddress::parse(address.to_owned()).map_err(|_| AppError::validation(message))
}

fn address_strings(value: Option<&Address<'_>>) -> Result<Vec<String>, AppError> {
    let mut addresses = Vec::new();
    for address in value.into_iter().flat_map(Address::iter) {
        if addresses.len() >= MAX_RETURNED_ADDRESSES_PER_FIELD {
            return Err(AppError::resource_limit(
                "Message address list exceeds the supported limit.",
            ));
        }
        if let Some(value) = address.address() {
            addresses.push(EmailAddress::parse(value.to_owned())?.to_string());
        }
    }
    Ok(addresses)
}

fn format_address(address: &mail_parser::Addr<'_>) -> String {
    match (address.name(), address.address()) {
        (Some(name), Some(value)) => {
            format!("{} <{}>", sanitize_inline(name), sanitize_inline(value))
        }
        (None, Some(value)) => sanitize_inline(value),
        (Some(name), None) => sanitize_inline(name),
        (None, None) => "Unknown sender".to_owned(),
    }
}

fn sanitize_inline(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(1_024)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn sanitize_header_text(value: &str) -> Result<String, AppError> {
    if value.contains('\0') {
        return Err(AppError::validation("Message header contains a null byte."));
    }
    Ok(sanitize_inline(value))
}

fn sanitize_filename(value: &str) -> String {
    let mut sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '/' | '\\') {
                '_'
            } else {
                character
            }
        })
        .take(255)
        .collect::<String>();
    if sanitized.trim_matches([' ', '.']).is_empty() {
        sanitized = "attachment.bin".to_owned();
    }
    sanitized
}

fn validate_header_identifier(value: &str, message: &'static str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > MAX_HEADER_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(AppError::validation(message));
    }
    Ok(())
}

fn draft_integrity_digest(
    parsed: &Message<'_>,
    content: &DraftContent,
    message_id: &str,
) -> Result<[u8; 32], AppError> {
    let mut digest = Sha256::new();
    digest.update(b"proton-mail-mac-mcp/stored-draft/v1\0");
    update_digest_field(&mut digest, &content.confirmation_digest());
    update_digest_field(&mut digest, message_id.as_bytes());

    let in_reply_to = parsed.in_reply_to().as_text().unwrap_or_default();
    if !in_reply_to.is_empty() {
        validate_header_identifier(in_reply_to, "Draft In-Reply-To identifier is invalid.")?;
    }
    update_digest_field(&mut digest, in_reply_to.as_bytes());

    let references = parsed.references().as_text_list().unwrap_or_default();
    if references.len() > 50 {
        return Err(AppError::resource_limit(
            "Draft References header exceeds the supported size.",
        ));
    }
    let mut total = 0_usize;
    for reference in references {
        let reference = reference.as_ref();
        validate_header_identifier(reference, "Draft reference identifier is invalid.")?;
        total = total
            .checked_add(reference.len())
            .ok_or_else(|| AppError::resource_limit("Draft References header is too large."))?;
        if total > 16 * 1024 {
            return Err(AppError::resource_limit(
                "Draft References header exceeds the supported size.",
            ));
        }
        update_digest_field(&mut digest, reference.as_bytes());
    }
    Ok(digest.finalize().into())
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(value.len().to_be_bytes());
    digest.update(value);
}

fn address_values(addresses: &[EmailAddress]) -> Vec<String> {
    addresses
        .iter()
        .map(|address| address.as_str().to_owned())
        .collect()
}

async fn read_validated_attachment(attachment: &OutgoingAttachment) -> Result<Vec<u8>, AppError> {
    let metadata = tokio::fs::symlink_metadata(&attachment.canonical_path)
        .await
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::NotFound,
                "reinspect draft attachment",
                "A draft attachment is unavailable.",
                error,
            )
        })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != attachment.size_bytes
    {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "revalidate draft attachment",
            "A draft attachment changed after validation.",
        ));
    }
    let bytes = tokio::fs::read(&attachment.canonical_path)
        .await
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::PermissionDenied,
                "read draft attachment",
                "A draft attachment cannot be read.",
                error,
            )
        })?;
    if bytes.len() as u64 != attachment.size_bytes
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != attachment.digest
    {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "revalidate draft attachment contents",
            "A draft attachment changed after validation.",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::domain::value::MailboxName;

    #[test]
    fn html_only_body_is_converted_to_inert_text() {
        let raw = concat!(
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: HTML message\r\n",
            "Date: Sat, 01 Aug 2026 12:00:00 +0000\r\n",
            "Message-ID: <html@example.com>\r\n",
            "X-Pm-Internal-Id: internal-html\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<html><body><p>Hello <strong>world</strong>.</p>",
            "<img src=\"https://tracker.example/pixel\"><script>ignore()</script></body></html>"
        )
        .as_bytes();
        let fallback = fixed_date();
        let summary = parse_summary(raw, fallback).expect("parse summary");
        assert_eq!(summary.message_id.as_deref(), Some("html@example.com"));
        assert_ne!(summary.message_id.as_deref(), Some("html@example.com.evil"));
        let message = parse_stored_message(locator_for(&summary), raw, fallback)
            .expect("parse bounded message");
        assert!(message.plain_text.contains("Hello world"));
        assert!(!message.plain_text.contains("<img"));
        assert!(!message.plain_text.contains("https://tracker.example"));
    }

    #[test]
    fn attachment_filename_cannot_escape_download_directory() {
        let raw = concat!(
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Attachment\r\n",
            "Date: Sat, 01 Aug 2026 12:00:00 +0000\r\n",
            "Message-ID: <attachment@example.com>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=boundary\r\n",
            "\r\n",
            "--boundary\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "Body\r\n",
            "--boundary\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=\"../../payload.bin\"\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "c2FmZQ==\r\n",
            "--boundary--\r\n"
        )
        .as_bytes();
        let fallback = fixed_date();
        let summary = parse_summary(raw, fallback).expect("parse summary");
        let message =
            parse_stored_message(locator_for(&summary), raw, fallback).expect("parse message");
        let filename = &message
            .attachments
            .first()
            .expect("one attachment")
            .filename;
        assert!(!filename.contains('/'));
        assert!(!filename.contains('\\'));
        assert_ne!(filename, "../../payload.bin");
    }

    #[test]
    fn malformed_transfer_encoding_is_rejected() {
        let raw = concat!(
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Invalid encoding\r\n",
            "Date: Sat, 01 Aug 2026 12:00:00 +0000\r\n",
            "Message-ID: <invalid@example.com>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Disposition: attachment; filename=payload.bin\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "!!!!not-base64!!!!\r\n"
        )
        .as_bytes();
        let fallback = fixed_date();
        let summary = parse_summary(raw, fallback).expect("parse summary");
        assert!(parse_stored_message(locator_for(&summary), raw, fallback).is_err());
    }

    #[tokio::test]
    async fn reply_thread_headers_are_exact_and_forward_does_not_thread() {
        let raw = concat!(
            "From: sender@example.com\r\n",
            "To: recipient@example.com\r\n",
            "Subject: Thread source\r\n",
            "Date: Sat, 01 Aug 2026 12:00:00 +0000\r\n",
            "Message-ID: <source@example.com>\r\n",
            "References: <root@example.com>\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n\r\n",
            "Source body\r\n"
        )
        .as_bytes();
        let thread = extract_thread_headers(raw, DraftMode::Reply)
            .expect("extract thread")
            .expect("reply has thread headers");
        assert!(
            extract_thread_headers(raw, DraftMode::Forward)
                .expect("inspect forward")
                .is_none()
        );
        let content = DraftContent {
            mode: DraftMode::Reply,
            account: EmailAddress::parse("sender@example.com").expect("valid sender"),
            recipients: RecipientSet::new(
                vec![EmailAddress::parse("recipient@example.com").expect("valid recipient")],
                Vec::new(),
                Vec::new(),
            )
            .expect("valid recipient set"),
            subject: Subject::parse("Re: Thread source").expect("valid subject"),
            body: PlainTextBody::parse("Reply body").expect("valid body"),
            attachments: Vec::new(),
            in_reply_to: None,
        };
        let encoded = build_draft_message(&content, "draft@example.invalid", Some(&thread))
            .await
            .expect("build reply MIME");
        let parsed = MessageParser::default()
            .parse(&encoded)
            .expect("parse built MIME");
        assert_eq!(parsed.in_reply_to().as_text(), Some("source@example.com"));
        let references = parsed.references().as_text_list().unwrap_or_default();
        assert_eq!(references.len(), 2);
        assert_eq!(
            references.first().map(AsRef::as_ref),
            Some("root@example.com")
        );
        assert_eq!(
            references.get(1).map(AsRef::as_ref),
            Some("source@example.com")
        );
    }

    #[tokio::test]
    async fn attachment_change_after_preview_is_rejected() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("attachment.txt");
        std::fs::write(&path, b"initial").expect("write initial attachment");
        let attachment = OutgoingAttachment {
            canonical_path: path.clone(),
            display_name: "attachment.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            size_bytes: 7,
            digest: Sha256::digest(b"initial").into(),
            warning: None,
        };
        std::fs::write(path, b"changed").expect("change attachment");
        let content = DraftContent {
            mode: DraftMode::New,
            account: EmailAddress::parse("sender@example.com").expect("valid sender"),
            recipients: RecipientSet::new(
                vec![EmailAddress::parse("recipient@example.com").expect("valid recipient")],
                Vec::new(),
                Vec::new(),
            )
            .expect("valid recipient set"),
            subject: Subject::parse("Attachment").expect("valid subject"),
            body: PlainTextBody::parse("Body").expect("valid body"),
            attachments: vec![attachment],
            in_reply_to: None,
        };
        assert!(
            build_draft_message(&content, "draft@example.invalid", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn draft_from_address_is_revalidated() {
        let content = DraftContent {
            mode: DraftMode::New,
            account: EmailAddress::parse("sender@example.com").expect("valid sender"),
            recipients: RecipientSet::new(
                vec![EmailAddress::parse("recipient@example.com").expect("valid recipient")],
                Vec::new(),
                Vec::new(),
            )
            .expect("valid recipient set"),
            subject: Subject::parse("From integrity").expect("valid subject"),
            body: PlainTextBody::parse("Body").expect("valid body"),
            attachments: Vec::new(),
            in_reply_to: None,
        };
        let raw = build_draft_message(&content, "from-integrity@example.invalid", None)
            .await
            .expect("build draft MIME");
        let fallback = fixed_date();
        let summary = parse_summary(&raw, fallback).expect("parse summary");
        let wrong_account = EmailAddress::parse("other@example.com").expect("valid account");

        assert!(
            parse_stored_draft(locator_for(&summary), &raw, fallback, &wrong_account, None)
                .is_err()
        );
    }

    #[tokio::test]
    async fn hidden_thread_headers_are_bound_to_the_stored_draft() {
        let content = DraftContent {
            mode: DraftMode::Reply,
            account: EmailAddress::parse("sender@example.com").expect("valid sender"),
            recipients: RecipientSet::new(
                vec![EmailAddress::parse("recipient@example.com").expect("valid recipient")],
                Vec::new(),
                Vec::new(),
            )
            .expect("valid recipient set"),
            subject: Subject::parse("Thread integrity").expect("valid subject"),
            body: PlainTextBody::parse("Body").expect("valid body"),
            attachments: Vec::new(),
            in_reply_to: None,
        };
        let first_thread = ThreadHeaders {
            in_reply_to: "first@example.invalid".to_owned(),
            references: vec!["root@example.invalid".to_owned()],
        };
        let second_thread = ThreadHeaders {
            in_reply_to: "other@example.invalid".to_owned(),
            references: vec!["root@example.invalid".to_owned()],
        };
        let first_raw = build_draft_message(
            &content,
            "thread-integrity@example.invalid",
            Some(&first_thread),
        )
        .await
        .expect("build first draft MIME");
        let second_raw = build_draft_message(
            &content,
            "thread-integrity@example.invalid",
            Some(&second_thread),
        )
        .await
        .expect("build second draft MIME");
        let fallback = fixed_date();
        let first_summary = parse_summary(&first_raw, fallback).expect("parse first summary");
        let second_summary = parse_summary(&second_raw, fallback).expect("parse second summary");
        assert_eq!(first_summary.fingerprint, second_summary.fingerprint);

        let first = parse_stored_draft(
            locator_for(&first_summary),
            &first_raw,
            fallback,
            &content.account,
            Some(&content),
        )
        .expect("parse first draft");
        let second = parse_stored_draft(
            locator_for(&second_summary),
            &second_raw,
            fallback,
            &content.account,
            Some(&content),
        )
        .expect("parse second draft");

        assert_eq!(
            first.content.confirmation_digest(),
            second.content.confirmation_digest()
        );
        assert_ne!(first.integrity_digest, second.integrity_digest);
    }

    #[tokio::test]
    async fn synchronized_draft_must_match_request_and_preserves_warnings() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("review.sh");
        std::fs::write(&path, b"echo review\n").expect("write attachment");
        let content = DraftContent {
            mode: DraftMode::New,
            account: EmailAddress::parse("sender@example.com").expect("valid sender"),
            recipients: RecipientSet::new(
                vec![EmailAddress::parse("recipient@example.com").expect("valid recipient")],
                Vec::new(),
                Vec::new(),
            )
            .expect("valid recipient set"),
            subject: Subject::parse("Round trip").expect("valid subject"),
            body: PlainTextBody::parse("Exact body").expect("valid body"),
            attachments: vec![OutgoingAttachment {
                canonical_path: path,
                display_name: "review.sh".to_owned(),
                media_type: "text/plain".to_owned(),
                size_bytes: 12,
                digest: Sha256::digest(b"echo review\n").into(),
                warning: Some("Review this script before sending."),
            }],
            in_reply_to: None,
        };
        let raw = build_draft_message(&content, "round-trip@example.invalid", None)
            .await
            .expect("build draft MIME");
        let fallback = fixed_date();
        let summary = parse_summary(&raw, fallback).expect("parse summary");
        let stored = parse_stored_draft(
            locator_for(&summary),
            &raw,
            fallback,
            &content.account,
            Some(&content),
        )
        .expect("verify synchronized draft");
        assert_eq!(
            stored
                .content
                .attachments
                .first()
                .and_then(|attachment| attachment.warning),
            Some("Review this script before sending.")
        );

        let mut changed_expectation = content;
        changed_expectation.body =
            PlainTextBody::parse("Different body").expect("valid changed body");
        assert!(
            parse_stored_draft(
                locator_for(&summary),
                &raw,
                fallback,
                &changed_expectation.account,
                Some(&changed_expectation),
            )
            .is_err()
        );
    }

    fn fixed_date() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0)
            .single()
            .expect("valid fixed date")
    }

    fn locator_for(summary: &ParsedSummary) -> MessageLocator {
        MessageLocator {
            mailbox: MailboxName::parse("INBOX").expect("valid mailbox"),
            uid_validity: 1,
            uid: 7,
            fingerprint: summary.fingerprint,
            proton_internal_id: summary.proton_internal_id.clone(),
        }
    }
}
