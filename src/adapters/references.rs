use std::sync::Arc;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    application::ports::{CursorClaims, ReferenceCodec, SecureRandom},
    domain::{
        error::{AppError, ErrorCode},
        mail::{AttachmentLocator, MessageLocator},
        value::{AttachmentRef, DraftRef, MailboxName, MessageRef},
    },
};

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const MAX_ENCODED_BYTES: usize = 2_048;
const AAD: &[u8] = b"proton-mail-mac-mcp/opaque-reference/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReferenceKind {
    Message,
    Attachment,
    Draft,
    Cursor,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    version: u8,
    kind: ReferenceKind,
    profile_hash: [u8; 32],
    payload: T,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageClaims {
    mailbox: MailboxName,
    uid_validity: u32,
    uid: u32,
    fingerprint: [u8; 32],
    proton_internal_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentClaims {
    message: MessageClaims,
    part_index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    mailbox: MailboxName,
    uid_validity: u32,
    before_uid: u32,
    query_digest: [u8; 32],
    expires_at_millis: i64,
}

pub struct EncryptedReferenceCodec {
    key: Zeroizing<[u8; KEY_BYTES]>,
    profile_hash: [u8; 32],
    random: Arc<dyn SecureRandom>,
}

impl EncryptedReferenceCodec {
    pub fn new(
        key_material: Zeroizing<Vec<u8>>,
        profile: &str,
        random: Arc<dyn SecureRandom>,
    ) -> Result<Self, AppError> {
        if key_material.len() != KEY_BYTES {
            return Err(AppError::new(
                ErrorCode::NotConfigured,
                "load opaque-reference key",
                "Opaque-reference key is unavailable or malformed; run configure.",
            ));
        }
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        key.copy_from_slice(&key_material);
        let profile_hash = Sha256::digest(profile.as_bytes()).into();
        Ok(Self {
            key,
            profile_hash,
            random,
        })
    }

    fn encode<T: Serialize>(&self, kind: ReferenceKind, payload: T) -> Result<String, AppError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&Envelope {
                version: FORMAT_VERSION,
                kind,
                profile_hash: self.profile_hash,
                payload,
            })
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "encode opaque reference",
                    "Opaque reference could not be created.",
                    error,
                )
            })?,
        );
        let mut nonce = [0_u8; NONCE_BYTES];
        self.random.fill(&mut nonce)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|error| {
            AppError::with_source(
                ErrorCode::Internal,
                "initialize opaque-reference cipher",
                "Opaque reference could not be created.",
                error,
            )
        })?;
        let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| {
            AppError::new(
                ErrorCode::Internal,
                "construct opaque-reference nonce",
                "Opaque reference could not be created.",
            )
        })?;
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &plaintext,
                    aad: AAD,
                },
            )
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "encrypt opaque reference",
                    "Opaque reference could not be created.",
                    error,
                )
            })?;
        let total_length = nonce
            .len()
            .checked_add(ciphertext.len())
            .ok_or_else(|| AppError::resource_limit("Opaque reference is too large."))?;
        let mut encoded = Vec::with_capacity(total_length);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        let encoded = URL_SAFE_NO_PAD.encode(encoded);
        if encoded.len() > MAX_ENCODED_BYTES {
            return Err(AppError::resource_limit("Opaque reference is too large."));
        }
        Ok(encoded)
    }

    fn decode<T: DeserializeOwned>(
        &self,
        encoded: &str,
        expected_kind: ReferenceKind,
    ) -> Result<T, AppError> {
        if encoded.len() > MAX_ENCODED_BYTES || encoded.len() < 48 {
            return Err(stale_reference());
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| stale_reference())?;
        let (nonce, ciphertext) = decoded
            .split_at_checked(NONCE_BYTES)
            .ok_or_else(stale_reference)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(self.key.as_ref()).map_err(|_| stale_reference())?;
        let nonce_value = XNonce::try_from(nonce).map_err(|_| stale_reference())?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce_value,
                    Payload {
                        msg: ciphertext,
                        aad: AAD,
                    },
                )
                .map_err(|_| stale_reference())?,
        );
        let envelope: Envelope<T> =
            serde_json::from_slice(&plaintext).map_err(|_| stale_reference())?;
        if envelope.version != FORMAT_VERSION
            || envelope.kind != expected_kind
            || envelope.profile_hash != self.profile_hash
        {
            return Err(stale_reference());
        }
        Ok(envelope.payload)
    }
}

#[async_trait]
impl ReferenceCodec for EncryptedReferenceCodec {
    async fn encode_message(&self, locator: &MessageLocator) -> Result<MessageRef, AppError> {
        self.encode(ReferenceKind::Message, MessageClaims::from(locator))
            .map(MessageRef::from_encoded)
    }

    async fn decode_message(&self, value: &MessageRef) -> Result<MessageLocator, AppError> {
        self.decode::<MessageClaims>(value.as_str(), ReferenceKind::Message)
            .map(MessageLocator::from)
    }

    async fn encode_attachment(
        &self,
        locator: &AttachmentLocator,
    ) -> Result<AttachmentRef, AppError> {
        self.encode(
            ReferenceKind::Attachment,
            AttachmentClaims {
                message: MessageClaims::from(&locator.message),
                part_index: locator.part_index,
            },
        )
        .map(AttachmentRef::from_encoded)
    }

    async fn decode_attachment(
        &self,
        value: &AttachmentRef,
    ) -> Result<AttachmentLocator, AppError> {
        let claims = self.decode::<AttachmentClaims>(value.as_str(), ReferenceKind::Attachment)?;
        Ok(AttachmentLocator {
            message: MessageLocator::from(claims.message),
            part_index: claims.part_index,
        })
    }

    async fn encode_draft(&self, locator: &MessageLocator) -> Result<DraftRef, AppError> {
        self.encode(ReferenceKind::Draft, MessageClaims::from(locator))
            .map(DraftRef::from_encoded)
    }

    async fn decode_draft(&self, value: &DraftRef) -> Result<MessageLocator, AppError> {
        self.decode::<MessageClaims>(value.as_str(), ReferenceKind::Draft)
            .map(MessageLocator::from)
    }

    async fn encode_cursor(&self, claims: &CursorClaims) -> Result<String, AppError> {
        self.encode(
            ReferenceKind::Cursor,
            CursorPayload {
                mailbox: claims.mailbox.clone(),
                uid_validity: claims.uid_validity,
                before_uid: claims.before_uid,
                query_digest: claims.query_digest,
                expires_at_millis: claims.expires_at.timestamp_millis(),
            },
        )
    }

    async fn decode_cursor(&self, value: &str) -> Result<CursorClaims, AppError> {
        let claims = self.decode::<CursorPayload>(value, ReferenceKind::Cursor)?;
        let expires_at = chrono::DateTime::from_timestamp_millis(claims.expires_at_millis)
            .ok_or_else(stale_reference)?;
        Ok(CursorClaims {
            mailbox: claims.mailbox,
            uid_validity: claims.uid_validity,
            before_uid: claims.before_uid,
            query_digest: claims.query_digest,
            expires_at,
        })
    }
}

impl From<&MessageLocator> for MessageClaims {
    fn from(locator: &MessageLocator) -> Self {
        Self {
            mailbox: locator.mailbox.clone(),
            uid_validity: locator.uid_validity,
            uid: locator.uid,
            fingerprint: locator.fingerprint,
            proton_internal_id: locator.proton_internal_id.clone(),
        }
    }
}

impl From<MessageClaims> for MessageLocator {
    fn from(claims: MessageClaims) -> Self {
        Self {
            mailbox: claims.mailbox,
            uid_validity: claims.uid_validity,
            uid: claims.uid,
            fingerprint: claims.fingerprint,
            proton_internal_id: claims.proton_internal_id,
        }
    }
}

fn stale_reference() -> AppError {
    AppError::new(
        ErrorCode::StaleRef,
        "decode opaque reference",
        "Opaque reference is invalid, stale, or belongs to another profile.",
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        application::ports::{ReferenceCodec, SecureRandom},
        domain::{error::AppError, mail::MessageLocator, value::MailboxName},
    };

    use super::EncryptedReferenceCodec;

    #[derive(Debug)]
    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), AppError> {
            destination.fill(7);
            Ok(())
        }
    }

    #[tokio::test]
    async fn references_are_profile_bound_and_tamper_evident() {
        let first = EncryptedReferenceCodec::new(
            zeroize::Zeroizing::new(vec![3; 32]),
            "primary",
            Arc::new(FixedRandom),
        )
        .expect("valid test codec");
        let second = EncryptedReferenceCodec::new(
            zeroize::Zeroizing::new(vec![3; 32]),
            "secondary",
            Arc::new(FixedRandom),
        )
        .expect("valid test codec");
        let locator = MessageLocator {
            mailbox: MailboxName::parse("INBOX").expect("valid mailbox"),
            uid_validity: 42,
            uid: 7,
            fingerprint: [9; 32],
            proton_internal_id: Some("opaque-id".to_owned()),
        };
        let encoded = first
            .encode_message(&locator)
            .await
            .expect("encode reference");
        assert!(
            crate::domain::value::MessageRef::parse(encoded.as_str().to_owned()).is_ok(),
            "the encoder must not emit a reference rejected by the public parser"
        );
        assert_eq!(
            first
                .decode_message(&encoded)
                .await
                .expect("decode reference"),
            locator
        );
        assert!(second.decode_message(&encoded).await.is_err());

        let mut tampered = encoded.as_str().to_owned().into_bytes();
        if let Some(last) = tampered.last_mut() {
            *last = if *last == b'A' { b'B' } else { b'A' };
        }
        let tampered = String::from_utf8(tampered).expect("ASCII reference");
        let parsed = crate::domain::value::MessageRef::parse(tampered).expect("well formed");
        assert!(first.decode_message(&parsed).await.is_err());
    }
}
