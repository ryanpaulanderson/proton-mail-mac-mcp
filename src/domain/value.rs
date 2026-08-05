use std::{fmt, path::PathBuf, str::FromStr};

use email_address::EmailAddress as ParsedEmailAddress;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use super::error::AppError;

pub const MAX_RECIPIENTS: usize = 20;
pub const MAX_SUBJECT_BYTES: usize = 998;
pub const MAX_BODY_BYTES: usize = 1_000_000;
pub const DEFAULT_PAGE_SIZE: u16 = 25;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const DEFAULT_BODY_PAGE_CHARS: u32 = 8_000;
pub const MAX_BODY_PAGE_CHARS: u32 = 20_000;
pub const MAX_SEARCH_TERM_BYTES: usize = 2_048;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct EmailAddress(String);

impl EmailAddress {
    pub fn parse(value: impl Into<String>) -> Result<Self, AppError> {
        let value = value.into();
        if value.len() > 254 || value.chars().any(char::is_control) {
            return Err(AppError::validation(
                "Email address is invalid or too long.",
            ));
        }
        ParsedEmailAddress::from_str(&value)
            .map_err(|_| AppError::validation("Email address is invalid."))?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct MailboxName(String);

impl MailboxName {
    pub fn parse(value: impl Into<String>) -> Result<Self, AppError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || value
                .chars()
                .any(|character| matches!(character, '\0' | '\r' | '\n'))
        {
            return Err(AppError::validation("Mailbox name is invalid."));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MailboxName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Subject(String);

impl Subject {
    pub fn parse(value: impl Into<String>) -> Result<Self, AppError> {
        let value = value.into().nfc().collect::<String>();
        if value.len() > MAX_SUBJECT_BYTES
            || value
                .chars()
                .any(|character| matches!(character, '\0' | '\r' | '\n'))
        {
            return Err(AppError::validation("Subject is invalid or too long."));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct PlainTextBody(String);

impl PlainTextBody {
    pub fn parse(value: impl Into<String>) -> Result<Self, AppError> {
        let normalized_newlines = value.into().replace("\r\n", "\n").replace('\r', "\n");
        let normalized = normalized_newlines.nfc().collect::<String>();
        if normalized.len() > MAX_BODY_BYTES || normalized.contains('\0') {
            return Err(AppError::resource_limit(
                "Plain-text body is invalid or exceeds the one-megabyte limit.",
            ));
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchTerm(String);

impl SearchTerm {
    pub fn parse(value: impl Into<String>) -> Result<Self, AppError> {
        let value = value.into().nfc().collect::<String>();
        if value.is_empty()
            || value.len() > MAX_SEARCH_TERM_BYTES
            || value
                .chars()
                .any(|character| matches!(character, '\0' | '\r' | '\n'))
        {
            return Err(AppError::validation(
                "Search terms must be nonempty, single-line text no longer than 2,048 bytes.",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize(u16);

impl PageSize {
    pub fn parse(value: Option<u16>) -> Result<Self, AppError> {
        let value = value.unwrap_or(DEFAULT_PAGE_SIZE);
        if value == 0 || value > MAX_PAGE_SIZE {
            return Err(AppError::validation("Page size must be between 1 and 100."));
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyPageRequest {
    offset_chars: u32,
    max_chars: u32,
}

impl BodyPageRequest {
    pub fn parse(offset_chars: Option<u32>, max_chars: Option<u32>) -> Result<Self, AppError> {
        let max_chars = max_chars.unwrap_or(DEFAULT_BODY_PAGE_CHARS);
        if max_chars == 0 || max_chars > MAX_BODY_PAGE_CHARS {
            return Err(AppError::validation(
                "Body page size must be between 1 and 20,000 characters.",
            ));
        }
        Ok(Self {
            offset_chars: offset_chars.unwrap_or(0),
            max_chars,
        })
    }

    pub const fn offset_chars(self) -> u32 {
        self.offset_chars
    }

    pub const fn max_chars(self) -> u32 {
        self.max_chars
    }
}

macro_rules! opaque_ref {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AppError> {
                let value = value.into();
                if value.len() < 24
                    || value.len() > 2_048
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(AppError::validation("Opaque reference is malformed."));
                }
                Ok(Self(value))
            }

            pub(crate) fn from_encoded(value: String) -> Self {
                Self(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_ref!(MessageRef);
opaque_ref!(AttachmentRef);
opaque_ref!(DraftRef);
opaque_ref!(PreparedSendToken);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAttachmentPath(PathBuf);

impl CanonicalAttachmentPath {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}
