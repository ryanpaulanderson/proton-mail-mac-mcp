use std::error::Error as StdError;

use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotConfigured,
    BridgeUnavailable,
    AuthenticationFailed,
    TlsValidationFailed,
    PermissionDenied,
    ValidationFailed,
    ResourceLimit,
    NotFound,
    StaleRef,
    TokenExpired,
    DraftChanged,
    DraftNotFound,
    TokenReferenceMismatch,
    Conflict,
    SendRejected,
    SendUnknown,
    Internal,
}

#[derive(Debug, Error)]
#[error("{operation} failed ({code:?})")]
pub struct AppError {
    code: ErrorCode,
    operation: &'static str,
    public_message: &'static str,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl AppError {
    pub const fn new(
        code: ErrorCode,
        operation: &'static str,
        public_message: &'static str,
    ) -> Self {
        Self {
            code,
            operation,
            public_message,
            source: None,
        }
    }

    pub fn with_source<E>(
        code: ErrorCode,
        operation: &'static str,
        public_message: &'static str,
        source: E,
    ) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            code,
            operation,
            public_message,
            source: Some(Box::new(source)),
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    pub const fn public_message(&self) -> &'static str {
        self.public_message
    }

    pub const fn validation(public_message: &'static str) -> Self {
        Self::new(
            ErrorCode::ValidationFailed,
            "validate input",
            public_message,
        )
    }

    pub const fn resource_limit(public_message: &'static str) -> Self {
        Self::new(
            ErrorCode::ResourceLimit,
            "enforce resource limit",
            public_message,
        )
    }
}
