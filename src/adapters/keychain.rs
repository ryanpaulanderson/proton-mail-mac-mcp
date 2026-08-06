use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    application::ports::SecretStore,
    domain::error::{AppError, ErrorCode},
};

const MAX_KEY_NAME_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct KeychainSecretStore {
    service: String,
}

impl KeychainSecretStore {
    pub fn new(service: impl Into<String>) -> Result<Self, AppError> {
        let service = service.into();
        validate_label(&service, "Keychain service name is invalid.")?;
        Ok(Self { service })
    }
}

#[async_trait]
impl SecretStore for KeychainSecretStore {
    async fn get(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
        validate_label(key, "Keychain secret name is invalid.")?;
        let service = self.service.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || get_secret(&service, &key))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join Keychain reader",
                    "Keychain access stopped unexpectedly.",
                    error,
                )
            })?
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), AppError> {
        validate_label(key, "Keychain secret name is invalid.")?;
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(AppError::resource_limit(
                "Keychain secret is empty or exceeds the supported size.",
            ));
        }
        let service = self.service.clone();
        let key = key.to_owned();
        let value = Zeroizing::new(value.to_vec());
        tokio::task::spawn_blocking(move || set_secret(&service, &key, &value))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join Keychain writer",
                    "Keychain access stopped unexpectedly.",
                    error,
                )
            })?
    }

    async fn exists(&self, key: &str) -> Result<bool, AppError> {
        validate_label(key, "Keychain secret name is invalid.")?;
        let service = self.service.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || secret_exists(&service, &key))
            .await
            .map_err(|error| {
                AppError::with_source(
                    ErrorCode::Internal,
                    "join Keychain probe",
                    "Keychain access stopped unexpectedly.",
                    error,
                )
            })?
    }
}

fn validate_label(value: &str, message: &'static str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > MAX_KEY_NAME_BYTES || value.chars().any(char::is_control) {
        return Err(AppError::validation(message));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn get_secret(service: &str, key: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    use security_framework::passwords::get_generic_password;

    get_generic_password(service, key)
        .map(Zeroizing::new)
        .map_err(|error| {
            let code = if error.code() == security_framework_sys::base::errSecItemNotFound {
                ErrorCode::NotConfigured
            } else {
                ErrorCode::PermissionDenied
            };
            AppError::with_source(
                code,
                "read Keychain secret",
                "Required Keychain material is unavailable; run configure.",
                error,
            )
        })
}

#[cfg(not(target_os = "macos"))]
fn get_secret(_service: &str, _key: &str) -> Result<Zeroizing<Vec<u8>>, AppError> {
    Err(platform_error())
}

#[cfg(target_os = "macos")]
fn set_secret(service: &str, key: &str, value: &[u8]) -> Result<(), AppError> {
    security_framework::passwords::set_generic_password(service, key, value).map_err(|error| {
        AppError::with_source(
            ErrorCode::PermissionDenied,
            "write Keychain secret",
            "Keychain material could not be stored.",
            error,
        )
    })
}

#[cfg(not(target_os = "macos"))]
fn set_secret(_service: &str, _key: &str, _value: &[u8]) -> Result<(), AppError> {
    Err(platform_error())
}

#[cfg(target_os = "macos")]
fn secret_exists(service: &str, key: &str) -> Result<bool, AppError> {
    use security_framework::passwords::get_generic_password;

    match get_generic_password(service, key) {
        Ok(secret) => {
            let _secret = Zeroizing::new(secret);
            Ok(true)
        }
        Err(error) if error.code() == security_framework_sys::base::errSecItemNotFound => Ok(false),
        Err(error) => Err(AppError::with_source(
            ErrorCode::PermissionDenied,
            "probe Keychain secret",
            "Keychain material could not be inspected.",
            error,
        )),
    }
}

#[cfg(not(target_os = "macos"))]
fn secret_exists(_service: &str, _key: &str) -> Result<bool, AppError> {
    Err(platform_error())
}

#[cfg(not(target_os = "macos"))]
fn platform_error() -> AppError {
    AppError::new(
        ErrorCode::NotConfigured,
        "access macOS Keychain",
        "This tool requires macOS Keychain.",
    )
}

#[cfg(test)]
mod tests {
    use super::validate_label;

    #[test]
    fn labels_reject_control_characters_and_oversize_values() {
        assert!(validate_label("bridge.primary", "invalid").is_ok());
        assert!(validate_label("bridge\nprimary", "invalid").is_err());
        assert!(validate_label(&"x".repeat(257), "invalid").is_err());
    }
}
