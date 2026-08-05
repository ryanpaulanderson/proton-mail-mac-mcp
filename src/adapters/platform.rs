use chrono::{DateTime, Utc};

use crate::{
    application::ports::{Clock, SecureRandom},
    domain::error::{AppError, ErrorCode},
};

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Default)]
pub struct SystemSecureRandom;

impl SecureRandom for SystemSecureRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), AppError> {
        getrandom::fill(destination).map_err(|_| {
            AppError::new(
                ErrorCode::Internal,
                "generate secure random bytes",
                "Secure random generation is unavailable.",
            )
        })
    }
}
