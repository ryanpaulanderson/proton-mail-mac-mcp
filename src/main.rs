#![forbid(unsafe_code)]

use std::process::ExitCode;

use proton_mail_mac_mcp::{
    cli,
    domain::error::{AppError, ErrorCode},
};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = initialize_logging() {
        eprintln!("configuration_failed: {}", error.public_message());
        return ExitCode::FAILURE;
    }
    match cli::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(
                operation = error.operation(),
                error_code = ?error.code(),
                message = error.public_message(),
                "application stopped"
            );
            ExitCode::FAILURE
        }
    }
}

fn initialize_logging() -> Result<(), AppError> {
    tracing_subscriber::fmt()
        .with_env_filter("off,proton_mail_mac_mcp=info")
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
        .map_err(|_| {
            AppError::new(
                ErrorCode::Internal,
                "initialize redacted logging",
                "Redacted diagnostic logging could not be initialized.",
            )
        })
}
