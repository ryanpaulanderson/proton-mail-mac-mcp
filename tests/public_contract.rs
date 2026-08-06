use proton_mail_mac_mcp::{AppError, ErrorCode};

#[test]
fn public_errors_expose_stable_safe_fields() {
    let error = AppError::new(
        ErrorCode::SendUnknown,
        "verify sent message",
        "Send outcome is uncertain. Check Sent before attempting another send.",
    );

    assert_eq!(error.code(), ErrorCode::SendUnknown);
    assert_eq!(error.operation(), "verify sent message");
    assert_eq!(
        error.public_message(),
        "Send outcome is uncertain. Check Sent before attempting another send."
    );
    assert!(!error.to_string().contains("recipient@example.com"));
}
