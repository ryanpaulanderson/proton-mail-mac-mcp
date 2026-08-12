use std::time::Duration;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::{
    adapters::{
        bridge::{
            BridgeTlsStream, PinnedBridgeTls, decode_bridge_password, decode_certificate_sha256,
        },
        config::{AppConfig, BridgeTlsMode, verify_certificate},
    },
    application::ports::{BridgeHealth, MailSender},
    domain::{
        error::{AppError, ErrorCode},
        mail::SubmissionDraft,
        value::EmailAddress,
    },
};

const IO_TIMEOUT: Duration = Duration::from_secs(20);
const DATA_TIMEOUT: Duration = Duration::from_secs(60);
const QUIT_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_REPLY_LINE_BYTES: usize = 2 * 1024;
const MAX_COMMAND_BYTES: usize = 8 * 1024;
const MAX_REPLY_BYTES: usize = 64 * 1024;
const MAX_REPLY_LINES: usize = 128;
const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 998;

pub struct BridgeSmtpSender {
    tls: PinnedBridgeTls,
    port: u16,
    tls_mode: BridgeTlsMode,
    username: String,
    password: Zeroizing<String>,
    account: EmailAddress,
}

impl BridgeSmtpSender {
    pub fn new(
        config: &AppConfig,
        certificate_path: &std::path::Path,
        password_bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AppError> {
        config.validate()?;
        let certificate_der =
            verify_certificate(certificate_path, &config.bridge.certificate_sha256)?;
        let certificate_sha256 = decode_certificate_sha256(&config.bridge.certificate_sha256)?;
        let password = decode_bridge_password(password_bytes)?;
        Ok(Self {
            tls: PinnedBridgeTls::new(
                &certificate_der,
                certificate_sha256,
                config.bridge.tls_server_name.clone(),
            )?,
            port: config.bridge.smtp_port,
            tls_mode: config.bridge.smtp_tls_mode,
            username: config.bridge.username.clone(),
            password,
            account: config.account()?,
        })
    }

    async fn connect_authenticated(
        &self,
    ) -> Result<(SmtpSession<BridgeTlsStream>, Vec<String>), AppError> {
        let tcp = self.tls.open_loopback(self.port).await?;
        let mut session = match self.tls_mode {
            BridgeTlsMode::ImplicitTls => {
                let tls = self.tls.negotiate(tcp).await?;
                let mut session = SmtpSession::new(tls);
                session.expect_greeting().await?;
                session
            }
            BridgeTlsMode::StartTls => {
                let mut plaintext = SmtpSession::new(tcp);
                plaintext.expect_greeting().await?;
                let capabilities = plaintext.ehlo().await?;
                require_capability(&capabilities, "STARTTLS")?;
                plaintext.command_expect(b"STARTTLS", 220).await?;
                let tcp = plaintext.into_inner();
                let tls = self.tls.negotiate(tcp).await?;
                SmtpSession::new(tls)
            }
        };
        let capabilities = session.ehlo().await?;
        require_auth_plain(&capabilities)?;
        session
            .authenticate(&self.username, self.password.as_str())
            .await?;
        Ok((session, capabilities))
    }

    async fn quit_best_effort<S>(&self, session: &mut SmtpSession<S>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match tokio::time::timeout(QUIT_TIMEOUT, session.command_expect(b"QUIT", 221)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(
                operation = "bridge_smtp_quit",
                error_code = ?error.code(),
                "Bridge SMTP quit did not complete"
            ),
            Err(_) => tracing::warn!(
                operation = "bridge_smtp_quit",
                error_code = "bridge_unavailable",
                "Bridge SMTP quit timed out"
            ),
        }
    }
}

#[async_trait]
impl MailSender for BridgeSmtpSender {
    async fn health(&self) -> Result<BridgeHealth, AppError> {
        let (mut session, capabilities) = self.connect_authenticated().await?;
        self.quit_best_effort(&mut session).await;
        Ok(BridgeHealth {
            reachable: true,
            authenticated: true,
            capabilities,
        })
    }

    async fn submit(&self, submission: &SubmissionDraft) -> Result<(), AppError> {
        if submission.draft.content.account != self.account {
            return Err(AppError::new(
                ErrorCode::PermissionDenied,
                "authorize SMTP sender",
                "Prepared draft account does not match the configured Bridge sender.",
            ));
        }
        let message = SanitizedMessage::parse(submission.raw_message())?;
        let (mut session, _) = self.connect_authenticated().await?;
        submit_transaction(&mut session, &self.account, submission, &message).await?;
        self.quit_best_effort(&mut session).await;
        Ok(())
    }
}

async fn submit_transaction<S>(
    session: &mut SmtpSession<S>,
    account: &EmailAddress,
    submission: &SubmissionDraft,
    message: &SanitizedMessage<'_>,
) -> Result<(), AppError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mail_from = format!("MAIL FROM:<{}>", account.as_str());
    session
        .command_submission(mail_from.as_bytes(), 250)
        .await?;
    for recipient in submission
        .draft
        .content
        .recipients
        .to()
        .iter()
        .chain(submission.draft.content.recipients.cc())
        .chain(submission.draft.content.recipients.bcc())
    {
        let command = format!("RCPT TO:<{}>", recipient.as_str());
        session.command_submission(command.as_bytes(), 250).await?;
    }
    session.command_submission(b"DATA", 354).await?;

    // Once DATA begins, transport failure is conservatively uncertain: the
    // caller must inspect Sent and must never retry this operation blindly.
    if tokio::time::timeout(DATA_TIMEOUT, session.write_message(message))
        .await
        .map_err(|_| send_unknown())?
        .is_err()
    {
        return Err(send_unknown());
    }
    let response = tokio::time::timeout(IO_TIMEOUT, session.read_reply())
        .await
        .map_err(|_| send_unknown())?
        .map_err(|_| send_unknown())?;
    if (400..=599).contains(&response.code) {
        return Err(AppError::new(
            ErrorCode::SendRejected,
            "submit message through Bridge SMTP",
            "Proton Mail Bridge rejected the prepared message.",
        ));
    }
    if response.code == 250 {
        Ok(())
    } else {
        Err(send_unknown())
    }
}

struct SmtpSession<S> {
    stream: BufReader<S>,
}

impl<S> SmtpSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    fn into_inner(self) -> S {
        self.stream.into_inner()
    }

    async fn expect_greeting(&mut self) -> Result<(), AppError> {
        let response = self.read_reply_timed().await?;
        if response.code != 220 {
            return Err(protocol_error(
                "read Bridge SMTP greeting",
                "Proton Mail Bridge did not provide a valid SMTP greeting.",
            ));
        }
        Ok(())
    }

    async fn ehlo(&mut self) -> Result<Vec<String>, AppError> {
        self.write_command(b"EHLO localhost").await?;
        let response = self.read_reply_timed().await?;
        if response.code != 250 {
            return Err(protocol_error(
                "negotiate Bridge SMTP capabilities",
                "Proton Mail Bridge rejected the SMTP capability negotiation.",
            ));
        }
        parse_capabilities(&response.lines)
    }

    async fn authenticate(&mut self, username: &str, password: &str) -> Result<(), AppError> {
        let mut plain = Zeroizing::new(Vec::with_capacity(
            username
                .len()
                .saturating_add(password.len())
                .saturating_add(2),
        ));
        plain.push(0);
        plain.extend_from_slice(username.as_bytes());
        plain.push(0);
        plain.extend_from_slice(password.as_bytes());
        let encoded = Zeroizing::new(STANDARD.encode(plain.as_slice()));
        let command = Zeroizing::new(format!("AUTH PLAIN {}", encoded.as_str()));
        self.write_command(command.as_bytes()).await?;
        let response = self.read_reply_timed().await?;
        match response.code {
            235 => Ok(()),
            400..=499 => Err(AppError::new(
                ErrorCode::BridgeUnavailable,
                "authenticate to Bridge SMTP",
                "Proton Mail Bridge temporarily could not authenticate the local SMTP session.",
            )),
            500..=599 => Err(AppError::new(
                ErrorCode::AuthenticationFailed,
                "authenticate to Bridge SMTP",
                "Proton Mail Bridge rejected the configured credentials; run configure again.",
            )),
            _ => Err(protocol_error(
                "authenticate to Bridge SMTP",
                "Proton Mail Bridge returned an unexpected authentication response.",
            )),
        }
    }

    async fn command_expect(&mut self, command: &[u8], expected: u16) -> Result<(), AppError> {
        self.write_command(command).await?;
        let response = self.read_reply_timed().await?;
        if response.code != expected {
            return Err(protocol_error(
                "execute Bridge SMTP command",
                "Proton Mail Bridge rejected the SMTP operation.",
            ));
        }
        Ok(())
    }

    async fn command_submission(&mut self, command: &[u8], expected: u16) -> Result<(), AppError> {
        self.write_command(command).await?;
        let response = self.read_reply_timed().await?;
        if response.code == expected {
            return Ok(());
        }
        if (400..=599).contains(&response.code) {
            return Err(AppError::new(
                ErrorCode::SendRejected,
                "submit message through Bridge SMTP",
                "Proton Mail Bridge rejected the prepared message.",
            ));
        }
        Err(protocol_error(
            "execute Bridge SMTP submission command",
            "Proton Mail Bridge returned an unexpected SMTP response.",
        ))
    }

    async fn write_command(&mut self, command: &[u8]) -> Result<(), AppError> {
        if command.is_empty()
            || command.len() > MAX_COMMAND_BYTES
            || command
                .iter()
                .any(|byte| matches!(*byte, b'\0' | b'\r' | b'\n'))
        {
            return Err(AppError::validation("SMTP command is malformed."));
        }
        tokio::time::timeout(IO_TIMEOUT, async {
            self.stream.get_mut().write_all(command).await?;
            self.stream.get_mut().write_all(b"\r\n").await?;
            self.stream.get_mut().flush().await
        })
        .await
        .map_err(|_| protocol_error("write Bridge SMTP command", "Proton Mail Bridge timed out."))?
        .map_err(|error| {
            AppError::with_source(
                ErrorCode::BridgeUnavailable,
                "write Bridge SMTP command",
                "Proton Mail Bridge ended the SMTP connection.",
                error,
            )
        })
    }

    async fn read_reply_timed(&mut self) -> Result<SmtpReply, AppError> {
        tokio::time::timeout(IO_TIMEOUT, self.read_reply())
            .await
            .map_err(|_| {
                protocol_error("read Bridge SMTP reply", "Proton Mail Bridge timed out.")
            })?
    }

    async fn read_reply(&mut self) -> Result<SmtpReply, AppError> {
        let mut lines = Vec::new();
        let mut total = 0_usize;
        let mut expected_code = None;
        loop {
            if lines.len() >= MAX_REPLY_LINES {
                return Err(AppError::resource_limit(
                    "Bridge SMTP reply exceeds the supported line count.",
                ));
            }
            let line = read_limited_line(&mut self.stream).await?;
            total = total.checked_add(line.len()).ok_or_else(|| {
                AppError::resource_limit("Bridge SMTP reply exceeds the supported size.")
            })?;
            if total > MAX_REPLY_BYTES {
                return Err(AppError::resource_limit(
                    "Bridge SMTP reply exceeds the supported size.",
                ));
            }
            let (code, more) = parse_reply_prefix(&line)?;
            if expected_code.is_some_and(|expected| expected != code) {
                return Err(protocol_error(
                    "parse Bridge SMTP reply",
                    "Proton Mail Bridge returned an inconsistent SMTP reply.",
                ));
            }
            expected_code = Some(code);
            lines.push(line);
            if !more {
                return Ok(SmtpReply { code, lines });
            }
        }
    }

    async fn write_message(&mut self, message: &SanitizedMessage<'_>) -> std::io::Result<()> {
        for header in &message.headers {
            write_data_line(self.stream.get_mut(), header).await?;
        }
        write_data_line(self.stream.get_mut(), b"").await?;
        write_body_lines(self.stream.get_mut(), message.body).await?;
        self.stream.get_mut().write_all(b".\r\n").await?;
        self.stream.get_mut().flush().await
    }
}

struct SmtpReply {
    code: u16,
    lines: Vec<Vec<u8>>,
}

struct SanitizedMessage<'a> {
    headers: Vec<Vec<u8>>,
    body: &'a [u8],
}

impl<'a> SanitizedMessage<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self, AppError> {
        let (header, body) = split_header_body(raw)?;
        if header.len() > MAX_HEADER_BYTES {
            return Err(AppError::resource_limit(
                "Draft headers exceed the supported size.",
            ));
        }
        let mut headers = Vec::new();
        let mut skip_current = false;
        let mut seen_header = false;
        for raw_line in header.split(|byte| *byte == b'\n') {
            let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
            if line.is_empty() || line.len() > MAX_HEADER_LINE_BYTES || line.contains(&b'\r') {
                return Err(AppError::validation("Draft headers are malformed."));
            }
            if matches!(line.first(), Some(b' ' | b'\t')) {
                if !seen_header {
                    return Err(AppError::validation(
                        "Draft headers are malformed and cannot be submitted.",
                    ));
                }
                if !skip_current {
                    headers.push(line.to_vec());
                }
                continue;
            }
            let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
                AppError::validation("Draft headers are malformed and cannot be submitted.")
            })?;
            let name = line.get(..colon).ok_or_else(|| {
                AppError::validation("Draft headers are malformed and cannot be submitted.")
            })?;
            if name.is_empty()
                || !name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                return Err(AppError::validation(
                    "Draft headers are malformed and cannot be submitted.",
                ));
            }
            skip_current = name.eq_ignore_ascii_case(b"bcc")
                || name.eq_ignore_ascii_case(b"x-unsent")
                || name
                    .get(..5)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"x-pm-"));
            if !skip_current && !is_allowed_submission_header(name) {
                return Err(AppError::validation(
                    "Draft contains an unsupported transport header and cannot be submitted.",
                ));
            }
            seen_header = true;
            if !skip_current {
                headers.push(line.to_vec());
            }
        }
        if body.iter().enumerate().any(|(index, byte)| {
            *byte == b'\r' && body.get(index.saturating_add(1)) != Some(&b'\n')
        }) {
            return Err(AppError::validation(
                "Draft MIME body contains malformed line endings.",
            ));
        }
        Ok(Self { headers, body })
    }
}

fn is_allowed_submission_header(name: &[u8]) -> bool {
    [
        b"date".as_slice(),
        b"from".as_slice(),
        b"to".as_slice(),
        b"cc".as_slice(),
        b"subject".as_slice(),
        b"message-id".as_slice(),
        b"in-reply-to".as_slice(),
        b"references".as_slice(),
        b"mime-version".as_slice(),
        b"content-type".as_slice(),
        b"content-transfer-encoding".as_slice(),
        b"content-disposition".as_slice(),
    ]
    .iter()
    .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

async fn read_limited_line<R>(reader: &mut R) -> Result<Vec<u8>, AppError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|error| {
            AppError::with_source(
                ErrorCode::BridgeUnavailable,
                "read Bridge SMTP reply",
                "Proton Mail Bridge ended the SMTP connection.",
                error,
            )
        })?;
        if available.is_empty() {
            return Err(protocol_error(
                "read Bridge SMTP reply",
                "Proton Mail Bridge ended the SMTP connection.",
            ));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position.saturating_add(1));
        if line.len().saturating_add(take) > MAX_REPLY_LINE_BYTES {
            return Err(AppError::resource_limit(
                "Bridge SMTP reply line exceeds the supported size.",
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            if !line.ends_with(b"\r\n") {
                return Err(protocol_error(
                    "parse Bridge SMTP reply",
                    "Proton Mail Bridge returned malformed SMTP line endings.",
                ));
            }
            line.truncate(line.len().saturating_sub(2));
            return Ok(line);
        }
    }
}

fn parse_reply_prefix(line: &[u8]) -> Result<(u16, bool), AppError> {
    if line.len() < 4 || !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(protocol_error(
            "parse Bridge SMTP reply",
            "Proton Mail Bridge returned a malformed SMTP reply.",
        ));
    }
    let code = std::str::from_utf8(&line[..3])
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            protocol_error(
                "parse Bridge SMTP reply",
                "Proton Mail Bridge returned a malformed SMTP reply.",
            )
        })?;
    match line.get(3) {
        Some(b'-') => Ok((code, true)),
        Some(b' ') => Ok((code, false)),
        _ => Err(protocol_error(
            "parse Bridge SMTP reply",
            "Proton Mail Bridge returned a malformed SMTP reply.",
        )),
    }
}

fn parse_capabilities(lines: &[Vec<u8>]) -> Result<Vec<String>, AppError> {
    let mut capabilities = Vec::with_capacity(lines.len());
    for line in lines {
        let value = line.get(4..).ok_or_else(|| {
            protocol_error(
                "parse Bridge SMTP capabilities",
                "Proton Mail Bridge returned malformed SMTP capabilities.",
            )
        })?;
        let value = std::str::from_utf8(value).map_err(|_| {
            protocol_error(
                "parse Bridge SMTP capabilities",
                "Proton Mail Bridge returned non-text SMTP capabilities.",
            )
        })?;
        capabilities.push(value.to_ascii_uppercase());
    }
    Ok(capabilities)
}

fn require_capability(capabilities: &[String], expected: &str) -> Result<(), AppError> {
    if capabilities
        .iter()
        .any(|value| value.split_ascii_whitespace().next() == Some(expected))
    {
        Ok(())
    } else {
        Err(protocol_error(
            "validate Bridge SMTP capability",
            "Proton Mail Bridge does not advertise a required SMTP capability.",
        ))
    }
}

fn require_auth_plain(capabilities: &[String]) -> Result<(), AppError> {
    if capabilities.iter().any(|value| {
        value.strip_prefix("AUTH ").is_some_and(|methods| {
            methods
                .split_ascii_whitespace()
                .any(|method| method == "PLAIN")
        })
    }) {
        Ok(())
    } else {
        Err(protocol_error(
            "validate Bridge SMTP authentication",
            "Proton Mail Bridge does not advertise the required AUTH PLAIN method.",
        ))
    }
}

fn split_header_body(raw: &[u8]) -> Result<(&[u8], &[u8]), AppError> {
    let search_end = raw.len().min(MAX_HEADER_BYTES.saturating_add(4));
    let prefix = raw
        .get(..search_end)
        .ok_or_else(|| AppError::validation("Draft MIME header boundary is malformed."))?;
    if let Some(position) = prefix.windows(4).position(|window| window == b"\r\n\r\n") {
        let body = raw
            .get(position.saturating_add(4)..)
            .ok_or_else(|| AppError::validation("Draft MIME body boundary is malformed."))?;
        return Ok((&raw[..position], body));
    }
    if let Some(position) = prefix.windows(2).position(|window| window == b"\n\n") {
        let body = raw
            .get(position.saturating_add(2)..)
            .ok_or_else(|| AppError::validation("Draft MIME body boundary is malformed."))?;
        return Ok((&raw[..position], body));
    }
    if raw.len() > MAX_HEADER_BYTES {
        Err(AppError::resource_limit(
            "Draft headers exceed the supported size.",
        ))
    } else {
        Err(AppError::validation(
            "Draft MIME has no valid header/body boundary.",
        ))
    }
}

async fn write_data_line<W>(writer: &mut W, line: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if line.first() == Some(&b'.') {
        writer.write_all(b".").await?;
    }
    writer.write_all(line).await?;
    writer.write_all(b"\r\n").await
}

async fn write_body_lines<W>(writer: &mut W, body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut remaining = body;
    while !remaining.is_empty() {
        let newline = remaining.iter().position(|byte| *byte == b'\n');
        let (line, rest) = match newline {
            Some(position) => {
                let next = position.saturating_add(1);
                (&remaining[..position], &remaining[next..])
            }
            None => (remaining, &[][..]),
        };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        write_data_line(writer, line).await?;
        remaining = rest;
    }
    Ok(())
}

fn protocol_error(operation: &'static str, message: &'static str) -> AppError {
    AppError::new(ErrorCode::BridgeUnavailable, operation, message)
}

fn send_unknown() -> AppError {
    AppError::new(
        ErrorCode::SendUnknown,
        "submit message through Bridge SMTP",
        "Send outcome is uncertain. Check Sent before attempting another send.",
    )
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use crate::domain::{
        error::ErrorCode,
        mail::{
            DraftContent, DraftMode, MessageLocator, RecipientSet, StoredDraft, SubmissionDraft,
        },
        value::{EmailAddress, MailboxName, PlainTextBody, Subject},
    };

    use super::{
        SanitizedMessage, SmtpSession, parse_capabilities, parse_reply_prefix, submit_transaction,
    };

    #[test]
    fn submission_removes_bcc_and_unsent_headers_with_continuations() {
        let raw = b"From: sender@example.test\r\nTo: recipient@example.test\r\nBcc: hidden@example.test\r\n\thidden-two@example.test\r\nX-Unsent: 1\r\nSubject: hello\r\n\r\nbody";
        let message = SanitizedMessage::parse(raw).expect("sanitize message");
        let headers = message.headers.concat();
        assert!(
            !headers
                .windows(4)
                .any(|window| window.eq_ignore_ascii_case(b"bcc:"))
        );
        assert!(
            !headers
                .windows(9)
                .any(|window| window.eq_ignore_ascii_case(b"x-unsent:"))
        );
        assert_eq!(message.body, b"body");
    }

    #[test]
    fn malformed_and_inconsistent_replies_fail_closed() {
        assert_eq!(
            parse_reply_prefix(b"250-hello").expect("reply"),
            (250, true)
        );
        assert_eq!(
            parse_reply_prefix(b"250 done").expect("reply"),
            (250, false)
        );
        assert!(parse_reply_prefix(b"25 done").is_err());
        assert!(parse_reply_prefix(b"250?done").is_err());
        assert!(parse_capabilities(&[b"bad".to_vec()]).is_err());
    }

    #[test]
    fn malformed_or_missing_header_boundaries_are_rejected() {
        assert!(SanitizedMessage::parse(b"Subject: no boundary").is_err());
        assert!(SanitizedMessage::parse(b"Malformed\r\n\r\nbody").is_err());
        assert!(SanitizedMessage::parse(b" Subject continuation\r\n\r\nbody").is_err());
        assert!(SanitizedMessage::parse(b"Reply-To: attacker@example.test\r\n\r\nbody").is_err());
    }

    #[tokio::test]
    async fn smtp_transaction_uses_bcc_only_in_envelope_and_dot_stuffs_body() {
        let submission = test_submission();
        let message = SanitizedMessage::parse(submission.raw_message()).expect("sanitize message");
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(script_submission(server, Some(b"250 accepted\r\n")));
        let mut session = SmtpSession::new(client);
        submit_transaction(
            &mut session,
            &EmailAddress::parse("sender@example.test").expect("sender"),
            &submission,
            &message,
        )
        .await
        .expect("submit message");
        drop(session);
        let transcript = server.await.expect("join SMTP server");
        let transcript = String::from_utf8(transcript).expect("ASCII transcript");
        assert!(transcript.contains("RCPT TO:<hidden@example.test>\r\n"));
        assert!(!transcript.to_ascii_lowercase().contains("bcc:"));
        assert!(!transcript.to_ascii_lowercase().contains("x-unsent:"));
        assert!(transcript.contains("\r\n..leading dot\r\n.\r\n"));
    }

    #[tokio::test]
    async fn rejection_after_data_is_definite_but_disconnect_is_uncertain() {
        let submission = test_submission();
        let message = SanitizedMessage::parse(submission.raw_message()).expect("sanitize message");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(script_submission(server, Some(b"550 rejected\r\n")));
        let mut session = SmtpSession::new(client);
        let rejected = submit_transaction(
            &mut session,
            &EmailAddress::parse("sender@example.test").expect("sender"),
            &submission,
            &message,
        )
        .await
        .expect_err("reject message");
        assert_eq!(rejected.code(), ErrorCode::SendRejected);
        drop(session);
        server.await.expect("join rejecting SMTP server");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(script_submission(server, None));
        let mut session = SmtpSession::new(client);
        let uncertain = submit_transaction(
            &mut session,
            &EmailAddress::parse("sender@example.test").expect("sender"),
            &submission,
            &message,
        )
        .await
        .expect_err("report uncertain message");
        assert_eq!(uncertain.code(), ErrorCode::SendUnknown);
        drop(session);
        server.await.expect("join disconnecting SMTP server");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(script_submission(server, Some(b"354 unexpected\r\n")));
        let mut session = SmtpSession::new(client);
        let uncertain = submit_transaction(
            &mut session,
            &EmailAddress::parse("sender@example.test").expect("sender"),
            &submission,
            &message,
        )
        .await
        .expect_err("report unexpected final response");
        assert_eq!(uncertain.code(), ErrorCode::SendUnknown);
        drop(session);
        server.await.expect("join unexpected SMTP server");
    }

    fn test_submission() -> SubmissionDraft {
        let account = EmailAddress::parse("sender@example.test").expect("sender");
        let recipients = RecipientSet::new(
            vec![EmailAddress::parse("recipient@example.test").expect("recipient")],
            Vec::new(),
            vec![EmailAddress::parse("hidden@example.test").expect("bcc")],
        )
        .expect("recipients");
        let content = DraftContent {
            mode: DraftMode::New,
            account,
            recipients,
            subject: Subject::parse("SMTP contract").expect("subject"),
            body: PlainTextBody::parse(".leading dot").expect("body"),
            attachments: Vec::new(),
            in_reply_to: None,
        };
        let draft = StoredDraft {
            locator: MessageLocator {
                mailbox: MailboxName::parse("Drafts").expect("mailbox"),
                uid_validity: 1,
                uid: 1,
                fingerprint: [1; 32],
                proton_internal_id: None,
            },
            message_id: "smtp-contract@example.invalid".to_owned(),
            integrity_digest: [2; 32],
            content,
        };
        SubmissionDraft::new(
            draft,
            b"From: sender@example.test\r\nTo: recipient@example.test\r\nBcc: hidden@example.test\r\nX-Unsent: 1\r\nMessage-ID: <smtp-contract@example.invalid>\r\nSubject: SMTP contract\r\nDate: Tue, 11 Aug 2026 12:00:00 +0000\r\n\r\n.leading dot"
                .to_vec(),
        )
        .expect("submission")
    }

    async fn script_submission(
        stream: DuplexStream,
        final_reply: Option<&'static [u8]>,
    ) -> Vec<u8> {
        let mut stream = BufReader::new(stream);
        let mut transcript = Vec::new();
        for expected in [
            "MAIL FROM:<sender@example.test>\r\n",
            "RCPT TO:<recipient@example.test>\r\n",
            "RCPT TO:<hidden@example.test>\r\n",
            "DATA\r\n",
        ] {
            let mut line = String::new();
            stream
                .read_line(&mut line)
                .await
                .expect("read SMTP command");
            assert_eq!(line, expected);
            transcript.extend_from_slice(line.as_bytes());
            let reply = if expected == "DATA\r\n" {
                b"354 continue\r\n".as_slice()
            } else {
                b"250 ok\r\n".as_slice()
            };
            stream
                .get_mut()
                .write_all(reply)
                .await
                .expect("write SMTP reply");
        }
        loop {
            let mut line = Vec::new();
            stream
                .read_until(b'\n', &mut line)
                .await
                .expect("read SMTP data");
            if line.is_empty() {
                break;
            }
            transcript.extend_from_slice(&line);
            if line == b".\r\n" {
                break;
            }
        }
        if let Some(reply) = final_reply {
            stream
                .get_mut()
                .write_all(reply)
                .await
                .expect("write final SMTP reply");
        }
        transcript
    }
}
