# Compatibility and validation scope

## Validated matrix

| Component | Validated version / environment | Evidence |
| --- | --- | --- |
| Rust | 1.88.0 | Format, Clippy with warnings denied, all-feature tests, and docs tests. |
| CI host | `macos-15` | GitHub Actions workflow target. |
| Local macOS | 26.6 | Build/test host and local Bridge integration target. |
| Proton Mail Bridge | 3.25.0 installed | IMAP read/draft behavior and SMTP protocol integration target. |

The automated suite uses controlled MIME and in-memory SMTP/IMAP fakes; it does
not require or read a live mailbox and never sends real mail. Live Bridge
acceptance is an explicit, manually approved operation. Before first use,
configure the local Bridge profile and run `proton_status`.

The Proton Mail macOS application has no compatibility role. The server does
not use AppleScript, Accessibility, Automation, UI selectors, coordinates,
keystrokes, the clipboard, or GUI subprocesses.

## Bridge assumptions

The adapters require:

- IPv4 loopback IMAP and SMTP on `127.0.0.1`;
- independently configured STARTTLS or implicit TLS modes, with defaults of
  IMAP 1143/STARTTLS and SMTP 1025/implicit TLS;
- a hostname-valid, enrolled self-signed certificate whose peer DER digest
  exactly matches the configured SHA-256 value;
- the Bridge username/password credential for both protocols;
- IMAP4rev1 behavior, UIDVALIDITY, UID FETCH/SEARCH/STORE, Draft APPEND, and
  atomic MOVE;
- Bridge's `X-Pm-Internal-Id` header for safely verified moves; and
- SMTP AUTH PLAIN, preservation of a caller-supplied Message-ID, and creation
  of a Sent item that becomes visible through IMAP.

SMTP replies are parsed as bounded RFC-style multiline responses. BCC and
draft-only/internal Bridge headers are removed before DATA, unknown top-level
transport headers are rejected, CRLF is normalized, and leading dots are
escaped. Any connection loss or malformed/missing reply after DATA begins is
treated as uncertain and is not retried.

Proton documents that Bridge exposes local IMAP and SMTP, defaults to ports
1143 and 1025, and supports SSL or STARTTLS in its
[Bridge settings guide](https://proton.me/support/comprehensive-guide-to-bridge-settings)
and [port guidance](https://proton.me/support/port-already-occupied-error).
Implementation assumptions are also checked against the official
[Proton Mail Bridge source](https://github.com/ProtonMail/proton-bridge).

## Upgrade procedure

After a Bridge upgrade:

1. Run the automated Rust checks.
2. Run `proton_status`; do not weaken certificate, authentication, or protocol
   checks to make it pass.
3. With synthetic non-sensitive data, validate draft creation, content digest
   stability, BCC handling, and recoverable Trash cleanup.
4. Validate one intentionally self-addressed send only with the repository
   owner's explicit approval. Confirm exact Message-ID verification, source
   draft cleanup status, and no duplicate send.
5. Update this matrix and protocol contract in the same reviewed change.

Certificate rotation is never accepted silently. Export the new Bridge
certificate, inspect why it changed, and run configure to enroll its new
digest.
