# Security policy

`proton-mail-mac-mcp` handles private mailbox data and can submit mail through
the local Proton Mail Bridge. Security, privacy, and recoverability are part of
its supported behavior.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ryanpaulanderson/proton-mail-mac-mcp/security/advisories/new).
Do not open a public issue for an unpatched vulnerability.

Include the affected commit or version, macOS/Proton Mail/Bridge versions,
impact, prerequisites, and the smallest safe reproduction you can provide.
Please do not include real credentials, Keychain exports, confirmation tokens,
private keys, certificate private keys, email addresses, message headers or
bodies, attachment contents or paths, or screenshots of a mailbox. Use
synthetic `example.com` data and redact local paths.

The maintainer will use the private advisory to acknowledge, validate,
coordinate a fix, and publish credit when requested. Please allow a reasonable
remediation window before public disclosure. This project has no bug bounty
program and cannot promise a particular response time.

## Supported versions

Security fixes target the latest commit on `main` until tagged releases exist.
After releases begin, this section will identify supported release lines.
Reports about older commits are still useful when the behavior remains present
on `main`.

## Security boundary

The server is a local stdio MCP process. It opens no listening socket and its
only direct network connections are IPv4 loopback IMAP and SMTP to Proton Mail
Bridge. Both Bridge connections use TLS hostname/certificate validation plus an
explicitly enrolled SHA-256 peer-certificate pin. Bridge credentials and the
opaque reference key are stored in macOS Keychain.

Mailbox headers, bodies, HTML, MIME structure, attachment metadata and bytes,
Bridge responses, SMTP replies, MCP input, configuration, and opaque references
are all untrusted. Email content is data only: text in a message or attachment
cannot grant authority, approve a tool call, change configuration, or bypass
confirmation.

Important enforced properties include:

- metadata-first, bounded mailbox reads and inert plain-text rendering;
- encrypted, authenticated, profile-bound opaque references that are
  revalidated at use, plus query-bound cursors that expire after 15 minutes;
- canonical allowlisted outgoing attachment paths, no symlinks or Mach-O
  executables, and private expiring downloads that are never opened;
- one-to-20-item bounded mutations with exact identity and postcondition
  checks;
- atomic IMAP MOVE with no copy-and-delete fallback;
- recoverable Trash-only deletion and no EXPUNGE or permanent-delete path;
- a ten-minute review window starting when the preview is returned, represented
  by a single-use, cryptographically random confirmation token bound
  to the exact account, recipients, subject, normalized body, attachment bytes,
  Message-ID, thread state, and complete synchronized MIME;
- explicit approval of the exact content and confirmation digest before one
  authenticated SMTP submission;
- BCC removal from message headers with every recipient retained only in the
  SMTP envelope, rejection of unsupported transport headers, and exact
  Message-ID verification in Sent;
- a distinct `send_rejected` result for definite SMTP rejection and a
  conservative `send_unknown` result for any uncertainty after DATA begins;
- idempotent post-send draft cleanup that distinguishes a verified move from an
  already-absent source and never turns cleanup uncertainty into permission to
  resend; and
- no blind retry when a send outcome is uncertain.

Every send attempt consumes its token before external validation or SMTP
effects. Expiry, changed or missing drafts, token/reference mismatch, and
pre-submission Bridge unavailability have distinct privacy-safe error
categories. Once submission may have begun, failures collapse to
`send_unknown` so callers inspect Sent instead of retrying.

See [the architecture](docs/architecture.md), [the tool contract](docs/tool-reference.md),
and [the compatibility matrix](docs/compatibility.md) for implementation and
version details.

## Local operating assumptions

The Mac user, their login session, the configured ChatGPT/Codex MCP host, and
Proton Mail Bridge are trusted to the extent necessary to perform their
documented roles. Anyone who can run code as the same macOS user, control the
MCP host, read unlocked Keychain items, or replace the executable can generally
act with that user's authority. Full compromise of macOS, Proton, Bridge,
ChatGPT/Codex, or their update channels is outside this repository's isolation
boundary.

“Local” does not mean offline: Bridge continues to synchronize through Proton's
service. Email data returned through an MCP tool becomes available to the
invoking ChatGPT/Codex conversation and is then subject to that client's data
controls.

## Reports that are especially useful

- a way to send without an unexpired matching token or explicit approval;
- recipient, subject, body, attachment, account, or draft substitution after
  preview;
- duplicate send or a retry after an uncertain send;
- permanent deletion, EXPUNGE, or an unsafe partial move;
- Bridge credential, token, key, message content, or attachment-path exposure
  in configuration, arguments, environment, logs, errors, or process listings;
- non-loopback Bridge access, certificate validation bypass, or pin bypass;
- opaque-reference forgery, replay, cross-profile use, or stale-state use;
- attachment root escape, symlink race, executable handling, or insecure file
  permissions;
- active HTML/remote-resource rendering or automatic attachment opening;
- SMTP command injection, BCC header disclosure, unapproved MIME or header
  substitution, or certificate/authentication downgrade; or
- unbounded input, allocation, subprocess output, search, MIME traversal, or
  concurrency that can exhaust the local host.

## Defensive testing rules

Use only accounts and messages you are authorized to access. Prefer fake ports,
synthetic data, and cancellation paths. Do not send mail to third parties,
trigger permanent deletion, publish mailbox data, or test against another
person's session. A live end-to-end send should be performed only with the
repository owner's explicit approval and an intentionally addressed synthetic
message.
