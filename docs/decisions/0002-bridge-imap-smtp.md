# ADR 0002: Bridge IMAP and SMTP as the mail boundary

- Status: Accepted
- Date: 2026-08-11
- Supersedes: [ADR 0001](0001-bridge-content-visible-send.md)

## Context

The first implementation used Bridge IMAP for mailbox state and embedded
AppleScript/Accessibility for a visible Proton Mail app send. Live testing
showed that Accessibility authorization belongs to the actual MCP host process,
making the boundary fragile across ChatGPT/Codex host changes even when the
standalone script was correct. The repository owner selected a Bridge-first
architecture and reserved GUI Computer Use for optional manual troubleshooting
outside the server.

Bridge already exposes authenticated local IMAP and SMTP, so the project can
remove the Proton Mail app, AppleScript subprocess, UI selectors, and TCC
permissions while retaining the application-level approval state machine.

## Decision

Use Proton Mail Bridge IMAP for folders, reads, mutations, attachments, draft
storage, exact draft reload, Sent verification, and recoverable draft cleanup.
Use Proton Mail Bridge SMTP for the one irreversible delivery attempt. Both
protocols connect only to IPv4 loopback and share strict hostname/certificate
validation plus the explicitly enrolled certificate pin.

Sending remains a two-step MCP workflow. Preparing or updating creates the
exact Bridge draft and returns a ten-minute single-use token plus a digest bound
to the account, recipients, subject, body, attachments, Message-ID, thread
headers, and synchronized MIME. The client must present the exact content and
obtain explicit approval before `proton_send_prepared`. That call consumes the
token before revalidation and makes at most one SMTP transaction.

Treat transport failure after SMTP DATA begins as uncertain. Never retry it.
After Bridge accepts the message, require exact Message-ID evidence in Sent.
Only then move the source draft to Trash; cleanup failure is a warning on an
otherwise authoritative `sent` result.

## Consequences

- A paid Proton Mail plan and a running, authenticated Bridge are required.
- The Proton Mail macOS app and Automation/Accessibility permissions are not
  required.
- The approval display belongs to the MCP client rather than a server-owned
  native dialog. Tool instructions require exact-content presentation and
  explicit approval, while the server cryptographically binds and revalidates
  the approved operation.
- SMTP parsing, DATA escaping, BCC header removal, rejection/uncertainty
  semantics, and Sent verification become security-critical tested code.
- “Local” describes the tool boundary; Bridge still communicates with Proton's
  service.

## Rejected alternatives

- **Keep AppleScript as a second send path:** preserves a broad, brittle TCC/UI
  boundary and creates two irreversible transports with different guarantees.
- **Use IMAP APPEND to Sent as delivery:** IMAP stores messages but is not a
  mail-submission protocol and cannot prove external delivery.
- **Retry on SMTP timeout or disconnect:** can duplicate mail when Bridge
  accepted DATA but the final response was lost.
- **Transmit the stored BCC header:** discloses blind recipients in delivered
  message headers. BCC stays in the SMTP envelope only.
- **Copy plus delete when MOVE is unavailable:** creates partial-state and data
  loss hazards. Atomic MOVE remains required.
- **Permanent deletion:** remains outside the recoverable Trash-only safety
  contract.
