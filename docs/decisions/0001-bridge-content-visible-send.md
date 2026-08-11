# ADR 0001: Bridge for mailbox data, visible Proton UI for sending

- Status: Superseded by [ADR 0002](0002-bridge-imap-smtp.md)
- Date: 2026-08-05

## Context

This record preserves the original decision. The UI boundary was removed after
live host-process testing showed that macOS TCC ownership made embedded
Accessibility automation brittle for local MCP hosts, and the repository owner
chose Bridge as the complete mail transport boundary.

The tool needs reliable local mailbox access while preserving a visible,
user-controlled send boundary in the Proton Mail macOS application. Proton Mail
does not expose a native AppleScript dictionary for mailbox data, and scraping
all message content through Accessibility would be fragile, locale-sensitive,
slow, and likely to expose unrelated UI state. Bridge exposes standards-based
local IMAP, but sending directly through SMTP would bypass the requested native
Proton Mail UI confirmation.

## Decision

Use Proton Mail Bridge IMAP over authenticated pinned loopback TLS for folder,
metadata, MIME, attachment, mutation, and draft storage operations. Use static
AppleScript plus macOS Accessibility only to open the exact Bridge-created
draft, verify the visible composer, obtain native confirmation, and press Send
once. Verify the exact Message-ID in Sent through Bridge afterward.

Keep authorization, validation, digest binding, token state, and retry policy
in Rust application code. AppleScript is a small version-sensitive adapter that
accepts versioned JSON on stdin and returns bounded facts.

## Consequences

- A paid Proton Mail plan and a running Bridge application are required.
- Mail reads are reliable and testable without scraping private screen state.
- Sending remains visible and requires two independent user-facing stages:
  draft review and native final confirmation.
- UI selector compatibility must be checked after Proton Mail updates and fails
  closed when uncertain.
- Send completion can be uncertain after the one allowed click. The API exposes
  `send_unknown` and forbids blind retry.
- Bridge and Proton Mail continue to synchronize with Proton's service; “local”
  describes the tool boundary, not an offline mail system.

## Rejected alternatives

- **Accessibility for all mailbox reads:** too broad, fragile, and prone to
  exposing unrelated content.
- **Direct SMTP send through Bridge:** bypasses visible Proton UI verification
  and native final confirmation.
- **Dynamic AppleScript source:** could turn untrusted email text into
  executable code or leak data through process arguments.
- **Copy plus delete when MOVE is unavailable:** creates partial-state and data
  loss hazards. Atomic MOVE is required.
- **Coordinate clicks, keyboard shortcuts, or clipboard automation:** cannot
  prove exact target identity and are unsafe for consequential actions.
- **Permanent deletion:** outside the recoverable Trash-only safety contract.
