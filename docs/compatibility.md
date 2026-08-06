# Compatibility and validation scope

## Validated matrix

| Component | Validated version / environment | Evidence |
| --- | --- | --- |
| Rust | 1.88.0 | Format, Clippy with warnings denied, all-feature tests, and docs tests. |
| CI host | `macos-15` | GitHub Actions workflow target. |
| Local macOS | 26.6 | Build/test host and non-destructive Accessibility selector check. |
| Proton Mail app | 1.13.3 | Bundle version and live semantic Accessibility inspection. |
| Embedded Proton web app | 5.0.125.9 | Version shown by the Proton Mail app during selector validation. |
| Proton Mail Bridge | 3.25.0 installed | Configuration target; IMAP behavior cross-checked against Proton's open-source Bridge tests/source. |

The automated suite uses fake ports and controlled MIME/IMAP inputs; it does
not require or read a live mailbox. A live Bridge credential integration test
is intentionally not part of CI. Before first use, configure the local Bridge
profile and run `proton_status`.

## UI selector contract

The reviewed AppleScript assumes Proton Mail's English UI and exactly one
standard Proton Mail window. The validated composer exposed:

- one enabled `AXButton` named `Send`;
- one `AXTextField` described as `Subject`;
- one `AXTextArea` for the body;
- recipient buttons whose help value is the exact address and whose label
  identifies To, CC, or BCC;
- an attachment summary button with help `Show attachment details` or
  `Hide attachment details`;
- one `Remove <filename>` button per expanded attachment; and
- an `AXWebArea` URL containing the exact Proton internal draft ID as a path
  segment.

Every selector is checked for uniqueness and relevant enabled/value state.
Changed hierarchy, localization, extra windows, dialogs, missing attributes,
or mismatched values fail closed. No coordinate, menu index, clipboard, or raw
keystroke fallback exists.

Selector validation used a synthetic, non-sensitive draft and attachment. The
test draft was moved to Trash afterward. A permanent-delete confirmation was
cancelled and no permanent deletion was performed.

## Bridge assumptions

The adapter requires:

- IPv4 loopback IMAP on `127.0.0.1`;
- STARTTLS by default or explicitly configured implicit TLS;
- a hostname-valid, enrolled self-signed certificate whose peer DER digest
  exactly matches the configured SHA-256 value;
- IMAP4rev1 behavior, UIDVALIDITY, UID FETCH/SEARCH/STORE, Draft APPEND, and
  atomic MOVE;
- Bridge's `X-Pm-Internal-Id` header for safely verified moves and UI draft
  selection; and
- preservation of a caller-supplied Message-ID when a draft is sent through
  the Proton Mail UI.

Proton documents the loopback TLS model in its
[Bridge connection guidance](https://proton.me/support/bridge-ssl-connection-issue).
The implementation assumptions were also checked against the official
[Proton Mail Bridge source](https://github.com/ProtonMail/proton-bridge),
including Draft APPEND coverage and `X-Pm-Internal-Id` generation.

## Upgrade procedure

After a Proton Mail or Bridge upgrade:

1. Run the automated Rust and AppleScript compile checks.
2. Run `proton_status`; do not weaken certificate or UI checks to make it pass.
3. With synthetic non-sensitive data, validate draft selection, exact
   recipient/body/attachment matching, native cancellation, and Trash cleanup.
4. Validate one intentionally addressed send only with the repository owner's
   explicit approval. Confirm exact Message-ID verification and no duplicate
   send.
5. Update this matrix and selector source in the same reviewed change.

Certificate rotation is never accepted silently. Export the new Bridge
certificate, inspect why it changed, and run configure to enroll its new
digest.
