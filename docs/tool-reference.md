# MCP tool reference

All input objects reject unknown fields. All tools advertise
`openWorldHint=false`. Email-derived output is untrusted data even when it is
returned in a typed field.

| Tool | Purpose | Important behavior |
| --- | --- | --- |
| `proton_status` | Read local readiness | No mailbox content; returns a redacted account hint and authenticated Bridge IMAP/SMTP readiness. |
| `proton_list_folders` | List folder metadata | Returns at most 512 names and selectability. |
| `proton_list_messages` | Search message metadata | Defaults to INBOX and 25 items; returns sender, subject, date, opaque reference, and encrypted query-bound cursor. |
| `proton_get_message` | Read one content page | Returns inert plain text plus attachment metadata; no HTML rendering or remote loads. |
| `proton_download_attachment` | Save attachment bytes | Creates a new private file in the managed directory; never opens it; 24-hour expiry. |
| `proton_set_flags` | Set read/star state | One to 20 exact references; idempotent target state and read-back verification. |
| `proton_move_messages` | Move to a named folder | One to 20 exact references; atomic IMAP MOVE and exact destination verification. |
| `proton_archive_messages` | Move to configured Archive | One to 20 exact references; no copy-delete fallback. |
| `proton_trash_messages` | Move to configured Trash | Recoverable Trash-only action; never expunges. |
| `proton_prepare_draft` | Create a Bridge draft | New/reply/reply-all/forward; returns preview, content digest, draft reference, and ten-minute single-use token. |
| `proton_update_draft` | Replace a prepared draft | Creates a replacement, moves the prior draft to Trash, and returns a new digest and token. |
| `proton_discard_draft` | Discard one draft | Idempotently moves only an exact Drafts item to Trash and distinguishes `cleaned`, `already_absent`, and unresolved cleanup. |
| `proton_send_prepared` | Send once through Bridge SMTP | Consumes token, reloads and re-digests the exact MIME, makes one SMTP transaction, and requires exact Sent verification. Never retry `send_unknown`. |
| `proton_cleanup_downloads` | Remove expired managed files | Deletes only expired, tool-named entries in the private download directory. |

## Common limits

| Boundary | Limit |
| --- | ---: |
| Concurrent MCP operations | 8 |
| List page | 1–100 messages |
| Message cursor lifetime | 15 minutes |
| UID search window per page | 5,000 |
| Mutation batch | 1–20 messages |
| Combined To/CC/BCC recipients | 1–20, no duplicates |
| Search term | 2,048 UTF-8 bytes |
| Returned body page | 1–20,000 Unicode characters |
| Accepted draft body | 1,000,000 UTF-8 bytes |
| Raw message | 64 MiB |
| Header fetch | 256 KiB |
| MIME shape | 256 parts, 50 attachments |
| Decoded MIME content | 60 MiB total; 4 MiB body |
| Returned addresses | 100 per header field |
| Outgoing attachments | 10 files, 10 MiB each, 18 MiB total |
| Decoded incoming attachment | 50 MiB |
| Pending prepared sends | 64 |
| Prepared-send lifetime | 10 minutes |
| Managed download lifetime | 24 hours |

Search dates are RFC 3339 values. Bridge applies IMAP day granularity:
`date_from` is inclusive and `date_to` is exclusive.

## Draft inputs

- `mode=new` forbids `source_message_ref`.
- `reply`, `reply_all`, and `forward` require one exact source reference.
- Callers provide the exact recipients and body for every mode. Reply modes
  preserve the source Message-ID thread headers; forward mode does not add
  reply threading.
- Attachment paths must be absolute, existing regular files under configured
  roots. Symlinks and Mach-O executables are rejected. Scripts and archives
  produce preview warnings. Bytes are re-hashed when the MIME draft is built.

The returned `body_preview` is bounded to 500 characters for protocol economy.
`body_char_count` and `body_preview_truncated` make that boundary explicit; the
client must present the original full body with the exact recipients, subject,
attachments, and returned `confirmation_digest` before requesting explicit
approval. The token and digest bind that content even when the response preview
is truncated.

A successful send returns `status=sent` only after exact Message-ID evidence in
Sent. `draft_cleanup=cleaned` means this operation moved the source draft to
Trash. `already_absent` means the exact source draft was already gone or its
absence was verified after an ambiguous move result. `attention_required` is
reserved for an unresolved cleanup state and includes
`draft_cleanup_recovery`; follow that guidance without resending the verified
message.

`proton_discard_draft` uses the same cleanup states and is idempotent. Repeating
it after the exact draft is gone returns `already_absent` without another
mailbox mutation. Its additive `success` field remains `true` for `cleaned` and
`already_absent`, while `recovery_guidance` is populated only for
`attention_required`.

## Stable error categories

| Error code | Meaning / response |
| --- | --- |
| `not_configured` | Run `configure` or repair missing local material. |
| `bridge_unavailable` | Start Bridge or inspect its local state. For any interrupted non-idempotent operation, inspect the relevant folder before retrying. |
| `authentication_failed` | Re-run configure with the current Bridge password. |
| `tls_validation_failed` | The certificate is invalid or changed; explicitly re-enroll it with configure. |
| `permission_denied` | The requested account, mailbox, or local resource is not authorized. |
| `validation_failed` | Input violates the closed contract. |
| `resource_limit` | A bounded count/size/concurrency limit was exceeded. |
| `not_found` | The exact item did not become available. Avoid blindly repeating non-idempotent draft creation. |
| `stale_ref` | An opaque reference/cursor is stale, or a prepared-send token is unknown or already consumed. |
| `token_expired` | Prepare the draft again and review the newly returned preview and token. |
| `draft_changed` | The prepared draft changed after preview. Prepare it again and review the replacement before sending. |
| `draft_not_found` | The prepared draft no longer exists. Prepare a new draft and review it before sending. |
| `token_reference_mismatch` | Use the draft reference and token returned together by the same preview; the attempted token is consumed. |
| `conflict` | Re-read state; the message/draft changed, a postcondition failed, or a draft write outcome requires inspecting Drafts/Trash before retry. |
| `send_rejected` | Bridge definitively rejected submission. The token is consumed; correct the cause and prepare again. |
| `send_unknown` | A send may have occurred. Inspect Sent by exact content before any new attempt. |
| `internal` | A local invariant or subsystem stopped unexpectedly without authorization to retry a send. |

Mutation batches return a per-item outcome so a partial batch is never reported
as all-or-nothing. Sending is intentionally not idempotent and has no retry
loop.
