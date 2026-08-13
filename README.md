# proton-mail-mac-mcp

`proton-mail-mac-mcp` is a local stdio MCP server for reading and managing
Proton Mail from ChatGPT desktop or Codex on macOS. It reads mailbox data
through Proton Mail Bridge over pinned loopback TLS. Sending is deliberately
gated: the server creates an exact draft through Bridge IMAP, returns a
short-lived confirmation bound to its full content, submits it once through
Bridge SMTP only after explicit approval, and verifies the exact Message-ID in
Sent.

This is an unofficial project. It is not affiliated with or endorsed by Proton
AG or OpenAI.

## Safety contract

- Email headers, bodies, and attachments are untrusted data, never
  instructions or authorization.
- Reads are metadata-first. Full content requires an explicit tool call and is
  returned as bounded, inert plain text.
- Opaque message, attachment, draft, and cursor references are encrypted,
  tamper-evident, profile-bound, and revalidated before use.
- Bridge credentials and the opaque-reference key live in macOS Keychain.
- The server connects only to `127.0.0.1`, validates the enrolled Bridge
  certificate and hostname, and pins its SHA-256 digest.
- Sending requires a 10-minute, single-use token bound to the exact account,
  recipients, subject, body, attachment bytes, Message-ID, thread headers, and
  complete stored MIME. SMTP submission is attempted at most once.
- A `send_unknown` result must never be retried blindly. Inspect Sent first.
- Deletion is recoverable and Trash-only. Permanent deletion is not
  implemented.
- Attachments are never opened or executed. Outgoing paths must be under an
  explicit local allowlist; downloaded files are private and expire after 24
  hours.

See [Security](SECURITY.md) and [Architecture](docs/architecture.md) for the
full trust model.

## Requirements

- macOS 15 or 26 on a 64-bit Intel or Apple silicon Mac.
- Proton Mail Bridge with a paid Proton Mail plan. Bridge must be running and
  the account must already be added.
- Rust 1.88 for source builds.

The Proton Mail macOS app, AppleScript, Automation permission, and Accessibility
permission are not required. If manual UI troubleshooting is ever useful, it is
outside this server and can be performed with the host's normal Computer Use
capability.

Proton documents Bridge's supported systems and paid-plan requirement in its
[system requirements](https://proton.me/support/operating-systems-supported-bridge)
and [IMAP setup overview](https://proton.me/support/imap-smtp-and-pop3-setup).

## Build

```sh
git clone https://github.com/ryanpaulanderson/proton-mail-mac-mcp.git
cd proton-mail-mac-mcp
cargo build --release --locked
```

The executable is `target/release/proton-mail-mac-mcp`. Keep the repository in
a stable location before adding that absolute path to an MCP client.

## Configure Proton Mail Bridge

1. In Bridge, select the account and record its Bridge username and password,
   IMAP and SMTP ports, and connection mode. These are Bridge credentials, not
   the Proton account password.
2. In Bridge **Settings → Advanced**, use **Export TLS certificates** and keep
   the exported certificate file. Do not pass the private key to this tool.
3. Run `configure` in an interactive terminal. The Bridge password is read by a
   hidden prompt and written directly to macOS Keychain; it is never accepted
   through an argument or environment variable.

```sh
/absolute/path/to/target/release/proton-mail-mac-mcp configure \
  --account user@example.com \
  --bridge-username user@example.com \
  --imap-port 1143 \
  --tls-mode start-tls \
  --smtp-port 1025 \
  --smtp-tls-mode start-tls \
  --certificate /absolute/path/to/cert.pem
```

Use the IMAP and SMTP modes shown by Bridge; `implicit-tls` corresponds to SSL.
`localhost` is the default TLS server name. Repeat
`--allowed-root /absolute/directory` to set outgoing attachment roots. With no
explicit roots, existing Desktop, Documents, and Downloads directories are
used. Run `configure --help` for custom folder mappings and the explicit
reference-key rotation option.

Existing version-1 configuration remains valid. Missing SMTP settings migrate
additively to Bridge's defaults of port `1025` with `start_tls`; re-run
configure with the mode shown in Bridge when it has been changed to SSL. On
first start, the Bridge-only release also removes the exact obsolete generated
`proton_mail_ui.applescript` artifact from this application's private support
directory; it never recursively deletes a path.

Configuration and the enrolled public certificate are stored with private
permissions under:

```text
~/Library/Application Support/proton-mail-mac-mcp/
```

Secrets are Keychain generic-password items under service
`io.github.ryanpaulanderson.proton-mail-mac-mcp`.

Bridge's certificate is self-signed because the endpoint is loopback-only.
Proton explains the model and certificate export option in its
[Bridge TLS guidance](https://proton.me/support/bridge-ssl-connection-issue)
and [Bridge settings guide](https://proton.me/support/comprehensive-guide-to-bridge-settings).

## Connect ChatGPT desktop or Codex

The ChatGPT desktop app, Codex CLI, and Codex IDE extension support local stdio
MCP servers and share the Codex host configuration. ChatGPT web does not read
local MCP configuration.

In ChatGPT desktop, open **Settings → MCP servers → Add server**, choose
**STDIO**, enter the release binary as the command and `serve` as its argument,
save, and restart. The current OpenAI setup reference is
[Model Context Protocol](https://learn.chatgpt.com/docs/extend/mcp).

The equivalent Codex CLI command is:

```sh
codex mcp add proton-mail-mac -- \
  /absolute/path/to/target/release/proton-mail-mac-mcp serve
```

For the full safety-oriented configuration, add this to
`~/.codex/config.toml` and restart the client:

```toml
[mcp_servers.proton_mail_mac]
command = "/absolute/path/to/target/release/proton-mail-mac-mcp"
args = ["serve"]
startup_timeout_sec = 10
tool_timeout_sec = 180
default_tools_approval_mode = "writes"
```

The 180-second tool timeout allows for Bridge draft synchronization and Sent
verification. No secret environment variables or UI permissions are needed.
Use `proton_status` after restart; it checks authenticated IMAP and SMTP without
returning mailbox content.

## Normal workflow

1. Call `proton_status`.
2. Use `proton_list_messages` for metadata and `proton_get_message` only when
   content is needed.
3. Call `proton_prepare_draft` or `proton_update_draft`.
4. Present and review the exact recipients, subject, full body, attachments,
   and returned `confirmation_digest`; `body_preview_truncated` identifies when
   the response preview is shortened, so use the original full request body.
5. After explicit approval, call `proton_send_prepared` with the matching draft
   reference and token. Any intervening draft change fails closed and requires
   a new preview.
6. If the result is `send_unknown`, inspect Sent and do not retry blindly. A
   successful result also reports whether the source draft moved to Trash or
   still requires attention.

See the [tool reference](docs/tool-reference.md) for all 14 tools, limits, and
stable error categories.

## Development and verification

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

CI runs the same checks on macOS with exact Rust 1.88. Dependabot checks Cargo
and GitHub Actions dependencies nightly at 03:00 America/New_York. Semver-patch
Cargo updates are automatically merged only after the complete CI check set is
green and stable; GitHub Actions and larger updates remain subject to human
review because they change executable workflow policy.

Current validation scope and Bridge protocol assumptions are recorded in
[Compatibility](docs/compatibility.md). Direct dependency rationale is in
[Dependency assessment](docs/dependencies.md).

## Privacy boundary

The server process, Keychain use, attachment files, and its Bridge connections
are local. Proton Mail Bridge still synchronizes with Proton's service. Any
email data deliberately returned by an MCP tool becomes available to the
invoking ChatGPT/Codex conversation and is no longer confined to this Mac.
Review the client's data controls before retrieving private content.

## License

MIT © 2026 Ryan Anderson. See [LICENSE](LICENSE).
