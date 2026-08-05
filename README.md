# proton-mail-mac-mcp

A planned local MCP server for reading and managing Proton Mail through Proton Mail Bridge and controlling visible send operations in the Proton Mail macOS application with AppleScript.

> [!IMPORTANT]
> This repository is currently a bootstrap scaffold. It cannot access or send email yet.

## Planned design

- Rust stdio MCP server for ChatGPT desktop and Codex.
- Local TLS/IMAP access through Proton Mail Bridge.
- AppleScript and macOS Accessibility for native compose, reply, forward, and confirmed send operations.
- Metadata-first reads, Keychain-backed secrets, recoverable Trash-only deletion, and explicit attachment handling.
- Two-step sending with a separate native macOS confirmation dialog.

## Development

The repository pins Rust 1.88. Run the bootstrap checks with:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

## Privacy boundary

Mailbox access and UI automation are planned to run locally. Email content deliberately returned by an MCP tool can still become part of the ChatGPT or Codex conversation and should not be treated as remaining exclusively on the Mac.

## Project status and affiliation

This is an unofficial project and is not affiliated with or endorsed by Proton AG or OpenAI.

## License

MIT © 2026 Ryan Anderson. See [LICENSE](LICENSE).
