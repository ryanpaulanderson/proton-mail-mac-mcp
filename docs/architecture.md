# Architecture

The planned local-only data path is:

1. ChatGPT desktop or Codex starts this project as a stdio MCP server.
2. Rust reads and manages mailbox state through Proton Mail Bridge over loopback TLS/IMAP.
3. Static AppleScript adapters use macOS Accessibility for visible compose, reply, forward, and send operations in Proton Mail.
4. macOS Keychain holds credentials and local cryptographic keys.

This checkpoint contains repository infrastructure only. Mail access and UI automation are not implemented yet.
