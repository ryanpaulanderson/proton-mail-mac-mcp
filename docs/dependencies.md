# Dependency assessment

The package minimizes dependencies around external boundaries that are unsafe
or impractical to implement ad hoc: MCP framing/schema generation, async IMAP,
TLS, MIME, cryptography, Keychain, bounded async I/O, and CLI/config parsing.
`Cargo.lock` is committed for reproducibility.

## Direct dependency groups

| Area | Crates | Rationale |
| --- | --- | --- |
| MCP and schemas | `rmcp`, `schemars`, `serde`, `serde_json` | Typed MCP stdio framing, closed JSON contracts, and structured output. |
| Bridge protocol | `async-imap`, `native-tls`, `tokio-native-tls`, `tokio`, `futures` | Async IMAP with platform TLS, explicit timeouts, and bounded streams. |
| Mail format | `mail-parser`, `mail-builder`, `email_address`, `chrono` | Standards-aware MIME/header/address/date handling instead of custom parsers. |
| Cryptography | `chacha20poly1305`, `sha2`, `getrandom`, `base64`, `zeroize` | Authenticated opaque references, digests, CSPRNG, encoding, and secret cleanup. |
| macOS secrets | `security-framework`, `security-framework-sys` | Native Keychain access without shelling out or putting secrets in arguments. |
| Files and config | `directories`, `tempfile`, `toml`, `infer`, `unicode-normalization` | Platform paths, atomic writes, strict config, bounded type inference, normalization. |
| Process and diagnostics | `clap`, `rpassword`, `tracing`, `tracing-subscriber`, `thiserror`, `async-trait` | Validated CLI, hidden password prompt, redacted diagnostics, typed boundaries. |

Direct dependencies declare permissive MIT, Apache-2.0, or compatible dual
licenses. The project itself uses MIT. Transitive license and source changes
must still be reviewed with each lockfile update; this document is not a
substitute for the license texts shipped by dependencies.

## Risk controls

- Rust 1.88 and exact dependency resolution are exercised on macOS CI.
- `unsafe_code` is forbidden in this package. Platform and cryptographic crates
  may contain audited unsafe internals; their APIs are isolated in adapters.
- TLS uses native certificate and hostname validation with built-in roots
  disabled for the Bridge connection, followed by an explicit SHA-256 peer pin.
- MIME and IMAP libraries receive hard byte, count, stream, and time bounds
  before application data is returned.
- No dependency may write MCP diagnostics to stdout. Application tracing is
  restricted to this crate and emitted to stderr.
- Dependabot evaluates Cargo and GitHub Actions nightly. Patch updates are not
  auto-merged because security-sensitive behavior requires human review.
- GitHub Actions are pinned by full commit SHA. Cargo changes preserve the
  committed lockfile and must pass formatting, Clippy, tests, and AppleScript
  compilation.

## Update review checklist

1. Read upstream release and security notes and confirm maintenance activity.
2. Inspect direct and newly introduced transitive licenses.
3. Review changes in unsafe/native/TLS/IMAP/MIME/crypto transitive surfaces.
4. Confirm MSRV remains Rust 1.88 and regenerate `Cargo.lock` intentionally.
5. Run all repository checks and relevant malformed-input tests.
6. For `rmcp`, re-check generated schemas and tool annotations. For Proton UI
   or protocol dependencies, repeat the compatibility procedure.
