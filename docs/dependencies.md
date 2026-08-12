# Dependency assessment

The package minimizes dependencies around external boundaries that are unsafe
or impractical to implement ad hoc: MCP framing/schema generation, async IMAP,
TLS, MIME, cryptography, Keychain, bounded async I/O, and CLI/config parsing.
`Cargo.lock` is committed for reproducibility.

## Direct dependency groups

| Area | Crates | Rationale |
| --- | --- | --- |
| MCP and schemas | `rmcp`, `schemars`, `serde`, `serde_json` | Typed MCP stdio framing, closed JSON contracts, and structured output. |
| Bridge protocol | `async-imap`, `native-tls`, `tokio-native-tls`, `tokio`, `futures` | Async IMAP, bounded SMTP I/O, platform TLS, and explicit timeouts. SMTP's small sequential protocol surface is implemented locally to preserve exact post-DATA uncertainty semantics without adding another dependency. |
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
- SMTP replies, lines, capabilities, commands, header bytes, and DATA writes
  are bounded. Protocol transcripts and AUTH material are never logged.
- No dependency may write MCP diagnostics to stdout. Application tracing is
  restricted to this crate and emitted to stderr.
- Dependabot evaluates Cargo and GitHub Actions nightly. Semver-patch updates
  may be auto-merged by `.github/workflows/dependabot-auto-merge.yml` only when
  the update is created by `dependabot[bot]`, the complete reported check set is
  green and stable, and the repository's `CI / Quality and tests` check passes.
  Minor, major, non-semver, failed, ambiguous, and stale updates remain for
  human review.
- GitHub Actions are pinned by full commit SHA. Cargo changes preserve the
  committed lockfile and must pass formatting, Clippy, and tests.

The auto-merge workflow runs on `pull_request_target` so it can inspect trusted
repository checks and merge metadata without checking out or executing the
Dependabot branch. Its write-capable job is gated by the bot identity, exact
repository, patch-only metadata, stable checks, and the pull request head SHA.

## Update review checklist

1. For updates not covered by the patch auto-merge policy, read upstream
   release and security notes and confirm maintenance activity.
2. Inspect direct and newly introduced transitive licenses.
3. Review changes in unsafe/native/TLS/IMAP/MIME/crypto transitive surfaces.
4. Confirm MSRV remains Rust 1.88 and regenerate `Cargo.lock` intentionally.
5. Run all repository checks and relevant malformed-input tests.
6. For `rmcp`, re-check generated schemas and tool annotations. For Bridge
   protocol dependencies, repeat the compatibility procedure.
