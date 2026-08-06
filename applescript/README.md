# Proton Mail Accessibility adapter

`proton_mail_ui.applescript` is the reviewed source for the macOS UI boundary.
Rust passes a versioned JSON request over standard input; private message data is
never placed in executable source, arguments, environment variables, the
clipboard, or shell commands. The script returns a small JSON result containing
only capability facts and stable result codes.

The selector contract was checked non-destructively against Proton Mail 1.13.3
(web application 5.0.125.9) on macOS. It relies on semantic Accessibility roles,
labels, enabled state, and the Proton internal draft identifier present in the
active `AXURL`. It contains no coordinates, menu positions, raw keystrokes, or
localization-dependent send success message.

The script never creates message content. Bridge writes the exact MIME draft;
the script opens that draft, verifies the visible composer, asks for native
confirmation, performs one `AXPress` on the enabled Send button, and waits for
the composer to close. Rust then verifies the Message-ID in Sent through Bridge.

Compile-check the source without writing generated artifacts to the repository:

```sh
osacompile -o "${TMPDIR}/proton_mail_ui.scpt" applescript/proton_mail_ui.applescript
```
