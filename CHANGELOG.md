# Changelog

## v0.0.43 — 2026-11-09

- Reject all static remote MCP headers; require host-vault references for every remote header.
- Update the sandboxes-go-sdk dependency to v0.0.22.

## v0.0.42 — 2026-11-08

- Redact malformed MCP `--header` and `--secret-header` values from CLI errors.
- Harden tag-triggered release publishing and fix checksum manifest paths in release assets.
- Restrict the installer verification bypass to explicit local-file installs.
- Fail closed if macOS signing, signature verification, or quarantine removal fails.
- Validate installer release-version input before invoking download tools.
- Add `rsbx mcp add --secret-header` so MCP credentials cross RPC only as vault placeholders.
- Add the blue shark symbol mark to the TUI dashboard.
- Update the direct `tcell` dependency to v3.6.0.
- Update the selected `golang.org/x/sys` version from v0.49.0 to v0.50.0.
