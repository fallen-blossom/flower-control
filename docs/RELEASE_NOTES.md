# Flower Control 0.1.0-preview.3

[简体中文](RELEASE_NOTES.zh-CN.md)

**Windows 11 x64 source preview. Not a signed one-click installer.**

This release makes the B46-r6 source line available as a complete public repository and source archive. It includes the local Codex plugin generator, administrator-helper build/install tools, three MCP channels, documentation, tests, licenses, and a per-file source manifest.

## Highlights

- **Four selectable permission tiers:** 01 fully stopped, 02 ordinary control, 03 administrator windows, 04 administrator execution.
- **A clear 03/04 boundary:** 03 can operate an already-open elevated window; 04 can additionally start an exact program through local policy. UAC secure desktop automation and the legacy system-takeover path are frozen.
- **Three channels:** Web for managed Chromium-family pages, App for Windows accessibility controls, Computer for selected-window capture and input.
- **Local settings:** deny lists, administrator-window rules, administrator launch records, privacy masks, Stop, and Computer pause.
- **Recovery-safe input:** Ctrl+Alt+9, HUD Stop, tray Stop, re-observation before resume, and no automatic replay of uncertain input.
- **Rewritten documentation:** separate installation, permission, usage, troubleshooting, and browser-profile guides in English and Simplified Chinese.

## Install from source

Start with [installation](INSTALL.md), then [permissions](PERMISSIONS.md) and [usage](USAGE.md).

The release archive is source code plus checksums. You build the native helper and Python environment locally, approve the generated helper installation through UAC, add the local Codex marketplace, and trust the generated Hook before use.

## Validation boundary

The development machine has an installed helper, a local Codex plugin publication, and three-channel load evidence. This release records source/export consistency and the checked build/install tooling. It does not claim:

- a completed clean-PC or second-account first install;
- universal website or third-party application support;
- UAC secure-desktop automation;
- signed binaries or silent updates;
- a general success rate.

A successful status probe or one harmless target test is not proof that every later target and action is safe.

## Files

- `flower-control-0.1.0-preview.3-source.zip`: full public source tree.
- `SHA256SUMS.txt`: checksum for the source archive.

Use the checksum before extracting or building. Do not download an unverified helper binary from an issue or mirror.
