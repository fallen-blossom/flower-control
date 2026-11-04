# Flower Control 0.1.0

[简体中文](RELEASE_NOTES.zh-CN.md)

**Release preparation; Setup and its assets are not published yet.** Start with [installation](INSTALLER.md), then [first use](USAGE.md#first-use-after-installation).

## Changes in this version

- A complete offline Setup with Python and .NET runtime dependencies. A new installation uses one selected Program/Data/Cache/Packages root; existing installations retain their registered location and data.
- Local status/settings access, read-only integrity checks, redacted diagnostic export, ordinary-preference backup/draft import and storage review.
- Tier 02 for a new policy; existing tiers and Stop are preserved. Separate all-channel emergency Stop (**Ctrl+Alt+Shift+9**) and Computer-only Stop (**Ctrl+Alt+9**).
- Maintenance keeps the original plan and receipt for interrupted work. Uninstall reviews the exact scope and retains personal data and protected recovery state by default; Data/Cache recycling requires separate confirmation.
- A fixed minimal FFmpeg recording encoder, with matching FFmpeg/x264/zlib source archives, build recipes and original notices. It retains the local PNG/concat/pad/H.264/MP4 path and disables network protocols.

Web, App and Computer remain the three task channels. Codex is the main entry; additional host adapters keep their own documented scope. Optional external decision services require local enablement. Flower adds no telemetry or automatic updates.

## Verification and distribution

Source/isolated checks, Windows version-resource checks and short synthetic-frame encoder tests have passed. Final matching 0.1.0 installation, real High control, host trust/loading, update recovery and uninstall remain unverified. See [validation](VALIDATION.md) for the scope; no clean-PC or overall success-rate claim is made.

The release will be unsigned (`signed: false`). Use the official GitHub Release, its SHA-256s and matching source/build inputs to check file identity; these do not provide a trusted publisher signature. Windows UAC remains a manual decision. [Private vulnerability reporting](https://github.com/fallen-blossom/flower-control/security/advisories/new) is enabled.

## Earlier previews

[Preview.3 and its original assets](https://github.com/fallen-blossom/flower-control/releases/tag/v0.1.0-preview.3) remain unchanged. Their source-only installation instructions and historical test results belong to that snapshot, not to the 0.1.0 installer.
