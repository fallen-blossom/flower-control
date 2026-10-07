# Changelog

## Unreleased — restored Computer frame reliability, next-step display, and Chromium-family Web

- The moving Computer frame no longer disappears when another topmost window covers it or when the scoped app opens a visible top-level panel without an owner. The frame layer keeps a periodic read-only z-order probe, re-raises itself when covered, and keeps the frame for a same-process visible top-level window while still excluding Flower's own overlays.
- The optional per-call `next_step` display text (1-48 characters, shown as the 下一步 line on the Computer HUD) was restored on `observe`, `activate`, and `input`. It is display text only and grants no authority; an empty value keeps the previous signature.
- Web request validation now accepts the Chromium-family executables Brave, Chrome, and Edge. Brave remains the only configuration with real foreground verification; Chrome and Edge are **pending verification**.

No new dependency, telemetry, remote service, or automatic update was added.

## Unreleased — optional local connection mode

Adds a shared stdio connection entry and recipient-local configurations for Cursor, VS Code, native OpenCode v1/v2, and Antigravity. Original Codex chat hooks remain the default. An optional Flower Control Compatibility plugin can coexist with the original in local Codex. It shares one administrator helper, has distinct MCP names, and has no chat isolation, private browser access, or cross-channel handoff. No telemetry, remote service, or dependency was added.

The shared implementation has protocol and native build checks. Individual client tasks and Dot cloud-dispatched local tool loading remain untested. The existing preview release archive is an earlier snapshot; use current main for these source changes.

## 0.1.0-preview.1 — 2026-10-06

Three local MCP channels for Brave Web, desktop accessibility, and Windows computer input. Dedicated temporary, AI, and personal browser environments; direct batches for mechanical work; optional Jev target selection. A current-user administrator helper provides the shared input path, tray controls, and Ctrl+Alt+9 stop.

The release preparation includes fixes for the Computer border during an owned dialog, the public arguments for region selection, and reopening a cleanly closed AI profile after a normal Brave update. Installed-source checks and focused real tasks have been completed on the development machine.

This is a source preview under the MIT license, with English and Chinese installation, browser-login, privacy, and validation guides. Source adapters for native Windows Claude Code and the Antigravity IDE are included; neither has been built, tested, or installed. Antigravity uses connection scope and omits personal-browser access.

The recorded Codex acceptance applies to the earlier installed baseline. The later host-adapter changes and a complete first installation on a clean PC remain untested. This preview is distributed on GitHub and is not listed in the official OpenAI plugin directory.
