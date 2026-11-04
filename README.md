# Flower Control

[简体中文](README.zh-CN.md)

**Windows 11 x64 source preview · 0.1.0-preview.3**

Flower Control gives Codex three local MCP channels for operating Windows and the web:

| Channel | What it does | Good for |
| --- | --- | --- |
| **Web** | Reads page structure and acts on page elements | Forms, search, web editors, uploads/downloads, temporary browsers |
| **App** | Reads controls exposed by Windows applications | Buttons, fields, lists, menus, settings pages, dialogs |
| **Computer** | Captures one selected window and sends pointer/keyboard input | Canvas, drag and drop, shortcuts, interfaces with weak accessibility |

Codex plans the task. Flower handles local target binding, permission checks, input release, and result readback. You do not have to call every tool by hand; describe the task in normal language.

## Read these first

1. [Install](docs/INSTALL.md): Windows 11, Codex desktop, CPython 3.14, .NET 10 SDK, and Visual Studio C++ Build Tools.
2. [Permissions and settings](docs/PERMISSIONS.md): the four tiers are **01 fully stopped**, **02 ordinary control**, **03 administrator windows**, and **04 administrator execution**.
3. [Usage](docs/USAGE.md): Web, App, Computer, target selection, pause, Stop, and common recovery paths.

This is a **source preview**. The repository contains source and a reproducible local build; it does not contain a signed executable and does not auto-update. A GitHub Release is a version page with source archives and checksums, not an installer and not a portable helper.

## What is included

- Managed Brave, Edge, and Chrome profiles for Web, with temporary, AI, and personal login profiles.
- App control through Windows UI Automation, including buttons, fields, lists, menus, screenshots, and short recordings.
- Computer control through a selected-window screenshot, pointer/keyboard input, drag, scroll, keys, and bounded short sequences.
- Tray settings, permission tiers, deny lists, privacy masks, Stop, and Computer pause/resume.
- A local Codex plugin integration. Source adapters for DSH, Claude, and local clients are retained, but are not the primary acceptance path for this preview.

## Permission tiers

| Tier | Name | Ordinary windows | Administrator windows | Administrator launch | Notes |
| --- | --- | --- | --- | --- | --- |
| 01 | Fully stopped | No | No | No | Stops all three channels; tray and Stop remain available |
| 02 | Ordinary control | Yes | No | No | Everyday windows without administrator permission |
| 03 | Administrator windows | Yes | Yes | No | Read/control elevated windows, but do not start an elevated process |
| 04 | Administrator execution | Yes | Yes | Yes, through the local list | Starts administrator programs through the local list; UAC secure desktop and the legacy system takeover are frozen |

Permissions are local settings. The chat agent cannot write the protected permission file. Deny lists win over allow lists. Every target, launch, and action is checked again against the current tier and Stop state.

## First trial

After installation and Hook trust, open a new Codex chat and start with a harmless target:

> Check the Web, App, and Computer status and origin probes. Confirm that the loaded source and helper match the files on disk.

> Use Flower App on the Notepad window I select, append one line, and read it back without saving to a new path.

> Open a public page in a temporary Flower browser, read its title, then close the temporary session.

Use a test window or a public page first. Do not give the agent passwords, verification codes, payment information, or private browser profiles.

## Browser profiles and privacy

Temporary browsers are disposable. The AI profile is an independent profile for ordinary agent work. The personal profile, Luohua, requires an explicit per-chat grant and a separate grant for each browser. Flower does not import your everyday browser cookies. See [browser profiles](docs/BROWSER_PROFILES.md).

## Stop, pause, and recovery

- **Ctrl+Alt+9** ends the current Computer input and releases held keys. It does not change the saved tier or create a global all-writes Stop.
- **HUD Stop** stops the current Computer cycle.
- **Tray Stop Computer Use** ends the current computer operation; App/Web do not inherit a new permission from that Stop.
- **Computer pause** stops Computer mouse/keyboard input while App/Web can continue.
- **Resume** requires a fresh observation. Never replay an uncertain action automatically.

## Privacy and security

Flower does not add telemetry, crash uploads, remote configuration, or automatic updates. Browsing reaches the sites you request; Codex still uses its configured model service. Jev, Perplexity, and compatible decision providers are optional external services and only run after local enablement. Keys enter locally in Settings, never through chat or command-line arguments.

The administrator helper runs under the current Windows account. It does not disable Defender, the firewall, or UAC.

## Current limits

- Web is not arbitrary browser automation; it uses supported Chromium-family browsers and managed profiles.
- Computer is not desktop-wide control; it operates the bound window.
- UAC secure desktop, password entry, cross-user elevation, silent updates, and indefinite key holds are outside this preview's promise.
- Permission and source changes are rechecked before later work; uncertain actions are not replayed automatically.

## Release status

The B46-r6 line has an installation, a local Codex publication, and three-channel load evidence on the development machine. The source archive records a per-file SHA-256 manifest. A clean-PC one-click installation, every website, every third-party app, and every administrator scenario are not implied by that record. For an issue, include the version, status, error code, and a minimal reproduction; see [troubleshooting](docs/TROUBLESHOOTING.md).

## License

Flower's own code is under the [MIT License](LICENSE). MCP, Playwright, FlaUI, Pillow, and other dependencies retain their licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and [dependency inventory](dependency-inventory.json).
