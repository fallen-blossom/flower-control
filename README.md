# Flower Control

[简体中文](README.zh-CN.md)

**Windows 11 x64 · 0.1.0 release preparation**

Flower Control gives Codex local tools for websites and Windows applications. Describe the task in chat; Flower binds the selected target, checks local permissions, performs the action and reads back the result.

| Channel | Use it for |
| --- | --- |
| Web | Page elements, forms, tabs and transfers in managed Brave, Edge or Chrome profiles |
| App | Accessible Windows controls, menus, lists and dialogs |
| Computer | Pointer/keyboard input, canvas work and dragging inside a selected window |

## Install

**0.1.0 Setup and its release assets are not published yet.** The existing preview.3 download is a source snapshot. Check [official Releases](https://github.com/fallen-blossom/flower-control/releases) for availability; do not treat an old source ZIP as an installer.

Once 0.1.0 is published:

1. Download `FlowerControl-Setup.exe` and `SHA256SUMS.txt` from its Release. Compare the executable with `Get-FileHash -Algorithm SHA256`.
2. Run Setup under your everyday Windows account. A new installation can use a new dedicated root such as `D:\FlowerControl`; Program, Data, Cache and Packages stay beneath it. Windows registration, temporary extraction and host caches can still use the system drive.
3. Review the plan and approve Windows UAC yourself. Setup includes Python and .NET; ordinary users need no compiler. Codex and a supported browser must already be installed.
4. In Codex, install/enable the generated local plugin and confirm the requested Hook trust. Setup registration, chat loading and successful control are separate results.

The release will be unsigned. Windows may show an unknown publisher; compare the official asset SHA and matching source/build inputs before deciding to run it. Flower does not add a trust root or ask you to disable Windows protection.

See [the installer guide](docs/INSTALLER.md) for the full path, [Codex setup prompts](docs/INSTALL_WITH_CODEX.md) for assistance, or [source development](docs/INSTALL.md) to build it yourself.

## First use

1. Open the flower tray icon → **Settings / 设置**. A new installation defaults to **02 Ordinary control**; updates retain the existing tier. Tier buttons apply immediately; ordinary list edits require **Ctrl+S**.
2. Open a new Codex chat and a separate blank Notepad document. Ask:

> Check Flower's Web, App and Computer status. List Notepad windows so I can identify my new blank document. Bind that document, type “Flower test passed” and read it back. Do not save or close it. Finish control afterwards, releasing input and preserving the text.

3. Try a public page:

> Open https://example.com in a temporary Flower browser, read its title, then close only this temporary session.

Continue with [usage](docs/USAGE.md), [permissions](docs/PERMISSIONS.md), then [browser profiles](docs/BROWSER_PROFILES.md). Start with ordinary windows; 03 permits administrator windows, and 04 additionally permits listed administrator launches. UAC secure desktop and cross-user elevation remain outside the supported control path.

## Stop and maintenance

- **Ctrl+Alt+Shift+9** or the tray/settings emergency button blocks new writes across all Flower channels until explicit local resume. Hotkey registration failures are shown; the buttons remain available.
- **Ctrl+Alt+9**, HUD Stop and Computer pause affect Computer input. App/Web retain their independent permissions.
- After Stop or an uncertain result, observe the target again before further action. Unknown actions are not replayed automatically.

Use Setup/maintenance for updates; keep the registered root and original recovery materials. Settings offers ordinary-preference backup/draft import, redacted diagnostics and storage review. Windows **Settings → Apps → Flower Control → Uninstall** reviews the exact scope and retains personal data, cache and protected recovery state by default. Data/Cache recycling requires a separate review and confirmation after a completed uninstall. See [maintenance and uninstall](docs/INSTALLER.md).

## Privacy, validation and license

Flower adds no telemetry, crash uploads, remote configuration or automatic updates. Personal browser profiles need explicit per-chat permission; everyday browser cookies are not imported. Optional decision services remain off until locally enabled. Enter keys in Settings, not in chat.

[Validation](docs/VALIDATION.md) separates source/isolated checks and encoder tests from final-installer acceptance. Final 0.1.0 installation, real High control, host trust/loading, update recovery and uninstall are still unverified. [Release notes](docs/RELEASE_NOTES.md) describe this version; historical preview results retain their original scope.

Use [troubleshooting](docs/TROUBLESHOOTING.md) for ordinary problems and [private vulnerability reporting](https://github.com/fallen-blossom/flower-control/security/advisories/new) for security flaws. Keep credentials, profiles and private screenshots out of public reports.

Flower code uses the [MIT License](LICENSE). Dependencies retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md) and the [dependency inventory](dependency-inventory.json). The minimal FFmpeg recording encoder has matching source materials and notices; its GPL license does not become MIT.
