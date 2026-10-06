# Flower Control 0.1.0 preview

[简体中文](RELEASE_NOTES.zh-CN.md)

Flower Control gives Codex tools to operate websites and Windows apps. Ask it to fill a form, use a menu, edit a page, upload a file, or drag an object on a canvas.

- **Web** reads and operates webpage elements through Playwright. This preview supports Brave; other browsers are planned.
- **App** reads and operates accessible Windows controls through FlaUI, including fields, lists, menus, and dialogs.
- **Computer** takes screenshots of a selected window and sends mouse and keyboard input for canvases, dragging, shortcuts, and interfaces without useful accessible controls.

Control state stays on your machine. Flower adds no usage telemetry, crash uploads, remote configuration, or automatic updates. Your agent's model service and normal website traffic still apply. Optional Jev receives short goals and candidate labels to select a target; Flower can execute that choice in the same tool call. Jev is off on a new installation.

Press **Ctrl+Alt+9** to stop writes. Computer shows a moving border, elapsed time, and a Stop button. After stopping, the agent observes the target again before continuing. Mechanical steps can run in batches.

Temporary browsers start separately. The AI profile retains its own logins; the personal profile needs permission once per chat. Log in inside the chosen Flower profile to use a saved account through Web. Logins are not copied from your everyday browser.

This is an **MIT-licensed Windows source preview**. It includes English and Chinese installation, login, privacy, and validation guides. You build and prepare the administrator helper for your own Windows account and source directory. No ready-to-run binary installer is included; Codex itself can run without administrator privileges. The helper tray menu is currently Chinese.

Source adapters for native Windows Claude Code and the Antigravity IDE are included but have **not been built or tested**. Antigravity uses connection scope, has no per-chat isolation, and omits personal-profile tools. Standalone Antigravity CLI, SDK, and cloud use are outside this preview.

The recorded Codex tests include spreadsheets, documents, drawing, web editing, file transfer, desktop lists and dialogs, stop/resume, and Jev in all three channels. They apply to the earlier installed Codex baseline, before the host-adapter changes. A document-color task missed the required shades. Clean-PC first installation and the later shared-code changes still need verification. No general success-rate or leaderboard claim is made.

Download `flower-control-0.1.0-preview.1-source.zip` and check it against `SHA256SUMS.txt`. Start with [installation](INSTALL.md), then [browser profiles and login](BROWSER_PROFILES.md). See [validation](VALIDATION.md) for test details and [privacy](../PRIVACY.md) for data boundaries.

Report reproducible problems in [GitHub issues](https://github.com/fallen-blossom/flower-control/issues). Keep credentials, browser profiles, and private screenshots out of attachments.
