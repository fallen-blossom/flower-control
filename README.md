# Flower Control

[简体中文](README.zh-CN.md)

[Download the source preview](https://github.com/fallen-blossom/flower-control/releases/tag/v0.1.0-preview.1) · [Install](docs/INSTALL.md) · [Browser login](docs/BROWSER_PROFILES.md)

Give Codex tools to operate websites and Windows apps: fill forms, read documents, use menus, upload files, click, type, and drag.

Install Flower as a Codex plugin, then tell Codex what you want done and which window or browser environment to use. It adds three tool channels: **Web for webpage elements, App for desktop controls, and Computer for actions based on screenshots**.

![Flower icon](assets/branding/flower-petal/flower-petal-256.png)

## What it does

| Channel | How it operates | Useful for |
| --- | --- | --- |
| **Web** | Reads page text, links, buttons, and form fields, then acts on those elements through Playwright | Research, web forms, online code editors, tabs, uploads, and downloads |
| **App** | Reads the controls a Windows app exposes, including names, values, lists, and menus, then operates them through FlaUI / Windows UI Automation | Desktop forms, settings, long lists, menus, and dialogs belonging to the selected app |
| **Computer** | Takes a screenshot of the selected window and sends mouse and keyboard input at the chosen position | Drawing, dragging, canvases, shortcuts, and interfaces with few readable controls |

For example, Web can read a page and fill its form without locating every field by screenshot. App can select an item in a desktop list or change a checkbox by its name. Computer can drag an object on a canvas or use an existing browser window you select. An app must expose its controls for App to read them; Computer provides a way to operate the visible interface when it does not.

Codex can combine the channels in one task, such as editing a webpage through Web and operating a related desktop dialog through App. The model plans the task; Flower supplies the local controls and checks the selected target and action state.

## Control and optional Jev

Known mechanical steps can run in a batch, reducing separate model/tool round trips. **Jev is an optional target selector**: it receives a short goal and a few candidate labels, chooses a target, and Flower can execute that choice within the same tool call. It is disabled on a new installation and is not required to use any of the three channels.

Press **Ctrl+Alt+9** to stop writes. Computer control shows a moving border, an elapsed-time label, and a Stop button. Resuming requires a fresh look at the target; an interrupted action is not silently repeated.

## Start here

Source adapters are included for [native Windows Claude Code](docs/CLAUDE_CODE.md) and [Antigravity](docs/ANTIGRAVITY.md), with a [shared local entry and configuration generator](docs/LOCAL_CLIENTS.md) for native Cursor, VS Code, and OpenCode. The shared entry has protocol checks and a helper build; individual clients have not completed real task acceptance or installation. Connection mode excludes private profiles and same-target cross-channel handoff. The Codex runtime evidence below does not validate these clients.

This is a **Windows source preview**. Start with [installation](docs/INSTALL.md), then read [browser profiles and login](docs/BROWSER_PROFILES.md). The setup uses a current Codex desktop installation, Windows 11 x64, CPython 3.14 x64, and .NET 10 SDK. The Web channel also needs Brave at its standard system installation path. Windows 10 and other hosts have not received the same acceptance coverage.

Installation prepares a package for **your Windows account and your source directory**. It is not a portable copy of the developer's administrator helper. Keep the source directory, Python runtime, and virtual environment in place after installation.

You can ask Codex in ordinary language; you do not need to name every tool call. For an initial trial, use a test window or a public page:

> Use Flower App to fill the fields in the window I select. Save and verify the result.

> Open this public page in a temporary Flower browser, find the information I asked for, and close the session when finished.

> Use Flower Computer to drag the orange object into the blue area in the window I select.

## Profiles and privacy

Temporary browsers start separately. The AI profile keeps its own logins and is available for normal agent work. The personal profile, named Luohua in the tool API, needs your permission once per chat. None of these profiles imports cookies from your everyday browser. To use a saved login through Web, log in once in the chosen Flower profile; the [login guide](docs/BROWSER_PROFILES.md) walks through the handoff.

Flower has **no usage telemetry, crash uploads, remote configuration, or automatic updates**. Its control state and browser data are stored locally. Codex still uses its configured model service, and browsing reaches the websites you request. Jev is an optional external AI service, disabled on a new installation; it receives approved short target labels and goals, not raw screenshots or a full page tree. See [privacy](PRIVACY.md) for the exact boundary.

## Browser compatibility

The **Web channel currently supports Brave only**. This is a preview release; support for other browsers is planned for later versions.

**App and Computer are general Windows window tools.** You can select a window from another browser and operate its visible interface through Computer. App can use whatever accessible controls that browser exposes. This does not create a managed Web session or import that browser's cookies into Flower.

## Current limits and testing

Login may expire normally. UAC secure-desktop prompts need a person. Custom input methods with English candidate windows need further adaptation. The helper's current tray menu is Chinese; the tool descriptions and this documentation are available in English.

Practical tests cover spreadsheets, documents, drawing, browser editing and file transfer, desktop lists and dialogs, stop/resume, and Jev in all three channels. One document-color task missed the required color precision. These results support the workflows tested; they are not a 95% success claim or a published OSWorld score. Read [validation](docs/VALIDATION.md).

## License and dependencies

Flower's own code is available under the [MIT license](LICENSE). MCP, Playwright, FlaUI, Pillow, and the other pinned dependencies keep their own licenses and are credited in [third-party notices](THIRD_PARTY_NOTICES.md).

For fixes, see [contributing](CONTRIBUTING.md). For a security issue, see [security](SECURITY.md).
