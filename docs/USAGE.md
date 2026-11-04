# Using Flower Control

[简体中文](USAGE.zh-CN.md)

You can describe the task normally. Codex chooses a Flower channel, binds a local target, performs the action, and reads the result back. You do not have to call individual MCP tools by hand.

## Choose the right channel

| Channel | Best first choice | Avoid using it for |
| --- | --- | --- |
| **Web** | Forms, page navigation, text fields, links, tabs, uploads/downloads, managed login profiles | A page that needs a profile you have not set up, or a browser that Flower does not manage |
| **App** | Buttons, menus, lists, fields, dialogs, settings pages with Windows accessibility | Canvas-only interfaces or applications that expose no useful controls |
| **Computer** | A selected window's visual layout, drag and drop, shortcuts, canvas or image controls | Whole-desktop control, password/UAC secure desktop, or an unbounded shortcut sequence |

Start with Web or App when the target exposes structure. Use Computer only for the part that truly needs pointer or keyboard input.

## Select a target

### Web

Flower uses its own managed Chromium-family profiles. It does not copy cookies from your everyday browser.

- **Temporary**: for public pages and one-off work. The session is disposable.
- **AI**: a persistent agent profile for ordinary logged-in work.
- **Luohua / personal**: a separate personal profile. It needs an explicit grant in the current chat, and each browser is granted separately.

For a new login, open the Flower profile window, log in yourself, close that login window normally, and then let Codex continue. Do not use Computer to automate password entry.

### App

Name the window or app and choose an accessible control when possible. Flower binds the target window and checks its identity. A title alone is not permanent identity; if the window restarts or its process changes, select it again.

### Computer

Select one target window first. The screenshot and input are scoped to that window, not the entire desktop. The frame, elapsed time, and Stop button show that a bounded Computer cycle is active.

## First requests to try

Read-only status:

> Check the Flower Web, App, and Computer status. Compare the loaded source with the on-disk source and show the effective Stop and pause state. Do not operate a target.

Web, disposable page:

> Open a public page in a temporary Flower browser, read the title and visible heading, and close the temporary session.

App, disposable window:

> Use Flower App on the Notepad window I select. Read the title and one control. Do not save a file.

Computer, bounded test:

> Use Flower Computer on the Calculator window I select. Click one visible digit and read the result. Stop after that single action.

Do not start with passwords, verification codes, payments, private profiles, or important unsaved work.

## Permissions, target checks, and Stop

Before a real action, Flower checks the current tier, target identity, deny list, origin/source state, and Stop or pause state. These checks happen again for later actions; one successful click is not a permanent grant.

| Control | Effect |
| --- | --- |
| **01 fully stopped** | Web, App, and Computer stop dispatching. Tray and settings remain available. |
| **Ctrl+Alt+9** | Ends the current Computer input and releases held keys; it does not change the saved tier or create a global Stop. |
| **HUD Stop** | Ends the current Computer cycle and releases held input. |
| **Tray Stop Computer Use** | Ends the current Computer operation; App and Web do not inherit a new grant from that Stop. |
| **Computer pause** | Blocks new Computer input while App and Web may continue. |
| **Resume** | Restores the current generation only after a fresh check; it never replays the previous action. |

If the target changed, the window closed, the source probe failed, the helper disconnected, or the result is unknown, stop and observe again. Do not ask the agent to “just retry” a destructive or uncertain input.

## Administrator windows and launch

- Use 03 when the administrator window is already open and you need to inspect or operate it.
- Use 04 only after the local launch list or work authorization has been configured for the exact program.
- A launcher, child process, associated app, or changed executable does not inherit an earlier approval.
- UAC secure desktop, password entry, and the legacy system-takeover path are frozen in this preview.

Approval of a specific task does not become a wildcard for unrelated windows or later tasks.

## Privacy and data

Flower itself adds no telemetry, crash uploads, remote configuration, or automatic updates. The target site or app, Codex's model service, and optional decision providers have their own network and data rules.

Do not put credentials, cookies, auth files, or private screenshots in a chat, command line, issue, or release archive. Use the settings UI for locally entered keys. Optional providers stay disabled until you enable them locally and review the destination and data boundary.

## Good recovery questions

When something stops halfway, ask:

> Report the current Flower status and the last target identity. Do not repeat the action. Tell me whether the result is confirmed, unknown, stopped, or blocked.

Then decide whether to re-select the target, resume after a fresh observation, lower the permission tier, or leave Flower stopped. The safe default is to preserve the existing denial and Stop state.

