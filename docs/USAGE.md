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

Bind a target window for ordinary control; pointer and keyboard input stay scoped to it. The frame, elapsed time, and Stop button show an active Computer cycle. A separate masked desktop overview does not grant input access to other windows.

## First use after installation

Use ordinary windows and a public page first; administrator rules, work authorization, and optional decision providers are unnecessary.

1. **You choose the tier:** find the flower icon under **^ Show hidden icons**, right-click → **Settings / 设置**, choose actual **02 Ordinary control** on the left, and wait for the saved tier to update. Tier changes are immediate; list drafts use Ctrl+S. A fresh policy defaults to 03; existing policies are retained.
2. **You open a test document:** start Notepad and create a blank document, separate from important work.
3. **In a new Codex chat, send:**

> Check whether Flower's three channels are available for ordinary control. Do not modify content. List selectable Notepad windows so I can identify the blank document I just created, then bind it.

4. **Identify the target in chat:** Codex lists candidates and binds a returned candidate ID. A separate generic picker need not appear. Identify your window by the listed title/process; you need not write tool arguments. The settings Ctrl+Alt+8 picker adds list rules and is a different operation.
5. **Send the input task and inspect the result:**

> In the bound blank Notepad, type “Flower test passed” and read it back. Do not save or close it. End this control session afterwards, preserving Notepad and the text.

You should see the text and receive an actual readback result. A handoff prompt means Codex is waiting for you, not that the action completed.

6. **Try a public page:**

> Open https://example.com in a temporary Flower browser. Read the page title and main heading, then close only this temporary session. Preserve my other browser windows.

The request expresses ordinary temporary-browser task consent; it requires no Luohua grant or guaranteed extra Flower confirmation card. Local tier, genuine chat origin, and Stop checks still apply. Handle logins and Windows UAC yourself.

7. **Describe the target and result for later tasks.** Prefer App/Web structure where useful. For a Computer trial, open Calculator, ask Codex to list and bind it, click one visible digit, and read the result.

## Finish and step away

> This task is complete. Finish App and Computer control, release held input, and close the control indicators. Keep my applications, unsaved documents, and results. Clean only explicitly identified temporary browser sessions from this task and report whether cleanup completed.

App and Computer each use `pause(mode='finish')`; Web finishes an explicit inventory of temporary sessions. These are separate boundaries. Finishing control does not save/close Notepad or exit the tray helper, which remains available for later tasks. Decide yourself whether to save or discard the test document. Closing a chat alone is not verified cleanup.

Choose actual tier **01 Fully stopped** to block new dispatch while away, or use the tray pause to block only Computer. See [permissions](PERMISSIONS.md) for recovery and [profile revocation](BROWSER_PROFILES.md#revoke-personal-profile-access) for removing a personal grant.

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
