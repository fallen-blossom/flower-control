# Permissions and settings

[简体中文](PERMISSIONS.zh-CN.md)

Flower has four selectable permission tiers. They are local settings and are checked again for each target, launch, and action. A saved tier is not a permanent approval for every task.

## Open settings

Right-click the Flower tray icon and choose **Settings**. The current native helper UI is Chinese-first.

Changes normally enter a shared draft. Switch pages freely; the draft is not discarded by navigation. Use **Ctrl+S** or the visible Save button to apply it. If the page has unsaved edits, closing it offers save, discard, or return. Closing without saving discards the draft; this page does not claim crash/restart recovery for every ordinary edit. A supported role handoff can preserve a draft into the new settings surface and tells you when that happens. The page may also offer **Ctrl+C** copy in a detail dialog; copying does not change permissions.

Some actions are immediate rather than ordinary draft edits: Stop, Computer pause, opening a browser profile, and certain UAC/preparation maintenance actions say so explicitly. Do not assume every button on the settings page is deferred until Ctrl+S.

A tier or list change can be rejected because the saved revision changed, the target identity is unknown, the configuration is damaged, or an existing Stop is still in force. Reopen settings and reload the current saved state instead of repeatedly forcing the old draft.

## The four selectable tiers

The UI numbers are presentation labels. The internal policy values are shown only to make source and status easier to correlate.

| UI tier | Internal value | Name | Ordinary windows | Administrator windows | Administrator launch | Web/App/Computer |
| --- | ---: | --- | --- | --- | --- | --- |
| 01 | -1 | Fully stopped | No | No | No | All three channels stop dispatching |
| 02 | 0 | Ordinary control | Yes | No | No | Normal targets only |
| 03 | 1 | Administrator windows | Yes | Yes | No | Can observe and operate elevated windows; cannot start an elevated process |
| 04 | 2 | Administrator execution | Yes | Yes | Yes, by local policy | Adds bounded High launch; UAC secure desktop remains frozen |

Higher tiers include the lower-tier capability. They are not independent additive switches.

### 03 vs 04

**03 Administrator windows** is for a window that is already open and elevated. Flower may inspect and operate it, but it does not create a new elevated process from this tier.

**04 Administrator execution** adds a launch path. A launch must match the current local launch policy and exact program identity. The launch is rechecked against the current tier, the current Stop state, the target binding, and the deny lists.

04 does **not** mean “can click any UAC prompt.” The old system-takeover/UAC route is frozen and has no selectable enable entry. Existing records may be retained for audit, but they are not a new permission.

## What the lists control

The lists live on different settings pages:

- **Program deny lists** block matching programs or window conditions. A deny match wins over an allow list or task authorization.
- **Administrator-window deny list** is a separate rule layer for elevated windows.
- **Administrator launch list** is used by 04. It approves exact program records, not a launcher’s child process or an associated application.
- **Work authorization** is a separate 04 mode. It binds a specific task, program, arguments, and directory; it does not silently turn every program into an allow rule.

Adding a program to a draft does not launch it and does not grant permission until the page is saved and the later action is checked.
+
### Minimal 04 setup

1. Open **Settings → Permissions**, select **04 Administrator execution**, and save the base tier.
2. For list mode, open the administrator launch list and use **pick by window** (preferred) or choose the program file from **Program actions**. Verify the full path and program identity, then add only the no-argument record to the draft. Button labels can differ slightly between builds.
3. Press **Ctrl+S** to save. Saving a launch record does not launch the program.
4. Return to the chat and make one bounded launch request for that exact program. Flower rechecks 04, Stop, the list or work authorization, target identity, and arguments.

For work authorization, select **authorize by work**, save the mode, then use **Enable work authorization** and confirm the hosts you need in the local page. It binds a task, program, arguments, and directory rather than allowing every program. If the new route is not available, the page rejects the change and preserves the previous selection.

The chat agent cannot write the protected permission file. Do not ask Codex to edit it directly. Use the tray settings with your own Windows account.

## Stop, pause, and tier 01

- **Tier 01 fully stopped** stops dispatch for Web, App, and Computer. The tray, settings, and Stop controls remain available.
- **Global all-writes Stop** is a separate local stop state, not something Ctrl+Alt+9 creates. If it is present and recoverable, the tray adds **Continue All Writes**. If that row is absent, do not clear state manually; use the status/error evidence and the supported maintenance recovery.
- **Computer pause** blocks new Computer mouse/keyboard work while App and Web may continue. Toggle it with the tray row **Pause Computer Use / Continue Computer Use**.
- **Ctrl+Alt+9**, the HUD Stop, and the tray **Stop Computer Use** end the current Computer operation and release held input. They do not change the saved tier or create a global all-writes Stop.
- **Continue** after a Computer Stop means a fresh target observation and a new action. It does not replay the last observation or an uncertain action.

To leave **01 fully stopped**, open **Tray → Settings**, select 02, 03, or 04, then press **Ctrl+S** or the visible save button. Changing a tier does not clear a separate global Stop, and a generic resume does not restore a revoked chat grant.

A stop, pause, damaged configuration, unavailable helper, or failed source admission must remain fail-closed. If the status is unknown, stop and inspect instead of retrying the action.

## Six tray icon filenames are not six tiers

The icon assets include six visual states:

```text
01-normal
02-admin-window
03-admin-launch
04-system-uac
05-disabled
06-fault
```

These filenames describe what the tray can show. They do not create six selectable permissions.

- The current selectable tiers map to normal, administrator-window, and administrator-launch visuals.
- `disabled` represents stopped or unavailable operation.
- `fault` represents a damaged or unreadable configuration.
- `system-uac` is retained for the frozen legacy visual path and is not a new 04 feature.

The saved policy tier and the icon state are related but not identical. Always read the tray text and the status page.

## Current safety boundaries

- A session or chat grant is not the same as a Windows administrator grant.
- A successful helper connection is not proof that every target action is safe.
- Password entry, cross-user elevation, UAC secure desktop clicks, and indefinite key holds are outside this preview’s promise.
- Administrator work-source failures remain fail-closed. Do not fabricate, replay, or consume a pending administrator message to make a status look healthy.

