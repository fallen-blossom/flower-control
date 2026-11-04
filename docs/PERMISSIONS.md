# Permissions and settings

[简体中文](PERMISSIONS.zh-CN.md)

Flower has four selectable permission tiers. They are local settings and are checked again for each target, launch, and action. A saved tier is not a permanent approval for every task.

## Open settings

Right-click the Flower tray icon and choose **Settings**. The candidate UI supports Simplified Chinese and English; language is saved separately.

**Actual tier buttons on the left save and switch immediately.** Watch the saved-tier display and result notice. Moving from an ordinary role to 03/04 may request Windows UAC; cancellation retains the old role. The Permissions-page list-layer tabs only change the view.

Lists, masks, and other ordinary edits enter a shared draft. Navigation preserves it; **Ctrl+S** or **Save permissions and action preferences** applies it. Closing with unsaved edits offers save, discard, or return. Supported role handoffs preserve drafts, but ordinary crash/restart recovery is not guaranteed. **Ctrl+C** in a detail dialog only copies information. Diagnostics settings import enters this draft too: imported allow rules are disabled and execution arguments cleared, then reviewed before Ctrl+S. Tier, Stop, work grants, and unknown results are never restored from a backup. Browser/language use a separate immediate-save confirmation.

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
### Minimal 04 setup

1. Open Settings, choose **04 Administrator execution** with the actual tier buttons on the left, and wait for the switch to finish. Confirm UAC if requested, then view the 04 list layer under Permissions.
2. Use **Program actions** to choose a program file, a running window, or **Press Ctrl+Alt+8 to pick a window (30 seconds)**. For the hotkey option, move the pointer onto the target and press Ctrl+Alt+8 within 30 seconds. Check the full path and identity, then add the no-argument rule. This list editor is separate from selecting a chat target.
3. Press **Ctrl+S** to save. Saving a launch record does not launch the program.
4. Return to the chat and make one bounded launch request for that exact program. Flower rechecks 04, Stop, the list or work authorization, target identity, and arguments.

For work authorization, select **Work-based**, save the mode, then use **Enable work authorization** and confirm the hosts you need in the local page. It binds a task, program, arguments, and directory rather than allowing every program. If the new route is not available, the page rejects the change and preserves the previous selection.

The chat agent cannot write the protected permission file. Do not ask Codex to edit it directly. Use the tray settings with your own Windows account.

## Stop, pause, and tier 01

- **Tier 01 fully stopped** stops dispatch for Web, App, and Computer. The tray, settings, and Stop controls remain available.
- **Global all-writes Stop** uses **Emergency stop all Flower** in settings/tray or the separate **Ctrl+Alt+Shift+9** hotkey. Registration failure is reported in overview/diagnostics. Ctrl+Alt+9 does not create it. If it is present and recoverable, the tray adds **Resume all writes**. If that row is absent, follow [recovery troubleshooting](TROUBLESHOOTING.md#missing-tray-or-recovery).
- **Computer pause** blocks new Computer mouse/keyboard work while App and Web may continue. Toggle it with the tray row **Pause Computer Use / Continue Computer Use**.
- **Ctrl+Alt+9**, the HUD Stop, and the tray **Stop Computer Use** end the current Computer operation and release held input. They do not change the saved tier or create a global all-writes Stop.
- **Continue** after a Computer Stop means a fresh target observation and a new action. It does not replay the last observation or an uncertain action.

To leave **01 fully stopped**, open **Tray → Settings**, choose 02, 03, or 04 with the actual tier buttons and wait for the saved tier to update. Save list drafts separately with **Ctrl+S**. Changing a tier does not clear a separate global Stop or restore a revoked chat grant.

A stop, pause, damaged configuration, unavailable helper, or failed source admission must remain fail-closed. If the status is unknown, stop and inspect instead of retrying the action.

## Six tray icon filenames are not six tiers

The six legacy filenames are not tier numbers. The actual mapping is:

| Current state | Appearance | Resource filename (legacy naming) |
| --- | --- | --- |
| 01 Fully stopped | White stop artwork | `05-disabled` |
| 02 Ordinary control, available | Blue | `02-admin-window` |
| 03 Administrator windows, available | Orange | `03-admin-launch` |
| 04 Administrator execution, available | Red | `04-system-uac` |
| Paused, unavailable, or faulted | Fault artwork | `06-fault` |

04 reuses red artwork only; it does **not** enable UAC secure desktop. `01-normal` is a retained resource. Read the tray text to distinguish pause from a fault. A fresh candidate policy defaults to **02 Ordinary control**; existing policies are retained. The original preview.3 default of 03 is historical. Check the actual saved tier before the first task.

## Current safety boundaries

- A session or chat grant is not the same as a Windows administrator grant.
- A successful helper connection is not proof that every target action is safe.
- Password entry, cross-user elevation, UAC secure desktop clicks, and indefinite key holds are outside this preview’s promise.
- Administrator work-source failures remain fail-closed. Do not fabricate, replay, or consume a pending administrator message to make a status look healthy.
