# Troubleshooting Flower Control

[简体中文](TROUBLESHOOTING.zh-CN.md)

Start with a read-only status check in a new chat:

> Show the Flower Web, App, and Computer status. Include registered tools, loaded source, on-disk source, high broker state, effective control state, and the last error code. Do not retry the failed action.

Do not attach credentials, cookies, browser profiles, private screenshots, or a complete home-directory dump to an issue.

## Local status before host integration

The candidate provides local read-only status and a settings-open request without first admitting a Codex MCP origin. Use the **actual installed version from Setup's receipt**, replacing the placeholder in ordinary PowerShell:

```powershell
& 'D:\FlowerControl\Program\versions\<actual-version>\Flower.HighHelper.exe' --flower-local-status
& 'D:\FlowerControl\Program\versions\<actual-version>\Flower.HighHelper.exe' --flower-local-settings
```

These only report the real ordinary/High executor or request its settings window. They dispatch no business input, clear no Stop and approve no chat/work. A local connection is not host-loading proof. Preserve an unverifiable executor error rather than copying executables or editing registration/permissions to force access.

Keep the same plan, receipt and recovery directory after install/update/uninstall failure. Diagnostics offers explicit full integrity checks, redacted export and bounded repair of the current settings window, without repairing authority, clearing unknown results or admitting pending messages.

The diagnostic timeline retains the latest 256 metadata snapshots from this helper process, displaying the latest 12. It is not a complete persistent step-by-step task history and does not record the screen. Existing execution/recovery journals remain separate.

## Is the plugin loaded?

Check that the plugin is installed and enabled for the current host:

```powershell
codex plugin list
```

The expected local identity is `flower-control@flower-control-local`. A configured count is not the current chat's tool list: it must receive all three channels. The old source-development generator supplies basic wiring; the frozen candidate includes its full Skill/Hook/icon set. Check the actual route and do not mix plugin directories.

## Missing tray or recovery

1. Expand **^ Show hidden icons** in the notification area and find the flower icon.
2. If absent, inspect the installer exit code and scheduled-task start from step 5. Ask Codex for read-only diagnosis; do not rerun the first-install script over it.
3. In tier 01, open Settings and choose actual tier 02 on the left; wait for the saved tier to update.
4. For Computer pause, choose **Continue Computer Use / 继续使用 Computer Use**, then request a fresh observation.
5. For all-writes Stop, use **Resume all writes / 继续全部写入** only when offered. Otherwise stay stopped and [report](https://github.com/fallen-blossom/flower-control/issues) the version, error and redacted status. Rebuilding the settings window is not universal authority repair.

Ctrl+Alt+9 remains Computer-only; Ctrl+Alt+Shift+9 or Emergency stop all Flower is the separate global Stop. Check diagnostics if another application owns a hotkey or registration fails.

If the plugin is installed but a new chat has no Flower tools:

1. Open a new chat, not the old one.
2. Check that the plugin is enabled.
3. Enter `/hooks` in Codex, review the exact generated command, and trust only that definition.
4. Reopen Codex normally if the plugin catalog changed.
5. Ask for the three status probes before doing any target action.

## Old chat or stale connection

An old chat may keep an old MCP process, old source path, old tool catalog, or an unknown target binding. A source update can therefore appear correct on disk while the old chat still behaves like the previous version.

Use a new chat after installing or updating. Compare `loaded_source` and `on_disk_source` from the status response. If their hashes or paths differ, do not continue target work in that chat. Restart Codex normally only after preserving the failed evidence; do not delete the source or permission state to force a reload.

## A tool name is not routed

This is a host-side routing problem, not automatically a Flower permission failure. The declared name and the dispatched name must be captured exactly.

Example symptom:

```text
declared:  codex_exec_code (tool args: { code: "..." })
dispatch:  unsupported call: exec_code_code
```

Use this checklist:

1. Record the client version, provider/adapter version, the exact tools schema sent to this thread, and the exact host error.
2. Find the component that owns the tool registration and dispatch. Do not assume it is Flower merely because Flower is installed.
3. Check whether a normalization step strips or adds `codex_`, `exec_`, or a namespace prefix more than once.
4. If a local router owns the issue, add only the exact alias observed in a reproducible call. Do not use a wildcard rule that strips `codex_` from every tool.
5. Add a regression test for the declared name, the dispatched name, and the successful call path; then refresh the router or open a new chat.
6. If the owner is the official Codex binary or upstream provider/adapter, file a minimal reproduction with both names and version alignment. Do not “fix” it by changing a Hook, permission router, or shell.
7. If a different spelling appears later, capture that exact name and repeat the same narrow alias/test procedure. Never broad-normalize unknown names.

A working `wait` tool does not prove that every tool uses the same router. Test the affected tool by its declared schema.

## Hook not trusted or source rejected

Flower installation writes a local Hook through `tools/configure_local_plugin.py`. Installation does not grant trust. Enter `/hooks` in Codex, review the exact command, and trust it before target work. The new chat can reject every Flower call until a matching review is accepted.

Source-development Hooks use the exact checkout and `.venv`; frozen candidate Hooks use the actual `<Root>\Program\versions\<version>` runtime/bootstrap. Check the generated route and host enablement/trust. Do not bypass a denial by changing the Hook or permission router, switching shells, or reusing a stale grant.

## Permission or Stop blocks the call

Check `effective_control` and the tray text:

- Tier 01 means all three channels stop dispatching.
- Global Stop blocks writes even if a later tier looks usable.
- Computer pause blocks only new Computer input.
- A damaged permission configuration uses the fault state and refuses related work.
- A deny list wins over an allow list or task authorization.

Do not lower a deny rule or clear Stop merely to make a test pass. Re-select the target and perform a fresh observation after recovery.

## Browser page is wrong or login is missing

Temporary and AI profiles are separate from your everyday browser. A site that is logged in normally may still show a login wall in a Flower profile.

Check which profile the request used. For a new login, open the matching Flower profile, log in yourself, and close the login window normally before continuing. Do not copy cookies or auth files from another browser. If a managed browser is already running with an unknown identity, do not delete its profile to force a new one.

## Administrator action fails

Use 03 only for an already-open administrator window. Use 04 only for an exact local launch record or work authorization. A changed executable, launcher child, unknown target, or mismatched arguments must fail closed.

UAC secure desktop automation and the legacy system-takeover path are frozen in this preview. A pending administrator-work message is not a reason to replay or consume it. Preserve the original denial and Stop state; ordinary work may continue only if the current host and status independently allow it.

## Installation or update failed

Keep the failed output directory and `preparation.json` or update `plan.json`. Do not:

- rerun a consumed first-install operation;
- reuse an old native/app/install output directory;
- overwrite an existing helper with the first-install script;
- delete the permission, browser, action, or rollback state to get a green result;
- upload a complete local environment dump.

For an issue, include the release version, build step, exact error code, whether the helper was previously installed, the new-chat status output, and the smallest harmless reproduction.
