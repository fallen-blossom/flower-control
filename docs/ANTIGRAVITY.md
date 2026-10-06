# Reduced Antigravity integration preview

[简体中文](ANTIGRAVITY.zh-CN.md)

The Windows Antigravity IDE source adapter is implemented. **It has not been
built, tested, or installed.** It reuses Flower's existing control engines without
the Google SDK or a cloud bridge.

Web operates temporary or AI-dedicated Brave environments. App operates selected
Windows accessibility controls. Computer captures a selected window and supplies
keyboard/mouse input. Existing mechanical batches, Stop, pause, action queries,
input release, and optional Jev remain available in the source implementation.

Personal Luohua browser tools are removed and denied. Per-chat grants and chat
isolation are not supported. The scope is an MCP connection: if Antigravity shares
one connection between chats, target selection and state are shared too. Each
channel has its own connection. Do not use this preview for concurrent chats
that require different private-window permissions. Reselect windows after
reconnection; query an unknown action before replaying it. Ctrl+Alt+9 stops writes.

Follow [Windows setup](INSTALL.md) for dependencies and native/app builds. Use a
regular local source directory, disable .NET SDK telemetry before building, and
identify the actual Antigravity.exe from the official installation. Add
`--antigravity-image` and that absolute path to the package-preparation command.
You may also include `--claude-image` to admit both explicitly selected hosts in
one fixed helper package. Do not admit a whole Electron, Python, or Node directory.

Generate the local workspace plugin from the prepared package:

```powershell
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $flowerPython -B -m tools.configure_antigravity_plugin --package .flower-build\install-antigravity --output .agents\plugins\flower-control
if ($LASTEXITCODE -ne 0) { throw 'Flower Antigravity configuration failed.' }
```

The package and output directory must be new. The generator writes plugin.json,
mcp_config.json, a skill, and a configuration record. It does not install, start,
change global settings, or overwrite an existing plugin. The exported package
places the generator under tools; in the development repository it is under
release/github/tools and requires --source-root when invoked directly.

Install the matching helper through the documented first-install or normal
pause/drain/update procedure. Existing installations are refused by the
first-install script. Let Antigravity load `.agents/plugins/flower-control`
through its local plugin flow, then inspect the three servers in the MCP manager.
None of these steps was performed for this source delivery.

No chat Hook is required. The adapter verifies the actual Antigravity launch
chain through the protected helper before supplying an internal origin ticket.
Do not fill flower_origin. Origin probes report connection scope, not verified
chat identity. An executable update changes its pinned digest and requires a
reviewed package refresh.

Flower adds no telemetry, remote configuration, or automatic updates. Results
still enter the configured Antigravity model service. Jev uses its documented
data flow only when enabled. See [privacy](../PRIVACY.md). Standalone CLI, SDK,
WSL, and cloud entrypoints are outside this preview.

Official references: [local plugins](https://antigravity.google/docs/plugins),
[MCP configuration](https://antigravity.google/docs/mcp).
