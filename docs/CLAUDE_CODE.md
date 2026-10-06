# Claude Code integration preview

[简体中文](CLAUDE_CODE.zh-CN.md)

The source adapter is implemented. **It has not been built, tested, or installed.**
It reuses Flower's Web, App, and Computer engines on the same Windows machine.
This preview targets the official native Windows Claude Code executable. npm/Node,
WSL, Claude Desktop, and cloud agents are outside this integration.

## Prepare the local package

Follow [Windows installation](INSTALL.md) for Python, .NET, dependency setup, and
the native/app builds. Set DOTNET_CLI_TELEMETRY_OPTOUT=1 before using the SDK.
Web currently supports Brave. Use a regular source directory, not a junction or
the development worktree. Confirm the actual claude.exe comes from the official
Claude installation; do not rename another program or substitute node.exe.

The following commands are for a later activation. They were not run for this
delivery. Output directories must be new.

```powershell
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
$flowerClaude = (Get-Command claude.exe -CommandType Application -ErrorAction Stop).Source
& $flowerPython -B -m tools.prepare_high_broker_install --native-bin .flower-build\native --app-bin .flower-build\app --native-build-evidence .flower-build\native-evidence.json --app-build-evidence .flower-build\app-evidence.json --claude-image $flowerClaude --output .flower-build\install-claude
if ($LASTEXITCODE -ne 0) { throw 'Flower package preparation failed.' }
& $flowerPython -B -m tools.configure_claude_plugin --package .flower-build\install-claude --output .flower-claude-plugin
if ($LASTEXITCODE -ne 0) { throw 'Flower Claude configuration failed.' }
```

The generator creates a local plugin manifest, three MCP entries, a synchronous
Hook, and a usage skill. It does not install or launch anything, change Claude or
Codex settings, or approve tools. In the development repository the generator is
under release/github/tools; pass --source-root when using it there. The exported
source package places it under tools, as used above.

Review the prepared package before installing the administrator helper. For an
existing Flower installation, use its normal pause, drain, and fixed-package
update procedure. The first-install script refuses an existing installation.
Do not reset profiles or action records to complete an update.

After installing and starting the matching helper, load the local plugin from
the source directory:

```powershell
claude --plugin-dir .flower-claude-plugin
```

This is local loading, not marketplace publication. `/mcp` and `/hooks` show the
servers and Hook. Claude's normal tool permissions remain in effect.

## Use the channels

Describe the task in ordinary language. Web acts on Brave page elements. App
uses accessible Windows controls. Computer uses screenshots and mouse/keyboard
input in a selected window. Start with a public page or your own test window.

The dedicated AI browser profile follows Flower's existing rules. A personal
browser profile needs approval in this Claude chat; a Codex chat's approval does
not transfer. Subagents use the session reported by the actual host Hook, never
a relationship invented in a prompt. See [browser login](BROWSER_PROFILES.md).

Ctrl+Alt+9 stops Flower writes across hosts. Pause, input release, unknown-action
queries, and optional Jev reuse the existing helper and controls. Flower adds no
telemetry. Claude model requests and Claude's own privacy settings remain the
host's responsibility; enabling Jev separately allows its documented data flow.

## Handle connection errors

For an unlinked origin, check the loaded helper version, enabled Hook, and actual
plugin-scoped tool names. Never supply flower_origin manually. A long first-time
tool approval can outlast a ticket. A fresh call is appropriate only when the
result proves origin expiry before dispatch; check action_id before retrying any
unknown business outcome.

A Claude executable update changes its pinned digest and requires a reviewed
host inventory refresh. Source changes or a moved source directory also require
a matching helper package. Do not broaden the allowlist to a whole directory,
generic Python, or Node.

Runtime compatibility remains untested. Loading, approval, and real control are
later steps; this source delivery requires no restart.

Official references: [local plugins](https://code.claude.com/docs/en/plugins),
[MCP](https://code.claude.com/docs/en/mcp),
[Hook input rewriting](https://code.claude.com/docs/en/hooks).
