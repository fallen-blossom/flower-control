# Install on another PC with Codex

[简体中文](INSTALL_WITH_CODEX.zh-CN.md)

For Windows 11 x64, install Codex desktop and Git first and use your normal account. This fetches current main, including tutorial corrections. Full manual commands are in [Install](INSTALL.md).

## Get the source

Run in ordinary PowerShell. Choose a writable ASCII local path whose destination does not exist; preserve existing checkouts.

```powershell
git clone https://github.com/fallen-blossom/flower-control.git C:\Tools\flower-control
if ($LASTEXITCODE -ne 0) { throw 'Clone failed; inspect the error before continuing.' }
Set-Location C:\Tools\flower-control
git log -1 --oneline
```

Open that folder in Codex, start a new chat, and send this prompt with the actual path.

## Installation prompt

```text
Install and verify Flower Control on this Windows 11 x64 PC.
Source: C:\Tools\flower-control

Read README.md, docs/INSTALL.md, docs/PERMISSIONS.md, and docs/USAGE.md from this checkout. Do the work, rather than only restating instructions.

I authorize installing the required official dependencies and building/installing the local Flower helper and Codex plugin. Check Git, Codex CLI, CPython 3.14 x64, .NET 10 SDK, and Visual Studio C++ tools. Check ASCII/local requirements for source, compiler, TEMP, and package paths. Reuse suitable tools, acquire missing dependencies from official publishers, and use lock files. If Flower is already installed, report its version and a supported update route first; this public snapshot lacks a complete online updater, so do not overwrite it using first-install scripts.

Follow INSTALL in one PowerShell context. Create the build parent, use fresh output/evidence paths, and pin the correct data root. Check each exit code; diagnose failure before continuing. Record the stable package and Disable.ps1 paths. Do not transfer another PC's binaries, credentials, profiles, or authorization state.

Let me handle Windows UAC and Codex /hooks trust, identifying the interface and buttons. Continue ordinary checks, builds, and preparation. Do not enable unrelated external services or change security software.

Guide me to actual tier 02 in tray settings, explaining immediate tier changes versus saved drafts. In a new chat verify all three loaded channels, then follow USAGE: I open a blank Notepad; you list candidates for me to identify, bind it, type “Flower test passed”, and read it back. Read https://example.com in a temporary browser. Finish App/Computer input and indicators, preserve my document, and clean only the explicit temporary session.

Report actual installed/loaded versions, real-operation results, blockers, settings/Stop/resume instructions, three future requests, and the disable/plugin-removal procedure. Status success is not proof of input success.
```

The second PC still needs its own build and real-operation checks. See [troubleshooting](TROUBLESHOOTING.md) and [disable/removal](INSTALL.md#9-disable-or-remove).
