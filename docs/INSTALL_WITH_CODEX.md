# Install on another PC with Codex

[简体中文](INSTALL_WITH_CODEX.zh-CN.md)

The 0.1.0 release, final Setup/checksums and matching acceptance record are being prepared. Published preview.3 is a source ZIP. After publication, choose the exact 0.1.0 Setup and checksums on [this repository’s Releases](https://github.com/fallen-blossom/flower-control/releases); no nonexistent binary URL is implied.

## You have an actual Setup.exe

Use Windows 11 x64 and Codex desktop. A complete candidate supplies its runtime; recipients need no Python, .NET SDK or Visual Studio. Check the real file and its matching maintainer-provided SHA-256, then open it with one ordinary PowerShell command:

```powershell
Start-Process -FilePath 'D:\Downloads\FlowerControl-Setup.exe' -ArgumentList '--install-root','D:\FlowerControl' -Wait
```

Use your actual file and choose a dedicated root such as `D:\FlowerControl` in the window. If the file/checksum is missing, report that rather than inventing a Release exe link. See [the installer guide](INSTALLER.md), including temporary C-drive usage and uninstall.

Installation prompt for Codex on that PC:

```text
Install and verify the actual Flower 0.1.0 offline installer I received on this Windows 11 x64 PC.
Installer: D:\Downloads\FlowerControl-Setup.exe. Root: D:\FlowerControl.
Use the SHA-256 supplied with this exact file. If absent, report the gap; do not invent a binary URL.
Read INSTALLER, PERMISSIONS and USAGE. Check the real file/hash and existing installation first. A complete candidate needs no new Python, .NET SDK or compilers; do not silently fetch another payload.
I authorize local preparation, Flower installation, selected Codex integration and harmless verification. I will personally confirm Windows UAC, plugin enablement and /hooks trust; identify exact objects/UI. Do not change security software or copy another PC's credentials, cookies, grants or host identity. Keep an existing real root/data, original plans/receipts and pending administrator messages; never replay unknown actions.
Check 02 ordinary control for a new policy; retain existing tiers. After host enablement/trust, verify three actually loaded channels and the Medium executor in a new chat. Registration/handshake is not loading or real-control proof.
I open blank Notepad: list candidates, let me identify it, bind, type “Flower test passed” and read back without saving/closing. Read https://example.com in a temporary browser. Finish App/Computer, release held input/indicators, preserve my document and close only this explicit temporary session.
Report actual versions, real results, unfinished checks, both Stop hotkey scopes and the exact Windows Apps/Packages uninstaller entry. Retain Data/Cache and protected Program records by default. After a successful new-layout uninstall, show an exact inventory and obtain my separate confirmation before recycling personal Data/Cache files; do not recursively delete the root.
```

## You only have source and want to build

This development route needs Git and compilers, using your everyday account; full commands are in [the source tutorial](INSTALL.md). Inspect the checkout: the original preview.3 tag does not contain this unpublished installer work.

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

I authorize required official dependencies and local builds/installation. Check Git, Codex CLI, CPython 3.14 x64, .NET 10 SDK, VC++ tools and source/compiler/TEMP/package ASCII/local requirements. Reuse suitable tools, use official publishers and lock files, and do not regenerate locks merely to make errors disappear. For an existing Flower install, inspect actual version/root/Stop/unknown state and this checkout's update tools. Do not overwrite using first-install scripts.

Follow INSTALL in one PowerShell context. Create the build parent, use fresh output/evidence paths, pin the data root, and generate the source-development plugin after file installation/registration. Check each exit code before continuing. Record stable package, Disable.ps1 and uninstall-preparation paths. Do not transfer another PC's credentials, profiles or grants.

Let me handle Windows UAC and Codex /hooks trust, identifying the interface and buttons. Continue ordinary checks, builds, and preparation. Do not enable unrelated external services or change security software.

Guide me to actual tier 02 in tray settings, explaining immediate tier changes versus saved drafts. In a new chat verify all three loaded channels, then follow USAGE: I open a blank Notepad; you list candidates for me to identify, bind it, type “Flower test passed”, and read it back. Read https://example.com in a temporary browser. Finish App/Computer input and indicators, preserve my document, and clean only the explicit temporary session.

Report actual installed/loaded versions, real-operation results, blockers, settings/Stop/resume instructions, three future requests, and the disable/plugin-removal procedure. Status success is not proof of input success.
```

The second PC still needs its own build and real-operation checks. See [troubleshooting](TROUBLESHOOTING.md) and [disable/removal](INSTALL.md#9-disable-or-remove).
