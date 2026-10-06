# Install the Windows source preview

[简体中文](INSTALL.zh-CN.md)

This route builds the current source and prepares the administrator helper locally. The developer's existing installation has been exercised; a complete first installation on a separate Windows account or clean PC remains a release check. Treat this guide as a reviewed source-install route, not a tested one-click installer.

## Requirements

- Windows 11 x64 and an interactive desktop session, using a Windows account that can approve UAC for itself.
- Current Codex desktop app. The installed Microsoft Store Codex host is the primary tested host; do not assume a headless CLI has the same desktop access.
- For the Web channel, Brave installed at `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`. App and Computer operate selected Windows windows and are not restricted to Brave.
- [CPython 3.14 x64](https://www.python.org/downloads/windows/) and [.NET 10 SDK x64](https://dotnet.microsoft.com/download/dotnet/10.0).

Choose a normal local directory for the source. Avoid a junction, network share, or folder you plan to move. Docker, WSL, a hosted browser, and a Flower cloud account are not required.

Before installing or invoking the .NET SDK, set this in the PowerShell session that will launch it:

```powershell
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
```

This disables the SDK's separate telemetry. See [Microsoft's guidance](https://learn.microsoft.com/en-us/dotnet/core/tools/telemetry). Downloading dependencies will still contact PyPI and NuGet.

## Build and prepare without elevation

Open PowerShell in the source root. The lock files target Windows x64 and CPython 3.14; do not remove their hashes if a package cannot be installed.

```powershell
py -3.14 -m venv .venv
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $flowerPython -m pip install --require-hashes --only-binary=:all: -r requirements.lock -r requirements-web.lock
dotnet restore .\flower_control\drivers\app_native\Flower.AppWorker.csproj --locked-mode --source https://api.nuget.org/v3/index.json
dotnet restore .\flower_control\drivers\high_helper\Flower.HighHelper.csproj --locked-mode
& $flowerPython -B -m tools.build_daily_payloads native --output .flower-build\native --evidence .flower-build\native-evidence.json
& $flowerPython -B -m tools.build_daily_payloads app --output .flower-build\app --evidence .flower-build\app-evidence.json
& $flowerPython -B -m tools.prepare_high_broker_install --native-bin .flower-build\native --app-bin .flower-build\app --native-build-evidence .flower-build\native-evidence.json --app-build-evidence .flower-build\app-evidence.json --output .flower-build\install
& $flowerPython -B -m tools.configure_local_plugin --package .flower-build\install --output .flower-local
```

Stop if any command fails. Build outputs must be new directories. The last two commands only prepare local files; they do not install, register a task, or change Codex settings. `configure_local_plugin` generates the three MCP entries and the hook command for your source path, so no developer-specific drive or username is needed.

The generated `broker.json`, `task.xml`, `active.json`, and installation scripts are available under `.flower-build\install` for inspection. They bind the source, account, Python, and binaries used during preparation.

## Install the administrator helper

The helper is needed for reliable Windows input and access to elevated applications. Codex itself can remain a normal user process. The install writes a versioned helper under `%ProgramFiles%\FlowerControl\HighHelper`, limits access to its files, and registers a task for **your account's interactive login**, at its highest available privilege. It does not install a SYSTEM service or disable UAC, Defender, or the firewall.

Run the following after reviewing the prepared package. Windows will ask you to approve UAC.

```powershell
$flowerApply = (Resolve-Path '.flower-build\install\ApplyInstall.ps1').Path
$flowerInstaller = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile', '-File', ('"' + $flowerApply + '"'))
if ($flowerInstaller.ExitCode -ne 0) { throw 'Flower helper installation did not complete.' }
$flowerPreparation = Get-Content -LiteralPath '.flower-build\install\preparation.json' -Raw | ConvertFrom-Json
Start-ScheduledTask -TaskName $flowerPreparation.task_name
```

The script is for **first installation**. An existing installation or task is refused rather than overwritten. If task registration alone failed, keep the generated package and use its documented `-CompleteTaskRegistration` recovery after checking the existing files. Do not clear the profile or action database to fix an installation error.

## Add the plugin to Codex

```powershell
codex plugin marketplace add .\.flower-local
codex plugin add flower-control@flower-control-local
```

These are local marketplace commands, not publication to the public plugin directory. See [official OpenAI plugin documentation](https://developers.openai.com/plugins/build/plugins#add-a-marketplace-from-the-cli).

Review and trust the generated Flower hook definition in Codex. Installing a plugin does not automatically trust its hooks. The hook associates calls with the current chat and does not grant personal-profile access. If skipped, origin checks can refuse valid calls. See [bundled hooks and trust](https://developers.openai.com/plugins/build/plugins#bundled-mcp-servers-and-lifecycle-hooks).

Open a new Codex chat and ask it to check all three Flower status tools and their origin probes. The helper should be available, the loaded source should match the files on disk, and the three channels should be admitted. A protocol greeting alone is insufficient. Then try one harmless write in a test window and confirm its result.

An old chat may retain old connections. Try a new chat first; reopen Codex normally if no new connection picks up the installed version. A Windows reboot is not part of normal installation.

## Optional Jev

Jev is off by default and is billed by its provider separately from Codex. Enable it only if you want its target selection and accept sending short task goals and candidate labels to TypeSafe. Enter the key in your own terminal, never in a chat or command-line argument:

```powershell
& $flowerPython -B -m flower_control.control.jev_setup enable
& $flowerPython -B -m flower_control.control.jev_setup status
```

The key is stored in Windows Credential Manager for the current user. To stop new Jev decisions:

```powershell
& $flowerPython -B -m flower_control.control.jev_setup disable
```

The three base channels remain available without Jev. Disabling the switch does not delete the stored key.

## Stop, update, or remove

Use **Ctrl+Alt+9** or the Stop control to stop writes. Ask the current chat to resume when you want it to continue; it must observe the target again. The tray menu's two Chinese actions are “stop/resume all writes” and “normally exit the administrator helper.”

Updates are manual in this preview. Finish current work, pause and normally stop the old helper, preserve the old package and state, then prepare a package for the changed source. The first-install script is not an updater. Changing only the MCP path does not update the source admitted by the helper.

To disable startup and request normal helper shutdown, run the generated `Disable.ps1` with the same UAC launch method above. Read its `instance_stopped` result; a disabled login task alone does not prove the current helper exited. Remove the plugin with `codex plugin remove flower-control@flower-control-local`. Keep browser data and state unless you deliberately choose to remove them. There is no automatic data deletion.
