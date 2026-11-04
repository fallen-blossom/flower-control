# Install Flower Control on Windows

[简体中文](INSTALL.zh-CN.md)

This page is the complete source-preview installation path for **Flower Control 0.1.0-preview.3**. A GitHub Release contains source and checksums, not a signed one-click installer.

The developer build and Codex plugin flow have been used on Windows. A clean Windows account, a second PC, and every third-party application are not implied to have been tested.

## 1. Prepare the machine

You need:

- Windows 11 x64 with a normal local ASCII path for the source.
- The current [Codex desktop app](https://developers.openai.com/codex/) and the `codex` CLI.
- [CPython 3.14 x64](https://www.python.org/downloads/windows/).
- [.NET 10 SDK x64](https://dotnet.microsoft.com/download/dotnet/10.0).
- [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the x64 desktop C++ workload.
- A Windows account that can approve its own UAC prompt. Do not install with a different administrator account and assume the helper is bound to your daily account.

Do not place the source on a network drive, in a junction, or in a path containing Chinese characters. Native builds currently require ASCII source, compiler, and output paths.

Open PowerShell in the directory that will contain the source. Disable .NET SDK telemetry for this shell:

```powershell
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
py -3.14 --version
dotnet --version
codex --version
```

The dependency installation still uses PyPI and NuGet.

## 2. Get the source

Use either Git or the source ZIP attached to the GitHub Release.

With Git:

```powershell
git clone https://github.com/fallen-blossom/flower-control.git
Set-Location .\flower-control
git checkout v0.1.0-preview.3
```

With the release ZIP, verify `SHA256SUMS.txt` first, extract the archive, and open PowerShell in the extracted `flower-control` directory. Do not download a random binary from an issue or mirror.

## 3. Create the Python environment

Every command below runs from the source root.

```powershell
py -3.14 -m venv .venv
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $flowerPython -m pip install --require-hashes --only-binary=:all: -r requirements.lock -r requirements-web.lock
```

If a lock file fails verification, stop. Do not regenerate the lock file to make installation pass.

## 4. Restore and build the native pieces

```powershell
dotnet restore .\flower_control\drivers\app_native\Flower.AppWorker.csproj --locked-mode --source https://api.nuget.org/v3/index.json
dotnet restore .\flower_control\drivers\high_helper\Flower.HighHelper.csproj --locked-mode
```

Create a fresh output directory under the operating-system temp root and build there:

```powershell
$flowerBuild = Join-Path $env:TEMP ('flower-build-' + [guid]::NewGuid().ToString('N'))
& $flowerPython -B -m tools.build_daily_payloads native --output "$flowerBuild\native" --evidence "$flowerBuild\native-evidence.json"
& $flowerPython -B -m tools.build_daily_payloads app --output "$flowerBuild\app" --evidence "$flowerBuild\app-evidence.json"
```

If Visual Studio is installed in a nonstandard location, add `--compiler-setup <absolute-path-to-vcvarsall.bat>` to the `native` command. The output and evidence paths must not already exist.

Prepare the administrator-helper package in a stable local install directory. The native build output stays under the OS temp root, but the generated install package and its recovery scripts must survive a temp cleanup:

```powershell
$flowerPackage = Join-Path $env:LOCALAPPDATA ('FlowerControl\source-install\' + [guid]::NewGuid().ToString('N'))
& $flowerPython -B -m tools.prepare_high_broker_install `
  --native-bin "$flowerBuild\native" `
  --app-bin "$flowerBuild\app" `
  --native-build-evidence "$flowerBuild\native-evidence.json" `
  --app-build-evidence "$flowerBuild\app-evidence.json" `
  --output "$flowerPackage"
```

Generate a recipient-local Codex marketplace. The output directory must be new:

```powershell
& $flowerPython -B -m tools.configure_local_plugin --package "$flowerPackage" --output .flower-local
$flowerPackage | Set-Content .\.flower-local\install-package-path.txt
```

This step only writes files. It does not install the helper, register a scheduled task, write Codex configuration, or grant Hook trust.

Before continuing, inspect:

```powershell
Get-ChildItem "$flowerPackage"
Get-ChildItem .flower-local -Recurse
Get-Content -Raw "$flowerPackage\preparation.json"
```

Keep the exact `$flowerPackage` path. It contains `ApplyInstall.ps1`, `Disable.ps1`, the task definition, source snapshot, and operation metadata. Do not reuse an old package or an old operation record.

## 5. Install the administrator helper

The helper is installed under `%ProgramFiles%\FlowerControl\HighHelper` and registers an interactive task for the current Windows account. Codex itself does not need to run as administrator. The helper does not disable Defender, the firewall, or UAC.

Run the generated installer with one explicit UAC approval:

```powershell
$flowerApply = (Resolve-Path "$flowerPackage\ApplyInstall.ps1").Path
$flowerInstaller = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile', '-File', ('"' + $flowerApply + '"'))
if ($flowerInstaller.ExitCode -ne 0) { throw 'Flower helper installation did not complete.' }
$flowerPreparation = Get-Content -LiteralPath "$flowerPackage\preparation.json" -Raw | ConvertFrom-Json
Start-ScheduledTask -TaskName $flowerPreparation.task_name
```

Approve the Windows prompt only if you started this command from the source directory you inspected. If installation fails, keep the output directory and error text. Do not rerun a consumed plan, overwrite an existing helper, or delete state to force success.

## 6. Add the plugin to Codex

```powershell
codex plugin marketplace add .\.flower-local
codex plugin add flower-control@flower-control-local
```

This adds a local marketplace. It is not an upload to the official OpenAI plugin directory.

Open Codex and review the Flower Hook definition before trusting it. In the Codex composer, enter `/hooks` to open Hook review, inspect the exact command, and trust only that definition. The current Codex consent UI may also surface a review prompt when the plugin is enabled. Installation and trust are separate: a new chat may refuse calls until the generated local Hook is trusted. Review the command path and keep trust disabled if it does not point to this source checkout and its `.venv`. See the official [Codex Hook trust behavior](https://developers.openai.com/plugins/build/plugins).

## 7. Verify in a new chat

Open a new Codex chat. Ask for a read-only status check first:

> Check the status of the Flower Web, App, and Computer channels. Show the registered tools, loaded source, on-disk source, and helper status. Do not operate a target yet.

For each channel, confirm:

- `registered_tools` contains the expected `flower_*` tools.
- `loaded_source` points to the checkout you installed.
- `on_disk_source` matches the loaded source hash and version.
- `high_broker` reports a connected helper with source admission and High control available when that channel needs it.
- `effective_control` is not stopped or paused unexpectedly.

Then run one harmless test:

> Use Flower App on the Notepad window I select. Read the window title and one control, then stop without saving.

A successful status probe does not prove every target or action. Test one temporary page or one disposable app window before using valuable data.

## 8. Update an existing installation

The first-install script is not an updater. Keep the old package and state, prepare a new package, then create a bound update plan:

```powershell
$flowerUpdate = Join-Path $env:TEMP ('flower-update-' + [guid]::NewGuid().ToString('N'))
& $flowerPython -B -m tools.prepare_work_authority_update `
  --package "$flowerPackage" `
  --output $flowerUpdate
```

Review the new output and `plan.json`. Launch the generated `Update.ps1` with the same explicit UAC method. A stale plan, a reused operation id, a running old helper, or a source/identity mismatch must be rejected rather than forced.

Do not use the first-install `ApplyInstall.ps1` to replace an existing helper.

## 9. Disable or remove

The generated `Disable.ps1` is in the same stable `$flowerPackage` directory recorded by `.flower-local\install-package-path.txt`; it is not copied into `%ProgramFiles%`. First read that saved path, then run the script through UAC:

```powershell
$flowerPackage = Get-Content -LiteralPath .\.flower-local\install-package-path.txt
if (-not (Test-Path -LiteralPath "$flowerPackage\Disable.ps1")) { throw 'Saved Flower package is unavailable; do not delete state to force disable.' }
$flowerDisable = (Resolve-Path "$flowerPackage\Disable.ps1").Path
$flowerStopper = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile', '-File', ('"' + $flowerDisable + '"'))
if ($flowerStopper.ExitCode -ne 0) { throw 'Flower helper disable did not complete.' }
```

Keep the script output and require `instance_stopped: true`. If the helper state is unknown, the scheduled task can still be disabled, but do not claim the instance stopped. Then remove the plugin if desired:

```powershell
codex plugin remove flower-control@flower-control-local
```

This command removes only the Codex plugin. It does **not** disable the scheduled task, stop the administrator helper, remove files under `%ProgramFiles%\FlowerControl`, or delete browser and action data. Run `Disable.ps1` too when you intend to stop Flower. Delete retained data only after identifying the exact local paths and keeping anything you still need.

## What this preview does not claim

- It is not a signed one-click installer.
- It is not a clean-PC unattended deployment.
- UAC secure-desktop automation is frozen.
- It does not grant every Windows app or website support.
- It does not disable or bypass Windows security controls.

For a failure, include the release version, the step number, the exact error code, the new-chat status output, and a minimal reproduction. Never attach credentials, cookies, private screenshots, or a complete local environment dump.
