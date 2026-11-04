# Install Flower Control on Windows

> 0.1.0 release preparation: ordinary users follow [the offline installer guide](INSTALLER.md) without the compilers in this development tutorial. The matching 0.1.0 Release/binaries are not published yet; source, final artifacts and real acceptance stay separate.

[简体中文](INSTALL.zh-CN.md)

**Ordinary users should start with the [offline installer candidate guide](INSTALLER.md)** after receiving a real Setup.exe; compilers are unnecessary there. The candidate is unpublished, unsigned, and not clean-PC accepted. Published preview.3 still contains source and checksums.

The revised **source development/local build route** below applies to a checkout containing these tools, not to installer recipients. Old tags retain their original snapshots. For an existing install, start at section 8 instead of overwriting it with first-install steps.

The developer build and Codex plugin flow have been used on Windows. A clean Windows account, a second PC, and every third-party application are not implied to have been tested.

## 1. Prepare the machine

You need:

- Windows 11 x64 with a normal local ASCII path for the source.
- The current [Codex desktop app](https://developers.openai.com/codex/) and the `codex` CLI.
- Git for the clone route below. For guided setup, see [Install with Codex](INSTALL_WITH_CODEX.md).
- [CPython 3.14 x64](https://www.python.org/downloads/windows/).
- [.NET 10 SDK x64](https://dotnet.microsoft.com/download/dotnet/10.0).
- [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the x64 desktop C++ workload.
- A Windows account that can approve its own UAC prompt. Do not install with a different administrator account and assume the helper is bound to your daily account.

Do not place the source on a network drive, in a junction, or in a path containing Chinese characters. Native builds currently require ASCII source, compiler, and output paths.

Run these commands sequentially in **one ordinary PowerShell window**, preserving the variables. Only the generated installer elevates through UAC.

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
git log -1 --oneline
```

The default `main` branch contains the preview.3 source plus later tutorial corrections. The `v0.1.0-preview.3` tag is the original release snapshot; check it out only when reproducing that snapshot. Use this online installation guide for corrected instructions.

With the [release ZIP](https://github.com/fallen-blossom/flower-control/releases/tag/v0.1.0-preview.3), run `Get-FileHash -Algorithm SHA256 .\flower-control-0.1.0-preview.3-source.zip` and verify `SHA256SUMS.txt` first, extract the archive, and open PowerShell in the extracted `flower-control` directory. Do not download a random binary from an issue or mirror.

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
dotnet restore .\flower_control\drivers\high_helper\Flower.HighHelper.csproj --locked-mode --source https://api.nuget.org/v3/index.json
```

Create a fresh output directory under the operating-system temp root and build there:

```powershell
$flowerBuild = Join-Path $env:TEMP ('flower-build-' + [guid]::NewGuid().ToString('N'))
if ($flowerBuild -match '[^\x00-\x7f]') { throw 'TEMP path must contain ASCII characters; use an ASCII local account/build environment.' }
New-Item -ItemType Directory -Path $flowerBuild | Out-Null
& $flowerPython -B -m tools.build_daily_payloads native --output "$flowerBuild\native" --evidence "$flowerBuild\native-evidence.json"
& $flowerPython -B -m tools.build_daily_payloads app --output "$flowerBuild\app" --evidence "$flowerBuild\app-evidence.json"
```

If Visual Studio is installed in a nonstandard location, add `--compiler-setup <absolute-path-to-vcvarsall.bat>` to the `native` command. The output and evidence paths must not already exist.

Prepare the administrator-helper package in a stable local install directory. The native build output stays under the OS temp root, but the generated install package and its recovery scripts must survive a temp cleanup:

Create the `$flowerBuild` parent first; builders create the `native` and `app` children themselves. Continue only after each command succeeds; keep build logs and evidence on failure. An ASCII source path does not fix a non-ASCII TEMP path.

```powershell
$flowerPackage = Join-Path $env:LOCALAPPDATA ('FlowerControl\source-install\' + [guid]::NewGuid().ToString('N'))
if ($flowerPackage -match '[^\x00-\x7f]') { throw 'Choose an accessible stable ASCII package path before continuing.' }
& $flowerPython -B -m tools.prepare_high_broker_install `
  --install-root "D:\FlowerControl" `
  --data-root "D:\FlowerControl\Data" `
  --native-bin "$flowerBuild\native" `
  --app-bin "$flowerBuild\app" `
  --native-build-evidence "$flowerBuild\native-evidence.json" `
  --app-build-evidence "$flowerBuild\app-evidence.json" `
  --output "$flowerPackage"
```

`--data-root` pins the user-data root, whose children include `state-v1`. Do not pass the `state-v1` child as the root. Ordinary roles 01/02 require this pinned root; an existing installation must retain its original root.

Before continuing, inspect:

```powershell
Get-ChildItem "$flowerPackage"
Get-Content -Raw "$flowerPackage\preparation.json"
```

Keep the exact `$flowerPackage` path. It contains `ApplyInstall.ps1`, `Disable.ps1`, the task definition, source snapshot, and operation metadata. Do not reuse an old package or an old operation record.

## 5. Install the administrator helper

The candidate example above installs under `D:\FlowerControl\Program`, alongside Data/Cache/Packages. Without a selected new root, use protected registration or the legacy ProgramFiles fallback. Do not override ProgramFiles through an environment variable. The full parent chain/ACL must prevent replacement; the installer does not change volume-wide ACLs. The helper registers an interactive task for the current Windows account. Codex itself does not need to run as administrator. The helper does not disable Defender, the firewall, or UAC.

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

After successful file installation, generate the source-development plugin against the registered actual root. The frozen installer already supplies the complete plugin and Skill; it does not need this source branch.

Generate a recipient-local Codex marketplace. The output directory must be new:

```powershell
& $flowerPython -B -m tools.configure_local_plugin --package "$flowerPackage" --output .flower-local
$flowerPackage | Set-Content .\.flower-local\install-package-path.txt
```

This step only writes files. It does not install the helper, register a scheduled task, write Codex configuration, or grant Hook trust.


```powershell
codex plugin marketplace add .\.flower-local
codex plugin add flower-control@flower-control-local
```

This adds a local marketplace. It is not an upload to the official OpenAI plugin directory.

Open Codex and review the Flower Hook definition before trusting it. In the Codex composer, enter `/hooks` to open Hook review, inspect the exact command, and trust only that definition. The current Codex consent UI may also surface a review prompt when the plugin is enabled. Installation and trust are separate: a new chat may refuse calls until the generated local Hook is trusted. Review the command path and keep trust disabled if it does not point to this source checkout and its `.venv`. See the official [Codex Hook trust behavior](https://developers.openai.com/plugins/build/plugins).

## 7. Verify in a new chat

After starting the scheduled task, find the flower icon in the notification area, possibly under **^ Show hidden icons**. Right-click → **Settings / 设置**, choose **02 Ordinary control / 普通控制** with the actual tier buttons on the left, and wait for the saved tier to read 02. Tier changes apply immediately; list drafts use Ctrl+S. Moving from an ordinary role to 03/04 may request Windows UAC. Permission-page list-layer tabs only change the view.

A fresh candidate policy defaults to **02 Ordinary control**; existing installations retain their policy. The original preview.3 default of 03 is historical. Check the actual saved tier before the first task. No administrator launch rules, work authorization, or optional decision provider are needed. See [first use](USAGE.md#first-use-after-installation) for a complete trial and [tray troubleshooting](TROUBLESHOOTING.md#missing-tray-or-recovery) if the icon is absent.

Open a new Codex chat. Ask for a read-only status check first:

> Check the status of the Flower Web, App, and Computer channels. Show the registered tools, loaded source, on-disk source, and helper status. Do not operate a target yet.

For each channel, confirm:

- `registered_tools` contains the expected `flower_*` tools.
- `loaded_source` points to the checkout you installed.
- `on_disk_source` matches the loaded source hash and version.
- `high_broker` connection, source admission, and executor identity checks pass. **In tier 02, `high_control_available: false` is normal**; verify the ordinary executor. Check High availability only when actually using 03/04.
- `effective_control` is not stopped or paused unexpectedly.

Then run one harmless test:

> Use Flower App on the Notepad window I select. Read the window title and one control, then stop without saving.

A successful status probe does not prove every target or action. Test one temporary page or one disposable app window before using valuable data.

## 8. Update an existing installation

The complete candidate Setup detects and retains the real root, backs up ordinary settings, and preserves failure-recovery material; see [update/recovery](INSTALLER.md#update-and-recover-a-failure). The source export now includes `prepare_work_authority_update`, `prepare_stopped_host_update`, `prepare_offline_continuation`, and matching templates rather than referencing an updater absent from the archive.

For source development, first have Codex inspect this checkout's `--help`, installed version/actual root/pause/unfinished state, then prepare the exact package and update plan for your final UAC review. An old incompatible protocol needs matched migration instructions. Do not use first-install ApplyInstall as an updater, replay a consumed operation, clear state, or uninstall merely to bypass checks. Source, installed files, host loading, and real actions are separate checks.

## 9. Disable or remove

**The complete candidate supports Windows Apps or the Packages maintenance uninstaller**, retaining Data/Cache/recovery by default; see [uninstall](INSTALLER.md#uninstall). The source-development disable route follows. Tier 01 temporarily blocks dispatch; Disable disables the scheduled task and attempts a normal helper shutdown. It retains installed files, profiles, and action data. Removing the plugin does not replace disabling the helper.

The generated `Disable.ps1` is in the stable `$flowerPackage` directory recorded by `.flower-local\install-package-path.txt`, not `%ProgramFiles%`. Using your normal Windows account, open a visible PowerShell with **Run as administrator**, change to the source root, and run this block. It displays the receipt and saves a new log:

```powershell
$flowerPackage = Get-Content -LiteralPath .\.flower-local\install-package-path.txt
if (-not (Test-Path -LiteralPath "$flowerPackage\Disable.ps1")) { throw 'Saved Flower package is unavailable; do not delete state to force disable.' }
$flowerDisable = (Resolve-Path "$flowerPackage\Disable.ps1").Path
$flowerDisableLog = Join-Path $flowerPackage ('disable-result-' + [guid]::NewGuid().ToString('N') + '.json')
& $flowerDisable | Tee-Object -FilePath $flowerDisableLog
```

Require `task_state` to be `disabled` or `absent`. `instance_stopped: true` confirms only that instance's exit; exit code alone does not prove it stopped.

The revised disable path handles ordinary and High roles separately with bounded graceful exit. Read the exact receipt: `instance_stopped: false` or unknown remains unresolved. Use tray Exit and read-only verification of the original identity; do not force-kill or erase ledgers.

After checking the disable result, return to **ordinary PowerShell** to remove the plugin:

```powershell
codex plugin remove flower-control@flower-control-local
```

This command removes only the Codex plugin. It does **not** disable the scheduled task, stop the administrator helper, remove files under the actual registered Flower root, or delete browser and action data. Run `Disable.ps1` too when you intend to stop Flower. Delete retained data only after identifying the exact local paths and keeping anything you still need.

A source-development installation can use `tools.prepare_uninstall --output <new-local-plan.json>` to inventory and generate the matching `.ApplyUninstall.ps1`. Review counts/bytes, host entries, retained paths, and blockers. Execute only the exact generated script after confirming that plan. Do not bypass blockers, replay unknown results, or recursively remove the entire root. Retained personal-data deletion needs a separate explicit decision.

## What this preview does not claim

- It is not a signed one-click installer.
- It is not a clean-PC unattended deployment.
- UAC secure-desktop automation is frozen.
- It does not grant every Windows app or website support.
- It does not disable or bypass Windows security controls.

For a failure, include the release version, the step number, the exact error code, the new-chat status output, and a minimal reproduction. Never attach credentials, cookies, private screenshots, or a complete local environment dump.
