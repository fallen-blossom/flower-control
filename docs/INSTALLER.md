# Install and uninstall with the 0.1.0 offline installer

[简体中文](INSTALLER.zh-CN.md)

**The 0.1.0 release is being prepared; its Setup and release assets are not published yet.** Preview.3 still contains source ZIPs only. This guide describes the actual installer flow without treating a version label, an earlier candidate or one exit code as acceptance.

After publication, download `FlowerControl-Setup.exe` and `SHA256SUMS.txt` from **0.1.0** on [this repository’s Releases](https://github.com/fallen-blossom/flower-control/releases). Developers use `flower-control-0.1.0-source.zip`. The complete payload ZIP does not replace the Setup UI. Do not invent an exe URL before the asset exists.

Matching 0.1.0 local installation, host trust, real control, update recovery and uninstall checks remain to be recorded. Unperformed clean/other-Windows checks are not claimed. The encoder's fixed build-source materials have been verified; final full-payload inventory and binary publication review remain pending. [Private vulnerability reporting](https://github.com/fallen-blossom/flower-control/security/advisories/new) is enabled. [Source development](INSTALL.md) is a separate route.

The 0.1.0 release will be **unsigned**. Obtain it from the [official GitHub Releases](https://github.com/fallen-blossom/flower-control/releases), compare the downloaded files with `SHA256SUMS.txt`, and consult the matching source, dependency inputs and build instructions. These establish the published artifact's identity; hashes do not provide a trusted publisher signature. Windows may show an unknown publisher, and you must decide whether to approve the UAC prompt. Flower does not install a trust root or ask you to disable Windows protection. The final artifact record retains `signed: false`.

## Recording encoder and its source materials

The candidate uses the independently built FFmpeg 8.1.1-flower-minimal-1 encoder from fixed FFmpeg, x264 and zlib sources. It keeps the local PNG-frame concat, padding and H.264/MP4 recording path with network protocols disabled. `ENCODER.json` pins the executable, original license/notices and matching corresponding-source ZIP. The builder rejects changed or missing materials and does not download a replacement encoder.

The offline payload includes those materials under `Payload/Notices/encoder`, including `flower-ffmpeg-8.1.1-minimal-1-corresponding-source.zip`. Setup's maintenance-material flow retains them under `<Root>\Packages\<actual-maintenance-directory>\Help\Notices\encoder` for offline access. The source ZIP contains the complete upstream archives, recipe, configuration and original component/GCC/MinGW runtime notices, without an encoder executable. Recipients do not need to compile it. Developers can use the [portable offline encoder build instructions](../tools/encoder_build/README.md) and [fixed inputs](../tools/encoder_build/inputs.lock.json).

Material hashes and the short synthetic recording/decode comparison do not establish size-limit behavior, foreground recording, host trust or complete installer acceptance. See [third-party notices](../THIRD_PARTY_NOTICES.md) for the retained licenses and distribution scope.

## Start on another PC

Use Windows 11 x64 and Codex desktop. Web also needs an installed supported Brave, Edge, or Chrome. A complete offline installer supplies its runtime; recipients do not install Python, the .NET SDK, Visual Studio, or compile source. Setup uses its embedded payload without fetching dependencies. Codex's model service and requested websites retain their own network behavior.

Place the real file locally and compare its SHA-256 with the maintainer's matching checksum. If your actual path is `D:\Downloads\FlowerControl-Setup.exe`, one ordinary PowerShell command opens it:

```powershell
Start-Process -FilePath 'D:\Downloads\FlowerControl-Setup.exe' -Wait
```

Use `Start-Process -FilePath 'D:\Downloads\FlowerControl-Setup.exe' -ArgumentList '--install-root','D:\FlowerControl' -Wait` to prefill the root. Setup still displays its checks and permission prompts, and retains the actual location of an existing installation.

Use `Get-FileHash -LiteralPath 'D:\Downloads\FlowerControl-Setup.exe' -Algorithm SHA256` to inspect the checksum. These are example paths, not download locations. Resolve unknown provenance or a mismatch before running it; do not disable system security to force installation.

## In the installer

1. Run under your everyday Windows account. Setup extracts and verifies its local payload, then reads protected machine registration.
2. For a new installation, choose a **new dedicated directory under an existing protected parent**, such as **D:\FlowerControl** or **C:\Program Files\FlowerControl**, and let Setup create/protect it. Do not pre-create an ordinary-user-writable empty root or place it under Downloads/Documents. Network locations, junctions and replaceable intermediate directories are rejected before elevation; Setup does not take over an existing directory's ACL.
3. Select host integrations. Codex is offered by default. DSH needs this PC's installed `DeepSeek Harness.exe`; another machine's host paths or identity do not transfer.
4. Review the directory and plan, then install. Confirm Windows UAC yourself. Cancelling retains preparation material without approving an administrator operation.
5. Read the separate file-install, executor-connection, and settings-open results. **Installed files do not mean an enabled host plugin or successful real window control.** Keep the receipt/recovery directory shown at the end.

If preflight rejects the directory owner or ancestor permissions, choose a new directory on another protected local volume; renaming a folder on the same volume does not change its parent security. Some volumes formatted through Windows storage services have a `NetworkService` volume-root owner and are also rejected. Setup does not take ownership of an entire drive. If no suitable data volume is available, use `C:\Program Files\FlowerControl`; an existing installation still retains its registered root. Do not broaden ordinary-user access to system directories to pass installation.

The new layout is:

```text
D:\FlowerControl\
  Program\   Code, runtimes, versions, protected permissions and recovery
  Data\      Settings, browser profiles, local state
  Cache\     Large caches and temporary work material
  Packages\  Versioned setup and maintenance material
```

A new installation with no old policy defaults to **02 Ordinary control**. Existing installations retain their actual tier, data root, Stop, and unfinished records. Setup locks the detected existing root for updates. Downloading a package onto D does not relocate an existing installation.

Program files, runtimes, data, and large caches use the selected root. Windows still owns UAC, registry, and uninstall registration; Codex and other hosts manage their own plugin caches/configuration. .NET single-file startup and Setup payload extraction also use Windows TEMP, commonly on C. **This is not a promise of zero bytes on C.** Check system temporary space rather than repeatedly reinstalling.

## Trust and enable Flower in Codex

Setup attempts and verifies local marketplace registration. The actual source is under `<Root>\Program\integrations\codex\<version>`. Follow its result:

- If Setup confirms Codex local marketplace registration, go directly to Codex's plugin UI to install/enable Flower Control. Do not repeat registration commands.
- If registration is incomplete, retain the receipt and exact marketplace path, then check the host installation using [troubleshooting](TROUBLESHOOTING.md). Only if manual registration is needed and the official CLI is available should you use that actual path, for example:

```powershell
codex plugin marketplace add '<the actual local marketplace path shown by Setup>'
```

The bare `codex` command works only when the CLI is on PATH. A Desktop-bundled CLI missing from PATH does not mean Flower's program installation failed, and does not require Python, an SDK or a compiler. Do not guess an old CLI path or overwrite a registration with an unknown owner.

Marketplace registration does not grant control permissions. In Codex's plugin UI, install/enable Flower Control, then review the exact current Hook commands through `/hooks` or the host's trust prompt yourself. Installing/enabling does not automatically trust Hooks; see [official OpenAI documentation](https://developers.openai.com/plugins/build/plugins).

Use the generated path rather than typing an old version. Marketplace registration does not prove loading in the current chat. Start a new chat and check three status responses, loaded/on-disk source, and the real ordinary executor. High control being unavailable under tier 02 is expected.

## Use it after installation

Setup's usage/AI-prompt button opens the local getting-started text. The complete bilingual guides are shipped under `<Root>\Packages\<actual maintenance directory>\Help\Guides` after installation, and under `Guides` in extracted setup material before installation. Open `docs\USAGE.md`, `docs\PERMISSIONS.md` or `docs\TROUBLESHOOTING.md` with Notepad; basic usage and uninstall instructions do not require another source download.

Open a blank Notepad document yourself, then send in the new chat:

> Check Flower's three channels, ordinary tier 02, and Stop first. List Notepad candidates so I can identify the blank document I just created, then bind it. Type “Flower test passed” and read it back. Do not save or close it. Finish App and Computer control, release held input, and preserve the document and text.

Then try:

> Open https://example.com in a temporary Flower browser. Read the title and main heading, then close only this temporary session. Preserve other windows.

Identify the candidate by its returned title/process. The settings list picker is separate from binding a chat target. Handle login, passwords, verification codes, and Windows UAC yourself. See [first use and finish](USAGE.md#first-use-after-installation).

## Stop and local maintenance

- **Ctrl+Alt+9**, HUD Stop, and Stop Computer Use end Computer input only.
- **Ctrl+Alt+Shift+9** or Emergency stop all Flower in settings/tray is the separate all-channel stop. Registration failures appear in status/diagnostics; do not assume a global hotkey is available.
- Resume all requires an explicit local choice. Changing tier, restarting, or finishing does not clear Stop or replay unknown results.
- Diagnostics offers read-only integrity checking, redacted export, ordinary settings backup/draft import, and storage categories. Imported allow rules are disabled; review and Ctrl+S. Browser/language use separate saves. Normal backups omit keys, cookies, chats, and live grants.
- Cleanup presents exact candidates before confirmation. Supported old cache metadata goes to the Windows Recycle Bin; profiles, execution ledgers, and recovery are excluded.

## Update and recover a failure

Let Setup detect the real root/version; do not choose an empty directory to bypass old state. Update preparation first exports an ordinary-settings backup without keys or grants and retains data/recovery material. An idle old role uses bounded graceful shutdown and exact receipts.

Retain the displayed work directory, original plan, and receipts on failure. The installer can reconnect to the same pending plan. Do not regenerate plans to replay consumed stages or an unknown action. Root drift, changed identity, busy requests, and unknown blockers require read-only inspection. A process exit code alone is not a verified rollback/recovery result. Old versions lacking a compatible maintenance path need matched migration instructions first.

An update does not clear Stop, reverse refusals, enable 03/04, consume pending administrator messages, or grant personal-profile access again.

## Uninstall

After installation has registered maintenance, use **Windows Settings → Apps → Installed apps → Flower Control → Uninstall**. Alternatively run the exact installed maintenance version:

```powershell
Start-Process -FilePath 'D:\FlowerControl\Packages\<actual-maintenance-directory>\FlowerControl-Maintenance.exe' -ArgumentList '--uninstall' -Wait
```

Windows Apps points to the exact maintenance entry. `<actual-maintenance-directory>` is not the human release label `0.1.0` or a literal placeholder to copy; use the exact path reported by Setup or the local uninstall registration. Maintenance first verifies registration, exact files/processes/tasks, and host entries, then shows the file count/size, retained paths, and blockers for your confirmation. It gracefully stops matching Flower roles, preserves unknown processes, and removes only host values that still match the recorded values.

**Data, Cache, and Program's permissions, privacy, work-authority, audit, execution-bindings, and recovery are retained by default**, including profiles, settings, Stop/unknown, permissions and recovery evidence. Owned program files go to the Windows Recycle Bin with no permanent-delete fallback. Busy files, changed identity, or unknown results keep the relevant work blocked/retained. Do not clear those records to force removal.

After a new-layout uninstall completes, choose **Review retained personal data** if desired. It inventories that installation's exact Data/Cache as the ordinary user and displays paths, file counts and sizes. A second confirmation recycles only the reviewed files; cancelling retains them. Empty directories and the Program records above remain. Busy files, links, changed content, a new installation or unknown results stop cleanup, with a separate partial-result receipt. Reinspect rather than blindly retry. Legacy personal directories require separate review.

This does not clear Windows Credential Manager, host caches or task outputs saved elsewhere, and is not secure erasure. Removing the host plugin alone does not uninstall the helper/autostart. Do not recursively delete the entire installation root.
