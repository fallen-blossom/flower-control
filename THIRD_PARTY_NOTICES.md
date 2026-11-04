# Third-party notices

Flower combines its own control code with libraries maintained by other projects. A license chosen for Flower does not replace their licenses or copyright notices.

The source archive distributes Flower source, lock files, documentation, and original branding. It does not bundle Brave, CPython, the .NET SDK/runtime, downloaded wheels, or compiled third-party DLLs. Source developers obtain the required dependencies from their publishers. The complete offline payload is a separate binary distribution with its admitted runtime components and their notices; the 0.1.0 source and installer release assets are still being prepared and are not published yet.

The current offline builder is a separate, unpublished binary candidate: it copies admitted local CPython/site-packages, self-contained .NET runtimes, native companions, and a fixed-hash encoder. `ENCODER.json` binds the independently built FFmpeg 8.1.1-flower-minimal-1 executable to its original license, notices, corresponding-source ZIP, source-input lock and build recipe. The builder and CI use the same `verified_encoder_materials` guard; a build-server environment path does not authorize a different binary or missing materials. Neither fetches an encoder implicitly. Final reconciliation of the full-payload inventory and dependency notices, and public binary redistribution review, remain **pending before binary publication**. A successful material check or generated inventory is not blanket legal or installed-product acceptance.

The recording encoder is built from complete, unmodified FFmpeg 8.1.1, x264 commit `b35605ace3ddf7c1a5d67a2eb553f034aef41d55`, and zlib 1.3.2 sources. It retains the local PNG-frame concat, padding and H.264/MP4 path; automatic external-library detection and network protocols are disabled. The [encoder build entry](tools/encoder_build/README.md) documents the portable offline interface and [fixed official inputs](tools/encoder_build/inputs.lock.json). These are developer build materials; installer recipients do not compile the encoder.

The builder includes `flower-ffmpeg-8.1.1-minimal-1-corresponding-source.zip`, `LICENSE`, `NOTICE.txt` and the matching `ENCODER.json` under `Payload/Notices/encoder`. The source ZIP contains the three complete upstream archives, recipe, generated configuration, source inventory and short synthetic recording/decode evidence; it contains no encoder executable. Original component licenses and GCC/MinGW runtime notices, including the GCC Runtime Library Exception, are preserved. The actual PE imports are Windows system DLLs, with no MSYS2/GCC runtime DLL dependency. The short fixture checks presentation timestamps, decoded frames and progress; it does not establish the size-limit behavior, foreground recording, host trust or complete installer acceptance. Keep the matching source package and original notices with binary distributions; its exact SHA-256 is pinned in `ENCODER.json`.

| Component | Pinned version | License / source |
| --- | --- | --- |
| Model Context Protocol Python SDK | 1.30.0 | [MIT](https://github.com/modelcontextprotocol/python-sdk) |
| Playwright Python | 1.63.0 | [Apache-2.0](https://github.com/microsoft/playwright-python); its embedded Node and driver notices also apply |
| FlaUI.Core, FlaUI.UIA3 | 5.0.0 | [MIT](https://raw.githubusercontent.com/FlaUI/FlaUI/v5.0.0/LICENSE.txt) |
| Interop.UIAutomationClient | 10.19041.0 | [MIT](https://github.com/FlaUI/UIAutomation-Interop) |
| Pillow | 12.3.0 | [MIT-CMU](https://github.com/python-pillow/Pillow) |
| pyee | 13.0.0 | [MIT](https://github.com/jfhbrook/pyee) |
| greenlet | 3.5.6 | [MIT AND PSF-2.0](https://github.com/python-greenlet/greenlet) |
| certifi | In requirements.lock | [MPL-2.0](https://github.com/certifi/python-certifi); preserve its notices and access to the covered source |
| CPython / typing_extensions | Python 3.14 / locked wheel | [PSF-family notices](https://docs.python.org/3/license.html) |
| pywin32 | 312 | [BSD-style Win32 bindings](https://raw.githubusercontent.com/mhammond/pywin32/main/win32/License.txt) and separate component notices; see below |
| FFmpeg recording encoder | 8.1.1-flower-minimal-1 | GPL-3.0-or-later; matching original texts and complete build-source materials described above |
| x264 | `b35605ace3ddf7c1a5d67a2eb553f034aef41d55` | GPL-2.0-or-later, combined here under GPL-3.0-or-later; original `COPYING` retained |
| zlib | 1.3.2 | zlib license; original `LICENSE` retained |

Other base Python dependencies are pinned in `requirements.lock`: MIT, BSD-3-Clause, MIT-0, Apache-2.0, and the dual Apache-2.0 OR BSD-3-Clause license. The detailed Python versions and license expressions are in `dependency-inventory.json`. It includes 34 unique Python packages across the two lock files and 13 App NuGet packages; the unmodified license files available in the installed Python distributions are retained under `licenses/third-party/` in the prepared source archive.

The pywin32 wheel contains multiple components. Its Win32/COM bindings and Pythonwin retain BSD-style notices; Scintilla, IDLE and MAPI retain their separate notices. Flower's `computer_capture_worker.py` imports `win32ui`, a Pythonwin binary component, for capture. The Flower source ZIP includes Flower's import and the copied third-party notices, rather than the installed wheel's runtime code. The full-site offline binary runtime includes the wheel's components, including Pythonwin and the [LGPL-2.1 adodbapi module](https://raw.githubusercontent.com/mhammond/pywin32/main/adodbapi/license.txt). Flower does not call adodbapi, but its Python source files and `license.txt` are included in that runtime; the wheel's original component notices are retained under `pywin32-312.dist-info/licenses/`. Flower's MIT license applies to Flower code and does not replace these licenses or restrict the modification, rebuilding and redistribution rights they grant. The package is recorded as `LicenseRef-pywin32-mixed`, rather than treating all its contents as PSF. Unmodified upstream notice files may contain paths relative to the original upstream layout.

The App lock contains these additional MIT packages: Microsoft.Win32.SystemEvents 8.0.0, System.CodeDom 8.0.0, System.Configuration.ConfigurationManager 8.0.1, System.Diagnostics.EventLog 8.0.1, System.Diagnostics.PerformanceCounter 8.0.1, System.Drawing.Common 8.0.10, System.Management 8.0.0, System.Security.Cryptography.ProtectedData 8.0.0, System.Security.Permissions 8.0.0, and System.Windows.Extensions 8.0.0. NuGet package license notices remain applicable when their DLLs are distributed.

MPL applies to its covered files and modifications, not automatically to Flower's independent files. [Mozilla's FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) explains the scope; use the actual license and preserve the covered source information when distributing it.

Jev is an optional hosted service, not code relicensed by Flower. Codex, Brave, Windows, and TypeSafe are separate products. This project does not claim to be an official OpenAI, Microsoft, Brave, or TypeSafe plugin.
