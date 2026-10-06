# Third-party notices

Flower combines its own control code with libraries maintained by other projects. A license chosen for Flower does not replace their licenses or copyright notices.

This source preview distributes Flower source, lock files, documentation, and original branding. It does not bundle Brave, CPython, the .NET SDK/runtime, downloaded wheels, or compiled third-party DLLs. Users obtain those dependencies from their publishers. Any later binary installer must include the exact dependencies' license texts and notices before distribution.

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

Other base Python dependencies are pinned in `requirements.lock`: MIT, BSD-3-Clause, MIT-0, Apache-2.0, and the dual Apache-2.0 OR BSD-3-Clause license. The detailed Python versions and license expressions are in `dependency-inventory.json`. It includes 34 unique Python packages across the two lock files and 13 App NuGet packages; the unmodified license files available in the installed Python distributions are retained under `licenses/third-party/` in the prepared source archive.

The pywin32 wheel contains multiple components. Its Win32/COM binding notices are BSD-style; Pythonwin/IDLE and MAPI components retain their separate notices. Its [adodbapi module carries LGPL-2.1](https://raw.githubusercontent.com/mhammond/pywin32/main/adodbapi/license.txt). Flower has no adodbapi or Pythonwin import and this archive does not distribute their code. A later bundle of the full wheel or virtual environment must handle those component obligations too. The package is recorded as `LicenseRef-pywin32-mixed`, rather than silently treating all its contents as PSF. Unmodified upstream notice files may contain paths relative to the original upstream layout.

The App lock contains these additional MIT packages: Microsoft.Win32.SystemEvents 8.0.0, System.CodeDom 8.0.0, System.Configuration.ConfigurationManager 8.0.1, System.Diagnostics.EventLog 8.0.1, System.Diagnostics.PerformanceCounter 8.0.1, System.Drawing.Common 8.0.10, System.Management 8.0.0, System.Security.Cryptography.ProtectedData 8.0.0, System.Security.Permissions 8.0.0, and System.Windows.Extensions 8.0.0. NuGet package license notices remain applicable when their DLLs are distributed.

MPL applies to its covered files and modifications, not automatically to Flower's independent files. [Mozilla's FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) explains the scope; use the actual license and preserve the covered source information when distributing it.

Jev is an optional hosted service, not code relicensed by Flower. Codex, Brave, Windows, and TypeSafe are separate products. This project does not claim to be an official OpenAI, Microsoft, Brave, or TypeSafe plugin.
