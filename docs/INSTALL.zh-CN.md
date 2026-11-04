# 在 Windows 安装 Flower Control

> 0.1.0 正式版准备：普通用户使用[离线安装器](INSTALLER.zh-CN.md)，不需要本文的编译环境。对应 0.1.0 Release/二进制尚未发布；源码、最终匹配包和实际验收分别核对。

[English](INSTALL.md)

**普通用户先看[离线安装器候选](INSTALLER.zh-CN.md)**：如果你已拿到实际 Setup.exe，可直接使用，不需要编译器。候选尚未公开发布、签名或完成干净 Windows 验收。已公开 preview.3 Release 仍只有源码和校验和。

以下保留经过修订的**源码开发/本机构建路线**，以含本批工具的实际 checkout 为准；它不把开发环境步骤强加给安装器用户。旧 tag 是发布时快照。已有安装先看第 8 节，不用首次安装覆盖。

开发机上的构建和 Codex 插件流程已经实际使用过；这不等于干净 Windows 账号、第二台电脑和所有第三方应用都已经验收。

## 1. 准备环境

需要：

- Windows 11 x64，源码放在普通本地目录，不要用中文路径。
- 当前 [Codex 桌面版](https://developers.openai.com/codex/)和 `codex` CLI。
- Git（选择下面的 Git 获取路线时需要）；不熟悉构建可用[交给 Codex 安装](INSTALL_WITH_CODEX.zh-CN.md)。
- [CPython 3.14 x64](https://www.python.org/downloads/windows/)。
- [.NET 10 SDK x64](https://dotnet.microsoft.com/download/dotnet/10.0)。
- [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)，并安装 x64 桌面 C++ 工具集。
- 当前 Windows 账号能自己确认 UAC。不要用另一个管理员账号代装，再假定助手绑定到了你日常使用的账号。

源码、编译器和输出路径当前都要求 ASCII 字符，不要放在网络盘或 Junction。

下面的命令请在**同一个普通 PowerShell 窗口**中依次执行，保留变量；仅安装脚本通过 UAC 提权。不要关闭窗口后直接从后半段继续。

在这一步对应的 PowerShell 中关闭 .NET SDK 遥测：

```powershell
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
py -3.14 --version
dotnet --version
codex --version
```

依赖下载仍会访问 PyPI 和 NuGet。

## 2. 获取源码

Git 路线：

```powershell
git clone https://github.com/fallen-blossom/flower-control.git
Set-Location .\flower-control
git log -1 --oneline
```

默认 `main` 包含 preview.3 的源码及后续教程修订。`v0.1.0-preview.3` 是原发布快照；需要复现原快照时才切换该 tag，安装时仍以本页在线修订为准。

也可以从[Release](https://github.com/fallen-blossom/flower-control/releases/tag/v0.1.0-preview.3)下载源码 ZIP 和 `SHA256SUMS.txt`，用 `Get-FileHash -Algorithm SHA256 .\flower-control-0.1.0-preview.3-source.zip` 对照校验和后解压；在解压出的 `flower-control` 根目录继续。ZIP 内文档是发布时快照，最新步骤见本页。不要从 issue、网盘或第三方镜像下载来路不明的二进制。

## 3. 创建 Python 环境

以下命令都在源码根目录执行：

```powershell
py -3.14 -m venv .venv
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $flowerPython -m pip install --require-hashes --only-binary=:all: -r requirements.lock -r requirements-web.lock
```

锁文件校验失败就停下。不要为了“先装上”重生成锁文件。

## 4. 还原依赖并构建

```powershell
dotnet restore .\flower_control\drivers\app_native\Flower.AppWorker.csproj --locked-mode --source https://api.nuget.org/v3/index.json
dotnet restore .\flower_control\drivers\high_helper\Flower.HighHelper.csproj --locked-mode --source https://api.nuget.org/v3/index.json
```

在系统临时目录新建输出目录，然后构建：

```powershell
$flowerBuild = Join-Path $env:TEMP ('flower-build-' + [guid]::NewGuid().ToString('N'))
if ($flowerBuild -match '[^\x00-\x7f]') { throw 'TEMP path must contain ASCII characters; use an ASCII local account/build environment.' }
New-Item -ItemType Directory -Path $flowerBuild | Out-Null
& $flowerPython -B -m tools.build_daily_payloads native --output "$flowerBuild\native" --evidence "$flowerBuild\native-evidence.json"
& $flowerPython -B -m tools.build_daily_payloads app --output "$flowerBuild\app" --evidence "$flowerBuild\app-evidence.json"
```

如果 Visual Studio 不在标准位置，在 `native` 命令后加 `--compiler-setup <vcvarsall.bat的绝对路径>`。输出和 evidence 路径必须是新的。

父目录 `$flowerBuild` 必须先创建，但 `native`、`app` 子目录由构建器创建，不要提前建。每条命令都应成功退出才继续；失败时保留 `*-build.log` 和 evidence，不要接着准备安装包。若系统临时目录含中文，仅换源码目录还不够；先选择受支持的 ASCII 构建环境再安装。

原生构建仍在系统临时目录，但管理员助手安装包要放在稳定的本地目录。否则临时目录被清理后，`Disable.ps1` 和后续恢复信息会一起丢失：

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

`--data-root` 固定用户数据根，内部会使用 `state-v1` 等子目录；不要把根写成 `FlowerControl\state-v1`。这也供切换到 01/02 的普通执行器使用。已有安装要保留其原数据根，不能用新目录绕过旧状态。

继续前先检查：

```powershell
Get-ChildItem "$flowerPackage"
Get-Content -Raw "$flowerPackage\preparation.json"
```

保留准确的 `$flowerPackage` 路径。这里有 `ApplyInstall.ps1`、`Disable.ps1`、计划任务定义、源码快照和 operation 信息。首次安装和后续恢复都不能复用旧包或旧 operation 记录。

## 5. 安装管理员助手

上面候选示例安装到 `D:\FlowerControl\Program`，Data/Cache/Packages 同根。未指定新根时使用受保护登记或兼容旧 ProgramFiles 根；不要改 ProgramFiles 环境变量。安装器检查整条父链/ACL，拒绝可被普通用户替换的目录，不会修改整盘权限。它注册当前 Windows 账号的交互式计划任务。Codex 本身不需要以管理员身份运行。助手不会关闭 Defender、防火墙或 UAC。

用一次明确的 UAC 确认启动生成的安装脚本：

```powershell
$flowerApply = (Resolve-Path "$flowerPackage\ApplyInstall.ps1").Path
$flowerInstaller = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile', '-File', ('"' + $flowerApply + '"'))
if ($flowerInstaller.ExitCode -ne 0) { throw 'Flower helper installation did not complete.' }
$flowerPreparation = Get-Content -LiteralPath "$flowerPackage\preparation.json" -Raw | ConvertFrom-Json
Start-ScheduledTask -TaskName $flowerPreparation.task_name
```

只有在你检查过这个源码目录后，才批准 Windows 提示。失败时保留输出目录和错误文本。不要重放已经消费的安装计划，不要覆盖已有助手，也不要删状态来强行成功。

## 6. 在 Codex 中添加插件

文件安装成功后，再生成与已登记实际根匹配的源码开发插件（冻结安装器已提供完整插件与 Skill，不用这段源码分支）：

生成当前用户和当前源码目录专用的 Codex 插件市场：

```powershell
& $flowerPython -B -m tools.configure_local_plugin --package "$flowerPackage" --output .flower-local
$flowerPackage | Set-Content .\.flower-local\install-package-path.txt
```

这一步只写文件，不安装助手、不注册计划任务、不写 Codex 配置，也不授予 Hook 信任。


```powershell
codex plugin marketplace add .\.flower-local
codex plugin add flower-control@flower-control-local
```

这是本地插件市场，不是上传到 OpenAI 官方插件目录。

打开 Codex，在输入框执行 `/hooks` 打开 Hook 审查，核对准确命令后再信任这一份定义。当前 Codex 也可能在启用插件时给出审查提示。安装插件和信任 Hook 是两件事；未信任时，新聊天会拒绝相关调用。命令路径必须指向这次源码目录及其 `.venv`。官方[插件 Hook 信任说明](https://developers.openai.com/plugins/build/plugins)也明确：安装或启用插件不会自动信任其 Hook。

## 7. 新建聊天做首次验证

安装并启动计划任务后，任务栏右下角应有 Flower 花形托盘图标，可能收在 **^ 显示隐藏图标**中。右键它 → **设置**，在左侧实际档位按钮选择 **02 普通控制**，等“已保存档位”显示 02。档位会立即保存和切换，名单等普通编辑才需要 Ctrl+S；从普通档转 03/04 可能出现需要你确认的 Windows UAC。权限页内的 02/03/04 名单查看层不等于左侧实际档位。

本批候选全新、无既有权限文件时默认 **02 普通控制**；已有机器保留原设置，因此仍须实际看“已保存档位”。preview.3 原发布快照的默认 03 不适用于本批候选。初次试用不用配置管理员启动名单、工作授权或可选 AI 决策服务。找不到托盘图标时先检查上述任务启动是否成功，按[排障](TROUBLESHOOTING.zh-CN.md#找不到托盘或无法恢复)处理。

新建 Codex 聊天，先只做只读状态检查：

> 检查 Flower 的 Web、App、Computer 三个 status，列出 registered tools、loaded source、on-disk source 和 high broker。先不要操作目标。

每个通道都确认：

- `registered_tools` 里有预期的 `flower_*` 工具。
- `loaded_source` 指向本次安装的源码目录。
- `on_disk_source` 的哈希和版本与当前文件一致。
- `high_broker` 的连接、源码准入和实际执行器身份检查通过。**02 普通档下 `high_control_available: false` 是正常结果**，应核普通执行器；仅使用 03/04 时再按该档位检查 High 能力。
- `effective_control` 没有被意外停止或暂停。

再做一个无害小试：

> 用 Flower App 操作我选择的记事本窗口，读取标题和一个控件，然后停止，不要保存文件。

“选择”由 Codex 先列出候选窗口，你在聊天中按标题/进程辨认目标，再由它绑定；不需要到设置里找通用窗口选择器。完整的记事本输入、公开网页及任务收尾步骤见[首次使用](USAGE.zh-CN.md#安装后第一次使用)。

状态探测成功不等于所有目标都能控制。先用临时网页或一次性测试窗口，再接触重要数据。

## 8. 更新已有安装

完整候选 Setup 的检测、原根保留、备份与失败接续见[安装维护指南](INSTALLER.zh-CN.md#更新或安装失败)。当前源码导出已包含 `prepare_work_authority_update`、`prepare_stopped_host_update`、`prepare_offline_continuation` 及匹配模板；不再依赖公开包外缺失的更新器。

源码开发更新先让 Codex 读取这次 checkout 的工具 `--help`、当前安装版本/真实根/暂停与未完成状态，准备准确的新包和更新计划，再由你审阅最终 UAC 阶段。旧版本缺协议时保留原安装，让维护者给匹配迁移路径。不要把首次 ApplyInstall 当升级器，不要重放已消费 operation，不要删状态或先卸载来绕过检查。新源码、文件安装、宿主加载和真实操作分别核实。

## 9. 停用或移除

**完整候选安装支持系统应用列表或 Packages 维护程序卸载**，默认保留 Data、Cache 与 recovery；见[卸载指南](INSTALLER.zh-CN.md#卸载)。下面保留源码开发安装的停用方法。 暂时不让 AI 操作可先选 01；想停止后台助手再执行下面的 Disable。它禁用计划任务并尝试正常停止实例，不删除程序文件、浏览器登录资料或动作数据。移除插件也不能代替停用助手。

生成的 `Disable.ps1` 在稳定的 `$flowerPackage` 目录，位置记录在 `.flower-local\install-package-path.txt`，不会复制进 `%ProgramFiles%`。用日常账号通过 Windows 的**以管理员身份运行**打开一个可见的 PowerShell，切到源码根目录，再执行下面命令。窗口保留回执，同时保存一份新日志：

```powershell
$flowerPackage = Get-Content -LiteralPath .\.flower-local\install-package-path.txt
if (-not (Test-Path -LiteralPath "$flowerPackage\Disable.ps1")) { throw 'Saved Flower package is unavailable; do not delete state to force disable.' }
$flowerDisable = (Resolve-Path "$flowerPackage\Disable.ps1").Path
$flowerDisableLog = Join-Path $flowerPackage ('disable-result-' + [guid]::NewGuid().ToString('N') + '.json')
& $flowerDisable | Tee-Object -FilePath $flowerDisableLog
```

回执的 `task_state` 应为 `disabled` 或 `absent`。`instance_stopped: true` 只表示脚本确认了那一个实例退出，不能只凭脚本退出码判断。

本批停用实现分别处理普通/High 两角色的有界正常退出。仍须读取准确回执：`instance_stopped: false` 或未知就保留状态，先用托盘退出并只读核对原进程身份，不强杀、不清账本。

确认停用结果后，回到**普通 PowerShell**移除 Codex 插件：

```powershell
codex plugin remove flower-control@flower-control-local
```

这条命令只移除 Codex 插件，**不会**禁用计划任务、停止管理员助手、删除实际登记根下的文件，也不会删除浏览器资料和动作数据。要真正停用 Flower，还要运行 `Disable.ps1`。需要清理数据时先确认精确本地路径，并保留仍要用的内容。

源码开发安装可用 `tools.prepare_uninstall --output <新的本地计划.json>` 只读盘点并生成准确 `.ApplyUninstall.ps1`。先审文件数/大小、host 条目、保留范围和 blockers；只有你确认同一份计划后，才执行准备器给出的准确脚本。不要绕过阻塞、重放未知结果或递归删除整个根。普通资料的后续删除须另作明确决定。

## 这个预览版不承诺什么

- 不是签名的一键安装器。
- 不是干净 PC 无人值守部署。
- UAC 安全桌面自动化当前已冻结。
- 不代表每个 Windows 应用和网站都支持。
- 不会关闭或绕过 Windows 安全机制。

出错时请附上版本、步骤编号、原始错误码、新聊天 status 和最小复现。不要上传凭据、Cookie、私人截图或完整本机环境转储。
