# 在 Windows 安装 Flower Control

[English](INSTALL.md)

这是 **Flower Control 0.1.0-preview.3** 的完整源码预览安装路线。GitHub Release 提供源码和校验和，不提供签名的一键安装器。

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
dotnet restore .\flower_control\drivers\high_helper\Flower.HighHelper.csproj --locked-mode
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
  --data-root "$env:LOCALAPPDATA\FlowerControl" `
  --native-bin "$flowerBuild\native" `
  --app-bin "$flowerBuild\app" `
  --native-build-evidence "$flowerBuild\native-evidence.json" `
  --app-build-evidence "$flowerBuild\app-evidence.json" `
  --output "$flowerPackage"
```

`--data-root` 固定用户数据根，内部会使用 `state-v1` 等子目录；不要把根写成 `FlowerControl\state-v1`。这也供切换到 01/02 的普通执行器使用。已有安装要保留其原数据根，不能用新目录绕过旧状态。

生成当前用户和当前源码目录专用的 Codex 插件市场：

```powershell
& $flowerPython -B -m tools.configure_local_plugin --package "$flowerPackage" --output .flower-local
$flowerPackage | Set-Content .\.flower-local\install-package-path.txt
```

这一步只写文件，不安装助手、不注册计划任务、不写 Codex 配置，也不授予 Hook 信任。

继续前先检查：

```powershell
Get-ChildItem "$flowerPackage"
Get-ChildItem .flower-local -Recurse
Get-Content -Raw "$flowerPackage\preparation.json"
```

保留准确的 `$flowerPackage` 路径。这里有 `ApplyInstall.ps1`、`Disable.ps1`、计划任务定义、源码快照和 operation 信息。首次安装和后续恢复都不能复用旧包或旧 operation 记录。

## 5. 安装管理员助手

助手安装到 `%ProgramFiles%\FlowerControl\HighHelper`，并注册当前 Windows 账号的交互式计划任务。Codex 本身不需要以管理员身份运行。助手不会关闭 Defender、防火墙或 UAC。

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

```powershell
codex plugin marketplace add .\.flower-local
codex plugin add flower-control@flower-control-local
```

这是本地插件市场，不是上传到 OpenAI 官方插件目录。

打开 Codex，在输入框执行 `/hooks` 打开 Hook 审查，核对准确命令后再信任这一份定义。当前 Codex 也可能在启用插件时给出审查提示。安装插件和信任 Hook 是两件事；未信任时，新聊天会拒绝相关调用。命令路径必须指向这次源码目录及其 `.venv`。官方[插件 Hook 信任说明](https://developers.openai.com/plugins/build/plugins)也明确：安装或启用插件不会自动信任其 Hook。

## 7. 新建聊天做首次验证

安装并启动计划任务后，任务栏右下角应有 Flower 花形托盘图标，可能收在 **^ 显示隐藏图标**中。右键它 → **设置**，在左侧实际档位按钮选择 **02 普通控制**，等“已保存档位”显示 02。档位会立即保存和切换，名单等普通编辑才需要 Ctrl+S；从普通档转 03/04 可能出现需要你确认的 Windows UAC。权限页内的 02/03/04 名单查看层不等于左侧实际档位。

全新、无既有权限文件时默认是 **03 管理员窗口**，不是 02；已有机器沿用原设置，因此请实际看“已保存档位”。初次试用不用配置管理员启动名单、工作授权或可选 AI 决策服务。找不到托盘图标时先检查上述任务启动是否成功，按[排障](TROUBLESHOOTING.zh-CN.md#找不到托盘或无法恢复)处理。

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

如果这台机器装过 Flower，先停止首次安装流程。本公开快照尚未提供完整的在线更新路线：保留 High 连接的更新准备路径引用了未随公开包提供的 `tools.prepare_stopped_host_update`，更新后还需要重新生成和刷新绑定具体版本的本地插件入口。

保留旧包、数据根和当前状态，在[问题页](https://github.com/fallen-blossom/flower-control/issues)提供旧版本及错误码，请维护者给出匹配版本的更新步骤。正常空闲的旧助手应由更新器有界暂停、退出；忙请求、身份变化或 Stop 冲突需要先解决。不要用首次安装的 `ApplyInstall.ps1` 覆盖已有安装，也不要删除状态或先卸载来绕过检查。

## 9. 停用或移除

**本版提供停用脚本和移除插件命令，没有完整的一键卸载器。** 暂时不让 AI 操作可先选 01；想停止后台助手再执行下面的 Disable。它禁用计划任务并尝试正常停止实例，不删除程序文件、浏览器登录资料或动作数据。移除插件也不能代替停用助手。

生成的 `Disable.ps1` 在稳定的 `$flowerPackage` 目录，位置记录在 `.flower-local\install-package-path.txt`，不会复制进 `%ProgramFiles%`。用日常账号通过 Windows 的**以管理员身份运行**打开一个可见的 PowerShell，切到源码根目录，再执行下面命令。窗口保留回执，同时保存一份新日志：

```powershell
$flowerPackage = Get-Content -LiteralPath .\.flower-local\install-package-path.txt
if (-not (Test-Path -LiteralPath "$flowerPackage\Disable.ps1")) { throw 'Saved Flower package is unavailable; do not delete state to force disable.' }
$flowerDisable = (Resolve-Path "$flowerPackage\Disable.ps1").Path
$flowerDisableLog = Join-Path $flowerPackage ('disable-result-' + [guid]::NewGuid().ToString('N') + '.json')
& $flowerDisable | Tee-Object -FilePath $flowerDisableLog
```

回执的 `task_state` 应为 `disabled` 或 `absent`。`instance_stopped: true` 只表示脚本确认了那一个实例退出，不能只凭脚本退出码判断。

**02/01 普通角色下，当前 Disable 脚本只能禁用自启，不能通过 High 管理接口停止普通实例**，可能返回 `instance_stopped: false`。此时在托盘选**退出**，让 Codex 按原助手的精确进程身份只读核实退出；未知就报告未知。退出助手会保留已有程序和成果。如果其他角色也未确认退出，同样先使用托盘退出并核实，不强杀或删状态。

确认停用结果后，回到**普通 PowerShell**移除 Codex 插件：

```powershell
codex plugin remove flower-control@flower-control-local
```

这条命令只移除 Codex 插件，**不会**禁用计划任务、停止管理员助手、删除 `%ProgramFiles%\FlowerControl` 下的文件，也不会删除浏览器资料和动作数据。要真正停用 Flower，还要运行 `Disable.ps1`。需要清理数据时先确认精确本地路径，并保留仍要用的内容。

若要彻底移除，请先完成上述停用和插件移除，保留输出，再让 Codex 盘点已安装版本、精确任务名、稳定安装包路径及用户数据目录，由你决定是否保留资料。此教程不提供递归删除整个 FlowerControl 根目录的命令。

## 这个预览版不承诺什么

- 不是签名的一键安装器。
- 不是干净 PC 无人值守部署。
- UAC 安全桌面自动化当前已冻结。
- 不代表每个 Windows 应用和网站都支持。
- 不会关闭或绕过 Windows 安全机制。

出错时请附上版本、步骤编号、原始错误码、新聊天 status 和最小复现。不要上传凭据、Cookie、私人截图或完整本机环境转储。
