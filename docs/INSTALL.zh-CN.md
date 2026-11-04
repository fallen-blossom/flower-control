# 在 Windows 安装 Flower Control

[English](INSTALL.md)

这是 **Flower Control 0.1.0-preview.3** 的完整源码预览安装路线。GitHub Release 提供源码和校验和，不提供签名的一键安装器。

开发机上的构建和 Codex 插件流程已经实际使用过；这不等于干净 Windows 账号、第二台电脑和所有第三方应用都已经验收。

## 1. 准备环境

需要：

- Windows 11 x64，源码放在普通本地目录，不要用中文路径。
- 当前 [Codex 桌面版](https://developers.openai.com/codex/)和 `codex` CLI。
- [CPython 3.14 x64](https://www.python.org/downloads/windows/)。
- [.NET 10 SDK x64](https://dotnet.microsoft.com/download/dotnet/10.0)。
- [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)，并安装 x64 桌面 C++ 工具集。
- 当前 Windows 账号能自己确认 UAC。不要用另一个管理员账号代装，再假定助手绑定到了你日常使用的账号。

源码、编译器和输出路径当前都要求 ASCII 字符，不要放在网络盘或 Junction。

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
git checkout v0.1.0-preview.3
```

也可以下载 Release 附带的源码 ZIP。先用 `SHA256SUMS.txt` 核对，再解压到 ASCII 路径。不要从 issue、网盘或第三方镜像下载来路不明的二进制。

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
& $flowerPython -B -m tools.build_daily_payloads native --output "$flowerBuild\native" --evidence "$flowerBuild\native-evidence.json"
& $flowerPython -B -m tools.build_daily_payloads app --output "$flowerBuild\app" --evidence "$flowerBuild\app-evidence.json"
```

如果 Visual Studio 不在标准位置，在 `native` 命令后加 `--compiler-setup <vcvarsall.bat的绝对路径>`。输出和 evidence 路径必须是新的。

原生构建仍在系统临时目录，但管理员助手安装包要放在稳定的本地目录。否则临时目录被清理后，`Disable.ps1` 和后续恢复信息会一起丢失：

```powershell
$flowerPackage = Join-Path $env:LOCALAPPDATA ('FlowerControl\source-install\' + [guid]::NewGuid().ToString('N'))
& $flowerPython -B -m tools.prepare_high_broker_install `
  --native-bin "$flowerBuild\native" `
  --app-bin "$flowerBuild\app" `
  --native-build-evidence "$flowerBuild\native-evidence.json" `
  --app-build-evidence "$flowerBuild\app-evidence.json" `
  --output "$flowerPackage"
```

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

新建 Codex 聊天，先只做只读状态检查：

> 检查 Flower 的 Web、App、Computer 三个 status，列出 registered tools、loaded source、on-disk source 和 high broker。先不要操作目标。

每个通道都确认：

- `registered_tools` 里有预期的 `flower_*` 工具。
- `loaded_source` 指向本次安装的源码目录。
- `on_disk_source` 的哈希和版本与当前文件一致。
- 需要助手时，`high_broker` 显示已连接、源码准入通过、High 控制可用。
- `effective_control` 没有被意外停止或暂停。

再做一个无害小试：

> 用 Flower App 操作我选择的记事本窗口，读取标题和一个控件，然后停止，不要保存文件。

状态探测成功不等于所有目标都能控制。先用临时网页或一次性测试窗口，再接触重要数据。

## 8. 更新已有安装

首次安装脚本不是更新器。保留旧包和状态，准备新包后生成绑定计划：

```powershell
$flowerUpdate = Join-Path $env:TEMP ('flower-update-' + [guid]::NewGuid().ToString('N'))
& $flowerPython -B -m tools.prepare_work_authority_update `
  --package "$flowerPackage" `
  --output $flowerUpdate
```

核对输出和 `plan.json`，再用与首次安装相同的明确 UAC 方式启动生成的 `Update.ps1`。旧计划、复用的 operation id、正在运行的旧助手、源码或身份不一致，都应该被拒绝，不能强行绕过。

不要用首次安装的 `ApplyInstall.ps1` 替换已有助手。

## 9. 停用或移除

生成的 `Disable.ps1` 在稳定的 `$flowerPackage` 目录，位置记录在 `.flower-local\install-package-path.txt`，不会复制进 `%ProgramFiles%`。先读取保存的路径，再通过 UAC 运行：

```powershell
$flowerPackage = Get-Content -LiteralPath .\.flower-local\install-package-path.txt
if (-not (Test-Path -LiteralPath "$flowerPackage\Disable.ps1")) { throw 'Saved Flower package is unavailable; do not delete state to force disable.' }
$flowerDisable = (Resolve-Path "$flowerPackage\Disable.ps1").Path
$flowerStopper = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile', '-File', ('"' + $flowerDisable + '"'))
if ($flowerStopper.ExitCode -ne 0) { throw 'Flower helper disable did not complete.' }
```

保留脚本输出，并要求 `instance_stopped: true`。如果助手状态未知，计划任务仍可能已禁用，但不能因此说实例已停止。如果只是想移除 Codex 插件：

```powershell
codex plugin remove flower-control@flower-control-local
```

这条命令只移除 Codex 插件，**不会**禁用计划任务、停止管理员助手、删除 `%ProgramFiles%\FlowerControl` 下的文件，也不会删除浏览器资料和动作数据。要真正停用 Flower，还要运行 `Disable.ps1`。需要清理数据时先确认精确本地路径，并保留仍要用的内容。

## 这个预览版不承诺什么

- 不是签名的一键安装器。
- 不是干净 PC 无人值守部署。
- UAC 安全桌面自动化当前已冻结。
- 不代表每个 Windows 应用和网站都支持。
- 不会关闭或绕过 Windows 安全机制。

出错时请附上版本、步骤编号、原始错误码、新聊天 status 和最小复现。不要上传凭据、Cookie、私人截图或完整本机环境转储。
