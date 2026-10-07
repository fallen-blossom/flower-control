# 安装 Windows 源码预览版

[English](INSTALL.md)

当前开发机的安装和受影响小试已经完成；换一个干净 Windows 账号或电脑从头安装，仍是正式发布前需要补的一项。这份教程是已核对的源码安装路线，不把它称作已经验完的一键安装器。

## 先准备什么

使用 Windows 11 x64、当前 Codex 桌面版、[CPython 3.14 x64](https://www.python.org/downloads/windows/)和 [.NET 10 SDK x64](https://dotnet.microsoft.com/download/dotnet/10.0)。Web 通道另需标准系统路径安装的 Chromium 内核浏览器（例如 `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe` 的 Brave）；Brave 已验证，Chrome、Edge 已接受但待验证。App 和 Computer 操作选定的 Windows 窗口，不限于某一种浏览器。当前主要验过 Microsoft Store 的 Codex 宿主。你的 Windows 账号应能给自己批准 UAC，不能用另一个管理员账号代装后假定身份相同。

源码放普通本地文件夹，不用 Junction 或网络盘，装好后不要移动。无需 Docker、WSL、托管浏览器或 Flower 云账号。

在安装或运行 .NET SDK 前，先在启动它的 PowerShell 里设置：

```powershell
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
```

这是关闭 SDK 自己的遥测，[Microsoft 有明确说明](https://learn.microsoft.com/en-us/dotnet/core/tools/telemetry)。依赖下载仍会访问 PyPI 和 NuGet。

## 普通权限下构建和准备

在源码根目录打开 PowerShell，依次运行。任何一步失败都先停下，不删哈希、不重新生成锁文件来凑过关。

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

输出目录必须是新的。最后两步只生成文件，不安装、不提权、不注册任务，也不写 Codex 配置。它会按你自己的路径生成 MCP 与 Hook，不需要开发者电脑的盘符和用户名。

## 管理员助手怎么装

助手负责 Windows 输入和管理员窗口访问，Codex 本身不用以管理员身份运行。安装写入 `%ProgramFiles%\FlowerControl\HighHelper` 的版本目录，设置文件权限，注册“当前账号交互登录时，以最高可用权限运行”的任务；不是 SYSTEM 服务，也不关闭 UAC、Defender 或防火墙。

先查看 `.flower-build\install` 里的 `broker.json`、`task.xml`、`active.json` 和安装脚本，再运行：

```powershell
$flowerApply = (Resolve-Path '.flower-build\install\ApplyInstall.ps1').Path
$flowerInstaller = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile', '-File', ('"' + $flowerApply + '"'))
if ($flowerInstaller.ExitCode -ne 0) { throw 'Flower helper installation did not complete.' }
$flowerPreparation = Get-Content -LiteralPath '.flower-build\install\preparation.json' -Raw | ConvertFrom-Json
Start-ScheduledTask -TaskName $flowerPreparation.task_name
```

Windows 会弹 UAC，点“是”。这是首次安装入口，发现已有安装或同名任务会拒绝覆盖。如果仅注册任务失败，保留原包，按生成的说明核对后用 `-CompleteTaskRegistration` 续完，别清浏览器或动作数据库。

## 在 Codex 里安装插件

```powershell
codex plugin marketplace add .\.flower-local
codex plugin add flower-control@flower-control-local
```

这是本地插件来源，不是上传公共目录。[官方插件文档](https://developers.openai.com/plugins/build/plugins#add-a-marketplace-from-the-cli)说明了这个区别。

在 Codex 中查看并信任生成的 Flower Hook 定义。安装不等于自动信任 Hook；它只关联当前聊天，不给个人环境授权。未启用时来源检查会拒绝调用。[官方 Hook 与信任说明](https://developers.openai.com/plugins/build/plugins#bundled-mcp-servers-and-lifecycle-hooks)。

新开一个 Codex 聊天，让它核对三个 Flower 状态、来源探针、源码是否一致和助手是否准入。再在测试窗口做一个无害操作，核对结果。只握手成功不能说明实际控制成功。

旧聊天可能保留旧连接，先试新聊天，必要时正常重开 Codex；通常不用重启 Windows。

## Jev 可选

新安装默认关闭。它由服务提供者另外计费，不属于 Codex 额度。你愿意发送短目标和候选文字时再启用，密钥只在自己的终端输入：

```powershell
& $flowerPython -B -m flower_control.control.jev_setup enable
& $flowerPython -B -m flower_control.control.jev_setup status
& $flowerPython -B -m flower_control.control.jev_setup disable
```

`enable` 会隐藏输入并写入当前用户的 Windows Credential Manager。`disable` 停止新决策，不删除已经保存的密钥。关掉 Jev，基础三个控制通道仍可使用。

## 停止、更新和停用

紧急停止用 **Ctrl+Alt+9**，也可点 Stop。之后明确让当前聊天继续，重新观察再执行。托盘可停止／恢复全部写入，或正常退出助手。

当前预览版手工更新。先结束任务、暂停并正常退出旧助手，保留旧包和状态，再为新源码准备包；不能把首次安装脚本当更新器，也不能只换 MCP 路径。

停用自启动并请求正常退出时，用上面同样的 UAC 启动方法运行生成的 `Disable.ps1`，看 `instance_stopped` 是否为真。然后可以运行 `codex plugin remove flower-control@flower-control-local` 卸载插件。浏览器和动作数据保留，只有你决定删除时才清理。
