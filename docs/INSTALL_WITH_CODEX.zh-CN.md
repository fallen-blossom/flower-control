# 让另一台电脑的 Codex 帮你安装

[English](INSTALL_WITH_CODEX.md)

适用 Windows 11 x64。先装好 Codex 桌面版和 Git，用日常 Windows 账号操作。下面获取当前 main 的源码与修订教程；完整手动命令见[安装教程](INSTALL.zh-CN.md)。

## 取源码

在普通 PowerShell 中执行。这里用 C:\Tools 举例，也可以换成有写权限的 D:/E: 英文目录。目标目录必须不存在，保留已有检出：

```powershell
git clone https://github.com/fallen-blossom/flower-control.git C:\Tools\flower-control
if ($LASTEXITCODE -ne 0) { throw 'Clone failed; inspect the error before continuing.' }
Set-Location C:\Tools\flower-control
git log -1 --oneline
```

在那台 Codex 中打开此文件夹，新建聊天，发送下面提示词；路径请改成实际目录。

## 安装提示词

```text
请在这台 Windows 11 x64 电脑安装并验证 Flower Control。
源码目录：C:\Tools\flower-control

先读 README.zh-CN.md、docs/INSTALL.zh-CN.md、docs/PERMISSIONS.zh-CN.md、docs/USAGE.zh-CN.md。以当前检出为准，实际完成工作，不只复述教程。

我允许安装本项目必需的官方依赖，并在本机构建、安装 Flower 助手和本地 Codex 插件。检查 Git、Codex CLI、CPython 3.14 x64、.NET 10 SDK、Visual Studio C++ 工具链，以及源码、编译器、TEMP 和安装包的 ASCII/本地路径要求。复用已满足要求的工具，缺失依赖从官方发布方获取，使用锁文件。若这台机已装 Flower，先报告版本与更新路线；此公开快照没有完整在线更新流程，不能用首次安装覆盖。

按 INSTALL 顺序执行，保留 PowerShell 变量，先建构建父目录，使用全新输出和证据路径，固定正确的数据根。每步核退出码，失败先定位，不接着安装。记录稳定的安装包及 Disable.ps1 路径，别搬另一台机的产物、凭据、资料和授权。

Windows UAC 和 Codex /hooks 信任让我亲自确认，告诉我具体界面和按钮；正常检查、构建和准备由你继续完成。不启用无关外部服务或修改安全软件。

安装后让我在托盘设置手选 02 普通控制，讲清实际档位立即生效、名单等草稿另存。在新聊天核对三通道实载，再按 USAGE 做真实小试：我开空白记事本，你列候选让我辨认后绑定，输入“Flower 测试成功”并读回；临时浏览器读取 https://example.com 标题。结束 App/Computer 控制、释放按键与提示，保留文档，只清本次明确创建的临时会话。

最后报告实际安装/加载版本、真实操作结果、未完成项、设置与停止恢复方法、三个日常任务例句，以及停用脚本和移除插件的方法。status 成功不能冒充真实输入成功。
```

另一台电脑的构建和真实操作仍需在那里执行。保留不含私密内容的错误证据，按[排障](TROUBLESHOOTING.zh-CN.md)处理。停用、移除插件和完整删除的区别见[安装教程第 9 节](INSTALL.zh-CN.md#9-停用或移除)。
