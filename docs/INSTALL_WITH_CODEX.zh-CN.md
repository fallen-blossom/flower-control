# 在另一台电脑安装，并让 Codex 帮你核实

[English](INSTALL_WITH_CODEX.md)

0.1.0 正式版正在准备，最终 Setup、SHA-256 与匹配验收仍待发布。当前公开的 preview.3 是源码 ZIP。正式发布后先从[本仓库 Releases](https://github.com/fallen-blossom/flower-control/releases)选择准确 0.1.0 的 Setup 和校验和；本页不虚构尚不存在的二进制链接。

## 已取得实际 Setup.exe

在 Windows 11 x64 装好 Codex 桌面版。完整候选自带运行时，不需要 Python、.NET SDK 或 Visual Studio。先核真实文件与维护者随同提供的 SHA-256，再用普通 PowerShell 一条命令启动：

```powershell
Start-Process -FilePath 'D:\Downloads\FlowerControl-Setup.exe' -ArgumentList '--install-root','D:\FlowerControl' -Wait
```

路径换成你收到的实际文件；在窗口中选 `D:\FlowerControl` 等专用根。没有实际包/校验和时先报告缺口，不猜 Release exe 链接。步骤、临时 C 盘占用和卸载见[安装器指南](INSTALLER.zh-CN.md)。

给那台 Codex 的安装提示词：

```text
请在这台Windows11 x64安装并验证我实际收到的Flower 0.1.0离线安装器。
安装器：D:\Downloads\FlowerControl-Setup.exe；目标根：D:\FlowerControl。
使用我随该文件提供的SHA-256；没有校验和就先报告，别猜下载链接。
先读INSTALLER、PERMISSIONS和USAGE，核真实文件/摘要/已有安装。完整候选不需要给我装Python、.NET SDK或编译器，不偷偷下载另一个载荷。
我允许本地准备、安装Flower、生成我选择的Codex接入和无害验证。Windows UAC、插件启用和/hooks信任由我亲自确认，请标明准确对象和界面。不改安全软件，不复制别台电脑的凭据、Cookie、授权或宿主身份。已有安装沿用真实根/数据，失败保留同一计划与回执，不重放unknown或消费pending管理员消息。
新安装核02普通控制，已有档位保留。宿主启用/信任后，新聊天检查三通道实际加载与Medium执行器；注册/握手不等于加载或真实控制。
我开空白记事本，你列候选让我辨认再绑定，输入“Flower测试成功”并读回，不保存不关闭；临时浏览器读https://example.com标题。finish App/Computer并释放按键/控制提示，保留文档，只关闭本次明确临时会话。
最后给实际版本、真实结果、未完成项、两个停止快捷键的范围，以及准确Windows应用/Packages维护卸载入口；默认保留Data/Cache和Program保护记录。新布局卸载成功后若要回收个人Data/Cache，先显示准确清单再另行让我确认，不递归删根。
```

## 只有源码，准备自行构建

以下是源码开发路线，需要 Git 和编译环境。用日常 Windows 账号操作，完整手动命令见[源码教程](INSTALL.zh-CN.md)。先核 checkout 的工具：preview.3 原 tag 不含本批尚未发布的新安装器成果。

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

我允许安装本项目必需的官方依赖，并在本机构建、安装 Flower 助手和本地 Codex 插件。检查 Git、Codex CLI、CPython 3.14 x64、.NET 10 SDK、Visual Studio C++ 工具链，以及源码、编译器、TEMP 和安装包的 ASCII/本地路径要求。复用已有工具，缺项从官方发布方获取，使用锁文件，不为了变绿重生成锁。已有 Flower 先读实际版本/根/Stop/未知状态，核当前 checkout 的更新工具，不能用首次安装覆盖。

按 INSTALL 顺序执行，保留 PowerShell 变量，先建构建父目录，使用全新输出和证据路径，固定正确的数据根；源码分支插件在文件安装并登记后生成。每步核退出码，失败先定位，不接着安装。记录稳定的安装包、Disable.ps1 和卸载准备入口，不搬别台机的凭据、资料或授权。

Windows UAC 和 Codex /hooks 信任让我亲自确认，告诉我具体界面和按钮；正常检查、构建和准备由你继续完成。不启用无关外部服务或修改安全软件。

安装后让我在托盘设置手选 02 普通控制，讲清实际档位立即生效、名单等草稿另存。在新聊天核对三通道实载，再按 USAGE 做真实小试：我开空白记事本，你列候选让我辨认后绑定，输入“Flower 测试成功”并读回；临时浏览器读取 https://example.com 标题。结束 App/Computer 控制、释放按键与提示，保留文档，只清本次明确创建的临时会话。

最后报告实际安装/加载版本、真实操作结果、未完成项、设置与停止恢复方法、三个日常任务例句，以及停用脚本和移除插件的方法。status 成功不能冒充真实输入成功。
```

另一台电脑的构建和真实操作仍需在那里执行。保留不含私密内容的错误证据，按[排障](TROUBLESHOOTING.zh-CN.md)处理。停用、移除插件和完整删除的区别见[安装教程第 9 节](INSTALL.zh-CN.md#9-停用或移除)。
