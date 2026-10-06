# 反重力基础接入预览

[English](ANTIGRAVITY.md)

已写好 Windows Antigravity IDE 的源码适配，**尚未构建、测试或安装**。保留能复用的基础控制，复杂的聊天权限以后再做，不需要 Google SDK 或云端转接服务。

## 本轮包含什么

Web 操作临时／AI 专用 Brave 的网页元素；App 操作选定窗口的桌面控件；Computer 截图并操作选定窗口的键鼠。现有批量机械动作、暂停、停止、动作查询、输入释放和可选 Jev 继续复用。Ctrl+Alt+9 是紧急停止键。

**暂不支持个人 Luohua 浏览器及其按聊天授权，也不承诺聊天隔离。** 个人浏览器工具从注册列表移除，调用入口也拒绝。任务范围是本地 MCP 连接：反重力若让多个聊天共用同一连接，目标选择和状态会共享。三个通道分别选择自己的目标。需要不同私人窗口权限的并行聊天暂不适合这版；重连后重新选窗口，未知动作按原 action_id 查询，不自动重放。

## 后续启用步骤

基本 Python／.NET 依赖、native／app 构建和首次助手安装见 [Windows 教程](INSTALL.zh-CN.md)。使用普通本地源码目录，构建前关闭 .NET SDK 遥测。通过反重力官方安装确认 Antigravity.exe 的完整路径；不要把通用 Electron、Python 或 Node 目录作为允许来源。

普通权限下准备固定包时，在原命令后加 `--antigravity-image` 和该 exe 的绝对路径。生成反重力本地插件：

```powershell
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $flowerPython -B -m tools.configure_antigravity_plugin --package .flower-build\install-antigravity --output .agents\plugins\flower-control
if ($LASTEXITCODE -ne 0) { throw 'Flower Antigravity configuration failed.' }
```

这里的 install-antigravity 是事先通过 `tools.prepare_high_broker_install` 准备的新包。可同时给准备命令传 `--claude-image`，一个助手准入这两种明确选择的宿主。插件输出目录须不存在；有旧目录时先审查，不覆盖。生成器创建 plugin.json、mcp_config.json、skill 和配置记录，不安装、不启动、不编辑全局设置。公开源码包生成器在 tools；开发仓库中在 release/github/tools，直接调用需补 --source-root。

如果已经安装 Flower，先按正常暂停、排空、固定包更新流程安装新版本。首次安装脚本不会覆盖已有助手。助手与插件配置应来自同一固定版本。然后让反重力按官方本地插件方式加载 `.agents/plugins/flower-control`；在 MCP 管理器查看三个服务器，在自有测试窗口中选择目标。上述步骤本轮均未执行。

无需配置聊天 Hook。本地连接适配会先通过受保护的管理员助手核验真实 Antigravity 启动链，再补入操作凭据。模型不应填写 flower_origin。来源探针明确返回连接范围，不把它写成真实聊天证明。固定 exe 升级改变哈希后，需要重新核对并准备包。

Flower 不加入遥测、远端配置或自动更新。工具结果仍会进入你配置的反重力模型服务；Jev 仅在单独启用后使用其原有获准数据。详细边界见 [隐私说明](../PRIVACY.zh-CN.md)。独立 Antigravity CLI、SDK、WSL 和云端入口本轮未接入。

官方入口：[本地插件](https://antigravity.google/docs/plugins)、[MCP 配置](https://antigravity.google/docs/mcp)。
