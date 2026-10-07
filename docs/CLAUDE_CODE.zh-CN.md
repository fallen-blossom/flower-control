# Claude Code 接入预览

[English](CLAUDE_CODE.md)

Claude Code 的源码接入已经写好，**尚未构建、测试或安装**。Web、App、Computer 复用现有 Flower 实现。当前范围是同一台 Windows 上的官方原生 Claude Code；npm／Node、WSL、Claude Desktop 和云端 agent 暂未接入。

## 先准备什么

需要当前原生 Claude Code、Flower 源码、CPython 3.14 x64、.NET 10 SDK，以及一个可为自己批准 UAC 的 Windows 账号。Web 接受 Chromium 内核的 Brave、Chrome、Edge（Brave 已验证，Chrome、Edge 待验证）。基本依赖和原生构建步骤见 [Windows 安装教程](INSTALL.zh-CN.md)，构建前设置 DOTNET_CLI_TELEMETRY_OPTOUT=1。Claude 的模型服务及隐私设置由 Claude 管理；Flower 没有加入遥测。

源码应在普通本地目录，不能直接使用开发 worktree 的 Junction 作为安装源。先从官方安装来源确认 claude.exe 的实际路径；不要给其他程序改名，也不要拿 node.exe、claude.cmd 或 WSL 入口代替它。

## 生成 Claude 专用配置

下面是后续启用时使用的命令，本次交付没有执行。先依照安装教程构建 native 和 app，保留各自的源码／二进制记录。包目录和插件输出目录必须是新目录。

```powershell
$flowerPython = Join-Path (Get-Location) '.venv\Scripts\python.exe'
$flowerClaude = (Get-Command claude.exe -CommandType Application -ErrorAction Stop).Source
& $flowerPython -B -m tools.prepare_high_broker_install --native-bin .flower-build\native --app-bin .flower-build\app --native-build-evidence .flower-build\native-evidence.json --app-build-evidence .flower-build\app-evidence.json --claude-image $flowerClaude --output .flower-build\install-claude
if ($LASTEXITCODE -ne 0) { throw 'Flower package preparation failed.' }
& $flowerPython -B -m tools.configure_claude_plugin --package .flower-build\install-claude --output .flower-claude-plugin
if ($LASTEXITCODE -ne 0) { throw 'Flower Claude configuration failed.' }
```

生成器只写本地文件，不安装助手、不启动 Claude、不编辑 ~/.claude 或 Codex 配置。它生成 .claude-plugin/plugin.json、.mcp.json、hooks/hooks.json 和一份操作 skill。MCP 入口绑定接收方自己准备的固定助手；Hook 使用该源码的本地 Python。源码仓库里的生成器位于 release/github/tools，开发者从仓库直接调用时还要明确传 --source-root 指向实际源码根；公开源码包里它位于 tools，可直接使用上面的命令。

若尚未安装 Flower，审查固定包后按安装教程安装此次准备的助手并启动任务。**已有 Flower 安装时，不运行首次安装脚本覆盖**；由现有更新流程正常暂停、排空和安装固定新包。不能为兼容而强杀无关应用、清空旧记录或删除哈希。

随后在源码根的普通 PowerShell 中启动本地插件：

```powershell
claude --plugin-dir .flower-claude-plugin
```

这条命令是接收方可选择的本地加载路线，不把插件提交到任何商城。Claude 的 `/mcp` 可查看服务器，`/hooks` 可查看 Hook；正常工具审批仍生效。加载插件不会自己获得私人浏览器授权或控制任何窗口。

## 用起来是什么样

在 Claude 中直接说要做什么，例如读取公开网页、填写测试表单，或操作你选定的软件窗口。Flower Web 操作 Brave 网页元素；App 操作软件提供的桌面控件；Computer 看所选窗口截图后操作鼠标键盘。优先使用能读出具体元素的通道，画布和视觉位置操作交给 Computer。

AI 专用 Brave 环境按已有规则供 agent 使用；你的个人浏览器环境需要在这个 Claude 聊天里单独批准。Codex 的个人环境授权不会自动带进来。Claude 子代理按实际 Hook 报告的 session 归属处理，不凭提示词继承其它聊天权限。登录办法见 [浏览器与登录](BROWSER_PROFILES.zh-CN.md)。

Ctrl+Alt+9 立即停止 Flower 写入；恢复和未知动作查询沿用现有机制。Jev 是同一套可选功能：启用后仍只处理获准的短目标与候选，不需要主模型逐步复核机械动作。

## 常见衔接问题

如果来源未关联，先看三服务器是否来自同一固定版本、Claude Hook 是否启用，以及真实工具名是否包含 plugin_flower-control 前缀。不要手工补 flower_origin。若在第一次工具审批页面停留太久，来源凭据可能过期；只有确认返回的是来源过期且尚未派发，才发起新的调用。结果未知的业务动作先查 action_id，不能直接重放。

Claude 升级改变了 exe 哈希后，需要重新核对并准备宿主清单；移动 Flower 源码或修改控制程序也需重新准备对应固定包。不要将整个目录、通用 Python 或 Node 设为允许来源。

本轮只是源码适配，因此没有“Claude 已经通过实测”的结论。安装、实际工具发现、首次审批和前台操作仍是后续工作，当前不需要为这份源码重启。

官方入口：[Claude 插件加载](https://code.claude.com/docs/en/plugins)、[MCP](https://code.claude.com/docs/en/mcp)、[Hook 参数改写](https://code.claude.com/docs/en/hooks)。
