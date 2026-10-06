# 在其他 Windows AI 客户端里使用 Flower

**可选兼容配置，尚未完成客户端实测。主力仍是原来的 Codex 接入。**安装时保留原默认配置，只有需要使用其他客户端才另外生成并导入这里的配置。

本轮补上共用的本地 MCP 接入，避免每换一个客户端就重写控制程序。Web、App、Computer 仍是原来的三个通道：Web 操作 Brave 网页，App 操作 Windows 控件，Computer 使用截图与键鼠。现有 Codex 和原生 Claude Code 的聊天接入保留；其他客户端可使用连接接入。

目前交付的是源码和配置生成器。共用接入已有协议回归和管理员助手构建检查；没有在下面各客户端里完成真实任务，不能把配置候选当成已实测支持。Dot 按用户决定暂不处理。

| 客户端 | 本轮提供什么 |
| --- | --- |
| Codex 桌面版 | 保留原来的聊天绑定和私人浏览器授权 |
| 原生 Windows Claude Code | 复用已有 Hook／插件候选，不做真实客户端测试 |
| Antigravity Windows IDE | 复用原生宿主登记与连接接入 |
| Cursor、VS Code | 各自格式的三通道 MCP 配置 |
| 原生 OpenCode | 分别生成 v1、v2 格式，按实际客户端版本选择 |

Gemini CLI 和经 Node 启动的客户端暂不纳入。把整个 `node.exe` 或 `python.exe` 认作可信宿主，会把其他脚本也放进来；本轮只登记具体的原生客户端 exe。客户端升级后 exe 的摘要变化，需要重新登记和准备助手包。

## 准备与导入

沿用安装教程准备本机管理员助手包，额外给准备工具传入客户端的实际 exe：`--local-mcp-image` 用于 Cursor、VS Code、原生 OpenCode；原有 `--claude-image`、`--antigravity-image` 继续使用。路径和摘要写入固定包，工具不会安装或启动客户端。不能直接使用开发者电脑上的配置或旧助手版本。

然后运行 `tools/configure_connection_mcp.py`，给它准备包目录、一个全新的输出目录和客户端类型：

```powershell
python tools/configure_connection_mcp.py --package <prepared-package> --output <new-output> --client cursor
```

可选类型为 `cursor`、`vscode`、`antigravity`、`opencode-v1`、`opencode-v2`。在源码仓库内运行时再加 `--source-root <repository-root>`；导出的发布目录可使用默认值。它只生成文件，不覆盖已有设置、不装插件、不启动助手。

Cursor 配置在 `.cursor/mcp.json`；VS Code 在 `.vscode/mcp.json`；Antigravity 是 `mcp_config.json`；OpenCode 是 `opencode.json`。通过客户端自己的 MCP 设置导入或合并三个条目，保留你已有的其他服务器。配置指向新助手的 `--flower-connection-client` 入口；旧助手没有这个参数，必须先按正常流程安装相应版本。

## 连接接入有什么差别

普通窗口、临时／AI 专用 Brave、观察、点击、输入、拖拽、动作查询、暂停恢复以及已有的可选 Jev，都复用现有控制程序。客户端无需提供聊天 Hook 或填写来源凭据，服务内部会补入凭据，管理员助手仍检查实际启动来源。

每条 MCP 连接有自己的任务范围，客户端复用连接时不能据此区分内部聊天。**落花私人 profile 不开放**；同一目标暂不从一个通道交给另一个通道，普通窗口和受管 Web 浏览器都遵守这个限制。普通的软件窗口可以走 App／Computer。若换连接，重新选择窗口和观察，不重放结果未知的旧动作。

正常断连会尝试按现有关闭流程收尾这条连接拥有的 Web 会话；AI profile 数据保留。停止、关闭失败和未知结果不会被改成成功。正在等待你登录的窗口会保留，由你正常关闭；这种断连后的未完成登录需要人工收尾，不承诺自动恢复。

首次检查先看 `flower_status` 和来源探针，再用测试网页或测试窗口完成一个小任务。紧急停止键仍是 **Ctrl+Alt+9**。新接入不加入遥测或远端配置；你选用的 AI 客户端仍可能把截图和回执送入自己的模型上下文。Jev 保持已有的单独启用规则。
## 本机 Codex 可选第二入口

原 Flower Control 仍是主力。`codex-compatibility` 生成一个独立的 Flower Control Compatibility 插件，三个 MCP 名称带 `-compat`，使用同一个管理员助手，不带聊天 Hook。它用于尝试连接模式，不能访问个人浏览器，也不提供按聊天隔离或跨通道接管。Dot 云端派发是否会加载本地工具仍待实际核对；换配置不能保证解决宿主的工具加载问题。

已准备固定助手包后，使用 `tools/configure_connection_mcp.py --client codex-compatibility --package <package> --source-root <source> --output <new-directory>` 生成配置。该命令只生成文件；安装需通过 Codex 的插件管理入口。两个入口可以并存，日常继续选原版；试用不成功时卸载 Compatibility 即可。不要让两个入口同时操控同一窗口。
