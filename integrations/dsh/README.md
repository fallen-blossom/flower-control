# Flower Control 的 DSH 接入

面向 DeepSeek Harness Desktop `0.2.1-rc.2`，使用其内置 `dsh-mcp-client 0.2.1-rc.2` 和 `Cordis 4.0.5`（在原 `~4.0.4` 范围内）。每个聊天各有 Web、App、Computer 三条普通 MCP 连接；所有连接共用既有一个管理员助手。模型名称不参与权限判断。退出聊天或卸载插件时，DSH 的 MCP 插件关闭自己的连接。

先选择获准的直接 API、CLI、文件、配置或注册表接口，并读回结果；注册表可通过 API、PowerShell 或 reg.exe 操作，不必打开 RegEdit。确实需要界面交互时，先 Web DOM、再 App UIA，只有视觉或坐标缺口才用 Computer。拒绝后不能换通道绕过权限或 Stop。

三通道还通过 MCP 初始化的 `instructions` 发送上述调用原则。当前 DSH 的官方 MCP 客户端会将这段文字加入模型的 systemPrompt；README 和 Codex Skill 本身不能代替这条传递路径。初始化测试只证明文字传输，不保证模型每次都遵守。

先用 `tools/configure_dsh_plugin.py` 从匹配的完整助手准备包生成本机 bundle。Windows Desktop 自带命令位于安装根的 `resources/runtime/cli/bin/dsh.cmd`；它使用同版 runtime 和随附 pnpm，支持管理 Desktop profile。不要只凭 PATH 上的旧 `dsh` 判断现装版本，也不要手改安装 cache。将下方占位符替换成自己的安装目录和准确 bundle：

```powershell
$dshCommand = Join-Path '<你的DSH安装目录>' 'resources/runtime/cli/bin/dsh.cmd'
& $dshCommand --version
& $dshCommand plugin --profile desktop add --offline --ignore-scripts '<准确 bundle 目录>'
```

安装前备份准确 profile 文件，安装后核 package、bundle 选择和真实 Desktop 装载。CLI 管理成功不代表 Desktop 聊天已调用；CLI 启动的聊天也不能冒充 Desktop 的真实 Host 父链。首次安装登记接收方本机 `DeepSeek Harness.exe` 路径及 EXE/ASAR 摘要。同一路径正常更新后，新 EXE 须通过 Windows 信任链和 DeepSeek 发布者身份验证，再由 EXE 签名覆盖的 `ElectronAsar` 资源核对 ASAR 头部及每份打包/解包文件；不自动接受缺失校验信息的更新。正常证书续期不再要求修改叶证书公钥固定值。路径变更和宿主协议变化仍须明确重新配置。

Bundle 用 `insert` 新增 Flower 实例，不能用只修改已有行的普通 patch。注册插件不依赖助手当时的 `status`；每条连接的固定启动入口及后续工具操作仍执行真实来源、ASAR 摘要与权限检查，不恢复 Stop、不改权限。

已有和新建聊天分别挂载三通道；一个通道启动失败会在宿主日志中留下 `flower_dsh_channel_startup_failed`，其余通道和聊天继续启动。插件注册成功不代表所有通道 ready。启动失败只有在该通道完成清理后才自动重挂，500 ms 起指数退避、最长 30 秒、最多 10 次；耗尽后明确记录 `flower_dsh_channel_startup_exhausted`。正常通道不重复创建，已连接通道仍由官方 MCP 客户端按原策略恢复。这些恢复只重新建立连接，不重放工具或输入。关闭聊天、原启动信号取消和卸载会取消定时器并排空各通道；清理失败明确报告并阻止该记录重挂，需在宿主完成清理后重新启用，不能把未确认关闭的连接算作已释放。

聊天身份由真实 Agent 传入固定启动入口。入口核对实际宿主进程链，拒绝经 Shell 或 Python 转接的 DSH 调用；普通 MCP 工具参数不能提供来源凭据。三通道同聊天关联同一任务，Codex 的任务和授权不能被 DSH 继承。

MCP 取消会传到原执行器。等待动作撤回，执行中的动作按已有输入释放合同收尾；状态查询不派发输入，未知结果不自动重试。前台资源使用现有共享排队和公平约束，不增加第二个管理员服务。

DSH 与 Codex 交付同一完整三通道工具表和同一份 Flower Control Skill；DSH 通过官方 skills registry 发现、加载，卸载时由所属 Cordis context 清理。私人浏览器使用同样的每聊天明确授权，管理员执行与 UAC 使用同样的本机委托、来源与实际能力门。既有 Codex 委托不会自动扩给 DSH。配置里的 supported 表示提供同一入口，不代表当前本机档位、04 或授权已可用。截图是否能交给当前 DSH 模型仍需按其图像能力核验；没有新增外部图像服务。完整双宿主验收、正式安装和当前聊天加载是独立证据，不能用源码测试代替。

新版默认 Host 的 pnpm 参数位于 `resources/runtime/primary-runtime/dependencies/pnpm/bin/pnpm.mjs`；旧准确路径和不带 pnpm 的六参数形式保留兼容。它仍须通过已登记摘要或发布者签名与 ASAR 完整性检查、直接父进程、Node 角色和其余准确参数检查。文件保持句柄仅绑定实际宿主实例；确认对应进程退出后释放，以允许正常更新。模板版本声明不会登记或更新本机 NativeHosts；DSH 的插件版本兼容确认也不等于 Flower 的宿主准入。
