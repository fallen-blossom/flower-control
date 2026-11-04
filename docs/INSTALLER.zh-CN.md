# 用 0.1.0 离线安装器安装与卸载

[English](INSTALLER.md)

**0.1.0 正式发行准备中，尚未公开对应 Setup 与发行资产。** 当前已公开的 preview.3 Release 仍只有源码 ZIP。本文按实际安装器说明正常流程，不把版本号、旧候选或一条退出码当成已完成验收。

正式发布后，从[本仓库 Releases](https://github.com/fallen-blossom/flower-control/releases)的 **0.1.0** 下载 `FlowerControl-Setup.exe` 和 `SHA256SUMS.txt`。源码开发者使用 `flower-control-0.1.0-source.zip`；完整载荷 `FlowerControl-offline-win-x64.zip` 不代替 Setup 向导。资产未出现前不要猜 exe 下载链接。

最终 0.1.0 匹配包的本机安装、宿主信任、真实控制、升级恢复和卸载仍待主线程验证记录；干净或另一台 Windows 未执行时不宣称通过。编码器固定构建与源码材料已核验，全包最终清单与二进制公开发行审查仍待完成；[私密漏洞报告](https://github.com/fallen-blossom/flower-control/security/advisories/new)已启用。[源码开发路线](INSTALL.zh-CN.md)单独保留。

0.1.0 选择**未签名发行**。请从[官方 GitHub Releases](https://github.com/fallen-blossom/flower-control/releases)取得文件，核对 `SHA256SUMS.txt`，并查阅匹配源码、依赖构建输入和构建说明。这些信息用于核对发布文件身份；SHA 校验不等于公信发布者签名。Windows 可能显示未知发布者，UAC 需要你人工判断并确认。Flower 不添加信任根，也不要求关闭 Windows 保护；最终产物记录保持 `signed: false`。

## 录屏编码器与对应源码材料

本候选使用由固定 FFmpeg、x264、zlib 源码独立构建的 FFmpeg 8.1.1-flower-minimal-1，保留本地 PNG 帧拼接、尺寸补齐和 H.264/MP4 录屏路径，禁用网络协议。`ENCODER.json` 固定编码器、原始许可/notice 与匹配源码 ZIP 的摘要。构建器会拒绝变化或缺失的材料，不会另行下载编码器替代。

离线载荷在 `Payload/Notices/encoder` 内附这些材料，包括 `flower-ffmpeg-8.1.1-minimal-1-corresponding-source.zip`。Setup 的维护材料流程将其保存在 `<Root>\Packages\<本机实际维护子目录>\Help\Notices\encoder`，方便离线查阅。源码 ZIP 包含完整上游源码归档、构建配方、配置与原始组件/GCC/MinGW 运行时 notice，不含编码器可执行文件；普通用户无需自己编译。开发者可查阅[可移植的离线编码器构建说明](../tools/encoder_build/README.md)与[固定输入清单](../tools/encoder_build/inputs.lock.json)。

材料摘要和短合成帧录制/解码比对，不代表大小上限行为、真实前台录屏、宿主信任或完整安装器验收已通过。保留许可与分发范围见[第三方说明](../THIRD_PARTY_NOTICES.md)。

## 另一台电脑怎么开始

需要 Windows 11 x64、Codex 桌面版；要用 Web 时还需要已安装的受支持 Brave、Edge 或 Chrome。普通用户使用完整离线安装器，不需要安装 Python、.NET SDK、Visual Studio 或自己编译。安装器只使用内置载荷，不会偷偷下载依赖；Codex 模型服务和你打开的网站仍按各自规则联网。

先把实际安装器放到本地，核对维护者提供的 SHA-256。示例文件位置是 `D:\Downloads\FlowerControl-Setup.exe`；这只是示例，请使用你收到的真实路径。启动它只需在普通 PowerShell 执行：

```powershell
Start-Process -FilePath 'D:\Downloads\FlowerControl-Setup.exe' -Wait
```

也可用 `Start-Process -FilePath 'D:\Downloads\FlowerControl-Setup.exe' -ArgumentList '--install-root','D:\FlowerControl' -Wait` 预填安装根。窗口仍会显示实际检查和权限确认；检测到已有安装时沿用其真实位置。

校验命令是 `Get-FileHash -LiteralPath 'D:\Downloads\FlowerControl-Setup.exe' -Algorithm SHA256`，结果必须与随同这份候选提供的校验和一致。来源或校验不明时先停下，不关闭系统安全功能来硬跑。

## 安装窗口里做什么

1. 以日常 Windows 账号运行。安装器先在本地解包、核摘要，并读取本机受保护安装登记。
2. 新安装在**已存在的受保护父目录下**选择一个尚未创建的专用目录，例如 **D:\FlowerControl** 或 **C:\Program Files\FlowerControl**，由安装器建立受保护根。可编辑位置或选择父目录；不要先建普通用户可写的空根，也不要选 Downloads/Documents、网络目录、junction 或可被普通用户替换的中间目录。已有未受保护目录会在提权前拒绝，不接管其 ACL。
3. 勾选要生成的宿主接入。Codex 入口默认提供；DSH 需要选择这台电脑实际安装的 `DeepSeek Harness.exe`，不沿用另一台机器的宿主路径或身份。
4. 检查目录和计划，再点击安装。需要你自己确认一次 Windows UAC；取消会保留已准备材料，不代你批准管理员权限。
5. 等待安装文件、实际执行器连接和设置打开请求的各自结果。**文件安装成功不等于插件已启用，也不等于真实窗口已经操作成功。** 保留安装器最后显示的回执与恢复材料路径。

如果检查提示目录所有者或上级权限不满足保护条件，换一个受保护本地卷下的新目录；可用盘的条件不同，不要只换同一盘中的文件夹名字。某些新卷经 Windows 存储服务格式化后，盘根所有者是 `NetworkService`，也会被拒绝。安装器不会自动接管整盘。没有合适的数据盘时，可使用 `C:\Program Files\FlowerControl`；已有安装仍沿用原登记根。不要为通过安装而给普通用户扩大系统目录权限。

新布局如下：

```text
D:\FlowerControl\
  Program\   程序、运行时、版本、权限与受保护恢复记录
  Data\      设置、浏览器资料与本地状态
  Cache\     大缓存和临时作业材料
  Packages\  版本化的安装与维护材料
```

新安装没有旧权限文件时默认 **02 普通控制**；已有安装保留实际档位、数据根、Stop 和未完成记录。安装器检测到已有安装后固定显示其真实根，按更新流程处理，不把在 D 盘下载的包冒充已迁到 D 盘。

程序、运行时、资料和大缓存按所选根落盘。Windows 的 UAC、注册表及卸载登记仍由系统管理，Codex 等宿主自己的插件缓存/配置仍由宿主管理；.NET 单文件启动和 Setup 的载荷解包还会在 Windows TEMP 使用临时空间，系统盘常见为 C 盘。**本版不承诺完全零 C 盘字节。** 不要在系统临时空间不足时反复重装。

## 在 Codex 中信任并启用

安装器会尝试并核验本地市场登记，实际来源位于 `<Root>\Program\integrations\codex\<version>`。先看安装结果：

- 显示“已核实 Codex 本地市场注册”时，直接进入 Codex 插件界面安装/启用 Flower Control，无需重复执行命令。
- 登记未完成时，保留回执和显示的准确市场路径，按[排障说明](TROUBLESHOOTING.zh-CN.md)检查宿主安装。只有需要手动登记且本机官方 CLI 可用时，才使用准确路径，例如：

```powershell
codex plugin marketplace add '<安装器显示的实际本地市场路径>'
```

`codex` 命令只有在 CLI 位于 PATH 时才能直接运行；桌面版内置 CLI 不在 PATH 不等于 Flower 程序安装失败，也无需因此安装 Python、SDK 或编译器。不要猜旧 CLI 路径或覆盖来源不明的登记。

市场登记不会自动授予权限。在 Codex 插件界面找到 Flower Control 并安装/启用；在 `/hooks` 或宿主显示的 Hook 审查中核对这次准确命令并由你信任。安装或启用插件不会自动信任 Hook，见 [OpenAI 官方说明](https://developers.openai.com/plugins/build/plugins)。

不要手写旧版本路径，不要把“市场已登记”当成“当前聊天已加载”。先建新聊天，让 Codex 报三个 status、loaded/on-disk source 和实际普通执行器。在 02 下 High 能力不可用是正常结果。

## 装完怎么用

安装器的“使用说明与 AI 提示词”会打开本地开始说明。完整中英教程随载荷保存于安装后的 `<Root>\Packages\<实际维护子目录>\Help\Guides`，安装前也可从已解包材料的 `Guides` 阅读；其中 `docs\USAGE.zh-CN.md`、`docs\PERMISSIONS.zh-CN.md` 和 `docs\TROUBLESHOOTING.zh-CN.md` 可直接用记事本打开。查基本使用和卸载方法无需再下载源码。

先亲自打开一份空白记事本文档，然后在新聊天发送：

> 先检查 Flower 三通道状态，确认当前是 02 普通控制且没有 Stop。列出记事本候选，让我辨认刚创建的空白文档，再绑定。绑定后输入“Flower 测试成功”并读回；不保存、不关闭。结束 App 和 Computer 控制并释放按键，保留文档和文字。

再试公开网页：

> 用 Flower 临时浏览器打开 https://example.com，读取标题和主标题。结束后只关闭这次临时会话，不动其他窗口。

候选列表中的标题/进程用于你辨认；设置里的名单选择器不是聊天的目标绑定。登录、密码、验证码和系统 UAC 由你处理。完整流程与 finish 含义见[使用说明](USAGE.zh-CN.md#安装后第一次使用)。

## 停止、设置与资料维护

- **Ctrl+Alt+9**、HUD Stop 和“停止 Computer Use”只结束 Computer 输入。
- **Ctrl+Alt+Shift+9** 或设置/托盘的“紧急停止全部 Flower”是独立的全通道停止。快捷键注册失败会在状态/诊断中显示，不要假定它必定可用。
- 全局继续需要你明确选择恢复；改档位、重新启动和 finish 都不自动清 Stop，不重放 unknown。
- 设置的诊断页提供只读自检、脱敏诊断导出、普通设置备份/草稿导入和空间分类。名单导入后允许规则禁用，审阅后 Ctrl+S；浏览器/语言是独立保存。密钥、Cookie、聊天和 live grants 不在普通备份内。
- 空间清理先列精确候选再确认，只回收受支持的旧缓存；不会把浏览器资料、执行台账和 recovery 当缓存。

## 更新或安装失败

有旧安装时让 Setup 读取真实根和版本；不要另选空目录绕过原状态。更新准备会先导出不含密钥/授权的普通设置备份，保留原数据和恢复材料；正常空闲的旧角色使用有界正常退出与回执核验。

失败时保留 Setup 显示的准确工作目录、原计划和回执。安装窗口可接回同一个待核计划；已消费阶段或结果未知的动作不能重新生成一个新计划来盲重放。目录漂移、身份变化、忙请求和 unknown 阻塞需要先只读核对。自动回滚/恢复的实际结果以回执为准，不能只看退出码。若旧版本不能通过受支持的维护协议接续，先让维护者给匹配迁移路径。

更新不会替你清 Stop、撤销拒绝、启用 03/04、消费 pending 管理员消息或重新授权个人资料。

## 卸载

完成安装维护登记后，在 **Windows 设置 → 应用 → 已安装的应用 → Flower Control → 卸载**。也可运行本机准确版本的维护程序：

```powershell
Start-Process -FilePath 'D:\FlowerControl\Packages\<本机实际维护子目录>\FlowerControl-Maintenance.exe' -ArgumentList '--uninstall' -Wait
```

系统应用列表已指向准确维护入口；`<本机实际维护子目录>` 不是发行版本 `0.1.0` 或可照抄的占位符。请使用安装器或本机卸载登记给出的准确路径。维护程序先核登记、精确程序文件/进程/任务和宿主入口，再显示清单、大小、保留范围与阻塞，等你确认后执行。它正常停止准确匹配的 Flower 实例，不强杀未知进程；只移除仍与登记值一致的宿主配置。

默认**保留 Data、Cache，以及 Program 内的 permissions、privacy、work-authority、audit、execution-bindings、recovery**，包括个人登录资料、设置、Stop/unknown、权限与恢复证据。程序文件走 Windows 回收站，失败不改永久删除。被占用、未知身份或未知结果会阻止/保留相应项。不要为了卸载顺利而先清这些记录。

新布局完成卸载后，可选择“审阅保留的个人资料…”。它在普通权限下重新盘点该安装的准确 Data/Cache，显示路径、文件数与大小；第二次确认后才将清单文件移入回收站。取消就保留，空目录和上述 Program 保护记录仍留存；占用、链接、内容变化、新安装或未确认结果会停止清理，部分结果有独立回执，不能盲目续删。旧布局不自动清个人目录，需先单独核对。

这不会清除 Windows Credential Manager、宿主缓存或任务另存的成果，也不是安全擦除。只有插件时可在宿主移除 Flower Control，但这不会代替卸载助手和自启动。不要递归删除整个安装根。
