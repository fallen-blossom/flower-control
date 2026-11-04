# Flower Control

[English](README.md)

**Windows 11 x64 · 0.1.0 正式发行准备**

Flower Control 让 Codex 操作网页和 Windows 应用。你在聊天里描述任务，Flower 在本机绑定目标、检查权限、执行动作并读回结果。

| 通道 | 适合做什么 |
| --- | --- |
| Web | 受管 Brave、Edge、Chrome 中的网页元素、表单、标签页和文件传输 |
| App | Windows 可访问控件、菜单、列表和对话框 |
| Computer | 指定窗口内的键鼠输入、画布和拖拽 |

## 安装

**0.1.0 Setup 与发行资产尚未发布。** 当前 preview.3 下载仍是源码快照。请查看[官方 Releases](https://github.com/fallen-blossom/flower-control/releases)的实际可用版本，不把旧源码 ZIP 当安装器。

0.1.0 发布后，普通安装顺序是：

1. 从对应 Release 下载 `FlowerControl-Setup.exe` 与 `SHA256SUMS.txt`，用 `Get-FileHash -Algorithm SHA256` 核对文件。
2. 以日常 Windows 账号运行 Setup。新安装可选一个尚不存在的专用根，例如 `D:\FlowerControl`；Program、Data、Cache、Packages 都在根下。Windows 登记、临时解包和宿主缓存仍可能使用系统盘。
3. 审阅计划，自己确认 Windows UAC。安装器包含 Python 和 .NET，普通用户无需编译器；Codex 和受支持浏览器需要已安装。
4. 在 Codex 中安装、启用生成的本地插件，并确认宿主要求的 Hook 信任。市场登记、聊天加载和实际控制会分别核实。

本版选择未签名发行。Windows 可能显示未知发布者；请结合官方资产 SHA、匹配源码与构建输入判断是否运行。Flower 不添加信任根，也不要求关闭 Windows 保护。

完整步骤见[安装器指南](docs/INSTALLER.zh-CN.md)；需要 Codex 协助时用[安装提示词](docs/INSTALL_WITH_CODEX.zh-CN.md)。开发者另走[源码路线](docs/INSTALL.zh-CN.md)。

## 第一次使用

1. 打开花形托盘图标 → **设置**。新安装默认 **02 普通控制**，更新保留原档位。档位按钮立即生效；名单等普通编辑需要 **Ctrl+S**。
2. 新建 Codex 聊天和一份独立的空白记事本文档，发送：

> 检查 Flower 的 Web、App、Computer 状态。列出记事本窗口，让我辨认刚新建的空白文档。绑定后输入“Flower 测试成功”并读回。先不保存或关闭文档；完成后结束控制，释放输入并保留文字。

3. 再试公开网页：

> 用 Flower 临时浏览器打开 https://example.com，读取标题，完成后只关闭本次临时会话。

接着阅读[使用说明](docs/USAGE.zh-CN.md)、[权限](docs/PERMISSIONS.zh-CN.md)和[浏览器资料](docs/BROWSER_PROFILES.zh-CN.md)。先用普通窗口；03 开放管理员窗口，04 另外开放本地名单中的管理员启动。UAC 安全桌面和跨用户提权不属于支持的控制路径。

## 停止与维护

- **Ctrl+Alt+Shift+9** 或托盘/设置中的紧急停止按钮：阻止全部 Flower 通道的新写入，直到你在本机明确恢复。热键注册失败会显示提示，按钮仍可用。
- **Ctrl+Alt+9**、HUD Stop 和 Computer 暂停只影响 Computer 输入；App/Web 保留各自权限边界。
- 停止或遇到未知结果后，先重新观察目标；未知动作不自动重放。

更新使用 Setup/维护入口，保留实际登记根和原恢复材料。设置提供普通偏好备份/草稿导入、脱敏诊断和空间审阅。卸载从 **Windows 设置 → 应用 → Flower Control → 卸载** 开始，先核准确范围，默认保留个人资料、缓存和受保护恢复状态。完成卸载后，Data/Cache 需要另行审阅确认才回收。详见[维护与卸载](docs/INSTALLER.zh-CN.md)。

## 隐私、验证与许可

Flower 不加入遥测、崩溃上传、远端配置或自动更新。个人浏览器资料需要当前聊天明确授权，不导入日常浏览器 Cookie。可选决策服务需要在本机启用；密钥在设置中输入，不交给聊天。

[验证说明](docs/VALIDATION.zh-CN.md)区分源码/隔离检查、编码器测试与最终安装器验收。最终 0.1.0 的安装、真实 High 控制、宿主信任/加载、升级恢复与卸载尚未验证。[版本说明](docs/RELEASE_NOTES.zh-CN.md)介绍本版；历史预览结果保留原版本范围。

普通问题见[排障](docs/TROUBLESHOOTING.zh-CN.md)，安全缺陷使用[私密漏洞报告](https://github.com/fallen-blossom/flower-control/security/advisories/new)。公开报告不要附凭据、浏览器资料或私人截图。

Flower 自有代码采用 [MIT License](LICENSE)。依赖保留各自许可，见[第三方声明](THIRD_PARTY_NOTICES.md)和[依赖清单](dependency-inventory.json)。最小 FFmpeg 录屏编码器附有匹配源码材料与声明，其 GPL 许可不会变成 MIT。
