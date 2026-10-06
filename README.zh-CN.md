# Flower Control

[English](README.md)

[下载源码预览版](https://github.com/fallen-blossom/flower-control/releases/tag/v0.1.0-preview.1) · [安装教程](docs/INSTALL.zh-CN.md) · [浏览器登录](docs/BROWSER_PROFILES.zh-CN.md)

让 Codex 帮你操作网页和 Windows 软件：填表、读文档、选菜单、上传文件，以及点击、打字和拖拽。

把 Flower 装进 Codex 后，告诉它要做什么、使用哪个窗口或浏览器环境即可。它提供三种工具：**Web 操作网页元素，App 操作桌面控件，Computer 看截图后操作鼠标和键盘。**

![Flower 图标](assets/branding/flower-petal/flower-petal-256.png)

## 能做什么

| 工具 | 怎么操作 | 适合做什么 |
| --- | --- | --- |
| **Web** | 读取网页文字、链接、按钮和输入框，通过 Playwright 直接操作这些元素 | 查资料、填网页表单、编辑在线代码、切标签页、上传和下载文件 |
| **App** | 读取 Windows 软件提供的控件名称、内容和状态，通过 FlaUI／Windows UI Automation 操作 | 填桌面表单、改设置、选长列表项目、用菜单、处理所选软件的弹窗 |
| **Computer** | 截取所选窗口，看图确定位置，再发送鼠标和键盘输入 | 绘图、拖拽、画布、快捷键，以及控件读不出来的界面 |

例如，Web 填网页表单时可以直接找到输入框；App 可以按名称选列表项目或改变复选框；Computer 可以把画布里的物体拖到指定位置，也可以操作你选中的现有浏览器窗口。软件愿意提供控件信息，App 才读得到；读不到时可以改用 Computer 操作可见界面。

Codex 可以在一个任务里组合使用它们，例如先用 Web 编辑网页，再用 App 处理相关桌面弹窗。模型负责理解任务和安排步骤，Flower 提供本地操作能力，并检查当前目标和动作状态。

## 操作提示与可选 Jev

已知顺序的机械步骤可以批量执行，减少模型和工具来回等待。**Jev 是可选的目标选择服务**：接收一个短目标和几项候选文字，选中目标后，Flower 可以在同一次工具调用里直接执行。新安装默认关闭，不启用也能使用三个通道。

**Ctrl+Alt+9 是紧急停止键。** Computer 控制时显示流动边框、耗时文字和 Stop 按钮。停止后重新观察再继续，不自动重放中断的动作。

## 安装与使用

另附 [Windows 原生 Claude Code](docs/CLAUDE_CODE.zh-CN.md)、[反重力 IDE](docs/ANTIGRAVITY.zh-CN.md)和 [Cursor／VS Code／原生 OpenCode 共用接入](docs/LOCAL_CLIENTS.zh-CN.md)的源码及配置生成器。共用入口已做协议检查和助手构建；这些客户端尚未完成真实任务验收或安装。连接模式不开放私人 profile，也暂不支持同一目标跨通道接管。下面的 Codex 实测结果不覆盖这些客户端。

当前准备发布的是 **Windows 源码预览版**。先看[安装教程](docs/INSTALL.zh-CN.md)，再看[浏览器登录教程](docs/BROWSER_PROFILES.zh-CN.md)。主要环境是 Windows 11 x64、当前 Codex 桌面版、CPython 3.14 x64 和 .NET 10 SDK；Web 通道另需标准系统路径安装的 Brave。Windows 10 和其它宿主的验收覆盖较少。

安装时会根据你的 Windows 账号和源码目录生成管理员助手配置，不能直接拿开发者电脑上的固定更新包安装。装好后保留源码目录、Python 和虚拟环境。

直接说任务即可，不需要逐条告诉 Codex 调哪个工具。第一次可以在测试窗口或公开页面试用：

> 用 Flower App 填好我选定窗口里的字段，保存后核对结果。

> 用 Flower 临时浏览器打开这个公开网页，找到我要的信息，做完关闭临时会话。

> 用 Flower Computer 把我选定窗口里的橙色物体拖到蓝色区域。

## 登录环境与隐私

临时浏览器相互独立。AI 浏览器保留自己的登录状态，正常任务可以直接使用。个人浏览器在工具里叫 Luohua／落花，每个聊天需要你授权一次。这三种环境都不会从日常浏览器自动复制 Cookie。要通过 Web 使用已登录账号，先在选定的 Flower 环境登录一次，具体步骤见[登录教程](docs/BROWSER_PROFILES.zh-CN.md)。

Flower **不采集使用统计、不上传崩溃报告、不接收远端配置、不自动更新**。控制状态和浏览器数据保存在本机。Codex 仍使用你配置的模型服务，浏览网页会访问相应网站。Jev 是另行启用的外部 AI 服务，新安装默认关闭；启用后发送获准的短候选文字和目标，不发送原始截图或整棵页面树。完整说明见[隐私文档](PRIVACY.zh-CN.md)。

## 浏览器兼容性

**Web 暂时只支持 Brave，当前为预览版，后续会逐步扩展其他浏览器的兼容性。**

**App 和 Computer 面向普通 Windows 窗口。** 其他浏览器窗口也可以选给 Computer，通过可见界面操作；App 能否读到具体按钮和字段，取决于该浏览器提供的控件信息。这种操作不等于接入 Web 通道，也不会把日常浏览器的 Cookie 导入 Flower。

## 当前限制与测试

网站登录会正常过期，UAC 安全桌面需要本人确认，自定义输入法的英文候选弹窗还需适配。工具说明和教程支持英文，当前助手托盘菜单仍是中文。

实际测试已覆盖表格、文档、绘图、网页编辑和文件交接、桌面列表与弹窗、停止后继续，以及三通道 Jev。一道文档着色题没有达到要求的颜色精度。能说这些工作链做成过，不能推出所有任务 95% 成功，也没有发布 OSWorld 排行榜成绩。见[测试说明](docs/VALIDATION.zh-CN.md)。

## 许可证

Flower 自己的代码采用 [MIT 许可证](LICENSE)。依赖保留各自的许可证，完整依赖和分发说明见[第三方声明](THIRD_PARTY_NOTICES.md)。
