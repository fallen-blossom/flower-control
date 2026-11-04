# Flower Control 排障

[English](TROUBLESHOOTING.md)

先在新聊天里做只读状态检查：

> 显示 Flower Web、App、Computer 三个 status，包括 registered tools、loaded source、on-disk source、high broker、effective control 和最后一个错误码。不要重试失败动作。

Issue 里不要附凭据、Cookie、浏览器资料、私人截图或完整用户目录转储。

## 还没接入宿主，也能查本机状态

候选提供本地只读状态和设置打开入口，不要求先有 Codex MCP 来源。使用安装回执的**实际已安装版本**，在普通 PowerShell 运行；示例中的版本必须替换：

```powershell
& 'D:\FlowerControl\Program\versions\<实际版本>\Flower.HighHelper.exe' --flower-local-status
& 'D:\FlowerControl\Program\versions\<实际版本>\Flower.HighHelper.exe' --flower-local-settings
```

前者只读真实普通/High 执行器状态，后者只请求打开已有设置。不派发业务输入、不清 Stop、不授权聊天或 work；本地连接成功仍不等于宿主已加载。找不到可验证执行器就保留错误，不复制 exe 或改权限/登记硬开。

安装/更新/卸载失败时保留同一计划、回执和恢复目录。诊断页提供显式全量完整性自检、脱敏导出和只重建当前设置窗口的有界修复，不会自动修复授权、删除 unknown 或放行 pending。

诊断时间线保留本次助手运行内最近 256 条状态元数据，界面显示最近 12 条；它不是跨重启的完整逐步任务历史，也不录屏。既有执行/恢复台账继续保留，两者不能互相替代。

## 插件到底加载了吗

确认插件已安装并启用：

```powershell
codex plugin list
```

本地身份应为 `flower-control@flower-control-local`。界面配置数量不等于当前线程工具清单；当前线程必须实际收到三个 Flower 通道工具。旧源码开发生成器只有基本入口，冻结候选带完整 Skill/Hook/图标；核实所用安装路线，不混用两份目录。

插件已安装但新聊天没有 Flower 工具时：

1. 先开新聊天，不要继续旧线程。
2. 确认插件启用。
3. 在 Codex 输入框执行 `/hooks`，核对这次生成的具体命令，再信任这一份定义。
4. 插件目录变化后，正常重开 Codex。
5. 先问三个 status，再操作目标。

## 旧聊天或旧连接

旧聊天可能保留旧 MCP 进程、旧源码路径、旧工具清单或未知目标绑定。于是磁盘上已经是新版本，旧聊天却还像上一版。

安装或更新后先开新聊天，比较 status 里的 `loaded_source` 和 `on_disk_source`。哈希或路径不同，就不要在这个聊天里继续操作目标。保留失败证据后再正常重启 Codex，不要删源码或权限状态来强制刷新。

## 工具名没有路由到

这是宿主侧路由问题，不要一上来归因于 Flower 权限。必须同时记录声明名和实际分发名。

例：

```text
声明:  codex_exec_code（参数 code: "..."）
分发:  unsupported call: exec_code_code
```

按下面排查：

1. 记录客户端版本、provider/adapter 版本、当前线程实际收到的 tools schema 和完整宿主错误。
2. 找到真正拥有工具注册和分发的那一层。不要因为装了 Flower 就先把根因算给 Flower。
3. 检查是否有一段逻辑重复裁剪或拼接 `codex_`、`exec_` 或命名空间前缀。
4. 如果本地 Router 确实拥有这个问题，只添加实际复现到的精确别名；不要写“统一裁掉 codex_”这种通配规则。
5. 给声明名、分发名和成功调用路径补回归测试，再刷新 Router 或开新聊天。
6. 如果根因在官方 Codex 二进制或上游 provider/adapter，提交最小复现、两个准确名字和版本对齐方案。不要改 Hook、权限 router 或换 Shell 绕过。
7. 以后出现另一种拼写，也要抓取准确分发名，只加实际观察到的别名，补测试、刷新 Router。不要对未知名字做宽泛规范化。

`wait` 能用不代表所有工具都经过同一条路由；要直接测出问题的那个工具及其声明 schema。

## Hook 未信任或来源被拒

Flower 安装会通过 `tools/configure_local_plugin.py` 生成本地 Hook。安装插件不等于信任 Hook。要在 Codex 输入框执行 `/hooks`，核对准确命令并信任后再操作目标；未信任时，新聊天可能拒绝全部 Flower 调用。

源码开发模式的 Hook 指向准确源码及其 `.venv`；冻结候选指向实际 `<Root>\Program\versions\<version>` 内置运行时/bootstrap。核对本次生成物并在宿主启用/信任；不改 Hook、权限 router、换 Shell 或复用旧授权绕过拒绝。

## 权限或 Stop 挡住了

查看 `effective_control` 和托盘文字：

- 01 完全停止：三个通道都不派发。
- 全局 Stop：即使后来看起来换了档位，也仍然阻止写入。
- Computer 暂停：只阻止新的 Computer 输入。
- Ctrl+Alt+9 只结束 Computer；Ctrl+Alt+Shift+9 或“紧急停止全部 Flower”是独立全局 Stop。快捷键占用/注册失败时看诊断，不假定成功。
- 权限配置损坏：进入 fault 状态，相关能力拒绝。
- 黑名单：优先于允许名单和任务授权。

不要为了跑通测试而降低黑名单或清除 Stop。恢复后要重新选择目标并重新观察。

## 浏览器页面不对或登录没了

临时资料和 AI 资料都独立于你日常浏览器。日常浏览器已登录，不代表 Flower 资料也登录了。

先确认本次请求用的是哪个资料。第一次登录时，让 Flower 打开对应资料窗口，你自己登录，正常关闭登录窗口后再继续。不要复制其它浏览器的 Cookie 或登录文件。已有受管浏览器身份不明时，不要删资料强行重开。

## 管理员操作失败

03 只用于已经打开的管理员窗口。04 只用于精确的本地启动记录或工作授权。程序换了、启动器拉起了子程序、目标身份不明或参数不一致，都应保持 fail-closed。

UAC 安全桌面自动化和旧系统接管路线在本预览版冻结。管理员消息为 pending 时，不要重放或消费它来让状态看起来正常。保留原来的拒绝和 Stop；只有当前宿主和 status 都独立允许时，普通工作才可以继续。

## 安装或更新失败

保留失败的输出目录和 `preparation.json` 或更新 `plan.json`。不要：

- 重跑已经消费的首次安装 operation；
- 复用旧的 native/app/install 输出目录；
- 用首次安装脚本覆盖已有助手；
- 为了变绿而删除权限、浏览器、动作或回滚状态；
- 上传完整本机环境转储。

Issue 请附版本、步骤、原始错误码、之前是否装过助手、新聊天 status 和最小无害复现。

## 找不到托盘或无法恢复

1. 先展开任务栏右下角 **^ 显示隐藏图标**，寻找花形图标，右键查看当前档位。
2. 图标仍没有：检查安装第 5 步的退出码及计划任务启动结果，把错误交给 Codex 做只读诊断。不要再次运行首次安装脚本覆盖它。
3. 01 完全停止：打开设置，用左侧实际档位按钮选 02，等待已保存档位更新。
4. Computer 暂停：在托盘点**继续使用 Computer Use**，再要求 Codex 重新观察目标。
5. 全部写入停止：只有菜单显示**继续全部写入**时才用；不可恢复或没有入口就保持停止，在[问题页](https://github.com/fallen-blossom/flower-control/issues)附版本、错误码和脱敏状态。只重建设置窗口不等于通用授权修复。

## 选了 D 盘，为何 C 盘还有临时占用

候选 Program/Data/Cache/Packages 使用实际登记根；旧安装不自动迁盘。Windows TEMP 和 .NET 单文件/Setup 解包仍可能使用 C，系统登记也不放进自定义根。区分临时解包与大缓存，以实际目录/字节/回执为准，不改 ProgramFiles 环境变量。发布、签名和干净机边界见[安装器指南](INSTALLER.zh-CN.md)。
