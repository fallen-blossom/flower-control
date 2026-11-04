# Flower Control 0.1.0

[English](RELEASE_NOTES.md)

**正式发行准备中，Setup 与对应资产尚未公开。** 先看[安装器指南](INSTALLER.zh-CN.md)，再做[第一次使用](USAGE.zh-CN.md#安装后第一次使用)。

## 本版变化

- 完整离线 Setup 自带 Python 与 .NET 运行依赖。新安装采用一个可选的 Program/Data/Cache/Packages 根；已有安装保留登记位置和资料。
- 本机 status/设置入口、只读完整性自检、脱敏诊断导出、普通偏好备份/草稿导入和空间审阅。
- 新权限文件默认 02；已有档位与 Stop 保留。**Ctrl+Alt+Shift+9** 紧急停止全部通道，**Ctrl+Alt+9** 继续只停止 Computer 输入。
- 中断维护保留原计划和回执。卸载先审阅准确范围，默认保留个人资料与受保护恢复状态；Data/Cache 回收需要另行确认。
- 固定的最小 FFmpeg 录屏编码器，附匹配 FFmpeg/x264/zlib 源码档、构建配方与原始声明；保留本地 PNG/concat/pad/H.264/MP4 路径，禁用网络协议。

Web、App、Computer 仍是三个任务通道。Codex 是主要入口，其他宿主适配遵守各自说明。可选外联决策服务需要在本机启用；Flower 不加入遥测或自动更新。

## 验证与发行

源码/隔离检查、Windows 版本资源检查和短合成帧编码器测试已通过。最终匹配 0.1.0 的安装、真实 High 控制、宿主信任/加载、升级恢复与卸载尚未验证。范围见[验证说明](VALIDATION.zh-CN.md)；没有干净机验收或整体成功率结论。

本版采用未签名发行（`signed: false`）。通过官方 GitHub Release、SHA-256 和匹配源码/构建输入核对文件身份；这些不等于公信发布者签名。Windows UAC 由你人工判断。[私密漏洞报告](https://github.com/fallen-blossom/flower-control/security/advisories/new)已启用。

## 历史预览

[Preview.3 及其原发行资产](https://github.com/fallen-blossom/flower-control/releases/tag/v0.1.0-preview.3)保持不变。其中的源码安装路线和历史测试属于原快照，不代表 0.1.0 安装器已通过。
