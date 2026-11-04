namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int RuleHelpId = 610;

    private static void ShowWorkspaceHelp()
    {
        MessageBoxW(window, WorkspaceHelpText(), UiText.Get("使用说明"), 0x40);
    }

    private static void ShowRuleHelp()
    {
        MessageBoxW(window, RuleHelpText(), UiText.Get("规则说明"), 0x40);
    }

    private static string WorkspaceHelpText() => UiText.Format(
        "第一次使用，按这 4 步：\r\n\r\n"
        + "1. 在“总览”确认当前权限档位和电脑操作状态。\r\n"
        + "2. 打开“权限”，点 02 / 03 / 04 选择要查看的规则层；点选只会切换查看层，不会立刻授权。\r\n"
        + "3. 需要用 High 权限继承启动时：选 04，切到“按工作授权”，再点“启用工作授权”。\r\n"
        + "4. 看到蓝色“待保存”后，点右下角“保存权限与操作偏好”；只有保存后才会生效。\r\n\r\n"
        + "04 工作授权：\r\n"
        + "· “按工作授权”不会自动放行任意程序；每次 High 启动仍要绑定具体任务、程序、参数和目录。\r\n"
        + "· 黑名单优先；安装后通常先启用 Codex，DSH 需要你在本机再确认一次。\r\n"
        + "· 当前委托：{0}\r\n\r\n"
        + "在哪里看说明：\r\n"
        + "· “使用说明”：本对话框。\r\n"
        + "· “规则说明”：当前权限页的规则说明。\r\n"
        + "· “详情”：最近一次操作消息，只有出现消息时才显示。\r\n"
        + "· 程序行右侧“程序操作” → “查看详情 / 复制路径”。\r\n\r\n"
        + "关闭本说明不会修改设置，也不会建立授权。",
        SemanticDelegationSummary());

    private static string SemanticDelegationSummary()
    {
        if (!saved.AdminLaunchEnabled || saved.AdminLaunchMode != "semantic")
            return UiText.Get("尚未启用按工作授权；先选 04 的“按工作授权”并保存。");
        if (saved.SemanticDelegation is null)
            return UiText.Get("已选择“按工作授权”，但尚未建立委托；先保存，再点“启用工作授权”。");
        if (!SemanticDelegation.IncludesDsh(saved.SemanticDelegation))
            return UiText.Get("Codex 已启用；DSH 尚未确认，点“为 DSH 启用工作授权”。");
        return UiText.Get("Codex 和 DSH 都已启用。");
    }

    private static string RuleHelpText() => ruleLayer < 2
        ? UiText.Format(
            "当前规则层：{0}\r\n\r\n"
            + "· 按完整路径或标题条件阻止窗口；行首 # 表示停用。\r\n"
            + "· 修改只进入本层草稿；点“保存权限与操作偏好”后才生效。\r\n"
            + "· 02 / 03 / 04 只切换查看层，不会改变已保存或待保存档位。\r\n"
            + "· 04 的 High 启动名单和“按工作授权”说明，请切到 04 后点“规则说明”。\r\n"
            + "· 关闭本说明不会修改设置。",
            TierDisplay(ruleLayer))
        : UiText.Get(
            "当前规则层：04 管理员执行\r\n\r\n"
            + "· 本层名单只用于 High 权限继承启动，不限制普通窗口控制。\r\n"
            + "· “按工作授权”不检查白名单；每次启动仍由 App 绑定具体任务、程序、参数和目录。\r\n"
            + "· “程序名单”按白名单放行，黑名单优先。\r\n"
            + "· 修改只进入草稿；出现蓝色“待保存”后，保存才生效。\r\n"
            + "· 02 / 03 / 04 只切换查看层，不会改变已保存或待保存档位。\r\n"
            + "· 关闭本说明不会修改设置。");
}
