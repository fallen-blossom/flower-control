namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int RuleHelpId = 610;

    private static void ShowWorkspaceHelp()
    {
        MessageBoxW(window, FirstRunGuideText() + "\r\n\r\n" + WorkspaceHelpText(), UiText.Get("使用说明"), 0x40);
    }

    private static void ShowFirstRunGuide()
        => MessageBoxW(window, FirstRunGuideText(), UiText.Get("首次使用与权限说明"), 0x40);

    private static string FirstRunGuideText() => UiText.Get(
        "推荐从 02 普通控制开始：可操作普通窗口；需要管理员窗口时再选 03，需要 High 启动时再选 04。已有档位不会自动降低。\r\n\r\n"
        + "左侧档位按钮是立即操作，会保存并切换执行权限；需要时由 Windows 请求确认。权限页顶部 02 / 03 / 04 只切换要查看的规则。\r\n\r\n"
        + "名单、敏感词与操作偏好先改草稿，点击“保存权限与操作偏好”后才生效；“启用工作授权”、浏览器打开和界面语言按各自按钮立即处理。\r\n\r\n"
        + "在当前聊天查看 flower_status，核对实际加载的 Web / App / Computer 通道、版本与已选目标。此设置窗口不能证明聊天已经注入，也不会替聊天选目标。\r\n\r\n"
        + "Ctrl+Alt+Shift+9 以及托盘和总览的“紧急停止全部 Flower”持续阻止三通道写入，必须明确继续；Ctrl+Alt+9 只结束当前 Computer Use。热键注册结果见总览，失败时仍可用按钮。恢复不重放未知动作，不撤销真实拒绝，也不清除单独的 Computer 暂停。\r\n\r\n"
        + "截图只在明确请求观察或录制时取得；诊断不默认录屏或上传。关闭说明不修改任何权限。");

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
