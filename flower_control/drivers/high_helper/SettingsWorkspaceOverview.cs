namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int OverviewActivityId = 910;
    private const int OverviewRuntimeId = 911;
    private const uint OverviewTimer = 188;
    private static string runtimeNotice = "";
    private static bool runtimeWritesStopped;

    private static Rect OverviewStopBounds() => PageBounds(new(StopId, IntPtr.Zero, 1110, 496, 330, 60, "BUTTON"));

    private static void BuildOverviewPage()
    {
        Label(UiText.Get("已保存档位"), 650, 270, h: 30, fontSize: 17);
        Label(TierDisplay(model.EffectiveTier), 650, 308, h: 62,
            emphasis: true, fontSize: 36, ink: AuthorityPresentation.Ink(model.EffectiveTier));
        Label(OverviewExecutorText(), 650, 383, h: 54, fontSize: 18,
            ink: !preview && core is not null ? 0xA9DCEE : null, id: OverviewRuntimeId);

        Label(UiText.Get("电脑操作"), 650, 457, 430, h: 38, emphasis: true, ink: 0xFFC9DC);
        Label(OverviewActivityText(), 650, 505, 430, 45,
            fontSize: 21, ink: OverviewActivityInk(), id: OverviewActivityId);
        Label(UiText.Get("只结束 Computer Use；App / Web 保持。"), 650, 560, h: 34, fontSize: 16);

        Label(UiText.Get("保护与规则"), 650, 621, h: 30, fontSize: 17);
        Label(UiText.Get("密码框自动保护 · Bitwarden 整窗保护"), 650, 661, h: 38, emphasis: true, fontSize: 21, ink: 0xC7DDC5);
        string admin = model.EffectiveTier < 2 ? UiText.Get("High 启动关闭")
            : saved.AdminLaunchMode == "semantic" ? UiText.Get("High 启动按工作授权") : UiText.Get("High 启动按程序名单");
        string uac = saved.UacMode == "off" ? UiText.Get("UAC 已冻结") : UiText.Get("UAC 已冻结 · 保留旧配置");
        Label(UiText.Format("普通禁止 {0} 条 · {1} · {2}",saved.DeniedApplications.Count(x => x.Enabled),admin,uac),
            650, 711, h: 62, fontSize: 18);
        if (!CompactSurface)
        {
            Label(UiText.Get("通道边界"), 650, 770, h: 30, emphasis: true, fontSize: 17);
            Label(UiText.Get("High 启动：继承已运行 High 会话的管理员权限；不是重新提权，正常不弹 UAC"),
                650, 802, h: 40, fontSize: 16);
            Label(UiText.Get("管理员工作授权只决定是否允许；首次 High 安装才可能请求 UAC。Stop、拒绝和未知动作仍共用检查"),
                650, 844, h: 40, fontSize: 16);
        }
    }

    private static string OverviewExecutorText()
    {
        string identity = preview ? UiText.Get("预览 · 不读取实际执行器权限")
            : core is null ? UiText.Get("独立设置窗口 · 未连接执行器")
            : core.OrdinaryResident ? UiText.Get("执行器正在使用 Medium 普通权限") : UiText.Get("执行器正在使用 High 管理员权限");
        if (!preview && core?.OrdinaryResident == true && model.EffectiveTier > 0)
            identity = UiText.Get("Medium 普通权限；管理员档位待 Windows 确认");
        return runtimeNotice.Length == 0 ? identity : UiText.BrokerSummary(runtimeNotice) + "\n" + identity;
    }

    private static string CurrentModeText() => runtimeNotice.Length != 0 ? UiText.BrokerSummary(runtimeNotice)
        : Dirty ? UiText.Get("草稿待保存 · ") + TierName(tier) : "●  " + EffectiveMode();

    private static string OverviewActivityText()
    {
        if (preview) return UiText.Get("示例：未在操作电脑");
        if (core is null) return UiText.Get("未连接电脑操作执行器");
        if (runtimeWritesStopped) return UiText.BrokerSummary(runtimeNotice);
        if (core.ComputerPaused) return UiText.Get("电脑操作已停止");
        int active = core.Requests.Values.Count(r => r.Channel == "flower-computer"
            && !r.ReadOnly && !r.Uac && !r.AdminLaunch);
        return active > 0 ? UiText.Format("正在处理 {0} 项电脑操作",active) : UiText.Get("当前没有执行中的输入");
    }

    private static void RefreshOverview()
    {
        // Refresh once per UI update/timer, never read persistent Stop files
        // from a paint callback. All pages share the saved-tier/runtime notice.
        string summary = preview ? "" : core?.Summary ?? UiText.Get("未连接执行器");
        string next = summary == "运行中" ? "" : summary;
        runtimeWritesStopped = !preview && core is not null && (core.IsPaused || core.IsFault);
        if (runtimeNotice != next)
        {
            runtimeNotice = next;
            InvalidateRect(window, IntPtr.Zero, false);
        }
        if (page != 0) return;
        SetChromeText(PageHandle(OverviewRuntimeId), OverviewExecutorText());
        SetChromeText(PageHandle(OverviewActivityId), OverviewActivityText());
        int index = pageControls.FindIndex(c => c.Id == OverviewActivityId);
        if (index >= 0 && pageControls[index].Ink != OverviewActivityInk())
        {
            pageControls[index] = pageControls[index] with { Ink = OverviewActivityInk() };
            InvalidateRect(pageControls[index].Handle, IntPtr.Zero, false);
        }
    }

    private static uint OverviewActivityInk() => runtimeWritesStopped || core?.ComputerPaused == true ? 0xA9DCEEu
        : core?.Requests.Values.Any(r => r.Channel == "flower-computer" && !r.ReadOnly && !r.Uac && !r.AdminLaunch) == true
            ? 0xB8DDB7u : 0xC1B9B8u;
}
