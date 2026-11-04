namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int OverviewActivityId = 910;
    private const int OverviewRuntimeId = 911;
    private const int OverviewChannelsId = 912, EmergencyStopId = 940, ResumeAllId = 941,
        FirstRunGuideId = 942, ReadOnlyCheckId = 943, RepairSurfaceId = 944, ExportDiagnosticsId = 945;
    private const uint OverviewTimer = 188;
    private static string runtimeNotice = "";
    private static bool runtimeWritesStopped;

    private static Rect OverviewStopBounds() => PageBounds(new(StopId, IntPtr.Zero, 1110, 496, 330, 60, "BUTTON"));

    private static void BuildOverviewPage()
    {
        Label(saved.Revision == "absent" ? UiText.Get("首次使用 · 推荐 02 普通控制") : UiText.Get("已保存档位"), 650, 270, 380, h: 30, fontSize: 17);
        PageButton(FirstRunGuideId, UiText.Get("首次使用与权限说明"), 1050, 270, 390, 30);
        Label(TierDisplay(model.EffectiveTier), 650, 308, h: 62,
            emphasis: true, fontSize: 36, ink: AuthorityPresentation.Ink(model.EffectiveTier));
        Label(OverviewExecutorText(), 650, 383, h: 54, fontSize: 18,
            ink: !preview && core is not null ? 0xA9DCEE : null, id: OverviewRuntimeId);

        Label(UiText.Get("电脑操作"), 650, 457, 430, h: 38, emphasis: true, ink: 0xFFC9DC);
        Label(OverviewActivityText(), 650, 505, 430, 45,
            fontSize: 21, ink: OverviewActivityInk(), id: OverviewActivityId);
        Label(UiText.Get("只结束 Computer Use；App / Web 保持。"), 650, 560, h: 34, fontSize: 16);

        Label(UiText.Get("App：管理员授权 / High 启动；Computer：自由键鼠"), 650, 608, h: 30, fontSize: 16);
        Label(OverviewChannelsText(), 650, 648, h: 108, fontSize: 16, id: OverviewChannelsId);
        PageButton(EmergencyStopId, UiText.Get("紧急停止全部 Flower"), 650, 766, 380, 40);
        PageButton(ResumeAllId, UiText.Get("明确继续全部写入"), 1050, 766, 390, 40);
        RefreshProductButtons();
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
        SetChromeText(PageHandle(OverviewChannelsId), OverviewChannelsText());
        RefreshProductButtons();
        int index = pageControls.FindIndex(c => c.Id == OverviewActivityId);
        if (index >= 0 && pageControls[index].Ink != OverviewActivityInk())
        {
            pageControls[index] = pageControls[index] with { Ink = OverviewActivityInk() };
            InvalidateRect(pageControls[index].Handle, IntPtr.Zero, false);
        }
    }

    private static string OverviewChannelsText()
    {
        if (preview) return UiText.Get("预览：三通道与目标均为未核实状态，不读取实际连接。");
        if (core is null) return UiText.Get("执行器未连接；宿主聊天注入、通道和目标尚未核实。");
        var status = core.ProductStatus();
        string activity = UiText.Format("本机连接 {0} · 当前请求 W {1} / A {2} / C {3}",
            status.Connections, status.WebRequests, status.AppRequests, status.ComputerRequests);
        string version = runtimeVersionState == "match" ? UiText.Get("执行器与安装版本一致；聊天版本另核。")
            : runtimeVersionState == "mismatch" ? UiText.Get("版本不一致；请核对更新结果。") : UiText.Get("安装和执行器版本未核实。");
        return activity + "\n" + UiText.Get("聊天注入与目标未核实；请在聊天查看 flower_status。")
            + "\n" + version + "\n" + EmergencyHotkeyText(status);
    }

    private static string EmergencyHotkeyText(ProductRuntimeStatus? status) => status?.EmergencyHotkeyRegistered switch {
        true => UiText.Get("全部停止 Ctrl+Alt+Shift+9 已注册；Ctrl+Alt+9 只结束 Computer。"),
        false => UiText.Format("全部停止热键注册失败（Win32 {0}）；请使用托盘或总览停止按钮。", status.EmergencyHotkeyError?.ToString() ?? "unknown"),
        _ => UiText.Get("全部停止热键注册状态尚未核实；托盘和总览保留停止按钮。")
    };

    private static void RefreshProductButtons()
    {
        EnableChromeControl(PageHandle(EmergencyStopId), preview || core is not null);
        EnableChromeControl(PageHandle(ResumeAllId), !Busy && !preview && core?.HasRecoverableGlobalStop == true);
        EnableChromeControl(PageHandle(ReadOnlyCheckId), !Busy);
        EnableChromeControl(PageHandle(RepairSurfaceId), !Busy && !invalidEdit);
    }

    private static uint OverviewActivityInk() => runtimeWritesStopped || core?.ComputerPaused == true ? 0xA9DCEEu
        : core?.Requests.Values.Any(r => r.Channel == "flower-computer" && !r.ReadOnly && !r.Uac && !r.AdminLaunch) == true
            ? 0xB8DDB7u : 0xC1B9B8u;
}
