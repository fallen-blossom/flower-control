using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static string loadedVersion = "", installedVersion = "", runtimeVersionState = "unverified", runtimeRoot = "";
    private static string runtimeIntegrityState = "unverified", runtimeIntegrityError = "";
    private static int runtimeIntegrityFiles;
    private static bool productCheckPending;

    private static void RefreshRuntimeIdentity()
    {
        loadedVersion = installedVersion = runtimeRoot = ""; runtimeVersionState = "unverified";
        if (preview) return;
        try
        {
            var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
            var location = InstallationLocation.Discover(policy.UserSid);
            runtimeRoot = location.Root; loadedVersion = policy.Version;
            string active = Path.Combine(location.ProgramRoot, "active.json");
            UserPermissions.CheckProtection(active); BrokerPolicy.RejectLinks(active);
            using var document = InstallationHealth.ReadManifest(active);
            if (!document.RootElement.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.String)
                return;
            string candidate = version.GetString() ?? "";
            if (!System.Text.RegularExpressions.Regex.IsMatch(candidate, "^[a-f0-9]{16,64}$")) return;
            installedVersion = candidate;
            runtimeVersionState = loadedVersion == installedVersion ? "match" : "mismatch";
        }
        catch { /* Unverified is a visible state, never permission to repair. */ }
    }

    private static string RuntimeVersionText() => runtimeVersionState == "match"
        ? UiText.Get("执行器与安装版本一致；聊天加载版本仍需在当前聊天核对。")
        : runtimeVersionState == "mismatch" ? UiText.Get("版本不一致：执行器与当前安装不同；请保留现场并核对更新结果。")
        : UiText.Get("安装与执行器版本尚未核实；不据此推断已安装或已注入。");

    private static void BuildProductDiagnosticsPage()
    {
        Field(486, "EDIT", ProductDiagnosticsText(), 650, 270, 790, 285,
            0x200000 | 4 | 0x40 | 0x800);
        PageButton(ReadOnlyCheckId, UiText.Get("刷新只读自检"), 650, 578, 380, 36);
        PageButton(RepairSurfaceId, UiText.Get("重建设置界面"), 1050, 578, 390, 36);
        PageButton(ExportDiagnosticsId, UiText.Get("导出脱敏诊断（可复制）"), 650, 633, 790, 36);
        BuildMaintenanceControls();
    }

    private static string ProductDiagnosticsText()
    {
        var status = preview ? null : core?.ProductStatus();
        if (status is not null) ProductDiagnostics.Current.Observe(status);
        string identity = preview ? UiText.Get("合成数据预览；没有读取真实权限、工作记录或 UAC。")
            : core is null ? UiText.Get("独立设置窗口 · 未连接执行器") : OverviewExecutorText();
        string text = identity + "\r\n\r\n" + OverviewChannelsText() + "\r\n" + RuntimeVersionText()
            + UiText.Get("\r\n安装根目录：") + (runtimeRoot.Length == 0 ? UiText.Get("未核实") : runtimeRoot)
            + UiText.Get("\r\n执行器版本：") + (loadedVersion.Length == 0 ? UiText.Get("未核实") : loadedVersion)
            + UiText.Get("\r\n安装版本：") + (installedVersion.Length == 0 ? UiText.Get("未核实") : installedVersion)
            + UiText.Get("\r\n文件完整性：") + (runtimeIntegrityState == "verified"
                ? UiText.Format("最近一次已核验 {0} 项文件", runtimeIntegrityFiles)
                : UiText.Get("未核实") + (runtimeIntegrityError.Length > 0 ? " · " + runtimeIntegrityError : ""))
            + UiText.Get("\r\n权限版本 ") + saved.Revision
            + UiText.Get("\r\n素材 ") + ArtworkState + "\r\n" + CapabilityText();
        text += "\r\n\r\n" + UiText.Get("仅本次助手运行的最近 256 条状态变化；不采集聊天、窗口内容或截图，不上传。")
            + "\r\n" + UiText.Get("重建仅影响设置界面并保留草稿；权限、Stop、拒绝、未知结果和 UAC 冻结均保持。");
        if (status is not null)
        {
            text += "\r\n\r\n" + UiText.Format("待确认释放记录：{0}；释放故障：{1}", status.PendingRecoveries, status.ReleaseFault)
                + UiText.Get("\r\n停止持久化诊断：") + (ProductDiagnostics.SafeCode(status.StopPersistenceError) ?? "none")
                + UiText.Get("\r\nComputer 暂停持久化诊断：") + (ProductDiagnostics.SafeCode(status.ComputerPausePersistenceError) ?? "none");
        }
        text += "\r\n\r\n" + UiText.Get("本次运行元数据时间线（状态变化，最新 12 条）：");
        foreach (var entry in ProductDiagnostics.Current.Snapshot().TakeLast(12))
            text += "\r\n" + entry.Utc + "  " + UiText.Format("连接 {0} / 请求 W{1} A{2} C{3} / 全停 {4} / 电脑暂停 {5} / 待确认 {6}",
                entry.Status.Connections, entry.Status.WebRequests, entry.Status.AppRequests, entry.Status.ComputerRequests,
                entry.Status.AllWritesStopped, entry.Status.ComputerPaused, entry.Status.PendingRecoveries);
        return text;
    }

    private static void CompleteProductCheck(WorkReply reply)
    {
        productCheckPending = false;
        runtimeIntegrityState = reply.Error is null ? "verified" : "unverified";
        runtimeIntegrityFiles = reply.DiagnosticFiles ?? 0;
        runtimeIntegrityError = ProductDiagnostics.SafeCode(reply.Error) ?? "";
        RefreshRuntimeIdentity();
        notice = reply.Error is null
            ? UiText.Format("只读自检通过：已核验 {0} 项文件及执行来源；聊天注入和前台控制仍需另核。", runtimeIntegrityFiles)
            : UiText.Get("只读自检未通过：") + runtimeIntegrityError + UiText.Get("；没有修复、改权限、恢复 Stop 或重放动作。");
        if (page == 4) SetChromeText(PageHandle(486), ProductDiagnosticsText());
        UpdateChrome();
    }

    private static bool ProductCommand(int id, int notification)
    {
        if (id is < EmergencyStopId or > ExportDiagnosticsId) return false;
        if (notification != 0) return true;
        try
        {
            if (id == EmergencyStopId)
            {
                EndPick(); workStop?.Cancel();
                if (preview) notice = UiText.Get("预览未改变真实 Stop 或权限。");
                else if (core is null) notice = UiText.Get("执行器未连接；无法确认紧急停止，请使用正在运行的 Flower 托盘入口。");
                else
                {
                    core.Pause(true);
                    notice = core.ProductStatus().StopPersistenceError is null
                        ? UiText.Get("全部 Flower 写入已停止；须明确继续。旧动作不重放，已运行程序与未知结果保留。")
                        : UiText.Get("当前执行器已停止；持久停止记录尚未确认。请保持停止并查看只读诊断。");
                }
            }
            else if (id == ResumeAllId)
            {
                if (preview || core is null || Busy) return true;
                if (core.OrdinaryResident)
                {
                    HostWindow.BeginOrdinaryControl(core, new("resume_all", UserPermissions.Read().Revision));
                    notice = UiText.Get("正在核对并继续全部写入；请等待实际状态更新。Computer 的单独暂停保持。");
                }
                else notice = core.ResumeGlobalFromLocalUser()
                    ? UiText.Get("已明确继续全部写入；下一步仍须新观察。Computer 的单独暂停与旧未知结果保持。")
                    : UiText.Get("没有可恢复的全部写入停止；当前状态未改变。");
            }
            else if (id == FirstRunGuideId) ShowFirstRunGuide();
            else if (id == ReadOnlyCheckId)
            {
                if (Busy) return true;
                if (preview) { notice = UiText.Get("预览未运行实际安装自检。"); UpdateChrome(); return true; }
                if (page == 0 && !invalidEdit) { page = 4; BuildPage(); }
                StartWork(token => {
                    var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                    return new("product_check", DiagnosticFiles: InstallationHealth.Verify(policy, token));
                });
                productCheckPending = true;
                notice = UiText.Get("正在后台核验安装清单与文件摘要；可以切页，紧急停止仍可从托盘使用。");
            }
            else if (id == RepairSurfaceId)
            {
                if (Busy || invalidEdit) { notice = UiText.Get("请先等待在途操作完成或修正当前字段；原输入保留。"); UpdateChrome(); return true; }
                surfaceFault = false; BuildPage();
                notice = UiText.Get("设置界面已重建，草稿保留；没有改变执行状态或重放动作。");
            }
            else if (id == ExportDiagnosticsId)
            {
                string json = ProductDiagnostics.Current.Export(preview ? null : core?.ProductStatus(),
                    runtimeVersionState, loadedVersion, installedVersion, runtimeIntegrityState,
                    runtimeIntegrityFiles, runtimeIntegrityError.Length == 0 ? null : runtimeIntegrityError);
                MessageBoxW(window, UiText.Get("以下仅含版本、状态计数和本次运行时间线。可选择文字后复制到本地文件；不会自动上传，未包含截图或聊天内容。")
                    + "\r\n\r\n" + json, UiText.Get("脱敏诊断导出"), 0x40);
            }
        }
        catch (Exception error)
        { notice = UiText.Get("操作未完成：") + UserFacingError(Program.Code(error)) + UiText.Get("；停止保护与原草稿保留，不自动重试。"); }
        UpdateChrome(); return true;
    }

    // UI-thread metadata only. Broker readers never message the protected UI,
    // and neither editor text nor program paths enter the status snapshot.
    private static PermissionSettingsWindow.SurfaceStatus workspaceStatus = new(
        0, "closed", false, false, false, false, 0, 0, 0, 0, 0, "closed", null, 0);

    internal static PermissionSettingsWindow.SurfaceStatus SurfaceDiagnostics
    {
        get
        {
            var current = Volatile.Read(ref workspaceStatus);
            if (current.Window != 0) return current;
            var legacy = PermissionSettingsWindow.SurfaceDiagnostics;
            return legacy.Window != 0 ? legacy : current;
        }
    }

    private static void PublishWorkspaceStatus(string stage, int? command = null, int notification = 0, string? error = null)
    {
        try
        {
            var old = Volatile.Read(ref workspaceStatus);
            bool live = window != IntPtr.Zero && Native.IsWindow(window);
            var focused = live ? GetFocus() : IntPtr.Zero;
            Volatile.Write(ref workspaceStatus, old with {
                Window = live ? window.ToInt64() : 0,
                Page = live ? page.ToString() : "closed",
                Visible = live && IsWindowVisible(window), Minimized = live && IsIconic(window),
                Enabled = live && IsWindowEnabled(window), Foreground = live && Native.GetForegroundWindow() == window,
                FocusControl = live && IsChild(window, focused) ? GetDlgCtrlID(focused) : 0,
                LastCommandControl = command ?? old.LastCommandControl,
                LastCommandNotification = command.HasValue ? notification : old.LastCommandNotification,
                Stage = live ? stage : "closed",
                Error = error ?? (!surfaceFault && (stage is "updated" or "closed" or "selection_started") ? null : old.Error), Sequence = old.Sequence + 1
            });
        }
        catch { /* Diagnostic failure cannot change settings or close the UI. */ }
    }
}
