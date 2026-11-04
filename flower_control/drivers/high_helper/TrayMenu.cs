using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

// Self-drawn dark tray popup. Grows up-left from the tray icon, animates with
// a layered fade/slide, shows the current tier plus hover details, and keeps
// fixed menu behaviour: Esc closes, Up/Down moves, Enter runs the highlight.
internal static class TrayMenu
{
    private delegate IntPtr Procedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Class
    { public uint Size, Style; public IntPtr Proc; public int ClassExtra, WindowExtra; public IntPtr Instance, Icon, Cursor, Background; public string? Menu; public string? Name; public IntPtr SmallIcon; }
    [StructLayout(LayoutKind.Sequential)] private struct Paint
    { public IntPtr Dc; public int Erase; public Native.Rect Rect; public int Restore, Update;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Reserved; }
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo
    { public uint Size; public Native.Rect Monitor, Work; public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct MouseTracking
    { public uint Size, Flags; public IntPtr Window; public uint HoverTime; }
    [StructLayout(LayoutKind.Sequential)] private struct GlyphPoint { public int X, Y; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ushort RegisterClassExW(ref Class value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateWindowExW(uint ex, string kind, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr data);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int w, int h, uint flags);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetFocus();
    [DllImport("user32.dll")] private static extern IntPtr SetCapture(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetCapture();
    [DllImport("user32.dll")] private static extern bool ReleaseCapture();
    [DllImport("user32.dll")] private static extern UIntPtr SetTimer(IntPtr hwnd, UIntPtr id, uint ms, IntPtr proc);
    [DllImport("user32.dll")] private static extern bool KillTimer(IntPtr hwnd, UIntPtr id);
    [DllImport("user32.dll")] private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromPoint(Native.Point point, uint flags);
    [DllImport("user32.dll")] private static extern bool GetMonitorInfoW(IntPtr monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern uint GetSysColor(int index);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
    private static extern bool SystemPreference(uint action, uint parameter, [MarshalAs(UnmanagedType.Bool)] out bool value, uint flags);
    [DllImport("user32.dll")] private static extern bool SetLayeredWindowAttributes(IntPtr hwnd, uint key, byte alpha, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr BeginPaint(IntPtr hwnd, out Paint paint);
    [DllImport("user32.dll")] private static extern bool EndPaint(IntPtr hwnd, ref Paint paint);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern int FillRect(IntPtr dc, ref Native.Rect rect, IntPtr brush);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int DrawTextW(IntPtr dc, string text, int length, ref Native.Rect rect, uint format);
    [DllImport("user32.dll")] private static extern int FrameRect(IntPtr dc, ref Native.Rect rect, IntPtr brush);
    [DllImport("user32.dll")] private static extern bool TrackMouseEvent(ref MouseTracking tracking);
    [DllImport("user32.dll")] private static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadImageW(IntPtr instance, IntPtr name, uint kind, int w, int h, uint flags);
    [DllImport("user32.dll")] private static extern bool DrawIconEx(IntPtr dc, int x, int y, IntPtr icon, int w, int h, uint step, IntPtr brush, uint flags);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateSolidBrush(uint color);
    [DllImport("gdi32.dll")] private static extern IntPtr CreatePen(int style, int width, uint color);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern uint SetTextColor(IntPtr dc, uint color);
    [DllImport("gdi32.dll")] private static extern int SetBkMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll")] private static extern IntPtr GetStockObject(int index);
    [DllImport("gdi32.dll")] private static extern bool RoundRect(IntPtr dc, int left, int top, int right, int bottom, int ew, int eh);
    [DllImport("gdi32.dll")] private static extern bool Ellipse(IntPtr dc, int left, int top, int right, int bottom);
    [DllImport("gdi32.dll")] private static extern bool Arc(IntPtr dc, int left, int top, int right, int bottom, int xs, int ys, int xe, int ye);
    [DllImport("gdi32.dll")] private static extern bool Polygon(IntPtr dc, GlyphPoint[] points, int count);
    [DllImport("gdi32.dll")] private static extern bool MoveToEx(IntPtr dc, int x, int y, IntPtr previous);
    [DllImport("gdi32.dll")] private static extern bool LineTo(IntPtr dc, int x, int y);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateFontW(int height, int width, int angle, int orientation, int weight, uint italic, uint underline, uint strike, uint charset, uint output, uint clip, uint quality, uint pitch, string face);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern bool GetTextExtentPoint32W(IntPtr dc, string text, int length, out Native.Point size);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern int GetTextFaceW(IntPtr dc, int count, System.Text.StringBuilder name);
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    [DllImport("user32.dll")] private static extern int GetMessageW(out Msg message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Msg message);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref Msg message);
    [StructLayout(LayoutKind.Sequential)] private struct Msg
    { public IntPtr Hwnd; public uint Message; public UIntPtr WParam; public IntPtr LParam; public uint Time; public int X, Y; }

    internal sealed record Row(int Id, string Label, string Detail, string Shortcut, bool Enabled, bool Danger);
    private const int FrameCount = 8, FrameMs = 14, SlidePx = 14;
    private static readonly Procedure procedure = WindowProc;
    private static bool registered;
    private static IntPtr window, ownerWindow, previousForeground;
    private static BrokerState? coreState;
    private static List<Row> rows = [];
    private static readonly List<(int Top, int Height)> hitboxes = [];
    private static int hoverIndex = -1, selectIndex = -1, finalX, finalY, frame, popupWidth, popupHeight;
    private static int pressedIndex = -1;
    private static double scale = 1;
    private static bool activated;
    private static IntPtr fontTitle, fontItem, fontDetail;
    private static double fontScale;
    // Test-build only: draw the real menu from synthetic state.
    private static bool previewMode;

    internal static (string Label, string Detail) TierInfo()
    {
        try
        {
            var permissions = UserPermissions.Read();
            if (permissions.UacPolicyError is not null)
                return (UiText.Get("故障 · 权限配置需修复"), UiText.Get("权限配置存在错误，相关能力在修复前一律拒绝。\r\n打开设置查看具体原因；托盘、停止和暂停仍然可用。"));
            int launch = permissions.AdminLaunchAllowlist.Count(item => item.Enabled);
            string launchMode = permissions.AdminLaunchMode == "semantic" ? UiText.Get("档位授权") : UiText.Get("名单");
            return UserPermissions.TierOf(permissions) switch {
                -1 => (AuthorityPresentation.Label(-1), UiText.Get("App、Computer、Web 全部停止派发。\r\n托盘、立即停止和暂停仍然可用；可在设置中选择 02、03 或 04。原 Stop 不会因此自动清除。")),
                0 => (AuthorityPresentation.Label(0), UiText.Get("只操作普通窗口。\r\n管理员窗口与 High 启动关闭，UAC 已冻结。\r\n普通窗口黑名单：") + permissions.DeniedApplications.Count(item => item.Enabled) + UiText.Get(" 项。")),
                1 => (AuthorityPresentation.Label(1), UiText.Get("可以观察与操作管理员窗口，不会启动管理员进程。\r\n管理员窗口黑名单：") + permissions.DeniedAdminWindowApplications.Count(item => item.Enabled) + UiText.Get(" 项。")),
                2 => (AuthorityPresentation.Label(2), UiText.Get("可通过名单或工作授权执行 High 启动；正常不弹 UAC。\r\n启动名单：") + launch + UiText.Get(" 项，模式：") + launchMode + "。"),
                3 => (AuthorityPresentation.Label(3), AuthorityPresentation.FrozenNotice + UiText.Get("\r\n旧设置保留；此状态不是新的 04 管理员执行。")),
                _ => (UiText.Get("故障 · 未知档位"), UiText.Get("权限档位无法识别，已按最保守方式停止相关操作。\r\n打开设置重新选择档位。"))
            };
        }
        catch (Exception)
        {
            return (UiText.Get("故障 · 权限不可读取"), UiText.Get("权限配置不可读取；打开设置查看具体原因。"));
        }
    }
    internal static List<Row> BuildRows(bool paused, string tier, string tierDetail, bool globalPaused = false,
        bool stoppedWithoutRecovery = false)
    {
        string state = stoppedWithoutRecovery ? UiText.Get("（全部写入已停止；保护记录不可恢复）")
            : globalPaused ? paused ? UiText.Get("（全部写入与 Computer 已停止）") : UiText.Get("（全部写入已停止）")
            : paused ? UiText.Get("（Computer 已暂停）") : "";
        var rows = new List<Row> {
            new Row(0, UiText.Get("当前档位 · ") + tier + state, tierDetail, "", false, false),
        };
        rows.Add(new Row(6, UiText.Get("紧急停止全部 Flower"),
            UiText.Get("立即阻止 Web / App / Computer 的新写入并取消在途控制；持续停止，须明确继续。已运行的程序与未知结果保留。"), "Ctrl+Alt+Shift+9", true, true));
        if (globalPaused) rows.Add(new Row(5, UiText.Get("继续全部写入"),
            UiText.Get("只恢复当前停止代次；会先核对受保护记录。旧动作、旧观察和未确认结果都不会重放，下一步仍需重新观察。"), "", true, false));
        rows.AddRange([
            new Row(1, UiText.Get("立即停止 Computer Use"), UiText.Get("结束当前 Computer Use：释放键鼠、取消在途操作；之后 AI 需重新调用才会继续。App 与 Web 不受影响。"), "Ctrl+Alt+9", true, true),
            new Row(2, paused ? UiText.Get("继续使用 Computer Use") : UiText.Get("暂停使用 Computer Use"),
                paused ? UiText.Get("恢复后 AI 的下一步操作需要重新观察；未知结果的动作不会重放。") : UiText.Get("暂停期间新的电脑操作会被拒绝；随时可在此继续。"), "", true, false),
            new Row(3, UiText.Get("设置"), UiText.Get("打开权限与隐私设置。"), "", true, false),
            new Row(4, UiText.Get("退出"), UiText.Get("正常退出管理员助手；已经运行的程序和成果不受影响。"), "", true, false),
        ]);
        return rows;
    }
    internal static (int X, int Y) PositionFor(int workLeft, int workTop, int workRight, int workBottom, int cursorX, int cursorY, int width, int height)
    {
        int right = Math.Min(cursorX + 12, workRight - 8);
        int left = Math.Max(workLeft + 8, right - width);
        int bottom = Math.Max(workTop + 8 + height, cursorY - 10);
        bottom = Math.Min(bottom, workBottom - 8);
        int top = Math.Max(workTop + 8, bottom - height);
        return (left, top);
    }

    internal static void Show(IntPtr owner, BrokerState core)
    {
        CancelMousePress();
        if (window != IntPtr.Zero && IsWindow(window)) Hide(restore: false);
        ownerWindow = owner; coreState = core;
        var instance = GetModuleHandleW(null);
        if (!registered)
        {
            var value = new Class { Size = (uint)Marshal.SizeOf<Class>(), Proc = Marshal.GetFunctionPointerForDelegate(procedure), Instance = instance, Name = "FlowerControl.TrayMenu" };
            if (RegisterClassExW(ref value) == 0) throw new Boundary("tray_menu_register_failed", Marshal.GetLastWin32Error());
            registered = true;
        }
        if (!GetCursorPos(out var cursor)) cursor = new Native.Point();
        var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
        if (!GetMonitorInfoW(MonitorFromPoint(cursor, 2), ref monitor)) throw new Boundary("tray_menu_monitor_unavailable");
        // The window owns the DPI that matters. A hidden zero-size owner reports
        // the system DPI, so a 150% monitor used to get a 100% layout with
        // every label clipped. Create on the target monitor first, then size
        // the layout from that window's real DPI.
        if (window == IntPtr.Zero || !IsWindow(window))
        {
            window = CreateWindowExW(0x00000080 | 0x00000008 | 0x00080000, "FlowerControl.TrayMenu", "Flower Control",
                0x80000000, monitor.Work.Left + 8, monitor.Work.Top + 8, 10, 10, owner, IntPtr.Zero, instance, IntPtr.Zero);
            if (window == IntPtr.Zero) throw new Boundary("tray_menu_window_failed", Marshal.GetLastWin32Error());
            try { int dark = SettingsWorkspace.HighContrast() ? 0 : 1; DwmSetWindowAttribute(window, 20, ref dark, sizeof(int)); } catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { }
            try { int round = 2; DwmSetWindowAttribute(window, 33, ref round, sizeof(int)); } catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { }
        }
        // A reused popup still belongs to the previous monitor until moved.
        // Move it while hidden, so GetDpiForWindow observes this invocation's
        // monitor before fonts, hitboxes and measurements are built.
        if (!SetWindowPos(window, IntPtr.Zero, monitor.Work.Left + 8, monitor.Work.Top + 8, 0, 0, 0x15))
            throw new Boundary("tray_menu_monitor_move_failed", Marshal.GetLastWin32Error());
        scale = Math.Max(1.0, GetDpiForWindow(window) / 96.0);
        (string Label, string Detail) tier = previewMode
            ? (AuthorityPresentation.Label(2), UiText.Get("预览 · 合成数据") + "\r\n" + AuthorityPresentation.FrozenNotice)
            : TierInfo();
        var recoverable = core.HasRecoverableGlobalStop;
        rows = BuildRows(core.ComputerPaused, tier.Label, tier.Detail, recoverable, core.IsPaused && !recoverable);
        EnsureFonts();
        Measure();
        var (x, y) = PositionFor(monitor.Work.Left, monitor.Work.Top, monitor.Work.Right, monitor.Work.Bottom, cursor.X, cursor.Y, popupWidth, popupHeight);
        bool animate = AnimationAllowed();
        finalX = x; finalY = y; frame = animate ? 0 : FrameCount; hoverIndex = -1; selectIndex = -1; activated = false;
        previousForeground = GetForegroundWindow();
        SetLayeredWindowAttributes(window, 0, animate ? (byte)0 : (byte)255, 2);
        ShowWindow(window, 5);
        SetForegroundWindow(window);
        if (GetForegroundWindow() == window && IsWindowVisible(window)) SetFocus(window);
        SetWindowPos(window, new IntPtr(-1), x, y + (animate ? SlidePx : 0), popupWidth, popupHeight, 0x0010);
        InvalidateRect(window, IntPtr.Zero, false);
        if (animate && SetTimer(window, new UIntPtr(1), FrameMs, IntPtr.Zero) == UIntPtr.Zero) throw new Boundary("tray_menu_timer_failed");
    }
    private static bool AnimationAllowed()
    {
        bool menu = !SystemPreference(0x1002, 0, out var menuPreference, 0) || menuPreference;
        bool client = !SystemPreference(0x1042, 0, out var clientPreference, 0) || clientPreference;
        return ShouldAnimate(SettingsWorkspace.HighContrast(), menu, client);
    }
    internal static bool ShouldAnimate(bool contrast, bool menu, bool client) => !contrast && menu && client;
    private static void Hide(bool restore)
    {
        CancelMousePress();
        if (window == IntPtr.Zero || !IsWindow(window)) return;
        bool mine = GetForegroundWindow() == window;
        KillTimer(window, new UIntPtr(1));
        if (GetFocus() == window) SetFocus(IntPtr.Zero);
        ShowWindow(window, 0);
        if (restore && mine && IsWindow(previousForeground)) SetForegroundWindow(previousForeground);
        hoverIndex = selectIndex = -1;
    }
    // Test-build entry: render the shipping menu from synthetic state so its
    // layout, glyphs and colours can be reviewed from a temporary build without
    // installing a new broker or asking the user for elevation.
    internal static int Preview()
    {
        previewMode = true;
        SetVisualState(TrayStateIcons.Select(2, true, false));
        var instance = GetModuleHandleW(null);
        if (!registered)
        {
            var value = new Class { Size = (uint)Marshal.SizeOf<Class>(), Proc = Marshal.GetFunctionPointerForDelegate(procedure),
                Instance = instance, Name = "FlowerControl.TrayMenu" };
            if (RegisterClassExW(ref value) == 0) throw new Boundary("tray_menu_register_failed", Marshal.GetLastWin32Error());
            registered = true;
        }
        var host = CreateWindowExW(0x00000080, "FlowerControl.TrayMenu", "Flower Control", 0, 0, 0, 0, 0,
            IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
        if (host == IntPtr.Zero) throw new Boundary("tray_menu_preview_host_failed", Marshal.GetLastWin32Error());
        var state = new BrokerState();
        state.SetComputerPaused(false);
        Show(host, state);
        Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { preview = "tray-menu",
            scale, dpi = GetDpiForWindow(window), width = popupWidth, height = popupHeight, hwnd = window.ToInt64() }));
        while (true)
        {
            int result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
            if (result == 0) break;
            if (result < 0) throw new Boundary("tray_menu_preview_messages_failed");
            TranslateMessage(ref message);
            DispatchMessageW(ref message);
        }
        return 0;
    }
    private static void Activate(Row row)
    {
        var core = coreState; var owner = ownerWindow;
        Hide(restore: row.Id is 1 or 2 or 5 or 6);
        // The preview must never touch broker state: the menu is drawn exactly
        // as it ships, but nothing here stops, pauses or exits anything.
        if (previewMode) return;
        switch (row.Id)
        {
            case 6:
                core?.Pause(true);
                if (core?.ProductStatus().StopPersistenceError is not null)
                    PermissionSettingsWindow.ShowError(owner, UiText.Get("当前执行器已停止；持久停止记录尚未确认。请保持停止并查看只读诊断。"));
                break;
            case 5:
                try
                {
                    if (core?.OrdinaryResident == true)
                    { HostWindow.BeginOrdinaryControl(core, new("resume_all", UserPermissions.Read().Revision)); break; }
                    if (core?.ResumeGlobalFromLocalUser() != true)
                        PermissionSettingsWindow.ShowError(owner, UiText.Get("没有可恢复的全部写入停止；当前状态未改变。"));
                }
                catch (Exception error)
                {
                    PermissionSettingsWindow.ShowError(owner, Program.Code(error) == "resume_state_changed"
                        ? UiText.Get("停止状态刚刚发生变化；没有恢复。请重新打开托盘菜单核对。")
                        : UiText.Get("全部写入未能恢复；停止保护仍保留。请重新打开托盘菜单核对。"));
                }
                break;
            case 1: core?.StopComputerUse(); break;
            case 2:
                try
                {
                    if (core?.OrdinaryResident == true)
                    {
                        if (!core.ComputerPaused) core.SetComputerPaused(true);
                        else HostWindow.BeginOrdinaryControl(core, new("computer_pause", UserPermissions.Read().Revision, ComputerPaused: false));
                    }
                    else core?.SetComputerPaused(!(core?.ComputerPaused ?? false));
                }
                catch (Exception error) { PermissionSettingsWindow.ShowError(owner, Program.Code(error) == "broker_stopping"
                    ? UiText.Get("助手正在退出，这次暂停或恢复未保存。请在新助手启动后操作。")
                    : UiText.Get("Computer 暂停状态未能保存或恢复。已保持暂停，请重试或检查本地保护存储。")); }
                break;
            case 3:
                // A settings creation failure must not leave this path silent;
                // the broker keeps running either way.
                try
                {
                    if (owner != IntPtr.Zero && core is not null)
                    {
                        try { SettingsWorkspace.Show(owner, core); }
                        catch (Exception error) { PermissionSettingsWindow.ShowError(owner,
                            UiText.Get("设置窗口未能打开：") + Program.Code(error) + UiText.Get("。执行器仍在运行，原设置未被默认值覆盖。请重新打开设置或查看本地诊断。")); }
                    }
                }
                catch (Exception) { PermissionSettingsWindow.ShowError(owner, UiText.Get("设置窗口无法打开。管理员助手仍在运行，请检查屏幕大小或权限配置。")); }
                break;
            case 4: core?.Stop(BrokerShutdownReason.TrayExit); break;
        }
    }
    private static void EnsureFonts()
    {
        if (fontTitle != IntPtr.Zero && fontScale == scale) return;
        if (fontTitle != IntPtr.Zero)
        {
            DeleteObject(fontTitle); DeleteObject(fontItem); DeleteObject(fontDetail);
            fontTitle = fontItem = fontDetail = IntPtr.Zero;
        }
        fontTitle = CreateFontW(-(int)Math.Round(15 * scale), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 5, 0, "Microsoft YaHei UI");
        fontItem = CreateFontW(-(int)Math.Round(14 * scale), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Microsoft YaHei UI");
        fontDetail = CreateFontW(-(int)Math.Round(12 * scale), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Microsoft YaHei UI");
        if (fontTitle == IntPtr.Zero || fontItem == IntPtr.Zero || fontDetail == IntPtr.Zero) throw new Boundary("tray_menu_font_failed");
        fontScale = scale;
    }
    private static int MeasureText(IntPtr font, string text)
    {
        var dc = GetDC(IntPtr.Zero);
        if (dc == IntPtr.Zero) throw new Boundary("tray_menu_dc_failed");
        var previous = SelectObject(dc, font);
        try { GetTextExtentPoint32W(dc, text, text.Length, out var size); return size.X; }
        finally { SelectObject(dc, previous); ReleaseDC(IntPtr.Zero, dc); }
    }
    private static void Measure()
    {
        int pad = (int)Math.Round(14 * scale), icon = (int)Math.Round(20 * scale);
        int width = (int)Math.Round(300 * scale);
        foreach (var row in rows)
        {
            int needed = row.Id == 0 ? MeasureText(fontTitle, row.Label) + icon + pad * 3
                : MeasureText(fontItem, row.Label) + icon + pad * 2 + (row.Shortcut.Length != 0 ? MeasureText(fontDetail, row.Shortcut) + pad * 2 : 0);
            width = Math.Max(width, needed);
        }
        popupWidth = Math.Min(width, (int)Math.Round(440 * scale));
        // Mirrors Draw()'s walk so the bottom strip always keeps three full
        // detail lines plus padding.
        int height = (int)Math.Round(10 * scale) + (int)Math.Round(62 * scale) + (int)Math.Round(6 * scale) + (int)Math.Round(7 * scale);
        for (int index = 1; index < rows.Count; index++)
        {
            if (rows[index].Id == 3 && index > 1) height += (int)Math.Round(7 * scale);
            height += (int)Math.Round(34 * scale);
        }
        height += (int)Math.Round(2 * scale) + (int)Math.Round(6 * scale) + (int)Math.Round(56 * scale);
        popupHeight = height;
    }
    private static void Draw()
    {
        Paint paint = default;
        var dc = BeginPaint(window, out paint);
        try
        {
            if (!GetClientRect(window, out var client)) return;
            int pad = (int)Math.Round(14 * scale), icon = (int)Math.Round(20 * scale);
            bool contrast = SettingsWorkspace.HighContrast();
            uint textInk = contrast ? GetSysColor(7) : Rgb(237, 237, 239);
            uint detailInk = contrast ? GetSysColor(7) : Rgb(150, 155, 165);
            var background = CreateSolidBrush(contrast ? GetSysColor(4) : Rgb(18, 20, 26));
            var border = CreateSolidBrush(contrast ? GetSysColor(7) : Rgb(48, 52, 62));
            var hover = CreateSolidBrush(contrast ? GetSysColor(13) : Rgb(40, 44, 54));
            var line = CreatePen(0, 1, contrast ? GetSysColor(7) : Rgb(48, 52, 62));
            try
            {
                FillRect(dc, ref client, background);
                var frameRect = client; FrameRect(dc, ref frameRect, border);
                hitboxes.Clear();
                int y = (int)Math.Round(10 * scale);
                int headerHeight = (int)Math.Round(62 * scale);
                var glyph = HeaderGlyph(icon);
                if (glyph != IntPtr.Zero) DrawIconEx(dc, pad, y + (int)Math.Round(6 * scale), glyph, icon, icon, 0, IntPtr.Zero, 3);
                var titleRect = Rect(pad + icon + (int)Math.Round(10 * scale), y, client.Right - pad, y + (int)Math.Round(22 * scale));
                Text(dc, fontTitle, textInk, ref titleRect, rows[0].Label, 0x10 | 4 | 0x8000);
                var detailRect = Rect(pad + icon + (int)Math.Round(10 * scale), y + (int)Math.Round(24 * scale), client.Right - pad, y + headerHeight);
                Text(dc, fontDetail, detailInk, ref detailRect, FirstLine(rows[0].Detail), 0x10 | 0x8000);
                y += headerHeight + (int)Math.Round(6 * scale);
                Separator(dc, line, pad, y, client.Right - pad); hitboxes.Add((-1, -1)); y += (int)Math.Round(7 * scale);
                for (int index = 1; index < rows.Count; index++)
                {
                    var row = rows[index];
                    if (row.Id == 3 && index > 1) { Separator(dc, line, pad, y, client.Right - pad); y += (int)Math.Round(7 * scale); }
                    int height = (int)Math.Round(32 * scale);
                    var box = Rect((int)Math.Round(8 * scale), y, client.Right - (int)Math.Round(8 * scale), y + height);
                    bool highlighted = (index == hoverIndex || index == selectIndex) && row.Enabled;
                    if (highlighted) { var filled = box; FillRect(dc, ref filled, hover); }
                    uint colour = contrast ? GetSysColor(!row.Enabled ? 17 : highlighted ? 14 : 7)
                        : !row.Enabled ? Rgb(120, 124, 132) : row.Danger ? Rgb(255, 122, 137) : textInk;
                    Glyph(dc, row.Id, pad + (int)Math.Round(6 * scale), y + height / 2, (int)Math.Round(16 * scale), colour, row.Id == 2 && row.Label.StartsWith(UiText.Get("继续"), StringComparison.Ordinal));
                    var labelRect = Rect(pad + icon + (int)Math.Round(8 * scale), y, client.Right - pad - (row.Shortcut.Length != 0 ? MeasureText(fontDetail, row.Shortcut) + pad : 0), y + height);
                    Text(dc, fontItem, colour, ref labelRect, row.Label, 0x20 | 4 | 0x8000);
                    if (row.Shortcut.Length != 0)
                    {
                        var shortcutRect = Rect(client.Right - pad - MeasureText(fontDetail, row.Shortcut), y, client.Right - pad, y + height);
                        Text(dc, fontDetail, contrast && highlighted ? GetSysColor(14) : detailInk, ref shortcutRect, row.Shortcut, 0x20 | 4 | 2);
                    }
                    hitboxes.Add((y, height));
                    y += height + (int)Math.Round(2 * scale);
                }
                y += (int)Math.Round(2 * scale);
                Separator(dc, line, pad, y, client.Right - pad); y += (int)Math.Round(6 * scale);
                string strip = hoverIndex > 0 && hoverIndex < rows.Count ? rows[hoverIndex].Detail : rows[0].Detail;
                var stripRect = Rect(pad, y, client.Right - pad, client.Bottom - (int)Math.Round(6 * scale));
                Text(dc, fontDetail, detailInk, ref stripRect, strip, 0x10 | 0x8000);
            }
            finally
            {
                foreach (var item in new[] { background, border, hover }) DeleteObject(item);
                DeleteObject(line);
            }
        }
        finally { EndPaint(window, ref paint); }
    }
    private static void Separator(IntPtr dc, IntPtr pen, int left, int y, int right)
    {
        var previous = SelectObject(dc, pen);
        try { MoveToEx(dc, left, y, IntPtr.Zero); LineTo(dc, right, y); }
        finally { SelectObject(dc, previous); }
    }
    private static void Glyph(IntPtr dc, int id, int x, int cy, int size, uint colour, bool resume)
    {
        var brush = CreateSolidBrush(colour);
        var pen = CreatePen(0, Math.Max(2, (int)Math.Round(size / 8.0)), colour);
        var oldBrush = SelectObject(dc, brush); var oldPen = SelectObject(dc, pen);
        try
        {
            int half = size / 2;
            // Segoe Fluent draws Stop/Pause as thin hollow outlines that read
            // as empty boxes in a menu. Keep solid hand-drawn shapes for those
            // two actions and use the shell font only for settings/exit.
            if (id is 3 or 4)
            {
                string glyph = id == 3 ? "\uE713" : "\uF3B1";
                var iconFont = IconFont(size);
                if (iconFont != IntPtr.Zero && IconGlyph(dc, iconFont, glyph, x, cy, size, colour)) return;
            }
            switch (id)
            {
                case 5: Polygon(dc, [new GlyphPoint { X = x + 2, Y = cy - half }, new GlyphPoint { X = x + size - 1, Y = cy }, new GlyphPoint { X = x + 2, Y = cy + half }], 3); break;
                case 1 or 6: RoundRect(dc, x, cy - half, x + size, cy + half, 5, 5); break;
                case 2 when resume: Polygon(dc, [new GlyphPoint { X = x + 1, Y = cy - half }, new GlyphPoint { X = x + size, Y = cy }, new GlyphPoint { X = x + 1, Y = cy + half }], 3); break;
                case 2: RoundRect(dc, x + 2, cy - half, x + 2 + size / 3, cy + half, 3, 3);
                        RoundRect(dc, x + size - size / 3 - 2, cy - half, x + size - 2, cy + half, 3, 3); break;
                case 3:
                    // Gear: a hub ring with eight teeth. The previous sun-like
                    // ellipse with four ticks read as a brightness control.
                {
                    // A thick ring plus short thick teeth merge into a gear
                    // silhouette; thin lines on a large ellipse read as a sun.
                    int centre = x + half, ring = Math.Max(3, half - 5);
                    var gear = CreatePen(0, Math.Max(2, (int)Math.Round(size / 7.0)), colour);
                    var previous = SelectObject(dc, gear);
                    try
                    {
                        // Teeth are filled quads on the rim, not radial lines:
                        // lines from the centre are what made this look like a
                        // brightness sun no matter how many were drawn.
                        for (int step = 0; step < 8; step++)
                        {
                            double angle = step * Math.PI / 4, spread = 0.30, inner = ring - 1, outer = half - 1;
                            Polygon(dc, [
                                new GlyphPoint { X = centre + (int)Math.Round(Math.Cos(angle - spread) * inner), Y = cy + (int)Math.Round(Math.Sin(angle - spread) * inner) },
                                new GlyphPoint { X = centre + (int)Math.Round(Math.Cos(angle - spread * .55) * outer), Y = cy + (int)Math.Round(Math.Sin(angle - spread * .55) * outer) },
                                new GlyphPoint { X = centre + (int)Math.Round(Math.Cos(angle + spread * .55) * outer), Y = cy + (int)Math.Round(Math.Sin(angle + spread * .55) * outer) },
                                new GlyphPoint { X = centre + (int)Math.Round(Math.Cos(angle + spread) * inner), Y = cy + (int)Math.Round(Math.Sin(angle + spread) * inner) },
                            ], 4);
                        }
                        Ellipse(dc, centre - ring, cy - ring, centre + ring, cy + ring);
                    }
                    finally { SelectObject(dc, previous); DeleteObject(gear); }
                    break;
                }
                default:
                    // Log out: a door open on the right with an arrow leaving it.
                    MoveToEx(dc, x + half - 3, cy - half + 1, IntPtr.Zero);
                    LineTo(dc, x + 1, cy - half + 1);
                    LineTo(dc, x + 1, cy + half - 1);
                    LineTo(dc, x + half - 3, cy + half - 1);
                    MoveToEx(dc, x + half - 2, cy, IntPtr.Zero);
                    LineTo(dc, x + size - 2, cy);
                    Polygon(dc, [new GlyphPoint { X = x + size - 1, Y = cy },
                                 new GlyphPoint { X = x + size - 6, Y = cy - 4 },
                                 new GlyphPoint { X = x + size - 6, Y = cy + 4 }], 3);
                    break;
            }
        }
        finally { SelectObject(dc, oldBrush); SelectObject(dc, oldPen); DeleteObject(brush); DeleteObject(pen); }
    }
    // Menu row icons come from the shell icon font, which is what a Windows
    // application is expected to look like. Probing the face name keeps the
    // fallback honest: a font that is not installed reports its substitute.
    private static IntPtr iconFontHandle;
    private static int iconFontSize;
    private static bool iconFontProbed, iconFontPresent;
    private static IntPtr IconFont(int size)
    {
        if (!iconFontProbed)
        {
            iconFontProbed = true;
            var probe = CreateFontW(-16, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe Fluent Icons");
            if (probe != IntPtr.Zero)
            {
                var dc = GetDC(IntPtr.Zero);
                if (dc != IntPtr.Zero)
                {
                    var previous = SelectObject(dc, probe);
                    var name = new System.Text.StringBuilder(64);
                    if (GetTextFaceW(dc, name.Capacity, name) > 0) iconFontPresent = name.ToString() == "Segoe Fluent Icons";
                    SelectObject(dc, previous); ReleaseDC(IntPtr.Zero, dc);
                }
                DeleteObject(probe);
            }
        }
        if (!iconFontPresent) return IntPtr.Zero;
        if (iconFontHandle != IntPtr.Zero && iconFontSize == size) return iconFontHandle;
        if (iconFontHandle != IntPtr.Zero) DeleteObject(iconFontHandle);
        iconFontHandle = CreateFontW(-size, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe Fluent Icons");
        iconFontSize = size;
        return iconFontHandle;
    }
    private static bool IconGlyph(IntPtr dc, IntPtr font, string glyph, int x, int cy, int size, uint colour)
    {
        var previous = SelectObject(dc, font);
        try
        {
            SetBkMode(dc, 1); SetTextColor(dc, colour);
            var rect = Rect(x, cy - size / 2, x + size, cy + size / 2);
            return DrawTextW(dc, glyph, glyph.Length, ref rect, 0x1 | 0x4 | 0x20 | 0x2000 | 0x8000) != 0;
        }
        finally { SelectObject(dc, previous); }
    }
    private static IntPtr headerGlyph;
    private static int headerGlyphSize;
    private static int headerGlyphState = -1;
    private static int visualState = 1;
    internal static void SetVisualState(int state) { if (state is >= 0 and < 9) visualState = state; }
    // The menu header carries the same petal mark as the tray icon instead of
    // the generic application icon. Both sources are owned by the module or by
    // TrayStateIcons' cache, so nothing here is ever destroyed.
    private static IntPtr HeaderGlyph(int size)
    {
        if (headerGlyph != IntPtr.Zero && headerGlyphSize == size && headerGlyphState == visualState) return headerGlyph;
        try { headerGlyph = TrayStateIcons.Load(visualState, size, size); headerGlyphState = visualState; }
        catch (Exception) { headerGlyph = LoadImageW(GetModuleHandleW(null), new IntPtr(32512), 1, size, size, 0x8000); }
        headerGlyphSize = size;
        return headerGlyph;
    }
    private static string FirstLine(string value)
    {
        int cut = value.IndexOf('\n');
        return cut < 0 ? value : value[..cut].TrimEnd('\r');
    }
    private static Native.Rect Rect(int left, int top, int right, int bottom) => new() { Left = left, Top = top, Right = right, Bottom = bottom };
    private static void Text(IntPtr dc, IntPtr font, uint colour, ref Native.Rect rect, string value, uint flags)
    {
        var previous = SelectObject(dc, font);
        try { SetBkMode(dc, 1); SetTextColor(dc, colour); DrawTextW(dc, value, value.Length, ref rect, flags | 0x2000); }
        finally { SelectObject(dc, previous); }
    }
    private static uint Rgb(int r, int g, int b) => (uint)(r | g << 8 | b << 16);
    private static IntPtr WindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        try
        {
            switch (message)
            {
                case 0x14: return new IntPtr(1);
                case 0xF: Draw(); return IntPtr.Zero;
                case 0x113:
                    if (wp.ToUInt64() == 1)
                    {
                        frame++;
                        int offset = Math.Max(0, SlidePx * (FrameCount - frame) / FrameCount);
                        byte alpha = (byte)Math.Min(255, frame * 255 / FrameCount);
                        SetLayeredWindowAttributes(hwnd, 0, alpha, 2);
                        SetWindowPos(hwnd, new IntPtr(-1), finalX, finalY + offset, popupWidth, popupHeight, 0x0010);
                        if (frame >= FrameCount) KillTimer(hwnd, new UIntPtr(1));
                    }
                    return IntPtr.Zero;
                case 0x86:
                    // FALSE here vetoes the active-window change, even if the
                    // popup has already hidden itself. Let USER32 complete the
                    // transition; close only after actual WA_INACTIVE below.
                    return DefWindowProcW(hwnd, message, wp, lp);
                case 6:
                {
                    var result = DefWindowProcW(hwnd, message, wp, lp);
                    if ((wp.ToUInt64() & 0xffff) == 0)
                    { CancelMousePress(); if (!previewMode) Hide(restore: false); }
                    else activated = true;
                    return result;
                }
                case 0x200:
                {
                    var point = new Native.Point { X = unchecked((short)(lp.ToInt64() & 0xffff)), Y = unchecked((short)((lp.ToInt64() >> 16) & 0xffff)) };
                    int index = HitTest(point.X, point.Y);
                    if (index != hoverIndex)
                    {
                        hoverIndex = index; if (index > 0) selectIndex = index;
                        InvalidateRect(hwnd, IntPtr.Zero, false);
                    }
                    var tracking = new MouseTracking { Size = (uint)Marshal.SizeOf<MouseTracking>(), Flags = 2, Window = hwnd };
                    TrackMouseEvent(ref tracking);
                    return IntPtr.Zero;
                }
                case 0x2A3:
                    if (hoverIndex != -1) { hoverIndex = -1; InvalidateRect(hwnd, IntPtr.Zero, false); }
                    if (!activated) Hide(restore: false);
                    return IntPtr.Zero;
                case 0x201:
                {
                    CancelMousePress();
                    int x = unchecked((short)(lp.ToInt64() & 0xffff)), y = unchecked((short)((lp.ToInt64() >> 16) & 0xffff));
                    if (EnabledRow(HitTest(x, y)))
                    {
                        SetCapture(hwnd);
                        if (GetCapture() == hwnd) MousePress(x, y);
                    }
                    return IntPtr.Zero;
                }
                case 0x202:
                    int released = GetCapture() == hwnd
                        ? MouseRelease(unchecked((short)(lp.ToInt64() & 0xffff)), unchecked((short)((lp.ToInt64() >> 16) & 0xffff))) : -1;
                    CancelMousePress();
                    if (released > 0) Activate(rows[released]);
                    return IntPtr.Zero;
                case 0x215: CancelMousePress(releaseCapture: false); return IntPtr.Zero; // WM_CAPTURECHANGED
                case 0x1f: CancelMousePress(); return IntPtr.Zero; // WM_CANCELMODE
                case 0x100:
                {
                    CancelMousePress();
                    int key = (int)wp.ToUInt32();
                    if (key == 0x1B) { Hide(restore: true); return IntPtr.Zero; }
                    if (key is 0x26 or 0x28)
                    {
                        MoveSelection(key == 0x26 ? -1 : 1); InvalidateRect(hwnd, IntPtr.Zero, false);
                    }
                    if (key == 0x0D && EnabledRow(selectIndex)) Activate(rows[selectIndex]);
                    return IntPtr.Zero;
                }
                default: return DefWindowProcW(hwnd, message, wp, lp);
            }
        }
        catch (Exception) { Console.Error.WriteLine("tray_menu_paint_failed"); return DefWindowProcW(hwnd, message, wp, lp); }
    }
    private static int HitTest(int y)
    {
        // hitboxes[0] shadows the header; every later entry lines up with the
        // row at the same index.
        for (int index = 1; index < rows.Count && index < hitboxes.Count; index++)
            if (hitboxes[index].Top >= 0 && y >= hitboxes[index].Top && y < hitboxes[index].Top + hitboxes[index].Height) return index;
        return -1;
    }
    private static bool EnabledRow(int index) => index > 0 && index < rows.Count && rows[index].Enabled;
    private static int HitTest(int x, int y)
        => x >= (int)Math.Round(8 * scale) && x < popupWidth - (int)Math.Round(8 * scale) ? HitTest(y) : -1;
    private static void MousePress(int x, int y)
    {
        int index = HitTest(x, y);
        pressedIndex = EnabledRow(index) ? index : -1;
    }
    private static int MouseRelease(int x, int y)
    {
        int pressed = pressedIndex; pressedIndex = -1;
        int released = HitTest(x, y);
        return pressed == released && EnabledRow(released) ? released : -1;
    }
    private static void CancelMousePress(bool releaseCapture = true)
    {
        pressedIndex = -1;
        if (releaseCapture && window != IntPtr.Zero && GetCapture() == window) ReleaseCapture();
    }
    private static void MoveSelection(int direction)
    {
        int index = EnabledRow(selectIndex) ? selectIndex : 0;
        for (int step = 0; step < rows.Count; step++)
        {
            index += direction;
            if (index <= 0) index = rows.Count - 1; else if (index >= rows.Count) index = 1;
            if (rows[index].Enabled) break;
        }
        selectIndex = hoverIndex = index;
    }
    internal static object SelfTest()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("tray_menu_selftest_failed_" + assertions); }
        var open = BuildRows(false, UiText.Get("普通控制"), "detail");
        Require(open.Count == 6 && open[0].Id == 0 && !open[0].Enabled);
        Require(open[1].Id == 6 && open[1].Danger && open[1].Shortcut == "Ctrl+Alt+Shift+9");
        Require(open.Single(r => r.Id == 1).Danger && open.Single(r => r.Id == 1).Shortcut == "Ctrl+Alt+9");
        Require(open.Single(r => r.Id == 2).Label.Contains(UiText.Get("暂停")) && open[^1].Label == UiText.Get("退出"));
        var paused = BuildRows(true, UiText.Get("普通控制"), "detail");
        Require(paused.Single(r => r.Id == 2).Label.Contains(UiText.Get("继续")) && paused[0].Label.Contains(UiText.Get("已暂停")));
        Require(BuildRows(false, "fixture", "detail", globalPaused: true).Any(r => r.Id == 5 && r.Enabled));
        assertions += ProductDiagnostics.SelfTest();
        // Tray pops up-left from the cursor and never leaves the work area.
        var (x, y) = PositionFor(0, 0, 1920, 1080, 1900, 1060, 300, 240);
        Require(x == 1612 && y == 810);
        (x, y) = PositionFor(0, 0, 1920, 1080, 100, 120, 300, 240);
        Require(x == 8 && y == 8);
        Require(FirstLine(UiText.Get("第一行\r\n第二行")) == UiText.Get("第一行") && FirstLine(UiText.Get("单行")) == UiText.Get("单行"));
        // hitboxes[0] belongs to the header and is never clickable; the row at
        // index n answers exactly for hitboxes[n].
        rows = open; hitboxes.Clear(); hitboxes.Add((-1, -1));
        for (int index = 1; index < rows.Count; index++) hitboxes.Add((100 + index * 40, 32));
        Require(HitTest(5) == -1);
        Require(HitTest(146) == 1 && HitTest(226) == 3);
        Require(HitTest(1000) == -1);
        // A release without a matching press must never dispatch stale hover.
        hoverIndex = 4; popupWidth = 300; scale = 1;
        Require(MouseRelease(20, 226) == -1);
        Require(MouseRelease(20, 266) == -1);
        MousePress(20, 226); Require(MouseRelease(20, 226) == 3);
        Require(MouseRelease(20, 226) == -1); // At most once.
        MousePress(20, 266); Require(MouseRelease(20, 226) == -1);
        MousePress(20, 226); Require(MouseRelease(20, 266) == -1);
        foreach (int outside in new[] { -1, 0, 7, 292, 300 })
        { MousePress(20, 266); Require(MouseRelease(outside, 266) == -1); MousePress(outside, 266); Require(MouseRelease(20, 266) == -1); }
        MousePress(20, 226); Require(MouseRelease(20, 258) == -1); // Separator.
        var disabled = rows[3]; rows[3] = disabled with { Enabled = false };
        MousePress(20, 226); Require(MouseRelease(20, 226) == -1);
        rows[3] = disabled;
        MousePress(20, 226); rows[3] = disabled with { Enabled = false };
        Require(MouseRelease(20, 226) == -1); rows[3] = disabled;
        MousePress(20, 266); CancelMousePress(); Require(MouseRelease(20, 266) == -1);
        MousePress(20, 266); Hide(false); Require(MouseRelease(20, 266) == -1);
        MousePress(20, 266); WindowProc(IntPtr.Zero, 0x215, UIntPtr.Zero, IntPtr.Zero); Require(MouseRelease(20, 266) == -1);
        MousePress(20, 266); WindowProc(IntPtr.Zero, 0x1f, UIntPtr.Zero, IntPtr.Zero); Require(MouseRelease(20, 266) == -1);
        selectIndex = -1; MoveSelection(1); Require(selectIndex == 1);
        MoveSelection(-1); Require(selectIndex == rows.Count - 1);
        var beforeLast = rows[^2]; rows[^2] = beforeLast with { Enabled = false };
        MoveSelection(-1); Require(selectIndex == rows.Count - 3); rows[^2] = beforeLast;
        // Preview may select Exit, but never acts on even a synthetic broker.
        var testCore = new BrokerState(); coreState = testCore; previewMode = true;
        try { Activate(rows[^1]); Require(!testCore.Shutdown.IsCancellationRequested); }
        finally { previewMode = false; coreState = null; }
        CancelMousePress(); hoverIndex = selectIndex = -1;
        hitboxes.Clear();
        return new { assertions, windowCreated = false, nativeInputExecuted = false };
    }
}

