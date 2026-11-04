using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static class HostWindow
{
    private const uint OpenSettingsMessage = 0x8002;
    [DllImport("user32.dll", SetLastError = true)] private static extern bool PostMessageW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    internal static void RequestSettings(BrokerState core)
    {
        // Only the authenticated local admin pipe calls this. The private UI
        // message is not admitted through UIPI; no policy or Stop is changed.
        if (!ReferenceEquals(state, core) || core.Shutdown.IsCancellationRequested || window == IntPtr.Zero
            || !PostMessageW(window, OpenSettingsMessage, UIntPtr.Zero, IntPtr.Zero))
            throw new Boundary("settings_window_unavailable");
    }
    [DllImport("user32.dll")] private static extern uint GetDoubleClickTime();
    private static long lastTraySelect = long.MinValue;
    internal sealed record CallbackFailure(uint Message, string Error, long Sequence);
    private static CallbackFailure? callbackFailure;
    internal static CallbackFailure? CallbackDiagnostics => Volatile.Read(ref callbackFailure);
    private delegate IntPtr Procedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Class
    {
        public uint Size, Style; public IntPtr Proc; public int ClassExtra, WindowExtra;
        public IntPtr Instance, Icon, Cursor, Background;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Menu;
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public IntPtr SmallIcon;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Message
    { public IntPtr Hwnd; public uint Kind; public UIntPtr Wp; public IntPtr Lp; public uint Time; public int X, Y; public uint Private; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct IconData
    {
        public uint Size; public IntPtr Hwnd; public uint Id, Flags, Callback; public IntPtr Icon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Tip;
        public uint State, StateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Info;
        public uint Timeout;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string Title;
        public uint InfoFlags; public Guid Guid; public IntPtr Balloon;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IconIdentifier
    { public uint Size; public IntPtr Hwnd; public uint Id; public Guid Guid; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? module);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ushort RegisterClassExW(ref Class value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool UnregisterClassW(string name, IntPtr instance);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateWindowExW(uint ex, string name, string title, uint style, int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr data);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] private static extern int GetMessageW(out Message message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Message message);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref Message message);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern UIntPtr SetTimer(IntPtr hwnd, UIntPtr id, uint ms, IntPtr proc);
    [DllImport("user32.dll")] private static extern bool KillTimer(IntPtr hwnd, UIntPtr id);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool RegisterHotKey(IntPtr hwnd, int id, uint modifiers, uint key);
    [DllImport("user32.dll")] private static extern bool UnregisterHotKey(IntPtr hwnd, int id);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetPropW(IntPtr hwnd, string name, IntPtr value);
    [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSRegisterSessionNotification(IntPtr hwnd, uint flags);
    [DllImport("wtsapi32.dll")] private static extern bool WTSUnRegisterSessionNotification(IntPtr hwnd);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern bool Shell_NotifyIconW(uint command, ref IconData data);
    [DllImport("shell32.dll")] private static extern int Shell_NotifyIconGetRect(ref IconIdentifier identifier, out Native.Rect location);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr LoadImageW(IntPtr instance, IntPtr name, uint type, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessageW(string message);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr change);
    private static readonly Procedure Proc = WindowProc;
    private static BrokerState? state;
    private static IconData icon;
    private static IntPtr window;
    private static TrayRegistration? tray;
    private static uint taskbarCreated;
    private static Task<string?>? permissionSave;
    private static CancellationTokenSource? permissionSaveStop;
    private static long trayPermissionReadAt = long.MinValue;
    private static string trayPermissionSummary = "权限状态待核对";
    private static UserPermissionSettings? trayPermissions;
    private static UacCapabilities? trayCapabilities;
    private static bool trayPermissionFault;
    private static bool computerHotkeyRegistered, emergencyHotkeyRegistered;
    private static string? trayPermissionRevision;
    internal static void BeginOrdinaryControl(BrokerState core, LocalUiOperation operation)
    {
        if (!core.OrdinaryResident || permissionSave is not null) throw new Boundary("local_writer_busy");
        permissionSaveStop = new(); var token = permissionSaveStop.Token;
        permissionSave = Task.Run(() =>
        {
            try { LocalUiWriter.Execute(core, operation, null, token); return (string?)null; }
            catch (Exception error) { return Program.Code(error); }
        });
    }
    internal static string PrivilegeSummary(UserPermissionSettings permissions)
    {
        int tier = UserPermissions.TierOf(permissions);
        if (tier < 0) return UiText.Get("01 完全停止｜App/Computer/Web 停止派发");
        if (permissions.UacPolicyError is not null) return UiText.Get("故障｜权限配置需修复");
        if (tier == 0) return UiText.Get("02 普通控制｜管理员能力关闭");
        if (tier == 1) return UiText.Get("03 管理员窗口｜不启动管理员进程");
        string launch = permissions.AdminLaunchMode == "semantic" ? UiText.Get("启动：语义授权") : UiText.Get("启动：名单");
        return (tier == 2 ? UiText.Get("04 管理员执行｜") : UiText.Get("旧系统接管（已冻结）｜")) + launch + UiText.Get("｜UAC 已冻结");
    }
    internal static void Run(BrokerState core)
    {
        state = core;
        var instance = GetModuleHandleW(null);
        var name = "FlowerControlHighBroker." + Environment.ProcessId;
        var value = new Class { Size = (uint)Marshal.SizeOf<Class>(), Proc = Marshal.GetFunctionPointerForDelegate(Proc), Instance = instance, Name = name };
        if (RegisterClassExW(ref value) == 0) throw new Boundary("host_window_register_failed", Marshal.GetLastWin32Error());
        try
        {
            window = CreateWindowExW(0, name, UiText.Get("Flower Control 管理员助手"), 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
            if (window == IntPtr.Zero || !SetPropW(window, "FlowerControlTaskIndicator", new IntPtr(1)))
                throw new Boundary("host_window_failed", Marshal.GetLastWin32Error());
            if (!WTSRegisterSessionNotification(window, 0)) throw new Boundary("session_notification_failed", Marshal.GetLastWin32Error());
            computerHotkeyRegistered = emergencyHotkeyRegistered = false;
            RefreshStopHotkeys(core);
            icon = new IconData { Size = (uint)Marshal.SizeOf<IconData>(), Hwnd = window, Id = 1, Flags = 7, Callback = 0x8001,
                Icon = LoadTrayIcon(), Tip = UiText.Get("Flower Control 管理员助手"), Info = "", Title = "" };
            taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
            if (taskbarCreated != 0) ChangeWindowMessageFilterEx(window, taskbarCreated, 1, IntPtr.Zero);
            // The exact private tray callback and shell-restart notification
            // must reach this High window from Explorer. No other message or
            // window filter is changed; failed restart delivery has polling.
            ChangeWindowMessageFilterEx(window, 0x8001, 1, IntPtr.Zero);
            tray = new(() => Shell_NotifyIconW(0, ref icon), () => Shell_NotifyIconW(1, ref icon),
                       () => Shell_NotifyIconW(2, ref icon), TrayIconExists);
            UpdateTray(core);
            try
            {
                if (SettingsWorkspace.HasIncomingHandoff || ShouldOpenFirstRun(UserPermissions.Read()))
                    SettingsWorkspace.Show(window, core);
            }
            catch (Exception error)
            { Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { settingsDraftImport = Program.Code(error) })); }
            if (SetTimer(window, new UIntPtr(1), 100, IntPtr.Zero) == UIntPtr.Zero)
                throw new Boundary("host_timer_failed", Marshal.GetLastWin32Error());
            while (true)
            {
                var result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result == 0) { core.Stop(BrokerShutdownReason.HostMessageQuit); break; }
                if (result < 0) throw new Boundary("host_message_loop_failed");
                if (!SettingsWorkspace.HandleDialogMessage(ref message) && !PermissionSettingsWindow.HandleDialogMessage(ref message))
                { TranslateMessage(ref message); DispatchMessageW(ref message); }
            }
        }
        finally
        {
            try { SettingsWorkspace.ShutdownOwnedWork(); PermissionSettingsWindow.ShutdownOwnedWork(); }
            finally
            {
                // Do not strand a partially committed preference change on exit.
                permissionSaveStop?.Cancel();
                try { permissionSave?.GetAwaiter().GetResult(); }
                finally { permissionSaveStop?.Dispose(); permissionSaveStop = null; permissionSave = null; }
                KillTimer(window, new UIntPtr(1)); tray?.Close(); tray = null; core.TrayAvailable(false);
                TrayStateIcons.Release();
                UnregisterHotKey(window, 9); core.HotkeyAvailable(false);
                UnregisterHotKey(window, 10); core.EmergencyHotkeyAvailable(false);
                computerHotkeyRegistered = emergencyHotkeyRegistered = false;
                WTSUnRegisterSessionNotification(window);
                if (Native.IsWindow(window)) DestroyWindow(window);
                UnregisterClassW(name, instance); state = null;
            }
        }
    }
    internal static IntPtr LoadTrayIcon()
    {
        // ApplicationIcon embeds group 32512 in this apphost. Select the small
        // system size from its multiresolution petal icon. LR_SHARED belongs to
        // the loaded module and must not be passed to DestroyIcon.
        var handle = LoadImageW(GetModuleHandleW(null), new IntPtr(32512), 1,
            Math.Max(16, GetSystemMetrics(49)), Math.Max(16, GetSystemMetrics(50)), 0x8000);
        if (handle == IntPtr.Zero) throw new Boundary("tray_icon_load_failed", Marshal.GetLastWin32Error());
        return handle;
    }
    internal static bool ShouldOpenFirstRun(UserPermissionSettings permissions)
        => permissions.Revision == "absent" && UserPermissions.TierOf(permissions) == 0;
    private static void RefreshStopHotkeys(BrokerState core)
    {
        // Role handoff can briefly leave the old helper owning either key.
        // Retry only unregistered keys on the existing one-second tray cadence;
        // a conflicting application retains its registration and buttons work.
        if (!computerHotkeyRegistered)
        {
            computerHotkeyRegistered = RegisterHotKey(window, 9, 0x4003, 0x39);
            core.HotkeyAvailable(computerHotkeyRegistered, computerHotkeyRegistered ? null : Marshal.GetLastWin32Error());
        }
        if (!emergencyHotkeyRegistered)
        {
            emergencyHotkeyRegistered = RegisterHotKey(window, 10, 0x4007, 0x39);
            core.EmergencyHotkeyAvailable(emergencyHotkeyRegistered, emergencyHotkeyRegistered ? null : Marshal.GetLastWin32Error());
        }
    }
    private static void UpdateTray(BrokerState core)
    {
        long now = Environment.TickCount64;
        if (trayPermissionReadAt == long.MinValue || now - trayPermissionReadAt >= 1000)
        {
            RefreshStopHotkeys(core);
            SettingsWorkspace.RefreshDisplayPreference();
            try
            {
                trayPermissions = UserPermissions.Read(); trayPermissionFault = false;
                trayPermissionSummary = PrivilegeSummary(trayPermissions);
                if (trayPermissionRevision != trayPermissions.Revision)
                {
                    trayPermissionRevision = trayPermissions.Revision;
                    trayCapabilities = trayPermissions.UacMode == "off" ? null : UacRuntime.Capabilities();
                }
            }
            catch (Exception) { trayPermissionFault = true; trayPermissionSummary = UiText.Get("权限配置需修复"); }
            trayPermissionReadAt = now;
            // Bounded metadata only. Sampling cannot change dispatch, Stop or
            // the user's policy; its failure must never break the tray.
            try { ProductDiagnostics.Current.Observe(core.ProductStatus()); } catch { }
        }
        string summary = UiText.BrokerSummary(core.Summary) + UiText.Get("｜") + trayPermissionSummary;
        int tier = trayPermissions is null ? -1 : UserPermissions.TierOf(trayPermissions);
        bool route = tier switch {
            -1 or 0 or 1 or 2 => true,
            3 => false,
            _ => false };
        route &= !core.OrdinaryResident || tier <= 0;
        if (core.OrdinaryResident && tier > 0) summary += UiText.Get("｜普通执行器；管理员待确认");
        int visualState = TrayStateIcons.Select(tier, route && !core.IsPaused && !core.TrayUnavailable,
            trayPermissionFault || trayPermissions?.UacPolicyError is not null || core.TrayFaulted || core.ComputerPaused
                || core.EmergencyHotkeyRegistered == false);
        TrayMenu.SetVisualState(visualState);
        SettingsWorkspace.SetVisualState(visualState);
        icon.Icon = TrayStateIcons.Load(visualState, Math.Max(16, GetSystemMetrics(49)), Math.Max(16, GetSystemMetrics(50)));
        core.TrayVisualState(TrayStateIcons.DisplayName(visualState));
        summary += UiText.Get("｜图标：") + TrayStateIcons.DisplayName(visualState);
        icon.Tip = "Flower Control" + UiText.Get("｜") + summary;
        if (icon.Tip.Length > 127) icon.Tip = icon.Tip[..127];
        tray?.Tick(now, summary);
        core.TrayAvailable(tray?.Registered == true);
    }
    private static bool TrayIconExists()
    {
        if (window == IntPtr.Zero || icon.Hwnd != window || !Native.IsWindow(window)) return false;
        // This icon uses HWND/uID rather than NIF_GUID. S_OK confirms that the
        // Shell can locate it; it does not prove visual display or menu delivery.
        var identifier = new IconIdentifier { Size = (uint)Marshal.SizeOf<IconIdentifier>(), Hwnd = icon.Hwnd, Id = icon.Id, Guid = Guid.Empty };
        return Shell_NotifyIconGetRect(ref identifier, out _) == 0;
    }
    internal static IntPtr? EndSessionMessage(BrokerState core, uint message, bool sessionEnded)
    {
        // QUERYENDSESSION is negotiation: another application or the user can
        // still cancel. It must not permanently cancel this reusable broker.
        if (message == 0x11) return new IntPtr(1);
        if (message != 0x16) return null;
        if (sessionEnded) core.Stop(BrokerShutdownReason.SessionEnded);
        return IntPtr.Zero;
    }
    internal static bool HandlePowerMessage(BrokerState core, uint message, uint change, Action<BrokerState>? probe = null)
    {
        if (message != 0x218) return false; // WM_POWERBROADCAST.
        if (change == 4) core.Desktop(false, "system_suspended"); // PBT_APMSUSPEND.
        else if (change is 6 or 7 or 18)
        {
            // Resuming never revives the cancelled request or clears a durable
            // Stop. The next independent operation needs a fresh observation.
            core.Desktop(false, "desktop_transition");
            (probe ?? BrokerHost.PollDesktop)(core);
        }
        else return false;
        return true;
    }
    internal static bool HandleStopHotkey(BrokerState core, uint id)
    {
        if (id == 9) { core.StopComputerUse(); return true; }
        if (id == 10) { core.Pause(true); return true; }
        return false;
    }
    private static IntPtr WindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        try { return WindowMessageCore(hwnd, message, wp, lp); }
        catch (Exception error)
        {
            // Shared Stop reads and tray refresh can fail transiently. Preserve
            // the UI message loop; never retry the failed action or let an
            // exception escape a reverse P/Invoke callback into USER32.
            var previous = CallbackDiagnostics;
            var failure = new CallbackFailure(message, Program.Code(error), (previous?.Sequence ?? 0) + 1);
            Volatile.Write(ref callbackFailure, failure);
            try { Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { hostWindowFailure = failure })); }
            catch { }
            return IntPtr.Zero;
        }
    }
    private static IntPtr WindowMessageCore(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        if (message == OpenSettingsMessage)
        {
            if (state is { } active && !active.Shutdown.IsCancellationRequested) SettingsWorkspace.Show(hwnd, active);
            return IntPtr.Zero;
        }
        var core = state;
        if (core is null) return DefWindowProcW(hwnd, message, wp, lp);
        if (HandlePowerMessage(core, message, wp.ToUInt32())) return new IntPtr(1);
        if (taskbarCreated != 0 && message == taskbarCreated)
        {
            tray?.ExplorerRestarted(Environment.TickCount64); UpdateTray(core);
            return IntPtr.Zero;
        }
        if (message == 0x113)
        {
            // Exit must not depend on a successful permission/Stop refresh.
            // In particular a busy shared mutex must not strand a stopped
            // broker in its timer callback forever.
            if (core.Shutdown.IsCancellationRequested) { DestroyWindow(hwnd); PostQuitMessage(0); return IntPtr.Zero; }
            core.RefreshPermissions();
            BrokerHost.PollDesktop(core);
            UpdateTray(core);
            if (permissionSave is { IsCompleted: true } saved)
            {
                var failure = saved.GetAwaiter().GetResult(); permissionSave = null;
                permissionSaveStop?.Dispose(); permissionSaveStop = null;
                if (failure is not null && !core.Shutdown.IsCancellationRequested)
                {
                    Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { trayPermissionSave = failure }));
                    PermissionSettingsWindow.ShowError(hwnd, UiText.Get("设置保存或复核失败。请打开设置核对实际权限；停止状态不会自动恢复。") );
                }
            }
            return IntPtr.Zero;
        }
        if (message == 0x312 && HandleStopHotkey(core, wp.ToUInt32()))
        {
            // 9 retains Computer-only semantics; 10 latches all-channel Stop.
            UpdateTray(core);
            return IntPtr.Zero;
        }
        if (message == 0x2b1)
        {
            var change = wp.ToUInt32();
            if (change is 2 or 4 or 7) core.Desktop(false, "desktop_locked");
            if (change is 1 or 3 or 8) { core.Desktop(false, "desktop_transition"); BrokerHost.PollDesktop(core); }
            if (change == 6) core.Stop(BrokerShutdownReason.SessionLogoff);
            return IntPtr.Zero;
        }
        var sessionResult = EndSessionMessage(core, message, wp != UIntPtr.Zero);
        if (sessionResult is { } handled) return handled;
        if (message == 0x8001)
        {
            uint trayEvent = (uint)(lp.ToInt64() & 0xffff);
            // Legacy callbacks deliver button-up; newer Shell/keyboard paths
            // deliver NIN_SELECT/NIN_KEYSELECT or WM_CONTEXTMENU. A double click
            // already contains the first button-up; do not open twice.
            bool select = trayEvent is 0x202 or 0x400 or 0x401;
            bool context = trayEvent is 0x205 or 0x7b;
            if (!select && !context) return IntPtr.Zero;
            long now = Environment.TickCount64;
            if (select && lastTraySelect != long.MinValue && now - lastTraySelect <= GetDoubleClickTime()) return IntPtr.Zero;
            if (select) lastTraySelect = now;
            // Self-drawn dark popup; a local creation failure must not take
            // down the broker, its tray, or the emergency-stop message loop.
            try { TrayMenu.Show(hwnd, core); }
            catch (Exception error) { Console.Error.WriteLine("Tray menu failed: " + Program.Code(error)); }
            return IntPtr.Zero;
        }
        return DefWindowProcW(hwnd, message, wp, lp);
    }
}
