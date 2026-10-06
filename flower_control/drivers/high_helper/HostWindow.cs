using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static class HostWindow
{
    private delegate IntPtr Procedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Class
    {
        public uint Size, Style; public IntPtr Proc; public int ClassExtra, WindowExtra;
        public IntPtr Instance, Icon, Cursor, Background;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Menu;
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public IntPtr SmallIcon;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Message
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
    [DllImport("user32.dll")] private static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool AppendMenuW(IntPtr menu, uint flags, UIntPtr id, string text);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    [DllImport("user32.dll")] private static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr hwnd, IntPtr rect);
    [DllImport("user32.dll")] private static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessageW(string message);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr change);
    private static readonly Procedure Proc = WindowProc;
    private static BrokerState? state;
    private static IconData icon;
    private static IntPtr window;
    private static TrayRegistration? tray;
    private static uint taskbarCreated;
    internal static void Run(BrokerState core)
    {
        state = core;
        var instance = GetModuleHandleW(null);
        var name = "FlowerControlHighBroker." + Environment.ProcessId;
        var value = new Class { Size = (uint)Marshal.SizeOf<Class>(), Proc = Marshal.GetFunctionPointerForDelegate(Proc), Instance = instance, Name = name };
        if (RegisterClassExW(ref value) == 0) throw new Boundary("host_window_register_failed", Marshal.GetLastWin32Error());
        try
        {
            window = CreateWindowExW(0, name, "Flower Control 管理员助手", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
            if (window == IntPtr.Zero || !SetPropW(window, "FlowerControlTaskIndicator", new IntPtr(1)))
                throw new Boundary("host_window_failed", Marshal.GetLastWin32Error());
            if (!WTSRegisterSessionNotification(window, 0)) throw new Boundary("session_notification_failed", Marshal.GetLastWin32Error());
            bool hotkey = RegisterHotKey(window, 9, 0x4003, 0x39); // Ctrl+Alt, main-row 9, MOD_NOREPEAT.
            core.HotkeyAvailable(hotkey, hotkey ? null : Marshal.GetLastWin32Error());
            icon = new IconData { Size = (uint)Marshal.SizeOf<IconData>(), Hwnd = window, Id = 1, Flags = 7, Callback = 0x8001,
                Icon = LoadTrayIcon(), Tip = "Flower Control 管理员助手", Info = "", Title = "" };
            taskbarCreated = RegisterWindowMessageW("TaskbarCreated");
            if (taskbarCreated != 0) ChangeWindowMessageFilterEx(window, taskbarCreated, 1, IntPtr.Zero);
            // The exact private tray callback and shell-restart notification
            // must reach this High window from Explorer. No other message or
            // window filter is changed; failed restart delivery has polling.
            ChangeWindowMessageFilterEx(window, 0x8001, 1, IntPtr.Zero);
            tray = new(() => Shell_NotifyIconW(0, ref icon), () => Shell_NotifyIconW(1, ref icon),
                       () => Shell_NotifyIconW(2, ref icon), TrayIconExists);
            UpdateTray(core);
            if (SetTimer(window, new UIntPtr(1), 100, IntPtr.Zero) == UIntPtr.Zero)
                throw new Boundary("host_timer_failed", Marshal.GetLastWin32Error());
            while (true)
            {
                var result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result == 0) break;
                if (result < 0) throw new Boundary("host_message_loop_failed");
                TranslateMessage(ref message); DispatchMessageW(ref message);
            }
        }
        finally
        {
            KillTimer(window, new UIntPtr(1)); tray?.Close(); tray = null; core.TrayAvailable(false);
            UnregisterHotKey(window, 9); core.HotkeyAvailable(false);
            WTSUnRegisterSessionNotification(window);
            if (Native.IsWindow(window)) DestroyWindow(window);
            UnregisterClassW(name, instance); state = null;
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
    private static void UpdateTray(BrokerState core)
    {
        icon.Tip = "Flower Control 管理员助手：" + core.Summary;
        tray?.Tick(Environment.TickCount64, core.Summary);
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
        if (sessionEnded) core.Stop();
        return IntPtr.Zero;
    }
    private static IntPtr WindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        var core = state;
        if (core is null) return DefWindowProcW(hwnd, message, wp, lp);
        if (taskbarCreated != 0 && message == taskbarCreated)
        {
            tray?.ExplorerRestarted(Environment.TickCount64); UpdateTray(core);
            return IntPtr.Zero;
        }
        if (message == 0x113)
        {
            BrokerHost.PollDesktop(core);
            UpdateTray(core);
            if (core.Shutdown.IsCancellationRequested) { DestroyWindow(hwnd); PostQuitMessage(0); }
            return IntPtr.Zero;
        }
        if (message == 0x312 && wp.ToUInt32() == 9)
        {
            core.Pause(true); // Shared gate closes before cancellation; no database or model wait.
            UpdateTray(core);
            return IntPtr.Zero;
        }
        if (message == 0x2b1)
        {
            var change = wp.ToUInt32();
            if (change is 2 or 4 or 7) core.Desktop(false, "desktop_locked");
            if (change is 1 or 3 or 8) { core.Desktop(false, "desktop_transition"); BrokerHost.PollDesktop(core); }
            if (change == 6) core.Stop();
            return IntPtr.Zero;
        }
        var sessionResult = EndSessionMessage(core, message, wp != UIntPtr.Zero);
        if (sessionResult is { } handled) return handled;
        if (message == 0x8001 && lp.ToInt64() is 0x205 or 0x203)
        {
            var stopSnapshot = core.WriteGate?.Snapshot();
            bool resumeSelected = stopSnapshot?.Stopped ?? core.IsPaused;
            var menu = CreatePopupMenu();
            try
            {
                AppendMenuW(menu, 2, UIntPtr.Zero, core.Summary);
                AppendMenuW(menu, 0, new UIntPtr(1), resumeSelected ? "恢复全部写入（需要新观察）" : "停止全部写入（Ctrl+Alt+9）");
                AppendMenuW(menu, 0, new UIntPtr(2), "正常退出管理员助手");
                GetCursorPos(out var point);
                // Native menu is an explicit user entry; protected from Flower targeting.
                Native.SetForegroundWindow(hwnd);
                var selected = TrackPopupMenu(menu, 0x100 | 0x2, point.X, point.Y, 0, hwnd, IntPtr.Zero);
                if (selected == 1)
                {
                    try { core.Pause(!resumeSelected, stopSnapshot?.Epoch); }
                    catch (Boundary error) when (error.Code == "resume_state_changed")
                    { Console.Error.WriteLine("New Stop retained; reopen the tray menu to resume."); }
                }
                if (selected == 2) core.Stop();
            }
            finally { DestroyMenu(menu); }
            return IntPtr.Zero;
        }
        return DefWindowProcW(hwnd, message, wp, lp);
    }
}
