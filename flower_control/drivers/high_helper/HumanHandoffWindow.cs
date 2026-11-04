using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal sealed record HumanHandoffResult(string RequestId, string Resolution, int ExtensionSeconds);

// A visible request, never an authorization or a resume operation. The caller
// owns the paused task and re-observes it after explicit user continuation.
internal static class HumanHandoffWindow
{
    private delegate IntPtr Procedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Class
    { public uint Size, Style; public IntPtr Proc; public int Extra, WindowExtra; public IntPtr Instance, Icon, Cursor, Background; public string? Menu; public string Name; public IntPtr SmallIcon; }
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo
    { public uint Size; public Native.Rect Monitor, Work; public uint Flags; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern ushort RegisterClassExW(ref Class value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateWindowExW(uint ex, string kind, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr id, IntPtr instance, IntPtr data);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool EnableWindow(IntPtr hwnd, bool enabled);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int GetMessageW(out HostWindow.Message message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);
    [DllImport("user32.dll")] private static extern UIntPtr SetTimer(IntPtr hwnd, UIntPtr id, uint milliseconds, IntPtr callback);
    [DllImport("user32.dll")] private static extern bool KillTimer(IntPtr hwnd, UIntPtr id);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetWindowTextW(IntPtr hwnd, string text);
    [DllImport("user32.dll")] private static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool ScreenToClient(IntPtr hwnd, ref Native.Point point);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int w, int h, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] private static extern bool GetMonitorInfoW(IntPtr monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsChild(IntPtr parent, IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetNextDlgTabItem(IntPtr hwnd, IntPtr control, bool previous);
    [DllImport("user32.dll")] private static extern IntPtr GetFocus();
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern short GetKeyState(int key);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsDialogMessageW(IntPtr hwnd, ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern bool SystemParametersInfoW(uint action, uint param, out uint value, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetPropW(IntPtr hwnd, string name, IntPtr value);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateFontW(int height, int width, int angle, int orientation, int weight, uint italic, uint underline, uint strike, uint charset, uint output, uint clip, uint quality, uint pitch, string face);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr item);
    private static readonly Procedure Proc = WindowProc;
    private static int active;
    private static bool registered;
    private static Session? current;
    private const string ClassName = "FlowerControl.HumanHandoff";

    internal static HumanHandoffResult Run(string requestId, string message, int timeoutSeconds,
        CancellationToken cancellation, Action<string, int> onAction, Func<bool> stopRequested)
    {
        if (string.IsNullOrWhiteSpace(requestId) || requestId.Length > 128 || requestId.Contains('\0') ||
            string.IsNullOrWhiteSpace(message) || message.Trim().Length > 240 || message.Contains('\0') ||
            timeoutSeconds is < 10 or > 3600 || onAction is null || stopRequested is null)
            throw new Boundary("invalid_handoff_request");
        if (Thread.CurrentThread.GetApartmentState() != ApartmentState.STA) throw new Boundary("handoff_requires_sta_thread");
        if (Interlocked.CompareExchange(ref active, 1, 0) != 0) throw new Boundary("handoff_window_already_open");
        try
        {
            using var session = new Session(message.Trim(), timeoutSeconds, cancellation, onAction, stopRequested);
            current = session;
            if (!session.Poll())
            {
                session.Create();
                // The request is visible without seizing focus from the user's
                // current application. It never activates the controlled target.
                ShowWindow(session.Window, 4);
                if (!IsWindowVisible(session.Window)) throw new Boundary("handoff_window_show_failed");
                session.Shown();
                while (session.Resolution is null)
                {
                    int result = GetMessageW(out var nativeMessage, IntPtr.Zero, 0, 0);
                    if (result < 0) throw new Boundary("handoff_message_pump_failed");
                    if (result == 0) { session.Finish("cancelled"); break; }
                    if (session.Poll()) break;
                    if (!session.Keyboard(ref nativeMessage))
                    { TranslateMessage(ref nativeMessage); DispatchMessageW(ref nativeMessage); }
                }
            }
            return new(requestId, session.Resolution ?? "cancelled", session.ExtensionSeconds);
        }
        finally { current = null; Interlocked.Exchange(ref active, 0); }
    }

    internal static object NativeLayoutProbe()
    {
        if (Interlocked.CompareExchange(ref active, 1, 0) != 0) throw new Boundary("handoff_window_already_open");
        int assertions = 0;
        var foreground = Native.GetForegroundWindow();
        void Check(bool condition) { if (!condition) throw new Boundary("handoff_native_probe_failed"); assertions++; }
        try
        {
            var events = new List<(string Action, int Seconds)>(); double elapsed = 0;
            using (var state = new Session("合成请求", 10, CancellationToken.None,
                (action, seconds) => events.Add((action, seconds)), () => false, () => elapsed))
            {
                Check(!state.Poll()); state.Extend();
                Check(state.ExtensionSeconds == 300 && events.SequenceEqual(new[] { ("extend", 300) }));
                elapsed = 309.9; Check(!state.Poll()); elapsed = 310; Check(state.Poll() && state.Resolution == "expired");
                Check(events.Count == 1); state.Finish("completed"); Check(state.Resolution == "expired");
            }
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); events.Clear();
            elapsed = 0;
            using (var state = new Session("合成请求", 3590, CancellationToken.None,
                (action, seconds) => events.Add((action, seconds)), () => false, () => elapsed))
            {
                state.Extend(); Check(state.ExtensionSeconds == 10 && events.SequenceEqual(new[] { ("extend", 300) }));
                state.Extend(); Check(state.ExtensionSeconds == 10 && events.Count == 1);
                elapsed = 3600; Check(state.Poll() && state.Resolution == "expired");
            }
            events.Clear();
            using (var state = new Session("合成请求", 10, cancelled.Token,
                (action, seconds) => events.Add((action, seconds)), () => true, () => 1000))
            { Check(state.Poll() && state.Resolution == "stopped"); Check(events.SequenceEqual(new[] { ("stopped", 0) })); }
            events.Clear();
            using (var state = new Session("合成请求", 10, cancelled.Token,
                (action, seconds) => events.Add((action, seconds)), () => false))
            { Check(state.Poll() && state.Resolution == "cancelled"); Check(events.SequenceEqual(new[] { ("cancelled", 0) })); }
            using var form = new Session("这是独立合成接管提示。请完成示例操作后选择结果。", 300,
                CancellationToken.None, (_, _) => { }, () => false);
            current = form; form.Create();
            Check(Native.IsWindow(form.Window) && GetClientRect(form.Window, out _));
            GetClientRect(form.Window, out var client);
            foreach (var control in form.Controls)
            {
                Check(IsChild(form.Window, control.Handle));
                Check(GetWindowRect(control.Handle, out var bounds));
                var position = new Native.Point { X = bounds.Left, Y = bounds.Top };
                Check(ScreenToClient(form.Window, ref position));
                Check(position.X >= 0 && position.Y >= 0 && position.X + bounds.Right - bounds.Left <= client.Right &&
                    position.Y + bounds.Bottom - bounds.Top <= client.Bottom);
                if (control.Id == 2002) Check(position.Y + bounds.Bottom - bounds.Top < client.Bottom - form.Px(116));
            }
            Check(form.Controls.Count(control => control.Id is >= 30 and <= 33) == 4);
            form.Finish("cancelled"); Check(!Native.IsWindow(form.Window));
            Check(Native.GetForegroundWindow() == foreground);
            return new { assertions, nativeInputExecuted = false, policyReadOrWritten = false, foregroundChanged = false };
        }
        finally { current = null; Interlocked.Exchange(ref active, 0); }
    }

    private static IntPtr WindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        var session = current;
        try
        {
            if (session is not null)
            {
                if (message == 1) session.Window = hwnd;
                if (message == 0x111)
                {
                    if (session.Poll()) return IntPtr.Zero;
                    if ((wp.ToUInt64() >> 16) != 0) return IntPtr.Zero;
                    int id = (int)(wp.ToUInt64() & 0xffff);
                    if (id == 33) session.Finish("stopped");
                    else if (id == 30) session.Finish("completed");
                    else if (id == 31) session.Finish("cancelled");
                    else if (id == 32) session.Extend();
                    return IntPtr.Zero;
                }
                if (message == 0x113) { session.Poll(); session.UpdateRemaining(); return IntPtr.Zero; }
                if (message == 0x10) { if (!session.Poll()) session.Finish("cancelled"); return IntPtr.Zero; }
                if (message == 2) { session.Destroyed(hwnd); return IntPtr.Zero; }
                if (message == 0xF) { session.Visual?.PaintSurface(hwnd, false, 0, session.Scale, session.Px(116)); return IntPtr.Zero; }
                if (message == 0x14) return new IntPtr(1);
                if (message is >= 0x132 and <= 0x138)
                    return session.Visual?.ControlColor(new IntPtr(unchecked((long)wp.ToUInt64())), message, false, GetDlgCtrlID(lp)) ?? IntPtr.Zero;
                if (message is 0x1A or 0x31A) { session.Visual?.Reload(hwnd); InvalidateRect(hwnd, IntPtr.Zero, true); }
            }
        }
        catch (Exception)
        {
            Console.Error.WriteLine("human_handoff_window_failed");
            session?.Finish("cancelled");
        }
        return DefWindowProcW(hwnd, message, wp, lp);
    }

    private sealed class Session : IDisposable
    {
        internal IntPtr Window;
        internal PermissionVisual? Visual;
        internal double Scale = 1;
        internal string? Resolution;
        internal int ExtensionSeconds;
        private readonly string message;
        private readonly CancellationToken cancellation;
        private readonly Action<string, int> onAction;
        private readonly Func<bool> stopRequested;
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private readonly Func<double>? elapsedSeconds;
        private readonly int timeoutSeconds;
        private readonly List<IntPtr> fonts = [];
        internal readonly List<(int Id, IntPtr Handle)> Controls = [];
        private IntPtr remaining;
        private IntPtr extendButton;
        private int lastRemaining = -1;
        internal Session(string message, int timeoutSeconds, CancellationToken cancellation,
            Action<string, int> onAction, Func<bool> stopRequested, Func<double>? elapsedSeconds = null)
        { this.message = message; this.timeoutSeconds = timeoutSeconds; this.cancellation = cancellation; this.onAction = onAction; this.stopRequested = stopRequested; this.elapsedSeconds = elapsedSeconds; }
        private double Elapsed => elapsedSeconds?.Invoke() ?? clock.Elapsed.TotalSeconds;
        internal int Px(int value) => (int)Math.Round(value * Scale);
        internal bool Poll()
        {
            if (Resolution is not null) return true;
            try { if (stopRequested()) { Finish("stopped"); return true; } }
            catch (Exception) { Console.Error.WriteLine("human_handoff_stop_probe_failed"); Finish("cancelled"); return true; }
            if (cancellation.IsCancellationRequested) { Finish("cancelled"); return true; }
            if (Elapsed >= (long)timeoutSeconds + ExtensionSeconds)
            { Finish("expired"); return true; }
            return false;
        }
        internal void Finish(string resolution)
        {
            if (Resolution is not null) return;
            Resolution = resolution;
            if (Window != IntPtr.Zero) KillTimer(Window, new UIntPtr(1));
            if (resolution != "expired") Notify(resolution, 0);
            if (Window != IntPtr.Zero) DestroyWindow(Window);
        }
        internal void Destroyed(IntPtr hwnd)
        {
            KillTimer(hwnd, new UIntPtr(1)); Window = IntPtr.Zero;
            // No thread-wide WM_QUIT remains to cancel the next request when
            // the caller deliberately reuses its dedicated STA thread.
            if (Resolution is null) Finish("cancelled");
        }
        private bool Notify(string action, int seconds)
        {
            // Integration contract: this callback only queues a small local
            // event; pipe writes, storage and target work run on another thread.
            try { onAction(action, seconds); return true; }
            catch (Exception) { Console.Error.WriteLine("human_handoff_notification_failed"); return false; }
        }
        internal void Shown() { if (!Poll() && !Notify("shown", 0)) Finish("cancelled"); }
        internal void Extend()
        {
            if (Poll()) return;
            int effective = Math.Min(300, 3600 - timeoutSeconds - ExtensionSeconds);
            if (effective <= 0) return;
            if (!Notify("extend", 300)) { Finish("cancelled"); return; }
            ExtensionSeconds += effective;
            if (extendButton != IntPtr.Zero) EnableWindow(extendButton, timeoutSeconds + ExtensionSeconds < 3600);
            lastRemaining = -1; UpdateRemaining();
        }
        internal void UpdateRemaining()
        {
            if (remaining == IntPtr.Zero || Resolution is not null) return;
            int seconds = (int)Math.Clamp(Math.Ceiling((long)timeoutSeconds + ExtensionSeconds - Elapsed), 0, int.MaxValue);
            if (seconds == lastRemaining) return;
            lastRemaining = seconds;
            SetWindowTextW(remaining, UiText.Format("剩余 {0}:{1:00} · 到时保持暂停 · 最长 60 分钟", seconds / 60, seconds % 60));
        }
        internal bool Keyboard(ref HostWindow.Message nativeMessage)
        {
            if (nativeMessage.Kind == 0x100 && (nativeMessage.Hwnd == Window || IsChild(Window, nativeMessage.Hwnd)))
            {
                int key = (int)nativeMessage.Wp.ToUInt64();
                if (key == 9 && GetKeyState(17) >= 0 && GetKeyState(18) >= 0)
                {
                    SendMessageW(Window, 0x127, new IntPtr((1 << 16) | 2), IntPtr.Zero);
                    var next = GetNextDlgTabItem(Window, GetFocus(), GetKeyState(16) < 0);
                    if (next != IntPtr.Zero) SetFocus(next);
                    return true;
                }
                if (key == 27) { Finish("cancelled"); return true; }
                if (key == 13 && GetDlgCtrlID(GetFocus()) is >= 30 and <= 33)
                { SendMessageW(Window, 0x111, new IntPtr(GetDlgCtrlID(GetFocus())), IntPtr.Zero); return true; }
            }
            return IsDialogMessageW(Window, ref nativeMessage);
        }
        internal void Create()
        {
            var instance = GetModuleHandleW(null);
            if (!registered)
            {
                var cls = new Class { Size = (uint)Marshal.SizeOf<Class>(), Style = 3,
                    Proc = Marshal.GetFunctionPointerForDelegate(Proc), Instance = instance, Name = ClassName };
                if (RegisterClassExW(ref cls) == 0) throw new Boundary("handoff_window_create_failed");
                registered = true;
            }
            var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
            if (!GetMonitorInfoW(MonitorFromWindow(IntPtr.Zero, 2), ref monitor)) throw new Boundary("handoff_work_area_unavailable");
            Window = CreateWindowExW(0x10000, ClassName, UiText.Get("Flower Control · 请你处理"), 0x00C80000 | 0x02000000,
                monitor.Work.Left + 12, monitor.Work.Top + 12, 640, 460, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
            if (Window == IntPtr.Zero || !SetPropW(Window, "FlowerControlTaskIndicator", new IntPtr(1)))
                throw new Boundary("handoff_window_create_failed");
            Scale = Math.Min(Math.Max(1, GetDpiForWindow(Window) / 96.0), Math.Min((monitor.Work.Right - monitor.Work.Left - 24) / 640.0,
                (monitor.Work.Bottom - monitor.Work.Top - 24) / 460.0));
            if (Scale < .65) throw new Boundary("handoff_screen_too_small");
            int width = Px(640), height = Px(460);
            if (!SetWindowPos(Window, IntPtr.Zero, monitor.Work.Left + (monitor.Work.Right - monitor.Work.Left - width) / 2,
                monitor.Work.Top + (monitor.Work.Bottom - monitor.Work.Top - height) / 2, width, height, 0x14))
                throw new Boundary("handoff_window_layout_failed");
            Visual = new PermissionVisual(); Visual.Reload(Window);
            var normal = Font(15, 400); var title = Font(25, 600); var small = Font(13, 400);
            Add(1000, "STATIC", "Flower Control", 88, 23, 510, 34, title);
            Add(2000, "STATIC", UiText.Get("需要你处理 · AI 已暂停输入"), 89, 63, 510, 25, small);
            Add(1001, "STATIC", message, 24, 116, 584, 108, normal);
            remaining = Add(2001, "STATIC", "", 24, 236, 584, 26, small);
            Add(2002, "STATIC", UiText.Get("点“我已完成”后保持暂停；明确继续才恢复操作。"), 24, 265, 584, 24, small);
            if (!GetClientRect(Window, out var client)) throw new Boundary("handoff_window_layout_failed");
            int bottom = (int)Math.Round(client.Bottom / Scale) - 102;
            Add(30, "BUTTON", UiText.Get("我已完成(&D)"), 24, bottom, 285, 36, normal, 1);
            Add(31, "BUTTON", UiText.Get("取消(&C)"), 321, bottom, 287, 36, normal);
            extendButton = Add(32, "BUTTON", UiText.Get("延长 5 分钟(&E)"), 24, bottom + 48, 285, 36, normal);
            EnableWindow(extendButton, timeoutSeconds < 3600);
            Add(33, "BUTTON", UiText.Get("停止(&S)"), 321, bottom + 48, 287, 36, normal);
            if (SystemParametersInfoW(0x100A, 0, out uint cues, 0) && cues == 0)
                SendMessageW(Window, 0x127, new IntPtr((3 << 16) | 1), IntPtr.Zero);
            UpdateRemaining();
            if (SetTimer(Window, new UIntPtr(1), 50, IntPtr.Zero) == UIntPtr.Zero) throw new Boundary("handoff_timer_failed");
        }
        private IntPtr Font(int size, int weight)
        {
            var result = CreateFontW(-Px(size), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, "Segoe UI");
            if (result == IntPtr.Zero) throw new Boundary("handoff_font_failed"); fonts.Add(result); return result;
        }
        private IntPtr Add(int id, string kind, string text, int x, int y, int width, int height, IntPtr font, uint style = 0)
        {
            uint nativeStyle = 0x50000000 | style | (kind == "BUTTON" ? 0x10000u : 0u);
            var control = CreateWindowExW(0, kind, text, nativeStyle, Px(x), Px(y), Px(width), Px(height), Window,
                new IntPtr(id), GetModuleHandleW(null), IntPtr.Zero);
            if (control == IntPtr.Zero) throw new Boundary("handoff_control_failed");
            Controls.Add((id, control));
            Visual!.Attach(control, kind, nativeStyle, id);
            SendMessageW(control, 0x30, font, new IntPtr(1)); return control;
        }
        public void Dispose()
        {
            if (Native.IsWindow(Window)) DestroyWindow(Window); Window = IntPtr.Zero;
            Visual?.Dispose(); Visual = null;
            foreach (var font in fonts) DeleteObject(font); fonts.Clear();
        }
    }
}
