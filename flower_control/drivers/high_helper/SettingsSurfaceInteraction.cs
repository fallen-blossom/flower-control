using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class PermissionSettingsWindow
{
    // Public UI mechanics only. No field text, rule paths, typed keys, grants
    // or screenshots cross into status. The UI thread publishes immutable data;
    // a broker RPC never sends messages to the protected settings surface.
    internal sealed record SurfaceStatus(long Window, string Page, bool Visible, bool Minimized,
        bool Enabled, bool Foreground, int FocusControl, int LastInputControl, uint LastInputMessage,
        int LastCommandControl, int LastCommandNotification, string Stage, string? Error, long Sequence);
    private static SurfaceStatus surfaceStatus = new(0, "closed", false, false, false, false, 0, 0, 0, 0, 0, "closed", null, 0);
    private static IntPtr restoreFocus;
    private static int windowStateChange;
    private static bool surfaceFault;
    [DllImport("user32.dll")] private static extern bool ValidateRect(IntPtr hwnd, IntPtr rect);
    internal static SurfaceStatus SurfaceDiagnostics => Volatile.Read(ref surfaceStatus);

    private static IntPtr WindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        try { return WindowMessageCore(hwnd, message, wp, lp); }
        catch (Exception error)
        {
            // This barrier includes async completion messages as well as
            // native controls. No exception may unwind through USER32 into
            // the High process. Do not destroy a page containing user drafts.
            surfaceFault = true;
            PublishSurface("window_handler_failed", error: Program.Code(error));
            try
            {
                if (message == 0xF) ValidateRect(hwnd, IntPtr.Zero);
                if (window != IntPtr.Zero && Native.IsWindow(window))
                {
                    if (controls.TryGetValue(30, out var save)) EnableWindow(save, false);
                    if (controls.TryGetValue(95, out var saveClose)) EnableWindow(saveClose, false);
                    SetNotice("界面操作未完成，原有草稿保留；保存已暂停，请重新载入核对。");
                }
                Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { settingsUiError = Program.Code(error), message }));
            }
            catch { /* The callback boundary must remain non-throwing. */ }
            return IntPtr.Zero;
        }
    }

    private static void PublishSurface(string stage, int? command = null, int notification = 0, string? error = null)
    {
        try
        {
            var old = SurfaceDiagnostics;
            bool live = window != IntPtr.Zero && Native.IsWindow(window);
            var focused = live ? GetFocus() : IntPtr.Zero;
            bool ownFocus = live && IsChild(window, focused);
            if (ownFocus && IsWindowVisible(focused) && IsWindowEnabled(focused)) restoreFocus = focused;
            Volatile.Write(ref surfaceStatus, old with {
                Window = live ? window.ToInt64() : 0, Page = live ? page.ToString() : "closed",
                Visible = live && IsWindowVisible(window), Minimized = live && IsIconic(window),
                Enabled = live && IsWindowEnabled(window), Foreground = live && Native.GetForegroundWindow() == window,
                FocusControl = ownFocus ? GetDlgCtrlID(focused) : 0,
                LastCommandControl = command ?? old.LastCommandControl,
                LastCommandNotification = command.HasValue ? notification : old.LastCommandNotification,
                Stage = stage, Error = error ?? (surfaceFault ? old.Error : null), Sequence = old.Sequence + 1 });
        }
        catch { /* Diagnostics cannot take down or change the permission page. */ }
    }
    private static void ObserveButtonInput(int id, uint message)
    {
        var old = SurfaceDiagnostics;
        Volatile.Write(ref surfaceStatus, old with { LastInputControl = id, LastInputMessage = message });
        PublishSurface("button_input");
    }
    private static void RestoreSettingsFocus()
    {
        if (window == IntPtr.Zero || !IsWindowVisible(window) || !IsWindowEnabled(window) || IsIconic(window)) return;
        var next = restoreFocus;
        if (next == IntPtr.Zero || !IsChild(window, next) || !IsWindowVisible(next) || !IsWindowEnabled(next))
            next = controls.GetValueOrDefault(compactNavigation ? 306 : 300 + Math.Max(0, NavIndex(page)));
        if (next != IntPtr.Zero && IsWindowVisible(next) && IsWindowEnabled(next)) SetFocus(next);
        PublishSurface("focus_restored");
    }
    private static void PresentSettings()
    {
        if (window == IntPtr.Zero) return;
        ++windowStateChange;
        try { ShowWindow(window, IsIconic(window) ? 9 : 5); }
        finally { --windowStateChange; }
        // Preserve a maximized window, and do not put keyboard focus into a
        // hidden tray popup when the foreground request was refused.
        Native.SetForegroundWindow(window);
        if (Native.GetForegroundWindow() == window) RestoreSettingsFocus();
        PublishSurface(Native.GetForegroundWindow() == window ? "presented" : "foreground_not_granted");
    }
}
