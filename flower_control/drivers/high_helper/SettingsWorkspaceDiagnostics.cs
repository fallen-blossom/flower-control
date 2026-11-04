namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
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
