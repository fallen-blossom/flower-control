using System.Runtime.InteropServices;
using System.Text;

internal static class BackgroundPatterns
{
    [DllImport("user32.dll")] private static extern bool IsChild(nint parent, nint child);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(nint hwnd, StringBuilder value, int length);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint SendMessageTimeoutW(nint hwnd, uint message, nint wp, string lp, uint flags, uint timeout, out nint result);
    [DllImport("user32.dll", EntryPoint = "SendMessageTimeoutW", SetLastError = true)]
    private static extern nint SendMessageNumber(nint hwnd, uint message, nint wp, nint lp, uint flags, uint timeout, out nint result);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
    private static extern int GetWindowLong(nint hwnd, int index);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(nint hwnd, out Rect rect);
    [StructLayout(LayoutKind.Sequential)] private struct Rect { internal int Left, Top, Right, Bottom; }

    internal static bool IsRichEditClass(string name) => name.StartsWith("RichEdit", StringComparison.OrdinalIgnoreCase);
    internal static bool IsNativeRichEdit(nint edit)
    {
        if (edit == nint.Zero) return false;
        if (!Native.IsWindow(edit)) throw new ArgumentException("native_control_changed");
        var name = new StringBuilder(128);
        if (GetClassNameW(edit, name, name.Capacity) == 0)
            throw new ArgumentException("native_control_class_unavailable");
        return IsRichEditClass(name.ToString());
    }
    internal static void RequireRichEdit(nint root, nint edit, int pid, int[]? bounds)
    {
        if (!Native.IsWindow(root) || !Native.IsWindowEnabled(root) || !Native.IsWindow(edit)
            || !Native.IsWindowEnabled(edit) || !IsChild(root, edit)
            || Native.GetWindowThreadProcessId(edit, out var actual) == 0 || actual != pid
            || !IsNativeRichEdit(edit) || (GetWindowLong(edit, -16) & (0x800 | 0x20)) != 0
            || bounds is not { Length: 4 } || !GetWindowRect(edit, out var rect)
            || rect.Right <= rect.Left || rect.Bottom <= rect.Top || bounds[2] <= bounds[0] || bounds[3] <= bounds[1]
            || Math.Max(rect.Left, bounds[0]) >= Math.Min(rect.Right, bounds[2])
            || Math.Max(rect.Top, bounds[1]) >= Math.Min(rect.Bottom, bounds[3]))
            throw new ArgumentException("rich_edit_target_changed");
    }
    internal static void ReplaceRichEdit(nint edit, string value, Action revalidate)
    {
        // Both messages have no meaningful return value. Dispatch each at most
        // once and never fall back to another write after an uncertain timeout.
        if (SendMessageNumber(edit, 0x00B1, nint.Zero, new nint(-1), 0x23, 700, out _) == nint.Zero)
            throw new TimeoutException("rich_edit_selection_unconfirmed");
        revalidate();
        if (SendMessageTimeoutW(edit, 0x00C2, new nint(1), value, 0x23, 700, out _) == nint.Zero)
            throw new TimeoutException("rich_edit_replace_unconfirmed");
    }
    internal static bool Supports(string command, string framework, string className)
    {
        // UIA's standard Value setter activates an Edit on Windows. Admit the
        // independently verified native text primitive only; other providers
        // remain rejected before their UIA setter can acquire foreground.
        return command == "set_value" && framework == "Win32" && className == "Edit";
    }
    internal static void RequireEdit(nint root, nint edit, int pid)
    {
        var className = new StringBuilder(128);
        if (edit == nint.Zero || !Native.IsWindow(edit) || !Native.IsWindowEnabled(edit) || !IsChild(root, edit)
            || Native.GetWindowThreadProcessId(edit, out var actual) == 0 || actual != pid
            || GetClassNameW(edit, className, className.Capacity) == 0 || className.ToString() != "Edit")
            throw new ArgumentException("background_provider_unsupported");
    }
    internal static void SetValue(nint edit, string value)
    {
        // One bounded message to the exact revalidated control. No input,
        // focus, activation, shell command or fallback provider is involved.
        if (SendMessageTimeoutW(edit, 0x000C, nint.Zero, value, 0x23, 700, out var result) == nint.Zero || result == nint.Zero)
            throw new TimeoutException("background_edit_write_unconfirmed");
    }
}
