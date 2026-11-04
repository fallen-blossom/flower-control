using System.Runtime.InteropServices;

namespace Flower.HighHelper;

// Native supplemental help only. It neither invokes commands nor changes focus.
// Root-relative tools plus relayed child messages also cover disabled controls.
internal sealed class SettingsTooltips : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct Common { public uint Size, Classes; }
    [StructLayout(LayoutKind.Sequential)] private struct Contrast { public uint Size, Flags; public IntPtr Scheme; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Tool
    {
        public uint Size, Flags;
        public IntPtr Window;
        public UIntPtr Id;
        public Native.Rect Bounds;
        public IntPtr Instance, Text, Data, Reserved;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Message
    {
        public IntPtr Window;
        public uint Kind;
        public UIntPtr Wp;
        public IntPtr Lp;
        public uint Time;
        public Native.Point Point;
        public uint Private;
    }
    [DllImport("comctl32.dll")] private static extern bool InitCommonControlsEx(ref Common value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateWindowExW(uint ex, string kind, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr id, IntPtr instance, IntPtr data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetPropW(IntPtr hwnd, string name, IntPtr value);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsChild(IntPtr parent, IntPtr hwnd);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern int MapWindowPoints(IntPtr from, IntPtr to, ref Native.Point point, uint count);
    [DllImport("user32.dll")] private static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", EntryPoint = "SendMessageW")] private static extern IntPtr SendTool(IntPtr hwnd, uint message, IntPtr wp, ref Tool value);
    [DllImport("user32.dll", EntryPoint = "SendMessageW")] private static extern IntPtr SendMouse(IntPtr hwnd, uint message, IntPtr wp, ref Message value);
    [DllImport("user32.dll")] private static extern int GetMessageTime();
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern uint GetSysColor(int index);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SystemParametersInfoW(uint action, uint size, ref Contrast value, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(Native.Point point);
    private delegate IntPtr TooltipProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data);
    [DllImport("comctl32.dll")] private static extern bool SetWindowSubclass(IntPtr hwnd, TooltipProc proc, UIntPtr id, UIntPtr data);
    [DllImport("comctl32.dll")] private static extern bool RemoveWindowSubclass(IntPtr hwnd, TooltipProc proc, UIntPtr id);
    [DllImport("comctl32.dll")] private static extern IntPtr DefSubclassProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    private sealed record Entry(string Text, IntPtr Buffer);
    private readonly IntPtr owner;
    private readonly Dictionary<IntPtr, Entry> entries = [];
    private IntPtr tooltip;
    private uint toolSize = (uint)Marshal.SizeOf<Tool>();
    private readonly TooltipProc tooltipProc;
    private bool ownerWasVisible;
    internal IntPtr WindowHandle => tooltip;
    internal int Count => entries.Count;

    internal SettingsTooltips(IntPtr owner)
    {
        GetWindowThreadProcessId(owner, out var pid);
        if (!IsWindow(owner) || pid != Environment.ProcessId) throw new Boundary("permission_help_owner_changed");
        this.owner = owner;
        tooltipProc = TooltipWindowProc;
        var common = new Common { Size = (uint)Marshal.SizeOf<Common>(), Classes = 0xff };
        if (!InitCommonControlsEx(ref common)) throw new Boundary("permission_help_initialization_failed");
        tooltip = CreateWindowExW(0x08000088, "tooltips_class32", "", 0x80000002,
            0, 0, 0, 0, owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (tooltip == IntPtr.Zero) throw new Boundary("permission_help_window_failed");
        if (!SetPropW(tooltip, "FlowerControlTaskIndicator", new IntPtr(1)))
        { DestroyWindow(tooltip); tooltip = IntPtr.Zero; throw new Boundary("permission_help_window_failed"); }
        if (!SetWindowSubclass(tooltip, tooltipProc, new UIntPtr(1), UIntPtr.Zero))
        { DestroyWindow(tooltip); tooltip = IntPtr.Zero; throw new Boundary("permission_help_window_failed"); }
        // Native hover delay; long explanations remain available in the F1 pane.
        SendMessageW(tooltip, 0x403, new IntPtr(3), new IntPtr(650)); // TTDT_INITIAL
        SendMessageW(tooltip, 0x403, new IntPtr(1), new IntPtr(150)); // TTDT_RESHOW
        SendMessageW(tooltip, 0x403, new IntPtr(2), new IntPtr(16000)); // TTDT_AUTOPOP
        SendMessageW(tooltip, 0x418, IntPtr.Zero, new IntPtr(360));
    }
    private IntPtr TooltipWindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        // Tools are clipped rectangles in the settings root, including those
        // over disabled children. Tell common controls which registered window
        // contains that rectangle; its default WindowFromPoint returns the child.
        if (message == 0x410 && lp != IntPtr.Zero && GetForegroundWindow() == owner)
        {
            var point = Marshal.PtrToStructure<Native.Point>(lp);
            var hit = WindowFromPoint(point);
            if (hit == owner || IsChild(owner, hit)) return owner;
        }
        return DefSubclassProc(hwnd, message, wp, lp);
    }
    private Tool Describe(IntPtr control, Entry entry)
    {
        var tool = new Tool { Size = toolSize, Window = owner,
            Id = new UIntPtr(unchecked((ulong)control.ToInt64())), Text = entry.Buffer };
        if (!IsWindowVisible(control) || !IsChild(owner, control) || !GetWindowRect(control, out var bounds)) return tool;
        // Intersect every ancestor client rectangle, including the scrolling
        // viewport: offscreen child portions must not cover the fixed footer.
        for (var parent = GetParent(control); parent != IntPtr.Zero; parent = GetParent(parent))
        {
            if (!GetClientRect(parent, out var clip)) return tool;
            var origin = new Native.Point(); MapWindowPoints(parent, IntPtr.Zero, ref origin, 1);
            bounds.Left = Math.Max(bounds.Left, origin.X + clip.Left);
            bounds.Top = Math.Max(bounds.Top, origin.Y + clip.Top);
            bounds.Right = Math.Min(bounds.Right, origin.X + clip.Right);
            bounds.Bottom = Math.Min(bounds.Bottom, origin.Y + clip.Bottom);
            if (parent == owner) break;
        }
        if (bounds.Right <= bounds.Left || bounds.Bottom <= bounds.Top) return tool;
        var first = new Native.Point { X = bounds.Left, Y = bounds.Top };
        var last = new Native.Point { X = bounds.Right, Y = bounds.Bottom };
        MapWindowPoints(IntPtr.Zero, owner, ref first, 1); MapWindowPoints(IntPtr.Zero, owner, ref last, 1);
        tool.Bounds = new Native.Rect { Left = first.X, Top = first.Y, Right = last.X, Bottom = last.Y };
        return tool;
    }
    internal void Register(IntPtr control, string text)
    {
        if (tooltip == IntPtr.Zero || !IsChild(owner, control) || string.IsNullOrWhiteSpace(text)) return;
        if (entries.TryGetValue(control, out var prior) && prior.Text == text) return;
        var entry = new Entry(text, Marshal.StringToHGlobalUni(text));
        var tool = Describe(control, entry);
        try
        {
            if (prior is null)
            {
                if (SendTool(tooltip, 0x432, IntPtr.Zero, ref tool) == IntPtr.Zero)
                {
                    // comctl32 v5 rejects the newer lpReserved member. Keep the
                    // same native control and use its documented V2 structure.
                    tool.Size = (uint)Marshal.OffsetOf<Tool>(nameof(Tool.Reserved)).ToInt32();
                    if (tool.Size == toolSize || SendTool(tooltip, 0x432, IntPtr.Zero, ref tool) == IntPtr.Zero)
                        throw new Boundary("permission_help_registration_failed");
                    toolSize = tool.Size;
                }
            }
            else { Pop(); SendTool(tooltip, 0x439, IntPtr.Zero, ref tool); }
            entries[control] = entry;
        }
        catch { Marshal.FreeHGlobal(entry.Buffer); throw; }
        if (prior is not null) Marshal.FreeHGlobal(prior.Buffer);
    }
    internal void Refresh()
    {
        if (tooltip == IntPtr.Zero) return;
        Pop();
        var font = SendMessageW(owner, 0x31, IntPtr.Zero, IntPtr.Zero);
        if (font == IntPtr.Zero)
            font = entries.Keys.Select(control => SendMessageW(control, 0x31, IntPtr.Zero, IntPtr.Zero)).FirstOrDefault(value => value != IntPtr.Zero);
        if (font != IntPtr.Zero) SendMessageW(tooltip, 0x30, font, IntPtr.Zero);
        var contrast = new Contrast { Size = (uint)Marshal.SizeOf<Contrast>() };
        bool highContrast = SystemParametersInfoW(0x42, contrast.Size, ref contrast, 0) && (contrast.Flags & 1) != 0;
        SendMessageW(tooltip, 0x413, new IntPtr(highContrast ? GetSysColor(24) : 0x332a2a), IntPtr.Zero);
        SendMessageW(tooltip, 0x414, new IntPtr(highContrast ? GetSysColor(23) : 0xf8f2f2), IntPtr.Zero);
        SendMessageW(tooltip, 0x418, IntPtr.Zero, new IntPtr((int)(360 * Math.Max(1, GetDpiForWindow(owner) / 96.0))));
        foreach (var pair in entries)
        { var tool = Describe(pair.Key, pair.Value); SendTool(tooltip, 0x434, IntPtr.Zero, ref tool); }
        ownerWasVisible = IsWindowVisible(owner);
    }
    internal void Relay(IntPtr messageWindow, uint message, UIntPtr wp, IntPtr lp)
    {
        if (tooltip == IntPtr.Zero || (messageWindow != owner && !IsChild(owner, messageWindow))) return;
        if (message is 0x100 or 0x104 or 0x10 || GetForegroundWindow() != owner) { Pop(); return; }
        if (message is not (0x200 or 0x201 or 0x202 or 0x204 or 0x205)) return;
        if (!ownerWasVisible && IsWindowVisible(owner)) Refresh();
        var local = new Native.Point { X = unchecked((short)lp.ToInt64()), Y = unchecked((short)(lp.ToInt64() >> 16)) };
        var point = local;
        MapWindowPoints(messageWindow, IntPtr.Zero, ref point, 1);
        MapWindowPoints(messageWindow, owner, ref local, 1);
        var packet = new Message { Window = owner, Kind = message, Wp = wp,
            Lp = new IntPtr((long)(ushort)local.X | ((long)(ushort)local.Y << 16)), Time = unchecked((uint)GetMessageTime()), Point = point };
        SendMouse(tooltip, 0x407, IntPtr.Zero, ref packet);
    }
    internal void Pop() { if (tooltip != IntPtr.Zero) SendMessageW(tooltip, 0x41c, IntPtr.Zero, IntPtr.Zero); }
    public void Dispose()
    {
        if (tooltip != IntPtr.Zero && IsWindow(tooltip))
        { RemoveWindowSubclass(tooltip, tooltipProc, new UIntPtr(1)); DestroyWindow(tooltip); }
        tooltip = IntPtr.Zero;
        foreach (var entry in entries.Values) Marshal.FreeHGlobal(entry.Buffer);
        entries.Clear();
    }
}
