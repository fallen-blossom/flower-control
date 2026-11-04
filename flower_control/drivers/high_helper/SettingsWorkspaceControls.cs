using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static int workspaceIconState = 1;
    private static IntPtr hotCombo;

    // HostWindow already computes availability, pause and fault for the tray.
    // Reuse that result on the same message-loop thread, never infer authority
    // from a settings draft. Cached icon handles belong to TrayStateIcons.
    internal static void SetVisualState(int state)
    {
        state = Math.Clamp(state, 0, 5);
        if (workspaceIconState == state) return;
        workspaceIconState = state;
        if (window == IntPtr.Zero) return;
        ApplyWindowIcons();
        if (appDialog is { Window: var dialogWindow } dialog && dialogWindow != IntPtr.Zero) ApplyDialogIcons(dialog);
        InvalidateChrome(Layout.BrandIcon);
    }

    private static void PaintBrandIcon(IntPtr dc)
    {
        var rect = Layout.BrandIcon;
        // One cache size per DPI, independent of arbitrary window resizing.
        int size = (int)Math.Round(40 * Math.Max(96, GetDpiForWindow(window)) / 96.0);
        DrawIconEx(dc, rect.Left, rect.Top, TrayStateIcons.Load(workspaceIconState, size, size),
            rect.Right - rect.Left, rect.Bottom - rect.Top, 0, IntPtr.Zero, 3);
    }

    private static void TrackComboHover(IntPtr hwnd)
    {
        hotCombo = hwnd;
        var tracking = new MouseTracking { Size = (uint)Marshal.SizeOf<MouseTracking>(), Flags = 2, Window = hwnd };
        TrackMouseEvent(ref tracking);
    }

    private static void SizeComboItems(IntPtr hwnd)
    {
        int height = Math.Max(FontPixels(20) + Px(12), Px(34));
        SendMessageW(hwnd, 0x153, new IntPtr(-1), new IntPtr(height));
        SendMessageW(hwnd, 0x153, IntPtr.Zero, new IntPtr(height + Px(6)));
    }

    private static void PaintComboField(IntPtr dc, IntPtr hwnd, Rect rect)
    {
        PaintControlBackdrop(new DrawItem { Dc = dc, Window = hwnd, Rect = rect });
        bool focus = GetFocus() == hwnd, enabled = IsWindowEnabled(hwnd);
        bool expanded = SendMessageW(hwnd, 0x157, IntPtr.Zero, IntPtr.Zero) != IntPtr.Zero;
        if (HighContrast())
        {
            Fill(dc, rect, GetSysColor(5)); Frame(dc, rect, GetSysColor(8));
        }
        else
        {
            SoftSurface(dc, rect, focus || expanded ? 0x816751u : 0x635346u,
                (byte)(!enabled ? 30 : focus || expanded ? 180 : hotCombo == hwnd ? 135 : 100), 9);
        }
        uint ink = HighContrast() ? GetSysColor(enabled ? 8 : 17) : enabled ? 0xF5EDF4u : 0xA99DA6u;
        var text = rect; text.Left += Px(14); text.Right -= Math.Max(Px(40), FontPixels(20) * 2);
        Text(dc, Text(hwnd), text, 20, ink, false, nativeColor: HighContrast());
        int x = rect.Right - Math.Max(Px(20), FontPixels(20)), y = (rect.Top + rect.Bottom) / 2;
        int arrow = Math.Max((int)Math.Round(4 * Math.Max(96, GetDpiForWindow(hwnd)) / 96.0), Px(5));
        int stroke = Math.Max(2, (int)Math.Ceiling(2 / scale));
        Line(dc, x - arrow, y - arrow / 2, x, y + arrow / 2, ink, stroke);
        Line(dc, x, y + arrow / 2, x + arrow, y - arrow / 2, ink, stroke);
        if (focus)
        {
            if (HighContrast()) { var ring = rect; ring.Left += 2; ring.Right -= 2; ring.Top += 2; ring.Bottom -= 2; PaintKeyboardFocus(dc, ref ring); }
            else Line(dc, rect.Left + Px(10), rect.Bottom - Px(2), rect.Right - Px(10), rect.Bottom - Px(2), 0xE3BCD8, 2);
        }
    }

    private static void PaintComboItem(DrawItem item)
    {
        // Closed fields are painted by the subclass as one surface, including
        // the arrow. This also handles native focus-only WM_DRAWITEM paths.
        if ((item.State & 0x1000) != 0)
        {
            int savedDc = SaveDC(item.Dc);
            try { GetClientRect(item.Window, out var rect); PaintComboField(item.Dc, item.Window, rect); }
            finally { RestoreDC(item.Dc, savedDc); }
            return;
        }
        bool selected = (item.State & 1) != 0;
        FillExact(item.Dc, item.Rect, HighContrast() ? GetSysColor(selected ? 13 : 5) : selected ? 0x5D443Fu : 0x2B2320u);
        if (item.Item == uint.MaxValue) return;
        int length = SendMessageW(item.Window, 0x149, new IntPtr(item.Item), IntPtr.Zero).ToInt32();
        if (length is < 0 or > 32768) return;
        var label = new StringBuilder(length + 1);
        SendComboText(item.Window, 0x148, new IntPtr(item.Item), label);
        var text = item.Rect; text.Left += Px(14); text.Right -= Px(32);
        Text(item.Dc, label.ToString(), text, 20, HighContrast() ? GetSysColor(selected ? 14 : 8) : 0xF7EFF6u, selected, nativeColor: HighContrast());
        int current = SendMessageW(item.Window, 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32();
        if (current == item.Item)
        {
            int size = Math.Max(8, FontPixels(20) / 2), x = item.Rect.Right - Math.Max(Px(18), FontPixels(20));
            int y = (item.Rect.Top + item.Rect.Bottom) / 2;
            uint ink = HighContrast() ? GetSysColor(selected ? 14 : 8) : 0xD9EACCu;
            int stroke = Math.Max(2, (int)Math.Ceiling(2 / scale));
            Line(item.Dc, x - size / 2, y, x - size / 6, y + size / 3, ink, stroke);
            Line(item.Dc, x - size / 6, y + size / 3, x + size / 2, y - size / 3, ink, stroke);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MeasureItem { public uint Type, Id, Item, Width, Height; public UIntPtr Data; }
    [StructLayout(LayoutKind.Sequential)]
    private struct MouseTracking { public uint Size, Flags; public IntPtr Window; public uint Hover; }
    private static bool MeasureThemedItem(IntPtr pointer)
    {
        var item = Marshal.PtrToStructure<MeasureItem>(pointer);
        if (item.Type == 3) item.Height = (uint)(FontPixels(20) + Px(18));
        else if (item.Type == 2 && item.Id == DecisionListId) item.Height = (uint)Math.Max(1, Px(46));
        else if (item.Type == 1 && menuLabels.TryGetValue(item.Data, out var entry))
        {
            var dc = GetDC(window);
            try { item.Width = (uint)(Math.Min(MeasureMenuText(dc, entry.Label), FontPixels(20) * 32) + Px(entry.Icon == IntPtr.Zero ? 58 : 92)); }
            finally { ReleaseDC(window, dc); }
            item.Height = (uint)Math.Max(FontPixels(20) + Px(24), Px(48));
        }
        else return false;
        Marshal.StructureToPtr(item, pointer, false); return true;
    }

    private sealed record MenuLabel(IntPtr Menu, string Label, IntPtr Text, IntPtr Icon = default);
    private static readonly Dictionary<UIntPtr, MenuLabel> menuLabels = [];
    [StructLayout(LayoutKind.Sequential)]
    private struct MenuInfo { public uint Size, Mask, Style, MaxHeight; public IntPtr Brush; public uint Help; public UIntPtr Data; }
    private static IntPtr CreatePopupMenu()
    {
        var menu = CreateNativePopupMenu();
        if (menu != IntPtr.Zero && !HighContrast())
        {
            var info = new MenuInfo { Size = (uint)Marshal.SizeOf<MenuInfo>(), Mask = 2, Brush = pageBrush };
            SetMenuInfo(menu, ref info);
        }
        return menu;
    }
    // MSAAMENUINFO gives owner-drawn native menus their real accessible names.
    [StructLayout(LayoutKind.Sequential)]
    private struct AccessibleMenuText { public uint Signature, Length; public IntPtr Text; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MenuItemInfo
    {
        public uint Size, Mask, Type, State, Id; public IntPtr Submenu, Checked, Unchecked;
        public UIntPtr Data; public IntPtr Text; public uint Length; public IntPtr Bitmap;
    }
    private static bool AppendMenuW(IntPtr menu, uint flags, uint id, string text, IntPtr icon = default)
    {
        if (!AppendNativeMenu(menu, flags, id, text)) return false;
        string label = text.Replace("&&", "&");
        var title = Marshal.StringToHGlobalUni(label);
        var accessible = Marshal.AllocHGlobal(Marshal.SizeOf<AccessibleMenuText>());
        Marshal.StructureToPtr(new AccessibleMenuText { Signature = 0xAA0DF00D, Length = (uint)label.Length, Text = title }, accessible, false);
        var data = (UIntPtr)accessible;
        var info = new MenuItemInfo { Size = (uint)Marshal.SizeOf<MenuItemInfo>(), Mask = 0x100 | 0x20, Type = 0x100, Data = data };
        if (!SetMenuItemInfoW(menu, id, false, ref info))
        { Marshal.FreeHGlobal(title); Marshal.FreeHGlobal(accessible); return false; }
        menuLabels.Add(data, new(menu, label, title, icon)); return true;
    }

    private static bool DestroyMenu(IntPtr menu)
    {
        bool destroyed = DestroyNativeMenu(menu);
        if (destroyed)
            foreach (var pair in menuLabels.Where(x => x.Value.Menu == menu).ToArray())
            { Marshal.FreeHGlobal(pair.Value.Text); Marshal.FreeHGlobal((IntPtr)pair.Key); menuLabels.Remove(pair.Key); }
        return destroyed;
    }

    private static int MeasureMenuText(IntPtr dc, string text)
    {
        var font = UiFont(-FontPixels(20), 400, BodyFace);
        var previous = SelectObject(dc, font); var bounds = new Rect();
        try { DrawTextW(dc, text, -1, ref bounds, 0x400 | 0x20 | 0x800); return bounds.Right; }
        finally { SelectObject(dc, previous); }
    }
    private static void PaintMenuItem(DrawItem item)
    {
        bool selected = (item.State & 1) != 0, disabled = (item.State & 6) != 0;
        FillExact(item.Dc, item.Rect, HighContrast() ? GetSysColor(selected ? 13 : 4) : selected ? 0x5D443Fu : 0x2B2320u);
        if (!menuLabels.TryGetValue(item.Data, out var entry)) return;
        var text = item.Rect; text.Left += Px(22); text.Right -= Px(22);
        if (entry.Icon != IntPtr.Zero)
        {
            int size = Math.Max(Px(24), FontPixels(20));
            DrawIconEx(item.Dc, text.Left, (item.Rect.Top + item.Rect.Bottom - size) / 2, entry.Icon, size, size, 0, IntPtr.Zero, 3);
            text.Left += size + Px(12);
        }
        Text(item.Dc, entry.Label, text, 20, HighContrast() ? GetSysColor(disabled ? 17 : selected ? 14 : 7) : disabled ? 0xA2949Fu : 0xF5ECF3u,
            false, nativeColor: HighContrast());
    }
    private static void FillExact(IntPtr dc, Rect rect, uint color)
    { var brush = CreateSolidBrush(color); try { FillRect(dc, ref rect, brush); } finally { DeleteObject(brush); } }

    private static void ShowEditContextMenu(IntPtr edit, IntPtr position)
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) return;
        try
        {
            bool readOnly = (GetWindowLongW(edit, -16) & 0x800) != 0;
            uint selection = unchecked((uint)SendMessageW(edit, 0xB0, IntPtr.Zero, IntPtr.Zero).ToInt64());
            bool selected = (selection & 0xffff) != ((selection >> 16) & 0xffff);
            if (!readOnly) { AppendMenuW(menu, 0, 1, UiText.Get("撤销     Ctrl+Z")); AppendMenuW(menu, 0, 2, UiText.Get("剪切     Ctrl+X")); }
            AppendMenuW(menu, 0, 3, UiText.Get("复制     Ctrl+C"));
            if (!readOnly) { AppendMenuW(menu, 0, 4, UiText.Get("粘贴     Ctrl+V")); AppendMenuW(menu, 0, 5, UiText.Get("删除")); }
            AppendMenuW(menu, 0, 6, UiText.Get("全选     Ctrl+A"));
            if (!selected) { EnableMenuItem(menu, 2, 1); EnableMenuItem(menu, 3, 1); EnableMenuItem(menu, 5, 1); }
            if (SendMessageW(edit, 0xC6, IntPtr.Zero, IntPtr.Zero) == IntPtr.Zero) EnableMenuItem(menu, 1, 1);
            if (!IsClipboardFormatAvailable(13)) EnableMenuItem(menu, 4, 1);
            GetWindowRect(edit, out var bounds);
            int x = position == new IntPtr(-1) ? bounds.Left + Px(20) : (short)((long)position & 0xffff);
            int y = position == new IntPtr(-1) ? bounds.Top + Px(30) : (short)(((long)position >> 16) & 0xffff);
            int command = TrackPopupMenu(menu, 0x102, x, y, 0, GetAncestor(edit, 2), IntPtr.Zero);
            if (!IsWindow(edit)) return;
            if (command == 6) SendMessageW(edit, 0xB1, IntPtr.Zero, new IntPtr(-1));
            else if (command is >= 1 and <= 5)
            {
                uint message = command switch { 1 => 0x304, 2 => 0x300, 3 => 0x301, 4 => 0x302, _ => 0x303 };
                SendMessageW(edit, message, IntPtr.Zero, IntPtr.Zero);
            }
        }
        finally { DestroyMenu(menu); }
    }

    [DllImport("user32.dll")] private static extern bool TrackMouseEvent(ref MouseTracking tracking);
    [DllImport("user32.dll", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode)] private static extern IntPtr SendComboText(IntPtr hwnd, uint message, IntPtr index, StringBuilder text);
    [DllImport("user32.dll", EntryPoint = "AppendMenuW", CharSet = CharSet.Unicode)] private static extern bool AppendNativeMenu(IntPtr menu, uint flags, uint id, string text);
    [DllImport("user32.dll", EntryPoint = "DestroyMenu")] private static extern bool DestroyNativeMenu(IntPtr menu);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetMenuItemInfoW(IntPtr menu, uint id, bool byPosition, ref MenuItemInfo info);
    [DllImport("user32.dll", EntryPoint = "CreatePopupMenu")] private static extern IntPtr CreateNativePopupMenu();
    [DllImport("user32.dll")] private static extern bool SetMenuInfo(IntPtr menu, ref MenuInfo info);
    [DllImport("user32.dll")] private static extern bool IsClipboardFormatAvailable(uint format);
    [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
}
