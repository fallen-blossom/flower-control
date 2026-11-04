using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static readonly SubclassProc ScrollThemeProcedure = ThemeScrollbar;

    // Native EDIT/LISTBOX still own hit testing, range, dragging, keyboard,
    // accessibility and scrolling. Only their existing non-client pixels change.
    private static IntPtr ThemeScrollbar(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        ++nativeCallbackDepth;
        try { return ThemeScrollbarCore(hwnd, message, wp, lp, id, data); }
        catch (Exception error) { NativeCallbackFailed(error); return IntPtr.Zero; }
        finally { try { FinishNativeCallback(); } catch (Exception error) { NativeCallbackFailed(error); } }
    }

    private static IntPtr ThemeScrollbarCore(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        if (message == 0x100 && (int)wp == 65 && GetKeyState(17) < 0)
        {
            var name = new System.Text.StringBuilder(32); GetClassNameW(hwnd, name, 32);
            if (name.ToString().Equals("Edit", StringComparison.OrdinalIgnoreCase))
            { SendMessageW(hwnd, 0xB1, IntPtr.Zero, new IntPtr(-1)); return IntPtr.Zero; }
        }
        if (message == 0x7B && !HighContrast())
        {
            var name = new System.Text.StringBuilder(32); GetClassNameW(hwnd, name, 32);
            if (name.ToString().Equals("Edit", StringComparison.OrdinalIgnoreCase)) { ShowEditContextMenu(hwnd, lp); return IntPtr.Zero; }
        }
        if (GetDlgCtrlID(hwnd) == ProgramListId && message == 0x7B)
        {
            if (lp != new IntPtr(-1))
            {
                var hit = new Rect { Left = (short)((long)lp & 0xffff), Top = (short)(((long)lp >> 16) & 0xffff) };
                hit.Right = hit.Left; hit.Bottom = hit.Top; MapWindowPoints(IntPtr.Zero, hwnd, ref hit, 2);
                if (!SelectProgramMenuRow(hwnd, hit.Left, hit.Top)) return IntPtr.Zero;
            }
            ShowProgramActionMenu(); return IntPtr.Zero;
        }
        if (message == 0x82) RemoveWindowSubclass(hwnd, ScrollThemeProcedure, id);
        var result = DefSubclassProc(hwnd, message, wp, lp);
        if (GetDlgCtrlID(hwnd) is ProgramListId or MaskListId && !HighContrast() &&
            (message == 0xF || message == 0x318 || message == 0x317 && ((long)lp & 4) != 0 && (((long)lp & 1) == 0 || IsWindowVisible(hwnd))))
        {
            try { PaintListRemainder(hwnd, message is 0x317 or 0x318 ? (IntPtr)wp : IntPtr.Zero); }
            catch (Exception error) { Console.Error.WriteLine("settings_list_paint: " + Program.Code(error)); }
        }
        if (GetDlgCtrlID(hwnd) == ProgramListId && message == 0x202)
        {
            GetClientRect(hwnd, out var client);
            int x = (short)((long)lp & 0xffff), y = (short)(((long)lp >> 16) & 0xffff);
            if (x >= client.Right - Px(60) && SelectProgramMenuRow(hwnd, x, y)) { ShowProgramActionMenu(); return result; }
        }
        if (GetDlgCtrlID(hwnd) == ProgramListId && message is 0x115 or 0x20A or 0x101) PositionProgramMenu();
        if (!HighContrast() && message is 0x85 or 0xF or 5 or 7 or 8 or 0x115 or 0x20A or 0xA0 or 0x2A2 or 0x317)
        {
            try
            {
                bool print = message == 0x317;
                if (!print || ((long)lp & 2) != 0 && (((long)lp & 1) == 0 || IsWindowVisible(hwnd)))
                    PaintNativeScrollbar(hwnd, print ? (IntPtr)wp : IntPtr.Zero);
            }
            catch (Exception error) { Console.Error.WriteLine("settings_scroll_paint: " + Program.Code(error)); }
        }
        return result;
    }

    private static void PaintNativeScrollbar(IntPtr hwnd, IntPtr printDc)
    {
        var info = new ScrollbarInfo { Size = (uint)Marshal.SizeOf<ScrollbarInfo>(), States = new uint[6] };
        if (!GetScrollBarInfo(hwnd, -5, ref info) || (info.States[0] & 0x18000) != 0) return;
        GetWindowRect(hwnd, out var outer);
        var bar = info.Bounds;
        bar.Left -= outer.Left; bar.Right -= outer.Left; bar.Top -= outer.Top; bar.Bottom -= outer.Top;
        if (bar.Right <= bar.Left || bar.Bottom <= bar.Top) return;
        var dc = printDc != IntPtr.Zero ? printDc : GetWindowDC(hwnd);
        if (dc == IntPtr.Zero) return;
        int savedDc = SaveDC(dc);
        try
        {
            IntersectClipRect(dc, bar.Left, bar.Top, bar.Right, bar.Bottom);
            Fill(dc, bar, 0x2B2320);
            int center = (bar.Left + bar.Right) / 2, radius = Math.Max(3, (bar.Right - bar.Left) / 6);
            int upper = bar.Top + info.ButtonSize / 2, lower = bar.Bottom - info.ButtonSize / 2;
            DrawArrow(upper, -1, info.States[1]); DrawArrow(lower, 1, info.States[5]);
            if (info.ThumbBottom > info.ThumbTop && (info.States[3] & 1) == 0)
            {
                var thumb = new Rect { Left = bar.Left + Math.Max(3, Px(5)), Right = bar.Right - Math.Max(3, Px(5)),
                    Top = bar.Top + info.ThumbTop + 2, Bottom = bar.Top + info.ThumbBottom - 2 };
                if (thumb.Right > thumb.Left && thumb.Bottom > thumb.Top) Fill(dc, thumb, (info.States[3] & 8) != 0 ? 0xD8B4E9u : 0x967CA8u);
            }
            void DrawArrow(int y, int direction, uint state)
            {
                uint ink = (state & 1) != 0 ? 0x63516Fu : (state & 8) != 0 ? 0xFFE8FFu : 0xC1A8D0u;
                Line(dc, center - radius, y - direction * radius / 2, center, y + direction * radius / 2, ink);
                Line(dc, center, y + direction * radius / 2, center + radius, y - direction * radius / 2, ink);
            }
        }
        finally { RestoreDC(dc, savedDc); if (printDc == IntPtr.Zero) ReleaseDC(hwnd, dc); }
    }

    private static void PaintFlowerAnnotations(IntPtr dc) => PaintPermissionAnnotations(dc);

    [StructLayout(LayoutKind.Sequential)]
    private struct ScrollbarInfo
    {
        public uint Size; public Rect Bounds; public int ButtonSize, ThumbTop, ThumbBottom, Reserved;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public uint[] States;
    }
    [DllImport("user32.dll")] private static extern bool GetScrollBarInfo(IntPtr hwnd, int id, ref ScrollbarInfo info);
    [DllImport("user32.dll")] private static extern IntPtr GetWindowDC(IntPtr hwnd);
    [DllImport("gdiplus.dll")] private static extern int GdipSetSmoothingMode(IntPtr graphics, int mode);
}
