using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    // Permission-specific content uses the same material system as every page.
    private static bool PermissionPage => page == 1;
    private const int ProgramMenuId = 424;
    private static readonly string[] PetalAnnotations =
        [UiText.Get("03  管理员窗口"), UiText.Get("02  普通控制"), UiText.Get("02  普通控制"), UiText.Get("04  管理员执行"), UiText.Get("04  管理员执行")];
    private static bool placingProgramMenu;
    private static uint Argb(uint color, byte alpha = 255)
        => (uint)alpha << 24 | (color & 255) << 16 | (color & 0xff00) | color >> 16 & 255;

    private static void PaintQuietAtmosphere(IntPtr dc, Rect canvas)
    {
        if (HighContrast()) return;
        int state = SaveDC(dc);
        if (SettingsArtwork.GdipCreateFromHDC(dc, out var graphics) != 0) { RestoreDC(dc, state); return; }
        try
        {
            int width = canvas.Right - canvas.Left, height = canvas.Bottom - canvas.Top;
            // Continuous scene shading, never a rectangular content card.
            Shade(new FloatRect(canvas.Left + width * .44f, canvas.Top, width * .56f, height), 0, 215, 0);
            Shade(new FloatRect(canvas.Left, canvas.Top + height * .53f, width, height * .47f), 0, 210, 1);
            void Shade(FloatRect bounds, byte start, byte end, int direction)
            {
                if (GdipCreateLineBrushFromRect(ref bounds, Argb(0x201510, start), Argb(0x201510, end), direction, 0, out var brush) != 0) return;
                try { GdipFillRectangle(graphics, brush, bounds.X, bounds.Y, bounds.Width, bounds.Height); }
                finally { GdipDeleteBrush(brush); }
            }
        }
        finally { SettingsArtwork.GdipDeleteGraphics(graphics); RestoreDC(dc, state); }
    }

    private static void SoftSurface(IntPtr dc, Rect rect, uint color, byte opacity, int radius = 12)
    {
        int state = SaveDC(dc);
        if (SettingsArtwork.GdipCreateFromHDC(dc, out var graphics) != 0) { RestoreDC(dc, state); return; }
        IntPtr brush = IntPtr.Zero, path = IntPtr.Zero;
        try
        {
            if (GdipCreateSolidFill(Argb(color, opacity), out brush) != 0 || GdipCreatePath(0, out path) != 0) return;
            GdipSetSmoothingMode(graphics, 4);
            float diameter = Math.Min(Px(radius) * 2, Math.Min(rect.Right - rect.Left, rect.Bottom - rect.Top));
            GdipAddPathArc(path, rect.Left, rect.Top, diameter, diameter, 180, 90);
            GdipAddPathArc(path, rect.Right - diameter, rect.Top, diameter, diameter, 270, 90);
            GdipAddPathArc(path, rect.Right - diameter, rect.Bottom - diameter, diameter, diameter, 0, 90);
            GdipAddPathArc(path, rect.Left, rect.Bottom - diameter, diameter, diameter, 90, 90);
            GdipClosePathFigure(path); GdipFillPath(graphics, brush, path);
        }
        finally
        {
            if (path != IntPtr.Zero) GdipDeletePath(path);
            if (brush != IntPtr.Zero) GdipDeleteBrush(brush);
            SettingsArtwork.GdipDeleteGraphics(graphics); RestoreDC(dc, state);
        }
    }

    private static Native.Point PetalPoint(float x, float y)
    {
        var flower = Layout.Flower;
        return new() { X = flower.Left + (int)Math.Round((flower.Right - flower.Left) * x), Y = flower.Top + (int)Math.Round((flower.Bottom - flower.Top) * y) };
    }

    private static void PaintRoseControl(IntPtr dc, Rect bounds)
    {
        artwork?.DrawControl(dc, NativeRect(bounds), "stop");
        int state = SaveDC(dc);
        if (SettingsArtwork.GdipCreateFromHDC(dc, out var graphics) != 0) { RestoreDC(dc, state); return; }
        IntPtr path = IntPtr.Zero, brush = IntPtr.Zero;
        try
        {
            if (GdipCreatePath(0, out path) != 0) return;
            GdipAddPathEllipse(path, bounds.Left + Px(7), bounds.Top + Px(10), bounds.Right - bounds.Left - Px(14), bounds.Bottom - bounds.Top - Px(20));
            if (GdipCreatePathGradientFromPath(path, out brush) != 0) return;
            GdipSetPathGradientCenterColor(brush, Argb(0x3A244F, 240));
            uint[] surround = [Argb(0x3A244F, 0)]; int count = 1;
            GdipSetPathGradientSurroundColorsWithCount(brush, surround, ref count);
            GdipSetPathGradientFocusScales(brush, .72f, .35f);
            GdipFillPath(graphics, brush, path);
        }
        finally
        {
            if (brush != IntPtr.Zero) GdipDeleteBrush(brush);
            if (path != IntPtr.Zero) GdipDeletePath(path);
            SettingsArtwork.GdipDeleteGraphics(graphics); RestoreDC(dc, state);
        }
    }

    private static void PaintPermissionAnnotations(IntPtr dc)
    {
        if (CompactSurface) return;
        var top = PetalPoint(.5f, .10f); var left = PetalPoint(.13f, .46f); var right = PetalPoint(.87f, .46f);
        var lowerLeft = PetalPoint(.28f, .80f); var lowerRight = PetalPoint(.72f, .80f);
        // Both upper petals belong to level 02. Each petal carries the full
        // number and name; a bare "01" made the right petal look detached.
        Label(PetalAnnotations[0], Layout.R(255, 108, 340, 44), 1, true);
        Label(PetalAnnotations[1], Layout.R(28, 294, 250, 44), 0);
        Label(PetalAnnotations[2], Layout.R(707, 423, 150, 38), 0);
        Label(PetalAnnotations[3], Layout.R(18, 617, 280, 44), 2);
        Label(PetalAnnotations[4], Layout.R(640, 637, 220, 44), 2);
        Leader(top, new Native.Point { X = top.X, Y = Px(162) }, new Native.Point { X = top.X, Y = Px(192) }, 1);
        Leader(left, new Native.Point { X = Px(62), Y = Px(346) }, new Native.Point { X = Px(188), Y = Px(346) }, 0);
        Leader(right, new Native.Point { X = Px(707), Y = Px(463) }, new Native.Point { X = Px(687), Y = Px(463) }, 0);
        Leader(lowerLeft, new Native.Point { X = Px(63), Y = Px(670) }, new Native.Point { X = Px(220), Y = Px(670) }, 2);
        Leader(lowerRight, new Native.Point { X = Px(765), Y = Px(689) }, new Native.Point { X = Px(654), Y = Px(689) }, 2);
        void Label(string value, Rect bounds, int level, bool center = false)
            => Text(dc, value, bounds, 24, HighContrast() ? GetSysColor(8) : AuthorityPresentation.Ink(level), false,
                centered: center, face: AnnotationFace);
        void Leader(Native.Point target, Native.Point label, Native.Point elbow, int level)
        {
            uint color = HighContrast() ? GetSysColor(8) : AuthorityPresentation.Ink(level);
            if (SettingsArtwork.GdipCreateFromHDC(dc, out var graphics) != 0) return;
            IntPtr pen = IntPtr.Zero;
            try
            {
                GdipSetSmoothingMode(graphics, 4);
                float dx = target.X - elbow.X, dy = target.Y - elbow.Y;
                float c1x = elbow.X + dx * .35f, c1y = elbow.Y;
                float c2x = target.X, c2y = target.Y - dy * .35f;
                if (GdipCreatePen1(Argb(color, 190), Math.Max(1f, Px(1)), 2, out pen) != 0) return;
                GdipDrawLine(graphics, pen, label.X, label.Y, elbow.X, elbow.Y);
                GdipDrawBezier(graphics, pen, elbow.X, elbow.Y, c1x, c1y, c2x, c2y, target.X, target.Y);
            }
            finally
            {
                if (pen != IntPtr.Zero) GdipDeletePen(pen);
                SettingsArtwork.GdipDeleteGraphics(graphics);
            }
        }
    }

    private static IntPtr BuildProgramActionMenu()
    {
        var menu = CreatePopupMenu();
        AppendMenuW(menu, 0, DetailId, UiText.Get("查看详情 / 复制路径"));
        int selected = Selection(ProgramListId); var rows = model.Programs(ruleLayer, denied);
        AppendMenuW(menu, 0, ToggleId, selected >= 0 && selected < rows.Length && rows[selected].Enabled ? UiText.Get("停用此规则") : UiText.Get("启用此规则"));
        AppendMenuW(menu, 0, RemoveId, UiText.Get("从名单移除"));
        return menu;
    }

    private static void ShowProgramActionMenu()
    {
        IntPtr menu = IntPtr.Zero;
        try
        {
            int index = Selection(ProgramListId);
            if (index < 0 || index >= model.Programs(ruleLayer, denied).Length) return;
            var boundRow = model.Programs(ruleLayer, denied)[index]; int boundLayer = ruleLayer;
            bool boundDenied = denied; var boundWindow = window;
            menu = BuildProgramActionMenu();
            if (menu == IntPtr.Zero) throw new Boundary("settings_menu_unavailable");
            GetWindowRect(PageHandle(ProgramMenuId), out var bounds);
            int choice = TrackPopupMenu(menu, 0x102, bounds.Right, bounds.Bottom, 0, window, IntPtr.Zero);
            if (choice != 0)
            {
                var current = model.Programs(ruleLayer, denied);
                if (window != boundWindow || page != 1 || ruleLayer != boundLayer || denied != boundDenied || Selection(ProgramListId) != index
                    || index >= current.Length || current[index] != boundRow)
                { notice = UiText.Get("名单已变化，请重新打开程序菜单。"); UpdateChrome(); return; }
                PageCommand(choice, 0);
            }
        }
        catch (Exception error)
        {
            surfaceFault |= error is not Boundary; notice = UiText.Get("程序操作未完成，草稿保留：") + Program.Code(error);
            Console.Error.WriteLine("settings_program_menu: " + Program.Code(error)); UpdateChrome();
        }
        finally { if (menu != IntPtr.Zero) DestroyMenu(menu); }
    }

    private static void PositionProgramMenu()
    {
        if (placingProgramMenu || !PermissionPage || ruleLayer < 2 || PageHandle(ProgramMenuId) == IntPtr.Zero) return;
        placingProgramMenu = true;
        try
        {
            var list = PageHandle(ProgramListId);
            int selected = Selection(ProgramListId), first = SendMessageW(list, 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32();
            GetClientRect(list, out var bounds); MapWindowPoints(list, window, ref bounds, 2);
            int top = bounds.Top + (selected - first) * ProgramRowHeight + (ProgramRowHeight - FontPixels(36)) / 2;
            bool visible = selected >= 0 && top >= bounds.Top && top + FontPixels(36) <= bounds.Bottom;
            if (visible) SetWindowPos(PageHandle(ProgramMenuId), IntPtr.Zero, bounds.Right - Px(53), top, Px(48), FontPixels(36), 0x14);
            ShowChromeControl(PageHandle(ProgramMenuId), visible);
        }
        finally { placingProgramMenu = false; }
    }

    private static void PaintListRemainder(IntPtr hwnd, IntPtr printDc)
    {
        bool programs = GetDlgCtrlID(hwnd) == ProgramListId;
        // The empty mask list has its own full-client hint painter.
        if (!programs && draft.Masks.Length == 0) return;
        GetClientRect(hwnd, out var client);
        int first = SendMessageW(hwnd, 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32();
        int used = Math.Min(client.Bottom, Math.Max(0, (programs ? RowCount : draft.Masks.Length) - first) * (programs ? ProgramRowHeight : MaskRowHeight));
        if (used >= client.Bottom) return;
        var dc = printDc != IntPtr.Zero ? printDc : GetDC(hwnd);
        int state = SaveDC(dc);
        try
        {
            IntersectClipRect(dc, 0, used, client.Right, client.Bottom);
            PaintControlBackdrop(new DrawItem { Window = hwnd, Dc = dc, Rect = client });
            if (programs && RowCount == 0)
            {
                var title = new Rect { Left = Px(24), Top = client.Top + Px(20), Right = client.Right - Px(24), Bottom = client.Top + Px(52) };
                Text(dc, UiText.Get("这份名单还没有程序"), title, 20, HighContrast() ? GetSysColor(8) : 0xE4DDE8u, false, nativeColor: HighContrast());
                var hint = new Rect { Left = Px(24), Top = title.Bottom + Px(2), Right = client.Right - Px(24), Bottom = title.Bottom + Px(52) };
                Text(dc, UiText.Get("使用下方“添加程序”入口；保存后才会生效。"), hint, 15, HighContrast() ? GetSysColor(8) : 0xBEB2BEu, false, nativeColor: HighContrast());
            }
        }
        finally { RestoreDC(dc, state); if (printDc == IntPtr.Zero) ReleaseDC(hwnd, dc); }
    }

    private static bool SelectProgramMenuRow(IntPtr list, int x, int y)
    {
        GetClientRect(list, out var client);
        if (x < 0 || x >= client.Right || y < 0 || y >= client.Bottom) return false;
        int index = SendMessageW(list, 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32() + y / ProgramRowHeight;
        if (index < 0 || index >= model.Programs(ruleLayer, denied).Length) return false;
        SendMessageW(list, 0x186, new IntPtr(index), IntPtr.Zero); PositionProgramMenu();
        return true;
    }

    [StructLayout(LayoutKind.Sequential)] private struct FloatRect(float x, float y, float width, float height)
    { public float X = x, Y = y, Width = width, Height = height; }
    [DllImport("gdiplus.dll")] private static extern int GdipCreateLineBrushFromRect(ref FloatRect rect, uint start, uint end, int mode, int wrap, out IntPtr brush);
    [DllImport("gdiplus.dll")] private static extern int GdipFillRectangle(IntPtr graphics, IntPtr brush, float x, float y, float width, float height);
    [DllImport("gdiplus.dll")] private static extern int GdipDeleteBrush(IntPtr brush);
    [DllImport("gdiplus.dll")] private static extern int GdipCreateSolidFill(uint color, out IntPtr brush);
    [DllImport("gdiplus.dll")] private static extern int GdipCreatePath(int mode, out IntPtr path);
    [DllImport("gdiplus.dll")] private static extern int GdipAddPathArc(IntPtr path, float x, float y, float width, float height, float start, float sweep);
    [DllImport("gdiplus.dll")] private static extern int GdipClosePathFigure(IntPtr path);
    [DllImport("gdiplus.dll")] private static extern int GdipFillPath(IntPtr graphics, IntPtr brush, IntPtr path);
    [DllImport("gdiplus.dll")] private static extern int GdipDeletePath(IntPtr path);
    [DllImport("gdiplus.dll")] private static extern int GdipAddPathEllipse(IntPtr path, float x, float y, float width, float height);
    [DllImport("gdiplus.dll")] private static extern int GdipCreatePathGradientFromPath(IntPtr path, out IntPtr brush);
    [DllImport("gdiplus.dll")] private static extern int GdipSetPathGradientCenterColor(IntPtr brush, uint color);
    [DllImport("gdiplus.dll")] private static extern int GdipSetPathGradientSurroundColorsWithCount(IntPtr brush, uint[] colors, ref int count);
    [DllImport("gdiplus.dll")] private static extern int GdipSetPathGradientFocusScales(IntPtr brush, float x, float y);
    [DllImport("gdiplus.dll")] private static extern int GdipCreatePen1(uint color, float width, int unit, out IntPtr pen);
    [DllImport("gdiplus.dll")] private static extern int GdipDeletePen(IntPtr pen);
    [DllImport("gdiplus.dll")] private static extern int GdipDrawBezier(IntPtr graphics, IntPtr pen, float x1, float y1, float x2, float y2, float x3, float y3, float x4, float y4);
    [DllImport("gdiplus.dll")] private static extern int GdipDrawEllipse(IntPtr graphics, IntPtr pen, float x, float y, float width, float height);
    [DllImport("gdiplus.dll")] private static extern int GdipFillEllipse(IntPtr graphics, IntPtr brush, float x, float y, float width, float height);
    [DllImport("gdiplus.dll")] private static extern int GdipDrawLine(IntPtr graphics, IntPtr pen, float x1, float y1, float x2, float y2);
    [DllImport("user32.dll")] private static extern int GetMenuItemCount(IntPtr menu);
}
