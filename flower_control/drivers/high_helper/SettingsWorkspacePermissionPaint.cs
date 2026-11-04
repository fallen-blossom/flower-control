using System.Runtime.InteropServices;

namespace Flower.HighHelper;

// The permission page keeps native BUTTON/LISTBOX controls and paints only
// their client rectangles. Nothing here owns hit testing, focus, keyboard or
// the authority model; the existing command IDs and validation remain intact.
internal static partial class SettingsWorkspace
{
    private static uint Rgb(int r, int g, int b) => (uint)(r | g << 8 | b << 16);
    private static readonly uint PermissionInk = Rgb(0xF7, 0xF0, 0xF2);
    private static readonly uint PermissionMuted = Rgb(0xC5, 0xB6, 0xC6);
    private static readonly uint PermissionFaint = Rgb(0x9E, 0x8C, 0xA5);
    private static readonly uint PermissionChampagne = Rgb(0xEF, 0xD4, 0xB2);
    private static readonly uint PermissionDraft = Rgb(0xFF, 0xC0, 0x8B);
    private static readonly uint PermissionLilac = Rgb(0xDC, 0xC9, 0xFF);
    private static readonly uint PermissionJade = Rgb(0xB8, 0xDD, 0xC2);
    private static readonly uint PermissionRose = Rgb(0xEF, 0xA0, 0xAD);

    private static void PaintPermissionTier(DrawItem item, int index)
    {
        int targetTier = AuthorityPresentation.ButtonTier(index);
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        int top = bounds.Top, bottom = bounds.Bottom, left = bounds.Left, right = bounds.Right;
        bool effective = model.EffectiveTier == targetTier;
        bool draft = Dirty && tier == targetTier;
        bool viewing = ruleLayer == targetTier;
        uint accent = AuthorityPresentation.Ink(targetTier);

        if (!HighContrast() && (draft || viewing))
        {
            var highlight = bounds;
            highlight.Left += Px(8);
            highlight.Right -= Px(4);
            highlight.Top += Px(2);
            highlight.Bottom -= Px(2);
            SoftSurface(item.Dc, highlight, draft ? Rgb(0x82, 0x69, 0x56) : Rgb(0x6D, 0x5A, 0x83),
                (byte)(draft ? 34 : 22), 22);
        }

        int stemX = left + Px(18);
        uint stem = effective || draft ? accent : Rgb(0x6E, 0x5E, 0x74);
        Line(item.Dc, stemX, top, stemX, bottom, HighContrast() ? GetSysColor(8) : stem);

        int node = Math.Max(Px(12), 12);
        var nodeRect = new Rect { Left = stemX - node / 2, Top = top + (bottom - top - node) / 2, Right = stemX + node / 2, Bottom = top + (bottom - top + node) / 2 };
        if (!HighContrast())
        {
            SoftSurface(item.Dc, nodeRect, accent, 255, node / 2);
            int core = Math.Max(Px(4), 4);
            var coreRect = new Rect { Left = stemX - core / 2, Top = (top + bottom - core) / 2, Right = stemX + core / 2, Bottom = (top + bottom + core) / 2 };
            SoftSurface(item.Dc, coreRect, Rgb(0x17, 0x10, 0x1C), 255, core / 2);
        }

        var number = new Rect { Left = left + Px(34), Top = top + Px(3), Right = left + Px(58), Bottom = bottom };
        Text(item.Dc, (index + 1).ToString("00"), number, 13,
            HighContrast() ? GetSysColor(8) : accent, false, nativeColor: HighContrast(), shadow: true);
        var name = new Rect { Left = left + Px(58), Top = top + Px(2), Right = right - Px(94), Bottom = top + Px(27) };
        Text(item.Dc, AuthorityPresentation.Name(targetTier), name, 22,
            HighContrast() ? GetSysColor(8) : accent,
            true, nativeColor: HighContrast(), shadow: true);
        var description = new Rect { Left = left + Px(58), Top = top + Px(27), Right = right - Px(20), Bottom = bottom - Px(2) };
        string detail = targetTier switch { -1 => UiText.Get("三个控制通道停止派发"), 0 => UiText.Get("普通窗口的观察与操作"), 1 => UiText.Get("管理员窗口的观察与操作"), _ => UiText.Get("High 启动授权") };
        Text(item.Dc, detail, description, 14,
            HighContrast() ? GetSysColor(8) : PermissionFaint, false, nativeColor: HighContrast());

        string badge = effective ? UiText.Get("生效") : draft ? UiText.Get("待保存") : viewing ? UiText.Get("查看") : "";
        if (badge.Length > 0)
        {
            var pill = new Rect { Left = right - Px(78), Top = top + Px(12), Right = right - Px(8), Bottom = top + Px(33) };
            if (!HighContrast()) SoftSurface(item.Dc, pill, accent, 20, 9);
            Text(item.Dc, badge, pill, 13, HighContrast() ? GetSysColor(8) : accent, false, centered: true, nativeColor: HighContrast());
        }

        if (GetFocus() == item.Window)
        {
            if (HighContrast())
            {
                var focus = bounds; focus.Left += 2; focus.Top += 2; focus.Right -= 2; focus.Bottom -= 2;
                PaintKeyboardFocus(item.Dc, ref focus);
            }
            else Line(item.Dc, bounds.Left + Px(20), bounds.Bottom - Px(2), bounds.Right - Px(10), bounds.Bottom - Px(2), accent, 2);
        }
    }

    private static void PaintPermissionTierCompact(DrawItem item, int index)
    {
        int targetTier = AuthorityPresentation.ButtonTier(index);
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        bool effective = model.EffectiveTier == targetTier;
        bool draft = Dirty && tier == targetTier;
        bool viewing = ruleLayer == targetTier;
        uint accent = AuthorityPresentation.Ink(targetTier);
        if (!HighContrast() && (draft || viewing))
            SoftSurface(item.Dc, bounds, draft ? Rgb(0x82, 0x69, 0x56) : Rgb(0x6D, 0x5A, 0x83), (byte)(draft ? 30 : 22), 12);
        int cx = bounds.Left + Px(10), cy = (bounds.Top + bounds.Bottom) / 2;
        if (!HighContrast())
        {
            SoftSurface(item.Dc, new Rect { Left = cx - Px(4), Top = cy - Px(4), Right = cx + Px(4), Bottom = cy + Px(4) }, accent, 255, 4);
            SoftSurface(item.Dc, new Rect { Left = cx - Px(1), Top = cy - Px(1), Right = cx + Px(1), Bottom = cy + Px(1) }, Rgb(0x17, 0x10, 0x1C), 255, 1);
        }
        string compactName = index switch { 0 => UiText.Get("停止"), 1 => UiText.Get("普通"), 2 => UiText.Get("窗口"), _ => UiText.Get("执行") };
        Text(item.Dc, (index + 1).ToString("00") + " " + compactName, new Rect { Left = bounds.Left + Px(18), Top = bounds.Top, Right = bounds.Right - Px(1), Bottom = bounds.Bottom },
            14, HighContrast() ? GetSysColor(8) : accent,
            true, nativeColor: HighContrast());
        if (GetFocus() == item.Window)
        {
            if (HighContrast())
            {
                var focus = bounds; focus.Left += 1; focus.Top += 1; focus.Right -= 1; focus.Bottom -= 1;
                PaintKeyboardFocus(item.Dc, ref focus);
            }
            else Line(item.Dc, bounds.Left + Px(8), bounds.Bottom - Px(1), bounds.Right - Px(8), bounds.Bottom - Px(1), accent, 2);
        }
    }

    private static void PaintPermissionViewTick(DrawItem item, int index)
    {
        PaintPermissionViewTickCompact(item, index);
    }

    private static void PaintPermissionViewTickCompact(DrawItem item, int index)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        bool active = ruleLayer == index;
        uint color = active ? PermissionLilac : PermissionMuted;
        string[] labels = { UiText.Get("02 普通"), UiText.Get("03 管理"), UiText.Get("04 执行") };
        Text(item.Dc, labels[index], bounds, 16, HighContrast() ? GetSysColor(8) : color, active, centered: true, nativeColor: HighContrast());
        if (!HighContrast())
            Line(item.Dc, bounds.Left + Px(16), bounds.Bottom - Px(2), bounds.Right - Px(16), bounds.Bottom - Px(2),
                active ? PermissionLilac : Rgb(0x4F, 0x40, 0x58), active ? 2 : 1);
        if (GetFocus() == item.Window)
        {
            if (HighContrast())
            {
                var focus = bounds; focus.Left += 1; focus.Top += 1; focus.Right -= 1; focus.Bottom -= 1;
                PaintKeyboardFocus(item.Dc, ref focus);
            }
            else Line(item.Dc, bounds.Left + Px(10), bounds.Bottom - Px(1), bounds.Right - Px(10), bounds.Bottom - Px(1), PermissionInk, 2);
        }
    }

    private static void PaintPermissionListKindCompact(DrawItem item, bool denied)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        bool active = denied == SettingsWorkspace.denied;
        uint accent = denied ? PermissionRose : PermissionJade;
        if (!HighContrast() && active) SoftSurface(item.Dc, bounds, accent, 16, 10);
        string title = denied ? UiText.Get("黑名单") : UiText.Get("白名单");
        int count = model.Programs(ruleLayer, denied).Length;
        string state = "  · " + (active ? UiText.Get("编辑") : UiText.Get("查看"));
        Text(item.Dc, title + "  " + count + state, new Rect { Left = bounds.Left + Px(12), Top = bounds.Top, Right = bounds.Right - Px(10), Bottom = bounds.Bottom },
            16, HighContrast() ? GetSysColor(8) : active ? PermissionInk : PermissionMuted, active, nativeColor: HighContrast());
        if (!HighContrast())
        {
            if (denied) Line(item.Dc, bounds.Left, bounds.Top + Px(5), bounds.Left, bounds.Bottom - Px(5), Rgb(0x45, 0x3A, 0x50));
            Line(item.Dc, bounds.Left + Px(12), bounds.Bottom - Px(2), bounds.Right - Px(12), bounds.Bottom - Px(2), active ? accent : Rgb(0x45, 0x3A, 0x50), active ? 2 : 1);
        }
        if (GetFocus() == item.Window)
        {
            if (HighContrast())
            {
                var focus = bounds; focus.Left += 1; focus.Top += 1; focus.Right -= 1; focus.Bottom -= 1;
                PaintKeyboardFocus(item.Dc, ref focus);
            }
            else Line(item.Dc, bounds.Left + Px(10), bounds.Bottom - Px(1), bounds.Right - Px(10), bounds.Bottom - Px(1), PermissionInk, 2);
        }
    }

    private static void PaintPermissionListKind(DrawItem item, bool denied)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        bool active = denied == SettingsWorkspace.denied;
        uint accent = denied ? PermissionRose : PermissionJade;
        if (!HighContrast())
        {
            SoftSurface(item.Dc, bounds, accent, (byte)(active ? 22 : 7), 14);
            Line(item.Dc, bounds.Left, bounds.Top, bounds.Right, bounds.Top, Rgb(0x3D, 0x34, 0x49));
            Line(item.Dc, bounds.Left, bounds.Bottom, bounds.Right, bounds.Bottom, Rgb(0x3D, 0x34, 0x49));
            if (active) Line(item.Dc, bounds.Left + Px(18), bounds.Bottom - Px(2), bounds.Right - Px(18), bounds.Bottom - Px(2), accent, 2);
        }
        string title = denied ? UiText.Get("黑名单") : UiText.Get("白名单");
        int count = model.Programs(ruleLayer, denied).Length;
        Text(item.Dc, title + "  " + count, new Rect { Left = bounds.Left + Px(18), Top = bounds.Top + Px(8), Right = bounds.Right - Px(92), Bottom = bounds.Top + Px(36) },
            24, HighContrast() ? GetSysColor(8) : PermissionInk, true, nativeColor: HighContrast(), shadow: true);
        Text(item.Dc, denied ? UiText.Get("优先于白名单，命中即阻止") : draft.AdminLaunchMode == "semantic" ? UiText.Get("工作授权不使用白名单") : UiText.Get("只有这些程序可以进入"),
            new Rect { Left = bounds.Left + Px(18), Top = bounds.Top + Px(37), Right = bounds.Right - Px(16), Bottom = bounds.Bottom - Px(4) },
            14, HighContrast() ? GetSysColor(8) : PermissionMuted, false, nativeColor: HighContrast());
        Text(item.Dc, active ? UiText.Get("正在编辑") : UiText.Get("点击查看"),
            new Rect { Left = bounds.Right - Px(92), Top = bounds.Top + Px(12), Right = bounds.Right - Px(14), Bottom = bounds.Top + Px(31) },
            13, HighContrast() ? GetSysColor(8) : active ? accent : PermissionFaint, false, centered: true, nativeColor: HighContrast());
        if (GetFocus() == item.Window)
        {
            var focus = bounds; focus.Left += 2; focus.Top += 2; focus.Right -= 2; focus.Bottom -= 2;
            PaintKeyboardFocus(item.Dc, ref focus);
        }
    }

    private static void PaintPermissionTextChoice(DrawItem item)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        if ((int)item.Id == ModeChoiceBase)
        {
            bool right = PermissionChoiceSelected(ModeChoiceBase + 1);
            bool enabled = (item.State & 4) == 0;
            int mid = (bounds.Left + bounds.Right) / 2;
            var thumb = bounds; thumb.Left = right ? mid : bounds.Left; thumb.Right = right ? bounds.Right : mid;
            if (!HighContrast())
            {
                SoftSurface(item.Dc, bounds, Rgb(0x54, 0x42, 0x62), (byte)(enabled ? 65 : 30), 18);
                thumb.Left += Px(3); thumb.Right -= Px(3); thumb.Top += Px(3); thumb.Bottom -= Px(3);
                SoftSurface(item.Dc, thumb, Rgb(0xB2, 0x9B, 0xC9), (byte)(enabled ? 85 : 30), 15);
                Line(item.Dc, thumb.Left + Px(12), thumb.Bottom - Px(2), thumb.Right - Px(12), thumb.Bottom - Px(2), PermissionLilac);
            }
            else { var fill = bounds; FillRect(item.Dc, ref fill, GetSysColorBrush(15)); Frame(item.Dc, thumb, GetSysColor(8)); }
            var left = bounds; left.Right = mid; var rightRect = bounds; rightRect.Left = mid;
            uint selected = HighContrast() ? GetSysColor(8) : enabled ? PermissionInk : PermissionFaint;
            uint other = HighContrast() ? GetSysColor(8) : PermissionMuted;
            Text(item.Dc, UiText.Get("程序名单"), left, 18, right ? other : selected, !right, centered: true, nativeColor: HighContrast());
            Text(item.Dc, UiText.Get("按工作授权"), rightRect, 18, right ? selected : other, right, centered: true, nativeColor: HighContrast());
            if (GetFocus() == item.Window) { var focus = bounds; focus.Left += 2; focus.Right -= 2; PaintKeyboardFocus(item.Dc, ref focus); }
            return;
        }
        bool active = PermissionChoiceSelected((int)item.Id);
        bool disabled = (item.State & 4) != 0;
        uint color = disabled ? Rgb(0x6F, 0x62, 0x75) : active ? PermissionInk : PermissionMuted;
        if (!HighContrast())
        {
            SoftSurface(item.Dc, bounds, active ? PermissionLilac : PermissionMuted, (byte)(active ? 35 : 12), 8);
            Frame(item.Dc, bounds, active ? PermissionLilac : PermissionFaint);
        }
        Text(item.Dc, PermissionChoiceText((int)item.Id), bounds, 18, HighContrast() ? GetSysColor(8) : color, active, centered: true, nativeColor: HighContrast());
        if (active && !HighContrast())
            Line(item.Dc, bounds.Left, bounds.Bottom - Px(2), bounds.Right, bounds.Bottom - Px(2), PermissionLilac, 1);
        if (GetFocus() == item.Window)
        {
            var focus = bounds; focus.Top += 1; focus.Bottom -= 1;
            PaintKeyboardFocus(item.Dc, ref focus);
        }
    }

    private static void PaintPermissionSave(DrawItem item)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        bool enabled = (item.State & 4) == 0;
        if (HighContrast())
        {
            var fill = bounds; FillRect(item.Dc, ref fill, GetSysColorBrush(enabled ? 15 : 16));
            Frame(item.Dc, bounds, GetSysColor(18));
            Text(item.Dc, UiText.Get("保存权限"), bounds, 17, GetSysColor(enabled ? 18 : 17), enabled, centered: true, nativeColor: true);
            return;
        }

        int left = bounds.Left + Px(2), right = bounds.Right - Px(2), top = bounds.Top + Px(1), bottom = bounds.Bottom - Px(1);
        int center = (top + bottom) / 2;
        int notch = Px(16);
        var points = new[]
        {
            (left + notch, top), (right - notch, top), (right, center),
            (right - notch, bottom), (left + notch, bottom), (left, center)
        };
        int state = SaveDC(item.Dc);
        IntPtr brush = IntPtr.Zero, path = IntPtr.Zero;
        try
        {
            if (SettingsArtwork.GdipCreateFromHDC(item.Dc, out var graphics) == 0)
            {
                try
                {
                    if (GdipCreatePath(0, out path) == 0)
                    {
                        for (int i = 0; i < points.Length; i++)
                        {
                            var next = points[(i + 1) % points.Length];
                            GdipAddPathLine(path, points[i].Item1, points[i].Item2, next.Item1, next.Item2);
                        }
                        GdipClosePathFigure(path);
                        if (GdipCreateSolidFill(Argb(Rgb(0x24, 0x1E, 0x36), (byte)(enabled ? 244 : 150)), out brush) == 0)
                            GdipFillPath(graphics, brush, path);
                    }
                }
                finally { SettingsArtwork.GdipDeleteGraphics(graphics); }
            }
        }
        finally
        {
            if (path != IntPtr.Zero) GdipDeletePath(path);
            if (brush != IntPtr.Zero) GdipDeleteBrush(brush);
            RestoreDC(item.Dc, state);
        }

        uint rim = enabled ? PermissionChampagne : Rgb(0x6D, 0x5E, 0x71);
        for (int i = 0; i < points.Length; i++)
        {
            var next = points[(i + 1) % points.Length];
            Line(item.Dc, points[i].Item1, points[i].Item2, next.Item1, next.Item2, rim);
        }
        if (enabled)
        {
            Line(item.Dc, left + notch, top, left + Px(25), top + Px(5), Rgb(0xF2, 0xD5, 0xB2));
            Line(item.Dc, right - notch, bottom, right - Px(27), bottom - Px(5), Rgb(0xF2, 0xD5, 0xB2));
        }
        int glyphX = left + Px(22), glyphY = center;
        uint glyph = enabled ? PermissionChampagne : Rgb(0x79, 0x6B, 0x7D);
        Line(item.Dc, glyphX, glyphY - Px(7), glyphX + Px(6), glyphY, glyph);
        Line(item.Dc, glyphX + Px(6), glyphY, glyphX, glyphY + Px(7), glyph);
        Line(item.Dc, glyphX, glyphY + Px(7), glyphX - Px(6), glyphY, glyph);
        Line(item.Dc, glyphX - Px(6), glyphY, glyphX, glyphY - Px(7), glyph);
        Line(item.Dc, glyphX - Px(2), glyphY, glyphX + Px(1), glyphY + Px(3), glyph);
        Line(item.Dc, glyphX + Px(1), glyphY + Px(3), glyphX + Px(5), glyphY - Px(3), glyph);

        var label = new Rect { Left = left + Px(38), Top = top, Right = right - Px(6), Bottom = bottom };
        Text(item.Dc, UiText.Get("保存权限"), label, 17, enabled ? PermissionInk : Rgb(0x86, 0x78, 0x8A), enabled, centered: false);
        if (GetFocus() == item.Window) { var focus = bounds; PaintKeyboardFocus(item.Dc, ref focus); }
    }

    private static void PaintPermissionStop(DrawItem item)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        if (HighContrast())
        {
            var fill = bounds; FillRect(item.Dc, ref fill, GetSysColorBrush(15));
            Frame(item.Dc, bounds, GetSysColor(18));
            Text(item.Dc, UiText.Get("结束电脑操作"), bounds, 17, GetSysColor(18), true, centered: true, nativeColor: true);
            return;
        }
        PaintRoseControl(item.Dc, bounds);
        int center = (bounds.Top + bounds.Bottom) / 2;
        int left = bounds.Left + Px(24);
        var square = new Rect { Left = left, Top = center - Px(5), Right = left + Px(10), Bottom = center + Px(5) };
        Fill(item.Dc, square, Rgb(0xFF, 0xE1, 0xE7));
        Text(item.Dc, UiText.Get("结束电脑操作"),
            new Rect { Left = left + Px(20), Top = bounds.Top, Right = bounds.Right - Px(16), Bottom = bounds.Bottom },
            18, Rgb(0xFF, 0xF4, 0xF6), true, centered: true);
        if (GetFocus() == item.Window)
        {
            var focus = bounds; focus.Left += 2; focus.Top += 2; focus.Right -= 2; focus.Bottom -= 2;
            PaintKeyboardFocus(item.Dc, ref focus);
        }
    }

    private static void PaintPermissionNoticeDetails(DrawItem item)
    {
        PaintControlBackdrop(item);
        var bounds = item.Rect;
        Text(item.Dc, UiText.Get("详情"), bounds, 15, PermissionLilac, false, centered: true);
        Line(item.Dc, bounds.Left + Px(8), bounds.Bottom - Px(2), bounds.Right - Px(8), bounds.Bottom - Px(2),
            (item.State & 4) != 0 ? PermissionFaint : PermissionLilac);
        if (GetFocus() == item.Window)
        {
            var focus = bounds; focus.Left += 1; focus.Top += 1; focus.Right -= 1; focus.Bottom -= 1;
            PaintKeyboardFocus(item.Dc, ref focus);
        }
    }

    private static void UpdateTierAccessibleText()
    {
        for (int index = 0; index < 4; index++)
        {
            var handle = GetDlgItem(window, TierBase + index);
            if (handle == IntPtr.Zero) continue;
            int targetTier = AuthorityPresentation.ButtonTier(index);
            bool effective = model.EffectiveTier == targetTier;
            bool draft = Dirty && tier == targetTier;
            bool viewing = PermissionPage && ruleLayer == targetTier;
            string label = AuthorityPresentation.Label(targetTier);
            if (effective) label += UiText.Get("，已保存");
            if (draft) label += UiText.Get("，待保存");
            if (viewing) label += UiText.Get("，正在查看");
            label += preview ? UiText.Get("。预览中只修改草稿。") : UiText.Get("。点击立即切换；其它编辑保留。");
            if (!Text(handle).Equals(label, StringComparison.Ordinal)) SetWindowTextW(handle, label);
        }
    }

    [DllImport("gdiplus.dll")] private static extern int GdipAddPathLine(IntPtr path, float x1, float y1, float x2, float y2);
}
