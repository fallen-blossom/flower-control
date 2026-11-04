using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static string BodyFace = "Microsoft YaHei UI", DisplayFace = "SimSun", AnnotationFace = "SimSun";
    private static int pageFontHeight;
    private static bool keyboardNavigation;
    private readonly record struct UiFontKey(int Height, int Weight, string Face);
    private static readonly Dictionary<UiFontKey, IntPtr> uiFonts = [];

    // Scene painting used to create and delete a GDI font for every text run.
    // A native frame can contain dozens of runs, so caching these immutable
    // handles removes allocator churn without changing text, hit testing or
    // accessibility. The cache is bounded by the finite size/weight roles used
    // by this window and is released on surface shutdown.
    private static IntPtr UiFont(int height, int weight, string face)
    {
        var key = new UiFontKey(height, weight, face);
        if (uiFonts.TryGetValue(key, out var existing)) return existing;
        var created = CreateFontW(height, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 4, 0, face);
        if (created != IntPtr.Zero) uiFonts[key] = created;
        return created;
    }

    private static void ReleaseUiFonts()
    {
        foreach (var font in uiFonts.Values) if (font != IntPtr.Zero) DeleteObject(font);
        uiFonts.Clear();
    }
    private static void SetKeyboardNavigation(bool value)
    {
        if (keyboardNavigation == value) return;
        keyboardNavigation = value;
        var focused = GetFocus();
        if (focused != IntPtr.Zero && IsChild(window, focused)) InvalidateRect(focused, IntPtr.Zero, false);
    }
    // Pointer activation has selection/hover feedback. Keyboard navigation
    // keeps a visible underline; Windows high contrast keeps its native ring.
    private static void PaintKeyboardFocus(IntPtr dc, ref Rect bounds)
    {
        if (HighContrast()) DrawFocusRect(dc, ref bounds);
        else if (keyboardNavigation)
            Line(dc, bounds.Left + Px(8), bounds.Bottom - Px(2), bounds.Right - Px(8), bounds.Bottom - Px(2), 0xE3BCD8, 2);
    }
    private static string SettingsIconFace = "Segoe MDL2 Assets";
    private static bool CompactSurface
    {
        get
        {
            // English needs the existing layout with wider content at either
            // size; the narrow hero column truncates full labels and notices.
            if (UiText.English) return true;
            GetClientRect(window, out var client);
            return window != IntPtr.Zero && client.Right < 1050 * Math.Max(96, GetDpiForWindow(window)) / 96.0;
        }
    }
    private static int FontPixels(int size) => Math.Max((int)Math.Round((CompactSurface ? 12 : 10) * Math.Max(96, GetDpiForWindow(window)) / 96.0), Px(size));
    private delegate IntPtr SubclassProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data);
    private static readonly SubclassProc ThemeProcedure = ThemeControl;

    private static IntPtr ThemeControl(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        ++nativeCallbackDepth;
        try { return ThemeControlCore(hwnd, message, wp, lp, id, data); }
        catch (Exception error) { NativeCallbackFailed(error); return IntPtr.Zero; }
        finally { try { FinishNativeCallback(); } catch (Exception error) { NativeCallbackFailed(error); } }
    }

    private static IntPtr ThemeControlCore(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        if (message == 0x82) { if (hotCombo == hwnd) hotCombo = IntPtr.Zero; RemoveWindowSubclass(hwnd, ThemeProcedure, id); }
        int controlId = GetDlgCtrlID(hwnd);
        if (controlId == ModeChoiceBase && message == 0x202)
        {
            GetClientRect(hwnd, out var bounds);
            int x = unchecked((short)(lp.ToInt64() & 0xffff));
            modeMouseChoice = x < bounds.Right / 2 ? 0 : 1;
            try { return DefSubclassProc(hwnd, message, wp, lp); }
            finally { modeMouseChoice = null; }
        }
        if (controlId == ModeChoiceBase && message is 0xF or 0x318) return DefSubclassProc(hwnd, message, wp, lp);
        bool maskList = controlId == MaskListId;
        bool combo = pageControls.Any(c => c.Handle == hwnd && c.Kind == "COMBOBOX");
        if (combo && message is 7 or 8 or 0x200 or 0x2A3 or 0x201 or 0x202 or 0x100 or 0x101)
        {
            if (message == 0x200) TrackComboHover(hwnd);
            if (message == 0x2A3 && hotCombo == hwnd) hotCombo = IntPtr.Zero;
            InvalidateRect(hwnd, IntPtr.Zero, false);
        }
        if (!HighContrast() && message is 0xF or 0x318
            && (!maskList || SendMessageW(hwnd, 0x18B, IntPtr.Zero, IntPtr.Zero) == IntPtr.Zero))
        {
            var paint = new PaintStruct();
            var dc = message == 0xF ? BeginPaint(hwnd, ref paint) : (IntPtr)wp;
            try
            {
                GetClientRect(hwnd, out var rect);
                if (combo) { PaintComboField(dc, hwnd, rect); return IntPtr.Zero; }
                PaintControlBackdrop(new DrawItem { Window = hwnd, Dc = dc, Rect = rect });
                if (maskList)
                {
                    var empty = rect; empty.Left += Px(20); empty.Top += Px(16);
                    WrappedText(dc, UiText.Get("还没有截图遮挡区域"), empty, 20, 0xD6C4DF);
                    return IntPtr.Zero;
                }
                // A newly added native checkbox must not be painted as a combo
                // merely because its ID is absent from a historical allowlist.
                bool check = (GetWindowLongW(hwnd, -16) & 0xF) == 3; // BS_AUTOCHECKBOX
                var text = rect;
                if (check)
                {
                    int markSize = Math.Max(1, Math.Min(rect.Bottom - rect.Top - Px(4), Math.Max(Px(19), FontPixels(16) + Px(2))));
                    int markTop = rect.Top + (rect.Bottom - rect.Top - markSize) / 2;
                    var mark = new Rect { Left = Px(2), Top = markTop, Right = Px(2) + markSize, Bottom = markTop + markSize };
                    bool enabled = IsWindowEnabled(hwnd), selected = SendMessageW(hwnd, 0xF0, IntPtr.Zero, IntPtr.Zero) != IntPtr.Zero;
                    SoftSurface(dc, mark, selected ? 0xB8DDB7u : 0xA69A98u, (byte)(selected ? enabled ? 230 : 95 : 110), 5);
                    if (selected)
                    {
                        uint ink = enabled ? 0x20331Eu : 0x5D615Bu;
                        int stroke = Math.Max(1, (int)Math.Ceiling(1.6 / scale));
                        Line(dc, mark.Left + markSize / 5, mark.Top + markSize / 2, mark.Left + markSize * 2 / 5, mark.Top + markSize * 3 / 4, ink, stroke);
                        Line(dc, mark.Left + markSize * 2 / 5, mark.Top + markSize * 3 / 4, mark.Left + markSize * 4 / 5, mark.Top + markSize / 4, ink, stroke);
                    }
                    text.Left = mark.Right + Math.Max(Px(14), FontPixels(16) / 2);
                }
                else
                {
                    text.Left += Px(4); text.Right -= Px(30);
                    int x = rect.Right - Px(16), y = (rect.Bottom - rect.Top) / 2;
                    Line(dc, x - Px(5), y - Px(2), x, y + Px(3), 0xDDC2E7);
                    Line(dc, x, y + Px(3), x + Px(5), y - Px(2), 0xDDC2E7);
                }
                Text(dc, Text(hwnd), text, 20, IsWindowEnabled(hwnd) ? 0xE9EAF2u : 0xA9A2ACu, false);
                if (GetFocus() == hwnd)
                {
                    var focus = rect; focus.Left += 1; focus.Top += 1; focus.Right -= 1; focus.Bottom -= 1;
                    PaintKeyboardFocus(dc, ref focus);
                }
            }
            catch (Exception error) { Console.Error.WriteLine("settings_control_paint: " + Program.Code(error)); }
            finally { if (message == 0xF) EndPaint(hwnd, ref paint); }
            return IntPtr.Zero;
        }
        return DefSubclassProc(hwnd, message, wp, lp);
    }

    private static void ApplyWindowMaterial()
    {
        ReleaseInteractiveControls(); ReleaseScene();
        ReleaseBackdrop();
        BodyFace = ResolveFace("MiSans", "Microsoft YaHei UI");
        SettingsIconFace = ResolveFace("Segoe Fluent Icons", "Segoe MDL2 Assets");
        DisplayFace = ResolveFace("Source Han Serif SC Heavy", "Source Han Serif SC", "SimSun");
        AnnotationFace = ResolveFace("Source Han Serif SC", "SimSun");
        int enabled = HighContrast() ? 0 : 1;
        _ = DwmSetWindowAttribute(window, 20, ref enabled, sizeof(int));
        int caption = HighContrast() ? -1 : 0x211624, ink = HighContrast() ? -1 : 0xF4E8FA;
        _ = DwmSetWindowAttribute(window, 35, ref caption, sizeof(int));
        _ = DwmSetWindowAttribute(window, 36, ref ink, sizeof(int));
        ApplyWindowIcons();
        Console.Error.WriteLine("settings_fonts: body=" + BodyFace + "; display=" + DisplayFace + "; annotation=" + AnnotationFace);
    }

    private static void ApplyWindowIcons()
    {
        uint dpi = Math.Max(96, GetDpiForWindow(window));
        // Same six embedded resources and state as the tray. Handles are
        // borrowed from TrayStateIcons across closing and reopening settings.
        var small = TrayStateIcons.Load(workspaceIconState, GetSystemMetricsForDpi(49, dpi), GetSystemMetricsForDpi(50, dpi));
        var large = TrayStateIcons.Load(workspaceIconState, GetSystemMetricsForDpi(11, dpi), GetSystemMetricsForDpi(12, dpi));
        SendMessageW(window, 0x80, IntPtr.Zero, small);
        SendMessageW(window, 0x80, new IntPtr(1), large);
    }

    [DllImport("user32.dll")] private static extern int GetSystemMetricsForDpi(int index, uint dpi);

    private static string ResolveFace(params string[] candidates)
    {
        var dc = GetDC(IntPtr.Zero);
        try
        {
            foreach (string candidate in candidates)
            {
                var font = CreateFontW(-24, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, candidate);
                if (font == IntPtr.Zero) continue;
                var previous = SelectObject(dc, font);
                var name = new StringBuilder(128);
                GetTextFaceW(dc, name.Capacity, name);
                SelectObject(dc, previous); DeleteObject(font);
                if (name.ToString().Equals(candidate, StringComparison.OrdinalIgnoreCase)
                    || name.ToString().StartsWith(candidate + " ", StringComparison.OrdinalIgnoreCase)) return name.ToString();
            }
            return candidates[^1];
        }
        finally { ReleaseDC(IntPtr.Zero, dc); }
    }

    private static string EffectiveMode() => model.EffectiveTier < 0 ? UiText.Get("完全停止") : model.EffectiveTier < 2 ? UiText.Get("本机窗口控制")
        : model.EffectiveTier == 2 ? saved.AdminLaunchMode == "semantic" ? UiText.Get("按工作授权") : UiText.Get("名单模式")
        : saved.UacMode == "semantic" ? UiText.Get("语义模式") : UiText.Get("名单模式");

    private static string VisibleNotice()
    {
        if (notice.StartsWith(UiText.Get("权限已保存")) && notice.Contains("privacy_words_save_outcome_unknown")) return UiText.Get("权限已存；敏感词结果未知，请重载。");
        if (notice.StartsWith(UiText.Get("权限已保存")) && notice.Contains("outcome_unknown")) return UiText.Get("权限已保存，部分结果待核对。");
        if (notice.Contains("outcome_unknown") || notice.StartsWith(UiText.Get("结果待核对"))) return UiText.Get("结果待核对，草稿保留。请查看详情。");
        if (notice.Contains("task_jev_disabled", StringComparison.Ordinal) || notice.Contains("jev_disabled_or_not_allowed", StringComparison.Ordinal))
            return UiText.Get("此任务未允许远程决策；主模型仍可用。");
        if (notice.Contains("jev_disabled", StringComparison.Ordinal)) return UiText.Get("决策 API 总开关关闭；主模型仍可用。");
        if (notice.Contains("client_unavailable", StringComparison.Ordinal)) return UiText.Get("决策服务客户端暂不可用。");
        if (notice.Contains("settings_ui_preferences_changed", StringComparison.Ordinal)) return UiText.Get("界面偏好已被其他窗口修改。");
        if (notice.Contains("privacy_words_changed", StringComparison.Ordinal)) return UiText.Get("敏感词表已被其他窗口修改。");
        if (notice.Contains("uac_registered_action_mismatch")) return UiText.Get("操作与登记内容不一致，草稿保留。");
        if (notice.StartsWith(UiText.Get("操作未完成"))) return UiText.Get("操作未完成，草稿保留。请查看详情。");
        string text = notice.Replace("privacy_words_changed", UiText.Get("敏感词已被其它窗口修改"))
            .Replace("settings_ui_preferences_changed", UiText.Get("显示偏好已被其它窗口修改"));
        return text.Length > (CompactSurface ? 25 : 38) ? text[..(CompactSurface ? 22 : 35)] + "…" : text;
    }

    private static void PaintBackdrop(IntPtr dc, Rect canvas)
    {
        int width = canvas.Right - canvas.Left, height = canvas.Bottom - canvas.Top;
        // Every child needs a small crop of the same static scene. Resampling
        // the full bitmap and both gradients per label/button stalls the UI.
        if (EnsureBackdrop(dc, width, height))
        {
            bool copied = backdropKey.Width == width && backdropKey.Height == height
                ? BitBlt(dc, canvas.Left, canvas.Top, width, height, backdropDc, 0, 0, 0x00CC0020)
                : CopyRaster(dc, canvas.Left, canvas.Top, width, height, backdropDc, 0, 0, backdropKey.Width, backdropKey.Height, 0x00CC0020);
            if (!copied) PaintBackdropUncached(dc, canvas);
        }
        else PaintBackdropUncached(dc, canvas);
    }

    private static void PaintBackdropUncached(IntPtr dc, Rect canvas)
    {
        Fill(dc, canvas, 0x1D1419);
        if (!HighContrast()) artwork?.DrawBackground(dc, NativeRect(canvas), .77f);
        PaintQuietAtmosphere(dc, canvas);
    }

    // Owner-drawn children paint the same parent background at the same origin.
    // Alpha sprite edges therefore reveal the scene, rather than a button box.
    private static void PaintControlBackdrop(DrawItem item)
    {
        int savedDc = SaveDC(item.Dc);
        IntersectClipRect(item.Dc, item.Rect.Left, item.Rect.Top, item.Rect.Right, item.Rect.Bottom);
        try
        {
        GetClientRect(window, out var client);
        GetWindowRect(item.Window, out var control);
        MapWindowPoints(IntPtr.Zero, window, ref control, 2);
        PaintBackdrop(item.Dc, new Rect
        {
            Left = -control.Left, Top = -control.Top,
            Right = client.Right - control.Left, Bottom = client.Bottom - control.Top
        });
        }
        finally { RestoreDC(item.Dc, savedDc); }
    }

    private static void PaintPageLabel(DrawItem item)
    {
        PaintControlBackdrop(item);
        var control = pageControls.FirstOrDefault(c => c.Handle == item.Window);
        bool primary = control?.Emphasis == true;
        bool custom = primary || control?.FontSize > 0 || control?.Id is >= 610 and <= 615;
        int size = control?.FontSize > 0 ? control.FontSize : control?.Id is >= 610 and <= 615 ? 16 : 23;
        var font = custom ? UiFont(-FontPixels(size), primary ? 600 : 400, BodyFace) : pageFont;
        var previous = SelectObject(item.Dc, font);
        SetTextColor(item.Dc, HighContrast() ? GetSysColor(8) : control?.Ink ?? (primary ? 0xEAF2F6u : 0xC1B9B8u));
        SetBkMode(item.Dc, 1);
        var rect = item.Rect;
        try { DrawTextW(item.Dc, Text(item.Window), -1, ref rect, 0x10 | 0x800); }
        finally { SelectObject(item.Dc, previous); }
    }

    private static int PageLabelHeight(PageControl control, int width)
    {
        var dc = GetDC(window);
        bool custom = control.Emphasis || control.FontSize > 0;
        var font = custom ? UiFont(-FontPixels(control.FontSize > 0 ? control.FontSize : 23), control.Emphasis ? 600 : 400, BodyFace) : pageFont;
        var previous = SelectObject(dc, font);
        var measured = new Rect { Right = width };
        try { return DrawTextW(dc, Text(control.Handle), -1, ref measured, 0x400 | 0x10 | 0x800) + Px(2); }
        finally { SelectObject(dc, previous); ReleaseDC(window, dc); }
    }

    private static void PaintFieldFrames(IntPtr dc)
    {
        foreach (var c in pageControls.Where(c => c.Kind == "EDIT" || c.Kind == "LISTBOX" && c.Id != ProgramListId))
        {
            GetWindowRect(c.Handle, out var rect); MapWindowPoints(IntPtr.Zero, window, ref rect, 2);
            rect.Left -= 1; rect.Top -= 1; rect.Right += 1; rect.Bottom += 1;
            if (HighContrast()) Frame(dc, rect, GetSysColor(8));
            else if (c.Kind == "EDIT")
            {
                rect.Left -= Px(10); rect.Right += Px(10); rect.Top -= Px(8); rect.Bottom += Px(8);
                SoftSurface(dc, rect, 0x2B2320, 255, 12);
            }
        }
    }

    private static void RefreshPageFont()
    {
        int height = FontPixels(20);
        if (pageFont != IntPtr.Zero && height == pageFontHeight) return;
        var next = CreateFontW(-height, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, BodyFace);
        if (next == IntPtr.Zero) return;
        var previous = pageFont; pageFont = next; pageFontHeight = height;
        foreach (var control in pageControls) SendMessageW(control.Handle, 0x30, next, new IntPtr(1));
        if (previous != IntPtr.Zero) DeleteObject(previous);
    }

    private static Rect PageBounds(PageControl c)
    {
        if (page == 3 && c.Id is GeneralPreferencesId or GeneralWebId or DecisionServicesId)
        {
            int index = c.Id == GeneralPreferencesId ? 0 : c.Id == GeneralWebId ? 1 : 2;
            return CompactSurface ? Layout.C(650 + index * 115, 100, 105, 36)
                : Layout.R(1040 + index * 140, 235, 130, 42);
        }
        if (PermissionPage) return PermissionBounds(c);
        if (page == 2 && privacyTab == 1 && CompactSurface && c.Kind == "STATIC" && c.Y == 650) c = c with { Y = 665 };
        // General pages use a slightly tighter vertical rhythm so the last
        // login-state note cannot run into the fixed status/save footer.
        double compactY = page == 3 ? .60 : .70;
        return CompactSurface ? Layout.C(310 + (int)Math.Round((c.X - 650) * (650.0 / 790)),
            200 + (int)Math.Round((c.Y - 265) * compactY), (int)Math.Round(c.W * (650.0 / 790)), Math.Max(c.Kind == "STATIC" ? 24 : 26, (int)Math.Round(c.H * compactY)))
            : Layout.R(865 + (int)Math.Round((c.X - 650) * (590.0 / 790)), c.Y + 82, (int)Math.Round(c.W * (590.0 / 790)), c.H);
    }

    private static void WrappedText(IntPtr dc, string value, Rect rect, int size, uint color)
    {
        var font = UiFont(-Math.Max(Px(size), (int)Math.Round(10 * Math.Max(96, GetDpiForWindow(window)) / 96.0)), 400, BodyFace);
        var previous = SelectObject(dc, font); SetBkMode(dc, 1); SetTextColor(dc, HighContrast() ? GetSysColor(8) : color);
        try { DrawTextW(dc, value, -1, ref rect, 0x10 | 0x800); }
        finally { SelectObject(dc, previous); }
    }

    private static void Line(IntPtr dc, int x1, int y1, int x2, int y2, uint color, int width = 1)
    {
        var pen = CreatePen(0, Math.Max(1, Px(width)), color);
        var previous = SelectObject(dc, pen);
        try { MoveToEx(dc, x1, y1, IntPtr.Zero); LineTo(dc, x2, y2); }
        finally { SelectObject(dc, previous); DeleteObject(pen); }
    }

    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern int GetTextFaceW(IntPtr dc, int size, StringBuilder name);
    [DllImport("user32.dll")] private static extern int MapWindowPoints(IntPtr from, IntPtr to, ref Rect rect, uint count);
    [DllImport("gdi32.dll")] private static extern bool MoveToEx(IntPtr dc, int x, int y, IntPtr previous);
    [DllImport("gdi32.dll")] private static extern bool LineTo(IntPtr dc, int x, int y);
    [DllImport("gdi32.dll")] private static extern int SaveDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern bool RestoreDC(IntPtr dc, int saved);
    [DllImport("gdi32.dll")] private static extern int IntersectClipRect(IntPtr dc, int left, int top, int right, int bottom);
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, uint attribute, ref int value, int size);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("comctl32.dll")] private static extern bool SetWindowSubclass(IntPtr hwnd, SubclassProc procedure, UIntPtr id, UIntPtr data);
    [DllImport("comctl32.dll")] private static extern bool RemoveWindowSubclass(IntPtr hwnd, SubclassProc procedure, UIntPtr id);
    [DllImport("comctl32.dll")] private static extern IntPtr DefSubclassProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
}
