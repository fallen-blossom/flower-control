using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

// Only paints application-owned surfaces. Native HWND types, check state,
// focus, keyboard navigation and accessibility providers remain in charge.
internal sealed class PermissionVisual : IDisposable
{
    private delegate IntPtr Subclass(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data);
    [StructLayout(LayoutKind.Sequential)] private struct Paint
    {
        public IntPtr Dc; public int Erase; public Native.Rect Rect; public int Restore, Update;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Reserved;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Contrast { public uint Size, Flags; public IntPtr Scheme; }
    [StructLayout(LayoutKind.Sequential)] private struct DrawItemData
    { public uint Type, Id, Item, Action, State; public IntPtr Window, Dc; public Native.Rect Rect; public UIntPtr Data; }
    [StructLayout(LayoutKind.Sequential)] private struct MouseTracking
    { public uint Size, Flags; public IntPtr Window; public uint HoverTime; }
    [DllImport("user32.dll")] private static extern bool SystemParametersInfoW(uint action, uint param, ref Contrast value, uint flags);
    [DllImport("user32.dll")] private static extern uint GetSysColor(int index);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern IntPtr BeginPaint(IntPtr hwnd, out Paint paint);
    [DllImport("user32.dll")] private static extern bool EndPaint(IntPtr hwnd, ref Paint paint);
    [DllImport("user32.dll")] private static extern int FillRect(IntPtr dc, ref Native.Rect rect, IntPtr brush);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int DrawTextW(IntPtr dc, string text, int length, ref Native.Rect rect, uint format);
    [DllImport("user32.dll")] private static extern bool DrawFocusRect(IntPtr dc, ref Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetFocus();
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern uint GetWindowLongW(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool ScreenToClient(IntPtr hwnd, ref Native.Point point);
    [DllImport("user32.dll")] private static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("user32.dll")] private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);
    [DllImport("user32.dll")] private static extern bool TrackMouseEvent(ref MouseTracking tracking);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadImageW(IntPtr instance, IntPtr name, uint kind, int w, int h, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? module);
    [DllImport("user32.dll")] private static extern bool DrawIconEx(IntPtr dc, int x, int y, IntPtr icon, int w, int h, uint step, IntPtr brush, uint flags);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateSolidBrush(uint color);
    [DllImport("gdi32.dll")] private static extern IntPtr CreatePen(int style, int width, uint color);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern uint SetTextColor(IntPtr dc, uint color);
    [DllImport("gdi32.dll")] private static extern uint SetBkColor(IntPtr dc, uint color);
    [DllImport("gdi32.dll")] private static extern int SetBkMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll")] private static extern bool RoundRect(IntPtr dc, int left, int top, int right, int bottom, int ew, int eh);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateRoundRectRgn(int left, int top, int right, int bottom, int ew, int eh);
    [DllImport("gdi32.dll")] private static extern int SelectClipRgn(IntPtr dc, IntPtr region);
    [DllImport("gdi32.dll")] private static extern bool Ellipse(IntPtr dc, int left, int top, int right, int bottom);
    [DllImport("gdi32.dll")] private static extern bool Polygon(IntPtr dc, [In] Native.Point[] points, int count);
    [DllImport("gdi32.dll")] private static extern IntPtr GetStockObject(int index);
    [DllImport("gdi32.dll")] private static extern bool MoveToEx(IntPtr dc, int x, int y, IntPtr point);
    [DllImport("gdi32.dll")] private static extern bool LineTo(IntPtr dc, int x, int y);
    [DllImport("gdi32.dll")] private static extern int SaveDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern bool RestoreDC(IntPtr dc, int state);
    [DllImport("gdi32.dll")] private static extern int IntersectClipRect(IntPtr dc, int left, int top, int right, int bottom);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] private static extern int SetWindowTheme(IntPtr hwnd, string? app, string? id);
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    [StructLayout(LayoutKind.Sequential)] private struct ColorVertex { public int X, Y; public ushort Red, Green, Blue, Alpha; }
    [StructLayout(LayoutKind.Sequential)] private struct GradientRect { public uint UpperLeft, LowerRight; }
    [DllImport("msimg32.dll")] private static extern bool GradientFill(IntPtr dc, [In] ColorVertex[] vertex, uint count, [In] GradientRect[] mesh, uint meshCount, uint mode);
    [DllImport("comctl32.dll")] private static extern bool SetWindowSubclass(IntPtr hwnd, Subclass proc, UIntPtr id, UIntPtr data);
    [DllImport("comctl32.dll")] private static extern bool RemoveWindowSubclass(IntPtr hwnd, Subclass proc, UIntPtr id);
    [DllImport("comctl32.dll")] private static extern IntPtr DefSubclassProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    private readonly Subclass procedure;
    private readonly record struct ButtonStyle(bool Check, bool Primary, bool Combo, int Navigation, bool OnCard);
    private readonly Dictionary<IntPtr, ButtonStyle> buttons = [];
    private readonly HashSet<IntPtr> hovering = [];
    private readonly HashSet<IntPtr> fields = [];
    private readonly List<IntPtr> nativeControls = [];
    private IntPtr backgroundBrush, cardBrush, inputBrush, panelBrush;
    private SettingsArtwork? artwork;
    private int artworkTier = -1;
    private uint background, panel, card, input, text, muted, edge, accent, primary, danger, warning, trackOff;
    private int selectedNavigation = 1;
    private readonly bool settingsSurface;
    private readonly Action<int, uint>? inputObserved;
    private (int Top, int Height)[]? settingsSections;
    private (int Top, int Height)[]? settingsBanners, settingsHeroes;
    private (int Left, int Top, int Width, int Height)[]? settingsChips;
    private (int Top, int Left, int Right)[]? settingsSeparators;
    private bool chipAdmin, chipUac, chipOrdinary = true, chipUacRequested;
    private bool compactSettingsNavigation;
    internal void SetSettingsLayout((int Top, int Height)[] sections, (int Top, int Height)[] banners, (int Top, int Height)[] heroes,
        (int Left, int Top, int Width, int Height)[] chips, (int Top, int Left, int Right)[] separators, bool compact)
    { if (settingsSurface) { settingsSections = sections; settingsBanners = banners; settingsHeroes = heroes; settingsChips = chips;
        settingsSeparators = separators; compactSettingsNavigation = compact; } }
    internal void SetChipStates(bool admin, bool uac, bool ordinary = true, bool uacRequested = false)
    { chipAdmin = admin; chipUac = uac; chipOrdinary = ordinary; chipUacRequested = uacRequested; }
    internal void ThemeBody(IntPtr hwnd)
    {
        // The body owns a native scrollbar; theming only the child controls
        // left a bright default bar on the right edge. Target the ScrollBar
        // sub-application and opt the non-client area into dark mode.
        SetWindowTheme(hwnd, HighContrast ? null : "DarkMode_Explorer", null);
        var parent = GetParent(hwnd);
        if (parent != IntPtr.Zero) SetWindowTheme(parent, HighContrast ? null : "DarkMode_Explorer", null);
        try { int dark = HighContrast ? 0 : 1; DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int)); }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { }
    }
    internal bool HighContrast { get; private set; }
    internal PermissionVisual(bool settingsSurface = false, Action<int, uint>? inputObserved = null)
    { this.settingsSurface = settingsSurface; this.inputObserved = inputObserved; procedure = ButtonProcedure; Reload(IntPtr.Zero); }
    private static uint Rgb(int r, int g, int b) => (uint)(r | g << 8 | b << 16);
    internal void Reload(IntPtr window)
    {
        var contrast = new Contrast { Size = (uint)Marshal.SizeOf<Contrast>() };
        HighContrast = SystemParametersInfoW(0x42, contrast.Size, ref contrast, 0) && (contrast.Flags & 1) != 0;
        // VISUAL_STYLE.md roles: deep-space base, glass card, muted ink and
        // the #5E6AD2 accent. SYSTEM warnings keep the danger red because
        // they are the most dangerous switch in the window.
        background = HighContrast ? GetSysColor(5) : Rgb(7, 7, 10);
        panel = HighContrast ? GetSysColor(5) : Rgb(10, 10, 14);
        card = HighContrast ? GetSysColor(5) : Rgb(20, 20, 25);
        input = HighContrast ? GetSysColor(5) : Rgb(11, 11, 15);
        text = HighContrast ? GetSysColor(8) : Rgb(237, 237, 239);
        muted = HighContrast ? GetSysColor(8) : Rgb(138, 143, 152);
        // The prototype border is rgba(255,255,255,.09); 44,44,52 read as a
        // bright wireframe around every card. Keep the hairline, drop the glare.
        edge = HighContrast ? GetSysColor(8) : Rgb(30, 30, 35);
        accent = HighContrast ? GetSysColor(13) : Rgb(148, 156, 240);
        primary = HighContrast ? GetSysColor(13) : Rgb(94, 106, 210);
        danger = HighContrast ? GetSysColor(8) : Rgb(255, 93, 122);
        warning = HighContrast ? GetSysColor(8) : Rgb(255, 180, 84);
        // Off track in the prototype is a translucent light rail, not a hole.
        trackOff = HighContrast ? GetSysColor(8) : Rgb(38, 38, 44);
        // Fixed user artwork is an optional material layer. It is never loaded
        // in high contrast and never required for the window to open.
        if (settingsSurface && !HighContrast) artwork ??= SettingsArtwork.TryCreate();
        if (!settingsSurface && !HighContrast)
        {
            background = Rgb(17, 20, 33); card = Rgb(24, 29, 46); input = Rgb(15, 19, 32);
            panel = Rgb(18, 22, 36); text = Rgb(236, 240, 252); muted = Rgb(168, 178, 204); edge = Rgb(56, 65, 91);
            warning = Rgb(255, 180, 84); trackOff = Rgb(48, 55, 78);
            accent = Rgb(142, 153, 247); primary = Rgb(84, 94, 178);
        }
        DisposeBrushes();
        backgroundBrush = CreateSolidBrush(background); panelBrush = CreateSolidBrush(panel);
        cardBrush = CreateSolidBrush(card); inputBrush = CreateSolidBrush(input);
        if (backgroundBrush == IntPtr.Zero || panelBrush == IntPtr.Zero || cardBrush == IntPtr.Zero || inputBrush == IntPtr.Zero)
            throw new Boundary("permission_brush_failed");
        if (window != IntPtr.Zero)
        {
            try { int dark = HighContrast ? 0 : 1; DwmSetWindowAttribute(window, 20, ref dark, sizeof(int)); }
            catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException) { }
            double dpiScale = Math.Max(1, GetDpiForWindow(window) / 96.0);
            foreach (var item in new[] { (0, 16), (1, 32) })
            {
                int size = (int)Math.Round(item.Item2 * dpiScale);
                var icon = LoadImageW(GetModuleHandleW(null), new IntPtr(32512), 1, size, size, 0x8000);
                if (icon != IntPtr.Zero) SendMessageW(window, 0x80, new IntPtr(item.Item1), icon);
            }
        }
        foreach (var control in nativeControls) Theme(control);
    }
    internal void Attach(IntPtr hwnd, string kind, uint style, int id, bool onCard = false)
    {
        nativeControls.Add(hwnd); Theme(hwnd);
        if (kind is "EDIT" or "LISTBOX") fields.Add(hwnd);
        if (kind is "BUTTON" or "COMBOBOX")
        {
            buttons[hwnd] = new(kind == "BUTTON" && (style & 15) == 3,
                id == 30 || settingsSurface && id is 62 or 162 or 95 or 96,
                kind == "COMBOBOX", id is >= 300 and <= 305 ? id - 300 : -1, onCard);
            if (!SetWindowSubclass(hwnd, procedure, new UIntPtr(41), UIntPtr.Zero))
                throw new Boundary("permission_button_theme_failed");
        }
    }
    internal void SelectPage(int page)
    {
        selectedNavigation = page;
        foreach (var button in buttons.Where(item => item.Value.Navigation >= 0)) InvalidateRect(button.Key, IntPtr.Zero, false);
    }
    private void Theme(IntPtr hwnd) => SetWindowTheme(hwnd, HighContrast ? null : "DarkMode_Explorer", null);
    internal IntPtr ControlColor(IntPtr dc, uint message, bool body, int id, IntPtr control = default)
    {
        // Read-only and disabled EDIT controls send WM_CTLCOLORSTATIC too.
        // Their client fill must still match the surrounding input frame.
        var editable = fields.Contains(control) || message is 0x133 or 0x134;
        // Hero text, status chips and warning banners sit on artwork that the
        // surface already painted; giving them a card brush would punch opaque
        // rectangles through the gradient.
        bool onArtwork = settingsSurface && body && id is 3000 or 3001 or 3002 or 3003 or 3004 or 3020 or 3030 or 3040;
        if (onArtwork)
        {
            SetBkMode(dc, 1);
            // The danger banner must read as danger, not as muted helper text.
            SetTextColor(dc, id == 3040 ? danger : id == 3001 ? muted : text);
            return GetStockObject(5);
        }
        uint color = editable ? input : body ? card : background;
        // SYSTEM references are the most dangerous switch in the window; the
        // style contract keeps them red instead of the muted helper ink.
        bool systemWarning = settingsSurface && !HighContrast && body && id is 79 or 2210;
        SetBkColor(dc, color);
        bool overviewMuted = id is 3001 or 3012 or 3014 or 3022;
        SetTextColor(dc, systemWarning ? danger : id == 40 || id is >= 2000 and < 3000 || overviewMuted ? muted : text);
        SetBkMode(dc, 1);
        return editable ? inputBrush : body ? cardBrush : backgroundBrush;
    }
    internal readonly record struct FieldFrame(IntPtr Handle, Native.Rect Bounds);
    internal IEnumerable<FieldFrame> FieldFrames(IntPtr viewport)
    {
        if (!GetClientRect(viewport, out var client)) yield break;
        foreach (var field in fields)
        {
            // All page fields belong to the same body HWND. Parent identity
            // alone does not make a hidden page's field part of this surface.
            // Inspect this HWND's visible style so hidden synthetic probes
            // exercise the same page filtering without displaying the root.
            if (GetParent(field) != viewport || (GetWindowLongW(field, -16) & 0x10000000) == 0
                || !GetWindowRect(field, out var area)) continue;
            var point = new Native.Point { X = area.Left, Y = area.Top };
            if (!ScreenToClient(viewport, ref point)) continue;
            var bounds = new Native.Rect { Left = point.X - 1, Top = point.Y - 1,
                Right = point.X + area.Right - area.Left + 1, Bottom = point.Y + area.Bottom - area.Top + 1 };
            if (bounds.Left >= client.Right || bounds.Right <= 0 || bounds.Top >= client.Bottom || bounds.Bottom <= 0) continue;
            yield return new(field, bounds);
        }
    }
    internal static (int Top, int Height)[] SectionBounds(int page) => page switch {
        0 => [(0, 82), (90, 82), (180, 76), (264, 112)],
        1 => [(0, 116), (136, 108), (260, 108), (392, 92)],
        2 => [(0, 84), (100, 88), (196, 444), (644, 60)],
        3 => [(0, 84), (100, 140), (248, 88), (348, 480)],
        4 => [(0, 232), (252, 414)],
        _ => [(0, 178), (196, 138), (348, 140), (500, 140)],
    };
    // Human handoff uses the original compact surface, independently of the
    // settings navigation. Its layout and default-button path stay unchanged.
    internal void PaintSurface(IntPtr hwnd, bool body, int scroll, double scale, int footerHeight)
        => PaintSurface(hwnd, body, -1, scroll, scale, footerHeight);
    internal void PaintSurface(IntPtr hwnd, bool body, int page, int scroll, double scale, int footerHeight, IntPtr externalDc = default)
    {
        Paint paint = default;
        var dc = externalDc == IntPtr.Zero ? BeginPaint(hwnd, out paint) : externalDc;
        try
        {
            if (!GetClientRect(hwnd, out var rect)) return;
            FillRect(dc, ref rect, backgroundBrush);
            int Px(int value) => (int)Math.Round(value * scale);
            if (settingsSurface && !HighContrast && artwork is not null)
            {
                // Background sits under every card and is dimmed by its own
                // alpha, so ordinary ink stays readable on the darkest base.
                artwork.DrawBackground(dc, rect, 0.55f);
            }
            if (body)
            {
                int state = SaveDC(dc);
                if (state == 0) throw new Boundary("permission_surface_clip_failed");
                try
                {
                    IntersectClipRect(dc, rect.Left, rect.Top, rect.Right, rect.Bottom);
                    foreach (var section in settingsSurface && settingsSections is not null ? settingsSections : SectionBounds(page))
                        Shape(dc, Px(4), Px(section.Item1) - scroll, rect.Right - Px(4), Px(section.Item1 + section.Item2) - scroll, Px(14), card, edge);
                    if (settingsSurface && settingsHeroes is not null)
                        foreach (var hero in settingsHeroes) PaintHero(dc, rect.Right, Px(hero.Item1) - scroll, Px(hero.Item2), Px);
                    if (settingsSurface && settingsChips is not null)
                    {
                        for (int index = 0; index < settingsChips.Length; index++)
                        {
                            var chip = settingsChips[index];
                            Shape(dc, Px(chip.Item1), Px(chip.Item2) - scroll, Px(chip.Item1 + chip.Item3), Px(chip.Item2 + chip.Item4) - scroll, Px(14), card, edge);
                            // The prototype's status dot is the at-a-glance state;
                            // text alone made all three chips read the same.
                            uint dot = index == 0 ? (chipOrdinary ? Rgb(75, 208, 127) : muted)
                                : index == 1 ? (chipAdmin ? Rgb(75, 208, 127) : muted)
                                : (chipUac ? Rgb(75, 208, 127) : chipUacRequested ? warning : muted);
                            int cx = Px(chip.Item1 + 14), cy = Px(chip.Item2 + chip.Item4 / 2);
                            var dotBrush = CreateSolidBrush(dot); var dotPen = CreatePen(0, 1, dot);
                            var oldDotBrush = SelectObject(dc, dotBrush); var oldDotPen = SelectObject(dc, dotPen);
                            try { Ellipse(dc, cx - Px(4), cy - Px(4), cx + Px(4), cy + Px(4)); }
                            finally { SelectObject(dc, oldDotBrush); SelectObject(dc, oldDotPen); DeleteObject(dotBrush); DeleteObject(dotPen); }
                        }
                    }
                    if (settingsSurface && settingsBanners is not null)
                        foreach (var banner in settingsBanners)
                        {
                            int top = Px(banner.Item1) - scroll, bottom = top + Px(banner.Item2);
                            bool system = page == 3;   // the UAC page is the SYSTEM surface
                            uint tint = system ? danger : Rgb(255, 180, 84);
                            Shape(dc, Px(4), top + Px(10), rect.Right - Px(4), bottom - Px(10), Px(14),
                                Mix(card, tint, 0.12) , Mix(edge, tint, 0.45));
                            PaintWarning(dc, Px(20), top + Px(24), Px(18), tint);
                        }
                    if (settingsSurface && settingsSeparators is not null)
                    {
                        var separator = CreateSolidBrush(edge);
                        try
                        {
                            foreach (var line in settingsSeparators)
                            {
                                var row = new Native.Rect { Left = Px(line.Left), Top = Px(line.Top) - scroll,
                                    Right = Px(line.Right), Bottom = Px(line.Top) - scroll + 1 };
                                FillRect(dc, ref row, separator);
                            }
                        }
                        finally { DeleteObject(separator); }
                    }
                    foreach (var frame in FieldFrames(hwnd))
                        Shape(dc, frame.Bounds.Left, frame.Bounds.Top, frame.Bounds.Right, frame.Bounds.Bottom, Px(5), input, edge);
                }
                finally { RestoreDC(dc, state); }
            }
            else
            {
                // The rail and footer are a slightly lighter panel in the
                // prototype. Without this split the window reads as one flat
                // sheet with boxes drawn on top, which is the "wireframe" look.
                if (settingsSurface)
                {
                    int footerTop = rect.Bottom - footerHeight;
                    if (!compactSettingsNavigation)
                    {
                        var rail = new Native.Rect { Left = 0, Top = 0, Right = Px(207), Bottom = footerTop };
                        FillRect(dc, ref rail, panelBrush);
                    }
                    var footer = new Native.Rect { Left = 0, Top = footerTop, Right = rect.Right, Bottom = rect.Bottom };
                    FillRect(dc, ref footer, panelBrush);
                    // The flower is part of the rail, so it must be painted
                    // after the opaque rail fill rather than underneath it.
                    if (!HighContrast && artwork is not null && artwork.HasFlower)
                    {
                        int railRight = compactSettingsNavigation ? Px(24) : Px(200);
                        int side = Math.Min(railRight - Px(16), Math.Max(Px(80), footerTop - Px(120)));
                        int left = Px(8), top = footerTop - side - Px(10);
                        if (side >= Px(80) && top > Px(56))
                            artwork.DrawFlower(dc, new Native.Rect { Left = left, Top = top,
                                Right = left + side, Bottom = top + side }, artworkTier);
                    }
                }
                int iconSize = settingsSurface ? 32 : 52;
                var icon = LoadImageW(GetModuleHandleW(null), new IntPtr(32512), 1, Px(iconSize), Px(iconSize), 0x8000);
                if (icon != IntPtr.Zero) DrawIconEx(dc, Px(24), Px(settingsSurface ? 24 : 25), icon, Px(iconSize), Px(iconSize), 0, IntPtr.Zero, 3);
                var stripe = settingsSurface
                    ? new Native.Rect { Left = Px(207), Top = Px(88), Right = Px(208), Bottom = rect.Bottom - footerHeight }
                    : new Native.Rect { Left = Px(24), Top = Px(94), Right = rect.Right - Px(24), Bottom = Px(96) };
                var line = CreateSolidBrush(edge); try { if (!settingsSurface || !compactSettingsNavigation) FillRect(dc, ref stripe, line); } finally { DeleteObject(line); }
                if (settingsSurface) { stripe.Left = 0; stripe.Right = rect.Right; }
                stripe.Top = rect.Bottom - footerHeight; stripe.Bottom = stripe.Top + 1;
                line = CreateSolidBrush(edge); try { FillRect(dc, ref stripe, line); } finally { DeleteObject(line); }
            }
        }
        finally { if (externalDc == IntPtr.Zero) EndPaint(hwnd, ref paint); }
    }
    internal bool DrawItem(IntPtr value)
    {
        var item = Marshal.PtrToStructure<DrawItemData>(value);
        if (item.Type != 4 || !buttons.TryGetValue(item.Window, out var style)) return false;
        PaintButton(item.Dc, item.Window, style, item.State);
        return true;
    }
    private static void Shape(IntPtr dc, int left, int top, int right, int bottom, int radius, uint fill, uint border)
    {
        var brush = CreateSolidBrush(fill); var pen = CreatePen(0, 1, border);
        var oldBrush = SelectObject(dc, brush); var oldPen = SelectObject(dc, pen);
        try { RoundRect(dc, left, top, right, bottom, radius, radius); }
        finally { SelectObject(dc, oldBrush); SelectObject(dc, oldPen); DeleteObject(brush); DeleteObject(pen); }
    }
    private static uint Mix(uint background, uint accent, double amount)
    {
        int Blend(int low, int high) => (int)Math.Round(low * (1 - amount) + high * amount);
        return (uint)(Blend((int)(background & 0xff), (int)(accent & 0xff))
            | Blend((int)((background >> 8) & 0xff), (int)((accent >> 8) & 0xff)) << 8
            | Blend((int)((background >> 16) & 0xff), (int)((accent >> 16) & 0xff)) << 16);
    }
    private void PaintHero(IntPtr dc, int right, int top, int height, Func<int, int> px)
    {
        int left = px(4), edgeRight = right - px(4), radius = px(14);
        // The prototype hero is a card with two soft colour glows, not a solid
        // purple banner. Blend into the card colour so the surface stays glassy.
        uint start = Mix(card, accent, 0.38), end = Mix(card, Rgb(176, 107, 255), 0.12);
        var vertices = new[]
        {
            new ColorVertex { X = left, Y = top, Red = (ushort)((start & 0xff) * 257),
                Green = (ushort)(((start >> 8) & 0xff) * 257), Blue = (ushort)(((start >> 16) & 0xff) * 257), Alpha = 0xffff },
            new ColorVertex { X = edgeRight, Y = top + height, Red = (ushort)((end & 0xff) * 257),
                Green = (ushort)(((end >> 8) & 0xff) * 257), Blue = (ushort)(((end >> 16) & 0xff) * 257), Alpha = 0xffff },
        };
        var mesh = new[] { new GradientRect { UpperLeft = 0, LowerRight = 1 } };
        var region = CreateRoundRectRgn(left, top, edgeRight, top + height, radius, radius);
        int saved = SaveDC(dc);
        try { SelectClipRgn(dc, region); GradientFill(dc, vertices, 2, mesh, 1, 0); }
        finally { RestoreDC(dc, saved); DeleteObject(region); }
        var outline = CreatePen(0, 1, Mix(edge, accent, 0.25));
        var oldBrush = SelectObject(dc, GetStockObject(5)); var oldPen = SelectObject(dc, outline);
        try { RoundRect(dc, left, top, edgeRight, top + height, radius, radius); }
        finally { SelectObject(dc, oldBrush); SelectObject(dc, oldPen); DeleteObject(outline); }
    }
    private static void PaintWarning(IntPtr dc, int x, int y, int size, uint color)
    {
        var brush = CreateSolidBrush(color); var pen = CreatePen(0, Math.Max(2, size / 9), color);
        var oldBrush = SelectObject(dc, brush); var oldPen = SelectObject(dc, pen);
        try
        {
            var points = new[]
            {
                new Native.Point { X = x + size / 2, Y = y },
                new Native.Point { X = x + size, Y = y + size },
                new Native.Point { X = x, Y = y + size },
            };
            Polygon(dc, points, 3);
        }
        finally { SelectObject(dc, oldBrush); SelectObject(dc, oldPen); DeleteObject(brush); DeleteObject(pen); }
    }
    private IntPtr ButtonProcedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        try
        {
            if (settingsSurface && message is 0x201 or 0x202 or 0x100 or 0x101)
                inputObserved?.Invoke(GetDlgCtrlID(hwnd), message);
            if (message == 0x82)
            { buttons.Remove(hwnd); hovering.Remove(hwnd); nativeControls.Remove(hwnd); RemoveWindowSubclass(hwnd, procedure, id); return DefSubclassProc(hwnd, message, wp, lp); }
            if (message == 0xF4 && settingsSurface && buttons.TryGetValue(hwnd, out var button) && !button.Check && !button.Combo)
                // IsDialogMessage sends BM_SETSTYLE when moving the default
                // button. Retain BS_OWNERDRAW so that path cannot paint a
                // native white button over the application surface.
                return DefSubclassProc(hwnd, message, new UIntPtr((wp.ToUInt64() & ~15ul) | 11), lp);
            if (message == 0x200 && settingsSurface && hovering.Add(hwnd))
            {
                var tracking = new MouseTracking { Size = (uint)Marshal.SizeOf<MouseTracking>(), Flags = 2, Window = hwnd };
                TrackMouseEvent(ref tracking); InvalidateRect(hwnd, IntPtr.Zero, false);
            }
            if (message == 0x2a3 && hovering.Remove(hwnd)) InvalidateRect(hwnd, IntPtr.Zero, false);
            if (message == 0x14 && !HighContrast) return new IntPtr(1);
            if (message == 0x318 && (!HighContrast || settingsSurface) && buttons.TryGetValue(hwnd, out var printStyle))
            { PaintButton(new IntPtr(unchecked((long)wp.ToUInt64())), hwnd, printStyle, 0); return IntPtr.Zero; }
            if (message == 0xF && buttons.TryGetValue(hwnd, out var style) && (!HighContrast || settingsSurface && !style.Check && !style.Combo))
            {
                var dc = BeginPaint(hwnd, out var paint);
                try { PaintButton(dc, hwnd, style, 0); }
                finally { EndPaint(hwnd, ref paint); }
                return IntPtr.Zero;
            }
            var result = DefSubclassProc(hwnd, message, wp, lp);
            if (message is 7 or 8 or 0xF1 or 0x201 or 0x202 or 0x100 or 0x101 or 0x128)
                InvalidateRect(hwnd, IntPtr.Zero, false);
            return result;
        }
        catch (Exception) { Console.Error.WriteLine("permission_control_paint_failed"); return DefSubclassProc(hwnd, message, wp, lp); }
    }
    private void PaintButton(IntPtr dc, IntPtr hwnd, ButtonStyle style, uint ownerState = 0)
    {
        bool checkbox = style.Check, isPrimary = style.Primary, combo = style.Combo;
        int navigation = style.Navigation, controlId = GetDlgCtrlID(hwnd);
        bool systemRisk = settingsSurface && controlId == 79;
        GetClientRect(hwnd, out var rect); var enabled = IsWindowEnabled(hwnd);
        bool pressed = (SendMessageW(hwnd, 0xF2, IntPtr.Zero, IntPtr.Zero).ToInt64() & 4) != 0 || (ownerState & 1) != 0;
        bool hot = hovering.Contains(hwnd), selectedNavigationItem = navigation == selectedNavigation && navigation >= 0;
        var label = new StringBuilder(256); GetWindowTextW(hwnd, label, label.Capacity);
        int size = settingsSurface ? Math.Max(12, (int)Math.Round(GetDpiForWindow(hwnd) / 96.0 * 20)) : Math.Max(12, (int)Math.Round(rect.Bottom * .64));
        uint fill = combo ? input : isPrimary && (enabled || !settingsSurface) ? primary : card;
        if (navigation >= 0) fill = selectedNavigationItem ? Mix(panel, accent, 0.18) : hot ? card : panel;
        else if (hot && enabled && !isPrimary && !checkbox) fill = edge;
        if (pressed) fill = input;
        // Owner-draw buttons cannot inherit the parent card fill. Page buttons
        // sit on a card; navigation and footer buttons sit on the panel. Filling
        // every button with the root background leaves dark corner wedges.
        bool onPanel = settingsSurface && (controlId is >= 300 and <= 305 || controlId is 30 or 31 or 32 or 91 or 94);
        FillRect(dc, ref rect, style.OnCard ? cardBrush : onPanel ? panelBrush : backgroundBrush);
        var textRect = rect;
        if (checkbox)
        {
            int top = (rect.Bottom - size) / 2;
            bool selected = SendMessageW(hwnd, 0xF0, IntPtr.Zero, IntPtr.Zero).ToInt64() == 1;
            if (settingsSurface)
            {
                // Painting does not replace BS_AUTOCHECKBOX. UIA ToggleState,
                // Space, mnemonics and BM_GETCHECK remain the native contract.
                int trackW = size * 2, right = rect.Right - size / 3, left = right - trackW;
                uint onColour = systemRisk ? danger : primary;
                Shape(dc, left, top, right, top + size, size, selected && enabled ? onColour : hot && enabled ? edge : trackOff, selected && enabled ? (systemRisk ? danger : accent) : edge);
                int dot = size - 6, dotX = selected ? right - dot - 3 : left + 3;
                Shape(dc, dotX, top + 3, dotX + dot, top + 3 + dot, dot, enabled ? text : muted, enabled ? text : muted);
                textRect.Left = 2; textRect.Right = left - size;
            }
            else
            {
            Shape(dc, 1, top, size + 1, top + size, Math.Max(3, size / 4), selected && enabled ? primary : trackOff, selected && enabled ? accent : edge);
            if (selected)
            {
                var pen = CreatePen(0, Math.Max(2, size / 9), enabled ? text : muted); var old = SelectObject(dc, pen);
                try { MoveToEx(dc, size / 4, top + size / 2, IntPtr.Zero); LineTo(dc, size * 5 / 12, top + size * 3 / 4); LineTo(dc, size * 4 / 5, top + size / 4); }
                finally { SelectObject(dc, old); DeleteObject(pen); }
            }
            textRect.Left = size + Math.Max(8, size * 2 / 3);
            }
        }
        else if (navigation >= 0)
        {
            Shape(dc, 0, 0, rect.Right, rect.Bottom, 8, fill, fill);
            textRect.Left = Math.Max(16, rect.Bottom * 2 / 5);
            if (selectedNavigationItem)
            {
                var indicator = new Native.Rect { Left = 0, Top = rect.Bottom / 4, Right = Math.Max(3, rect.Bottom / 14), Bottom = rect.Bottom * 3 / 4 };
                var brush = CreateSolidBrush(accent); try { FillRect(dc, ref indicator, brush); } finally { DeleteObject(brush); }
            }
        }
        else
        {
            bool risk = settingsSurface && controlId is 32 or 68 or 98;
            uint border = risk && enabled && !HighContrast ? danger : isPrimary && (enabled || !settingsSurface) ? primary : edge;
            Shape(dc, 0, 0, rect.Right, rect.Bottom, settingsSurface ? 8 : 10, fill, border);
        }
        if (combo)
        {
            textRect.Left = Math.Max(8, rect.Bottom / 4); textRect.Right -= rect.Bottom;
            var pen = CreatePen(0, Math.Max(2, rect.Bottom / 18), muted); var old = SelectObject(dc, pen);
            int center = rect.Right - rect.Bottom / 2, y = rect.Bottom / 2;
            try { MoveToEx(dc, center - 5, y - 2, IntPtr.Zero); LineTo(dc, center, y + 3); LineTo(dc, center + 5, y - 2); }
            finally { SelectObject(dc, old); DeleteObject(pen); }
        }
        var oldFont = SelectObject(dc, SendMessageW(hwnd, 0x31, IntPtr.Zero, IntPtr.Zero));
        try
        {
            uint labelColor = enabled && (navigation < 0 || selectedNavigationItem || hot) ? text : muted;
            if (systemRisk && enabled) labelColor = danger;
            if (HighContrast && isPrimary && enabled) labelColor = GetSysColor(14);
            if (HighContrast && !enabled) labelColor = GetSysColor(17);
            SetBkMode(dc, 1); SetTextColor(dc, labelColor);
            long cues = SendMessageW(hwnd, 0x129, IntPtr.Zero, IntPtr.Zero).ToInt64();
            uint align = checkbox || combo || navigation >= 0 ? 0u : 1u;
            uint hidePrefix = (cues & 2) != 0 ? 0x100000u : 0u;
            if (settingsSurface && !combo && navigation < 0)
            {
                textRect.Left += checkbox ? 0 : 10; textRect.Right -= checkbox ? 0 : 10;
                var measured = textRect;
                DrawTextW(dc, label.ToString(), label.Length, ref measured, 0x400 | 0x10 | align | hidePrefix);
                textRect.Top = Math.Max(2, (rect.Bottom - (measured.Bottom - measured.Top)) / 2);
                DrawTextW(dc, label.ToString(), label.Length, ref textRect, 0x10 | align | hidePrefix);
            }
            else DrawTextW(dc, label.ToString(), label.Length, ref textRect, 0x20 | 4 | align | hidePrefix);
            if ((GetFocus() == hwnd || (ownerState & 0x10) != 0) && (cues & 1) == 0)
            { var focus = new Native.Rect { Left = checkbox && !settingsSurface ? textRect.Left - 3 : 3, Top = 3, Right = rect.Right - 4, Bottom = rect.Bottom - 3 }; DrawFocusRect(dc, ref focus); }
        }
        finally { SelectObject(dc, oldFont); }
    }
    private void DisposeBrushes()
    {
        if (backgroundBrush != IntPtr.Zero) DeleteObject(backgroundBrush);
        if (panelBrush != IntPtr.Zero) DeleteObject(panelBrush);
        if (cardBrush != IntPtr.Zero) DeleteObject(cardBrush);
        if (inputBrush != IntPtr.Zero) DeleteObject(inputBrush);
        backgroundBrush = panelBrush = cardBrush = inputBrush = IntPtr.Zero;
    }
    internal void SetTier(int tier) => artworkTier = tier;
    internal string ArtworkState => artwork is null ? "unavailable"
        : artwork.HasFlower ? (artwork.Background is null ? "flower_without_background" : "complete")
        : artwork.Background is null ? "empty" : "background_only";
    public void Dispose() { DisposeBrushes(); artwork?.Dispose(); artwork = null; buttons.Clear(); hovering.Clear(); nativeControls.Clear(); fields.Clear(); }
}
