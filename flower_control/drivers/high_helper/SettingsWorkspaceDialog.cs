using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private sealed class AppDialog
    {
        internal IntPtr Window, Body, Font;
        internal required string Title;
        internal int Result, Default, Cancel;
        internal double DpiScale;
        internal readonly List<int> Buttons = [];
        internal EditorField[]? Fields;
        internal Func<AppDialog, bool>? Submit;
    }
    private sealed record EditorField(int Id, string Label, string Value, bool Secret = false, bool ReadOnly = false, string[]? Choices = null);
    private static AppDialog? appDialog;
    private static bool dialogClassRegistered;
    private static readonly WndProc DialogProcedure = AppDialogMessage;

    // Application-owned confirmation/details only. File picker, secure desktop
    // and OS permission surfaces stay native. Keep the existing IDYES/IDNO/
    // IDCANCEL contract and the caller's actual authority checks unchanged.
    private static int MessageBoxW(IntPtr owner, string text, string title, uint type,
        EditorField[]? fields = null, Func<AppDialog, bool>? submit = null)
    {
        if (HighContrast() && fields is null) return NativeMessageBox(owner, text, title, type);
        if (appDialog is not null) return 2;
        if (!dialogClassRegistered)
        {
            var cls = new WindowClass { Size = (uint)Marshal.SizeOf<WindowClass>(),
                Proc = Marshal.GetFunctionPointerForDelegate(DialogProcedure), Instance = instance,
                Name = "Flower.SettingsDialog" };
            if (RegisterClassExW(ref cls) == 0) throw new Boundary("settings_dialog_unavailable");
            dialogClassRegistered = true;
        }
        var dialog = new AppDialog { Title = title, DpiScale = Math.Max(96, GetDpiForWindow(owner)) / 96.0, Fields = fields, Submit = submit };
        int mode = (int)(type & 15);
        if (mode == 3) { dialog.Buttons.AddRange([6, 7, 2]); dialog.Cancel = 2; }
        else if (mode == 4) { dialog.Buttons.AddRange([6, 7]); dialog.Cancel = 7; }
        else { dialog.Buttons.Add(1); dialog.Cancel = 1; }
        dialog.Default = dialog.Buttons[Math.Clamp((int)(type >> 8) & 3, 0, dialog.Buttons.Count - 1)];
        appDialog = dialog;
        IntPtr priorFocus = GetFocus(); bool enabledOwner = IsWindowEnabled(owner); bool quit = false;
        try
        {
            int D(int value) => (int)Math.Round(value * dialog.DpiScale);
            GetWindowRect(owner, out var parent);
            var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
            GetMonitorInfoW(MonitorFromWindow(owner, 2), ref monitor);
            int width = Math.Min(D(620), monitor.Work.Right - monitor.Work.Left - D(32));
            int lines = text.Split('\n').Sum(line => Math.Max(1, (int)Math.Ceiling(line.Length / 42.0)));
            int height = Math.Min(D(fields is null ? Math.Clamp(200 + lines * 23, 320, 570) : 230 + fields.Length * 58), monitor.Work.Bottom - monitor.Work.Top - D(40));
            int x = Math.Clamp(parent.Left + (parent.Right - parent.Left - width) / 2, monitor.Work.Left, monitor.Work.Right - width);
            int y = Math.Clamp(parent.Top + (parent.Bottom - parent.Top - height) / 2, monitor.Work.Top, monitor.Work.Bottom - height);
            dialog.Window = CreateWindowExW(0x10001, "Flower.SettingsDialog", title, 0x00C80000 | 0x02000000,
                x, y, width, height, owner, IntPtr.Zero, instance, IntPtr.Zero);
            if (dialog.Window == IntPtr.Zero) throw new Boundary("settings_dialog_unavailable");
            SetPropW(dialog.Window, "FlowerControlTaskIndicator", new IntPtr(1));
            int dark = 1, caption = 0x211624, ink = 0xF4E8FA;
            DwmSetWindowAttribute(dialog.Window, 20, ref dark, 4);
            DwmSetWindowAttribute(dialog.Window, 35, ref caption, 4);
            DwmSetWindowAttribute(dialog.Window, 36, ref ink, 4);
            ApplyDialogIcons(dialog);
            GetClientRect(dialog.Window, out var client);
            dialog.Font = CreateFontW(-D(17), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, BodyFace);
            dialog.Body = CreateWindowExW(0, "EDIT", text, 0x50010000 | 0x200000 | 4 | 0x40 | 0x800,
                D(28), D(76), client.Right - D(56), fields is null ? client.Bottom - D(164) : D(65), dialog.Window, new IntPtr(1001), instance, IntPtr.Zero);
            if (dialog.Body == IntPtr.Zero) throw new Boundary("settings_dialog_unavailable");
            SendMessageW(dialog.Body, 0xC5, new IntPtr(1000000), IntPtr.Zero);
            SetWindowTheme(dialog.Body, HighContrast() ? "" : "DarkMode_CFD", "");
            SetWindowSubclass(dialog.Body, ScrollThemeProcedure, new UIntPtr(2), UIntPtr.Zero);
            SendMessageW(dialog.Body, 0x30, dialog.Font, new IntPtr(1));
            if (fields is not null)
            {
                int rowHeight = Math.Min(D(58), Math.Max(D(39), (client.Bottom - D(218)) / Math.Max(1, fields.Length)));
                for (int i = 0; i < fields.Length; i++)
                {
                    var field = fields[i]; int top = D(151) + i * rowHeight;
                    var label = CreateWindowExW(0, "STATIC", field.Label, 0x50000000, D(28), top + D(5), D(122), D(28), dialog.Window, new IntPtr(field.Id + 200), instance, IntPtr.Zero);
                    var input = CreateWindowExW(field.Choices is null ? 0x200u : 0u, field.Choices is null ? "EDIT" : "COMBOBOX",
                        field.Choices is null ? field.Value : "", 0x50010000u | (field.Choices is not null ? 3u | 0x200000u : 0x80u | (field.Secret ? 0x20u : 0u) | (field.ReadOnly ? 0x800u : 0u)),
                        D(155), top, client.Right - D(183), field.Choices is null ? D(32) : D(130), dialog.Window, new IntPtr(field.Id), instance, IntPtr.Zero);
                    if (input == IntPtr.Zero) throw new Boundary("settings_dialog_unavailable");
                    SendMessageW(label, 0x30, dialog.Font, new IntPtr(1)); SendMessageW(input, 0x30, dialog.Font, new IntPtr(1));
                    SetWindowTheme(input, HighContrast() ? "" : "DarkMode_CFD", "");
                    if (field.Choices is not null)
                    { foreach (string choice in field.Choices) SendMessageText(input, 0x143, IntPtr.Zero, choice); SendMessageW(input, 0x14E, new IntPtr(Math.Max(0, Array.IndexOf(field.Choices, field.Value))), IntPtr.Zero); }
                    else SendMessageW(input, 0xC5, new IntPtr(field.Secret ? 1280 : 1024), IntPtr.Zero);
                }
            }
            for (int i = 0; i < dialog.Buttons.Count; i++)
            {
                int id = dialog.Buttons[i];
                string label = mode == 3 ? id == 6 ? UiText.Get("保存并关闭") : id == 7 ? UiText.Get("放弃更改") : UiText.Get("返回编辑")
                    : mode == 4 ? id == 6 ? fields is null ? UiText.Get("继续") : UiText.Get("保存") : UiText.Get("取消") : UiText.Get("关闭");
                var button = CreateWindowExW(0, "BUTTON", label, 0x5001000B,
                    client.Right - D(28 + (dialog.Buttons.Count - i) * 132), client.Bottom - D(61), D(120), D(38),
                    dialog.Window, new IntPtr(id), instance, IntPtr.Zero);
                if (button == IntPtr.Zero) throw new Boundary("settings_dialog_unavailable");
                SendMessageW(button, 0x30, dialog.Font, new IntPtr(1)); SetWindowTheme(button, " ", " ");
            }
            if (enabledOwner) EnableWindow(owner, false);
            ShowWindow(dialog.Window, 5); SetFocus(GetDlgItem(dialog.Window, fields?.FirstOrDefault(f => !f.ReadOnly)?.Id ?? dialog.Default)); UpdateWindow(dialog.Window);
            while (dialog.Result == 0)
            {
                int result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result <= 0) { quit = result == 0; dialog.Result = dialog.Cancel; break; }
                if (message.Hwnd == dialog.Window || IsChild(dialog.Window, message.Hwnd))
                {
                    if (message.Kind is 0x201 or 0x204 or 0x207 or 0x20B or 0x246) SetKeyboardNavigation(false);
                    if (message.Kind == 0x100 && (int)message.Wp is 9 or 37 or 38 or 39 or 40) SetKeyboardNavigation(true);
                }
                if (message.Kind == 0x100 && (message.Hwnd == dialog.Window || IsChild(dialog.Window, message.Hwnd)))
                {
                    int key = (int)message.Wp;
                    if (key is 13 or 27 && dialog.Fields?.Any(f => f.Choices is not null
                        && SendMessageW(GetDlgItem(dialog.Window, f.Id), 0x157, IntPtr.Zero, IntPtr.Zero) != IntPtr.Zero) == true)
                    { TranslateMessage(ref message); DispatchMessageW(ref message); continue; }
                    if (key == 27) { dialog.Result = dialog.Cancel; continue; }
                    if (key == 13) { int focused = GetDlgCtrlID(GetFocus()); FinishDialog(dialog, dialog.Buttons.Contains(focused) ? focused : dialog.Default); continue; }
                    if (HandleAppDialogShortcut(key, (GetKeyState(17) & 0x8000) != 0)) continue;
                }
                if (!IsDialogMessageW(dialog.Window, ref message)) { TranslateMessage(ref message); DispatchMessageW(ref message); }
            }
            return dialog.Result;
        }
        finally
        {
            // Re-enable before destroying the owned window so Windows can
            // restore activation to its owner. Parent shortcuts never save
            // while a confirmation is open.
            if (enabledOwner && IsWindow(owner)) EnableWindow(owner, true);
            if (dialog.Window != IntPtr.Zero && IsWindow(dialog.Window))
            {
                foreach (var field in dialog.Fields ?? []) if (field.Secret) SetWindowTextW(GetDlgItem(dialog.Window, field.Id), "");
                DestroyWindow(dialog.Window);
            }
            if (dialog.Font != IntPtr.Zero) DeleteObject(dialog.Font);
            appDialog = null;
            PostPendingPageRebuild();
            if (IsWindow(owner)) { Native.SetForegroundWindow(owner); if (IsWindow(priorFocus)) SetFocus(priorFocus); }
            if (quit) PostQuitMessage(0);
        }
    }

    private static void ApplyDialogIcons(AppDialog dialog)
    {
        uint dpi = (uint)Math.Round(96 * dialog.DpiScale);
        SendMessageW(dialog.Window, 0x80, IntPtr.Zero, TrayStateIcons.Load(workspaceIconState, GetSystemMetricsForDpi(49, dpi), GetSystemMetricsForDpi(50, dpi)));
        SendMessageW(dialog.Window, 0x80, new IntPtr(1), TrayStateIcons.Load(workspaceIconState, GetSystemMetricsForDpi(11, dpi), GetSystemMetricsForDpi(12, dpi)));
    }

    private static void LayoutAppDialog(AppDialog dialog)
    {
        int D(int value) => (int)Math.Round(value * dialog.DpiScale);
        GetClientRect(dialog.Window, out var client);
        var font = CreateFontW(-D(17), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, BodyFace);
        if (font == IntPtr.Zero) throw new Boundary("settings_dialog_font_unavailable");
        var previous = dialog.Font; dialog.Font = font;
        SendMessageW(dialog.Body, 0x30, font, new IntPtr(1));
        SetWindowPos(dialog.Body, IntPtr.Zero, D(28), D(76), Math.Max(1, client.Right - D(56)), dialog.Fields is null ? Math.Max(1, client.Bottom - D(164)) : D(65), 0x14);
        if (dialog.Fields is { } fields)
        {
            int rowHeight = Math.Min(D(58), Math.Max(D(39), (client.Bottom - D(218)) / Math.Max(1, fields.Length)));
            for (int i = 0; i < fields.Length; i++)
            {
                var field = fields[i]; int top = D(151) + i * rowHeight;
                var input = GetDlgItem(dialog.Window, field.Id); var label = GetDlgItem(dialog.Window, field.Id + 200);
                SendMessageW(input, 0x30, font, new IntPtr(1)); SendMessageW(label, 0x30, font, new IntPtr(1));
                SetWindowPos(label, IntPtr.Zero, D(28), top + D(5), D(122), D(28), 0x14);
                SetWindowPos(input, IntPtr.Zero, D(155), top, Math.Max(1, client.Right - D(183)), field.Choices is null ? D(32) : D(130), 0x14);
            }
        }
        for (int i = 0; i < dialog.Buttons.Count; i++)
        {
            var button = GetDlgItem(dialog.Window, dialog.Buttons[i]);
            SendMessageW(button, 0x30, font, new IntPtr(1));
            SetWindowPos(button, IntPtr.Zero, client.Right - D(28 + (dialog.Buttons.Count - i) * 132), client.Bottom - D(61), D(120), D(38), 0x14);
        }
        if (previous != IntPtr.Zero) DeleteObject(previous);
        ApplyDialogIcons(dialog);
    }

    private static bool HandleAppDialogShortcut(int key, bool control)
    {
        if (!control || appDialog is not { } dialog) return false;
        var field = dialog.Fields?.FirstOrDefault(f => GetDlgItem(dialog.Window, f.Id) == GetFocus());
        if (field is not null)
        {
            if (key == 65 && field.Choices is null)
            { SendMessageW(GetFocus(), 0xB1, IntPtr.Zero, new IntPtr(-1)); return true; }
            return false; // Native edit copy/paste; password edits retain OS protection.
        }
        if (key == 65)
        { SetFocus(dialog.Body); SendMessageW(dialog.Body, 0xB1, IntPtr.Zero, new IntPtr(-1)); return true; }
        if (key != 67 || GetFocus() == dialog.Body) return false;
        // Match the former MessageBox Ctrl+C from its initially focused button.
        // Let native EDIT copy Unicode text; restore the prior selection.
        GetEditSelection(dialog.Body, 0xB0, out int start, out int end);
        SendMessageW(dialog.Body, 0xB1, IntPtr.Zero, new IntPtr(-1));
        SendMessageW(dialog.Body, 0x301, IntPtr.Zero, IntPtr.Zero);
        SendMessageW(dialog.Body, 0xB1, new IntPtr(start), new IntPtr(end));
        return true;
    }

    private static IntPtr AppDialogMessage(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        try { return AppDialogMessageCore(hwnd, message, wp, lp); }
        catch (Exception error)
        {
            Console.Error.WriteLine("settings_dialog_failed: " + Program.Code(error));
            if (appDialog is not null) appDialog.Result = appDialog.Cancel;
            if (message == 0xF) ValidateRect(hwnd, IntPtr.Zero);
            return IntPtr.Zero;
        }
    }

    private static IntPtr AppDialogMessageCore(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        var dialog = appDialog;
        if (dialog is null) return DefWindowProcW(hwnd, message, wp, lp);
        int D(int value) => (int)Math.Round(value * dialog.DpiScale);
        if (message == 0x2E0)
        {
            dialog.DpiScale = Math.Max(96, (int)(wp.ToUInt64() & 0xffff)) / 96.0;
            var rect = Marshal.PtrToStructure<Rect>(lp);
            SetWindowPos(hwnd, IntPtr.Zero, rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top, 0x14);
            LayoutAppDialog(dialog); InvalidateRect(hwnd, IntPtr.Zero, true);
            return IntPtr.Zero;
        }
        if (message is 0x15 or 0x1A or 0x31A)
        {
            bool contrast = HighContrast(); int dark = contrast ? 0 : 1, caption = contrast ? -1 : 0x211624, ink = contrast ? -1 : 0xF4E8FA;
            DwmSetWindowAttribute(hwnd, 20, ref dark, 4); DwmSetWindowAttribute(hwnd, 35, ref caption, 4); DwmSetWindowAttribute(hwnd, 36, ref ink, 4);
            InvalidateRect(hwnd, IntPtr.Zero, true);
            EnumChildWindows(hwnd, (child, _) =>
            { if (message == 0x15) SendMessageW(child, message, IntPtr.Zero, IntPtr.Zero); InvalidateRect(child, IntPtr.Zero, true); return true; }, IntPtr.Zero);
        }
        if (message == 2) { dialog.Result = dialog.Cancel; return IntPtr.Zero; }
        if (message == 0x10) { dialog.Result = dialog.Cancel; return IntPtr.Zero; }
        if (message == 0x111 && ((wp.ToUInt64() >> 16) & 0xffff) == 0 && dialog.Buttons.Contains((int)wp))
        { FinishDialog(dialog, (int)wp); return IntPtr.Zero; }
        if (message is 0x133 or 0x134 or 0x138)
        {
            SetBkMode((IntPtr)wp, 2); SetTextColor((IntPtr)wp, HighContrast() ? GetSysColor(8) : 0xF5EDF4); SetBkColor((IntPtr)wp, HighContrast() ? GetSysColor(5) : 0x2B2320);
            return HighContrast() ? GetSysColorBrush(5) : pageBrush;
        }
        if (message == 0x14) return new IntPtr(1);
        if (message == 0xF)
        {
            var paint = new PaintStruct(); var dc = BeginPaint(hwnd, ref paint);
            try
            {
                GetClientRect(hwnd, out var bounds); FillExact(dc, bounds, HighContrast() ? GetSysColor(5) : 0x2B2320);
                var title = new Rect { Left = D(28), Top = D(20), Right = bounds.Right - D(28), Bottom = D(60) };
                var font = CreateFontW(-D(25), 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 4, 0, BodyFace);
                var old = SelectObject(dc, font); SetBkMode(dc, 1); SetTextColor(dc, HighContrast() ? GetSysColor(8) : 0xF8EFF6);
                try { DrawTextW(dc, dialog.Title, -1, ref title, 0x20 | 0x4 | 0x800); }
                finally { SelectObject(dc, old); DeleteObject(font); }
                var footer = bounds; footer.Top = bounds.Bottom - D(82); FillExact(dc, footer, HighContrast() ? GetSysColor(15) : 0x211B1B);
            }
            finally { EndPaint(hwnd, ref paint); }
            return IntPtr.Zero;
        }
        if (message == 0x2B)
        {
            var item = Marshal.PtrToStructure<DrawItem>(lp);
            if (item.Type == 1) { PaintMenuItem(item); return new IntPtr(1); }
            FillExact(item.Dc, item.Rect, HighContrast() ? GetSysColor(15) : 0x211B1B);
            bool primary = item.Id == 6 || dialog.Buttons.Count == 1;
            if (HighContrast()) Frame(item.Dc, item.Rect, GetSysColor(18));
            else SoftSurface(item.Dc, item.Rect, primary ? 0xA27681u : 0x635346u, (byte)((item.State & 1) != 0 ? 230 : primary ? 210 : 140), 9);
            var old = SelectObject(item.Dc, dialog.Font); SetBkMode(item.Dc, 1); SetTextColor(item.Dc, HighContrast() ? GetSysColor(18) : 0xFFF5FA);
            try { var rect = item.Rect; DrawTextW(item.Dc, Text(item.Window), -1, ref rect, 1 | 0x4 | 0x20 | 0x800); }
            finally { SelectObject(item.Dc, old); }
            if (GetFocus() == item.Window)
            { var focus = item.Rect; focus.Left += D(3); focus.Top += D(3); focus.Right -= D(3); focus.Bottom -= D(3); PaintKeyboardFocus(item.Dc, ref focus); }
            return new IntPtr(1);
        }
        if (message == 0x2C && MeasureThemedItem(lp)) return new IntPtr(1);
        if (message == 0x400) return new IntPtr(0x534B0000 | dialog.Default); // DM_GETDEFID
        return DefWindowProcW(hwnd, message, wp, lp);
    }

    private static void FinishDialog(AppDialog dialog, int result)
    {
        if (result == 6 && dialog.Submit is not null && !dialog.Submit(dialog)) return;
        dialog.Result = result;
    }

    [DllImport("user32.dll", EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode)] private static extern int NativeMessageBox(IntPtr owner, string text, string title, uint type);
    [DllImport("user32.dll")] private static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint = "SendMessageW")] private static extern IntPtr GetEditSelection(IntPtr hwnd, uint message, out int start, out int end);
}
