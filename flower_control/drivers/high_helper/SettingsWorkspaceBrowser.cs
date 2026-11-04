namespace Flower.HighHelper;

// UI-only result metadata. No task/grant, URL, account or page contents.
internal sealed record SettingsBrowserOpenResult(string State, string? Reason = null);

internal static partial class SettingsWorkspace
{
    private const int GeneralPreferencesId = 490, GeneralWebId = 491,
        OpenPersonalBrowserId = 492, OpenAiBrowserId = 493, OpenTemporaryBrowserId = 494;
    private const int BrowserDefaultId = 920, BrowserManageId = 921, BrowserRescanId = 922, BrowserSystemId = 923;
    private const int BrowserPersonalNoteId = 925, BrowserAiNoteId = 926, BrowserTemporaryNoteId = 927;
    private const uint BrowserNoteInk = 0xBED5EA;
    private const uint BrowserOpenFinished = 0x8000 + 189;
    private static int generalSection;
    private static Func<string, string?, CancellationToken, Task<SettingsBrowserOpenResult>>? browserProfileOpener;
    private static BrowserPreferenceSnapshot? browserPreferences;
    private static string? managedBrowser;
    private static Task<SettingsBrowserOpenResult>? browserOpening;
    private static CancellationTokenSource? browserOpeningStop;
    private static string? browserOpeningKind;
    private static bool BrowserOpening => browserOpening is not null;

    internal static void AttachBrowserProfileOpener(Func<string, CancellationToken, Task<SettingsBrowserOpenResult>>? open)
        => browserProfileOpener = open is null ? null : (kind, _, token) => open(kind, token);
    internal static void AttachBrowserProfileBrowserOpener(Func<string, string?, CancellationToken, Task<SettingsBrowserOpenResult>>? open)
        => browserProfileOpener = open;

    private static string? BrowserKind(int id) => id switch
    {
        OpenPersonalBrowserId => "luohua", OpenAiBrowserId => "ai", OpenTemporaryBrowserId => "temporary", _ => null
    };
    private static string BrowserLabel(string kind) => kind switch
    { "luohua" => UiText.Get("个人登录态"), "ai" => UiText.Get("AI 登录态"), "temporary" => UiText.Get("临时登录态"), _ => UiText.Get("浏览器") };

    private static void BuildGeneralBrowserPage()
    {
        browserPreferences ??= preview ? BrowserPreferences.Synthetic() : BrowserPreferences.Read();
        var snapshot = browserPreferences;
        if (!snapshot.Installed.Any(i => i.Browser == managedBrowser)) managedBrowser = snapshot.Selected?.Browser ?? snapshot.Installed.FirstOrDefault()?.Browser;
        Label(UiText.Get("Windows 系统默认（仅外部链接）：") + snapshot.WindowsDefaultName, 650, 265, 520, 38, fontSize: 16);
        PageButton(BrowserRescanId, UiText.Get("重新识别"), 1190, 270, 250, 42);
        Label(UiText.Get("Flower-Web 新会话默认使用"), 650, 320, 790, 36, fontSize: 18, emphasis: true);
        string[] defaults = new[] { UiText.Get("跟随系统配置（") + snapshot.WindowsDefaultName + "）" }.Concat(snapshot.Installed.Select(i => i.Name)).ToArray();
        int defaultIndex = snapshot.Preference == "system" ? 0 : Array.FindIndex(snapshot.Installed, i => i.Browser == snapshot.Preference) + 1;
        if (snapshot.Preference != "system" && defaultIndex == 0) defaultIndex = -1;
        Combo(BrowserDefaultId, defaults, defaultIndex, 650, 363, 790);
        Label(UiText.Get("AI将默认使用这里选择的浏览器登录态进行操作。你可以在对话中指定使用其他浏览器，不会改变此默认设置。"), 650, 417, 790, 52, fontSize: 17,
            ink: snapshot.Error is not null ? 0xA9DCEE : BrowserNoteInk);
        Label(UiText.Get("当前管理对象"), 650, 475, 250, 40, fontSize: 18, emphasis: true);
        Combo(BrowserManageId, snapshot.Installed.Select(i => i.Name).ToArray(), Array.FindIndex(snapshot.Installed, i => i.Browser == managedBrowser), 930, 470, 510);
        string label = managedBrowser is null ? UiText.Get("未发现可用浏览器 · 请重新识别") : UiText.Get("正在管理：") + BrowserPreferences.Name(managedBrowser);
        Label(label, 650, 519, 790, 36, emphasis: true, fontSize: 18, id: BrowserSystemId);
        string State(string kind) => preview ? "exists" : managedBrowser is null ? "unavailable" : BrowserPreferences.ProfileState(managedBrowser, kind);
        string Button(string state) => state == "missing" ? UiText.Get("创建登录态") : state == "exists" ? UiText.Get("打开登录态") : state == "incomplete" ? UiText.Get("继续创建登录态") : UiText.Get("无法读取状态");
        string personal = State("luohua"), ai = State("ai");
        Label(UiText.Get("个人登录态"), 650, 563, 400, 36, emphasis: true, fontSize: 20);
        PageButton(OpenPersonalBrowserId, Button(personal), 1100, 558, 340, 42);
        Label(UiText.Get("账号与日常浏览器分开保存。AI 使用前须取得本聊天授权。"), 650, 604, 790, 40,
            fontSize: 18, ink: BrowserNoteInk, id: BrowserPersonalNoteId);
        Label(UiText.Get("AI 专用登录态"), 650, 650, 400, 36, emphasis: true, fontSize: 20);
        PageButton(OpenAiBrowserId, Button(ai), 1100, 645, 340, 42);
        Label(UiText.Get("先由你登录供 AI 使用的账号；与个人登录态分开保存。"), 650, 691, 790, 40,
            fontSize: 18, ink: BrowserNoteInk, id: BrowserAiNoteId);
        Label(UiText.Get("临时登录态"), 650, 737, 400, 36, emphasis: true, fontSize: 20);
        PageButton(OpenTemporaryBrowserId, UiText.Get("新建临时窗口"), 1100, 732, 340, 42);
        Label(UiText.Get("每次新建空白登录态，不沿用已保存的账号。"), 650, 778, 790, 26,
            fontSize: 18, ink: BrowserNoteInk, id: BrowserTemporaryNoteId);
        if (personal == "unavailable") EnableWindow(PageHandle(OpenPersonalBrowserId), false);
        if (ai == "unavailable") EnableWindow(PageHandle(OpenAiBrowserId), false);
        if (snapshot.Error is not null) notice = UiText.Get("浏览器设置待核对：") + UserFacingError(snapshot.Error) + UiText.Get("；原文件未改写。");
        UpdateBrowserButtons();
    }

    private static bool GeneralBrowserCommand(int id, int notification)
    {
        if (id is BrowserDefaultId or BrowserManageId or BrowserRescanId)
        {
            if (page != 3 || generalSection != 1 || Busy || BrowserOpening) return true;
            if (id == BrowserRescanId && notification == 0)
            { browserPreferences = null; BuildPage(); UpdateChrome(); return true; }
            if (notification != 1 || browserPreferences is not { } snapshot) return true;
            int selected = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32();
            if (id == BrowserManageId && selected >= 0 && selected < snapshot.Installed.Length)
            { managedBrowser = snapshot.Installed[selected].Browser; BuildPage(); UpdateChrome(); }
            if (id == BrowserDefaultId && selected >= 0 && selected <= snapshot.Installed.Length)
                RequestDefaultBrowser(selected == 0 ? "system" : snapshot.Installed[selected - 1].Browser);
            return true;
        }
        if (id is GeneralPreferencesId or GeneralWebId)
        {
            if (notification != 0 || page != 3) return true;
            int selected = id == GeneralWebId ? 1 : 0;
            if (generalSection == selected) return true;
            generalSection = selected;
            if (window != IntPtr.Zero) { BuildPage(); UpdateChrome(); }
            return true;
        }
        if (BrowserKind(id) is not { } kind) return false;
        if (notification == 0 && page == 3 && generalSection == 1) RequestBrowserProfile(kind);
        return true;
    }

    private static void RequestBrowserProfile(string kind)
    {
        if (kind is not ("luohua" or "ai" or "temporary")) return;
        if (preview) { notice = UiText.Get("预览不会打开浏览器，也不会读取登录信息。"); RefreshBrowserChrome(); return; }
        if (Busy || BrowserOpening) { notice = UiText.Get("浏览器设置或窗口正在处理；没有重复发送请求。"); RefreshBrowserChrome(); return; }
        var open = browserProfileOpener;
        if (open is null) { notice = UiText.Get("浏览器入口尚未安装；安装后再打开。"); RefreshBrowserChrome(); return; }
        browserOpeningKind = kind;
        string? selectedBrowser = managedBrowser;
        var stop = new CancellationTokenSource(); browserOpeningStop = stop;
        var handle = window; long expected = generation;
        var pending = Task.Run(async () => {
            try { return await open(kind, selectedBrowser, stop.Token).ConfigureAwait(false) ?? new SettingsBrowserOpenResult("unavailable"); }
            catch (OperationCanceledException) { return new SettingsBrowserOpenResult("cancelled"); }
            catch { return new SettingsBrowserOpenResult("unavailable"); }
            finally { stop.Dispose(); }
        });
        browserOpening = pending;
        _ = pending.ContinueWith(_ => {
            if (expected == generation && handle != IntPtr.Zero && handle == window)
                PostMessageW(handle, BrowserOpenFinished, UIntPtr.Zero, IntPtr.Zero);
        }, TaskScheduler.Default);
        notice = UiText.Get("正在打开 ") + (selectedBrowser is null ? "" : BrowserPreferences.Name(selectedBrowser) + " · ") + BrowserLabel(kind) + UiText.Get("；设置草稿保留。");
        RefreshBrowserChrome();
    }

    private static string BrowserResultNotice(SettingsBrowserOpenResult value, string kind) => value.State switch
    {
        "opened" or "reused" => BrowserLabel(kind) + UiText.Get("已打开；你可以手动登录。"),
        _ when value.Reason is "shared_browser_borrower_active" => UiText.Get("这个登录态仍有作业在运行；请先结束作业再打开。"),
        _ when value.Reason is "shared_browser_retained_pages" => UiText.Get("后台会话仍有页面；请先回原作业关闭页面，再打开。"),
        _ when value.Reason is "shared_browser_user_instance_retained" or "shared_browser_unowned_pages_retained" => UiText.Get("原浏览器会话仍保留；请先核对，有可见窗口时可手动关闭。"),
        _ when value.Reason is "shared_browser_action_recovery_required" or "shared_browser_close_pending"
            or "shared_browser_idle_state_changed" or "shared_browser_idle_state_unverified"
            or "shared_browser_borrower_unverified" or "shared_browser_borrower_limit"
            or "shared_browser_ledger_unverified" => UiText.Get("原浏览器状态待核对；请先查看，不要重复打开。"),
        _ when value.Reason is "shared_browser_transition_in_progress" => UiText.Get("正在切换这个登录态；请稍候再试。"),
        "busy" or "login_in_progress" => UiText.Get("这个登录态正在使用或打开，请稍后再试。"),
        "window_mode_conflict" => UiText.Get("这个登录态正在后台使用；结束原会话后再打开。"),
        "previous_instance_recovery_required" or "outcome_uncertain" => UiText.Get("打开结果待核对，请先查看浏览器；不要重复打开。"),
        "cancelled" => UiText.Get("已结束等待；已经打开的浏览器会保留。"),
        _ when value.Reason is "busy" or "login_in_progress" or "ai_profile_in_use" => UiText.Get("这个登录态正在使用或打开，请稍后再试。"),
        _ when value.Reason is "window_mode_conflict" => UiText.Get("这个登录态正在后台使用；结束原会话后再打开。"),
        _ when value.Reason is "previous_instance_recovery_required" or "outcome_uncertain" => UiText.Get("打开结果待核对，请先查看浏览器；不要重复打开。"),
        _ when value.Reason is "browser_not_found" or "brave_not_found" or "browser_executable_unavailable" or "selected_browser_not_installed" => UiText.Get("未找到选中的浏览器；请重新识别后切换。"),
        _ when value.Reason is "browser_profile_not_installed" or "browser_profile_bundle_unavailable" => UiText.Get("浏览器入口尚未安装；安装后再打开。"),
        _ => UiText.Get("浏览器入口暂不可用，请稍后再试；设置草稿保留。")
    };

    private static void CompleteBrowserProfileOpen()
    {
        if (browserOpening is null || !browserOpening.IsCompleted) return;
        var result = browserOpening.GetAwaiter().GetResult();
        string kind = browserOpeningKind ?? "";
        browserOpening = null; browserOpeningStop = null; browserOpeningKind = null;
        notice = BrowserResultNotice(result, kind);
        if (window != IntPtr.Zero && page == 3 && generalSection == 1) BuildPage();
        RefreshBrowserChrome();
    }
    private static void UpdateBrowserButtons()
    {
        if (window == IntPtr.Zero) return;
        foreach (int id in new[] { OpenPersonalBrowserId, OpenAiBrowserId, OpenTemporaryBrowserId, BrowserManageId, BrowserDefaultId, BrowserRescanId })
            if (PageHandle(id) != IntPtr.Zero) EnableWindow(PageHandle(id), !Busy && !BrowserOpening
                && (id == BrowserRescanId || browserPreferences?.Installed.Length > 0)
                && (id != BrowserDefaultId || browserPreferences?.Error is null or "selected_browser_not_installed"));
        if (!preview && managedBrowser is not null)
            foreach (var pair in new[] { (OpenPersonalBrowserId, "luohua"), (OpenAiBrowserId, "ai") })
                if (PageHandle(pair.Item1) != IntPtr.Zero && BrowserPreferences.ProfileState(managedBrowser, pair.Item2) == "unavailable")
                    EnableWindow(PageHandle(pair.Item1), false);
    }
    private static void RefreshBrowserChrome()
    {
        if (window != IntPtr.Zero) { UpdateBrowserButtons(); UpdateChrome(); }
    }
    private static void ResetBrowserOpening()
    {
        try { browserOpeningStop?.Cancel(); } catch (ObjectDisposedException) { }
        browserOpening = null; browserOpeningStop = null; browserOpeningKind = null;
        browserPreferences = null; managedBrowser = null;
    }

    private static void RequestDefaultBrowser(string selection)
    {
        if (browserPreferences is not { } snapshot || snapshot.Preference == selection || Busy || BrowserOpening) return;
        if (preview) { browserPreferences = snapshot with { Preference = selection, Selected = selection == "system" ? snapshot.WindowsDefault : snapshot.Installed.FirstOrDefault(i => i.Browser == selection) }; BuildPage(); UpdateChrome(); return; }
        string? revision = snapshot.Revision;
        StartWork(token => {
            var result = BrowserProfileOpen.SavePreferenceAsync(selection, revision, token).GetAwaiter().GetResult();
            return new("browser_preferences", Error: result.State == "saved" ? null : result.Reason ?? result.State);
        });
        notice = UiText.Get("正在保存 Flower 默认浏览器；现有窗口和聊天授权保留。"); UpdateBrowserButtons(); UpdateChrome();
    }

    private static void CompleteBrowserPreferenceSave(WorkReply reply)
    {
        browserPreferences = preview ? BrowserPreferences.Synthetic() : BrowserPreferences.Read();
        notice = reply.Error is null ? UiText.Get("Flower 默认浏览器已保存；从下次新建会话起生效。")
            : UiText.Get("浏览器选择未确认保存：") + UserFacingError(reply.Error) + UiText.Get("；已重读实际状态，不自动重试。");
        if (page == 3 && generalSection == 1) BuildPage(); UpdateChrome();
    }

    private static void PaintBrowserSystemLabel(DrawItem item)
    {
        PaintControlBackdrop(item);
        var text = item.Rect;
        string? path = browserPreferences?.Installed.FirstOrDefault(p => p.Browser == managedBrowser)?.Executable;
        string iconKey = path ?? "<missing-browser>";
        if (!programIcons.TryGetValue(iconKey, out var icon))
        {
            if (path is not null) PrivateExtractIconsW(path, 0, 32, 32, out icon, out _, 1, 0);
            if (icon == IntPtr.Zero) icon = CopyIcon(LoadIconW(IntPtr.Zero, new IntPtr(32512)));
            programIcons[iconKey] = icon;
        }
        int size = Math.Min(item.Rect.Bottom - item.Rect.Top, Math.Max(Px(28), FontPixels(22)));
        if (icon != IntPtr.Zero) DrawIconEx(item.Dc, text.Left, text.Top + (text.Bottom - text.Top - size) / 2, icon, size, size, 0, IntPtr.Zero, 3);
        text.Left += size + Px(12);
        Text(item.Dc, Text(item.Window), text, 20, 0xE4F1FF, false);
    }

    private static void PaintBrowserDescription(DrawItem item)
    {
        PaintControlBackdrop(item);
        string value = Text(item.Window);
        string emphasis = item.Id switch
        {
            BrowserPersonalNoteId => UiText.Get("本聊天授权"),
            BrowserAiNoteId => UiText.Get("与个人登录态分开保存"),
            _ => UiText.Get("每次新建")
        };
        int at = value.IndexOf(emphasis, StringComparison.Ordinal);
        if (at < 0) { PaintPageLabel(item); return; }
        // Keep a single, complete native STATIC caption for accessibility. The
        // three drawing runs only add visual emphasis; no text is an action.
        var runs = new[] { (value[..at], false), (emphasis, true), (value[(at + emphasis.Length)..], false) };
        var regular = UiFont(-FontPixels(18), 400, BodyFace);
        var strong = UiFont(-FontPixels(18), 600, BodyFace);
        var previous = SelectObject(item.Dc, regular);
        uint oldInk = SetTextColor(item.Dc, BrowserNoteInk);
        int oldMode = SetBkMode(item.Dc, 1);
        int Width(string text)
        {
            var measured = new Rect();
            DrawTextW(item.Dc, text, -1, ref measured, 0x400 | 0x20 | 0x800);
            return Math.Max(0, measured.Right - measured.Left);
        }
        var line = new Rect();
        int lineHeight = DrawTextW(item.Dc, "国Ay", -1, ref line, 0x400 | 0x20 | 0x800) + Px(2);
        int x = item.Rect.Left, y = item.Rect.Top;
        try
        {
            foreach (var (text, bold) in runs)
            {
                SelectObject(item.Dc, bold ? strong : regular);
                SetTextColor(item.Dc, HighContrast() ? GetSysColor(8) : BrowserNoteInk);
                for (int offset = 0; offset < text.Length;)
                {
                    int count = text.Length - offset;
                    while (count > 0 && Width(text.Substring(offset, count)) > item.Rect.Right - x) count--;
                    if (count == 0)
                    {
                        if (x == item.Rect.Left) count = 1;
                        else { x = item.Rect.Left; y += lineHeight; continue; }
                    }
                    string chunk = text.Substring(offset, count);
                    var rect = new Rect { Left = x, Top = y, Right = item.Rect.Right, Bottom = item.Rect.Bottom };
                    DrawTextW(item.Dc, chunk, -1, ref rect, 0x20 | 0x800);
                    x += Width(chunk); offset += count;
                    if (offset < text.Length) { x = item.Rect.Left; y += lineHeight; }
                }
            }
        }
        finally
        {
            SetBkMode(item.Dc, oldMode); SetTextColor(item.Dc, oldInk);
            SelectObject(item.Dc, previous);
        }
    }
}
