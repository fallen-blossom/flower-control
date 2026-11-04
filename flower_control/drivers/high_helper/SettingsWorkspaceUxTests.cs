using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const uint UxProbeTick = 0x8000 + 202;
    private static Action? uxProbeAction;

    // Only an explicit CLI fixture creates this Medium synthetic workspace.
    // Exercise actual native controls/modal loops, never the real High policy.
    internal static object UxSelfTest(string directory)
    {
        if (window != IntPtr.Zero || core is not null) throw new Boundary("settings_ux_fixture_requires_fresh_process");
        Directory.CreateDirectory(directory);
        int assertions = 0; var frames = new List<object>(); Exception? deferredError = null; string? failedCheck = null;
        void Check(bool value, string name) { assertions++; if (!value) { failedCheck = name; throw new InvalidOperationException("settings_ux_test: " + name); } }
        void Pump()
        { while (PeekMessageW(out var message, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref message); DispatchMessageW(ref message); } }
        void Capture(string name, IntPtr target)
        {
            UpdateWindow(target); GetWindowRect(target, out var rect);
            string path = Path.Combine(directory, name + ".png");
            SettingsArtwork.SaveWindowPng(target, rect.Right - rect.Left, rect.Bottom - rect.Top, path);
            frames.Add(new { path, pid = Environment.ProcessId, hwnd = target.ToInt64(), owner = window.ToInt64(),
                dpi = GetDpiForWindow(target), time = DateTimeOffset.Now, foreground_owner = Native.GetForegroundWindow() == window || Native.GetForegroundWindow() == target,
                bounds = new[] { rect.Left, rect.Top, rect.Right, rect.Bottom }, capture_backend = "PrintWindow exact native window; unscaled", synthetic = true });
        }
        bool Overlap(Rect a, Rect b) => a.Left < b.Right && b.Left < a.Right && a.Top < b.Bottom && b.Top < a.Bottom;
        preview = true; standalone = false; core = null; Initialize(Synthetic()); page = 1;
        bool passed = false;
        try
        {
            SetVisualState(2); Create(); ShowWindow(window, 5); Native.SetForegroundWindow(window); Pump();
            ProbeWindowMotion(directory, Check);
            var previousScene = sceneState; int previousIcon = workspaceIconState;
            var savedBeforeNotice = model.Saved; var draftBeforeNotice = model.Draft;
            runtimeNotice = "全部写入已停止";
            Check(CurrentModeText() == "全部写入已停止" && OverviewExecutorText().StartsWith("全部写入已停止\n"),
                "global_stop_notice_precedes_saved_tier_mode");
            UiText.SetLanguage("en");
            Check(CurrentModeText() == "All writes stopped" && OverviewExecutorText().StartsWith("All writes stopped\n"),
                "global_stop_notice_localized_without_changing_saved_tier");
            Check(ReferenceEquals(savedBeforeNotice, model.Saved) && ReferenceEquals(draftBeforeNotice, model.Draft),
                "stop_notice_keeps_saved_tier_and_draft");
            UiText.SetLanguage("zh-CN");
            InvalidateRect(window, IntPtr.Zero, false); Capture("global-stop-notice-synthetic", window);
            Check(sceneState != previousScene && sceneState?.SavedMode == "全部写入已停止" && workspaceIconState == previousIcon,
                "runtime_notice_rebuilds_scene_without_icon_change");
            runtimeNotice = "释放未确认，输入已停用";
            Check(CurrentModeText().Contains("释放未确认"), "release_fault_notice_is_visible");
            RefreshOverview();
            Check(runtimeNotice == "" && !runtimeWritesStopped, "preview_does_not_read_or_retain_runtime_stop");
            GetWindowRect(window, out var wide);
            foreach (int state in Enumerable.Range(0, 6))
            {
                SetVisualState(state);
                uint dpi = GetDpiForWindow(window);
                Check(SendMessageW(window, 0x7F, IntPtr.Zero, IntPtr.Zero) == TrayStateIcons.Load(state, GetSystemMetricsForDpi(49, dpi), GetSystemMetricsForDpi(50, dpi)), "small_icon_matches_tray_" + state);
                Check(SendMessageW(window, 0x7F, new IntPtr(1), IntPtr.Zero) == TrayStateIcons.Load(state, GetSystemMetricsForDpi(11, dpi), GetSystemMetricsForDpi(12, dpi)), "large_icon_matches_tray_" + state);
                if (state is 0 or 5) VerifyScenePixels(directory, "icon-state-" + state, Check);
            }
            var originalPreviewModel = model;
            try
            {
                model = new(originalPreviewModel.Saved);
                foreach (int target in new[] { -1, 0, 1, 2 })
                {
                    RequestTier(target); RequestSave(); Pump();
                    int expected = TrayStateIcons.Select(target, true, false);
                    uint dpi = GetDpiForWindow(window);
                    Check(model.EffectiveTier == target && !model.Dirty && workspaceIconState == expected,
                        "preview_saved_tier_updates_icon_" + target);
                    Check(SendMessageW(window, 0x7F, IntPtr.Zero, IntPtr.Zero) == TrayStateIcons.Load(expected, GetSystemMetricsForDpi(49, dpi), GetSystemMetricsForDpi(50, dpi))
                        && SendMessageW(window, 0x7F, new IntPtr(1), IntPtr.Zero) == TrayStateIcons.Load(expected, GetSystemMetricsForDpi(11, dpi), GetSystemMetricsForDpi(12, dpi)),
                        "saved_tier_title_and_taskbar_icons_match_" + target);
                }
            }
            finally { model = originalPreviewModel; }
            SetVisualState(2);
            notice = "权限已保存；词表待保存（privacy_words_save_outcome_unknown）";
            Check(VisibleNotice().StartsWith("权限已存") && VisibleNotice().Contains("敏感词结果未知"), "partial_commit_notice_retains_known_success");
            foreach (bool compact in new[] { false, true })
            {
                string prefix = compact ? "compact" : "wide";
                if (compact) SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, MinimumSurfaceSize(window).X, MinimumSurfaceSize(window).Y, 0x14);
                notice = "操作未完成：uac_registered_action_mismatch；原草稿保留，不自动重试。";
                UpdateChrome(); Pump();
                Check(!Overlap(Layout.Notice, Layout.Stop) && !Overlap(Layout.Notice, Layout.Add)
                    && !Overlap(Layout.Notice, Layout.NoticeDetails) && !Overlap(Layout.NoticeDetails, Layout.Reload), prefix + "_long_notice_clear_of_actions");
                Check(IsWindowVisible(GetDlgItem(window, NoticeDetailsId)), prefix + "_error_details_reachable");
                // Stop is intentionally hidden outside the overview. Start
                // from the visible leaf action immediately before the error
                // details in the actual Tab order.
                SetFocus(GetDlgItem(window, AddId));
                var tab = new HostWindow.Message { Hwnd = GetFocus(), Kind = 0x100, Wp = new UIntPtr(9) };
                HandleDialogMessage(ref tab);
                Check(GetFocus() == GetDlgItem(window, NoticeDetailsId), prefix + "_details_in_keyboard_tab_order");
                SetFocus(PageHandle(ViewLayerBase + 2)); Pump(); Capture(prefix + "-notice-focus", window);
                Check(PageHandle(LayerId) == IntPtr.Zero && PageHandle(RuleKindId) == IntPtr.Zero && PageHandle(ModeId) == IntPtr.Zero, prefix + "_permission_choices_are_visible_buttons");
                var originalModel = model; int originalLayer = ruleLayer;
                try
                {
                    model = new(UserPermissions.Effective(saved with { AuthorityTier = 2, AdminLaunchEnabled = true,
                        AdminLaunchMode = "semantic", SemanticDelegation = null }));
                    ruleLayer = 2; BuildPage(); UpdateChrome(); Pump();
                    var enable = PageHandle(SemanticEnableId);
                    Check(enable != IntPtr.Zero && IsWindowVisible(enable) && IsWindowEnabled(enable), prefix + "_work_delegation_reachable");
                    var toggle = PageHandle(ModeChoiceBase); GetClientRect(toggle, out var toggleBounds);
                    Check(toggle != IntPtr.Zero && PageHandle(ModeChoiceBase + 1) == IntPtr.Zero, prefix + "_single_mode_control");
                    var keyChoice = new HostWindow.Message { Hwnd = toggle, Kind = 0x100, Wp = new UIntPtr(37) };
                    SetFocus(toggle); HandleDialogMessage(ref keyChoice);
                    Check(draft.AdminLaunchMode == "allowlist" && saved.AdminLaunchMode == "semantic", prefix + "_left_arrow_only_changes_draft");
                    keyChoice.Wp = new UIntPtr(39); HandleDialogMessage(ref keyChoice);
                    Check(draft.AdminLaunchMode == "semantic", prefix + "_right_arrow_changes_draft");
                    int leftX = Math.Max(1, toggleBounds.Right / 4), rightX = Math.Max(1, toggleBounds.Right * 3 / 4), y = Math.Max(1, toggleBounds.Bottom / 2);
                    void ClickToggle(int x) { var point = new IntPtr((y << 16) | x); SendMessageW(toggle, 0x201, new IntPtr(1), point); SendMessageW(toggle, 0x202, IntPtr.Zero, point); }
                    ClickToggle(leftX); Check(draft.AdminLaunchMode == "allowlist", prefix + "_left_click_selects_allowlist");
                    ClickToggle(leftX); Check(draft.AdminLaunchMode == "allowlist", prefix + "_selected_click_is_idempotent");
                    ClickToggle(rightX); Check(draft.AdminLaunchMode == "semantic", prefix + "_right_click_selects_work");
                    SetFocus(toggle); SendMessageW(toggle, 0x100, new IntPtr(32), IntPtr.Zero); SendMessageW(toggle, 0x101, new IntPtr(32), IntPtr.Zero); Check(draft.AdminLaunchMode == "allowlist", prefix + "_space_key_toggles");
                    SetModeChoice(1); UpdateChrome();
                    GetWindowRect(enable, out var er); GetWindowRect(PageHandle(ProgramListId), out var lr);
                    GetWindowRect(PageHandle(ModeChoiceBase), out var mr);
                    GetWindowRect(PageHandle(ListKindBase), out var wr); GetWindowRect(PageHandle(ListKindBase + 1), out var br);
                    Check(er.Top < mr.Bottom && mr.Top < er.Bottom && er.Left >= mr.Right
                        && er.Bottom <= wr.Top && er.Bottom <= br.Top,
                        prefix + "_work_delegation_belongs_to_mode_row_above_both_lists");
                    GetClientRect(window, out var client); MapWindowPoints(window, IntPtr.Zero, ref client, 2);
                    Check(!Overlap(er, lr) && er.Left >= client.Left && er.Right <= client.Right && er.Bottom <= client.Bottom,
                        prefix + "_work_delegation_clear_of_rows_inside_window");
                    foreach (var sibling in Children().Where(h => h != enable && IsWindowVisible(h)))
                    {
                        GetWindowRect(sibling, out var sr);
                        Check(!Overlap(er, sr), prefix + "_work_delegation_clear_of_visible_sibling_" + GetDlgCtrlID(sibling));
                    }
                    SetFocus(PageHandle(ModeChoiceBase)); tab.Hwnd = GetFocus(); HandleDialogMessage(ref tab);
                    Check(GetFocus() == enable, prefix + "_mode_tabs_to_work_delegation");
                    tab.Hwnd = GetFocus(); HandleDialogMessage(ref tab);
                    Check(GetFocus() == PageHandle(ListKindBase), prefix + "_work_delegation_tabs_to_lists");
                    Capture(prefix + "-work-delegation", window);
                    VerifyScenePixels(directory, prefix, Check);
                    bool confirmationSeen = false; int confirmationTicks = 0;
                    uxProbeAction = () =>
                    {
                        if (confirmationSeen || appDialog is not { Window: var hwnd } dialog || hwnd == IntPtr.Zero) return;
                        confirmationSeen = true;
                        try
                        {
                            Check(dialog.Default == 7 && GetDlgCtrlID(GetFocus()) == 7, prefix + "_delegation_defaults_to_cancel");
                            Capture(prefix + "-delegation-confirm", hwnd);
                        }
                        catch (Exception error) { deferredError = error; }
                        finally { PostMessageW(hwnd, 0x100, new UIntPtr(13), IntPtr.Zero); }
                    };
                    using (var timer = new Timer(_ =>
                    {
                        if (Interlocked.Increment(ref confirmationTicks) > 50)
                        { if (appDialog is { } pending) PostMessageW(pending.Window, 0x10, UIntPtr.Zero, IntPtr.Zero); }
                        else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero);
                    }, null, 200, 100))
                    {
                        SetFocus(enable);
                        SendMessageW(enable, 0x100, new IntPtr(32), IntPtr.Zero);
                        SendMessageW(enable, 0x101, new IntPtr(32), IntPtr.Zero);
                    }
                    uxProbeAction = null;
                    if (deferredError is not null) throw deferredError;
                    Check(confirmationSeen && saved.SemanticDelegation is null, prefix + "_enter_does_not_enable_delegation");
                    model.Conflict = true; UpdateChrome(); Check(!IsWindowEnabled(enable), prefix + "_conflict_blocks_delegation");
                    model.Conflict = false; model.Edit(x => x with { AdminLaunchMode = "allowlist" }); UpdateChrome();
                    Check(!IsWindowEnabled(enable), prefix + "_unsaved_mode_blocks_delegation");
                }
                finally { model = originalModel; ruleLayer = originalLayer; BuildPage(); UpdateChrome(); Pump(); }
                var before = draft;
                SendMessageW(PageHandle(ListKindBase + 1), 0xF5, IntPtr.Zero, IntPtr.Zero); Pump();
                Check(denied && model.Draft == before, prefix + "_blacklist_button_changes_only_view");
                Capture(prefix + "-blacklist", window);
                SendMessageW(PageHandle(ListKindBase), 0xF5, IntPtr.Zero, IntPtr.Zero); Pump();
                Check(!denied && model.Draft == before, prefix + "_whitelist_button_keeps_draft");
                SetFocus(PageHandle(ViewLayerBase + 2));
                var arrow = new HostWindow.Message { Hwnd = GetFocus(), Kind = 0x100, Wp = new UIntPtr(39) };
                HandleDialogMessage(ref arrow); Pump();
                Check(ruleLayer == 0 && tier == 2 && PageHandle(ViewLayerBase + 3) == IntPtr.Zero, prefix + "_arrow_wraps_three_rules_without_uac_or_authority_change");
                SendMessageW(PageHandle(ViewLayerBase + 2), 0xF5, IntPtr.Zero, IntPtr.Zero); Pump();
                SetFocus(window); Pump();
                RequestDisplayLanguage("en"); Pump();
                Check(Text(GetDlgItem(window, NavBase + 1)) == UiText.Get("权限")
                    && Text(GetDlgItem(window, ReloadId)) == UiText.Get("重新载入")
                    && Text(GetDlgItem(window, NoticeDetailsId)) == UiText.Get("详情"), prefix + "_english_refreshes_chrome");
                Check(PageHandle(ModeChoiceBase + 1) == IntPtr.Zero, prefix + "_mode_is_one_control");
                Capture(prefix + "-english-permission", window);
                RequestDisplayLanguage("zh-CN"); Pump();
            }
            SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, wide.Right - wide.Left, wide.Bottom - wide.Top, 0x14);
            void DialogCase(string name, uint mode, int expected, bool keyboard, int key = 27, bool longText = true)
            {
                int ticks = 0; bool observed = false;
                uxProbeAction = () =>
                {
                    if (observed || appDialog is not { Window: var hwnd, Body: var body } dialog || hwnd == IntPtr.Zero || body == IntPtr.Zero) return;
                    // The dialog is registered before its native window and
                    // child controls have finished installing focus. Observe
                    // only after focus has moved inside the dialog so a slow
                    // first frame is not reported as a wrong default button.
                    if (!IsChild(hwnd, GetFocus())) return;
                    observed = true;
                    try
                    {
                        Check(!IsWindowEnabled(window), name + "_owner_disabled");
                        Check(GetDlgCtrlID(GetFocus()) == dialog.Default, name + "_safe_default_focus");
                        Check(Text(dialog.Body).Contains("uac_registered_action_mismatch"), name + "_raw_reason_preserved");
                        if (longText)
                        {
                            int first = SendMessageW(dialog.Body, 0xCE, IntPtr.Zero, IntPtr.Zero).ToInt32();
                            SendMessageW(dialog.Body, 0xB6, IntPtr.Zero, new IntPtr(3));
                            Check(SendMessageW(dialog.Body, 0xCE, IntPtr.Zero, IntPtr.Zero).ToInt32() > first, name + "_long_details_scroll");
                            SendMessageW(dialog.Body, 0xB6, IntPtr.Zero, new IntPtr(-3));
                        }
                        HandleAppDialogShortcut(65, true);
                        GetEditSelection(dialog.Body, 0xB0, out int start, out int end);
                        Check(GetFocus() == dialog.Body && start == 0 && end == Text(dialog.Body).Length, name + "_select_all_from_initial_button");
                        SendMessageW(dialog.Body, 0xB1, IntPtr.Zero, IntPtr.Zero); SetFocus(GetDlgItem(hwnd, dialog.Default));
                        Capture(name, hwnd);
                    }
                    catch (Exception error) { deferredError = error; }
                    finally
                    {
                        if (keyboard) PostMessageW(hwnd, 0x100, new UIntPtr((uint)key), IntPtr.Zero);
                        else SendMessageW(GetDlgItem(hwnd, expected), 0xF5, IntPtr.Zero, IntPtr.Zero);
                    }
                };
                using var timer = new Timer(_ =>
                {
                    if (Interlocked.Increment(ref ticks) > 50)
                    { var current = appDialog; if (current is not null) PostMessageW(current.Window, 0x10, UIntPtr.Zero, IntPtr.Zero); }
                    else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero);
                }, null, 300, 100);
                string title = (mode & 15) == 3 ? "关闭设置" : (mode & 15) == 4 ? "确认操作" : "操作详情";
                int answer = MessageBoxW(window, "操作与登记内容不一致。\r\n\r\nuac_registered_action_mismatch\r\n原草稿保留，不自动重试。\r\n\r\n" + (longText ? string.Join("\r\n", Enumerable.Repeat("完整详情可选择并复制；长文本使用原生滚动。", 14)) : "Ctrl+C 可复制详情，Esc 返回设置。"), title, mode);
                uxProbeAction = null;
                if (deferredError is not null) throw deferredError;
                Check(observed && answer == expected && IsWindowEnabled(window), name + "_return_and_restore_owner");
            }
            DialogCase("error-details", 0x40, 1, true);
            DialogCase("discard-confirmation", 3 | 0x20 | 0x200, 2, true);
            DialogCase("yes-no-cancel-choice", 3 | 0x20 | 0x200, 7, false);
            DialogCase("confirm-choice", 4 | 0x20 | 0x100, 6, false);
            DialogCase("confirm-enter-default-cancel", 4 | 0x20 | 0x100, 7, true, 13);
            DialogCase("error-brief", 0x40, 1, true, 27, false);
            void HelpCase(int id, string name, string marker)
            {
                var draftBeforeHelp = model.Draft;
                bool faultBeforeHelp = surfaceFault;
                int ticks = 0; bool observed = false;
                uxProbeAction = () =>
                {
                    if (observed || appDialog is not { Window: var hwnd, Body: var body } dialog || hwnd == IntPtr.Zero || body == IntPtr.Zero) return;
                    if (!IsChild(hwnd, GetFocus())) return;
                    observed = true;
                    try
                    {
                        string helpBody = Text(dialog.Body);
                        Check(helpBody.Contains(marker, StringComparison.Ordinal),
                            name + "_content_explains_next_action");
                        Check(helpBody.Contains("关闭本说明不会修改设置", StringComparison.Ordinal),
                            name + "_states_help_has_no_side_effect");
                        Capture(name, hwnd);
                    }
                    catch (Exception error) { deferredError = error; }
                    finally { PostMessageW(hwnd, 0x100, new UIntPtr(27), IntPtr.Zero); }
                };
                using (var timer = new Timer(_ =>
                {
                    if (Interlocked.Increment(ref ticks) > 50)
                    { var current = appDialog; if (current is not null) PostMessageW(current.Window, 0x10, UIntPtr.Zero, IntPtr.Zero); }
                    else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero);
                }, null, 250, 100))
                {
                    SendMessageW(id == HelpId ? GetDlgItem(window, id) : PageHandle(id), 0xF5, IntPtr.Zero, IntPtr.Zero);
                }
                uxProbeAction = null; Pump();
                if (deferredError is not null) throw deferredError;
                Check(observed && IsWindowEnabled(window) && model.Draft == draftBeforeHelp
                    && (!surfaceFault || surfaceFault == faultBeforeHelp),
                    name + "_opens_and_closes_without_changing_draft");
            }
            HelpCase(HelpId, "usage-guide", "第一次使用");
            HelpCase(RuleHelpId, "rule-help", "当前规则层：04");
            int menuTicks = 0; bool menuObserved = false;
            uxProbeAction = () =>
            {
                if (menuObserved) return;
                IntPtr popup = IntPtr.Zero;
                EnumThreadWindows(GetCurrentThreadId(), (hwnd, _) =>
                { var name = new StringBuilder(64); GetClassNameW(hwnd, name, 64); if (name.ToString() == "#32768" && IsWindowVisible(hwnd)) popup = hwnd; return true; }, IntPtr.Zero);
                if (popup == IntPtr.Zero) return;
                menuObserved = true;
                try { Capture("program-menu", popup); Check(menuLabels.Count == 3, "three_menu_items_keep_accessible_names"); }
                catch (Exception error) { deferredError = error; }
                finally { PostMessageW(window, 0x1F, UIntPtr.Zero, IntPtr.Zero); }
            };
            using (var timer = new Timer(_ => { if (Interlocked.Increment(ref menuTicks) > 50) PostMessageW(window, 0x1F, UIntPtr.Zero, IntPtr.Zero); else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero); }, null, 300, 100))
                ShowProgramActionMenu();
            uxProbeAction = null;
            if (deferredError is not null) throw deferredError;
            Check(menuObserved && menuLabels.Count == 0, "menu_cancel_releases_accessible_data");
            foreach (bool readOnly in new[] { false, true })
            {
                page = readOnly ? 4 : 2; privacyTab = 0; BuildPage(); UpdateChrome(); Pump();
                var edit = PageHandle(readOnly ? 486 : WordsId); SetFocus(edit);
                var previousKeys = new byte[256];
                Check(GetKeyboardState(previousKeys), "read_thread_local_key_state");
                try
                {
                    var keys = (byte[])previousKeys.Clone(); keys[17] = 0x80;
                    Check(SetKeyboardState(keys), "set_fixture_thread_local_control_modifier");
                    SendMessageW(edit, 0x100, new IntPtr(65), IntPtr.Zero);
                }
                finally { SetKeyboardState(previousKeys); }
                GetEditSelection(edit, 0xB0, out int selectedStart, out int selectedEnd);
                Check(selectedStart == 0 && selectedEnd == Text(edit).Length, "edit_control_a_" + readOnly);
                SendMessageW(edit, 0xB1, new IntPtr(1), new IntPtr(5));
                int ticks = 0; bool observed = false;
                uxProbeAction = () =>
                {
                    if (observed) return;
                    IntPtr popup = IntPtr.Zero;
                    EnumThreadWindows(GetCurrentThreadId(), (hwnd, _) =>
                    { var name = new StringBuilder(64); GetClassNameW(hwnd, name, 64); if (name.ToString() == "#32768" && IsWindowVisible(hwnd)) popup = hwnd; return true; }, IntPtr.Zero);
                    if (popup == IntPtr.Zero) return;
                    observed = true;
                    try { Capture(readOnly ? "readonly-context-menu" : "editable-context-menu", popup); Check(menuLabels.Count == (readOnly ? 2 : 6), "edit_menu_actions_" + readOnly); }
                    catch (Exception error) { deferredError = error; }
                    finally { PostMessageW(window, 0x1F, UIntPtr.Zero, IntPtr.Zero); }
                };
                using (var timer = new Timer(_ => { if (Interlocked.Increment(ref ticks) > 50) PostMessageW(window, 0x1F, UIntPtr.Zero, IntPtr.Zero); else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero); }, null, 300, 100))
                    SendMessageW(edit, 0x7B, edit, new IntPtr(-1));
                uxProbeAction = null;
                if (deferredError is not null) throw deferredError;
                GetEditSelection(edit, 0xB0, out int restoredStart, out int restoredEnd);
                Check(observed && restoredStart == 1 && restoredEnd == 5 && menuLabels.Count == 0, "edit_menu_cancel_keeps_selection_" + readOnly);
            }
            Check(!surfaceFault, "no_native_callback_fault");
            Check(preview && core is null && !Dirty && saved.Revision == "synthetic-workspace", "real_permissions_untouched");
            passed = true;
            return new { passed, assertions, frames = frames.Count, scope = "owned Medium native synthetic UI only; no install or real policy changes" };
        }
        finally
        {
            uxProbeAction = null;
            if (window != IntPtr.Zero) DestroyWindow(window);
            File.WriteAllText(Path.Combine(directory, "ux-proof.json"), JsonSerializer.Serialize(new { passed, assertions, failedCheck, frames }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct ComboInfo
    { public uint Size; public Rect Item, Button; public uint State; public IntPtr Combo, Edit, List; }
    [DllImport("user32.dll")] private static extern bool GetComboBoxInfo(IntPtr hwnd, ref ComboInfo info);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] private static extern bool EnumThreadWindows(uint thread, EnumProc callback, IntPtr data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int count);
    [DllImport("user32.dll")] private static extern bool GetKeyboardState(byte[] keys);
    [DllImport("user32.dll")] private static extern bool SetKeyboardState(byte[] keys);
}
