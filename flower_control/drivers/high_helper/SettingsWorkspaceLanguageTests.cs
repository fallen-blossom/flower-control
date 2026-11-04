using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    internal static object LanguageSelfTest(string directory)
    {
        if (window != IntPtr.Zero) throw new Boundary("settings_language_fixture_requires_fresh_process");
        Directory.CreateDirectory(directory);
        int assertions = 0; var frames = new List<object>();
        void Check(bool condition, string name) { assertions++; if (!condition) throw new InvalidOperationException("settings_language_test_" + name); }
        void Pump() { while (PeekMessageW(out var message, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref message); DispatchMessageW(ref message); } }
        void Capture(string name)
        {
            UpdateWindow(window); GetWindowRect(window, out var bounds);
            string path = Path.Combine(directory, name + ".png");
            SettingsArtwork.SaveWindowPng(window, bounds.Right - bounds.Left, bounds.Bottom - bounds.Top, path);
            frames.Add(new { path, language = UiText.Language, synthetic = true, capture_backend = "PrintWindow exact owned native window" });
        }
        preview = true; standalone = false; core = null; UiText.SetLanguage("zh-CN"); Initialize(Synthetic()); page = 3;
        bool passed = false;
        try
        {
            Create(); Pump();
            model.Edit(value => value with { HudCompact = !value.HudCompact });
            wordDraft = "do-not-translate 决策 C:\\private\\用户内容.txt";
            decisionDraft = DecisionProviderSettings.Legacy().Enable("jev", true);
            string before = JsonSerializer.Serialize(CaptureHandoff());
            Check(Dirty, "unrelated_drafts_present");
            Check(PageHandle(DisplayLanguageId) != IntPtr.Zero && Text(PageHandle(DisplayLanguageId)).Length > 0, "general_language_selector_reachable");
            SetFocus(PageHandle(DisplayLanguageId)); Capture("chinese-general");
            RequestDisplayLanguage("en"); Pump();
            Check(UiText.English && displayPreference.Language == "en", "preview_switch_english");
            Check(JsonSerializer.Serialize(CaptureHandoff()) == before && Dirty, "switch_keeps_every_original_draft_and_baseline");
            Check(Text(GetDlgItem(window, NavBase + 3)) == UiText.Get("常规"), "navigation_caption_retranslated");
            Check(GetDlgCtrlID(GetFocus()) == DisplayLanguageId, "language_selector_focus_retained");
            Check(Text(PageHandle(CompactId)) == UiText.Get("紧凑显示任务、阶段和停止入口"), "real_child_control_retranslated");
            Check(TrayMenu.BuildRows(false, AuthorityPresentation.Label(2), "fixture").First(row => row.Id == 3).Label == "Settings", "tray_menu_uses_same_language");
            Capture("english-general");
            page = 0; BuildPage(); UpdateChrome(); Pump(); Capture("english-overview");
            page = 3; BuildPage(); UpdateChrome(); Pump(); SetFocus(PageHandle(DisplayLanguageId));
            RequestDisplayLanguage("zh-CN"); Pump();
            Check(!UiText.English && Text(GetDlgItem(window, NavBase + 3)) == "常规", "switch_back_chinese");
            Check(JsonSerializer.Serialize(CaptureHandoff()) == before && Dirty, "second_switch_preserves_all_drafts");
            Capture("chinese-general-restored");
            page = 2; privacyTab = 2; BuildPage(); UpdateChrome(); Pump();
            var invalidRule = PageHandle(RulesId);
            SetWindowTextW(invalidRule, "unfinished-path");
            SendMessageW(window, 0x111, new IntPtr(RulesId | (0x300 << 16)), invalidRule); Pump();
            SetFocus(invalidRule); SendMessageW(invalidRule, 0xB1, new IntPtr(2), new IntPtr(8));
            long selection = SendMessageW(invalidRule, 0xB0, IntPtr.Zero, IntPtr.Zero).ToInt64();
            Check(invalidEdit && FieldText(RulesId) == "unfinished-path", "real_invalid_rule_edit_retained");
            int preferenceReads = 0;
            RefreshDisplayPreferenceFrom(() => { preferenceReads++; return new("en"); }); Pump();
            Check(preferenceReads == 0 && !UiText.English && invalidEdit, "external_refresh_deferred_before_read");
            Check(PageHandle(RulesId) == invalidRule && FieldText(RulesId) == "unfinished-path"
                && SendMessageW(invalidRule, 0xB0, IntPtr.Zero, IntPtr.Zero).ToInt64() == selection
                && GetFocus() == invalidRule, "external_refresh_keeps_raw_text_selection_and_focus");
            RequestDisplayLanguage("en"); Pump();
            Check(invalidEdit && !UiText.English && PageHandle(RulesId) == invalidRule
                && FieldText(RulesId) == "unfinished-path"
                && SendMessageW(invalidRule, 0xB0, IntPtr.Zero, IntPtr.Zero).ToInt64() == selection,
                "local_language_request_keeps_invalid_raw_edit");
            string correctedRule = Environment.ProcessPath!;
            SetWindowTextW(invalidRule, correctedRule);
            SendMessageW(window, 0x111, new IntPtr(RulesId | (0x300 << 16)), invalidRule); Pump();
            Check(!invalidEdit, "corrected_rule_passes_real_edit_validation");
            RefreshDisplayPreferenceFrom(() => { preferenceReads++; return new("en"); }); Pump();
            Check(preferenceReads == 1 && UiText.English && page == 2 && privacyTab == 2
                && FieldText(RulesId) == correctedRule && GetDlgCtrlID(GetFocus()) == RulesId,
                "deferred_language_applies_after_correction_on_same_page");
            page = 3; generalSection = 0; BuildPage(); UpdateChrome(); Pump();
            invalidEdit = true;
            SendMessageW(PageHandle(DisplayLanguageId), 0x14E, IntPtr.Zero, IntPtr.Zero);
            PageCommand(DisplayLanguageId, 1); Pump();
            Check(invalidEdit && UiText.English && displayPreference.Language == "en"
                && SendMessageW(PageHandle(DisplayLanguageId), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32() == 1
                && notice == UiText.Get("当前字段无效，请先修正或重新载入；原输入保留。"),
                "local_combo_reverts_selection_and_explains_invalid_edit");
            invalidEdit = false;
            Check(preview && core is null && saved.Revision == "synthetic-workspace" && displayPreference.Revision is null, "preview_never_writes_live_preference_or_policy");
            passed = true;
            return new { passed, assertions, frames = frames.Count, scope = "owned Medium synthetic settings and tray labels; no live preference/permission writes, High, installation, external UI or input" };
        }
        finally
        {
            if (window != IntPtr.Zero) DestroyWindow(window);
            UiText.SetLanguage("zh-CN");
            File.WriteAllText(Path.Combine(directory, "language-proof.json"), JsonSerializer.Serialize(new { passed, assertions, frames }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
}
