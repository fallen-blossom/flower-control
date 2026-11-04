using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    // Only caller-owned temporary state and this synthetic Medium preview.
    // No real settings, credentials, browser, UAC, Stop or physical input.
    internal static object DecisionSettingsSelfTest(string? evidenceDirectory = null)
    {
        int assertions = 0, captures = 0; string? failedCheck = null, failure = null;
        void Check(bool condition, string name) { assertions++; if (!condition) { failedCheck = name; throw new InvalidOperationException("decision_settings_test: " + name); } }
        bool Refused(Action operation, string? code = null)
        {
            try { operation(); return false; }
            catch (Boundary error) { return code is null || error.Code == code; }
            catch (JsonException) { return code is null; }
            catch (InvalidOperationException) { return code is null; }
        }
        string fixture = Path.Combine(Path.GetTempPath(), "flower-decision-settings-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture); string path = Path.Combine(fixture, DecisionProviderSettings.FileName);
        var absent = DecisionProviderSettings.Read(path);
        Check(absent.Legacy && absent.Revision is null && absent.Value!.Order.SequenceEqual(["jev", "host", "perplexity"])
            && absent.Value.Enabled.Length == 0 && !File.Exists(path), "missing_config_keeps_legacy_disabled_without_write");
        File.WriteAllText(Path.Combine(fixture, "jev.json"), "{\"schema\":1,\"enabled\":true}", new UTF8Encoding(false));
        var legacy = DecisionProviderSettings.Read(path);
        Check(legacy.Value!.Enabled.SequenceEqual(["jev"]) && legacy.Value.ActiveOrder().SequenceEqual(["jev"]), "legacy_jev_does_not_enable_perplexity");
        File.WriteAllText(Path.Combine(fixture, "jev.json"), "{\"schema\":true,\"enabled\":true}", new UTF8Encoding(false));
        Check(DecisionProviderSettings.Read(path).Value!.Enabled.Length == 0, "boolean_legacy_schema_never_enables_api");
        File.WriteAllText(Path.Combine(fixture, "jev.json"), "{\"schema\":1,\"enabled\":true}", new UTF8Encoding(false));
        var preferred = legacy.Value.Move(2, -1).Move(1, -1).Enable("perplexity", true);
        Check(preferred.Order.SequenceEqual(["perplexity", "jev", "host"]), "user_reorder_keeps_all_three_unique");
        var committed = DecisionProviderSettings.Save(path, legacy.Revision, preferred);
        var reopened = DecisionProviderSettings.Read(path);
        Check(!reopened.Legacy && reopened.Error is null && reopened.Value!.Same(preferred)
            && reopened.Revision == committed.Revision, "actual_atomic_save_and_reopen_preserve_order_and_enablement");
        Check(reopened.Value!.ActiveOrder().SequenceEqual(["perplexity", "jev"]), "preferred_order_reaches_both_apis");
        using (var document = JsonDocument.Parse(File.ReadAllBytes(path)))
            Check(document.RootElement.EnumerateObject().Select(x => x.Name).ToHashSet().SetEquals(["schema", "order", "enabled", "models"]), "saved_shape_has_no_key_or_extra_fields");
        var fallback = preferred.Move(2, -1);
        committed = DecisionProviderSettings.Save(path, reopened.Revision, fallback);
        Check(DecisionProviderSettings.Read(path).Value!.ActiveOrder().SequenceEqual(["perplexity"]), "host_ends_automatic_fallback_even_if_later_api_enabled");
        string latestBytes = File.ReadAllText(path);
        Check(Refused(() => DecisionProviderSettings.Save(path, reopened.Revision, preferred), "decision_settings_conflict")
            && File.ReadAllText(path) == latestBytes, "stale_revision_cannot_overwrite_new_service_settings");
        string external = latestBytes + "\n";
        Check(Refused(() => DecisionProviderSettings.Save(path, committed.Revision, preferred,
            beforeReplace: () => File.WriteAllText(path, external, new UTF8Encoding(false))), "decision_settings_conflict")
            && File.ReadAllText(path) == external, "final_cas_preserves_external_change_after_temp_write");
        Check(Directory.GetFiles(fixture, "*.tmp").Length == 0, "failed_cas_removes_own_temp_file");
        string valid = "{\"schema\":1,\"order\":[\"perplexity\",\"jev\",\"host\"],\"enabled\":[\"perplexity\",\"jev\"],\"models\":{\"perplexity\":\"pplx-decider-v1.2\",\"jev\":\"jev-1.13.0\"}}";
        foreach (string invalid in new[] {
            valid.Replace("\"schema\":1", "\"schema\":true"),
            valid.Replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
            valid.Replace("[\"perplexity\",\"jev\",\"host\"]", "[\"perplexity\",\"jev\",\"jev\"]"),
            valid.Replace("\"enabled\":[\"perplexity\",\"jev\"]", "\"enabled\":[\"host\"]"),
            valid.Replace("\"enabled\":[\"perplexity\",\"jev\"]", "\"enabled\":[\"jev\",\"jev\"]"),
            valid.Replace("pplx-decider-v1.2", "unapproved-model"),
            valid.Replace("\"models\":{", "\"api_key\":\"fixture\",\"models\":{") })
            Check(Refused(() => DecisionProviderSettings.Parse(Encoding.UTF8.GetBytes(invalid))), "invalid_config_refused");
        File.WriteAllText(path, "{bad-json", new UTF8Encoding(false));
        var corrupt = DecisionProviderSettings.Read(path);
        Check(corrupt.Error == "invalid_decision_settings" && corrupt.Value is null, "invalid_config_is_disabled_with_explanation");
        Check(Refused(() => DecisionProviderSettings.Save(path, corrupt.Revision, preferred), "invalid_decision_settings")
            && File.ReadAllText(path) == "{bad-json", "invalid_config_is_never_silently_reset");
        File.WriteAllText(path, valid, new UTF8Encoding(false));
        var fixedModels = preferred with { PerplexityModel = "pplx-decider-flash-v1.2", JevModel = "jev-1.14.0" };
        committed = DecisionProviderSettings.Save(path, DecisionProviderSettings.Read(path).Revision, fixedModels);
        Check(DecisionProviderSettings.Read(path).Value!.Same(fixedModels), "known_pinned_models_are_preserved");
        Check(DecisionProviderSettings.MutexName(path) == DecisionProviderSettings.MutexName(path.Replace('\\', '/').ToUpperInvariant()), "mutex_normalization_is_case_and_separator_stable");

        preview = true; standalone = false; core = null; Initialize(Synthetic()); Create();
        void Pump() { while (PeekMessageW(out var queued, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref queued); DispatchMessageW(ref queued); } }
        void Click(int id) { SendMessageW(GetDlgItem(window, id), 0xF5, IntPtr.Zero, IntPtr.Zero); Pump(); }
        void AnswerDialog(int answer, Action action)
        {
            bool seen = false; int ticks = 0;
            uxProbeAction = () => {
                if (appDialog is not { Window: var dialog } || dialog == IntPtr.Zero) return;
                seen = true; PostMessageW(dialog, 0x111, new UIntPtr((uint)answer), IntPtr.Zero);
            };
            using var timer = new Timer(_ => {
                if (Interlocked.Increment(ref ticks) > 50 && appDialog is { } dialog) PostMessageW(dialog.Window, 0x10, UIntPtr.Zero, IntPtr.Zero);
                else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero);
            }, null, 40, 40);
            try { action(); Pump(); } finally { uxProbeAction = null; }
            Check(seen, "owned_draft_dialog_observed");
        }
        void Capture(string name)
        {
            if (evidenceDirectory is null) return;
            Directory.CreateDirectory(evidenceDirectory); UpdateWindow(window); Pump();
            Render(Path.Combine(evidenceDirectory, name + ".png")); captures++;
        }
        bool completed = false;
        try
        {
            Click(NavBase + 3); Check(PageHandle(DecisionServicesId) != IntPtr.Zero && PageHandle(SmoothId) == IntPtr.Zero, "general_entry_exists_and_smooth_checkbox_stays_removed");
            Check(IsWindowVisible(PageHandle(DecisionServicesId)), "decision_services_tab_is_visible");
            Click(DecisionServicesId);
            Check(generalSection == 2 && decisionSnapshot!.Legacy && !DecisionDirty && !Dirty, "opening_services_preserves_legacy_without_draft_or_policy_change");
            var serviceList = PageHandle(DecisionListId);
            GetClientRect(serviceList, out var serviceListBounds);
            int serviceRowHeight = SendMessageW(serviceList, 0x1A1, IntPtr.Zero, IntPtr.Zero).ToInt32();
            Check(serviceListBounds.Bottom >= serviceRowHeight * 4, "four_service_rows_are_visible");
            int priorSelection = decisionSelection;
            decisionSelection = Array.IndexOf(decisionDraft!.Order, "host"); BuildPage(); Pump();
            Check(PageHandle(DecisionHostNoticeId) != IntPtr.Zero && PageHandle(DecisionSelectedEnableId) == IntPtr.Zero
                && FieldText(DecisionHostNoticeId).Contains("可用", StringComparison.Ordinal),
                "main_model_is_an_available_host_not_an_unchecked_service");
            decisionSelection = priorSelection; BuildPage(); Pump();
            SendMessageW(PageHandle(DecisionListId), 0x186, new IntPtr(2), IntPtr.Zero);
            SendMessageW(window, 0x111, new IntPtr(DecisionListId | 1 << 16), PageHandle(DecisionListId));
            Pump();
            Click(DecisionUpId);
            Check(decisionSelection == 1 && decisionDraft!.Order.SequenceEqual(["jev", "perplexity", "host"]),
                "first_reorder_step_reaches_perplexity_above_host");
            Check(IsWindowEnabled(PageHandle(DecisionUpId)), "first_reorder_leaves_up_enabled");
            Click(DecisionUpId);
            Check(decisionSelection == 0 && decisionDraft!.Order.SequenceEqual(["perplexity", "jev", "host"]),
                "second_reorder_step_reaches_preferred_order");
            Click(DecisionSelectedEnableId);
            Check(decisionDraft!.Order.SequenceEqual(["perplexity", "jev", "host"]) && decisionDraft.Enabled.Contains("perplexity")
                && DecisionDirty && !Dirty, "native_reorder_and_api_toggle_are_independent_service_draft");
            Check(!IsWindowEnabled(PageHandle(DecisionUpId)) && IsWindowEnabled(PageHandle(DecisionDownId)), "reorder_boundary_buttons_are_disabled");
            var serviceBefore = decisionDraft.Copy(); Click(GeneralWebId); Click(GeneralPreferencesId); Click(DecisionServicesId);
            Check(decisionDraft!.Same(serviceBefore) && DecisionDirty && !Dirty, "service_draft_survives_general_page_navigation");
            model.Edit(x => x with { HudCompact = !x.HudCompact }); var policyDraft = draft;
            Check(StatusLine().Contains("服务", StringComparison.Ordinal) && StatusLine().Contains("权限", StringComparison.Ordinal),
                "combined_draft_status_names_both_scopes");
            AnswerDialog(2, RequestClose);
            Check(window != IntPtr.Zero && DecisionDirty && Dirty && decisionDraft!.Same(serviceBefore) && draft == policyDraft,
                "close_return_keeps_service_and_permission_drafts");
            AnswerDialog(7, RequestReload);
            Check(DecisionDirty && Dirty && decisionDraft!.Same(serviceBefore) && draft == policyDraft,
                "reload_cancel_keeps_service_and_permission_drafts");
            Click(DecisionSaveId);
            Check(!DecisionDirty && Dirty && draft == policyDraft && saved.Revision == "synthetic-workspace", "service_save_does_not_save_or_discard_main_permission_draft");
            decisionSelection = Array.IndexOf(decisionDraft!.Order, "jev"); BuildPage(); Pump();
            Click(DecisionSelectedEnableId); Check(DecisionDirty, "disable_api_creates_service_draft");
            RequestSave(); Pump();
            Check(!Dirty && DecisionDirty && !decisionDraft!.Enabled.Contains("jev")
                && StatusLine().Contains("decision服务", StringComparison.Ordinal), "main_permission_save_does_not_save_service_draft_and_status_says_so");
            Click(DecisionSaveId);
            Check(!DecisionDirty && !Dirty && !decisionSnapshot!.Value!.Enabled.Contains("jev"), "explicit_save_applies_disablement_to_preview_snapshot");
            Check(FieldText(DecisionInfoId).Contains("主模型之后的 API 不会自动调用"), "fallback_boundary_is_readable_in_page");
            Check(DecisionPrivacyText.Contains("不调用主模型来脱敏") && DecisionPrivacyText.Contains("不保证完整匿名"), "privacy_explains_local_redaction_and_limit");
            Check(DecisionPrivacyUrl(DecisionPerplexityPrivacyId) == "https://docs.perplexity.ai/docs/resources/privacy-security"
                && DecisionPrivacyUrl(DecisionJevPrivacyId) == "https://help.typesafe.ai/articles/5974925716-how-is-submitted-data-used-or-retained"
                && DecisionPrivacyUrl(99999) is null, "privacy_links_are_fixed_official_urls");
            Capture("decision-services-wide");
            GetWindowRect(window, out var full); GetClientRect(window, out var client);
            SetWindowPos(window, IntPtr.Zero, full.Left, full.Top, MinimumSurfaceSize(window).X, MinimumSurfaceSize(window).Y, 0x14); Pump();
            Check(pageControls.All(c => { GetWindowRect(c.Handle, out var bounds); MapWindowPoints(IntPtr.Zero, window, ref bounds, 2);
                return bounds.Left >= 0 && bounds.Right <= MinimumSurfaceSize(window).X && bounds.Bottom <= Layout.Status.Top; }), "compact_service_controls_clear_fixed_footer");
            Check(!IsWindowVisible(GetDlgItem(window, StopId)), "computer_stop_is_not_shown_on_services_page");
            Capture("decision-services-compact");
            SetWindowPos(window, IntPtr.Zero, full.Left, full.Top, full.Right - full.Left, full.Bottom - full.Top, 0x14); Pump();
            decisionSnapshot = new(null, Error: "invalid_decision_settings"); decisionDraft = null; BuildPage(); UpdateChrome(); Pump();
            Check(!IsWindowEnabled(PageHandle(DecisionSaveId)) && !IsWindowEnabled(PageHandle(DecisionSelectedEnableId))
                && FieldText(DecisionInfoId).Contains("不会用默认值覆盖"), "invalid_config_cannot_be_saved_or_enabled_in_ui");
            Capture("decision-services-invalid");
            decisionSnapshot = new(DecisionProviderSettings.Legacy(), Legacy: true);
            decisionDraft = decisionSnapshot.Value!.Copy().Enable("jev", true);
            model.Edit(x => x with { HudCompact = !x.HudCompact });
            BuildPage(); UpdateChrome(); Pump();
            Check(DecisionDirty && Dirty, "save_all_close_has_both_draft_scopes");
            AnswerDialog(6, RequestClose);
            Pump();
            Check(window == IntPtr.Zero && !DecisionDirty && !Dirty,
                "save_all_close_saves_services_then_permissions_before_exit");
            // A frozen legacy role may still save independent service settings
            // and close. It must never need a role change for that clean close.
            Initialize(UserPermissions.Effective(Synthetic() with { AuthorityTier = 3, UacMode = "allowlist" }));
            page = 3; generalSection = 2; Create(); Pump();
            var frozenPolicy = saved;
            decisionDraft = decisionSnapshot!.Value!.Copy().Enable("perplexity", true);
            Check(DecisionDirty && !Dirty && !IsWindowEnabled(GetDlgItem(window, SaveId)), "legacy_uac_only_service_draft_is_independent");
            AnswerDialog(6, RequestClose); Pump();
            Check(window == IntPtr.Zero && !DecisionDirty && saved == frozenPolicy && model.EffectiveTier == 3,
                "legacy_uac_service_save_closes_without_permission_write_or_role_change");
            Initialize(frozenPolicy); page = 3; Create(); Pump();
            model.Edit(x => x with { HudCompact = !x.HudCompact });
            RequestSave(true); Pump();
            Check(window != IntPtr.Zero && Dirty && saved == frozenPolicy && model.EffectiveTier == 3 && notice.Contains("冻结"),
                "legacy_uac_main_dirty_save_remains_blocked_and_preserves_draft");
            AnswerDialog(7, RequestClose); Pump();
            completed = true;
        }
        catch (Exception error) { failure = error.ToString(); throw; }
        finally
        {
            if (window != IntPtr.Zero) DestroyWindow(window);
            if (evidenceDirectory is not null) File.WriteAllText(Path.Combine(evidenceDirectory, "decision-settings-proof.json"), JsonSerializer.Serialize(new {
                completed, assertions, captures, failedCheck, failure, fixture, cross_language_file = path, mutex = DecisionProviderSettings.MutexName(path),
                observed = new { selection = decisionSelection, order = decisionDraft?.Order, enabled = decisionDraft?.Enabled, generalSection, page },
                assembly = typeof(SettingsWorkspace).Assembly.Location, assembly_sha256 = Native.Digest(typeof(SettingsWorkspace).Assembly.Location),
                scope = "owned temporary actual provider-config storage and synthetic native preview only; no installed state, credentials, API request, UAC, Stop or physical input"
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        return new { assertions, captures, fixture, completed };
    }
}
