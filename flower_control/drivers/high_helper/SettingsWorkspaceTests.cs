using System.Reflection;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    // Owned Medium preview only. Native controls use their real command path,
    // while persistence uses preview memory and fresh temporary fixture files.
    internal static object SelfTest(string? evidenceDirectory = null)
    {
        int assertions = 0;
        void Check(bool value, string name) { assertions++; if (!value) throw new InvalidOperationException("workspace_test: " + name); }
        var baseline = Synthetic(); var m = new SettingsWorkspaceModel(baseline);
        Check(!m.Dirty, "initial_clean"); m.SelectTier(2);
        Check(m.DraftTier == 2 && !m.Dirty, "same_tier_is_idempotent");
        m.SelectTier(-1);
        Check(m.DraftTier == -1 && m.EffectiveTier == 2, "explicit_stop_is_only_draft_in_preview");
        Check(m.Draft.AdminLaunchAllowlist.Length == 2, "lower_tier_preserves_lists");
        m.SelectTier(0); var submitted = m.Draft;
        m.Edit(x => x with { HudCompact = !x.HudCompact });
        m.Commit(submitted, submitted with { Revision = "committed" });
        Check(m.Dirty && m.Draft.HudCompact != m.Saved.HudCompact && m.Draft.Revision == "committed", "late_edits_preserved");
        m.Reload(baseline);
        m.AddProgram(3, true, new(@"E:\Preview\Denied.exe", "sha256", new string('c', 64), "禁止示例", true, ""));
        Check(m.Draft.DeniedUacApplications.Length == 1 && m.Draft.AdminLaunchAllowlist.Length == 2 && m.Draft.UacAllowlist.Length == 0, "all_lists_independent");
        m.SelectTier(1); Check(m.Draft.AdminScope == baseline.AdminScope, "scope_preserved");
        m.Reload(baseline with { AuthorityTier = 3, UacMode = "allowlist" });
        m.Edit(x => x with { HudCompact = true, DeniedAdminWindowApplications = [new(@"E:\Preview\Keep.exe", "保留")] });
        m.ReconcileImmediateRevoke(UserPermissions.WithoutUac(m.Saved) with { Revision = "revoked" });
        Check(m.DraftTier == 2 && m.EffectiveTier == 2 && m.Draft.HudCompact && m.Draft.DeniedAdminWindowApplications.Length == 1 && m.Dirty, "immediate_revoke_keeps_unrelated_drafts");
        var acceptedOff = m.Saved;
        m.ReconcileImmediateRevoke(acceptedOff with { Revision = "external", HudPosition = "bottom_right" });
        Check(m.Conflict && m.Saved.Revision == "revoked" && m.Draft.Revision == "revoked"
            && m.Draft.HudCompact && m.Draft.DeniedAdminWindowApplications.Length == 1, "immediate_revoke_external_change_keeps_old_cas");
        m.ReconcileImmediateRevoke(acceptedOff with { Revision = "later" });
        Check(m.Conflict && m.Saved.Revision == "revoked" && m.Draft.Revision == "revoked", "immediate_revoke_conflict_is_sticky");
        var oldArgument = baseline.AdminLaunchAllowlist[0] with { Arguments = "--existing=exact" };
        m.Reload(baseline with { AdminLaunchAllowlist = [oldArgument] }); m.AddProgram(2, false, oldArgument with { Arguments = "" });
        Check(m.Draft.AdminLaunchAllowlist.Length == 2 && m.Draft.AdminLaunchAllowlist[0].Arguments == "--existing=exact", "exact_argument_rule_preserved");
        var overlapProgram = oldArgument with { Arguments = "" };
        m.Reload(baseline with { AdminLaunchAllowlist = [oldArgument, overlapProgram], DeniedAdminLaunchApplications = [overlapProgram] });
        Check(m.ProgramsOverlap(2), "legacy_overlap_is_reported_without_migration");
        m.AddProgram(2, true, overlapProgram, true);
        Check(!m.ProgramsOverlap(2) && m.Programs(2, false).Length == 0 && m.Programs(2, true).Length == 1
            && m.Saved.AdminLaunchAllowlist.Length == 2, "confirmed_move_changes_both_drafts_only");
        m.Reload(m.Saved);
        Check(m.ProgramsOverlap(2) && m.Programs(2, false).Length == 2, "discard_move_restores_both_sides");
        m.Reload(baseline with { DeniedApplications = [new(@"E:\Preview\Same.exe", "秘密"), new(@"E:\Preview\Same.exe", "", false)] });
        m.AddWindowRule(0, @"E:\Preview\Same.exe");
        Check(m.Draft.DeniedApplications.Length == 3 && m.Draft.DeniedApplications[0].TitleContains == "秘密" && !m.Draft.DeniedApplications[1].Enabled, "window_title_and_disabled_rules_preserved");

        var legacy = PermissionSettingsWindow.CreateRoleHandoff(baseline with { HudCompact = !baseline.HudCompact }, baseline,
            new("synthetic-word", "synthetic"), new(), "allowlist", "allowlist", false, 3);
        var oldUacView = PrepareSurfaceImport(baseline, legacy);
        Check(!oldUacView.Surface.Legacy && oldUacView.Surface.Page == 4 && oldUacView.Surface.RuleLayer == 2
            && oldUacView.Model.Draft.HudCompact != baseline.HudCompact && oldUacView.Model.EffectiveTier == 2,
            "legacy_uac_page_maps_to_frozen_diagnostics_without_role_or_draft_loss");
        var unreadableLegacy = PrepareSurfaceImport(baseline with { Revision = "role-updated", UacPolicyError = "fixture-unreadable" }, legacy);
        Check(unreadableLegacy.Model.Conflict && unreadableLegacy.Model.Draft.Revision == baseline.Revision
            && unreadableLegacy.Model.Draft.HudCompact != baseline.HudCompact,
            "new_import_preserves_sidecar_error_conflict_and_original_cas");
        var normal = legacy with { Legacy = false, Page = 2, RuleLayer = 1 };
        var privacyView = PrepareSurfaceImport(baseline, normal);
        Check(privacyView.Surface.Page == 2 && privacyView.Surface.RuleLayer == 1 && !privacyView.Model.Conflict,
            "current_handoff_keeps_page_and_rules");
        var unreadableCurrent = PrepareSurfaceImport(baseline with { Revision = "sidecar-changed", UacPolicyError = "fixture-unreadable" }, normal);
        Check(unreadableCurrent.Model.Conflict && unreadableCurrent.Model.Draft.Revision == baseline.Revision,
            "current_import_also_preserves_sidecar_error_conflict");

        string fixture = Path.Combine(Path.GetTempPath(), "flower-settings-words-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(fixture);
        string file = Path.Combine(fixture, "sensitive-words.txt"), sid = baseline.UserSid;
        var save = typeof(UserPermissions).GetMethod("SaveSettingsWordsAt", BindingFlags.NonPublic | BindingFlags.Static)!;
        var read = typeof(UserPermissions).GetMethod("ReadSettingsWordsAt", BindingFlags.NonPublic | BindingFlags.Static)!;
        var ws = (SettingsWordSnapshot)save.Invoke(null, [file, "测试词\r\nsecret", "absent", sid, true])!;
        Check(ws.Text.Contains("测试词") && ((SettingsWordSnapshot)read.Invoke(null, [file, true])!).Revision == ws.Revision, "unicode_words_roundtrip");
        bool conflict = false; try { save.Invoke(null, [file, "overwrite", "absent", sid, true]); } catch (TargetInvocationException error) { conflict = error.InnerException is Boundary b && b.Code == "privacy_words_changed"; }
        Check(conflict && File.ReadAllText(file).Contains("测试词"), "word_cas_preserves_existing");
        bool invalid = false; try { UserPermissions.ValidateSettingsWords(new string('x', 201)); } catch (Boundary) { invalid = true; }
        Check(invalid, "oversize_word_refused");

        preview = true; standalone = false; core = null; Initialize(baseline); Create();
        var captures = new List<object>();
        bool completed = false; string? failure = null;
        void WriteCaptureProof()
        {
            if (evidenceDirectory is null) return;
            Directory.CreateDirectory(evidenceDirectory);
            File.WriteAllText(Path.Combine(evidenceDirectory, "capture-proof.json"), JsonSerializer.Serialize(new { completed, failure, assertions, captures, scope = "owned native preview; synthetic BM_CLICK/WM_SETTEXT; no actual policy, UAC or foreground control task" }, new JsonSerializerOptions { WriteIndented = true }));
        }
        void Capture(string name)
        {
            if (evidenceDirectory is null) return;
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            Console.Error.WriteLine("settings_capture_begin: " + name);
            Directory.CreateDirectory(evidenceDirectory); ShowWindow(window, 5); UpdateWindow(window); Native.SetForegroundWindow(window);
            while (PeekMessageW(out var queued, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref queued); DispatchMessageW(ref queued); }
            Thread.Sleep(150); UpdateWindow(window);
            GetWindowRect(window, out var bounds); GetClientRect(window, out var client);
            bool foregroundBefore = Native.GetForegroundWindow() == window;
            var started = DateTimeOffset.Now;
            string output = Path.Combine(evidenceDirectory, name + ".png"); Render(output);
            bool foregroundAfter = Native.GetForegroundWindow() == window;
            captures.Add(new
            {
                file = output,
                pid = Environment.ProcessId,
                hwnd = window.ToInt64(),
                capture_started = started,
                time = DateTimeOffset.Now,
                foreground = foregroundBefore && foregroundAfter,
                foreground_before = foregroundBefore,
                foreground_after = foregroundAfter,
                dpi = GetDpiForWindow(window),
                capture_backend = "PrintWindow full window",
                bounds_type = "window",
                coordinate_space = "physical_px",
                bounds = new[] { bounds.Left, bounds.Top, bounds.Right, bounds.Bottom },
                client_size = new[] { client.Right, client.Bottom },
                page,
                preview,
                assembly = typeof(SettingsWorkspace).Assembly.Location,
                assembly_sha256 = Native.Digest(typeof(SettingsWorkspace).Assembly.Location),
                postprocessed = false
            });
            WriteCaptureProof();
            Console.Error.WriteLine("settings_capture_end: " + name + " ms=" + elapsed.ElapsedMilliseconds);
        }
        void Click(int id)
        {
            SendMessageW(GetDlgItem(window, id), 0xF5, IntPtr.Zero, IntPtr.Zero);
            while (PeekMessageW(out var queued, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref queued); DispatchMessageW(ref queued); }
        }
        bool Overlaps(Rect a, Rect b) => a.Left < b.Right && b.Left < a.Right && a.Top < b.Bottom && b.Top < a.Bottom;
        try
        {
            Check(Native.ProtectedWindowOrOwner(window), "protected_surface_marker");
            var monitor = new MonitorInfo { Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MonitorInfo>() };
            Check(GetMonitorInfoW(MonitorFromWindow(window, 2), ref monitor) && monitor.Work.Right > monitor.Work.Left && monitor.Work.Bottom > monitor.Work.Top && monitor.Work.Left >= monitor.Monitor.Left && monitor.Work.Bottom <= monitor.Monitor.Bottom, "native_monitor_work_area_layout");
            Capture("overview");
            Rect ActualPageBounds(int id)
            {
                GetWindowRect(PageHandle(id), out var bounds);
                MapWindowPoints(IntPtr.Zero, window, ref bounds, 2); return bounds;
            }
            Check(PageHandle(EmergencyStopId) != IntPtr.Zero && IsWindowEnabled(PageHandle(EmergencyStopId))
                && PageHandle(ResumeAllId) != IntPtr.Zero && !IsWindowEnabled(PageHandle(ResumeAllId)),
                "overview_preview_has_emergency_stop_and_never_enables_real_resume");
            Check(new[] { FirstRunGuideId, EmergencyStopId, ResumeAllId }.All(id => ActualPageBounds(id).Bottom <= Layout.Notice.Top),
                "overview_product_actions_keep_clear_of_fixed_footer");
            var beforeEmergency = model.Draft;
            Click(EmergencyStopId);
            Check(SettingsWorkspaceModel.Same(beforeEmergency, model.Draft) && preview && core is null,
                "preview_emergency_stop_does_not_change_policy_or_real_stop");
            notice = ""; UpdateChrome();
            Check(PetalAnnotations.Length == 5 && PetalAnnotations[2] == "02  普通控制"
                && PetalAnnotations[3] == "04  管理员执行" && PetalAnnotations[4] == PetalAnnotations[3], "both_lower_petals_show_admin_execution");
            Check(!UserFacingError("jev_disabled").Contains("jev_disabled", StringComparison.Ordinal)
                && UserFacingError("jev_disabled").Contains("主模型", StringComparison.Ordinal), "jev_disabled_has_user_facing_main_model_explanation");
            Click(NavBase + 1);
            Check(page == 1 && SendMessageW(PageHandle(ProgramListId), 0x18B, IntPtr.Zero, IntPtr.Zero).ToInt32() == 2, "native_permission_list");
            SetFocus(GetDlgItem(window, NavBase + 4));
            var tabMessage = new HostWindow.Message { Hwnd = GetFocus(), Kind = 0x100, Wp = new UIntPtr(9) };
            HandleDialogMessage(ref tabMessage); Check(GetFocus() == PageHandle(ViewLayerBase), "keyboard_navigation_then_visible_rule_buttons");
            Click(ViewLayerBase); Check(ruleLayer == 0 && tier == 2 && !Dirty, "viewing_rules_does_not_enable_a_tier");
            Click(ViewLayerBase + 2); Check(ruleLayer == 2 && PageHandle(LayerId) == IntPtr.Zero && PageHandle(ViewLayerBase + 3) == IntPtr.Zero, "three_rule_buttons_exclude_frozen_uac");
            Check(pageControls.Any(c => c.Id == RuleHelpId && c.Kind == "BUTTON")
                && GetDlgItem(window, HelpId) != IntPtr.Zero && IsWindowVisible(GetDlgItem(window, HelpId)),
                "usage_and_rule_help_are_visible_buttons");
            Check(!Overlaps(Layout.CurrentValue, Layout.SavedStatus) && !Overlaps(Layout.CurrentValue, Layout.PendingDraft)
                && !Overlaps(Layout.SavedStatus, Layout.PendingDraft) && !Overlaps(Layout.PendingDraft, Layout.TierCaption)
                && !Overlaps(Layout.TierCaption, Layout.Tier(0)),
                "permission_saved_and_pending_rows_have_separate_vertical_space");
            Check(Enumerable.Range(0, 4).All(i => Enumerable.Range(i + 1, 3 - i).All(j => !Overlaps(Layout.Tier(i), Layout.Tier(j)))),
                "permission_tiers_do_not_overlap_each_other");
            Check(!Overlaps(Layout.ViewBadge, Layout.ViewHelp) && !Overlaps(Layout.ViewHelp, Layout.ViewTab(0))
                && Enumerable.Range(0, 3).All(i => Enumerable.Range(i + 1, 2 - i).All(j => !Overlaps(Layout.ViewTab(i), Layout.ViewTab(j)))),
                "permission_view_badge_help_and_tabs_do_not_overlap");
            Check(!Overlaps(Layout.Help, Layout.Nav(4)) && !Overlaps(Layout.Help, Layout.PageTitle) && !Overlaps(Layout.Help, Layout.Brand),
                "usage_help_clear_of_navigation_title_and_brand");
            GetClientRect(window, out var permissionClient);
            Check(Layout.Tier(3).Bottom <= permissionClient.Bottom && Layout.ViewTab(2).Right <= permissionClient.Right,
                "permission_layout_stays_inside_client");
            SetFocus(window); Capture("permissions");
            Check(IsWindowVisible(PageHandle(ProgramMenuId)) && !IsWindowVisible(PageHandle(ToggleId)), "permission_actions_use_native_row_menu");
            var actionMenu = BuildProgramActionMenu();
            try { Check(GetMenuItemCount(actionMenu) == 3, "program_menu_preserves_three_actions"); } finally { DestroyMenu(actionMenu); }
            Check(VerifyProgramPopup(), "native_program_popup_opens_and_cancel_preserves_window");
            Check(VerifyProgramPopup(350), "slow_program_popup_is_observed_before_cancel");
            var listHandle = PageHandle(ProgramListId);
            Check(!SelectProgramMenuRow(listHandle, -1, 5) && !SelectProgramMenuRow(listHandle, 5, -1), "outside_program_release_cannot_open_row_menu");
            Check(SelectProgramMenuRow(listHandle, 10, ProgramRowHeight + 3) && Selection(ProgramListId) == 1, "context_menu_binds_clicked_program_row");
            SelectProgramMenuRow(listHandle, 10, 3);
            var originalPrograms = model.Programs(2, false);
            model.Programs(2, false, Enumerable.Range(0, 6).Select(i => originalPrograms[0] with { DisplayName = "合成程序菜单滚动核对 " + (i + 1), Path = @"E:\Preview\Menu" + i + ".exe" }).ToArray());
            BuildPage(); UpdateChrome(); listHandle = PageHandle(ProgramListId);
            SendMessageW(listHandle, 0x197, new IntPtr(3), IntPtr.Zero); PositionProgramMenu();
            Check(!IsWindowVisible(PageHandle(ProgramMenuId)), "scrolled_out_program_hides_its_action_button");
            SendMessageW(listHandle, 0x186, new IntPtr(3), IntPtr.Zero); PositionProgramMenu();
            GetClientRect(listHandle, out var listClient); MapWindowPoints(listHandle, IntPtr.Zero, ref listClient, 2);
            GetWindowRect(PageHandle(ProgramMenuId), out var menuBounds);
            Check(IsWindowVisible(PageHandle(ProgramMenuId)) && menuBounds.Right <= listClient.Right && menuBounds.Bottom <= listClient.Bottom, "row_menu_avoids_native_scrollbar_and_tracks_selection");
            Capture("permissions-long");
            SendMessageW(listHandle, 0x186, IntPtr.Zero, IntPtr.Zero); SendMessageW(listHandle, 0x197, IntPtr.Zero, IntPtr.Zero);
            model.Programs(2, false, originalPrograms); BuildPage(); UpdateChrome();
            // The visible row action is the native popup menu; its ToggleId
            // button is deliberately hidden. Exercise the exact command that
            // TrackPopupMenu returns instead of BM_CLICK on an invisible child.
            SendMessageW(window, 0x111, new IntPtr(ToggleId), IntPtr.Zero);
            Check(!model.Programs(2, false)[0].Enabled && saved.AdminLaunchAllowlist[0].Enabled, "program_menu_toggle_draft");
            Click(TierBase + 2); Check(model.EffectiveTier == 2 && tier == 1, "native_tier_draft_separation"); Capture("unsaved");
            Click(NavBase + 2); Check(page == 2, "privacy_navigation");
            SendMessageW(PageHandle(WordsId), 0xB1, IntPtr.Zero, new IntPtr(-1));
            SendMessageText(PageHandle(WordsId), 0xC2, new IntPtr(1), "合成敏感词\r\nsynthetic-secret");
            Check(Text(pageControls.Last().Handle).Contains("追加词表仍保留"), "privacy_help_native_text_complete");
            Check(wordDraft.Contains("synthetic-secret") && Dirty, "native_word_edit"); SetFocus(window); Capture("privacy");
            privacyTab = 2; BuildPage(); UpdateChrome(); SetFocus(window); Capture("privacy-rules");
            Check(FieldText(RulesId) == RuleText(draft.DeniedApplications), "privacy_rules_keep_shared_draft");
            Click(NavBase + 3); Check(!model.Programs(2, false)[0].Enabled, "page_switch_preserves_rules");
            Click(CompactId); Check(draft.HudCompact, "native_checkbox");
            SetFocus(PageHandle(CompactId));
            SendMessageW(PageHandle(CompactId), 0x100, new IntPtr(32), IntPtr.Zero);
            SendMessageW(PageHandle(CompactId), 0x101, new IntPtr(32), IntPtr.Zero);
            Check(!draft.HudCompact, "native_checkbox_space");
            Click(CompactId); SetFocus(window); Capture("appearance");
            model.Conflict = true; UpdateChrome(); RequestSave(); Check(saved.Revision == baseline.Revision && Dirty, "conflict_retains_draft"); model.Conflict = false; UpdateChrome();
            Click(SaveId); Check(model.EffectiveTier == 1 && !Dirty && saved.HudCompact && words.Text.Contains("synthetic-secret"), "preview_save_commits_same_snapshot");
            Check(preview && core is null, "no_live_broker_or_policy_write");
            Click(NavBase + 4); SetFocus(window); Capture("diagnostics");
            Check(new[] { ReadOnlyCheckId, RepairSurfaceId, ExportDiagnosticsId, ExportSettingsId, ImportSettingsId,
                StorageUsageId, CacheCleanupId }.All(id => PageHandle(id) != IntPtr.Zero
                    && ActualPageBounds(id).Bottom <= Layout.Notice.Top), "diagnostic_maintenance_actions_keep_clear_of_footer");
            int firstLine = SendMessageW(PageHandle(486), 0xCE, IntPtr.Zero, IntPtr.Zero).ToInt32();
            SendMessageW(PageHandle(486), 0xB6, IntPtr.Zero, new IntPtr(3));
            Check(SendMessageW(PageHandle(486), 0xCE, IntPtr.Zero, IntPtr.Zero).ToInt32() > firstLine, "decorated_scrollbar_keeps_native_edit_scrolling");
            SendMessageW(PageHandle(486), 0xB6, IntPtr.Zero, new IntPtr(-3));
            SetFocus(GetDlgItem(window, NavBase + 4));
            tabMessage.Hwnd = GetFocus(); HandleDialogMessage(ref tabMessage);
            Check(GetFocus() == PageHandle(486), "diagnostic_text_keyboard_reachable");
            Check(PageHandle(482) == IntPtr.Zero && PageHandle(483) == IntPtr.Zero, "frozen_system_actions_absent");
            Click(NavBase + 1); ruleLayer = 3; BuildPage(); UpdateChrome();
            Check(model.Programs(3, false).Length == 0 && model.Programs(2, false).Length == 2, "independent_empty_uac_list");
            Check(ruleLayer == 2 && PageHandle(ViewLayerBase + 3) == IntPtr.Zero, "legacy_view_does_not_expose_uac");
            Capture("permissions-04-execution");
            ruleLayer = 0; BuildPage(); UpdateChrome(); SetFocus(window); Capture("permissions-01");
            Check(FieldText(RulesId) == RuleText(draft.DeniedApplications), "permission_window_rules_native_editor");
            ruleLayer = 1; BuildPage(); UpdateChrome(); SetFocus(window); Capture("permissions-02");
            RequestTier(3); Check(tier == 1 && notice.Contains("冻结"), "frozen_tier_request_keeps_current_tier");
            Click(NavBase + 2); privacyTab = 1; BuildPage(); UpdateChrome(); LoadMaskFields();
            SetWindowTextW(PageHandle(462), "240"); Check(draft.Masks[0].Rect[2] == 240, "mask_coordinate_edit");
            SetWindowTextW(PageHandle(462), "99999"); Check(invalidEdit, "invalid_mask_blocks_save");
            Click(MaskRemoveId); Check(draft.Masks.Length == 1 && FieldText(462) == "99999", "invalid_mask_remove_keeps_raw_input");
            var capturedDraft = draft; ApplySave(new("save", capturedDraft, capturedDraft with { Revision = "async-preview" }));
            Check(invalidEdit && FieldText(462) == "99999", "async_completion_keeps_invalid_raw_input");
            SetWindowTextW(PageHandle(462), "240"); Check(!invalidEdit, "invalid_mask_recoverable");
            GetWindowRect(pageControls.Last().Handle, out var maskHelp); MapWindowPoints(IntPtr.Zero, window, ref maskHelp, 2);
            Check(maskHelp.Bottom + Px(8) <= Layout.Add.Top, "mask_help_stays_clear_of_leaf_action"); SetFocus(window); Capture("privacy-masks");
            Click(MaskRemoveId); Check(draft.Masks.Length == 0, "mask_remove_draft");
            Check(!IsWindowEnabled(PageHandle(462)) && !IsWindowEnabled(PageHandle(MaskRemoveId)), "empty_mask_editor_disabled");
            Click(SaveId); Check(!Dirty, "second_preview_save");
            var clean = draft; ApplySave(new("save", clean, clean, PreferenceError: "settings_ui_preferences_changed"));
            Check(model.Conflict, "preference_cas_blocks_overwrite"); model.Conflict = false; preferencePending = false;
            ApplySave(new("save", clean, clean, WordError: "privacy_words_save_outcome_unknown")); Check(model.Conflict, "unknown_word_save_blocks_retry"); model.Conflict = false;
            GetWindowRect(window, out var full);
            var wideFont = SendMessageW(PageHandle(462), 0x31, IntPtr.Zero, IntPtr.Zero);
            var minMaxMemory = System.Runtime.InteropServices.Marshal.AllocHGlobal(System.Runtime.InteropServices.Marshal.SizeOf<MinMaxInfo>());
            try
            {
                System.Runtime.InteropServices.Marshal.StructureToPtr(new MinMaxInfo(), minMaxMemory, false);
                SendMessageW(window, 0x24, IntPtr.Zero, minMaxMemory);
                var limits = System.Runtime.InteropServices.Marshal.PtrToStructure<MinMaxInfo>(minMaxMemory);
                var minimumMonitor = new MonitorInfo { Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MonitorInfo>() };
                Check(GetMonitorInfoW(MonitorFromWindow(window, 2), ref minimumMonitor), "minimum_size_monitor_available");
                double dpiScale = Math.Max(96, GetDpiForWindow(window)) / 96.0;
                Check(limits.MinTrack.X == Math.Min((int)Math.Ceiling(1000 * dpiScale), minimumMonitor.Work.Right - minimumMonitor.Work.Left)
                    && limits.MinTrack.Y == Math.Min((int)Math.Ceiling(680 * dpiScale), minimumMonitor.Work.Bottom - minimumMonitor.Work.Top),
                    "native_minimum_track_size_preserves_logical_size_at_current_dpi");
            }
            finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(minMaxMemory); }
            SetWindowPos(window, IntPtr.Zero, full.Left, full.Top, MinimumSurfaceSize(window).X, MinimumSurfaceSize(window).Y, 0x14); GetClientRect(window, out var small);
            Check(SendMessageW(PageHandle(462), 0x31, IntPtr.Zero, IntPtr.Zero) != wideFont, "resize_updates_native_control_font");
            Check(Layout.Save.Right <= small.Right && Layout.Save.Bottom <= small.Bottom && Layout.Stop.Right <= small.Right && Layout.Stop.Bottom <= small.Bottom, "small_window_fixed_actions_reachable");
            Capture("compact-window");
            Click(NavBase + 3); Click(GeneralWebId); SetFocus(window);
            Check(generalSection == 1 && pageControls.Where(c => IsWindowVisible(c.Handle)).All(c =>
            {
                GetWindowRect(c.Handle, out var bounds); MapWindowPoints(IntPtr.Zero, window, ref bounds, 2);
                return bounds.Left >= 0 && bounds.Top >= 0 && bounds.Right <= small.Right && bounds.Bottom <= Layout.Status.Top - Px(2);
            }), "compact_browser_controls_clear_footer_status");
            Capture("compact-browser");
            var browserFields = pageControls.Where(c => IsWindowVisible(c.Handle)).ToArray();
            Rect VisibleFieldBounds(PageControl control)
            {
                GetWindowRect(control.Handle, out var rectangle);
                if (control.Kind == "COMBOBOX")
                {
                    var info = new ComboInfo { Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<ComboInfo>() };
                    Check(GetComboBoxInfo(control.Handle, ref info), "compact_browser_combo_geometry_available");
                    // GetWindowRect includes the reserved drop-down extent.
                    // The closed native field ends at its item/arrow bounds.
                    rectangle.Bottom = rectangle.Top + Math.Max(info.Item.Bottom, info.Button.Bottom) + Px(2);
                }
                return rectangle;
            }
            for (int i = 0; i < browserFields.Length; i++)
                for (int j = i + 1; j < browserFields.Length; j++)
                {
                    var left = VisibleFieldBounds(browserFields[i]);
                    var right = VisibleFieldBounds(browserFields[j]);
                    if (Overlaps(left, right)) Console.Error.WriteLine($"browser_sibling_overlap: {browserFields[i].Id}/{browserFields[i].Kind} {left.Left},{left.Top},{left.Right},{left.Bottom} vs {browserFields[j].Id}/{browserFields[j].Kind} {right.Left},{right.Top},{right.Right},{right.Bottom}");
                    Check(!Overlaps(left, right), $"compact_browser_sibling_controls_do_not_overlap_{i}_{j}");
                }
            Click(NavBase + 1); ruleLayer = 2; BuildPage(); UpdateChrome();
            Check(IsWindowVisible(PageHandle(ProgramMenuId)), "compact_permission_row_menu_reachable");
            Check(!Overlaps(Layout.Help, Layout.Nav(0)) && !Overlaps(Layout.Help, Layout.PageTitle)
                && !Overlaps(Layout.Help, Layout.Flower) && !Overlaps(Layout.ViewHelp, Layout.ViewTab(0))
                && !Overlaps(Layout.ViewHelp, Layout.PageLead),
                "compact_usage_and_rule_help_clear_of_page_chrome");
            Capture("compact-permissions");
            notice = "";
            foreach (int targetPage in new[] { 0, 2, 3, 4 })
            {
                if (targetPage == 2) privacyTab = 0;
                Click(NavBase + targetPage); SetFocus(window);
                Capture("compact-" + new[] { "overview", "permissions", "privacy", "appearance", "diagnostics" }[targetPage]);
                var fixedActions = new List<Rect> { Layout.Reload, Layout.Save, Layout.Status, Layout.Notice, Layout.NoticeDetails };
                if (targetPage == 0) fixedActions.Add(OverviewStopBounds());
                var offenders = new List<string>();
                foreach (var c in pageControls.Where(c => IsWindowVisible(c.Handle)))
                {
                    GetWindowRect(c.Handle, out var bounds); MapWindowPoints(IntPtr.Zero, window, ref bounds, 2);
                    bool inside = bounds.Left >= 0 && bounds.Top >= 0 && bounds.Right <= small.Right && bounds.Bottom <= small.Bottom;
                    // A static child can repaint across a fixed action too;
                    // keep its entire native text box clear of those controls.
                    int overlap = c.Kind == "COMBOBOX" ? -1 : fixedActions.FindIndex(action => Overlaps(bounds, action));
                    bool clear = overlap < 0;
                    if (!inside || !clear) offenders.Add($"{c.Id}/{c.Kind}/{(clear ? "inside" : "overlap[" + overlap + "]")}/{bounds.Left},{bounds.Top},{bounds.Right},{bounds.Bottom}");
                }
                if (offenders.Count > 0) Console.Error.WriteLine("compact_control_offenders: " + string.Join("; ", offenders));
                Check(offenders.Count == 0, "compact_page_controls_clear_fixed_actions_" + targetPage);
            }
            SetWindowPos(window, IntPtr.Zero, full.Left, full.Top, full.Right - full.Left, full.Bottom - full.Top, 0x14);
            RequestClose(); Check(window == IntPtr.Zero, "clean_close_releases_surface");
            completed = true;
        }
        catch (Exception error) { failure = error.Message; throw; }
        finally
        {
            if (window != IntPtr.Zero) DestroyWindow(window);
            WriteCaptureProof();
        }
        return new { assertions, scope = "native settings preview and owned word-storage fixtures", captures = captures.Count, fixture };
    }
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool PeekMessageW(out HostWindow.Message message, IntPtr hwnd, uint min, uint max, uint flags);
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MenuGui
    { public uint Size, Flags; public IntPtr Active, Focus, Capture, Menu, MoveSize, Caret; public Rect CaretRect; }
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool GetGUIThreadInfo(uint thread, ref MenuGui gui);
}
