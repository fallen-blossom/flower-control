using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    // Real native confirmation dialogs in an owned Medium preview. The
    // native inspector reads a fixed system EXE; persistence remains synthetic.
    internal static object SelectionSelfTest(string directory)
    {
        if (window != IntPtr.Zero || core is not null || Native.Process(Environment.ProcessId).Identity.Integrity != 8192)
            throw new Boundary("selection_fixture_requires_fresh_medium_process");
        Directory.CreateDirectory(directory);
        string native = Path.Combine(Path.GetDirectoryName(typeof(SettingsWorkspace).Assembly.Location)!, "Flower.UacNative.dll");
        UacNativeBridge.UseMediumFixture(native, Native.Digest(native));
        int assertions = 0;
        void Check(bool value, string name) { assertions++; if (!value) throw new InvalidOperationException("selection_fixture: " + name); }
        void Pump()
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            while (clock.ElapsedMilliseconds < 120)
            {
                while (PeekMessageW(out var message, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref message); DispatchMessageW(ref message); }
                Thread.Sleep(2);
            }
        }
        void Capture(string name)
        {
            GetWindowRect(window, out var rect);
            SettingsArtwork.SaveWindowPng(window, rect.Right - rect.Left, rect.Bottom - rect.Top, Path.Combine(directory, name + ".png"));
        }
        bool Ordinary(string cls, uint style = 0, bool cloak = false, bool owned = false, string title = "test", string image = @"C:\Fixture\app.exe")
            => PickableWindow(cls, style, true, cloak, owned, title, image);
        Check(!Ordinary("Progman") && !Ordinary("WorkerW") && !Ordinary("Shell_TrayWnd"), "shell_surfaces_omitted");
        Check(!Ordinary("tooltips_class32") && !Ordinary("#32768"), "native_menus_and_tips_omitted");
        Check(!Ordinary("test", 0x80) && !Ordinary("test", cloak: true), "tool_and_cloaked_windows_omitted");
        Check(!Ordinary("test", owned: true) && Ordinary("test", 0x40000, owned: true), "owned_window_app_style_respected");
        Check(Ordinary("test", title: ""), "real_untitled_application_kept");
        Check(!Ordinary("test", title: "", image: @"C:\Windows\explorer.exe") && Ordinary("test", image: @"C:\Windows\explorer.exe"), "blank_shell_not_file_manager");

        preview = true; standalone = false; core = null;
        Initialize(Synthetic() with { AdminLaunchAllowlist = [], DeniedAdminLaunchApplications = [] }); page = 1;
        var snapshots = new List<object>();
        try
        {
            Create(); ShowWindow(window, 5); Native.SetForegroundWindow(window); Pump();
            var original = SelectionContext(); var unchanged = draft;
            foreach (var stale in new[] { original with { Page = 2 }, original with { PrivacyTab = original.PrivacyTab + 1 }, original with { Layer = 1 }, original with { Denied = true },
                original with { Generation = original.Generation + 1 }, original with { Revision = "foreign" }, original with { StopEpoch = 1 } })
            {
                bool refused = false;
                try { RequireSelectionContext(stale); } catch (Boundary error) { refused = error.Code == "uac_window_pick_expired"; }
                Check(refused && draft == unchanged, "changed_selection_context_refused_without_mutation");
            }
            var peer = Native.Process(Environment.ProcessId, false).Identity;
            var boundWindow = new WindowChoice(window, peer, Environment.ProcessPath!, "fixture", 800, 600);
            Check(SameWindowChoice(boundWindow, boundWindow), "same_exact_window_accepted");
            Check(!SameWindowChoice(boundWindow, boundWindow with { Width = 900 }) && !SameWindowChoice(boundWindow, boundWindow with { Height = 700 }), "resized_window_refused_before_mask_mutation");
            Check(!SameWindowChoice(boundWindow, boundWindow with { Peer = peer with { Created = peer.Created + 1 } }), "replacement_process_refused");
            string executable = Path.Combine(Environment.SystemDirectory, "notepad.exe");
            foreach (bool black in new[] { false, true })
            foreach (int existing in new[] { 0, 12 })
            {
                var seeded = Enumerable.Range(0, existing).Select(i => new UacApplicationPermission(@"C:\Fixture\Existing" + i + ".exe", "sha256", new string('a', 64), "Existing " + i, true, "")).ToArray();
                model.Reload(Synthetic() with { AdminLaunchAllowlist = black ? [] : seeded, DeniedAdminLaunchApplications = black ? seeded : [] });
                denied = black; BuildPage(); UpdateChrome(); Pump();
                // An owned modal is acknowledged only after matching the exact
                // preview owner and process. No production dialog is touched.
                uxProbeAction = () => DismissOwnedSelectionDialog(window, 6);
                using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                {
                    nativeCommandDepth++;
                    try { ConfirmCandidate(executable, null); }
                    finally { nativeCommandDepth--; PostPendingPageRebuild(); }
                }
                uxProbeAction = null; Pump();
                var list = PageHandle(ProgramListId); GetClientRect(list, out var bounds);
                int count = SendMessageW(list, 0x18B, IntPtr.Zero, IntPtr.Zero).ToInt32();
                int selected = Selection(ProgramListId), top = SendMessageW(list, 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32();
                Check(count == existing + 1 && selected == existing, "new_row_selected_" + black + "_" + existing);
                Check(selected >= top && (selected - top + 1) * ProgramRowHeight <= bounds.Bottom, "new_row_fully_visible_" + black + "_" + existing);
                Check(IsWindowVisible(list) && GetFocus() == list && !pageRebuildPending && !pageRebuildPosted, "native_list_ready_" + black + "_" + existing);
                snapshots.Add(new { black, existing, count, selected, top, height = bounds.Bottom });
                Capture((black ? "black" : "white") + "-added-" + existing);
                var added = draft;
                var submitted = draft; RequestSave(); Pump();
                Check(!Dirty && model.Saved.AdminLaunchAllowlist.Length == added.AdminLaunchAllowlist.Length
                    && model.Saved.DeniedAdminLaunchApplications.Length == added.DeniedAdminLaunchApplications.Length, "preview_save_preserves_lists");
                model.Reload(saved); BuildPage(); UpdateChrome(); Pump();
                Check(SendMessageW(PageHandle(ProgramListId), 0x18B, IntPtr.Zero, IntPtr.Zero).ToInt32() == existing + 1, "preview_reload_retains_native_rows");
            }
            // Both add and enable routes must confirm the same cross-list move.
            var inspected = UacIdentity.InspectForAllowlist(executable) with { Arguments = "" };
            foreach (bool destinationDenied in new[] { false, true })
            {
                model.Reload(Synthetic() with { AdminLaunchAllowlist = destinationDenied ? [inspected] : [],
                    DeniedAdminLaunchApplications = destinationDenied ? [] : [inspected] });
                denied = destinationDenied; BuildPage(); UpdateChrome(); Pump();
                var before = draft;
                uxProbeAction = () => DismissOwnedSelectionDialog(window, 7);
                using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                    ConfirmCandidate(executable, null);
                uxProbeAction = null; Check(draft == before, "cross_add_cancel_" + destinationDenied);
                uxProbeAction = () => DismissOwnedSelectionDialog(window, 6);
                using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                    ConfirmCandidate(executable, null);
                uxProbeAction = null; Pump();
                Check(model.Programs(2, destinationDenied).Length == 1 && model.Programs(2, !destinationDenied).Length == 0
                    && model.Saved != draft, "cross_add_confirm_draft_" + destinationDenied);
                model.Reload(Synthetic() with { AdminLaunchAllowlist = destinationDenied ? [inspected] : [inspected with { Enabled = false }],
                    DeniedAdminLaunchApplications = destinationDenied ? [inspected with { Enabled = false }] : [inspected] });
                BuildPage(); UpdateChrome(); Pump();
                Check(model.ProgramsOverlap(2), "legacy_overlap_remains_" + destinationDenied);
                SendMessageW(PageHandle(ProgramListId), 0x186, IntPtr.Zero, IntPtr.Zero);
                before = draft;
                uxProbeAction = () => DismissOwnedSelectionDialog(window, 7);
                using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                    EditProgram(false);
                uxProbeAction = null; Check(draft == before, "cross_enable_cancel_" + destinationDenied);
                uxProbeAction = () => DismissOwnedSelectionDialog(window, 6);
                using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                    EditProgram(false);
                uxProbeAction = null; Pump();
                Check(model.Programs(2, destinationDenied).Single().Enabled && model.Programs(2, !destinationDenied).Length == 0
                    && model.Saved != draft, "cross_enable_confirm_draft_" + destinationDenied);
            }
            // Cancellation leaves all existing rows and unrelated drafts intact.
            var beforeCancel = draft;
            uxProbeAction = () => DismissOwnedSelectionDialog(window, 7);
            using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                ConfirmCandidate(executable, null);
            uxProbeAction = null; Pump();
            Check(draft == beforeCancel && pendingProgramReveal is null, "confirmation_cancel_keeps_draft");

            var beforeError = draft;
            model.Edit(x => x with { HudCompact = !x.HudCompact }); UpdateChrome();
            uxProbeAction = () => DismissOwnedSelectionDialog(window, 1);
            using (var tick = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 80, 80))
                RunProgramSelection(() => throw new Boundary("uac_allowlist_payload_host_rejected"));
            uxProbeAction = null;
            Check(Dirty && IsWindowEnabled(GetDlgItem(window, SaveId)) && !surfaceFault && notice.Contains(UiText.Get("此程序依赖解释器或 .NET 运行时，不能加入当前启动白名单；请使用按工作授权。")), "unsupported_selection_keeps_unrelated_draft_saveable");
            PublishWorkspaceStatus("command", AddId);
            Check(SurfaceDiagnostics.Error == "uac_allowlist_payload_host_rejected", "selection_error_survives_command_metadata");
            surfaceFault = true; PublishWorkspaceStatus("updated");
            Check(SurfaceDiagnostics.Error == "uac_allowlist_payload_host_rejected", "fault_diagnostic_survives_later_ui_refresh");
            surfaceFault = false;
            Check(ProgramIcon(executable) != IntPtr.Zero, "menu_icon_available");
            var choices = RunningProgramChoices();
            Check(choices.Select(x => x.Image).Distinct(StringComparer.OrdinalIgnoreCase).Count() == choices.Count, "running_program_paths_distinct");
            return new { assertions, snapshots, running_candidates = choices.Count, synthetic_settings = true, installed = false,
                scope = "Medium owned preview; real native EXE inspection and confirmation; no protected policy writes, High launch or UAC" };
        }
        finally { uxProbeAction = null; if (window != IntPtr.Zero) DestroyWindow(window); }
    }

    private static void DismissOwnedSelectionDialog(IntPtr owner, int command)
    {
        EnumWindows((dialog, _) =>
        {
            Native.GetWindowThreadProcessId(dialog, out var pid);
            if (pid == (uint)Environment.ProcessId && Native.GetWindow(dialog, 4) == owner && GetDlgItem(dialog, command) != IntPtr.Zero)
                PostMessageW(dialog, 0x111, new UIntPtr((uint)command), IntPtr.Zero);
            return true;
        }, IntPtr.Zero);
    }
}
