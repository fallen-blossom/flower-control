using System.Runtime.InteropServices;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    internal static object LifecycleSelfTest(string directory)
    {
        if (window != IntPtr.Zero || core is not null) throw new Boundary("settings_lifecycle_fixture_requires_fresh_process");
        Directory.CreateDirectory(directory);
        var measurements = new List<object>(); var frames = new List<object>(); int assertions = 0;
        void Check(bool value, string name) { assertions++; if (!value) throw new InvalidOperationException("settings_lifecycle: " + name); }
        void Pump()
        {
            while (PeekMessageW(out var message, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref message); DispatchMessageW(ref message); }
            if (window != IntPtr.Zero) UpdateWindow(window);
        }
        void Capture(string name)
        {
            ShowWindow(window, 5); Native.SetForegroundWindow(window); Pump();
            GetWindowRect(window, out var rect); string file = Path.Combine(directory, name + ".png");
            SettingsArtwork.SaveWindowPng(window, rect.Right - rect.Left, rect.Bottom - rect.Top, file);
            frames.Add(new { file, pid = Environment.ProcessId, hwnd = window.ToInt64(), dpi = GetDpiForWindow(window),
                foreground = Native.GetForegroundWindow() == window, bounds = new[] { rect.Left, rect.Top, rect.Right, rect.Bottom }, synthetic = true });
        }
        void Start(int targetPage = 1)
        {
            preview = true; standalone = false; core = null; Initialize(Synthetic()); page = targetPage;
            Create(); ShowWindow(window, 5); Native.SetForegroundWindow(window); Pump();
        }
        void MouseButton(int id)
        {
            var button = GetDlgItem(window, id); GetClientRect(button, out var rect);
            var point = new IntPtr(((rect.Bottom / 2) << 16) | (rect.Right / 2));
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            SendMessageW(button, 0x201, new IntPtr(1), point); SendMessageW(button, 0x202, IntPtr.Zero, point);
            double callback = elapsed.Elapsed.TotalMilliseconds; Pump();
            measurements.Add(new { action = "button", id, callback_ms = callback, frame_ms = elapsed.Elapsed.TotalMilliseconds });
            Check(!pageRebuildPending && !pageRebuildPosted && nativeCallbackDepth == 0 && nativeCommandDepth == 0, "button_returns_to_idle_" + id);
        }
        void SelectPrivacy(int target, bool cancel = false)
        {
            var combo = PageHandle(PrivacyTabId); int before = privacyTab; SetFocus(combo);
            SendMessageW(combo, 0x14F, new IntPtr(1), IntPtr.Zero); Pump();
            var info = new ComboInfo { Size = (uint)Marshal.SizeOf<ComboInfo>() }; GetComboBoxInfo(combo, ref info);
            var elapsed = System.Diagnostics.Stopwatch.StartNew();
            if (cancel)
            {
                SendMessageW(combo, 0x100, new IntPtr(40), IntPtr.Zero);
                Check(privacyTab == before && IsWindow(combo), "open_arrow_does_not_commit_or_destroy");
                SendMessageW(combo, 0x100, new IntPtr(27), IntPtr.Zero);
            }
            else
            {
                var row = new Rect(); SendItemRect(info.List, 0x198, new IntPtr(target), ref row);
                var point = new IntPtr((((row.Top + row.Bottom) / 2) << 16) | Math.Max(4, (row.Right - row.Left) / 2));
                SendMessageW(info.List, 0x200, IntPtr.Zero, point); SendMessageW(info.List, 0x201, new IntPtr(1), point); SendMessageW(info.List, 0x202, IntPtr.Zero, point);
                Check(IsWindow(combo), "native_combo_survives_until_mouse_callback_returns");
            }
            double callback = elapsed.Elapsed.TotalMilliseconds; Pump();
            Check(privacyTab == (cancel ? before : target), "privacy_selection_matches_commit_or_cancel");
            Check(!pageRebuildPending && !pageRebuildPosted && nativeCallbackDepth == 0 && nativeCommandDepth == 0, "native_selection_queue_drained");
            measurements.Add(new { action = cancel ? "popup_arrow_escape" : "popup_mouse_commit", target, callback_ms = callback, frame_ms = elapsed.Elapsed.TotalMilliseconds });
        }
        bool passed = false;
        try
        {
            Start(); GetWindowRect(window, out var wide);
            foreach (bool compact in new[] { false, true })
            {
                if (compact) SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, MinimumSurfaceSize(window).X, MinimumSurfaceSize(window).Y, 0x14);
                for (int n = 0; n < 12; n++)
                {
                    MouseButton(ViewLayerBase + n % 3);
                    Check(ruleLayer == n % 3 && tier == 2 && model.EffectiveTier == 2 && !Dirty, "view_layer_never_enables_permission");
                    if (ruleLayer >= 2)
                    {
                        MouseButton(ListKindBase + 1); Check(denied && !Dirty, "blacklist_is_view_only");
                        MouseButton(ListKindBase); Check(!denied && !Dirty, "whitelist_is_view_only");
                    }
                }
                MouseButton(ViewLayerBase + 2);
                var original = model.Programs(2, false);
                model.Programs(2, false, Enumerable.Range(0, 8).Select(i => original[i % 2] with { DisplayName = "合成程序 " + (i + 1) }).ToArray());
                BuildPage(); UpdateChrome(); Pump();
                var list = PageHandle(ProgramListId); GetClientRect(list, out var bounds);
                Check(bounds.Bottom >= ProgramRowHeight * 4, "four_program_rows_visible_" + compact);
                Capture(compact ? "compact-four-rows" : "wide-four-rows");
                model.Reload(Synthetic()); BuildPage(); UpdateChrome(); Pump();
                MouseButton(ListKindBase + 1); Capture(compact ? "compact-blacklist" : "wide-blacklist"); MouseButton(ListKindBase);
            }
            SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, wide.Right - wide.Left, wide.Bottom - wide.Top, 0x14);
            MouseButton(NavBase + 2); SelectPrivacy(1); SelectPrivacy(2); SelectPrivacy(0); SelectPrivacy(1, true);
            Check(!Dirty, "native_popup_cancel_preserves_all_drafts");
            // A new generation supersedes an already posted render. Both
            // messages may exist, but only the current one can mutate the UI.
            nativeCommandDepth++;
            try { BuildPage(); Initialize(Synthetic()); page = 1; BuildPage(); }
            finally { nativeCommandDepth--; PostPendingPageRebuild(); }
            Pump(); Check(!pageRebuildPending && !pageRebuildPosted && PageHandle(ViewLayerBase) != IntPtr.Zero, "reload_drops_stale_generation_without_stuck_posted_flag");
            Capture("wide-buttons");
            // Complete a synthetic save while a real native row menu is in
            // its nested message loop. No protected persistence is invoked.
            bool menuSaveObserved = false;
            uxProbeAction = () =>
            {
                if (menuSaveObserved) return;
                var gui = new MenuGui { Size = (uint)Marshal.SizeOf<MenuGui>() };
                if (!GetGUIThreadInfo(GetCurrentThreadId(), ref gui) || (gui.Flags & 0x10) == 0 || gui.Menu != window) return;
                menuSaveObserved = true; closeAfterSave = true; work = Task.FromResult(new WorkReply("save", draft, draft));
                SendMessageW(window, WorkFinished, IntPtr.Zero, IntPtr.Zero);
                Check(IsWindow(window) && surfaceClosePending, "async_save_does_not_destroy_owner_on_native_menu_stack");
            };
            using (var timer = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 100, 100))
                SendMessageW(PageHandle(ProgramMenuId), 0xF5, IntPtr.Zero, IntPtr.Zero);
            uxProbeAction = null; Pump();
            Check(menuSaveObserved && window == IntPtr.Zero, "async_close_cancels_own_menu_then_closes_after_unwind");
            Start(); bool dialogSaveObserved = false;
            uxProbeAction = () =>
            {
                if (dialogSaveObserved || appDialog?.Window == IntPtr.Zero || appDialog is null) return;
                dialogSaveObserved = true; closeAfterSave = true; work = Task.FromResult(new WorkReply("save", draft, draft));
                SendMessageW(window, WorkFinished, IntPtr.Zero, IntPtr.Zero);
                Check(IsWindow(window) && surfaceClosePending, "async_save_preserves_owner_until_dialog_unwinds");
            };
            using (var timer = new Timer(_ => PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero), null, 100, 100))
                MessageBoxW(window, "合成预览：验证保存结果在详情打开期间返回。", "关闭生命周期检查", 0x40);
            uxProbeAction = null; Pump(); Check(dialogSaveObserved && window == IntPtr.Zero, "async_save_closes_after_dialog_unwinds");
            // The dialog's EDIT owns its context menu through the dialog root,
            // so closing only the main window's menu does not end this loop.
            Start(); bool nestedMenuEntered = false, nestedSaveObserved = false;
            int nestedTicks = 0, nestedTimedOut = 0;
            uxProbeAction = () =>
            {
                if (appDialog is not { Window: var dialogWindow } dialog || dialogWindow == IntPtr.Zero) return;
                if (!nestedMenuEntered)
                {
                    nestedMenuEntered = true;
                    SendMessageW(dialog.Body, 0x7B, dialog.Body, new IntPtr(-1));
                    return;
                }
                if (nestedSaveObserved) return;
                var gui = new MenuGui { Size = (uint)Marshal.SizeOf<MenuGui>() };
                if (!GetGUIThreadInfo(GetCurrentThreadId(), ref gui) || (gui.Flags & 0x10) == 0 || gui.Menu != dialogWindow) return;
                nestedSaveObserved = true; closeAfterSave = true; work = Task.FromResult(new WorkReply("save", draft, draft));
                SendMessageW(window, WorkFinished, IntPtr.Zero, IntPtr.Zero);
                Check(IsWindow(window) && IsWindow(dialogWindow) && surfaceClosePending, "nested_menu_keeps_both_owners_alive_until_unwind");
            };
            using (var timer = new Timer(_ =>
            {
                if (Interlocked.Increment(ref nestedTicks) > 30 && appDialog is { } dialog)
                { Interlocked.Exchange(ref nestedTimedOut, 1); PostMessageW(dialog.Window, 0x1F, UIntPtr.Zero, IntPtr.Zero); }
                PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero);
            }, null, 100, 100))
                MessageBoxW(window, "合成预览：详情文本菜单打开期间收到保存关闭结果。", "嵌套菜单关闭检查", 0x40);
            uxProbeAction = null; Pump();
            Check(nestedMenuEntered && nestedSaveObserved && nestedTimedOut == 0 && window == IntPtr.Zero, "async_close_cancels_dialog_owned_edit_menu_without_timeout");
            Console.Error.WriteLine("settings_lifecycle_stage: resource_warmup");
            using var process = System.Diagnostics.Process.GetCurrentProcess();
            // Warm both sizes before measuring process-owned native objects.
            // Shared tray icon caches are intentionally process lifetime.
            for (int n = 0; n < 2; n++)
            { Start(); SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, n == 0 ? 1000 : wide.Right - wide.Left, n == 0 ? 680 : wide.Bottom - wide.Top, 0x14); Pump(); CloseSurfaceSafely(); Pump(); }
            uint gdiBefore = GetGuiResources(process.Handle, 0), userBefore = GetGuiResources(process.Handle, 1);
            for (int n = 0; n < 8; n++)
            {
                Console.Error.WriteLine("settings_lifecycle_stage: resource_cycle_" + n);
                Start();
                SendMessageW(window, 0x231, IntPtr.Zero, IntPtr.Zero);
                try
                {
                    SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, MinimumSurfaceSize(window).X, MinimumSurfaceSize(window).Y, 0x14); Pump();
                    SetWindowPos(window, IntPtr.Zero, wide.Left, wide.Top, wide.Right - wide.Left, wide.Bottom - wide.Top, 0x14); Pump();
                }
                finally { SendMessageW(window, 0x232, IntPtr.Zero, IntPtr.Zero); }
                CloseSurfaceSafely(); Pump();
                Check(sceneDc == IntPtr.Zero && backdropDc == IntPtr.Zero && interactiveControls.Count == 0,
                    "close_releases_retained_scene_and_resize_rasters_" + n);
            }
            uint gdiAfter = GetGuiResources(process.Handle, 0), userAfter = GetGuiResources(process.Handle, 1);
            Console.Error.WriteLine("settings_lifecycle_stage: resource_cycles_done");
            Check(gdiBefore != 0 && gdiAfter <= gdiBefore, "reopen_resize_does_not_accumulate_gdi_objects");
            Check(userBefore != 0 && userAfter <= userBefore && menuLabels.Count == 0, "reopen_resize_does_not_accumulate_user_objects");
            measurements.Add(new { action = "eight_reopen_resize_close_cycles", gdiBefore, gdiAfter, userBefore, userAfter });
            passed = true;
            return new { passed, assertions, frames = frames.Count, measurements, scope = "Medium synthetic native mouse/control callbacks, no real policy write or High launch" };
        }
        finally
        {
            uxProbeAction = null;
            if (window != IntPtr.Zero) DestroyWindow(window);
            File.WriteAllText(Path.Combine(directory, "lifecycle-proof.json"), JsonSerializer.Serialize(new { passed, assertions, frames, measurements }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
    [DllImport("user32.dll", EntryPoint = "SendMessageW")] private static extern IntPtr SendItemRect(IntPtr hwnd, uint message, IntPtr index, ref Rect rect);
    [DllImport("user32.dll")] private static extern uint GetGuiResources(IntPtr process, uint flags);
}
