using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private sealed record MotionSample(string name, double total_ms, int paints, int sizes, int moves,
        double paint_ms, int owner_draws, double owner_draw_ms);
    // Explicit Medium preview only. Window messages never enter the real
    // foreground-input executor or change the pointer/keyboard state.
    private static void ProbeWindowMotion(string directory, Action<bool, string> check)
    {
        var samples = new List<object>(); var captures = new List<object>(); int paints = 0, sizes = 0, moves = 0, draws = 0; long paintTicks = 0, drawTicks = 0;
        SubclassProc observer = (hwnd, message, wp, lp, id, data) =>
        {
            if (message == 5) ++sizes;
            if (message == 3) ++moves;
            if (message is not (15 or 0x2B)) return DefSubclassProc(hwnd, message, wp, lp);
            if (message == 15) ++paints; else ++draws; long start = Stopwatch.GetTimestamp();
            try { return DefSubclassProc(hwnd, message, wp, lp); }
            finally { long ticks = Stopwatch.GetTimestamp() - start; if (message == 15) paintTicks += ticks; else drawTicks += ticks; }
        };
        void Pump()
        { while (PeekMessageW(out var msg, IntPtr.Zero, 0, 0, 1)) { TranslateMessage(ref msg); DispatchMessageW(ref msg); } UpdateWindow(window); }
        void Capture(string name)
        {
            Pump(); GetWindowRect(window, out var bounds); string path = Path.Combine(directory, name + ".png");
            SettingsArtwork.SaveWindowPng(window, bounds.Right - bounds.Left, bounds.Bottom - bounds.Top, path);
            captures.Add(new { path, bounds = new[] { bounds.Left, bounds.Top, bounds.Right, bounds.Bottom },
                dpi = GetDpiForWindow(window), foreground = Native.GetForegroundWindow() == window, synthetic = true,
                pid = Environment.ProcessId, hwnd = window.ToInt64(), interactiveWindowMove, capture_backend = "PrintWindow exact unscaled native window" });
        }
        GetWindowRect(window, out var original); int width = original.Right - original.Left, height = original.Bottom - original.Top;
        var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
        check(GetMonitorInfoW(MonitorFromWindow(window, 2), ref monitor), "initial_window_monitor_available");
        var expected = CenterInWorkArea(monitor.Work, width, height);
        check(Math.Abs(original.Left - expected.Left) <= 1 && Math.Abs(original.Top - expected.Top) <= 1,
            "initial_window_centered_in_target_work_area");
        var negative = CenterInWorkArea(new Rect { Left = -1920, Top = -1200, Right = 0, Bottom = -40 }, 1000, 680);
        check(negative.Left == -1460 && negative.Top == -960, "centering_preserves_negative_monitor_origin");
        var clipped = CenterInWorkArea(new Rect { Left = 40, Top = 50, Right = 840, Bottom = 650 }, 1800, 1200);
        check(clipped.Left == 40 && clipped.Top == 50 && clipped.Right == 840 && clipped.Bottom == 650,
            "oversized_window_fits_work_area_including_frame");
        var owner = CreateWindowExW(0x08000000, "STATIC", "Synthetic placement owner", 0x90000000,
            monitor.Work.Left + 8, monitor.Work.Top + 8, 64, 64, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
        try { check(owner != IntPtr.Zero && StartupMonitor(owner) == MonitorFromWindow(owner, 2), "visible_owner_selects_its_monitor"); }
        finally { if (owner != IntPtr.Zero) DestroyWindow(owner); }
        GetCursorPos(out var cursor);
        check(StartupMonitor(IntPtr.Zero) == MonitorFromPoint(cursor, 2), "ownerless_window_uses_pointer_monitor");
        var limits = Marshal.AllocHGlobal(Marshal.SizeOf<MinMaxInfo>());
        try
        {
            Marshal.StructureToPtr(new MinMaxInfo(), limits, false); SendMessageW(window, 0x24, IntPtr.Zero, limits);
            var value = Marshal.PtrToStructure<MinMaxInfo>(limits);
            check(value.MinTrack.X > 0 && value.MinTrack.X <= monitor.Work.Right - monitor.Work.Left
                && value.MinTrack.Y > 0 && value.MinTrack.Y <= monitor.Work.Bottom - monitor.Work.Top,
                "minimum_tracking_size_stays_in_monitor_work_area");
        }
        finally { Marshal.FreeHGlobal(limits); }
        int captionY = original.Top + Math.Max(8, GetSystemMetricsForDpi(4, GetDpiForWindow(window)) / 2);
        var hit = new IntPtr((captionY << 16) | ((original.Left + width / 2) & 0xffff));
        check(SendMessageW(window, 0x84, IntPtr.Zero, hit).ToInt32() == 2, "native_title_center_is_caption_drag_target");
        ProbePositionBatchFallback(check);
        ProbeBatchComboHeights(check);
        SetWindowSubclass(window, observer, new UIntPtr(208), UIntPtr.Zero);
        try
        {
            void Measure(string name, Action action)
            {
                paints = sizes = moves = draws = 0; paintTicks = drawTicks = 0; var elapsed = Stopwatch.StartNew(); action(); Pump();
                samples.Add(Snapshot(name, elapsed.Elapsed.TotalMilliseconds));
            }
            MotionSample Snapshot(string name, double ms) => new(name, ms, paints, sizes, moves,
                paintTicks * 1000.0 / Stopwatch.Frequency, draws, drawTicks * 1000.0 / Stopwatch.Frequency);
            Measure("twelve_page_switches", () => {
                foreach (int target in new[] { 0, 2, 3, 4, 1, 0, 2, 3, 4, 1, 0, 1 })
                { SendMessageW(GetDlgItem(window, NavBase + target), 0xF5, IntPtr.Zero, IntPtr.Zero); Pump(); }
            });
            check(page == 1 && pageControls.Where(c => IsWindowVisible(c.Handle)).All(c =>
                c.Kind == "COMBOBOX" || c.Id is ProgramMenuId || GetClientRect(c.Handle, out var bounds) && bounds.Right > 0 && bounds.Bottom > 0),
                "page_switch_ends_on_complete_permission_surface");
            var warmScene = sceneGeometry; var warmBackdrop = backdropKey;
            Measure("six_window_activation_repaints", () => {
                for (int i = 0; i < 6; i++) SendMessageW(window, 0x15, new IntPtr(i % 2), IntPtr.Zero);
            });
            check(sceneGeometry == warmScene && backdropKey == warmBackdrop,
                "window_activation_reuses_scene_and_backdrop_caches");
            Measure("six_position_only_moves", () => {
                for (int i = 0; i < 6; i++) { SetWindowPos(window, IntPtr.Zero, original.Left + 8 + i * 2, original.Top + 8, 0, 0, 0x15); Pump(); }
            });
            var movedDraft = draft;
            Measure("six_native_loop_position_moves", () => {
                SendMessageW(window, 0x231, IntPtr.Zero, IntPtr.Zero);
                try { for (int i = 0; i < 6; i++) { SetWindowPos(window, IntPtr.Zero, original.Left + 8 + i * 2, original.Top + 8, 0, 0, 0x15); Pump(); } }
                finally { SendMessageW(window, 0x232, IntPtr.Zero, IntPtr.Zero); }
            });
            check(draft == movedDraft && !interactiveWindowMove && interactiveControls.Count == 0,
                "title_move_does_not_activate_controls_or_leave_rasters");
            Measure("six_exposed_move_repaints", () => {
                for (int i = 0; i < 6; i++) { SetWindowPos(window, IntPtr.Zero, original.Left + 8 + i * 2, original.Top + 8, 0, 0, 0x15); InvalidateRect(window, IntPtr.Zero, false); Pump(); }
            });
            Measure("four_small_resizes", () => {
                for (int i = 0; i < 4; i++) { SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width - 6 - i * 2, height - 6 - i * 2, 0x14); Pump(); }
            });
            SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width, height, 0x14); Pump();
            var originalDraft = draft;
            model.Edit(x => x with { SmoothPointer = !x.SmoothPointer }); UpdateChrome(); Pump();
            var beforeDraft = draft; var beforeSaved = saved;
            var focus = PageHandle(ViewLayerBase + 2); SetFocus(focus);
            var focusMessage = new HostWindow.Message { Hwnd = focus, Kind = 0 };
            HandleDialogMessage(ref focusMessage);
            ShowWindow(window, 6); Pump(); check(IsIconic(window), "synthetic_window_minimizes");
            Show(IntPtr.Zero, null!); Pump(); GetWindowRect(window, out var restored);
            check(!IsIconic(window) && GetFocus() == focus && draft == beforeDraft && saved == beforeSaved,
                "restore_preserves_focus_and_unsaved_model");
            check(restored.Left == original.Left && restored.Top == original.Top && restored.Right == original.Right && restored.Bottom == original.Bottom,
                "restore_preserves_user_placement_without_recentering");
            bool closeSeen = false; int closeTicks = 0; Exception? closeError = null;
            uxProbeAction = () => {
                if (closeSeen || appDialog is not { Window: var dialog } pending || dialog == IntPtr.Zero) return;
                closeSeen = true;
                try { check(pending.Default == 2 && GetDlgCtrlID(GetFocus()) == 2, "unsaved_close_defaults_to_return"); }
                catch (Exception error) { closeError = error; }
                finally { PostMessageW(dialog, 0x100, new UIntPtr(27), IntPtr.Zero); }
            };
            using (var timer = new Timer(_ => {
                if (Interlocked.Increment(ref closeTicks) > 50 && appDialog is { } pending) PostMessageW(pending.Window, 0x10, UIntPtr.Zero, IntPtr.Zero);
                else PostMessageW(window, UxProbeTick, UIntPtr.Zero, IntPtr.Zero);
            }, null, 100, 100))
            {
                var escape = new HostWindow.Message { Hwnd = GetFocus(), Kind = 0x100, Wp = new UIntPtr(27) };
                HandleDialogMessage(ref escape);
            }
            uxProbeAction = null; if (closeError is not null) throw closeError;
            check(closeSeen && IsWindow(window) && draft == beforeDraft && saved == beforeSaved,
                "escape_close_return_keeps_unsaved_draft");
            model.Edit(_ => originalDraft); UpdateChrome(); Pump();
            paints = sizes = moves = draws = 0; paintTicks = drawTicks = 0;
            var totalResize = Stopwatch.StartNew(); var intermediateResize = Stopwatch.StartNew();
            var retainedGeometry = sceneGeometry;
            SendMessageW(window, 0x231, IntPtr.Zero, IntPtr.Zero);
            try { for (int i = 0; i < 4; i++) { SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width - 6 - i * 2, height - 6 - i * 2, 0x14); Pump(); } }
            finally
            {
                var mid = Snapshot("native_loop_intermediate_four_steps", intermediateResize.Elapsed.TotalMilliseconds);
                samples.Add(mid);
                bool reused = sceneGeometry == retainedGeometry;
                paints = sizes = moves = draws = 0; paintTicks = drawTicks = 0; var exitResize = Stopwatch.StartNew();
                SendMessageW(window, 0x232, IntPtr.Zero, IntPtr.Zero); Pump();
                var end = Snapshot("native_loop_exit_final_frame", exitResize.Elapsed.TotalMilliseconds); samples.Add(end);
                check(reused, "native_resize_reuses_complete_scene_within_aspect_guard");
                samples.Add(new MotionSample("four_native_loop_resizes", totalResize.Elapsed.TotalMilliseconds,
                    mid.paints + end.paints, mid.sizes + end.sizes, mid.moves + end.moves,
                    mid.paint_ms + end.paint_ms, mid.owner_draws + end.owner_draws, mid.owner_draw_ms + end.owner_draw_ms));
            }
            SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width, height, 0x14); Pump();
            check(!interactiveWindowMove && interactiveControls.Count == 0, "resize_end_releases_all_transient_control_rasters");
            VerifyScenePixels(directory, "after-native-resize", check);
            SendMessageW(window, 0x231, IntPtr.Zero, IntPtr.Zero);
            try
            {
                var retained = sceneGeometry;
                SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width - 24, height - 16, 0x14); Pump();
                check(sceneGeometry == retained, "live_wide_frame_reuses_complete_scene"); Capture("native-resize-live-wide");
                SetVisualState(5); Pump(); VerifyScenePixels(directory, "native-live-state-invalidation", check);
                SetVisualState(2); Pump();
                SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width, height + 100, 0x14); Pump();
                GetClientRect(window, out var changedAspect);
                check(sceneGeometry.Width == changedAspect.Right && sceneGeometry.Height == changedAspect.Bottom,
                    "native_resize_rebuilds_scene_beyond_five_percent_aspect_change");
                SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, MinimumSurfaceSize(window).X, MinimumSurfaceSize(window).Y, 0x14);
                check(!IsWindowVisible(PageHandle(612)), "wide_to_compact_hides_wide_list_caption");
                Capture("native-resize-live-compact");
                check(sceneState?.Compact == true, "native_resize_rebuilds_scene_at_compact_boundary");
            }
            finally { SendMessageW(window, 0x232, IntPtr.Zero, IntPtr.Zero); }
            Capture("native-resize-ended-compact"); VerifyScenePixels(directory, "ended-compact", check);
            SetWindowPos(window, IntPtr.Zero, original.Left, original.Top, width, height, 0x14); Pump();
            check(IsWindowVisible(PageHandle(612)), "compact_to_wide_restores_list_caption"); Capture("window-centered-final");
            string priorNotice = notice; bool priorFault = surfaceFault;
            try
            {
                // This is the real callback failure entry, with an already
                // warm scene. Do not mask stale-cache bugs with UpdateChrome.
                NativeCallbackFailed(new InvalidOperationException("synthetic-callback-failure")); Pump();
                check(surfaceFault && !IsWindowEnabled(GetDlgItem(window, SaveId)), "callback_failure_disables_save");
                VerifyScenePixels(directory, "native-error-without-chrome-refresh", check); Capture("native-error-notice");
            }
            finally { notice = priorNotice; surfaceFault = priorFault; UpdateChrome(); Pump(); }
            File.WriteAllText(Path.Combine(directory, "window-motion-probe.json"), JsonSerializer.Serialize(new { samples, captures,
                original = new[] { original.Left, original.Top, original.Right, original.Bottom }, dpi = GetDpiForWindow(window),
                scope = "Medium synthetic window messages; no physical input, policy or High access" }, new JsonSerializerOptions { WriteIndented = true }));
        }
        finally { RemoveWindowSubclass(window, observer, new UIntPtr(208)); GC.KeepAlive(observer); }
    }

    private static void ProbeBatchComboHeights(Action<bool, string> check)
    {
        int oldPage = page, oldTab = privacyTab, oldSection = generalSection, oldFocus = GetDlgCtrlID(GetFocus());
        var beforeDraft = draft;
        try
        {
            foreach (int targetPage in new[] { 2, 3 })
            {
                page = targetPage; privacyTab = generalSection = 0; BuildPage(); UpdateChrome();
                var measured = pageControls.Where(c => c.Kind == "COMBOBOX").Select(c => (c.Handle,
                    Closed: SendMessageW(c.Handle, 0x154, new IntPtr(-1), IntPtr.Zero).ToInt32(),
                    Item: SendMessageW(c.Handle, 0x154, IntPtr.Zero, IntPtr.Zero).ToInt32())).ToArray();
                check(measured.Length > 0 && positionBatch is null, "combo_page_flushes_native_positions_" + targetPage);
                // This existing method runs without a batch here, so it is
                // the original per-control native size/item-height sequence.
                PositionPageControls();
                foreach (var combo in measured)
                {
                    check(combo.Closed > 0 && combo.Item > 0
                        && combo.Closed == SendMessageW(combo.Handle, 0x154, new IntPtr(-1), IntPtr.Zero).ToInt32()
                        && combo.Item == SendMessageW(combo.Handle, 0x154, IntPtr.Zero, IntPtr.Zero).ToInt32(),
                        "batched_combo_heights_match_original_native_sequence_" + targetPage);
                    SendMessageW(combo.Handle, 0x14F, new IntPtr(1), IntPtr.Zero);
                    var info = new ComboInfo { Size = (uint)Marshal.SizeOf<ComboInfo>() };
                    try
                    {
                        bool open = GetComboBoxInfo(combo.Handle, ref info) && IsWindowVisible(info.List);
                        GetWindowRect(info.List, out var popup);
                        check(open && popup.Bottom - popup.Top > combo.Item + 2,
                            "batched_combo_keeps_readable_native_popup_" + targetPage);
                    }
                    finally { SendMessageW(combo.Handle, 0x14F, IntPtr.Zero, IntPtr.Zero); }
                }
                check(draft == beforeDraft, "combo_layout_probe_keeps_draft_" + targetPage);
            }
        }
        finally
        {
            page = oldPage; privacyTab = oldTab; generalSection = oldSection; BuildPage(); UpdateChrome();
            var handle = PageHandle(oldFocus); SetFocus(handle != IntPtr.Zero ? handle : window);
        }
    }

    private static void ProbePositionBatchFallback(Action<bool, string> check)
    {
        var original = new[] { PageHandle(ViewLayerBase + 2), PageHandle(ModeChoiceBase), PageHandle(SemanticEnableId) }
            .Select(handle => { GetWindowRect(handle, out var rect); MapWindowPoints(IntPtr.Zero, window, ref rect, 2); return (Handle: handle, Rect: rect); }).ToArray();
        var beforeDraft = draft; var beforeFocus = GetFocus();
        foreach (bool partial in new[] { false, true })
        {
            using var batch = BeginPositionBatch(true);
            check(batch is not null, "fallback_fixture_starts_own_layout_batch");
            batch!.ApplyForFixture = rows => {
                if (partial)
                {
                    var first = rows[0]; SetWindowPosNative(first.Window, first.After, first.X, first.Y, first.Width, first.Height, first.Flags);
                }
                return false; // Inject a zero/partial native-application failure.
            };
            try
            {
                foreach (var row in original) SetWindowPos(row.Handle, IntPtr.Zero, row.Rect.Left, row.Rect.Top + 2,
                    row.Rect.Right - row.Rect.Left, row.Rect.Bottom - row.Rect.Top, 0x14);
                foreach (var row in original)
                {
                    GetWindowRect(row.Handle, out var rect); MapWindowPoints(IntPtr.Zero, window, ref rect, 2);
                    check(rect.Top == row.Rect.Top, "layout_batch_keeps_fields_in_place_until_flush");
                }
                FlushPositionBatch();
                foreach (var row in original)
                {
                    GetWindowRect(row.Handle, out var rect); MapWindowPoints(IntPtr.Zero, window, ref rect, 2);
                    check(rect.Left == row.Rect.Left && rect.Top == row.Rect.Top + 2
                        && rect.Right == row.Rect.Right && rect.Bottom == row.Rect.Bottom + 2,
                        partial ? "partial_layout_failure_restores_all_native_positions" : "zero_layout_failure_restores_all_native_positions");
                }
                check(positionBatch is null && draft == beforeDraft && GetFocus() == beforeFocus,
                    "layout_fallback_keeps_focus_draft_and_closes_batch");
            }
            finally
            {
                FlushPositionBatch();
                foreach (var row in original) SetWindowPosNative(row.Handle, IntPtr.Zero, row.Rect.Left, row.Rect.Top,
                    row.Rect.Right - row.Rect.Left, row.Rect.Bottom - row.Rect.Top, 0x14);
            }
        }
        chromeLayoutDirty = true; UpdateChrome();
    }

    private static void VerifyScenePixels(string directory, string name, Action<bool, string> check)
    {
        GetClientRect(window, out var client); var screen = GetDC(window);
        var memory = CreateCompatibleDC(screen); var bitmap = CreateCompatibleBitmap(screen, client.Right, client.Bottom);
        var previous = SelectObject(memory, bitmap);
        try
        {
            check(EnsureScene(screen, client.Right, client.Bottom), name + "_scene_buffer_available");
            PaintScene(memory);
            var cached = Read(sceneDc, sceneBitmap, scenePrevious);
            var uncached = Read(memory, bitmap, previous);
            check(cached.AsSpan().SequenceEqual(uncached), name + "_cached_scene_matches_original_pixels");
            File.WriteAllText(Path.Combine(directory, name + "-pixels.json"), JsonSerializer.Serialize(new {
                width = client.Right, height = client.Bottom, bytes = cached.Length,
                cached_sha256 = Convert.ToHexString(SHA256.HashData(cached)).ToLowerInvariant(),
                uncached_sha256 = Convert.ToHexString(SHA256.HashData(uncached)).ToLowerInvariant(), equal = cached.AsSpan().SequenceEqual(uncached)
            }));
            byte[] Read(IntPtr dc, IntPtr image, IntPtr stock)
            {
                var info = new WindowBitmapInfo { Size = 40, Width = client.Right, Height = -client.Bottom, Planes = 1, Bits = 32 };
                var pixels = new byte[checked(client.Right * client.Bottom * 4)];
                SelectObject(dc, stock);
                try { check(GetWindowDibits(dc, image, 0, (uint)client.Bottom, pixels, ref info, 0) == client.Bottom, name + "_bitmap_readback"); }
                finally { SelectObject(dc, image); }
                return pixels;
            }
        }
        finally { SelectObject(memory, previous); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(window, screen); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct WindowBitmapInfo
    { public uint Size; public int Width, Height; public ushort Planes, Bits; public uint Compression, Bytes; public int X, Y; public uint Colors, Important; }
    [DllImport("gdi32.dll", EntryPoint = "GetDIBits")] private static extern int GetWindowDibits(IntPtr dc, IntPtr bitmap, uint first, uint lines, byte[] bits, ref WindowBitmapInfo info, uint usage);
}
