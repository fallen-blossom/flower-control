using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const uint MenuTimingSubclassId = 0x4D50;
    private const int MenuTimingDeadlineMs = 5000;
    private static readonly SubclassProc MenuTimingProcedure = MenuTimingWindowProcedure;
    private static MenuTimingCase? menuTimingCase;

    // Preserve the old observer beside the fixed observer to reproduce the race.
    internal static object MenuTimingProbe()
    {
        if (window != IntPtr.Zero || work is not null)
            throw new Boundary("settings_menu_probe_requires_fresh_process");
        preview = true; standalone = false; core = null;
        Initialize(Synthetic()); page = 1;
        var results = new List<MenuTimingResult>();
        try
        {
            Create();
            foreach (bool fixedObserver in new[] { false, true })
            {
                foreach (var scenario in new[]
                {
                    (Name: "baseline", BeforeClickMs: 0, CommandDelayMs: 0),
                    (Name: "delay_before_bm_click", BeforeClickMs: 350, CommandDelayMs: 0),
                    (Name: "delay_before_menu_command", BeforeClickMs: 0, CommandDelayMs: 350)
                })
                {
                    results.Add(RunMenuTimingCase((fixedObserver ? "fixed_" : "") + scenario.Name,
                        fixedObserver, scenario.BeforeClickMs, scenario.CommandDelayMs));
                    if (window == IntPtr.Zero) break;
                }
                if (window == IntPtr.Zero) break;
            }
            return new
            {
                scope = "owned Medium Synthetic menu timing; no policy writes or explicit foreground activation",
                original_test = "GUI flags & 0x14, then unconditional WM_CANCELMODE; due 200 ms, period 100 ms",
                fixed_test = "cancel only after GUI_POPUPMENUMODE and this window's menu owner; 5000 ms failure deadline",
                results
            };
        }
        finally { if (window != IntPtr.Zero) DestroyWindow(window); }
    }

    // Formal SelfTest shares the actual BM_CLICK, three-item popup,
    // cancellation, normal-exit and unchanged-draft obligations.
    private static bool VerifyProgramPopup(int commandDelayMs = 0)
    {
        try
        {
            var result = RunMenuTimingCase("selftest_popup_" + commandDelayMs, true, 0, commandDelayMs);
            if (!result.verified) Console.Error.WriteLine("settings_menu_verify: " + JsonSerializer.Serialize(result));
            return result.verified;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("settings_menu_verify_error: " + Program.Code(error));
            return false;
        }
    }

    private static MenuTimingResult RunMenuTimingCase(string name, bool fixedObserver, int beforeClickMs, int commandDelayMs)
    {
        if (!preview || core is not null || window == IntPtr.Zero || work is not null || page != 1
            || ruleLayer < 2 || menuTimingCase is not null || beforeClickMs < 0 || commandDelayMs < 0
            || beforeClickMs >= MenuTimingDeadlineMs || commandDelayMs >= MenuTimingDeadlineMs)
            throw new Boundary("settings_menu_probe_invalid_context");

        DrainMenuProbeMessages(); UpdateWindow(window);
        var run = new MenuTimingCase(name, window, commandDelayMs);
        var draftBefore = model.Draft;
        int selectionBefore = Selection(ProgramListId);
        if (selectionBefore < 0 || selectionBefore >= RowCount)
            throw new Boundary("settings_menu_probe_requires_program_selection");
        if (!SetWindowSubclass(run.Owner, MenuTimingProcedure, new UIntPtr(MenuTimingSubclassId), UIntPtr.Zero))
            throw new Boundary("settings_menu_probe_subclass_failed");

        Volatile.Write(ref menuTimingCase, run);
        Timer? dismiss = null;
        bool timerDrained = false, aliveAtCheck = false, returned = false;
        int observedAtCheck = 0;
        MenuTimingSnapshot? returnGui = null;
        try
        {
            run.Record("case_begin", new { fixedObserver, beforeClickMs, commandDelayMs, selected = selectionBefore, rows = RowCount, ruleLayer, denied }, run.Snapshot());
            dismiss = new Timer(_ =>
            {
                try
                {
                    int tick = Interlocked.Increment(ref run.TimerTicks);
                    run.CheckDeadline();
                    var gui = run.Snapshot();
                    bool ownPopup = gui.QuerySucceeded && (gui.Flags & 0x10) != 0 && gui.MenuOwner == run.Owner.ToInt64();
                    bool observed = fixedObserver ? ownPopup : gui.QuerySucceeded && (gui.Flags & 0x14) != 0;
                    if (observed) Interlocked.Exchange(ref run.OriginalObserved, 1);
                    if (ownPopup) Interlocked.Exchange(ref run.OwnedPopupObserved, 1);
                    long sample = run.Record("timer_sample", new { tick }, gui);
                    if (ownPopup) Interlocked.CompareExchange(ref run.OwnedSampleSequence, sample, 0);

                    // Original cases deliberately preserve unconditional cancel.
                    // Fixed cases cannot enqueue cancel before observing owner.
                    if (fixedObserver && (!ownPopup || Interlocked.CompareExchange(ref run.CancelRequested, 1, 0) != 0)) return;
                    run.Record("cancel_intent", new { tick, ownPopup });
                    bool posted = Native.PostMessageW(run.Owner, 0x1F, IntPtr.Zero, IntPtr.Zero);
                    int error = posted ? 0 : Marshal.GetLastPInvokeError();
                    if (posted) Interlocked.Increment(ref run.CancelPosts);
                    else
                    {
                        Interlocked.Increment(ref run.ObserverErrors);
                        if (fixedObserver) Interlocked.Exchange(ref run.CancelRequested, 0);
                    }
                    run.Record("cancel_post", new { tick, posted, error });
                }
                catch (Exception error)
                {
                    Interlocked.Increment(ref run.ObserverErrors);
                    run.Record("timer_observer_error", new { error = error.GetType().Name });
                }
            }, null, 200, 100);

            if (beforeClickMs != 0)
            {
                run.Record("before_click_delay_begin"); Thread.Sleep(beforeClickMs); run.Record("before_click_delay_end");
            }
            var button = PageHandle(ProgramMenuId);
            run.Record("bm_click_begin", new { button = button.ToInt64(), visible = IsWindowVisible(button), enabled = IsWindowEnabled(button) }, run.Snapshot());
            SendMessageW(button, 0xF5, IntPtr.Zero, IntPtr.Zero);
            returned = true; run.CheckDeadline(); returnGui = run.Snapshot();
            run.Record("bm_click_return", new { observed = Volatile.Read(ref run.OriginalObserved), windowAlive = Native.IsWindow(run.Owner) }, returnGui);
        }
        finally
        {
            try
            {
                if (dismiss is not null)
                {
                    using var drained = new ManualResetEvent(false);
                    dismiss.Dispose(drained);
                    // Sample before waiting: late callbacks cannot repair a miss.
                    observedAtCheck = Volatile.Read(ref run.OriginalObserved);
                    aliveAtCheck = window == run.Owner && Native.IsWindow(run.Owner);
                    drained.WaitOne(); timerDrained = true;
                    run.Record("timer_disposed", new { timerDrained });
                }
                if (timerDrained) DrainMenuProbeMessages();
            }
            finally
            {
                Volatile.Write(ref menuTimingCase, null);
                if (Native.IsWindow(run.Owner)) RemoveWindowSubclass(run.Owner, MenuTimingProcedure, new UIntPtr(MenuTimingSubclassId));
            }
        }

        var events = run.Events.OrderBy(e => e.Sequence).ToArray();
        long First(string kind) => events.FirstOrDefault(e => e.Kind == kind)?.Sequence ?? 0;
        long enter = First("WM_ENTERMENULOOP"), init = First("WM_INITMENUPOPUP"), exit = First("WM_EXITMENULOOP"), finish = First("bm_click_return");
        long intent = First("cancel_intent"), cancel = First("WM_CANCELMODE");
        bool lifecycle = run.EnterCount == 1 && run.ThreeItemInitCount == 1 && run.ExitCount == 1 && run.InvalidMenuCount == 0
            && enter > 0 && enter < init && init < cancel && cancel < exit && exit < finish;
        bool ownedCancellation = run.OwnedSampleSequence > 0 && run.OwnedSampleSequence < intent && intent < cancel && run.CancelPosts == 1;
        bool draftUnchanged = model.Draft == draftBefore;
        bool normalExit = returned && aliveAtCheck && returnGui is { QuerySucceeded: true, MenuOwner: 0 }
            && (returnGui.Flags & 0x14) == 0;
        bool verified = observedAtCheck == 1 && ownedCancellation && lifecycle && normalExit && draftUnchanged
            && Selection(ProgramListId) == selectionBefore && timerDrained && run.ObserverErrors == 0 && run.DeadlineExceeded == 0;
        return new(name, fixedObserver, run.Owner.ToInt64(), run.OwnerThread, observedAtCheck == 1 && aliveAtCheck,
            observedAtCheck, run.OriginalObserved, run.OwnedPopupObserved, run.TimerTicks, run.ObserverErrors,
            timerDrained, run.DeadlineExceeded != 0, draftUnchanged, lifecycle, ownedCancellation, normalExit, verified, events);
    }

    private static void DrainMenuProbeMessages()
    {
        while (window != IntPtr.Zero && PeekMessageW(out var queued, window, 0, 0, 1))
        { TranslateMessage(ref queued); DispatchMessageW(ref queued); }
    }

    private static IntPtr MenuTimingWindowProcedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp, UIntPtr id, UIntPtr data)
    {
        var run = Volatile.Read(ref menuTimingCase);
        if (run is not null)
        {
            try
            {
                bool command = message == 0x111 && ((ulong)wp & 0xffff) == ProgramMenuId;
                int menuItems = message == 0x117 ? GetMenuItemCount((IntPtr)wp) : -1;
                if (message == 0x211) { run.EnterCount++; if (wp == UIntPtr.Zero) run.InvalidMenuCount++; }
                if (message == 0x117) { if (menuItems == 3) run.ThreeItemInitCount++; else run.InvalidMenuCount++; }
                if (message == 0x212) { run.ExitCount++; if (wp == UIntPtr.Zero) run.InvalidMenuCount++; }
                string? name = message switch
                {
                    0x211 => "WM_ENTERMENULOOP", 0x117 => "WM_INITMENUPOPUP",
                    0x121 => "WM_ENTERIDLE", 0x212 => "WM_EXITMENULOOP",
                    0x1F => "WM_CANCELMODE", 0x6 => "WM_ACTIVATE",
                    0x1C => "WM_ACTIVATEAPP", 0x82 => "WM_NCDESTROY", _ => null
                };
                if (command) name = "program_menu_WM_COMMAND";
                if (name is not null)
                    run.Record(name, new
                    {
                        hwnd = hwnd.ToInt64(), wParam = wp.ToUInt64(), lParam = lp.ToInt64(), menuItems,
                        selected = command ? Selection(ProgramListId) : -1, rows = command ? RowCount : -1
                    }, run.Snapshot());
                if (command && run.CommandDelayMs != 0 && Interlocked.Exchange(ref run.CommandDelayApplied, 1) == 0)
                {
                    run.Record("command_delay_begin"); Thread.Sleep(run.CommandDelayMs); run.Record("command_delay_end");
                }
            }
            catch (Exception error)
            {
                Interlocked.Increment(ref run.ObserverErrors);
                run.Record("window_observer_error", new { error = error.GetType().Name });
            }
        }
        if (message == 0x82) RemoveWindowSubclass(hwnd, MenuTimingProcedure, id);
        return DefSubclassProc(hwnd, message, wp, lp);
    }

    private sealed class MenuTimingCase(string name, IntPtr owner, int commandDelayMs)
    {
        internal readonly string Name = name;
        internal readonly IntPtr Owner = owner;
        internal readonly int CommandDelayMs = commandDelayMs;
        internal readonly uint OwnerThread = Native.GetWindowThreadProcessId(owner, out _);
        internal readonly ConcurrentQueue<MenuTimingEvent> Events = new();
        private readonly Stopwatch clock = Stopwatch.StartNew();
        private long sequence;
        internal long OwnedSampleSequence;
        internal int OriginalObserved, OwnedPopupObserved, TimerTicks, ObserverErrors, CommandDelayApplied;
        internal int EnterCount, ThreeItemInitCount, ExitCount, InvalidMenuCount, CancelRequested, CancelPosts, DeadlineExceeded;

        internal void CheckDeadline()
        {
            if (clock.ElapsedMilliseconds < MenuTimingDeadlineMs || Interlocked.Exchange(ref DeadlineExceeded, 1) != 0) return;
            Record("deadline_exceeded");
            Console.Error.WriteLine("settings_menu_probe_deadline: " + Name);
            // Never blindly cancel an unobserved menu. A native hard block
            // without confirmed ownership requires the runner's process timeout.
        }

        internal MenuTimingSnapshot Snapshot()
        {
            var gui = new MenuGui { Size = (uint)Marshal.SizeOf<MenuGui>() };
            bool ok = GetMenuTimingGuiInfo(OwnerThread, ref gui);
            int error = ok ? 0 : Marshal.GetLastPInvokeError();
            if (!ok) Interlocked.Increment(ref ObserverErrors);
            return new(ok, error, gui.Flags, gui.Active.ToInt64(), gui.Focus.ToInt64(), gui.Capture.ToInt64(), gui.Menu.ToInt64(), Native.GetForegroundWindow().ToInt64());
        }

        internal long Record(string kind, object? data = null, MenuTimingSnapshot? gui = null)
        {
            long next = Interlocked.Increment(ref sequence);
            Events.Enqueue(new(next, clock.Elapsed.TotalMilliseconds, kind, Environment.CurrentManagedThreadId, GetMenuTimingThreadId(), gui, data));
            return next;
        }
    }

    private sealed record MenuTimingResult(string scenario, bool fixed_observer, long owner_hwnd, uint owner_thread,
        bool original_assertion, int original_observed_at_check, int observed_after_timer_drain, int owned_popup_observed,
        int timer_ticks, int observer_errors, bool timer_drained, bool deadline_exceeded, bool draft_unchanged,
        bool menu_lifecycle, bool owned_cancellation, bool normal_exit, bool verified, MenuTimingEvent[] events);
    private sealed record MenuTimingEvent(long Sequence, double Milliseconds, string Kind, int ManagedThread, uint NativeThread, MenuTimingSnapshot? Gui, object? Data);
    private sealed record MenuTimingSnapshot(bool QuerySucceeded, int QueryError, uint Flags, long Active, long Focus, long Capture, long MenuOwner, long Foreground);
    [DllImport("user32.dll", EntryPoint = "GetGUIThreadInfo", SetLastError = true)]
    private static extern bool GetMenuTimingGuiInfo(uint thread, ref MenuGui gui);
    [DllImport("kernel32.dll", EntryPoint = "GetCurrentThreadId")]
    private static extern uint GetMenuTimingThreadId();
}
