using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

internal record InputContext(long? Focus, long? Layout, string Composition)
{
    [StructLayout(LayoutKind.Sequential)] private struct Gui
    { public uint Size, Flags; public IntPtr Active, Focus, Capture, Menu, MoveSize, Caret; public Native.Rect CaretRect; }
    [DllImport("user32.dll")] private static extern bool GetGUIThreadInfo(uint thread, ref Gui gui);
    [DllImport("user32.dll")] private static extern IntPtr GetKeyboardLayout(uint thread);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    [DllImport("imm32.dll")] private static extern IntPtr ImmGetContext(IntPtr hwnd);
    [DllImport("imm32.dll")] private static extern bool ImmReleaseContext(IntPtr hwnd, IntPtr context);
    [DllImport("imm32.dll")] private static extern int ImmGetCompositionStringW(IntPtr context, uint kind, IntPtr text, uint length);
    [DllImport("imm32.dll")] private static extern IntPtr ImmGetDefaultIMEWnd(IntPtr hwnd);
    private delegate bool EnumWindow(IntPtr hwnd, IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool EnumThreadWindows(uint thread, EnumWindow callback, IntPtr parameter);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int capacity);
    internal static string MergeComposition(string imm, bool? candidate) =>
        candidate == true ? "active" : imm == "unknown" && candidate == false ? "inactive" : imm;
    private static bool? CandidateVisible(Bound bound, uint thread, IntPtr focus, IntPtr layout)
    {
        if (!Native.Foreground(bound.Hwnd) || layout == IntPtr.Zero ||
            Native.GetWindowThreadProcessId(focus, out var focusPid) != thread || focusPid != bound.Pid) return null;
        var ime = ImmGetDefaultIMEWnd(focus);
        var name = new StringBuilder(256);
        if (ime == IntPtr.Zero || Native.GetWindowThreadProcessId(ime, out var imePid) != thread || imePid != bound.Pid
            || GetClassNameW(ime, name, name.Capacity) == 0 || name.ToString() != "IME"
            || Native.GetAncestor(Native.GetWindow(ime, 4), 2).ToInt64() != bound.Hwnd) return null;
        var found = new Dictionary<string, List<IntPtr>>(); int count = 0; bool incomplete = false;
        var complete = EnumThreadWindows(thread, (window, _) => {
            if (++count > 64 || Native.GetWindowThreadProcessId(window, out var pid) != thread || pid != bound.Pid)
            { incomplete = true; return false; }
            name.Clear();
            if (GetClassNameW(window, name, name.Capacity) == 0) { incomplete = true; return false; }
            var className = name.ToString();
            if (className is "SoPY_Cand" or "SoPY_Comp2")
            {
                if (!found.TryGetValue(className, out var windows)) found[className] = windows = [];
                windows.Add(window);
            }
            return true;
        }, IntPtr.Zero);
        var current = GetGui(bound);
        if (!complete || incomplete || found.Count != 2 || current?.Focus != focus || !Native.Foreground(bound.Hwnd)
            || GetKeyboardLayout(thread) != layout) return null;
        // Read current visibility after enumeration; never retrieve candidate text.
        if (found.Values.SelectMany(w => w).Any(w => !Native.IsWindow(w))) return null;
        return found.Values.SelectMany(w => w).Any(Native.IsWindowVisible);
    }
    private static Gui? GetGui(Bound bound)
    {
        var thread = Native.GetWindowThreadProcessId(new IntPtr(bound.Hwnd), out var pid);
        var gui = new Gui { Size = (uint)Marshal.SizeOf<Gui>() };
        return pid == bound.Pid && thread != 0 && GetGUIThreadInfo(thread, ref gui) ? gui : null;
    }
    internal static InputContext Read(Bound bound)
    {
        var gui = GetGui(bound);
        if (gui is null || gui.Value.Focus == IntPtr.Zero || Native.GetAncestor(gui.Value.Focus, 2).ToInt64() != bound.Hwnd)
            return new(null, null, "unknown");
        var focus = gui.Value.Focus;
        var thread = Native.GetWindowThreadProcessId(new IntPtr(bound.Hwnd), out _);
        var layout = GetKeyboardLayout(thread);
        var context = ImmGetContext(focus);
        var composition = "unknown";
        if (context != IntPtr.Zero)
        {
            int count; bool released;
            try { count = ImmGetCompositionStringW(context, 8, IntPtr.Zero, 0); }
            finally { released = ImmReleaseContext(focus, context); }
            composition = count < 0 || !released ? "unknown" : count > 0 ? "active" : "inactive";
        }
        if (composition != "active") composition = MergeComposition(composition, CandidateVisible(bound, thread, focus, layout));
        return new(focus.ToInt64(), layout == IntPtr.Zero ? null : layout.ToInt64(), composition);
    }
    internal bool Changed(InputContext current) => Focus is not null && current.Focus != Focus
        || Layout is not null && current.Layout != Layout || Composition != "unknown" && current.Composition != Composition;
    internal static InputContext Prepare(Bound bound, Action check, InputLedger ledger, Receipt receipt)
    {
        InputContext? initial = null;
        return PrepareCore(() => { var current = Read(bound); initial ??= current; return current; }, check,
            () => ledger.Send(Executor.KeyPair(0x1b, false), receipt, preparation: true, finalPreflight: () => {
                check();
                var fresh = Read(bound);
                if (fresh.Focus != initial!.Focus || fresh.Layout != initial.Layout) throw new Boundary("input_context_changed");
                if (fresh.Composition == "inactive") throw new Boundary("ime_composition_already_closed");
                if (fresh.Composition != "active") throw new Boundary("input_context_changed");
            }),
            report => receipt.ImePreparation = report);
    }
    internal static InputContext PrepareCore(Func<InputContext> read, Action check, Action escape, Action<object> report)
    {
        var before = read();
        report(new { composition = before.Composition, focus_known = before.Focus is not null,
            layout_known = before.Layout is not null, composition_text_read = false });
        if (before.Composition != "active") return before;
        check();
        var current = read();
        if (before.Focus == current.Focus && before.Layout == current.Layout && current.Composition == "inactive")
        {
            report(new { composition = "inactive", state = "composition_already_closed", composition_text_read = false });
            return current;
        }
        if (before.Changed(current)) throw new Boundary("input_context_changed");
        try { escape(); }
        catch (Boundary error) when (error.Code == "ime_composition_already_closed")
        {
            var closed = read();
            if (closed.Focus != before.Focus || closed.Layout != before.Layout || closed.Composition != "inactive")
                throw new Boundary("input_context_changed");
            report(new { composition = "inactive", state = "composition_already_closed", composition_text_read = false });
            return closed;
        }
        var wait = Stopwatch.StartNew();
        while (true)
        {
            check();
            var after = read();
            if (before.Focus != after.Focus || before.Layout != after.Layout) throw new Boundary("input_context_changed");
            if (after.Composition == "inactive")
            {
                report(new { composition = "inactive", focus_known = true, layout_known = after.Layout is not null,
                    composition_text_read = false, state = "composition_interrupted" });
                return after;
            }
            if (after.Composition == "unknown" || wait.ElapsedMilliseconds >= 150) throw new Boundary("input_context_changed");
            Thread.Sleep(10);
        }
    }
    internal static bool MouseDown(Step step) => step.Raw.Type == 0 && (step.Raw.Data.Mouse.Flags & 0x2a) != 0;
    private static Native.Point AbsolutePoint(Native.Mouse mouse, DesktopShape? desktop)
    {
        if (desktop is null) throw new Boundary("desktop_topology_required");
        return new() { X = checked((int)(desktop.Left + Math.Round(mouse.Dx * (desktop.Width - 1.0) / 65535))),
            Y = checked((int)(desktop.Top + Math.Round(mouse.Dy * (desktop.Height - 1.0) / 65535))) };
    }
    internal static Native.Point? FocusPoint(Step[] steps, DesktopShape? desktop, Native.Point? initial)
    {
        var point = initial;
        Native.Point? clicked = null;
        foreach (var step in steps.Where(s => s.Raw.Type == 0))
        {
            if ((step.Raw.Data.Mouse.Flags & 0x8000) != 0) point = AbsolutePoint(step.Raw.Data.Mouse, desktop);
            else if ((step.Raw.Data.Mouse.Flags & 1) != 0) point = null; // Pointer acceleration makes relative destinations indeterminate.
            if (MouseDown(step)) clicked = point;
        }
        return clicked;
    }
    internal static long? CheckReceiver(Bound bound, Step[] steps, DesktopShape? desktop)
    {
        if (!steps.Any(step => step.Raw.Type == 0)) return null;
        var gui = GetGui(bound) ?? throw new Boundary("mouse_receiver_unavailable");
        if (gui.Capture != IntPtr.Zero)
        {
            if (Native.GetAncestor(gui.Capture, 2).ToInt64() != bound.Hwnd) throw new Boundary("mouse_receiver_changed");
            return null; // Capture identifies the target root, not the child that may receive focus.
        }
        var points = new List<Native.Point>();
        foreach (var step in steps.Where(s => s.Raw.Type == 0 && (s.Raw.Data.Mouse.Flags & 0x8000) != 0))
        {
            points.Add(AbsolutePoint(step.Raw.Data.Mouse, desktop));
        }
        Native.Point? initial = null;
        if (points.Count == 0)
        {
            if (!GetCursorPos(out var point)) throw new Boundary("mouse_receiver_unavailable");
            points.Add(point);
            initial = point;
        }
        if (points.Any(point => Native.GetAncestor(Native.WindowFromPoint(point), 2).ToInt64() != bound.Hwnd))
            throw new Boundary("mouse_receiver_changed");
        if (FocusPoint(steps, desktop, initial) is not { } clicked) return null;
        var receiver = Native.WindowFromPoint(clicked);
        if (Native.GetAncestor(receiver, 2).ToInt64() != bound.Hwnd) throw new Boundary("mouse_receiver_changed");
        return receiver.ToInt64();
    }
}

internal sealed class InputContextGuard(InputContext baseline, bool keyboard)
{
    internal InputContext Baseline { get; private set; } = baseline;
    private long? expectedFocus;
    private long focusDeadline;
    private bool traversal;
    internal void TraversalDispatched(long now) { traversal = true; focusDeadline = now + 150; }
    internal void MouseDispatched(long? receiver, long now)
    {
        expectedFocus = keyboard ? receiver : null;
        focusDeadline = now + 150;
    }
    internal void Recheck(InputContext current, long now)
    {
        if (now > focusDeadline) { expectedFocus = null; traversal = false; }
        if (!keyboard)
        {
            // Mouse-only plans do not depend on keyboard focus, layout or IME.
            // Retain the observed context without interrupting normal UI changes.
            Baseline = current;
            return;
        }
        if (!Baseline.Changed(current)) return;
        if (Baseline.Focus is not null && current.Focus is not null && (current.Focus == expectedFocus || traversal)
            && !(Baseline with { Focus = current.Focus }).Changed(current))
        {
            Baseline = Baseline with { Focus = current.Focus };
            expectedFocus = null; // One accepted mouse-down may rebind only this exact child once.
            traversal = false;
            return;
        }
        throw new Boundary("input_context_changed");
    }
}
