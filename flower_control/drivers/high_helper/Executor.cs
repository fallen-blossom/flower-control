using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Flower.HighHelper;

internal sealed class ResourceLocks : IDisposable
{
    private readonly int thread = Environment.CurrentManagedThreadId;
    private readonly List<Mutex> held = [];
    private readonly List<Mutex> opened = [];
    internal static string Name(string resource) => "Local\\FlowerControl.Resource.v1."
        + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(resource))).ToLowerInvariant();
    internal ResourceLocks(IEnumerable<string> resources)
    {
        try
        {
            foreach (var resource in resources.Order(StringComparer.Ordinal))
            {
                // Medium pre-creates and retains these exact objects without ownership.
                // Do not create a new High-labelled lock or substitute a lock name.
                var mutex = Mutex.OpenExisting(Name(resource)); opened.Add(mutex);
                try
                {
                    if (!mutex.WaitOne(0)) throw new Boundary("resource_busy");
                    held.Add(mutex);
                }
                catch (AbandonedMutexException) { held.Add(mutex); throw new Boundary("abandoned_resource"); }
            }
        }
        catch
        {
            try { Dispose(); }
            catch { throw new Boundary("mutex_release_unconfirmed"); }
            throw;
        }
    }
    public void Dispose()
    {
        if (thread != Environment.CurrentManagedThreadId) throw new Boundary("lock_wrong_thread");
        for (var i = held.Count - 1; i >= 0; --i) held[i].ReleaseMutex();
        held.Clear();
        foreach (var mutex in opened) mutex.Dispose();
        opened.Clear();
    }
}

internal record Step(Native.Input Raw, string? Token = null, bool Down = false, Native.Input Release = default);
internal sealed class InputLedger
{
    internal string Identity { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
    private readonly Func<Native.Input[], uint> send;
    private readonly List<Step> held = [];
    private bool known = true;
    private readonly SharedWriteGate? writeGate;
    private readonly long stopEpoch;
    internal InputLedger(Func<Native.Input[], uint>? send = null, SharedWriteGate? writeGate = null)
    {
        this.writeGate = writeGate; stopEpoch = writeGate?.Snapshot().Epoch ?? 0;
        this.send = send ?? (steps => Native.SendInput((uint)steps.Length, steps, Marshal.SizeOf<Native.Input>()));
    }
    internal string State => !known ? "unknown" : held.Count != 0 ? "release_pending" : "released";
    internal bool CountKnown => known;
    internal HashSet<string> OwnTokens => held.Select(step => step.Token!).ToHashSet();
    internal void Send(Step[] steps, Receipt result, bool activation = false, bool preparation = false, Action? finalPreflight = null)
    {
        writeGate?.Admit(stopEpoch); // Release uses its own bypass: stopping must never prevent exact ups.
        finalPreflight?.Invoke(); // Optional immediate IME recheck after gate admission, before any dispatch count.
        if (!activation && !preparation) result.BusinessAttempted = true;
        result.RequestedEvents += steps.Length;
        known = false;
        var sending = Stopwatch.StartNew();
        uint count;
        try { count = send(steps.Select(s => s.Raw).ToArray()); }
        finally
        {
            if (!activation && !preparation)
                result.TimingsMs["dispatch"] = result.TimingsMs.GetValueOrDefault("dispatch") + sending.Elapsed.TotalMilliseconds;
        }
        if (count > steps.Length) throw new Boundary("input_count_unknown");
        for (var i = 0; i < count; ++i)
        {
            var step = steps[i];
            if (step.Token is null) continue;
            if (step.Down) held.Add(step);
            else
            {
                var index = held.FindLastIndex(s => s.Token == step.Token);
                if (index < 0) throw new Boundary("input_count_unknown");
                held.RemoveAt(index);
            }
        }
        known = true;
        result.SentEvents += (int)count;
        if (activation) result.ActivationEvents += (int)count;
        else if (preparation) result.ImeEvents += (int)count;
        else result.BusinessEvents += (int)count;
        if (count != steps.Length) throw new Boundary("input_partial", Marshal.GetLastWin32Error());
    }
    internal void Release(Receipt result)
    {
        if (held.Count == 0) return;
        var wasKnown = known;
        var releases = held.AsEnumerable().Reverse().Select(s => s.Release).ToArray();
        known = false;
        var count = send(releases);
        if (count > releases.Length) throw new Boundary("input_count_unknown");
        held.RemoveRange(held.Count - (int)count, (int)count);
        result.ReleaseEvents += (int)count;
        known = wasKnown;
        if (count != releases.Length) throw new Boundary("release_partial", Marshal.GetLastWin32Error());
    }
}

internal static class Executor
{
    internal static bool InitialGeometryRequired(Operation operation, bool minimized) =>
        operation.Kind == "window_layout" || operation.Kind == "computer_input_plan" && !(minimized && operation.RestoreMinimized);
    private static readonly int[] ExternalKeys = [1, 2, 4, 5, 6, 0x10, 0x11, 0x12, 0x5b, 0x5c];
    internal static void ExternalInput(InputLedger? ledger = null)
    {
        var own = ledger?.OwnTokens ?? [];
        bool Owned(int code)
        {
            if (own.Contains("vk:" + code)) return true;
            if (code == 1 && own.Contains("mouse:left") || code == 2 && own.Contains("mouse:right") || code == 4 && own.Contains("mouse:middle")) return true;
            return code switch { 0xa0 => own.Contains("vk:16"), 0xa2 => own.Contains("vk:17"), 0xa4 => own.Contains("vk:18"),
                16 => own.Contains("vk:160") || own.Contains("vk:161"), 17 => own.Contains("vk:162") || own.Contains("vk:163"),
                18 => own.Contains("vk:164") || own.Contains("vk:165"), _ => false };
        }
        var codes = ledger is null ? ExternalKeys : Enumerable.Range(1, 254);
        if (codes.Any(vk => !Owned(vk) && Native.GetAsyncKeyState(vk) < 0)) throw new Boundary("external_input_held");
    }
    private static void RequestForeground(IntPtr hwnd, Receipt result)
    {
        result.ActivationRequested = true;
        var brought = Native.BringWindowToTop(hwnd);
        result.ActivationDiagnostics.Add(new ActivationAttempt("BringWindowToTop", brought, brought ? 0 : Marshal.GetLastWin32Error()));
        var set = Native.SetForegroundWindow(hwnd);
        result.ActivationDiagnostics.Add(new ActivationAttempt("SetForegroundWindow", set, set ? 0 : Marshal.GetLastWin32Error()));
    }
    internal static bool WaitForegroundCompletion(IntPtr previous, Action check,
        Func<(IntPtr Window, bool Target)> sample, Func<bool> protectedForeground,
        Func<long> elapsed, Func<int> remaining, Func<int, bool> fence, Action<int> delay)
    {
        var started = elapsed();
        bool responsive = false;
        while (true)
        {
            check();
            var current = sample();
            if (current.Target) return true;
            // SetForegroundWindow can briefly leave no active window while its
            // cross-queue notification is pending. A third window is interference.
            if (current.Window != IntPtr.Zero && (current.Window != previous || protectedForeground()))
                throw new Boundary("foreground_changed");
            var budget = Math.Min(200L - (elapsed() - started), remaining());
            if (budget <= 0)
            { check(); if (!responsive) throw new Boundary("target_unresponsive"); return false; }
            // WM_NULL fences the target queue's asynchronous activation nudge.
            // Split a stalled target into short waits so Stop stays observable.
            responsive |= fence((int)Math.Min(20, budget));
            check();
            current = sample();
            if (current.Target) return true;
            if (current.Window != IntPtr.Zero && (current.Window != previous || protectedForeground()))
                throw new Boundary("foreground_changed");
            budget = Math.Min(200L - (elapsed() - started), remaining());
            if (budget <= 0)
            { check(); if (!responsive) throw new Boundary("target_unresponsive"); return false; }
            delay((int)Math.Min(10, budget));
        }
    }
    private static bool WaitForegroundCompletion(Prepare prepare, Bound bound, IntPtr previous,
        Func<bool> stopped, Stopwatch clock)
    {
        var hwnd = new IntPtr(bound.Hwnd);
        return WaitForegroundCompletion(previous,
            () => Check(prepare, bound, stopped, clock, false, false),
            () => { var current = Native.GetForegroundWindow(); return (current, Native.GetAncestor(current, 2) == hwnd); },
            Native.ProtectedForeground, () => clock.ElapsedMilliseconds,
            () => prepare.DeadlineMs - (int)clock.ElapsedMilliseconds,
            timeout => Native.SendMessageTimeoutW(hwnd, 0, IntPtr.Zero, IntPtr.Zero, 3, (uint)timeout, out _) != IntPtr.Zero,
            Thread.Sleep);
    }
    internal static Step[] KeyPair(ushort scan, bool unicode)
    {
        var down = new Native.Input { Type = 1, Data = new Native.Union { Key = new Native.Key {
            Vk = unicode ? (ushort)0 : scan, Scan = unicode ? scan : (ushort)0, Flags = unicode ? 4U : 0U } } };
        var up = down; up.Data.Key.Flags |= 2;
        var token = (unicode ? "unicode:" : "vk:") + scan;
        return [new Step(down, token, true, up), new Step(up, token)];
    }
    internal static void Check(Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, bool foreground, bool geometry, InputLedger? ledger = null)
    {
        if (stopped()) throw new Boundary("input_stopped");
        if (clock.ElapsedMilliseconds >= prepare.DeadlineMs) throw new Boundary("deadline_expired");
        Native.VerifyPeer(prepare.Parent);
        if (Native.CheckTarget(prepare.Target with { Nonce = bound.WindowNonce }, false) != bound) throw new Boundary("target_identity_changed");
        if (foreground && !Native.Foreground(bound.Hwnd)) throw new Boundary("foreground_changed");
        if (geometry) Native.CheckGeometry(prepare.Target, prepare.Operation.Kind == "computer_input_plan");
        if (Protocol.UsesPhysicalInput(prepare.Operation)) ExternalInput(ledger);
    }
    internal static void Execute(Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, InputLedger ledger, Receipt result)
    {
        Check(prepare, bound, stopped, clock, false,
              InitialGeometryRequired(prepare.Operation, Native.IsIconic(new IntPtr(bound.Hwnd))));
        if (prepare.Operation.Kind == "bind") { result.State = "bound"; return; }
        var activationAt = clock.Elapsed.TotalMilliseconds;
        var hwnd = new IntPtr(bound.Hwnd);
        var previous = Native.GetForegroundWindow();
        if (Native.IsIconic(hwnd))
        {
            if (!prepare.Operation.RestoreMinimized) throw new Boundary("target_minimized");
            result.ActivationRequested = true;
            Native.ShowWindowAsync(hwnd, 9);
            // Identity/Stop/desktop checks continue while asynchronous restore
            // settles. The caller's observed geometry is never replaced here.
            for (var i = 0; i < 10 && Native.IsIconic(hwnd); ++i)
            {
                Check(prepare, bound, stopped, clock, false, false);
                Thread.Sleep(10);
            }
            if (Native.IsIconic(hwnd)) throw new Boundary("target_minimized");
        }
        Check(prepare, bound, stopped, clock, false, false);
        if (!Native.Foreground(bound.Hwnd))
        {
            if (Native.ProtectedForeground()) throw new Boundary("activation_foreground_protected");
            if (Native.SendMessageTimeoutW(hwnd, 0, IntPtr.Zero, IntPtr.Zero, 3, 200, out _) == IntPtr.Zero)
                throw new Boundary("target_unresponsive", Marshal.GetLastWin32Error());
            Check(prepare, bound, stopped, clock, false, false);
            if (Native.GetForegroundWindow() != previous && !Native.Foreground(bound.Hwnd)) throw new Boundary("foreground_changed");
            if (Native.IsShellDesktop(bound))
                ShellDesktopWorker.Execute(prepare, bound, previous, stopped, clock, ledger, result);
            else
            {
                RequestForeground(hwnd, result);
                if (!WaitForegroundCompletion(prepare, bound, previous, stopped, clock))
                {
                    Check(prepare, bound, stopped, clock, false, false);
                    var retryForeground = Native.GetForegroundWindow();
                    // Completion at the budget edge already satisfies activation;
                    // use one sample before deciding whether Alt is still needed.
                    if (Native.GetAncestor(retryForeground, 2) != hwnd)
                    {
                        if (retryForeground != previous || Native.ProtectedForeground()) throw new Boundary("foreground_changed");
                        ledger.Send(KeyPair(0x12, false), result, activation: true);
                        Check(prepare, bound, stopped, clock, false, false);
                        if (Native.GetForegroundWindow() != previous && !Native.Foreground(bound.Hwnd)) throw new Boundary("foreground_changed");
                        RequestForeground(hwnd, result);
                        WaitForegroundCompletion(prepare, bound, previous, stopped, clock);
                    }
                }
            }
        }
        // One bounded activation attempt with one balanced Alt-assisted retry.
        for (var i = 0; i < 10 && !Native.Foreground(bound.Hwnd); ++i)
        {
            Check(prepare, bound, stopped, clock, false, false);
            Thread.Sleep(10);
        }
        result.Foreground = Native.Foreground(bound.Hwnd);
        result.TimingsMs["activation"] = clock.Elapsed.TotalMilliseconds - activationAt;
        if (!result.Foreground) throw new Boundary("user_activation_required");
        if (prepare.Operation.Kind == "activate") { result.State = "activated"; return; }
        using var foregroundEvents = new ForegroundEvents(bound);
        bool PhaseStopped() { foregroundEvents.Check(); return stopped(); }
        if (prepare.Operation.Kind == "computer_input_plan")
        {
            ComputerPlans.Execute(ComputerPlans.Parse(prepare.Operation.Plan!.Value), prepare, bound, PhaseStopped, clock, ledger, result);
            foregroundEvents.Check();
            return;
        }
        if (prepare.Operation.Kind == "text")
        {
            foreach (var batch in ComputerPlans.TextBatches(prepare.Operation.Text!))
            {
                Check(prepare, bound, PhaseStopped, clock, true, false);
                ledger.Send(batch.Segments[0].Steps, result);
            }
        }
        else
        {
            Check(prepare, bound, PhaseStopped, clock, true, true);
            int x = prepare.Operation.X!.Value, y = prepare.Operation.Y!.Value;
            var rectangle = prepare.Target.Bounds;
            if (x < rectangle[0] || x >= rectangle[2] || y < rectangle[1] || y >= rectangle[3]
                || Native.GetAncestor(Native.WindowFromPoint(new Native.Point { X = x, Y = y }), 2) != hwnd)
                throw new Boundary("click_receiver_changed");
            int left = Native.GetSystemMetrics(76), top = Native.GetSystemMetrics(77);
            int width = Native.GetSystemMetrics(78), height = Native.GetSystemMetrics(79);
            if (width <= 0 || height <= 0 || x < left || x >= (long)left + width || y < top || y >= (long)top + height)
                throw new Boundary("desktop_topology_changed");
            var move = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse {
                Dx = (int)Math.Round((x - (double)left) * 65535 / Math.Max(1, width - 1)),
                Dy = (int)Math.Round((y - (double)top) * 65535 / Math.Max(1, height - 1)), Flags = 0xc001 } } };
            var down = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 2 } } };
            var up = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 4 } } };
            Check(prepare, bound, PhaseStopped, clock, true, true);
            ledger.Send([new Step(move), new Step(down, "mouse:left", true, up), new Step(up, "mouse:left")], result);
        }
        foregroundEvents.Check();
        result.State = "dispatched_unverified";
    }
}
