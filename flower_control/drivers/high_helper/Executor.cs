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
    internal static Mutex Retain(string resource) => Mutex.OpenExisting(Name(resource));
    internal ResourceLocks(IEnumerable<string> resources)
    {
        try
        {
            foreach (var resource in resources.Order(StringComparer.Ordinal))
            {
                // Medium pre-creates and retains these exact objects without ownership.
                // Do not create a new High-labelled lock or substitute a lock name.
                var mutex = Retain(resource); opened.Add(mutex);
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
    private readonly Func<bool>? stopped;
    private long lastDispatchCheck;
    private long lastWaitCheck;
    private long? mouseCapture;
    internal Action<Step[]>? PrivacyCheck;
    internal Func<string, bool>? PreDispatchRecovery;
    internal Action? InvalidatePrivacy;
    internal (Bound Target, PasswordMetadata.Info Metadata)? GesturePrivacy, PendingGesturePrivacy;
    internal void ClearGesturePrivacy() { GesturePrivacy = PendingGesturePrivacy = null; }
    internal InputLedger(Func<Native.Input[], uint>? send = null, SharedWriteGate? writeGate = null, Func<bool>? stopped = null)
    {
        this.writeGate = writeGate; stopEpoch = writeGate?.Snapshot().Epoch ?? 0;
        this.send = send ?? InputActivityLatch.Send;
        this.stopped = stopped;
    }
    internal string State => !known ? "unknown" : held.Count != 0 ? "release_pending" : "released";
    internal bool CountKnown => known;
    internal HashSet<string> OwnTokens => held.Select(step => step.Token!).ToHashSet();
    internal void CheckMouseCapture(long capture)
    {
        if (!held.Any(s => s.Token!.StartsWith("mouse:", StringComparison.Ordinal))) { mouseCapture = null; return; }
        if (mouseCapture is not null && mouseCapture != capture) throw new Boundary("pointer_drag_capture_changed");
        if (capture != 0) mouseCapture = capture;
    }
    internal void CheckMotionWait(Func<bool> stopped, Stopwatch clock, int deadlineMs, Action? heldCheck = null)
    {
        long now = Stopwatch.GetTimestamp();
        if (lastWaitCheck != 0
            && Stopwatch.GetElapsedTime(lastWaitCheck, now).TotalMilliseconds < PointerPath.MotionWaitCheckMs) return;
        lastWaitCheck = now;
        if (stopped()) throw new Boundary("input_stopped");
        if (clock.ElapsedMilliseconds >= deadlineMs) throw new Boundary("deadline_expired");
        writeGate?.Admit(stopEpoch);
        if (held.Count != 0 && Stopwatch.GetElapsedTime(lastDispatchCheck).TotalMilliseconds >= PointerPath.MotionCheckMs)
        {
            if (heldCheck is null) throw new Boundary("held_input_check_required");
            heldCheck(); lastDispatchCheck = Stopwatch.GetTimestamp();
        }
    }
    internal void KeyboardUps(Step[] steps, Receipt result, Action check)
    {
        if (State != "released" || steps.Any(step => step.Down || step.Raw.Type != 1
                || step.Token is null || !step.Token.StartsWith("vk:", StringComparison.Ordinal)
                || (step.Raw.Data.Key.Flags & 2) == 0)) throw new Boundary("keyboard_preparation_requires_ups");
        check(); writeGate?.Admit(stopEpoch); check();
        if (stopped?.Invoke() == true) throw new Boundary("input_stopped");
        result.RequestedEvents += steps.Length;
        known = false;
        var count = send(steps.Select(step => step.Raw).ToArray());
        if (count > steps.Length) throw new Boundary("input_count_unknown");
        known = true;
        result.SentEvents += (int)count;
        result.KeyboardReleaseEvents += (int)count;
        if (count != steps.Length) throw new Boundary("keyboard_preparation_incomplete");
    }
    internal void Send(Step[] steps, Receipt result, bool activation = false, bool preparation = false, Action? finalPreflight = null, bool pointer = false)
    {
        void Prepare()
        {
            if (steps.Any(s => s.Raw.Type == 1)) ClearGesturePrivacy();
            if (!activation && (!pointer || OwnTokens.Any(t => t.StartsWith("mouse:", StringComparison.Ordinal)))
                && !steps.All(s => s.Token is not null && !s.Down && OwnTokens.Contains(s.Token)))
            {
                long privacyAt = Stopwatch.GetTimestamp();
                try { PrivacyCheck?.Invoke(steps); }
                finally { PointerPath.AddTiming(result, "privacy_path", privacyAt); }
            }
            long gateAt = Stopwatch.GetTimestamp();
            try { writeGate?.Admit(stopEpoch); } // Release uses its own bypass: stopping must never prevent exact ups.
            finally { PointerPath.AddTiming(result, "write_gate", gateAt); }
            long preflightAt = Stopwatch.GetTimestamp();
            try { finalPreflight?.Invoke(); } // Full immediate recheck before any dispatch count.
            finally { PointerPath.AddTiming(result, "final_preflight", preflightAt); }
            gateAt = Stopwatch.GetTimestamp();
            try { writeGate?.Admit(stopEpoch); } // A check/provider can itself race a new Stop.
            finally { PointerPath.AddTiming(result, "write_gate", gateAt); }
            long stopAt = Stopwatch.GetTimestamp();
            try { if (stopped?.Invoke() == true) throw new Boundary("input_stopped"); }
            finally { PointerPath.AddTiming(result, "stop_check", stopAt); }
            lastDispatchCheck = Stopwatch.GetTimestamp();
        }
        try { Prepare(); }
        catch (Boundary error)
        {
            if (PreDispatchRecovery?.Invoke(error.Code) != true) throw;
            ClearGesturePrivacy(); InvalidatePrivacy?.Invoke();
            Prepare(); // No requested count or native call existed before this recovery.
        }
        if (!activation && !preparation && !pointer) result.BusinessAttempted = true;
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
        var reviewedGesture = PendingGesturePrivacy;
        if (steps.Any(s => s.Raw.Type == 1)) ClearGesturePrivacy();
        if (count == steps.Length && steps.Any(s => s.Down && s.Token?.StartsWith("mouse:", StringComparison.Ordinal) == true))
            GesturePrivacy = reviewedGesture;
        PendingGesturePrivacy = null;
        if (count != steps.Length || !OwnTokens.Any(t => t.StartsWith("mouse:", StringComparison.Ordinal))) ClearGesturePrivacy();
        known = true;
        result.SentEvents += (int)count;
        if (activation) result.ActivationEvents += (int)count;
        else if (preparation) result.ImeEvents += (int)count;
        else if (pointer) result.PointerEvents += (int)count;
        else result.BusinessEvents += (int)count;
        if (count != steps.Length) throw new Boundary("input_partial", Marshal.GetLastWin32Error());
    }
    internal void Release(Receipt result)
    {
        ClearGesturePrivacy();
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
    internal static void CheckAuthority(Prepare prepare, Func<bool> stopped, Stopwatch clock, InputLedger? ledger = null,
        bool checkExternal = true)
    {
        if (stopped()) throw new Boundary("input_stopped");
        if (clock.ElapsedMilliseconds >= prepare.DeadlineMs) throw new Boundary("deadline_expired");
        Native.VerifyPeer(prepare.Parent);
        if (checkExternal && Protocol.UsesPhysicalInput(prepare.Operation)) ExternalInput(ledger);
    }
    internal static void WaitActivationInputsReleased(Func<bool> held, Action check, Action wait)
    {
        while (held()) { check(); wait(); }
    }
    internal static void EndKeyboardInput(Prepare prepare, Bound bound, Func<bool> stopped,
        Stopwatch clock, InputLedger ledger, Receipt result)
    {
        void Check()
        {
            CheckAuthority(prepare, stopped, clock, ledger, checkExternal: false);
            if (Native.CheckTarget(prepare.Target with { Nonce = bound.WindowNonce }, false) != bound)
                throw new Boundary("target_identity_changed");
            Native.Desktop();
            if (Native.ProtectedForeground()) throw new Boundary("activation_foreground_protected");
        }
        Check();
        if (ledger.State != "released") { ExternalInput(ledger); return; }
        if (prepare.Operation.Kind == "activate")
        {
            // Preserve the person's held inputs if they resumed using the
            // computer just after the takeover countdown.
            WaitActivationInputsReleased(() => Enumerable.Range(1, 254).Any(vk => Native.GetAsyncKeyState(vk) < 0),
                Check, () => Thread.Sleep(20));
            return;
        }
        var keys = Enumerable.Range(8, 247).Where(vk => Native.GetAsyncKeyState(vk) < 0).ToHashSet();
        foreach (var (generic, left, right) in new[] { (16, 160, 161), (17, 162, 163), (18, 164, 165) })
            if (keys.Contains(left) || keys.Contains(right)) keys.Remove(generic);
        if (keys.Count == 0) return;
        var previous = Native.GetForegroundWindow();
        var steps = keys.Order().Where(vk => Native.GetAsyncKeyState(vk) < 0)
            .Select(vk => {
                var step = KeyPair((ushort)vk, false)[1];
                if (vk is 0x21 or 0x22 or 0x23 or 0x24 or 0x25 or 0x26 or 0x27 or 0x28
                        or 0x2c or 0x2d or 0x2e or 0x5b or 0x5c or 0x6f or 0x90 or 0xa3 or 0xa5)
                { var raw = step.Raw; raw.Data.Key.Flags |= 1; step = step with { Raw = raw }; }
                return step;
            }).ToArray();
        if (steps.Length == 0) return;
        ledger.KeyboardUps(steps, result, () => {
            Check();
            if (Native.GetForegroundWindow() != previous) throw new Boundary("foreground_changed");
        });
    }
    internal static UserPermissionSettings Check(Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock,
        bool foreground, bool geometry, InputLedger? ledger = null, Receipt? result = null)
    {
        long stage = Stopwatch.GetTimestamp();
        CheckAuthority(prepare, stopped, clock, ledger);
        PointerPath.AddTiming(result, "authority_check", stage);
        // One fresh settings read for this synchronous check. Callers may pass
        // it down to the receiver and swept-region predicates of this same
        // preflight; it never survives a wait, recovery or another dispatch.
        stage = Stopwatch.GetTimestamp();
        var permissions = UserPermissions.Read();
        PointerPath.AddTiming(result, "permission_read", stage);
        stage = Stopwatch.GetTimestamp();
        try
        {
            if (Native.CheckTarget(prepare.Target with { Nonce = bound.WindowNonce }, false, permissions) != bound)
                throw new Boundary("target_identity_changed");
        }
        finally { PointerPath.AddTiming(result, "target_check", stage); }
        stage = Stopwatch.GetTimestamp();
        try { if (foreground && !Native.Foreground(bound.Hwnd)) throw new Boundary("foreground_changed"); }
        finally { PointerPath.AddTiming(result, "foreground_check", stage); }
        stage = Stopwatch.GetTimestamp();
        try { if (geometry) Native.CheckGeometry(prepare.Target, prepare.Operation.Kind == "computer_input_plan"); }
        finally { PointerPath.AddTiming(result, "geometry_check", stage); }
        return permissions;
    }
    internal static void RequireActivationTarget(string kind, bool implicitActivation, Func<bool> ownedPopup)
    {
        if ((implicitActivation || kind is not ("bind" or "activate")) && ownedPopup())
            throw new Boundary("new_window_detected");
    }
    internal static bool RecoverInitialActivation(string reason, InputLedger ledger, Receipt result,
        Action authority, Action target, Action retry)
    {
        if (reason != "foreground_changed" || ledger.State != "released" || result.ForegroundRecoveries != 0)
            return false;
        authority(); target();
        ++result.ForegroundRecoveries;
        retry(); // Same clock, immutable target and unsent business plan.
        return true;
    }
    internal static void Execute(Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, InputLedger ledger, Receipt result,
        bool implicitActivation = false, Func<bool>? waitStopped = null, ForegroundEvents? activationHistory = null,
        ComputerPlan? inputPlan = null, PointerPath.PreparedApproach? preparedApproach = null)
    {
        using var ownedActivationEvents = activationHistory is null && prepare.Operation.Kind != "bind"
            && (prepare.Operation.Kind != "activate" || implicitActivation)
            ? new ForegroundEvents(bound, activationPhase: true) : null;
        var activationEvents = activationHistory ?? ownedActivationEvents;
        void ActivationTarget() => RequireActivationTarget(prepare.Operation.Kind, implicitActivation,
            () => {
                activationEvents?.Check();
                return Native.ForegroundChangeReason(bound, Native.GetForegroundWindow().ToInt64()) == "new_window_detected";
            });
        var hwnd = new IntPtr(bound.Hwnd);
        try
        {
        ActivationTarget();
        if (prepare.Operation.Kind != "bind") EndKeyboardInput(prepare, bound, stopped, clock, ledger, result);
        Check(prepare, bound, stopped, clock, false,
              InitialGeometryRequired(prepare.Operation, Native.IsIconic(new IntPtr(bound.Hwnd))));
        if (prepare.Operation.Kind == "bind") { result.State = "bound"; return; }
        var activationAt = clock.Elapsed.TotalMilliseconds;
        var previous = Native.GetForegroundWindow();
        if (Native.IsIconic(hwnd))
        {
            ActivationTarget();
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
            ActivationTarget();
            if (Native.ProtectedForeground()) throw new Boundary("activation_foreground_protected");
            if (Native.SendMessageTimeoutW(hwnd, 0, IntPtr.Zero, IntPtr.Zero, 3, 200, out _) == IntPtr.Zero)
                throw new Boundary("target_unresponsive", Marshal.GetLastWin32Error());
            Check(prepare, bound, stopped, clock, false, false);
            ActivationTarget();
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
                        ActivationTarget();
                        ledger.Send(KeyPair(0x12, false), result, activation: true);
                        Check(prepare, bound, stopped, clock, false, false);
                        if (Native.GetForegroundWindow() != previous && !Native.Foreground(bound.Hwnd)) throw new Boundary("foreground_changed");
                        ActivationTarget();
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
        }
        catch (Boundary error)
        {
            if (!RecoverInitialActivation(error.Code, ledger, result,
                () => Check(prepare, bound, stopped, clock, false,
                    InitialGeometryRequired(prepare.Operation, Native.IsIconic(hwnd)), ledger),
                () => {
                    ActivationTarget();
                    if (Native.ProtectedForeground()) throw new Boundary("activation_foreground_protected");
                },
                () => Execute(prepare, bound, stopped, clock, ledger, result, implicitActivation, waitStopped, activationEvents))) throw;
            return;
        }
        activationEvents!.EndActivation(bound);
        ForegroundEvents? foregroundEvents = activationEvents;
        var priority = new ForegroundPriority(() => result.ForegroundRecoveries == 0 ? ledger.State : "recovery_exhausted",
            () => CheckAuthority(prepare, stopped, clock, ledger, checkExternal: false),
            () => {
                foregroundEvents?.CheckRecovery();
                if (Native.ForegroundChangeReason(bound, Native.GetForegroundWindow().ToInt64()) == "new_window_detected")
                    throw new Boundary("new_window_detected");
                ++result.ForegroundRecoveries;
                // Activation is preparation only. It cannot resend a business
                // step or replace the bound observation/geometry.
                Execute(prepare with { Operation = new Operation("activate", RestoreMinimized: true) },
                    bound, stopped, clock, ledger, result, implicitActivation: true, waitStopped: waitStopped);
                foregroundEvents?.CheckRecovery();
                Native.CheckGeometry(prepare.Target, prepare.Operation.Kind == "computer_input_plan");
            }, () => {
                var previousEvents = foregroundEvents;
                var nextEvents = new ForegroundEvents(bound);
                try { previousEvents?.CheckRecovery(); previousEvents?.Dispose(); }
                catch { nextEvents.Dispose(); throw; }
                foregroundEvents = nextEvents;
            });
        var previousRecovery = ledger.PreDispatchRecovery;
        ledger.PreDispatchRecovery = priority.Recover;
        bool PhaseState(Func<bool> cancelled)
        {
            if (cancelled()) return true;
            priority.Check(() => {
                foregroundEvents!.Check();
                if (!Native.Foreground(bound.Hwnd)) throw new Boundary("foreground_changed");
                ExternalInput(ledger);
            });
            return false;
        }
        bool PhaseStopped() => PhaseState(stopped);
        bool PhaseWaitStopped() => PhaseState(waitStopped ?? stopped);
        try
        {
        if (prepare.Operation.Kind == "computer_input_plan")
        {
            ComputerPlans.Execute(inputPlan ?? ComputerPlans.Parse(prepare.Operation.Plan!.Value), prepare, bound,
                PhaseStopped, clock, ledger, result, PhaseWaitStopped, preparedApproach);
            return;
        }
        if (prepare.Operation.Kind == "text")
        {
            void CheckText() => Check(prepare, bound, PhaseStopped, clock, true, false, ledger);
            var context = new InputContextGuard(InputContext.Prepare(bound, CheckText, ledger, result), true);
            foreach (var batch in ComputerPlans.TextBatches(prepare.Operation.Text!))
            {
                context.SettlePending(() => InputContext.Read(bound), () => clock.ElapsedMilliseconds, CheckText, Thread.Sleep);
                var steps = batch.Segments[0].Steps;
                ledger.Send(steps, result, finalPreflight: () => {
                    CheckText(); context.RecheckCurrent(() => InputContext.Read(bound), clock.ElapsedMilliseconds);
                });
                if (steps.Any(step => step.Down && step.Token == "vk:9")) context.TraversalDispatched(clock.ElapsedMilliseconds);
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
                Dx = PointerPath.Normalize(x, left, width),
                Dy = PointerPath.Normalize(y, top, height), Flags = 0xc001 } } };
            var down = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 2 } } };
            var up = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 4 } } };
            Check(prepare, bound, PhaseStopped, clock, true, true);
            var steps = new[] { new Step(move), new Step(down, "mouse:left", true, up), new Step(up, "mouse:left") };
            var desktop = new DesktopShape(left, top, width, height);
            PointerPath.Approach(steps, bound, desktop, ledger, result,
                () => Check(prepare, bound, PhaseStopped, clock, true, true),
                waitCheck: () => ledger.CheckMotionWait(PhaseWaitStopped, clock, prepare.DeadlineMs,
                    () => Check(prepare, bound, PhaseStopped, clock, true, true)));
            ledger.Send(steps, result, finalPreflight: () => {
                Check(prepare, bound, PhaseStopped, clock, true, true);
                InputContext.CheckReceiver(bound, steps, desktop);
            });
        }
        result.State = "dispatched_unverified";
        }
        finally { ledger.PreDispatchRecovery = previousRecovery; foregroundEvents?.Dispose(); }
    }
}
