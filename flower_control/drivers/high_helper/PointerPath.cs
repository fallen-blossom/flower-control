using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static class PointerPath
{
    internal const int MotionGroupMs = 16;
    internal const int MotionCheckMs = 80;
    internal const int MotionWaitCheckMs = 4;
    internal static void AddTiming(Receipt? result, string name, long started)
    {
        if (result is not null)
            result.TimingsMs[name] = result.TimingsMs.GetValueOrDefault(name)
                + System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds;
    }
    internal readonly record struct Sample(Native.Point Point, int OffsetMs);
    internal sealed record PreparedApproach(Native.Point Start, Native.Point End, DesktopShape Desktop,
        PointerGeometry.Motion Motion, PointerGeometry.Constraints? Constraints, double PlanningMs);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    internal static PointerGeometry.Motion Plan(Native.Point start, Native.Point end, DesktopShape? desktop = null,
        PointerGeometry.Constraints? constraints = null) => PointerGeometry.Plan(start, end, desktop, constraints);
    internal static Native.Point[] Points(Native.Point start, Native.Point end, DesktopShape? desktop = null)
    {
        var motion = Plan(start, end, desktop);
        if (motion.DurationMs == 0) return [];
        return Enumerable.Range(1, 5).Select(i => PointerGeometry.PointAtDistance(motion.Route!,
            motion.Profile!.Distance(motion.DurationMs * i / 6000.0)).Pixel).ToArray();
    }
    internal static int Normalize(int value, int origin, int size)
    {
        long pixel = (long)value - origin;
        if (size <= 0 || pixel < 0 || pixel >= size) throw new Boundary("pointer_point_outside_bounds");
        long low = (pixel * 65536 + size - 1) / size;
        long high = ((pixel + 1) * 65536 + size - 1) / size - 1;
        if (low > high || low < 0 || high > 65535) throw new Boundary("pointer_pixel_unrepresentable");
        return (int)((low + high) / 2);
    }
    internal static Step Move(Native.Point point, DesktopShape desktop) => new(new Native.Input {
        Data = new Native.Union { Mouse = new Native.Mouse {
            Dx = Normalize(point.X, desktop.Left, desktop.Width), Dy = Normalize(point.Y, desktop.Top, desktop.Height), Flags = 0xc001 } } });
    internal static Native.Point Cursor()
    {
        if (!GetCursorPos(out var point)) throw new Boundary("pointer_position_unavailable");
        return point;
    }
    private static PointerGeometry.Motion PlanForInput(Native.Point start, Native.Point end, DesktopShape desktop,
        PointerGeometry.Constraints? constraints, Receipt receipt, string pathMode = "free", bool forceMotion = false, Action? checkpoint = null)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        try { return PointerGeometry.Plan(start, end, desktop, constraints, pathMode: pathMode, forceMotion: forceMotion, checkpoint: checkpoint); }
        catch (Boundary error) when (error.Code == "pointer_planning_budget_exceeded")
        {
            receipt.PointerPlanningFailure = new { Start = new[] { start.X, start.Y }, End = new[] { end.X, end.Y },
                Stage = error.Data["PointerStage"] as string ?? "unknown",
                Work = error.Data["PointerWork"] is int work ? work : 0,
                ElapsedMs = error.Data["PointerElapsedMs"] is double elapsed ? elapsed : clock.Elapsed.TotalMilliseconds };
            throw;
        }
        finally { receipt.TimingsMs["pointer_planning"] = receipt.TimingsMs.GetValueOrDefault("pointer_planning") + clock.Elapsed.TotalMilliseconds; }
    }
    private static bool ApproachCandidate(Step[] business) =>
        business.Length != 0 && business[0].Token is null
        && business[0].Raw.Type == 0 && business[0].Raw.Data.Mouse.Flags == 0xc001;
    private static PointerGeometry.Constraints? PointConstraints(PointerGeometry.Constraints? constraints) =>
        constraints is null ? null
        : new PointerGeometry.Constraints(constraints.Obstacles, new(0, 0, 0, 0), constraints.UncertaintyPx);
    private static bool SameConstraints(PointerGeometry.Constraints? a, PointerGeometry.Constraints? b)
    {
        if (a is null || b is null) return a is null && b is null;
        return a.Footprint == b.Footprint && a.UncertaintyPx == b.UncertaintyPx
            && a.Obstacles.SequenceEqual(b.Obstacles);
    }
    internal static PreparedApproach? PrepareApproach(Step[] business, DesktopShape? desktop,
        PointerGeometry.Constraints? constraints, Action? checkpoint = null)
    {
        if (!ApproachCandidate(business) || desktop is null) return null;
        var start = Cursor();
        var end = InputContext.AbsolutePoint(business[0].Raw.Data.Mouse, desktop);
        var pointConstraints = PointConstraints(constraints);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var motion = PointerGeometry.Plan(start, end, desktop, pointConstraints, checkpoint: checkpoint);
        return new(start, end, desktop, motion, constraints, clock.Elapsed.TotalMilliseconds);
    }
    internal static bool ApproachReusable(PreparedApproach? prepared, Step[] business, DesktopShape? desktop,
        PointerGeometry.Constraints? constraints, Native.Point cursor)
    {
        if (prepared is null || !ApproachCandidate(business) || desktop is null
            || prepared.Desktop != desktop) return false;
        var end = InputContext.AbsolutePoint(business[0].Raw.Data.Mouse, desktop);
        return prepared.Start.X == cursor.X && prepared.Start.Y == cursor.Y
            && prepared.End.X == end.X && prepared.End.Y == end.Y
            && SameConstraints(prepared.Constraints, constraints);
    }
    internal static bool TryApproach(PreparedApproach? prepared, Step[] business, Bound bound,
        DesktopShape? desktop, InputLedger ledger, Receipt result, Func<UserPermissionSettings> check,
        PointerGeometry.Constraints? constraints = null, Action? waitCheck = null)
    {
        if (ledger.OwnTokens.Count != 0 || !ApproachReusable(prepared, business, desktop, constraints, Cursor()))
            return false;
        MeasureApproach(result, () => {
            result.TimingsMs["pointer_planning"] = result.TimingsMs.GetValueOrDefault("pointer_planning")
                + prepared!.PlanningMs;
            check();
            if (prepared.Motion.DurationMs > 0)
                Play(prepared.Motion, bound, prepared.Desktop, ledger, result, check,
                    waitCheck ?? (() => check()));
        });
        return true;
    }
    internal static void Approach(Step[] business, Bound bound, DesktopShape? desktop, InputLedger ledger, Receipt result,
        Func<UserPermissionSettings> check, PointerGeometry.Constraints? constraints = null, Action? waitCheck = null)
    {
        if (ledger.OwnTokens.Count != 0 || !ApproachCandidate(business)) return;
        MeasureApproach(result, () => {
            if (desktop is null) throw new Boundary("mouse_desktop_required");
            check();
            var pointConstraints = constraints is null ? null
                : new PointerGeometry.Constraints(constraints.Obstacles, new(0, 0, 0, 0), constraints.UncertaintyPx);
            var motion = PlanForInput(Cursor(), InputContext.AbsolutePoint(business[0].Raw.Data.Mouse, desktop), desktop, pointConstraints, result,
                checkpoint: waitCheck);
            if (motion.DurationMs > 0)
                Play(motion, bound, desktop, ledger, result, check, waitCheck ?? (() => check()));
        });
    }
    internal static void MeasureApproach(Receipt result, Action action, Func<double>? elapsedForFixture = null)
    {
        var clock = System.Diagnostics.Stopwatch.StartNew();
        double dispatchBefore = result.TimingsMs.GetValueOrDefault("dispatch");
        try { action(); }
        finally
        {
            double elapsed = elapsedForFixture?.Invoke() ?? clock.Elapsed.TotalMilliseconds;
            double native = Math.Max(0, result.TimingsMs.GetValueOrDefault("dispatch") - dispatchBefore);
            result.TimingsMs["pointer_approach"] = result.TimingsMs.GetValueOrDefault("pointer_approach") + Math.Max(0, elapsed - native);
        }
    }
    private static void CheckDesktop(DesktopShape desktop)
    {
        if (desktop.Left != Native.GetSystemMetrics(76) || desktop.Top != Native.GetSystemMetrics(77)
            || desktop.Width != Native.GetSystemMetrics(78) || desktop.Height != Native.GetSystemMetrics(79))
            throw new Boundary("desktop_topology_changed");
    }
    internal static void WaitForOffset(int offsetMs, Func<double> elapsedMs, Action check, Action<int> delay)
    {
        while (offsetMs - elapsedMs() > 0)
        {
            check();
            double remaining = offsetMs - elapsedMs();
            if (remaining > 0) delay(Math.Max(1, (int)Math.Ceiling(Math.Min(4, remaining))));
        }
    }
    internal static void Play(PointerGeometry.Motion motion, Bound bound, DesktopShape desktop, InputLedger ledger, Receipt result,
        Func<UserPermissionSettings> check, Action waitCheck, bool includeEndpoint = false)
    {
        var samples = includeEndpoint ? motion.Samples : motion.Samples[..^1];
        var clock = System.Diagnostics.Stopwatch.StartNew(); double shift = 0;
        UserPermissionSettings? cachedPermissions = null; long checkedAt = long.MinValue;
        using var waiter = new PointerWait();
        void WaitUntil(int offset)
        {
            long started = System.Diagnostics.Stopwatch.GetTimestamp();
            try { WaitForOffset(offset, () => clock.Elapsed.TotalMilliseconds - shift, waitCheck, waiter.Delay); }
            finally { AddTiming(result, "motion_wait", started); }
        }
        int lastOffset = 0;
        for (int i = 0; i < samples.Length; ++i)
        {
            double elapsed = clock.Elapsed.TotalMilliseconds - shift;
            while (i + 1 < samples.Length && !RequiredSample(samples[i], motion.Route)
                && samples[i + 1].OffsetMs <= elapsed && samples[i + 1].OffsetMs - lastOffset <= 20
                && (motion.Route is null || PointerGeometry.SegmentClear(PointerGeometry.V.Of(Cursor()),
                    PointerGeometry.V.Of(samples[i + 1].Point), motion.Route.Obstacles)))
            {
                ++i;
                if (result.InputResult is { } progress) ++progress.SkippedMotionSegments;
            }
            var sample = samples[i];
            if (elapsed - sample.OffsetMs > 20)
            {
                shift = clock.Elapsed.TotalMilliseconds - sample.OffsetMs;
                if (result.InputResult is { } progress) ++progress.MotionClockRebases;
            }
            WaitUntil(sample.OffsetMs);
            // Send at a smooth 16ms cadence. Target/permission snapshots are
            // refreshed at most every 80ms for automatic motion; every send
            // still rechecks Stop, write gates, desktop topology and chords.
            int groupEnd = MotionGroupEnd(samples, i, motion.Route, motion.Automatic);
            var steps = samples[i..(groupEnd + 1)].Select(s => Move(s.Point, desktop)).ToArray();
            void Guard()
            {
                long now = System.Diagnostics.Stopwatch.GetTimestamp();
                if (cachedPermissions is null
                    || System.Diagnostics.Stopwatch.GetElapsedTime(checkedAt, now).TotalMilliseconds >= MotionCheckMs)
                {
                    cachedPermissions = check(); checkedAt = now;
                }
                CheckDesktop(desktop);
                if (motion.Route is not null && !MotionGroupClear(Cursor(), samples, i, groupEnd, motion.Route.Obstacles))
                    throw new Boundary("pointer_motion_geometry_changed");
                UserPermissions.RequireInput(bound, steps, desktop, sweepMotion: true, permissions: cachedPermissions);
            }
            ledger.Send(steps, result, pointer: true, finalPreflight: Guard);
            lastOffset = samples[groupEnd].OffsetMs;
            i = groupEnd;
        }
        WaitUntil(motion.DurationMs);
    }
    private static bool RequiredSample(Sample sample, PointerGeometry.Route? route) => route is not null
        && route.Required.Any(required => required.Point.Pixel.X == sample.Point.X && required.Point.Pixel.Y == sample.Point.Y);
    internal static int MotionGroupEnd(Sample[] samples, int first, PointerGeometry.Route? route, bool automatic)
    {
        int last = first;
        if (!automatic || RequiredSample(samples[first], route)) return last;
        while (last + 1 < samples.Length && samples[last + 1].OffsetMs - samples[first].OffsetMs <= MotionGroupMs
            && !RequiredSample(samples[last + 1], route)
            && (route is null || PointerGeometry.SegmentClear(PointerGeometry.V.Of(samples[last].Point),
                PointerGeometry.V.Of(samples[last + 1].Point), route.Obstacles))) ++last;
        return last;
    }
    internal static bool MotionGroupClear(Native.Point actualStart, Sample[] samples, int first, int last,
        PointerGeometry.Box[] obstacles)
    {
        var previous = PointerGeometry.V.Of(actualStart);
        for (int index = first; index <= last; ++index)
        {
            var next = PointerGeometry.V.Of(samples[index].Point);
            if (!PointerGeometry.SegmentClear(previous, next, obstacles)) return false;
            previous = next;
        }
        return true;
    }
    internal static Native.Point ConfirmEndpoint(Native.Point end, Bound bound, DesktopShape desktop, InputLedger ledger,
        Receipt result, Func<UserPermissionSettings> check, Action waitCheck, PointerGeometry.Constraints? constraints)
    {
        var actual = Cursor();
        if (actual.X == end.X && actual.Y == end.Y) return end;
        check();
        var correction = PlanForInput(actual, end, desktop, constraints, result, pathMode: "direct", forceMotion: true, checkpoint: waitCheck);
        Play(correction, bound, desktop, ledger, result, check, waitCheck, includeEndpoint: true);
        actual = Cursor();
        if (actual.X != end.X || actual.Y != end.Y) throw new Boundary("pointer_endpoint_unconfirmed");
        return end;
    }
}
