using System.Diagnostics;
using System.Text.Json;

namespace Flower.HighHelper;

internal record InputBinding(string TaskId, string ActionId, string? ObservationId, string? Generation, int? SequenceStep);
internal record DesktopShape(int Left, int Top, int Width, int Height);
internal record PlannedSegment(int OffsetMs, Step[] Steps);
internal record PointerHints(PointerGeometry.Constraints Constraints, bool Automatic, Native.Point[] RequiredPoints);
internal record PlannedBatch(int DurationMs, PlannedSegment[] Segments, PointerHints? Pointer = null);
internal record ComputerPlan(InputBinding Binding, string Command, DesktopShape? Desktop, PlannedBatch[] Plans, bool SuppressPointerApproach = false, bool SettleFinalFocus = false);

internal static class ComputerPlans
{
    internal static PlannedBatch[] TextBatches(string text, bool splitTabs = false)
    {
        if (string.IsNullOrEmpty(text) || text.Length > 8192) throw new Boundary("input_plan_rejected");
        for (int i = 0; i < text.Length; ++i)
        {
            if (char.IsHighSurrogate(text[i]))
            { if (++i >= text.Length || !char.IsLowSurrogate(text[i])) throw new Boundary("input_plan_rejected"); }
            else if (char.IsLowSurrogate(text[i])) throw new Boundary("input_plan_rejected");
        }
        var batches = new List<PlannedBatch>(); var steps = new List<Step>(); int units = 0;
        void Flush()
        {
            if (steps.Count == 0) return;
            batches.Add(new(0, [new(0, steps.ToArray())])); steps.Clear(); units = 0;
        }
        var normalized = text.Replace("\r\n", "\n").Replace('\r', '\n');
        for (int i = 0; i < normalized.Length; ++i)
        {
            char unit = normalized[i]; int size = char.IsHighSurrogate(unit) ? 2 : 1;
            // Keep the historical argument for App callers. All literal text
            // now isolates navigation/submission, regardless of that argument.
            bool navigation = unit is '\n' or '\t';
            if (units + size > 64 || navigation) Flush();
            if (unit is '\n' or '\t') steps.AddRange(Executor.KeyPair(unit == '\n' ? (ushort)13 : (ushort)9, false));
            else
            {
                steps.AddRange(Executor.KeyPair(unit, true));
                if (size == 2) steps.AddRange(Executor.KeyPair(normalized[++i], true));
            }
            units += size;
            if (navigation) Flush();
        }
        Flush();
        if (batches.Count > 8192) throw new Boundary("input_plan_rejected");
        return batches.ToArray();
    }
    private static void Fields(JsonElement value, params string[] keys)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(keys) == false
            || value.EnumerateObject().Count() != keys.Length) throw new Boundary("input_plan_rejected");
    }
    private static int Number(JsonElement value, string name, int min, int max)
    {
        if (!value.TryGetProperty(name, out var field) || !field.TryGetInt32(out var number) || number < min || number > max)
            throw new Boundary("input_plan_rejected");
        return number;
    }
    private static bool Down(JsonElement value) => value.GetProperty("down").ValueKind switch
    { JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new Boundary("input_plan_rejected") };
    private static string Text(JsonElement value, string name, int max = 256)
    {
        var field = value.GetProperty(name);
        if (field.ValueKind != JsonValueKind.String) throw new Boundary("input_plan_rejected");
        var text = field.GetString()!;
        if (text.Length is < 1 || text.Length > max || text.Any(char.IsControl)) throw new Boundary("input_plan_rejected");
        return text;
    }
    internal static ComputerPlan Parse(JsonElement data)
    {
        try { return ParseCore(data); }
        catch (Boundary) { throw; }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { throw new Boundary("input_plan_rejected"); }
    }
    private static ComputerPlan ParseCore(JsonElement data)
    {
        bool hasSuppression = data.TryGetProperty("suppress_pointer_approach", out var suppression);
        bool hasSettle = data.TryGetProperty("settle_final_focus", out var settle);
        int schemaVersion = Number(data, "schema_version", 1, 2);
        var fields = new List<string> { "kind", "schema_version", "command", "binding", "desktop", "plans" };
        if (hasSuppression) fields.Add("suppress_pointer_approach");
        if (hasSettle) fields.Add("settle_final_focus");
        if (schemaVersion == 2) fields.Add("motion_spec");
        Fields(data, fields.ToArray());
        if (hasSuppression && suppression.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
            || hasSettle && settle.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Boundary("input_plan_rejected");
        if (Text(data, "kind") != "computer_input_plan") throw new Boundary("input_plan_rejected");
        if (schemaVersion == 2 && Text(data, "motion_spec") != PointerGeometry.Spec) throw new Boundary("pointer_spec_mismatch");
        if (schemaVersion == 2 && hasSuppression && suppression.ValueKind == JsonValueKind.True)
            throw new Boundary("pointer_approach_plan_required");
        var command = Text(data, "command");
        if (command is not ("text" or "key" or "click" or "double_click" or "scroll" or "drag" or "move_relative" or "key_mouse" or "mouse_hold" or "move" or "hover" or "batch"))
            throw new Boundary("input_plan_rejected");
        var bind = data.GetProperty("binding");
        Fields(bind, "task_id", "action_id", "observation_id", "generation", "sequence_step");
        var binding = new InputBinding(Text(bind, "task_id", 128), Text(bind, "action_id", 512),
            Text(bind, "observation_id"), Text(bind, "generation", 4096),
            bind.GetProperty("sequence_step").ValueKind == JsonValueKind.Null ? null : Number(bind, "sequence_step", 0, 7));
        if (hasSettle && settle.GetBoolean() && (binding.SequenceStep is null or >= 7)) throw new Boundary("input_plan_rejected");
        DesktopShape? desktop = null;
        var shape = data.GetProperty("desktop");
        if (shape.ValueKind != JsonValueKind.Null)
        {
            Fields(shape, "left", "top", "width", "height");
            desktop = new(Number(shape, "left", int.MinValue, int.MaxValue), Number(shape, "top", int.MinValue, int.MaxValue),
                Number(shape, "width", 1, 100000), Number(shape, "height", 1, 100000));
        }
        var rawPlans = data.GetProperty("plans");
        if (rawPlans.ValueKind != JsonValueKind.Array || rawPlans.GetArrayLength() is < 1 or > 8192
            || command is not ("text" or "batch") && rawPlans.GetArrayLength() != 1) throw new Boundary("input_plan_rejected");
        var plans = new List<PlannedBatch>();
        int totalUnits = 0, totalEvents = 0;
        bool hasAbsolute = false;
        foreach (var rawPlan in rawPlans.EnumerateArray())
        {
            PointerHints? pointer = null;
            if (rawPlan.TryGetProperty("pointer", out var pointerValue))
            {
                if (schemaVersion != 2) throw new Boundary("pointer_spec_mismatch");
                Fields(rawPlan, "duration_ms", "segments", "pointer");
                pointer = ParsePointer(pointerValue);
            }
            else Fields(rawPlan, "duration_ms", "segments");
            var duration = Number(rawPlan, "duration_ms", 0, 3000);
            var rawSegments = rawPlan.GetProperty("segments");
            if (rawSegments.ValueKind != JsonValueKind.Array || (duration == 0 ? rawSegments.GetArrayLength() != 1
                : rawSegments.GetArrayLength() < 2 || rawSegments.GetArrayLength() > (schemaVersion == 2 ? 128 : 64))) throw new Boundary("input_plan_rejected");
            var segments = new List<PlannedSegment>();
            var held = new HashSet<string>();
            var units = new List<char>();
            int eventCount = 0, previous = -1, textKeys = 0;
            foreach (var rawSegment in rawSegments.EnumerateArray())
            {
                Fields(rawSegment, "offset_ms", "events");
                var offset = Number(rawSegment, "offset_ms", 0, duration);
                if (offset <= previous) throw new Boundary("input_plan_rejected");
                previous = offset;
                var rawEvents = rawSegment.GetProperty("events");
                if (rawEvents.ValueKind != JsonValueKind.Array || rawEvents.GetArrayLength() < 1) throw new Boundary("input_plan_rejected");
                var steps = rawEvents.EnumerateArray().Select(Map).ToArray();
                for (int i = 0; i < steps.Length; ++i)
                {
                    var step = steps[i];
                    if (command == "text")
                    {
                        if (duration != 0 || step.Raw.Type != 1 || step.Token is null)
                            throw new Boundary("input_plan_rejected");
                        if (step.Down && (i + 1 >= steps.Length || steps[i + 1].Token != step.Token || steps[i + 1].Down))
                            throw new Boundary("input_plan_rejected");
                        if (step.Token.StartsWith("vk:", StringComparison.Ordinal))
                        {
                            if (step.Raw.Data.Key.Vk is not (9 or 13) || steps.Length != 2) throw new Boundary("input_plan_rejected");
                            if (step.Down) ++textKeys;
                        }
                        else if (step.Raw.Data.Key.Scan is 9 or 10 or 13) throw new Boundary("input_plan_rejected");
                        if (step.Down && char.IsHighSurrogate((char)step.Raw.Data.Key.Scan)
                            && (i + 2 >= steps.Length || !steps[i + 2].Down
                                || steps[i + 2].Raw.Data.Key.Vk != 0
                                || !char.IsLowSurrogate((char)steps[i + 2].Raw.Data.Key.Scan)))
                            throw new Boundary("input_plan_rejected");
                    }
                    hasAbsolute |= step.Raw.Type == 0 && (step.Raw.Data.Mouse.Flags & 0x8000) != 0;
                    if (step.Token is null) continue;
                    if (step.Down ? !held.Add(step.Token) : !held.Remove(step.Token)) throw new Boundary("input_plan_unbalanced");
                    if (held.Count(t => t.StartsWith("vk:", StringComparison.Ordinal)) > 5) throw new Boundary("input_plan_rejected");
                    if (step.Token.StartsWith("unicode:", StringComparison.Ordinal) && step.Down)
                    {
                        if (command is not ("text" or "batch") || duration != 0 || i + 1 >= steps.Length
                            || steps[i + 1].Token != step.Token || steps[i + 1].Down) throw new Boundary("input_plan_rejected");
                        units.Add((char)step.Raw.Data.Key.Scan);
                    }
                    if (duration > 0 && offset == duration && step.Down) throw new Boundary("input_plan_rejected");
                }
                eventCount += steps.Length;
                if (steps.Any(step => step.Token?.StartsWith("unicode:", StringComparison.Ordinal) == true)
                    && steps.Any(step => step.Token is "vk:9" or "vk:13")) throw new Boundary("input_plan_rejected");
                segments.Add(new(offset, steps));
            }
            if (eventCount is < 1 or > 128 || segments[0].OffsetMs != 0 || segments[^1].OffsetMs != duration
                || held.Count != 0 || units.Count > 64
                || duration > 0 && (segments[^1].Steps[^1].Token is null || segments[^1].Steps[^1].Down))
                throw new Boundary("input_plan_unbalanced");
            for (int i = 0; i < units.Count; ++i)
            {
                if (char.IsHighSurrogate(units[i]))
                { if (++i >= units.Count || !char.IsLowSurrogate(units[i])) throw new Boundary("input_plan_rejected"); }
                else if (char.IsLowSurrogate(units[i])) throw new Boundary("input_plan_rejected");
            }
            if (command == "text" && (units.Count + textKeys == 0 || eventCount != (units.Count + textKeys) * 2)) throw new Boundary("input_plan_rejected");
            totalUnits += units.Count + textKeys; totalEvents += eventCount;
            if (pointer is not null)
            {
                if (desktop is null) throw new Boundary("mouse_desktop_required");
                if (pointer.Automatic && (duration == 0 || pointer.RequiredPoints.Length < 2
                    || !segments.SelectMany(s => s.Steps).Any(InputContext.MouseDown))) throw new Boundary("input_plan_rejected");
                var points = segments.SelectMany(s => s.Steps).Where(s => s.Raw.Type == 0 && (s.Raw.Data.Mouse.Flags & 0x8000) != 0)
                    .Select(s => InputContext.AbsolutePoint(s.Raw.Data.Mouse, desktop)).ToArray();
                int cursor = 0;
                foreach (var requiredPoint in pointer.RequiredPoints)
                {
                    while (cursor < points.Length && (points[cursor].X != requiredPoint.X || points[cursor].Y != requiredPoint.Y)) ++cursor;
                    if (cursor == points.Length) throw new Boundary("pointer_required_point_missing");
                    ++cursor;
                }
                var body = pointer.Constraints.Footprint;
                if (points.Any(p => p.X < desktop.Left - body.Left || p.Y < desktop.Top - body.Top
                    || p.X >= desktop.Left + (double)desktop.Width - body.Right || p.Y >= desktop.Top + (double)desktop.Height - body.Bottom))
                    throw new Boundary("pointer_point_outside_bounds");
            }
            plans.Add(new(duration, segments.ToArray(), pointer));
        }
        if (totalUnits > 8192 || totalEvents > 16384 || plans.Sum(p => p.DurationMs) > 3000 || hasAbsolute && desktop is null) throw new Boundary("input_plan_rejected");
        return new(binding, command, desktop, plans.ToArray(), hasSuppression && suppression.ValueKind == JsonValueKind.True,
            hasSettle && settle.GetBoolean());
    }
    private static Step Map(JsonElement value)
    {
        var kind = Text(value, "kind");
        Native.Input input = default, release = default;
        string? token = null;
        bool down = false;
        if (kind is "virtual_key" or "unicode_key")
        {
            Fields(value, "kind", kind == "virtual_key" ? "code" : "unit", "down");
            var code = Number(value, kind == "virtual_key" ? "code" : "unit", kind == "virtual_key" ? 1 : 0, kind == "virtual_key" ? 254 : 65535);
            down = Down(value); input.Type = 1;
            input.Data.Key = new Native.Key { Vk = kind == "virtual_key" ? (ushort)code : (ushort)0,
                Scan = kind == "unicode_key" ? (ushort)code : (ushort)0,
                Flags = (kind == "unicode_key" ? 4U : code is 0x21 or 0x22 or 0x23 or 0x24 or 0x25 or 0x26 or 0x27 or 0x28
                    or 0x2C or 0x2D or 0x2E or 0x5B or 0x5C or 0x6F or 0x90 or 0xA3 or 0xA5 ? 1U : 0U) | (down ? 0U : 2U) };
            release = input; release.Data.Key.Flags |= 2;
            token = (kind == "virtual_key" ? "vk:" : "unicode:") + code;
        }
        else if (kind == "mouse_button")
        {
            Fields(value, "kind", "button", "down"); down = Down(value);
            var button = Text(value, "button");
            uint flag = button switch { "left" => 2, "right" => 8, "middle" => 32, _ => throw new Boundary("input_plan_rejected") };
            input.Data.Mouse.Flags = down ? flag : flag * 2; release = input; release.Data.Mouse.Flags = flag * 2;
            token = "mouse:" + button;
        }
        else if (kind == "mouse_absolute")
        {
            Fields(value, "kind", "nx", "ny");
            input.Data.Mouse = new Native.Mouse { Dx = Number(value, "nx", 0, 65535), Dy = Number(value, "ny", 0, 65535), Flags = 0xc001 };
        }
        else if (kind == "mouse_relative")
        {
            Fields(value, "kind", "dx", "dy");
            int x = Number(value, "dx", -2048, 2048), y = Number(value, "dy", -2048, 2048);
            if (x == 0 && y == 0) throw new Boundary("input_plan_rejected");
            input.Data.Mouse = new Native.Mouse { Dx = x, Dy = y, Flags = 1 };
        }
        else if (kind == "mouse_wheel")
        {
            Fields(value, "kind", "axis", "delta");
            int delta = Number(value, "delta", -1200, 1200);
            if (delta == 0) throw new Boundary("input_plan_rejected");
            input.Data.Mouse = new Native.Mouse { Data = unchecked((uint)delta),
                Flags = Text(value, "axis") switch { "vertical" => 0x800, "horizontal" => 0x1000, _ => throw new Boundary("input_plan_rejected") } };
        }
        else throw new Boundary("input_plan_rejected");
        return new(input, token, down, release);
    }
    private static PointerHints ParsePointer(JsonElement value)
    {
        Fields(value, "spec", "obstacles", "footprint", "uncertainty_px", "automatic", "required_points");
        if (Text(value, "spec") != PointerGeometry.Spec) throw new Boundary("pointer_spec_mismatch");
        PointerGeometry.Box Rect(JsonElement array, bool footprint)
        {
            if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != 4) throw new Boundary("input_plan_rejected");
            var values = array.EnumerateArray().Select(n => n.TryGetInt32(out var x) ? x : throw new Boundary("input_plan_rejected")).ToArray();
            var box = new PointerGeometry.Box(values[0], values[1], values[2], values[3]);
            if (!footprint && (values[0] >= values[2] || values[1] >= values[3])) throw new Boundary("input_plan_rejected");
            return box;
        }
        var obstacles = value.GetProperty("obstacles");
        if (obstacles.ValueKind != JsonValueKind.Array || obstacles.GetArrayLength() > PointerGeometry.MaxObstacles)
            throw new Boundary("pointer_obstacle_limit");
        var constraints = new PointerGeometry.Constraints(obstacles.EnumerateArray().Select(x => Rect(x, false)).ToArray(),
            Rect(value.GetProperty("footprint"), true), Number(value, "uncertainty_px", 0, 256));
        constraints.Validate();
        bool automatic = value.GetProperty("automatic").ValueKind switch {
            JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new Boundary("input_plan_rejected") };
        var required = value.GetProperty("required_points");
        if (required.ValueKind != JsonValueKind.Array || required.GetArrayLength() > 64) throw new Boundary("input_plan_rejected");
        var points = required.EnumerateArray().Select(p => {
            if (p.ValueKind != JsonValueKind.Array || p.GetArrayLength() != 2
                || !p[0].TryGetInt32(out int x) || !p[1].TryGetInt32(out int y)) throw new Boundary("input_plan_rejected");
            return new Native.Point { X = x, Y = y };
        }).ToArray();
        return new(constraints, automatic, points);
    }
    internal static bool HasKeyboardEvents(ComputerPlan plan) => plan.Plans.Any(batch =>
        batch.Segments.Any(segment => segment.Steps.Any(step => step.Raw.Type == 1)));
    internal static int ExecutionBudget(ComputerPlan plan)
    {
        // Conservative work admission, not a measured latency guarantee.
        // Keep the exact weights/classification in computer_native.py aligned.
        int budget = 2000;
        int physicalAllowance = 0;
        foreach (var batch in plan.Plans)
        {
            budget += batch.DurationMs;
            var first = batch.Segments[0].Steps[0];
            if (first.Token is null && first.Raw.Type == 0 && first.Raw.Data.Mouse.Flags == 0xc001) budget += 120;
            var held = new HashSet<string>();
            foreach (var segment in batch.Segments)
            {
                var steps = segment.Steps;
                bool ownedUps = steps.All(step => step.Token is not null && !step.Down && held.Contains(step.Token));
                if (!ownedUps)
                {
                    bool motionSample = batch.Pointer is not null && steps.All(step =>
                        step.Token is null && step.Raw.Type == 0 && step.Raw.Data.Mouse.Flags == 0xc001);
                    bool physicalKey = steps.Any(step => step.Raw.Type == 1 && step.Token?.StartsWith("vk:", StringComparison.Ordinal) == true
                        && step.Token != "vk:9");
                    // Measured B40 physical-key plans cost 0.34-0.37s each,
                    // not 50ms. Preserve Unicode/navigation admission capacity.
                    int weight = !motionSample && steps.Any(step => step.Raw.Type == 0) ? 500 : 50;
                    budget += weight;
                    if (physicalKey && weight == 50) physicalAllowance += 450;
                }
                if (steps.Any(step => step.Down && (step.Token == "vk:9" || step.Token?.StartsWith("mouse:", StringComparison.Ordinal) == true))) budget += 150;
                foreach (var step in steps)
                    if (step.Token is not null) { if (step.Down) held.Add(step.Token); else held.Remove(step.Token); }
            }
        }
        if (budget > 30000) throw new Boundary("input_plan_budget_exceeded");
        return Math.Min(30000, Math.Max(5000, budget + physicalAllowance));
    }
    internal static void Execute(ComputerPlan plan, Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, InputLedger ledger, Receipt result,
        Func<bool>? waitStopped = null, PointerPath.PreparedApproach? preparedApproach = null)
    {
        Executor.Check(prepare, bound, stopped, clock, true, true, ledger);
        CheckDesktop(plan.Desktop);
        var keyboard = HasKeyboardEvents(plan) || plan.SettleFinalFocus;
        var baseline = keyboard
            ? InputContext.Prepare(bound, () => Executor.Check(prepare, bound, stopped, clock, true, true, ledger), ledger, result)
            : new InputContext(null, null, "unknown");
        var context = new InputContextGuard(baseline, keyboard);
        InputPreflight? cachedPreflight = null; long cachedAt = long.MinValue;
        InputPreflight CachedCheck(Step[] steps, bool force = false)
        {
            long now = clock.ElapsedMilliseconds;
            if (force || cachedPreflight is null || now - cachedAt >= PointerPath.MotionCheckMs)
            {
                cachedPreflight = Check(plan, prepare, bound, stopped, clock, ledger, context, steps, result);
                cachedAt = now;
            }
            return cachedPreflight.Value;
        }
        result.InputResult ??= new InputProgress { Binding = plan.Binding };
        result.InputResult.PlannedPlans = plan.Plans.Length;
        result.InputResult.PlannedSegments = plan.Plans.Sum(batch => batch.Segments.Length);
        int completedPlans = 0, completedSegments = 0;
        using var motionWaiter = plan.Plans.Any(p => p.DurationMs > 0) ? new PointerWait() : null;
        for (int p = 0; p < plan.Plans.Length; ++p)
        {
            var batch = plan.Plans[p];
            var elapsed = Stopwatch.StartNew();
            int lastOffset = 0; double shift = 0;
            Step[] waitingSteps = batch.Segments[0].Steps;
            void WaitCheck() => ledger.CheckMotionWait(waitStopped ?? stopped, clock, prepare.DeadlineMs,
                () => _ = CachedCheck(waitingSteps));
            int s = 0;
            while (s < batch.Segments.Length)
            {
                var segment = batch.Segments[s];
                waitingSteps = segment.Steps;
                if (s == 0)
                {
                    // A preceding navigation event must settle before even the
                    // approach curve for the next business batch can dispatch.
                    context.SettlePending(() => InputContext.Read(bound), () => clock.ElapsedMilliseconds,
                        () => CheckEnvironment(plan, prepare, bound, stopped, clock, ledger, result), Thread.Sleep);
                    if (!plan.SuppressPointerApproach)
                    {
                        bool reused = p == 0 && s == 0 && PointerPath.TryApproach(preparedApproach,
                            segment.Steps, bound, plan.Desktop, ledger, result,
                            () => Check(plan, prepare, bound, stopped, clock, ledger, context, segment.Steps, result).Permissions,
                            batch.Pointer?.Constraints, WaitCheck);
                        if (!reused)
                            PointerPath.Approach(segment.Steps, bound, plan.Desktop, ledger, result,
                                () => Check(plan, prepare, bound, stopped, clock, ledger, context, segment.Steps, result).Permissions,
                                batch.Pointer?.Constraints, WaitCheck);
                    }
                    elapsed.Restart(); // The approach never shortens a planned key/button hold.
                }
                if (s > 0)
                {
                    double position = elapsed.Elapsed.TotalMilliseconds - shift;
                    if (CanSkipMotionSegment(batch, s, lastOffset, position, plan.Desktop))
                    { ++result.InputResult.SkippedMotionSegments; ++s; continue; }
                    if (batch.Pointer?.Automatic is true && position - segment.OffsetMs > 20)
                    { shift = elapsed.Elapsed.TotalMilliseconds - segment.OffsetMs; ++result.InputResult.MotionClockRebases; }
                }
                var grouped = segment.Steps.ToList(); int groupEnd = s;
                bool currentPure = IsPureMotion(segment.Steps);
                bool currentRequired = batch.Pointer is not null && plan.Desktop is not null && currentPure && batch.Pointer.RequiredPoints.Any(p =>
                    p.X == InputContext.AbsolutePoint(segment.Steps[0].Raw.Data.Mouse, plan.Desktop).X &&
                    p.Y == InputContext.AbsolutePoint(segment.Steps[0].Raw.Data.Mouse, plan.Desktop).Y) == true;
                if (batch.Pointer?.Automatic is true && plan.Desktop is not null && currentPure && !currentRequired)
                {
                    while (groupEnd + 1 < batch.Segments.Length)
                    {
                        var next = batch.Segments[groupEnd + 1];
                        if (next.OffsetMs - segment.OffsetMs > PointerPath.MotionGroupMs || !IsPureMotion(next.Steps)) break;
                        var nextPoint = InputContext.AbsolutePoint(next.Steps[0].Raw.Data.Mouse, plan.Desktop);
                        if (batch.Pointer.RequiredPoints.Any(p => p.X == nextPoint.X && p.Y == nextPoint.Y)) break;
                        var previousPoint = InputContext.AbsolutePoint(grouped[^1].Raw.Data.Mouse, plan.Desktop);
                        if (!PointerGeometry.SegmentClear(PointerGeometry.V.Of(previousPoint),
                            PointerGeometry.V.Of(nextPoint), batch.Pointer.Constraints.Expanded())) break;
                        grouped.AddRange(next.Steps); ++groupEnd;
                    }
                }
                waitingSteps = grouped.ToArray();
                WaitForOffset(segment.OffsetMs, () => (long)(elapsed.Elapsed.TotalMilliseconds - shift),
                    WaitCheck, delay => motionWaiter!.Delay(Math.Min(4, delay)));
                context.SettlePending(() => InputContext.Read(bound), () => clock.ElapsedMilliseconds,
                    () => CheckEnvironment(plan, prepare, bound, stopped, clock, ledger, result), Thread.Sleep);
                long? focusReceiver;
                int before = result.BusinessEvents;
                var dispatchedSteps = grouped.ToArray();
                CheckDesktop(plan.Desktop);
                bool forceCheck = !currentPure || currentRequired;
                try { focusReceiver = DispatchPointerSegment(dispatchedSteps, ledger, result,
                    () => CachedCheck(dispatchedSteps, forceCheck),
                    batch.Pointer, plan.Desktop, bound, WaitCheck); }
                catch
                {
                    result.InputResult.PartialSegment = new { plan = p, segment = s,
                        accepted_count = ledger.CountKnown ? (int?)(result.BusinessEvents - before) : null,
                        requested_count = dispatchedSteps.Length };
                    throw;
                }
                if (s == 0) elapsed.Restart(); // Start holds at the accepted down, after read-only preparation.
                if (dispatchedSteps.Any(InputContext.MouseDown))
                    context.MouseDispatched(focusReceiver, clock.ElapsedMilliseconds);
                if (dispatchedSteps.Any(step => step.Down && step.Token == "vk:9"))
                    context.TraversalDispatched(clock.ElapsedMilliseconds);
                completedSegments += groupEnd - s + 1; result.InputResult.CompletedSegments = completedSegments;
                lastOffset = batch.Segments[groupEnd].OffsetMs;
                s = groupEnd + 1;
            }
            ++completedPlans; result.InputResult.CompletedPlans = completedPlans;
            double completedAt = clock.Elapsed.TotalMilliseconds;
            if (result.InputResult.LastCompletedPlanMs is { } previous)
                result.InputResult.MaxInterPlanGapMs = Math.Max(result.InputResult.MaxInterPlanGapMs, completedAt - previous);
            else result.InputResult.FirstCompletedPlanMs = completedAt;
            result.InputResult.LastCompletedPlanMs = completedAt;
        }
        if (plan.SettleFinalFocus)
            context.SettlePending(() => InputContext.Read(bound), () => clock.ElapsedMilliseconds,
                () => CheckEnvironment(plan, prepare, bound, stopped, clock, ledger, result), Thread.Sleep);
        result.InputResult.BusinessComplete = true;
        result.State = "dispatched_unverified";
    }
    private static bool CanSkipMotionSegment(PlannedBatch batch, int index, int lastOffset, double elapsed, DesktopShape? desktop)
    {
        if (batch.Pointer?.Automatic is not true || desktop is null || index + 1 >= batch.Segments.Length) return false;
        var segment = batch.Segments[index]; var next = batch.Segments[index + 1];
        if (segment.Steps.Length != 1 || segment.Steps[0].Token is not null || segment.Steps[0].Raw.Type != 0
            || segment.Steps[0].Raw.Data.Mouse.Flags != 0xc001 || next.OffsetMs > elapsed || next.OffsetMs - lastOffset > 20
            || next.Steps[0].Raw.Type != 0 || next.Steps[0].Raw.Data.Mouse.Flags != 0xc001) return false;
        var point = InputContext.AbsolutePoint(segment.Steps[0].Raw.Data.Mouse, desktop);
        if (batch.Pointer.RequiredPoints.Any(p => p.X == point.X && p.Y == point.Y)) return false;
        return PointerGeometry.SegmentClear(PointerGeometry.V.Of(PointerPath.Cursor()),
            PointerGeometry.V.Of(InputContext.AbsolutePoint(next.Steps[0].Raw.Data.Mouse, desktop)), batch.Pointer.Constraints.Expanded());
    }
    private static bool IsPureMotion(Step[] steps) =>
        steps.Length == 1 && steps[0].Token is null && steps[0].Raw.Type == 0 &&
        steps[0].Raw.Data.Mouse.Flags == 0xc001;
    private static void CheckPointerChords(Step[] steps, DesktopShape? desktop, PointerHints? hints, InputLedger ledger)
    {
        if (hints is null || hints.Constraints.Obstacles.Length == 0) return;
        var previous = PointerPath.Cursor();
        var carrying=ledger.OwnTokens.Where(t=>t.StartsWith("mouse:",StringComparison.Ordinal)).ToHashSet();
        var bodyObstacles=hints.Constraints.Expanded();
        var pointObstacles=new PointerGeometry.Constraints(hints.Constraints.Obstacles,new(0,0,0,0),
            hints.Constraints.UncertaintyPx).Expanded();
        foreach (var step in steps)
        {
            if (step.Raw.Type == 0 && (step.Raw.Data.Mouse.Flags & 0x8000) != 0)
            {
                var point = InputContext.AbsolutePoint(step.Raw.Data.Mouse, desktop);
                if (!PointerGeometry.SegmentClear(PointerGeometry.V.Of(previous), PointerGeometry.V.Of(point),
                    carrying.Count>0 ? bodyObstacles : pointObstacles)) throw new Boundary("pointer_motion_geometry_changed");
                previous = point;
            }
            if (step.Token is not null && step.Token.StartsWith("mouse:",StringComparison.Ordinal))
            {
                if (step.Down)
                {
                    if (!PointerGeometry.SegmentClear(PointerGeometry.V.Of(previous),PointerGeometry.V.Of(previous),bodyObstacles))
                        throw new Boundary("pointer_motion_geometry_changed");
                    carrying.Add(step.Token);
                }
                else carrying.Remove(step.Token);
            }
        }
    }
    internal static PointerPath.PreparedApproach? PrepareApproach(ComputerPlan plan, Action checkpoint)
    {
        if (plan.SuppressPointerApproach || plan.Desktop is null || plan.Plans.Length == 0) return null;
        var batch = plan.Plans[0];
        return PointerPath.PrepareApproach(batch.Segments[0].Steps, plan.Desktop,
            batch.Pointer?.Constraints, checkpoint);
    }
    internal static bool CanPrepareApproach(ComputerPlan plan)
    {
        if (plan.SuppressPointerApproach || plan.Desktop is null || plan.Plans.Length == 0) return false;
        var steps = plan.Plans[0].Segments[0].Steps;
        return steps.Length != 0 && steps[0].Token is null && steps[0].Raw.Type == 0
            && steps[0].Raw.Data.Mouse.Flags == 0xc001;
    }
    private readonly record struct InputPreflight(long? Receiver, UserPermissionSettings Permissions);
    private static long? DispatchPointerSegment(Step[] steps, InputLedger ledger, Receipt result, Func<InputPreflight> check,
        PointerHints? hints, DesktopShape? desktop, Bound bound, Action waitCheck)
    {
        int split = -1;
        if (hints is not null && steps.Any(s => s.Token is not null && s.Token.StartsWith("mouse:", StringComparison.Ordinal) && !s.Down))
            for (int i = steps.Length - 2; i >= 0; --i)
                if (steps[i].Raw.Type == 0 && steps[i].Raw.Data.Mouse.Flags == 0xc001
                    && steps.Skip(i + 1).All(s => s.Token is not null && !s.Down)) { split = i + 1; break; }
        Native.Point? endpoint = null;
        long? Guard()
        {
            var receiver = check().Receiver;
            CheckPointerChords(steps, desktop, hints, ledger);
            if (endpoint is { } required)
            {
                var current = PointerPath.Cursor();
                if (current.X != required.X || current.Y != required.Y) throw new Boundary("pointer_endpoint_changed_before_release");
            }
            return receiver;
        }
        if (split < 0) return DispatchSegment(steps, ledger, result, Guard);
        if (desktop is null) throw new Boundary("mouse_desktop_required");
        // Balance was checked for the whole envelope. Each group is sent once.
        var prefix = steps[..split]; var releases = steps[split..];
        long? focus = DispatchSegment(prefix, ledger, result, () => { var receiver = check().Receiver; CheckPointerChords(prefix, desktop, hints, ledger); return receiver; });
        endpoint = PointerPath.ConfirmEndpoint(InputContext.AbsolutePoint(prefix[^1].Raw.Data.Mouse, desktop),
            bound, desktop, ledger, result, () => check().Permissions, waitCheck, hints!.Constraints);
        DispatchSegment(releases, ledger, result, () => {
            var receiver = check().Receiver;
            var actual = PointerPath.Cursor();
            if (actual.X != endpoint.Value.X || actual.Y != endpoint.Value.Y) throw new Boundary("pointer_endpoint_changed_before_release");
            return receiver;
        });
        return focus;
    }
    internal static long? DispatchSegment(Step[] steps, InputLedger ledger, Receipt result, Func<long?> check)
    {
        // Privacy preparation is read-only. Obtain the receiver in the final
        // check after that work and gate admission. Pure-motion callers may
        // reuse a bounded check; business/required sends force a fresh one.
        long? receiver = null;
        ledger.Send(steps, result, finalPreflight: () => receiver = check());
        return receiver;
    }
    internal static void WaitForOffset(int offsetMs, Func<long> elapsedMs, Action check, Action<int> sleep)
    {
        while (elapsedMs() < offsetMs)
        {
            check();
            // Rechecks can cross the offset. Never pass a negative delay (or
            // -1, which Thread.Sleep interprets as an unbounded wait) to Sleep.
            int delay = (int)Math.Max(0, Math.Min(20, offsetMs - elapsedMs()));
            if (delay > 0) sleep(delay);
        }
    }
    private static InputPreflight Check(ComputerPlan plan, Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock,
        InputLedger ledger, InputContextGuard context, Step[] steps, Receipt result)
    {
        var permissions = CheckEnvironment(plan, prepare, bound, stopped, clock, ledger, result);
        long stage = Stopwatch.GetTimestamp();
        try { context.RecheckCurrent(() => InputContext.Read(bound), clock.ElapsedMilliseconds); }
        finally { PointerPath.AddTiming(result, "input_context_check", stage); }
        stage = Stopwatch.GetTimestamp();
        try { CheckDesktop(plan.Desktop); }
        finally { PointerPath.AddTiming(result, "desktop_check", stage); }
        stage = Stopwatch.GetTimestamp();
        long? receiver;
        try { receiver = InputContext.CheckReceiver(bound, steps, plan.Desktop, ledger.CheckMouseCapture, permissions); }
        finally { PointerPath.AddTiming(result, "receiver_check", stage); }
        return new(receiver, permissions);
    }
    private static UserPermissionSettings CheckEnvironment(ComputerPlan plan, Prepare prepare, Bound bound, Func<bool> stopped,
        Stopwatch clock, InputLedger ledger, Receipt result)
    {
        var permissions = Executor.Check(prepare, bound, stopped, clock, true, true, ledger, result);
        CheckDesktop(plan.Desktop);
        return permissions;
    }
    private static void CheckDesktop(DesktopShape? desktopShape)
    {
        if (desktopShape is { } desktop && (desktop.Left != Native.GetSystemMetrics(76) || desktop.Top != Native.GetSystemMetrics(77)
            || desktop.Width != Native.GetSystemMetrics(78) || desktop.Height != Native.GetSystemMetrics(79))) throw new Boundary("desktop_topology_changed");
    }
}
internal sealed record InputProgress
{
    public InputBinding? Binding { get; set; }
    public bool? BusinessStarted { get; set; } = false;
    public bool BusinessComplete { get; set; }
    public int? AcceptedEvents { get; set; }
    public int CompletedPlans { get; set; }
    public int CompletedSegments { get; set; }
    public int PlannedPlans { get; set; }
    public int PlannedSegments { get; set; }
    public double? FirstCompletedPlanMs { get; set; }
    public double? LastCompletedPlanMs { get; set; }
    public double MaxInterPlanGapMs { get; set; }
    public int SkippedMotionSegments { get; set; }
    public int MotionClockRebases { get; set; }
    public object? PartialSegment { get; set; }
    public int CleanupEvents { get; set; }
    public bool NativeCountKnown { get; set; } = true;
}
