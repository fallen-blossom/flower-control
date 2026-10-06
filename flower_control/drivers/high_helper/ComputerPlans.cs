using System.Diagnostics;
using System.Text.Json;

namespace Flower.HighHelper;

internal record InputBinding(string TaskId, string ActionId, string? ObservationId, string? Generation, int? SequenceStep);
internal record DesktopShape(int Left, int Top, int Width, int Height);
internal record PlannedSegment(int OffsetMs, Step[] Steps, JsonElement[] Events);
internal record PlannedBatch(int DurationMs, PlannedSegment[] Segments);
internal record ComputerPlan(InputBinding Binding, string Command, DesktopShape? Desktop, PlannedBatch[] Plans);

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
            batches.Add(new(0, [new(0, steps.ToArray(), [])])); steps.Clear(); units = 0;
        }
        var normalized = text.Replace("\r\n", "\n").Replace('\r', '\n');
        for (int i = 0; i < normalized.Length; ++i)
        {
            char unit = normalized[i]; int size = char.IsHighSurrogate(unit) ? 2 : 1;
            if (units + size > 64 || splitTabs && unit == '\t') Flush();
            if (unit is '\n' or '\t') steps.AddRange(Executor.KeyPair(unit == '\n' ? (ushort)13 : (ushort)9, false));
            else
            {
                steps.AddRange(Executor.KeyPair(unit, true));
                if (size == 2) steps.AddRange(Executor.KeyPair(normalized[++i], true));
            }
            units += size;
            if (splitTabs && unit == '\t') Flush();
        }
        Flush();
        if (batches.Count > 131) throw new Boundary("input_plan_rejected");
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
        Fields(data, "kind", "schema_version", "command", "binding", "desktop", "plans");
        if (Text(data, "kind") != "computer_input_plan" || Number(data, "schema_version", 1, 1) != 1) throw new Boundary("input_plan_rejected");
        var command = Text(data, "command");
        if (command is not ("text" or "key" or "click" or "double_click" or "scroll" or "drag" or "move_relative" or "key_mouse" or "mouse_hold" or "move" or "hover" or "batch"))
            throw new Boundary("input_plan_rejected");
        var bind = data.GetProperty("binding");
        Fields(bind, "task_id", "action_id", "observation_id", "generation", "sequence_step");
        var binding = new InputBinding(Text(bind, "task_id", 128), Text(bind, "action_id", 512),
            Text(bind, "observation_id"), Text(bind, "generation", 4096),
            bind.GetProperty("sequence_step").ValueKind == JsonValueKind.Null ? null : Number(bind, "sequence_step", 0, 2));
        DesktopShape? desktop = null;
        var shape = data.GetProperty("desktop");
        if (shape.ValueKind != JsonValueKind.Null)
        {
            Fields(shape, "left", "top", "width", "height");
            desktop = new(Number(shape, "left", int.MinValue, int.MaxValue), Number(shape, "top", int.MinValue, int.MaxValue),
                Number(shape, "width", 1, 100000), Number(shape, "height", 1, 100000));
        }
        var rawPlans = data.GetProperty("plans");
        if (rawPlans.ValueKind != JsonValueKind.Array || rawPlans.GetArrayLength() is < 1 or > 131
            || command is not ("text" or "batch") && rawPlans.GetArrayLength() != 1) throw new Boundary("input_plan_rejected");
        var plans = new List<PlannedBatch>();
        int totalUnits = 0, totalEvents = 0;
        bool hasAbsolute = false;
        foreach (var rawPlan in rawPlans.EnumerateArray())
        {
            Fields(rawPlan, "duration_ms", "segments");
            var duration = Number(rawPlan, "duration_ms", 0, 2000);
            var rawSegments = rawPlan.GetProperty("segments");
            if (rawSegments.ValueKind != JsonValueKind.Array || (duration == 0 ? rawSegments.GetArrayLength() != 1
                : rawSegments.GetArrayLength() is < 2 or > 16)) throw new Boundary("input_plan_rejected");
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
                var events = rawEvents.EnumerateArray().Select(e => e.Clone()).ToArray();
                var steps = events.Select(Map).ToArray();
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
                            if (step.Raw.Data.Key.Vk is not (9 or 13)) throw new Boundary("input_plan_rejected");
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
                    if (held.Count(t => t.StartsWith("vk:", StringComparison.Ordinal)) > 4) throw new Boundary("input_plan_rejected");
                    if (step.Token.StartsWith("unicode:", StringComparison.Ordinal) && step.Down)
                    {
                        if (command is not ("text" or "batch") || duration != 0 || i + 1 >= steps.Length
                            || steps[i + 1].Token != step.Token || steps[i + 1].Down) throw new Boundary("input_plan_rejected");
                        units.Add((char)step.Raw.Data.Key.Scan);
                    }
                    if (duration > 0 && offset == duration && step.Down) throw new Boundary("input_plan_rejected");
                }
                eventCount += steps.Length;
                segments.Add(new(offset, steps, events));
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
            plans.Add(new(duration, segments.ToArray()));
        }
        if (totalUnits > 8192 || totalEvents > 16384 || plans.Sum(p => p.DurationMs) > 2000 || hasAbsolute && desktop is null) throw new Boundary("input_plan_rejected");
        return new(binding, command, desktop, plans.ToArray());
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
    internal static bool HasKeyboardEvents(ComputerPlan plan) => plan.Plans.Any(batch =>
        batch.Segments.Any(segment => segment.Steps.Any(step => step.Raw.Type == 1)));
    internal static void Execute(ComputerPlan plan, Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, InputLedger ledger, Receipt result)
    {
        Executor.Check(prepare, bound, stopped, clock, true, true, ledger);
        CheckDesktop(plan.Desktop);
        var keyboard = HasKeyboardEvents(plan);
        var baseline = keyboard
            ? InputContext.Prepare(bound, () => Executor.Check(prepare, bound, stopped, clock, true, true, ledger), ledger, result)
            : InputContext.Read(bound);
        var context = new InputContextGuard(baseline, keyboard);
        result.InputResult ??= new InputProgress { Binding = plan.Binding };
        int completedPlans = 0, completedSegments = 0;
        for (int p = 0; p < plan.Plans.Length; ++p)
        {
            var batch = plan.Plans[p];
            var elapsed = Stopwatch.StartNew();
            for (int s = 0; s < batch.Segments.Length; ++s)
            {
                var segment = batch.Segments[s];
                WaitForOffset(segment.OffsetMs, () => elapsed.ElapsedMilliseconds,
                    () => Check(plan, prepare, bound, stopped, clock, ledger, context, segment.Steps), Thread.Sleep);
                var focusReceiver = Check(plan, prepare, bound, stopped, clock, ledger, context, segment.Steps);
                int before = result.BusinessEvents;
                try { ledger.Send(segment.Steps, result); }
                catch
                {
                    result.InputResult.PartialSegment = new { plan = p, segment = s,
                        accepted_count = ledger.CountKnown ? (int?)(result.BusinessEvents - before) : null,
                        requested_count = segment.Steps.Length };
                    throw;
                }
                if (segment.Steps.Any(InputContext.MouseDown))
                    context.MouseDispatched(focusReceiver, clock.ElapsedMilliseconds);
                if (segment.Steps.Any(step => step.Down && step.Token == "vk:9"))
                    context.TraversalDispatched(clock.ElapsedMilliseconds);
                ++completedSegments; result.InputResult.CompletedSegments = completedSegments;
            }
            ++completedPlans; result.InputResult.CompletedPlans = completedPlans;
        }
        result.InputResult.BusinessComplete = true;
        result.State = "dispatched_unverified";
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
    private static long? Check(ComputerPlan plan, Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, InputLedger ledger, InputContextGuard context, Step[] steps)
    {
        Executor.Check(prepare, bound, stopped, clock, true, true, ledger);
        context.Recheck(InputContext.Read(bound), clock.ElapsedMilliseconds);
        CheckDesktop(plan.Desktop);
        return InputContext.CheckReceiver(bound, steps, plan.Desktop);
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
    public object? PartialSegment { get; set; }
    public int CleanupEvents { get; set; }
    public bool NativeCountKnown { get; set; } = true;
}
