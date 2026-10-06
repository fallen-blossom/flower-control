using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Flower.HighHelper;

internal record LayoutPlan(InputBinding Binding, string Command, int[] RequestedRect, DesktopShape Desktop, int[][] WorkAreas);
internal sealed record WindowLayoutResult
{
    public InputBinding? Binding { get; init; }
    public string Command { get; init; } = "";
    public int[] RequestedRect { get; init; } = [];
    public int[]? ObservedRect { get; set; }
    public bool DispatchAttempted { get; set; }
    public bool? CallReturned { get; set; } = false;
    public bool? ApiSucceeded { get; set; }
    public bool? Dispatched { get; set; } = false;
    public bool? RequestedReached { get; set; } = false;
}

internal static class WindowLayout
{
    internal const uint Flags = 0x14; // Synchronous SWP_NOACTIVATE | SWP_NOZORDER, only in the owned worker.
    [DllImport("user32.dll", SetLastError = true)] private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern bool IsZoomed(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)] private static extern int GetWindowLongW(IntPtr hwnd, int index);
    private delegate bool MonitorCallback(IntPtr monitor, IntPtr dc, IntPtr rect, IntPtr data);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool EnumDisplayMonitors(IntPtr dc, IntPtr clip, MonitorCallback callback, IntPtr data);
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo
    { public uint Size; public Native.Rect Monitor, Work; public uint Flags; }
    [DllImport("user32.dll", SetLastError = true)] private static extern bool GetMonitorInfoW(IntPtr monitor, ref MonitorInfo info);
    private static void Fields(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != names.Length
            || !value.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(names)) throw new Boundary("window_layout_rejected");
    }
    private static int Number(JsonElement value)
    { if (!value.TryGetInt32(out var n)) throw new Boundary("window_layout_rejected"); return n; }
    private static string Text(JsonElement value, int limit)
    {
        if (value.ValueKind != JsonValueKind.String || value.GetString() is not { Length: > 0 } text
            || text.Length > limit || text.Any(char.IsControl)) throw new Boundary("window_layout_rejected");
        return text;
    }
    private static int[] Rect(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() != 4) throw new Boundary("window_layout_rejected");
        var rect = value.EnumerateArray().Select(Number).ToArray();
        if (rect[0] >= rect[2] || rect[1] >= rect[3]) throw new Boundary("window_layout_rejected");
        return rect;
    }
    internal static bool Covered(int[] rect, int[][] areas)
    {
        var edges = areas.SelectMany(a => new[] { Math.Clamp(a[0], rect[0], rect[2]), Math.Clamp(a[2], rect[0], rect[2]) })
            .Append(rect[0]).Append(rect[2]).Distinct().Order().ToArray();
        for (int i = 1; i < edges.Length; ++i)
        {
            int cursor = rect[1];
            foreach (var area in areas.Where(a => a[0] <= edges[i - 1] && a[2] >= edges[i] && a[1] < rect[3] && a[3] > rect[1]).OrderBy(a => a[1]))
            {
                var top = Math.Max(rect[1], area[1]); var bottom = Math.Min(rect[3], area[3]);
                if (top > cursor) return false;
                cursor = Math.Max(cursor, bottom);
            }
            if (cursor < rect[3]) return false;
        }
        return true;
    }
    internal static LayoutPlan Parse(JsonElement value, int[] original)
    {
        try
        {
            Fields(value, "kind", "schema_version", "command", "binding", "requested_rect", "desktop", "work_areas");
            if (Text(value.GetProperty("kind"), 32) != "window_layout" || Number(value.GetProperty("schema_version")) != 1) throw new Boundary("window_layout_rejected");
            var command = Text(value.GetProperty("command"), 32);
            if (command is not ("window_move" or "window_resize")) throw new Boundary("window_layout_rejected");
            var bind = value.GetProperty("binding"); Fields(bind, "task_id", "action_id", "observation_id", "generation", "sequence_step");
            int? step = bind.GetProperty("sequence_step").ValueKind == JsonValueKind.Null ? null : Number(bind.GetProperty("sequence_step"));
            if (step is < 0 or > 2) throw new Boundary("window_layout_rejected");
            var binding = new InputBinding(Text(bind.GetProperty("task_id"), 128), Text(bind.GetProperty("action_id"), 512),
                Text(bind.GetProperty("observation_id"), 256), Text(bind.GetProperty("generation"), 4096), step);
            var rect = Rect(value.GetProperty("requested_rect"));
            long width = (long)rect[2] - rect[0], height = (long)rect[3] - rect[1];
            if (width > 16384 || height > 16384 || width * height > 16777216) throw new Boundary("window_layout_budget_exceeded");
            if (command == "window_move" ? width != (long)original[2] - original[0] || height != (long)original[3] - original[1]
                : rect[0] != original[0] || rect[1] != original[1]) throw new Boundary("window_layout_rejected");
            var shape = value.GetProperty("desktop"); Fields(shape, "left", "top", "width", "height");
            var desktop = new DesktopShape(Number(shape.GetProperty("left")), Number(shape.GetProperty("top")), Number(shape.GetProperty("width")), Number(shape.GetProperty("height")));
            if (desktop.Width is < 1 or > 100000 || desktop.Height is < 1 or > 100000
                || (long)desktop.Left + desktop.Width > int.MaxValue || (long)desktop.Top + desktop.Height > int.MaxValue) throw new Boundary("window_layout_rejected");
            var rawAreas = value.GetProperty("work_areas");
            if (rawAreas.ValueKind != JsonValueKind.Array || rawAreas.GetArrayLength() is < 1 or > 32) throw new Boundary("window_layout_rejected");
            var areas = Sort(rawAreas.EnumerateArray().Select(Rect).ToArray());
            if (areas.Select(a => string.Join(",", a)).Distinct().Count() != areas.Length
                || areas.Any(a => a[0] < desktop.Left || a[1] < desktop.Top || a[2] > (long)desktop.Left + desktop.Width || a[3] > (long)desktop.Top + desktop.Height)) throw new Boundary("window_layout_rejected");
            if (!Covered(rect, areas)) throw new Boundary("window_layout_outside_work_area");
            return new(binding, command, rect, desktop, areas);
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or OverflowException)
        { throw new Boundary("window_layout_rejected"); }
    }
    private static int[][] Sort(int[][] areas) => areas.OrderBy(a => a[0]).ThenBy(a => a[1]).ThenBy(a => a[2]).ThenBy(a => a[3]).ToArray();
    private static int[][] Areas()
    {
        var areas = new List<int[]>(); bool failed = false;
        MonitorCallback callback = (monitor, _, _, _) =>
        {
            var info = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
            if (!GetMonitorInfoW(monitor, ref info)) { failed = true; return false; }
            areas.Add([info.Work.Left, info.Work.Top, info.Work.Right, info.Work.Bottom]); return true;
        };
        if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, callback, IntPtr.Zero) || failed || areas.Count is < 1 or > 32)
            throw new Boundary("work_area_unavailable", Marshal.GetLastWin32Error());
        return Sort(areas.ToArray());
    }
    internal static void CheckDesktop(LayoutPlan plan)
    {
        var current = new DesktopShape(Native.GetSystemMetrics(76), Native.GetSystemMetrics(77), Native.GetSystemMetrics(78), Native.GetSystemMetrics(79));
        if (current != plan.Desktop || !Areas().SelectMany(a => a).SequenceEqual(plan.WorkAreas.SelectMany(a => a))) throw new Boundary("desktop_topology_changed");
    }
    internal static void CheckNormal(LayoutPlan plan, Bound bound)
    {
        var hwnd = new IntPtr(bound.Hwnd);
        ValidateNormal(plan.Command, Native.IsIconic(hwnd), IsZoomed(hwnd), plan.Command != "window_resize" || (GetWindowLongW(hwnd, -16) & 0x40000) != 0);
    }
    internal static void ValidateNormal(string command, bool minimized, bool maximized, bool resizable)
    {
        if (minimized || maximized) throw new Boundary("window_not_normal");
        if (command == "window_resize" && !resizable) throw new Boundary("window_resize_unavailable");
    }
    internal static WindowLayoutResult NewResult(LayoutPlan plan) => new() { Binding = plan.Binding, Command = plan.Command, RequestedRect = plan.RequestedRect };
    internal static void ValidateResult(LayoutPlan plan, WindowLayoutResult result)
    {
        if (result.Binding != plan.Binding || result.Command != plan.Command || !result.RequestedRect.SequenceEqual(plan.RequestedRect)
            || !result.DispatchAttempted && (result.CallReturned != false || result.ApiSucceeded is not null
                || result.Dispatched != false || result.RequestedReached != false || result.ObservedRect is not null)
            || result.DispatchAttempted && result.CallReturned == false
            || result.DispatchAttempted && result.CallReturned is null && (result.ApiSucceeded is not null || result.Dispatched is not null
                || result.RequestedReached is not null || result.ObservedRect is not null)
            || result.CallReturned == true && (result.ApiSucceeded is null || result.Dispatched != result.ApiSucceeded
                || (result.ObservedRect is null) != (result.RequestedReached is null))) throw new Boundary("layout_worker_result_rejected");
        if (result.ObservedRect is { } rect && (rect.Length != 4 || rect[0] >= rect[2] || rect[1] >= rect[3]
            || result.RequestedReached != rect.SequenceEqual(plan.RequestedRect))) throw new Boundary("layout_worker_result_rejected");
    }
    internal static void Perform(LayoutPlan plan, Receipt receipt, Action before, Action after,
        Func<(bool Success, int Error)> dispatch, Func<int[]> readRect)
    {
        receipt.LayoutResult ??= NewResult(plan);
        var result = receipt.LayoutResult;
        before();
        receipt.BusinessAttempted = true; receipt.RequiresNewObservation = true;
        receipt.State = "interrupted";
        result.DispatchAttempted = true; result.Dispatched = null; result.RequestedReached = null;
        result.CallReturned = null;
        receipt.SemanticBusinessDispatched = null;
        var sending = Stopwatch.StartNew();
        (bool Success, int Error) api;
        try { api = dispatch(); }
        finally { receipt.TimingsMs["dispatch"] = sending.Elapsed.TotalMilliseconds; }
        result.ApiSucceeded = api.Success;
        result.CallReturned = true;
        result.Dispatched = api.Success; receipt.SemanticBusinessDispatched = api.Success;
        receipt.Winerror = api.Success ? null : api.Error;
        after(); result.ObservedRect = readRect();
        result.RequestedReached = result.ObservedRect.SequenceEqual(plan.RequestedRect);
        receipt.State = api.Success ? "dispatched_unverified" : "interrupted";
        receipt.Reason = !api.Success ? "window_layout_api_failed" : result.RequestedReached == false ? "window_layout_adjusted" : null;
    }
    internal static (bool Success, int Error) Call(LayoutPlan plan, Bound bound)
    {
        var rect = plan.RequestedRect;
        var accepted = SetWindowPos(new IntPtr(bound.Hwnd), IntPtr.Zero, rect[0], rect[1], rect[2] - rect[0], rect[3] - rect[1], Flags);
        return (accepted, accepted ? 0 : Marshal.GetLastWin32Error());
    }
}
