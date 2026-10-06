using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.CompilerServices;

namespace Flower.HighHelper;

internal record Operation(string Kind, int? X = null, int? Y = null, string? Text = null, bool RestoreMinimized = false, JsonElement? Plan = null, bool Activate = false);
internal record Prepare(string Phase, Peer Parent, Target Target, Operation Operation, string[] Resources, int DeadlineMs,
    string TaskId = "", string ConnectionId = "", long DesktopRevision = 0);
internal record Ready(string Phase, Peer Helper, string AssemblyDigest, Bound Target, string[] Resources, bool MutexOwned,
    string LedgerIdentity, string TaskId, string ConnectionId, long DesktopRevision);
internal record ActivationAttempt(string Api, bool Succeeded, int Winerror);
internal sealed record Receipt
{
    public string Phase { get; init; } = "done";
    public string? LedgerIdentity { get; set; }
    public string TaskId { get; set; } = "";
    public string ConnectionId { get; set; } = "";
    public long DesktopRevision { get; set; }
    public bool RequiresNewObservation { get; set; }
    public string State { get; set; } = "rejected";
    public string? Reason { get; set; }
    public int? Winerror { get; set; }
    public Bound? Target { get; set; }
    public int SentEvents { get; set; }
    public int ActivationEvents { get; set; }
    public int BusinessEvents { get; set; }
    public int ImeEvents { get; set; }
    public bool BusinessAttempted { get; set; }
    public bool NativeCountKnown { get; set; } = true;
    public object? ImePreparation { get; set; }
    public InputProgress? InputResult { get; set; }
    public InputBinding? RequestBinding { get; set; }
    public Peer? SemanticExecutor { get; set; }
    public bool? SemanticExecutorExited { get; set; }
    public bool? SemanticBusinessDispatched { get; set; } = false;
    public object? AppResult { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public WindowLayoutResult? LayoutResult { get; set; }
    public int RequestedEvents { get; set; }
    public int ReleaseEvents { get; set; }
    public string InputRelease { get; set; } = "released";
    public bool ActivationRequested { get; set; }
    public List<ActivationAttempt> ActivationDiagnostics { get; } = [];
    public bool Foreground { get; set; }
    public bool MutexReleased { get; set; }
    public bool HighVerified { get; set; }
    public bool BusinessVerified { get; init; } = false;
    public Dictionary<string, double> TimingsMs { get; } = [];
}

internal static class Protocol
{
    internal static bool ReadOnly(Operation operation) => operation.Kind == "bind"
        || operation.Kind == "app_request" && !operation.Activate && operation.Plan is { } plan
            && plan.GetProperty("command").GetString() is "observe" or "read_text";
    internal static bool NeedsForeground(Operation operation) => operation.Kind is not ("bind" or "window_layout")
        && !(operation.Kind == "app_request" && !operation.Activate && operation.Plan is { } plan
            && plan.GetProperty("command").GetString() is "observe" or "read_text");
    internal static bool UsesPhysicalInput(Operation operation) => operation.Kind is "activate" or "click" or "text" or "computer_input_plan";
    internal const int Limit = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions Options = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private static readonly ConditionalWeakTable<Stream, List<byte>> Buffers = new();
    internal static JsonDocument? Read(Stream pipe, int timeoutMs, CancellationToken stop = default, int limit = Limit)
    {
        var data = Buffers.GetValue(pipe, _ => []);
        using var deadline = new CancellationTokenSource(Math.Max(1, timeoutMs));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, stop);
        var buffer = new byte[8192];
        while (true)
        {
            var newline = data.IndexOf(10);
            if (newline >= 0)
            {
                if (newline >= limit) throw new Boundary("message_too_large");
                var message = JsonDocument.Parse(data.Take(newline).ToArray());
                data.RemoveRange(0, newline + 1);
                try { Unique(message.RootElement); }
                catch { message.Dispose(); throw; }
                return message;
            }
            if (data.Count >= limit) throw new Boundary("message_too_large");
            var count = pipe.ReadAsync(buffer, linked.Token).AsTask().GetAwaiter().GetResult();
            if (count == 0)
            {
                if (data.Count != 0) throw new Boundary("partial_message");
                return null;
            }
            data.AddRange(buffer.Take(count));
        }
    }
    private static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            if (value.EnumerateObject().GroupBy(p => p.Name).Any(g => g.Count() != 1)) throw new Boundary("schema_rejected");
            foreach (var property in value.EnumerateObject()) Unique(property.Value);
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
    }
    internal static void CheckUnique(JsonDocument data) => Unique(data.RootElement);
    internal static T Decode<T>(JsonDocument data) => data.Deserialize<T>(Options) ?? throw new Boundary("schema_rejected");
    internal static bool Phase(JsonDocument data, string phase)
    {
        var root = data.RootElement;
        return root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 1
            && root.TryGetProperty("Phase", out var value) && value.GetString() == phase;
    }
    internal static bool Signal(JsonDocument data, string phase, string ledger)
    {
        var root = data.RootElement;
        return root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 2
            && root.TryGetProperty("Phase", out var value) && value.ValueKind == JsonValueKind.String && value.GetString() == phase
            && root.TryGetProperty("LedgerIdentity", out var identity) && identity.ValueKind == JsonValueKind.String && identity.GetString() == ledger;
    }
    internal static bool Signal(JsonDocument data, string phase, string ledger, Prepare request, string? expectedAction = null)
    {
        var root = data.RootElement;
        expectedAction ??= request.Operation.Kind == "computer_input_plan" ? ComputerPlans.Parse(request.Operation.Plan!.Value).Binding.ActionId
            : request.Operation.Kind == "window_layout" ? WindowLayout.Parse(request.Operation.Plan!.Value, request.Target.Bounds).Binding.ActionId
            : request.Operation.Kind == "app_request" ? AppExecutor.Parse(request.Operation.Plan!.Value, request.Target).Binding.ActionId : null;
        return root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 6
            && root.TryGetProperty("ActionId", out var action) && action.ValueKind == JsonValueKind.String
            && action.GetString() is { Length: <= 512 } actionId && !actionId.Any(char.IsControl)
            && (actionId.Length > 0 || phase == "ack" && expectedAction == "")
            && (expectedAction is null || expectedAction == actionId)
            && root.TryGetProperty("Phase", out var value) && value.ValueKind == JsonValueKind.String && value.GetString() == phase
            && root.TryGetProperty("LedgerIdentity", out var id) && id.ValueKind == JsonValueKind.String && id.GetString() == ledger
            && root.TryGetProperty("TaskId", out var task) && task.ValueKind == JsonValueKind.String && task.GetString() == request.TaskId
            && root.TryGetProperty("ConnectionId", out var connection) && connection.ValueKind == JsonValueKind.String && connection.GetString() == request.ConnectionId
            && root.TryGetProperty("DesktopRevision", out var revision) && revision.TryGetInt64(out var number) && number == request.DesktopRevision;
    }
    internal static void Write(Stream pipe, object message)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message) + "\n");
        if (bytes.Length > Limit) throw new Boundary("message_too_large");
        using var deadline = new CancellationTokenSource(500);
        pipe.WriteAsync(bytes, deadline.Token).AsTask().GetAwaiter().GetResult();
        pipe.FlushAsync(deadline.Token).GetAwaiter().GetResult();
    }
    internal static void Validate(Prepare data, bool mediumFixture)
    {
        var target = data.Target; var operation = data.Operation;
        if (data.Phase != "prepare" || data.Parent is null || target is null || operation is null || data.Resources is null
            || data.DeadlineMs is < 100 or > 5000 || target.Hwnd <= 0 || target.Pid <= 0 || target.Created <= 0
            || target.Nonce < 0 || target.Bounds is null || target.Bounds.Length != 4
            || target.Bounds[0] >= target.Bounds[2] || target.Bounds[1] >= target.Bounds[3]
            || target.ImageDigest is null || !System.Text.RegularExpressions.Regex.IsMatch(target.ImageDigest, "^[a-f0-9]{64}$")
            || (mediumFixture ? target.Integrity != 8192 : target.Integrity is not (8192 or 12288))) throw new Boundary("prepare_rejected");
        if (operation.Kind is not ("bind" or "activate" or "click" or "text" or "computer_input_plan" or "app_request" or "window_layout")
            || (operation.Kind != "bind" && target.Nonce == 0)
            || (operation.Kind == "click" ? operation.X is null || operation.Y is null || operation.Text is not null
                : operation.X is not null || operation.Y is not null)
            || (operation.Kind == "text" ? string.IsNullOrEmpty(operation.Text) || operation.Text.Length > 64
                : operation.Text is not null)
            || ((operation.Kind is "bind" or "window_layout") && operation.RestoreMinimized)) throw new Boundary("operation_rejected");
        if (operation.Activate && (operation.Kind != "app_request" || operation.Plan is null
                || AppExecutor.Parse(operation.Plan.Value, target).Command is not ("invoke" or "focus" or "guarded_input"))
            || operation.Kind == "app_request" && operation.RestoreMinimized && !operation.Activate)
            throw new Boundary("operation_rejected");
        if (operation.Kind == "app_request" && operation.Plan is { } guarded
            && guarded.GetProperty("command").GetString() == "guarded_input" && !operation.Activate)
            throw new Boundary("guarded_input_requires_foreground_ledger");
        if (operation.Kind == "computer_input_plan")
        {
            if (operation.Plan is null || ComputerPlans.Parse(operation.Plan.Value).Binding.TaskId != data.TaskId)
                throw new Boundary("input_plan_rejected");
        }
        else if (operation.Kind == "app_request")
        {
            if (operation.Plan is null || AppExecutor.Parse(operation.Plan.Value, target).Binding.TaskId != data.TaskId)
                throw new Boundary("app_request_rejected");
        }
        else if (operation.Kind == "window_layout")
        {
            if (operation.Plan is null || WindowLayout.Parse(operation.Plan.Value, target.Bounds).Binding.TaskId != data.TaskId)
                throw new Boundary("window_layout_rejected");
        }
        else if (operation.Plan is not null) throw new Boundary("operation_rejected");
        if (operation.Text is not null)
        {
            for (var i = 0; i < operation.Text.Length; ++i)
            {
                var ch = operation.Text[i];
                if (char.IsControl(ch) && ch is not ('\r' or '\n' or '\t')) throw new Boundary("operation_rejected");
                if (char.IsHighSurrogate(ch))
                {
                    if (++i >= operation.Text.Length || !char.IsLowSurrogate(operation.Text[i])) throw new Boundary("operation_rejected");
                }
                else if (char.IsLowSurrogate(ch)) throw new Boundary("operation_rejected");
            }
        }
        var physical = $"physical-window-v1:{target.Pid}:{target.Created}:{target.Hwnd}";
        if (data.Resources.Length is < 1 or > 8 || data.Resources.Distinct().Count() != data.Resources.Length
            || (NeedsForeground(operation) || operation.Kind == "window_layout") && !data.Resources.Contains("desktop-foreground-input-v1") || !data.Resources.Contains(physical)
            || data.Resources.Any(r => r is null || r.Length > 128 || (r != physical && r != "desktop-foreground-input-v1"
                && !System.Text.RegularExpressions.Regex.IsMatch(r, "^web-(profile|session):[a-zA-Z0-9_-]{1,96}$"))))
            throw new Boundary("resources_rejected");
    }
}
