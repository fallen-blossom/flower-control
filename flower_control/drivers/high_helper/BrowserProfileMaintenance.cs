using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed record MaintenanceToolResult(string State, JsonElement? Result = null, string? Error = null);

internal static partial class BrowserProfileOpen
{
    internal static async Task<MaintenanceToolResult> RunMaintenanceAsync(string action, string? file, CancellationToken cancellation, string? expectedDigest = null)
    {
        if (action is not ("settings_export" or "storage_usage" or "cache_plan" or "cache_recycle")
            || action == "storage_usage" && file is not null || action != "storage_usage" &&
                (file is null || !Path.IsPathFullyQualified(file) || file.StartsWith(@"\\", StringComparison.Ordinal))
            || (action == "cache_recycle" ? expectedDigest is null || !Regex.IsMatch(expectedDigest, "^[a-f0-9]{64}$") : expectedDigest is not null))
            throw new Boundary("maintenance_request_rejected");
        string key = "maintenance:" + action + ":" + file + ":" + expectedDigest;
        await Gate.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            if (!Requests.TryGetValue(key, out var pending))
            {
                cancellation.ThrowIfCancellationRequested();
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                if (policy.RuntimeInventorySha256 == "" || policy.DataRoot == "") throw new Boundary("maintenance_tool_unavailable");
                List<string> args = action switch {
                    "settings_export" => ["export", "--output", file!],
                    "storage_usage" => ["usage"],
                    "cache_plan" => ["plan", "--output", file!],
                    "cache_recycle" => ["recycle", "--plan", file!, "--apply", "--expected-sha256", expectedDigest!],
                    _ => throw new Boundary("maintenance_request_rejected") };
                pending = StartFixedPython(policy, action == "settings_export" ? "tools/settings_portability.py" : "tools/storage_maintenance.py", action, args);
                Requests.Add(key, pending);
            }
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < TimeSpan.FromSeconds(60))
            {
                cancellation.ThrowIfCancellationRequested();
                if (File.Exists(pending.Result))
                {
                    BrokerPolicy.RejectLinks(pending.Result);
                    using var input = new FileStream(pending.Result, FileMode.Open, FileAccess.Read, FileShare.Read);
                    if (input.Length is < 1 or > 32_000_000) return new("outcome_unknown");
                    using var document = JsonDocument.Parse(input); Protocol.CheckUnique(document);
                    var value = document.RootElement;
                    string command = action switch { "settings_export" => "export", "storage_usage" => "usage", "cache_plan" => "plan", _ => "recycle" };
                    if (value.GetProperty("request_id").GetString() != pending.Id || value.GetProperty("command").GetString() != command)
                        return new("outcome_unknown");
                    string? state = value.GetProperty("state").GetString();
                    if (state is not ("completed" or "failed")) return new("outcome_unknown");
                    Requests.Remove(key); pending.Process.Dispose();
                    return state == "completed" ? new("completed", value.GetProperty("result").Clone())
                        : new("failed", Error: value.GetProperty("error").GetString());
                }
                if (WaitForSingleObject(pending.Process, 0) == 0) return new("outcome_unknown");
                await Task.Delay(100, cancellation).ConfigureAwait(false);
            }
            return new("outcome_unknown");
        }
        finally { Gate.Release(); }
    }
}
