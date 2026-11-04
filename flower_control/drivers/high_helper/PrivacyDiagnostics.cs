using System.Text.Json;
using System.Text.Json.Serialization;

namespace Flower.HighHelper;

internal sealed record PrivacyFailure(
    [property: JsonPropertyName("stage")] string Stage,
    [property: JsonPropertyName("exception_type")] string ExceptionType,
    [property: JsonPropertyName("hresult")] int Hresult);

internal static class PrivacyDiagnostics
{
    private static readonly HashSet<string> Stages = ["request_or_identity", "root", "password_descendants",
        "root_password", "password_recheck", "password_offscreen", "password_rectangle", "focus_element",
        "focus_identity", "focus_process", "focus_root", "focus_password", "focus_ancestor", "focus_rectangle", "focus_recheck"];
    private static readonly HashSet<string> Kinds = ["COMException", "TimeoutException", "PropertyNotSupportedException",
        "ArgumentException", "InvalidOperationException", "ElementNotAvailableException", "UnauthorizedAccessException",
        "NotSupportedByFrameworkException", "PropertyNotCachedException", "InvalidCastException", "JsonException"];
    internal static PrivacyFailure? From(Exception error) => error.Data["PrivacyDiagnostics"] as PrivacyFailure;
    internal static Boundary ScanFailure(JsonElement value)
    {
        var error = new Boundary("privacy_password_scan_incomplete");
        if (value.ValueKind != JsonValueKind.Object) return error;
        var keys = value.EnumerateObject().Select(p => p.Name).ToArray();
        if (keys.Length != 6 || !keys.ToHashSet().SetEquals(new[] {"state", "dispatched", "reason", "stage", "exception_type", "hresult"})
            || value.GetProperty("state").ValueKind != JsonValueKind.String || value.GetProperty("state").GetString() != "rejected"
            || value.GetProperty("dispatched").ValueKind != JsonValueKind.False
            || value.GetProperty("reason").ValueKind != JsonValueKind.String || value.GetProperty("reason").GetString() != "privacy_scan_incomplete"
            || value.GetProperty("stage").ValueKind != JsonValueKind.String
            || !Stages.Contains(value.GetProperty("stage").GetString()!)
            || value.GetProperty("hresult").ValueKind != JsonValueKind.Number
            || !value.GetProperty("hresult").TryGetInt32(out int hresult)) return error;
        string? kind = value.GetProperty("exception_type").ValueKind == JsonValueKind.String
            ? value.GetProperty("exception_type").GetString() : null;
        error.Data["PrivacyDiagnostics"] = new PrivacyFailure(value.GetProperty("stage").GetString()!,
            kind is not null && Kinds.Contains(kind) ? kind : "unknown_native_exception", hresult);
        return error;
    }
}
