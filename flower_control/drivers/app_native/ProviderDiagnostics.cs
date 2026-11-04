using System.Text;
using System.Text.Json;

internal static class ProviderReads
{
    internal static Dictionary<string, object?> Rejection(Exception error, string reason,
                                                         string stage, string? pattern)
    {
        var actual = error is ProviderPropertyFailure ? error.InnerException ?? error : error;
        return new() { ["state"] = "rejected", ["dispatched"] = false,
            ["reason"] = reason, ["stage"] = stage,
            ["failure_property"] = (error as ProviderPropertyFailure)?.Property,
            ["failure_pattern"] = pattern, ["exception_type"] = actual.GetType().Name,
            ["hresult"] = actual.HResult };
    }
    internal static T Required<T>(string property, Func<T> read)
    {
        try { return read(); }
        catch (ProviderPropertyFailure) { throw; }
        catch (Exception error) { throw new ProviderPropertyFailure(property, error); }
    }

    // Unsupported is distinct from an actual provider failure. The fallback is
    // limited to a visible root and nonempty rectangles with positive overlap.
    internal static bool VisibleForInput(Func<bool> offscreen, Func<bool> rootVisible,
                                         Func<int[]?> controlBounds, Func<int[]?> rootBounds)
    {
        try { return !offscreen(); }
        catch (FlaUI.Core.Exceptions.PropertyNotSupportedException)
        {
            if (!rootVisible()) return false;
            var control = controlBounds();
            var root = rootBounds();
            static bool Valid(int[]? r) => r is { Length: 4 } && r[2] > r[0] && r[3] > r[1];
            return Valid(control) && Valid(root)
                && Math.Max(control![0], root![0]) < Math.Min(control[2], root[2])
                && Math.Max(control[1], root[1]) < Math.Min(control[3], root[3]);
        }
        catch (Exception error) { throw new ProviderPropertyFailure("IsOffscreen", error); }
    }

    // Observation represents a provider's unsupported AutomationId as empty.
    // RuntimeId and the selected window still have to match independently.
    internal static bool MatchesAutomationId(string expected, Func<string?> read)
    {
        try { return (read() ?? "") == expected; }
        catch (FlaUI.Core.Exceptions.PropertyNotSupportedException) { return expected == ""; }
        catch (ProviderPropertyFailure) { throw; }
        catch (Exception error) { throw new ProviderPropertyFailure("AutomationId", error); }
    }
}

internal static class PropertyDiagnostics
{
    internal static void Validate(JsonElement value, JsonElement target)
    {
        static void Fields(JsonElement obj, params string[] names)
        {
            if (obj.ValueKind != JsonValueKind.Object || obj.EnumerateObject().Count() != names.Length
                || !obj.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(names)) throw new ArgumentException();
        }
        static int[] Id(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() is < 1 or > 32) throw new ArgumentException();
            return value.EnumerateArray().Select(item => item.GetInt32()).ToArray();
        }
        Fields(value, "reference", "observation", "properties");
        var names = value.GetProperty("properties");
        if (names.ValueKind != JsonValueKind.Array || names.GetArrayLength() != 1 || names[0].GetString() != "help_text") throw new ArgumentException();
        var reference = value.GetProperty("reference");
        var observation = value.GetProperty("observation");
        Fields(reference, "runtime_id", "automation_id");
        Fields(observation, "root_runtime_id", "reference_runtime_id", "observed_at_ms");
        if (!Id(reference.GetProperty("runtime_id")).SequenceEqual(Id(observation.GetProperty("reference_runtime_id")))
            || !Id(target.GetProperty("root_runtime_id")).SequenceEqual(Id(observation.GetProperty("root_runtime_id")))
            || reference.GetProperty("automation_id").GetString() is not { Length: <= 256 }
            || observation.GetProperty("observed_at_ms").GetInt64() <= 0) throw new ArgumentException();
    }

    internal static Dictionary<string, object?> ReadHelpText(Func<(bool Supported, string? Value)> read,
                                                            bool budgetExpired)
    {
        if (budgetExpired) return new() { ["state"] = "not_read_due_to_budget" };
        try
        {
            var (supported, value) = read();
            if (!supported) return new() { ["state"] = "unsupported" };
            var builder = new StringBuilder();
            int count = 0;
            bool truncated = false;
            foreach (var rune in (value ?? "").EnumerateRunes())
            {
                if (count++ >= 512) { truncated = true; break; }
                builder.Append(rune);
            }
            return new() { ["state"] = "available", ["value"] = builder.ToString(), ["truncated"] = truncated };
        }
        catch (FlaUI.Core.Exceptions.PropertyNotSupportedException)
        { return new() { ["state"] = "unsupported" }; }
        catch (Exception error)
        { return new() { ["state"] = "read_error", ["failure_property"] = "HelpText", ["exception_type"] = error.GetType().Name, ["hresult"] = error.HResult }; }
    }
}
