using System.Text.Json;

namespace Flower.App;

// The public selectors have already been bound to the authorized observation.
// High separately validates this shape before starting its matching worker.
internal sealed record TransitionCondition(int[] RuntimeId, string AutomationId, string Field, JsonElement Expected);
internal static class TransitionGate
{
    internal static TransitionCondition[] Parse(JsonElement value)
    {
        Fields(value, ["precondition", "postcondition"]);
        return new[] { "precondition", "postcondition" }.Select(label =>
        {
            var condition = value.GetProperty(label);
            Fields(condition, ["reference", "field", "equals"]);
            var reference = condition.GetProperty("reference");
            Fields(reference, ["runtime_id", "automation_id"]);
            var id = reference.GetProperty("runtime_id");
            if (id.ValueKind != JsonValueKind.Array || id.GetArrayLength() is < 1 or > 32) throw new ArgumentException();
            var runtime = id.EnumerateArray().Select(item => item.GetInt32()).ToArray();
            var automationId = reference.GetProperty("automation_id").GetString();
            if (automationId is null || automationId.Length > 256) throw new ArgumentException();
            var field = condition.GetProperty("field").GetString();
            var expected = condition.GetProperty("equals");
            if (field is "selected" or "focused")
            {
                if (expected.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new ArgumentException();
            }
            else if (field is not ("name" or "value" or "toggle_state" or "expand_collapse_state")
                || expected.ValueKind != JsonValueKind.String || expected.GetString()!.Length > 8192)
                throw new ArgumentException();
            return new TransitionCondition(runtime, automationId, field!, expected.Clone());
        }).ToArray();
    }

    // Called after go and action-control rebind, immediately before BeginWrite.
    // Missing/unreadable fields are an explicit zero-input rejection.
    internal static string? Check(TransitionCondition[] conditions, Func<TransitionCondition, object?> read)
    {
        try
        {
            if (Matches(conditions[1], read(conditions[1]))) return "already_satisfied";
            return Matches(conditions[0], read(conditions[0])) ? null : "transition_precondition_not_met";
        }
        catch { return "transition_property_unavailable"; }
    }

    private static bool Matches(TransitionCondition condition, object? actual)
    {
        if (condition.Expected.ValueKind == JsonValueKind.String)
        {
            if (actual is not string text || text.Length > 8192) throw new ArgumentException();
            return text == condition.Expected.GetString();
        }
        if (actual is not bool value) throw new ArgumentException();
        return value == condition.Expected.GetBoolean();
    }
    private static void Fields(JsonElement value, string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != fields.Length
            || !value.EnumerateObject().Select(field => field.Name).ToHashSet().SetEquals(fields)) throw new ArgumentException();
    }
}
