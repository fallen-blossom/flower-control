using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using System.Text.Json;
using System.Text;

static class LocalScope
{
    public static void Validate(JsonElement scope)
    {
        if (!scope.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(new[] { "anchors", "observed_at_ms" })
            || scope.GetProperty("observed_at_ms").GetInt64() <= 0)
            throw new ArgumentException();
        var anchors = scope.GetProperty("anchors");
        if (anchors.GetArrayLength() is < 1 or > 8) throw new ArgumentException();
        foreach (var anchor in anchors.EnumerateArray())
        {
            if (!anchor.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(new[] {
                    "container_runtime_id", "container_automation_id", "item_runtime_id", "item_name" }))
                throw new ArgumentException();
            foreach (var key in new[] { "container_runtime_id", "item_runtime_id" })
            {
                var id = anchor.GetProperty(key);
                if (id.GetArrayLength() is < 1 or > 32) throw new ArgumentException();
                foreach (var number in id.EnumerateArray()) _ = number.GetInt32();
            }
            string name = anchor.GetProperty("item_name").GetString()!;
            if (string.IsNullOrWhiteSpace(name) || name.EnumerateRunes().Count() > 256
                || anchor.GetProperty("container_automation_id").GetString()!.EnumerateRunes().Count() > 256)
                throw new ArgumentException();
        }
    }

    public static bool BelongsTo(ITreeWalker walker, AutomationElement item, AutomationElement container)
    {
        var expected = container.Properties.RuntimeId.Value;
        AutomationElement? current = item;
        for (int depth = 0; current is not null && depth <= 8; depth++)
        {
            if (current.Properties.RuntimeId.Value.SequenceEqual(expected)) return true;
            current = walker.GetParent(current);
        }
        return false;
    }

    public static AutomationElement? Resolve(ITreeWalker walker, AutomationElement root, JsonElement scope,
        Func<ITreeWalker, AutomationElement, int[], string, AutomationElement?> find, long maxAge = 15_000)
    {
        long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - scope.GetProperty("observed_at_ms").GetInt64();
        if (age < 0 || age > maxAge) return null;
        var current = root;
        foreach (var anchor in scope.GetProperty("anchors").EnumerateArray())
        {
            var containerId = anchor.GetProperty("container_runtime_id").EnumerateArray().Select(n => n.GetInt32()).ToArray();
            var container = find(walker, current, containerId, anchor.GetProperty("container_automation_id").GetString()!);
            if (container is null || container.Properties.IsPassword.Value
                || !container.Patterns.ItemContainer.TryGetPattern(out var pattern) || pattern is null) return null;
            string name = anchor.GetProperty("item_name").GetString()!;
            var property = container.FrameworkAutomationElement.PropertyIdLibrary.Name;
            var item = pattern.FindItemByProperty(null, property, name);
            if (item is null || pattern.FindItemByProperty(item, property, name) is not null
                || item.Name != name || item.Properties.IsPassword.Value
                || !item.Properties.RuntimeId.Value.SequenceEqual(anchor.GetProperty("item_runtime_id")
                    .EnumerateArray().Select(n => n.GetInt32())) || !BelongsTo(walker, item, container)) return null;
            current = item;
        }
        return current;
    }
}
