// Metadata-only root membership and focused password checks. The production
// UIA adapter and offline fixtures call this same algorithm; no OS/input API.
internal static class PasswordFocus
{
    internal sealed record Result(bool Password, int[]? Rectangle);
    private sealed record Node<T>(T Element, int[] Identity) where T : class;

    private static T At<T>(string stage, Func<T> read)
    {
        try { return read(); }
        catch (Exception error) { error.Data["PrivacyStage"] = stage; throw; }
    }
    private static T Required<T>(T? value) where T : class => value ?? throw new InvalidOperationException();
    private static int[] Identity<T>(T element, Func<T, int[]?> runtimeId, string stage) where T : class => At(stage, () =>
    {
        var value = runtimeId(element);
        if (value is null || value.Length == 0) throw new InvalidOperationException();
        return value.ToArray(); // A provider-owned mutable array cannot alter the bound identity.
    });
    private static void Process<T>(T element, int expectedPid, Func<T, int> processId, string stage) where T : class => At(stage, () =>
    {
        if (expectedPid <= 0 || processId(element) != expectedPid) throw new InvalidOperationException();
        return true;
    });
    private static List<Node<T>> Ancestors<T>(T focused, int expectedPid, int[] rootId,
        Func<T, int> processId, Func<T, int[]?> runtimeId, Func<T, T?> parent, string? recheck = null) where T : class
    {
        var nodes = new List<Node<T>>();
        T? current = focused;
        for (int depth = 0; current is not null && depth < 32; ++depth)
        {
            var element = current;
            var identity = Identity(element, runtimeId, recheck ?? (depth == 0 ? "focus_identity" : "focus_ancestor"));
            Process(element, expectedPid, processId, recheck ?? (depth == 0 ? "focus_process" : "focus_ancestor"));
            if (nodes.Any(node => node.Identity.SequenceEqual(identity)))
                return At<List<Node<T>>>(recheck ?? "focus_ancestor", () => throw new InvalidOperationException());
            nodes.Add(new(element, identity));
            if (identity.SequenceEqual(rootId)) return nodes;
            if (depth < 31) current = At(recheck ?? "focus_ancestor", () => parent(element));
        }
        return At<List<Node<T>>>(recheck ?? "focus_root", () => throw new InvalidOperationException());
    }
    internal static Result Read<T>(T? root, int expectedPid, Func<T?> focused,
        Func<T, int> processId, Func<T, int[]?> runtimeId, Func<T, T?> parent,
        Func<T, bool> password, Func<T, int[]?> rectangle) where T : class
    {
        var target = At("focus_root", () => Required(root));
        var rootId = Identity(target, runtimeId, "focus_root");
        Process(target, expectedPid, processId, "focus_root");
        var first = At("focus_element", () => Required(focused()));
        var nodes = Ancestors(first, expectedPid, rootId, processId, runtimeId, parent);
        bool blocked = false;
        // Membership is proved before reading any password flag. Never inspect
        // a foreign window's ancestors merely because it owns current focus.
        foreach (var node in nodes) blocked |= At("focus_password", () => password(node.Element));
        var box = At("focus_rectangle", () =>
        {
            var value = rectangle(first);
            if (value is not null && (value.Length != 4 || value[0] >= value[2] || value[1] >= value[3]))
                throw new InvalidOperationException();
            return value?.ToArray();
        });
        var current = At("focus_recheck", () => Required(focused()));
        var freshRootId = Identity(target, runtimeId, "focus_recheck");
        Process(target, expectedPid, processId, "focus_recheck");
        if (!freshRootId.SequenceEqual(rootId))
            return At<Result>("focus_recheck", () => throw new InvalidOperationException());
        var fresh = Ancestors(current, expectedPid, rootId, processId, runtimeId, parent, "focus_recheck");
        if (fresh.Count != nodes.Count || fresh.Where((node, index) => !node.Identity.SequenceEqual(nodes[index].Identity)).Any())
            return At<Result>("focus_recheck", () => throw new InvalidOperationException());
        foreach (var node in fresh) blocked |= At("focus_password", () => password(node.Element));
        var final = At("focus_recheck", () => Required(focused()));
        Process(final, expectedPid, processId, "focus_recheck");
        if (!Identity(final, runtimeId, "focus_recheck").SequenceEqual(nodes[0].Identity))
            return At<Result>("focus_recheck", () => throw new InvalidOperationException());
        return new(blocked, box);
    }
}
