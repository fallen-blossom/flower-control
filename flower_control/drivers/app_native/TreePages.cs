using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using System.Text.Json;

// The legacy SnapshotBuilder's breadth/depth and per-page budgets are retained.
// Disposable workers cannot retain COM elements: carry ancestor RuntimeIds and
// lazy sibling branches instead of the legacy numeric skip-from-root cursor.
internal sealed class TreeCursorChanged : Exception { }
internal sealed class ProviderIdentityUnavailable : Exception
{
    public ProviderIdentityUnavailable(Exception? cause = null) : base("RuntimeId unavailable", cause) { }
}
internal sealed class TreePages : BoundedTreePages<AutomationElement>
{
    public TreePages(ITreeWalker walker, AutomationElement root, JsonElement? cursor)
        : base(root, cursor, element => ReadRuntimeId(() => element.Properties.RuntimeId.Value),
            walker.GetFirstChild, walker.GetNextSibling) { }

    internal static int[] ReadRuntimeId(Func<int[]?> read)
    {
        int[]? id;
        try { id = read(); }
        catch (FlaUI.Core.Exceptions.PropertyNotSupportedException error)
        {
            throw new ProviderIdentityUnavailable(error);
        }
        // Missing identity cannot form a cursor path or a write reference.
        // Other provider faults retain their original classification.
        return id is { Length: > 0 } ? id : throw new ProviderIdentityUnavailable();
    }
}

internal class BoundedTreePages<T> where T : class
{
    private readonly T root;
    private readonly Func<T, int[]> Id;
    private readonly Func<T, T?> FirstChild;
    private readonly Func<T, T?> NextSibling;
    private readonly PriorityQueue<int[][], (int Depth, int Sequence)> pending = new();
    private int sequence;
    private readonly Dictionary<string, T> bound = new();
    public int[][] Scope { get; }
    public int Count => pending.Count;

    public BoundedTreePages(T root, JsonElement? cursor, Func<T, int[]> id,
        Func<T, T?> firstChild, Func<T, T?> nextSibling)
    {
        this.root = root;
        Id = id; FirstChild = firstChild; NextSibling = nextSibling;
        Scope = cursor is null ? new[] { Id(root) } : ReadPath(cursor.Value.GetProperty("scope"));
        Resolve(Scope);
        if (cursor is null) Enqueue(Scope);
        else foreach (var path in cursor.Value.GetProperty("pending").EnumerateArray()) Enqueue(ReadPath(path));
    }
    public static void Validate(JsonElement cursor)
    {
        if (cursor.ValueKind != JsonValueKind.Object || cursor.EnumerateObject().Count() != 3)
            throw new ArgumentException();
        var scope = ReadPath(cursor.GetProperty("scope"));
        var branches = cursor.GetProperty("pending");
        if (branches.GetArrayLength() is < 1 or > 256
            || cursor.GetProperty("observed_at_ms").GetInt64() <= 0) throw new ArgumentException();
        foreach (var branch in branches.EnumerateArray())
        {
            var path = ReadPath(branch);
            if (path.Length < scope.Length || !scope.Select((id, i) => id.SequenceEqual(path[i])).All(x => x))
                throw new ArgumentException();
        }
    }
    private static int[][] ReadPath(JsonElement path)
    {
        if (path.GetArrayLength() is < 1 or > 17) throw new ArgumentException();
        return path.EnumerateArray().Select(id => {
            if (id.GetArrayLength() is < 1 or > 32) throw new ArgumentException();
            return id.EnumerateArray().Select(n => n.GetInt32()).ToArray();
        }).ToArray();
    }
    private T Resolve(int[][] path)
    {
        var key = JsonSerializer.Serialize(path);
        if (bound.TryGetValue(key, out var cached)) return cached;
        if (!Id(root).SequenceEqual(path[0])) throw new TreeCursorChanged();
        var current = root;
        for (int i = 1; i < path.Length; i++)
        {
            var child = FirstChild(current);
            int checkedSiblings = 0;
            while (child is not null && !Id(child).SequenceEqual(path[i]))
            {
                if (++checkedSiblings > 2048) throw new TreeCursorChanged();
                child = NextSibling(child);
            }
            current = child ?? throw new TreeCursorChanged();
        }
        bound[key] = current;
        return current;
    }
    private void Enqueue(int[][] path, T? element = null)
    {
        if (element is not null) bound[JsonSerializer.Serialize(path)] = element;
        pending.Enqueue(path, (path.Length, sequence++));
    }
    public (T Element, int Depth, int[][] Path) Peek()
    {
        var path = pending.Peek();
        return (Resolve(path), path.Length - Scope.Length, path);
    }
    // Commit only after the entry has fitted the output budget. No dropped node
    // when byte/time/node limits end a page before its entry is retained.
    public bool Commit(T element, int maxDepth)
    {
        var path = pending.Dequeue();
        if (path.Length > Scope.Length)
        {
            var sibling = NextSibling(element);
            if (sibling is not null) Enqueue(path[..^1].Append(Id(sibling)).ToArray(), sibling);
        }
        var child = FirstChild(element);
        if (child is null) return false;
        if (path.Length - Scope.Length >= maxDepth) return true;
        Enqueue(path.Append(Id(child)).ToArray(), child);
        return false;
    }
    public object Cursor(long now) => new { scope = Scope,
        pending = pending.UnorderedItems.OrderBy(x => x.Priority).Select(x => x.Element).ToArray(),
        observed_at_ms = now };
}
