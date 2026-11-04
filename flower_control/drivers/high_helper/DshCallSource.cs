using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// An expected host epoch can only restrict an admitted call. It cannot
// register a message, review it, delegate authority, restore Stop or approve.
internal sealed record DshCallSourceGuard(string InstanceId, long Revision);

internal static class DshCallSource
{
    private sealed record Expected(string SessionHash, DshCallSourceGuard Guard);
    private static readonly AsyncLocal<Expected?> current = new();
    private sealed class Scope(Expected? previous) : IDisposable
    {
        private bool disposed;
        public void Dispose() { if (!disposed) { disposed = true; current.Value = previous; } }
    }
    internal static IDisposable Enter(string source, string? session, DshCallSourceGuard? guard, bool required)
    {
        var previous = current.Value;
        if (source != "dsh-desktop-flower")
        {
            if (guard is not null) throw new Boundary("dsh_call_source_unexpected");
            current.Value = null; return new Scope(previous);
        }
        if (!required) { current.Value = null; return new Scope(previous); }
        if (guard is null || guard.InstanceId is null || !Regex.IsMatch(guard.InstanceId, "\\A[0-9a-f]{32}\\z")
            || guard.Revision is < 0 or > 9007199254740991 || session is null || session.Length == 0)
            throw new Boundary("dsh_call_source_required");
        string key = DshTranscriptReader.SessionHash(session);
        DshMessageBinding.RequireGuard(key, guard);
        current.Value = new(key, guard);
        return new Scope(previous);
    }
    internal static DshCallSourceGuard? For(string key)
    {
        var expected = current.Value;
        if (expected is null) return null;
        if (expected.SessionHash != key) throw new Boundary("dsh_call_source_session_changed");
        return expected.Guard;
    }
    internal static T Dispatch<T>(Func<T> create)
    {
        var expected = current.Value;
        return expected is null ? create() : DshMessageBinding.DispatchGuard(expected.SessionHash, expected.Guard, create);
    }
}
