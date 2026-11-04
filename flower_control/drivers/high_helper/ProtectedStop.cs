using System.Security.Principal;
using System.Text.Json;

namespace Flower.HighHelper;

// The Medium shared gate remains a coordination hint. It cannot clear this
// independent, durable High/SYSTEM stop record by changing shared bytes.
internal static class ProtectedStop
{
    internal sealed record State(int Schema, string UserSid, int Session, bool Stopped, long Epoch);
    private static string PathFor(string sid, int session, bool create, bool computer = false)
    {
        if (session <= 0 || new SecurityIdentifier(sid).Value != sid || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
            throw new Boundary("protected_stop_context_rejected");
        var own = Native.Process(Environment.ProcessId).Identity;
        if (Native.UiAccess(own.Pid) || !(own.User == sid && (own.Integrity == 12288 || !create && own.Integrity == 8192)
            || own.User == "S-1-5-18" && own.Integrity == 16384))
            throw new Boundary("protected_stop_role_required");
        var root = InstallationLocation.Current().ProgramRoot;
        UacClaimJournal.CheckParent(Path.GetDirectoryName(root)!, false); UacClaimJournal.CheckParent(root, false);
        var recovery = Path.Combine(root, "recovery");
        try { UacClaimJournal.CheckParent(recovery, false); }
        catch (Exception error) when (create && error is FileNotFoundException or DirectoryNotFoundException)
        { SecurityLabel.CreateDirectory(recovery, sid); UacClaimJournal.CheckParent(recovery, true); }
        var directory = Path.Combine(recovery, computer ? "computer-pause" : "stop");
        if (create) SecurityLabel.CreateDirectory(directory, sid);
        UacClaimJournal.CheckParent(directory, true);
        return Path.Combine(directory, sid + "." + session + ".json");
    }
    internal static State Decode(JsonDocument document, string sid, int session)
    {
        Protocol.CheckUnique(document);
        var value = Protocol.Decode<State>(document);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal)
                .SetEquals(new[] { "Schema", "UserSid", "Session", "Stopped", "Epoch" })
            || value.Schema != 1 || value.UserSid != sid || value.Session != session || value.Epoch < 0)
            throw new Boundary("protected_stop_record_rejected");
        return value;
    }
    internal static State Read(string sid, int session) => ReadFor(sid, session, false);
    internal static State ReadComputer(string sid, int session) => ReadFor(sid, session, true);
    private static State ReadFor(string sid, int session, bool computer)
    {
        try
        {
            var path = PathFor(sid, session, false, computer);
            UserPermissions.CheckProtection(path);
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (file.Length is < 1 or > 4096) throw new Boundary("protected_stop_record_rejected");
            using var document = JsonDocument.Parse(file); return Decode(document, sid, session);
        }
        catch (FileNotFoundException) { return new(1, sid, session, false, 0); }
        catch (DirectoryNotFoundException) { return new(1, sid, session, false, 0); }
    }
    internal static void RequireRunning(string sid, int session)
    { if (Read(sid, session).Stopped || OrdinaryStopJournal.Read(sid, session).Stopped) throw new Boundary("global_write_stopped"); }
    internal static void Latch(SharedWriteGate shared, Action persist, bool newStop = true, Action? sharedClosed = null)
    {
        bool persistenceAttempted = false;
        try
        {
            shared.Stop(() => { sharedClosed?.Invoke(); persistenceAttempted = true; persist(); }, newStop);
        }
        catch (Exception error)
        {
            // A Medium-writable coordination mutex must never prevent the
            // independent High/SYSTEM Stop from being persisted.
            if (!persistenceAttempted)
                try { persist(); }
                catch (Exception failure) { error.Data["ProtectedStopPersistenceError"] = Program.Code(failure); }
            throw; // Shared closure is still unconfirmed even if persistence succeeded.
        }
    }
    internal static State Next(State prior, bool stopped, long? expectedEpoch)
    {
        if (!stopped && expectedEpoch != prior.Epoch) throw new Boundary("resume_state_changed");
        return prior with { Stopped = stopped, Epoch = checked(prior.Epoch + 1) };
    }
    internal static State Set(string sid, int session, bool stopped, long? expectedEpoch = null)
        => SetFor(sid, session, stopped, expectedEpoch, false);
    internal static State SetComputer(string sid, int session, bool paused, long? expectedEpoch = null)
        => SetFor(sid, session, paused, expectedEpoch, true);
    // The legacy broker cannot export a last-moment in-memory tray pause.
    // Set a stop before replacing it; only the real tray Continue clears this.
    internal static State InitializeComputer(string sid, int session)
        => SetFor(sid, session, true, null, true);
    private static State SetFor(string sid, int session, bool stopped, long? expectedEpoch, bool computer)
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        if (!stopped && (own.User != sid || own.Integrity != 12288)) throw new Boundary("protected_stop_local_resume_required");
        var path = PathFor(sid, session, true, computer);
        using var mutex = new Mutex(false, "Local\\FlowerControl." + (computer ? "ComputerPause." : "ProtectedStop.") + sid + "." + session);
        bool held;
        try { held = mutex.WaitOne(2000); }
        catch (AbandonedMutexException) { held = true; }
        if (!held) throw new Boundary("protected_stop_busy");
        try
        {
            var prior = ReadFor(sid, session, computer);
            var next = Next(prior, stopped, expectedEpoch);
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            SecurityLabel.Write(temporary, JsonSerializer.SerializeToUtf8Bytes(next), sid);
            UserPermissions.CheckProtection(temporary);
            File.Move(temporary, path, true);
            if (ReadFor(sid, session, computer) != next) throw new Boundary("protected_stop_write_unverified");
            return next;
        }
        finally { mutex.ReleaseMutex(); }
    }
}
