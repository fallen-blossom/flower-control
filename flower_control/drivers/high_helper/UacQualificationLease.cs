using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record UacQualificationContext(string PolicyRevision, string BootId,
    long SharedStopEpoch, long ProtectedStopEpoch, long Tick);
internal sealed record UacQualificationLease(string LeaseId, string Version, Peer Owner,
    string PolicyRevision, string BootId, long SharedStopEpoch, long ProtectedStopEpoch,
    long IssuedTick, long ExpiresTick);
internal sealed record UacQualificationRecord(int Schema, string UserSid, int Session,
    long Epoch, UacQualificationLease? Active);
internal sealed record UacQualificationSnapshot(UacQualificationRecord Record, string Revision);

// Durable revocation coordination only. No task/CLI/off exception consumes this
// component yet. A successful snapshot check is NOT final execution admission:
// the future executor must serialize its last go/native gate with revocation.
internal sealed partial class UacQualificationLeaseStore
{
    internal const long LifetimeMilliseconds = 300000;
    private readonly string root, sid, version;
    private readonly int session;
    private readonly bool fixture;
    private readonly Func<bool, Peer> role;
    private readonly Func<UacQualificationContext> context;
    private readonly Func<Peer, bool> liveOwner;
    private readonly Action<string>? checkpoint;
    private string PathName => Path.Combine(root, "lease.json");
    private string LockName => Path.Combine(root, "writer.lock");

    private UacQualificationLeaseStore(string root, string sid, int session, string version,
        bool fixture, Func<bool, Peer> role, Func<UacQualificationContext> context,
        Func<Peer, bool> liveOwner, Action<string>? checkpoint = null)
    {
        this.root = root; this.sid = sid; this.session = session; this.version = version;
        this.fixture = fixture; this.role = role; this.context = context;
        this.liveOwner = liveOwner; this.checkpoint = checkpoint;
    }

    internal static UacQualificationLeaseStore Open(BrokerPolicy policy, int session)
    {
        var install = InstallationLocation.Current().ProgramRoot;
        string directory = Path.Combine(install, "versions", policy.Version);
        if (policy.Fixture || policy.Schema != 1 || policy.Mode != "high" || session <= 0
            || !Sid(policy.UserSid) || !Hex(policy.Version, 16, 64)
            || !Path.GetFullPath(policy.Directory).TrimEnd('\\').Equals(directory, StringComparison.OrdinalIgnoreCase)
            || !Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(directory, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_qualification_context_rejected");
        string application = Path.Combine(directory, "Flower.HighHelper.exe");
        Peer Role(bool issue)
        {
            var own = Native.Process(Environment.ProcessId);
            if (!own.Image.Equals(application, StringComparison.OrdinalIgnoreCase) || Native.UiAccess(own.Identity.Pid))
                throw new Boundary("uac_qualification_role_rejected");
            BrokerPolicy.RejectLinks(application);
            UserPermissions.CheckSystemExecutableProtection(application);
            if (own.Identity.ImageDigest != Native.Digest(application)) throw new Boundary("uac_qualification_image_changed");
            if (!issue && own.Identity.User == "S-1-5-18" && own.Identity.Integrity == 16384)
            { UacSystemBootstrap.VerifyInteractiveUser(session, policy.UserSid); return own.Identity; }
            if (own.Identity.User != policy.UserSid || own.Identity.Session != session || own.Identity.Integrity != 12288)
                throw new Boundary("uac_qualification_role_rejected");
            return own.Identity;
        }
        UacQualificationContext Context()
        {
            // Local shared objects must be read inside the actual target session.
            // A session-0 bootstrap can inspect/revoke, never claim this check.
            var own = Native.Process(Environment.ProcessId, false).Identity;
            string? sharedSid = SharedSid(own, policy.UserSid, session);
            var settings = own.User == "S-1-5-18" ? UserPermissions.ReadForInteractiveUser(policy.UserSid) : UserPermissions.Read();
            using var shared = new SharedWriteGate(verifiedInteractiveSid: sharedSid);
            var state = shared.Snapshot(); var stop = ProtectedStop.Read(policy.UserSid, session);
            if (state.Stopped || stop.Stopped) throw new Boundary("global_write_stopped");
            return new(settings.Revision, UacChatAuthorization.BootId(), state.Epoch, stop.Epoch, Environment.TickCount64);
        }
        bool Live(Peer owner)
        {
            var current = Native.Process(owner.Pid);
            return current.Identity == owner && !Native.UiAccess(owner.Pid)
                && current.Image.Equals(application, StringComparison.OrdinalIgnoreCase);
        }
        var store = new UacQualificationLeaseStore(Path.Combine(install, "recovery", "qualification",
            policy.UserSid + "." + session.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            policy.UserSid, session, policy.Version, false, Role, Context, Live);
        Role(false); return store;
    }

    private static string? SharedSid(Peer own, string sid, int session)
    {
        if (own.Session != session) throw new Boundary("uac_qualification_interactive_session_required");
        if (own.User == "S-1-5-18" && own.Integrity == 16384) return sid;
        if (own.User == sid && own.Integrity == 12288) return null;
        throw new Boundary("uac_qualification_role_rejected");
    }

    private static bool Hex(string? value, int min = 64, int max = 64) => value is not null
        && value.Length >= min && value.Length <= max && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Sid(string? value)
    {
        try { return value is not null && value.StartsWith("S-1-5-21-", StringComparison.Ordinal)
            && new SecurityIdentifier(value).Value == value; } catch (ArgumentException) { return false; }
    }
    private static bool Revision(string? value) => value == "absent" || Hex(value);
    private static string Hash(byte[]? bytes) => bytes is null ? "absent" : Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private void Validate(UacQualificationRecord value)
    {
        if (value.Schema != 1 || value.UserSid != sid || value.Session != session || value.Epoch < 0)
            throw new Boundary("uac_qualification_record_invalid");
        if (value.Active is not { } active) return;
        if (!Hex(active.LeaseId, 32, 32) || !Hex(active.Version, 16, 64) || active.Owner is null
            || active.Owner.User != sid || active.Owner.Session != session || active.Owner.Integrity != 12288
            || active.Owner.Pid <= 0 || active.Owner.Created <= 0 || !Hex(active.Owner.ImageDigest)
            || !Revision(active.PolicyRevision) || !Hex(active.BootId, 32, 32) || active.BootId.All(c => c == '0')
            || active.SharedStopEpoch < 0 || active.ProtectedStopEpoch < 0 || active.IssuedTick < 0
            || active.ExpiresTick <= active.IssuedTick || active.ExpiresTick - active.IssuedTick > LifetimeMilliseconds
            || value.Epoch == 0) throw new Boundary("uac_qualification_record_invalid");
    }
    private UacQualificationRecord Decode(byte[] bytes)
    {
        static void Keys(JsonElement value, params string[] names)
        {
            if (value.ValueKind != JsonValueKind.Object || !value.EnumerateObject().Select(p => p.Name)
                .ToHashSet(StringComparer.Ordinal).SetEquals(names)) throw new Boundary("uac_qualification_record_invalid");
        }
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            Protocol.CheckUnique(document); var value = document.RootElement;
            Keys(value, "Schema", "UserSid", "Session", "Epoch", "Active");
            if (value.GetProperty("Active").ValueKind != JsonValueKind.Null)
            {
                var active = value.GetProperty("Active");
                Keys(active, "LeaseId", "Version", "Owner", "PolicyRevision", "BootId", "SharedStopEpoch",
                    "ProtectedStopEpoch", "IssuedTick", "ExpiresTick");
                Keys(active.GetProperty("Owner"), "Pid", "Created", "Session", "User", "ImageDigest", "Integrity");
            }
            var record = Protocol.Decode<UacQualificationRecord>(document); Validate(record); return record;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or Boundary)
        { throw new Boundary("uac_qualification_record_invalid"); }
    }
    private bool Ensure(bool create)
    {
        if (fixture)
        {
            if (create) Directory.CreateDirectory(root);
            try { BrokerPolicy.RejectLinks(root);
                if ((File.GetAttributes(root) & FileAttributes.Directory) == 0) throw new Boundary("uac_qualification_storage_unprotected");
                return true; }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { return false; }
        }
        string recovery = Path.GetDirectoryName(Path.GetDirectoryName(root)!)!;
        string install = Path.GetDirectoryName(recovery)!;
        UacClaimJournal.CheckParent(Path.GetDirectoryName(install)!, false); UacClaimJournal.CheckParent(install, false);
        foreach (string directory in new[] { recovery, Path.GetDirectoryName(root)!, root })
        {
            try { if (directory == recovery) UacClaimJournal.CheckParent(directory, false); else AuditFiles.Check(directory, true); }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
            {
                if (!create) return false;
                AuditFiles.EnsureDirectory(directory);
            }
        }
        return true;
    }
    private void CheckFile(string path)
    {
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new Boundary("uac_qualification_storage_unprotected");
        if (!fixture) AuditFiles.Check(path, false);
    }
    private byte[]? ReadBytes()
    {
        try
        {
            CheckFile(PathName);
            using var stream = new FileStream(PathName, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length is < 1 or > 8192) throw new Boundary("uac_qualification_record_invalid");
            byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return bytes;
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { return null; }
    }
    private UacQualificationSnapshot Snapshot(byte[]? bytes) => new(bytes is null ? new(1, sid, session, 0, null) : Decode(bytes), Hash(bytes));
    internal UacQualificationSnapshot Read()
    { role(false); return Snapshot(Ensure(false) ? ReadBytes() : null); }

    private T Locked<T>(Func<T> action)
    {
        role(false); Ensure(true);
        try
        {
            try { CheckFile(LockName); }
            catch (FileNotFoundException)
            {
                try { if (fixture) { using var created = new FileStream(LockName, FileMode.CreateNew, FileAccess.Write, FileShare.Read); }
                    else AuditFiles.WriteNew(LockName, []); }
                catch (IOException) { CheckFile(LockName); }
            }
            long deadline = Environment.TickCount64 + 1000;
            while (true)
            {
                FileStream held;
                try { CheckFile(LockName); held = new FileStream(LockName, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException error) when ((error.HResult & 0xffff) is 32 or 33)
                {
                    if (Environment.TickCount64 >= deadline) throw new Boundary("uac_qualification_busy");
                    Thread.Sleep(20); continue;
                }
                using (held) { role(false); return action(); }
            }
        }
        catch (UnauthorizedAccessException) { throw new Boundary("uac_qualification_storage_unavailable"); }
    }
    private UacQualificationSnapshot Write(UacQualificationSnapshot expected, UacQualificationRecord next)
    {
        Validate(next);
        var before = ReadBytes();
        if (!Revision(expected.Revision) || Hash(before) != expected.Revision) throw new Boundary("uac_qualification_changed");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(next);
        string temporary = Path.Combine(root, Guid.NewGuid().ToString("N") + ".pending");
        bool replacing = false;
        try
        {
            checkpoint?.Invoke("before_write");
            if (fixture) { using var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                output.Write(bytes); output.Flush(true); }
            else AuditFiles.WriteNew(temporary, bytes);
            checkpoint?.Invoke("before_replace");
            if (Hash(ReadBytes()) != expected.Revision) throw new Boundary("uac_qualification_changed");
            replacing = true;
            if (before is null) File.Move(temporary, PathName); else File.Replace(temporary, PathName, null);
            checkpoint?.Invoke("after_replace");
            var after = ReadBytes();
            if (after is null || !after.SequenceEqual(bytes)) throw new Boundary("uac_qualification_write_unconfirmed");
            return Snapshot(after);
        }
        catch (Exception error) when (replacing)
        { var unknown = new Boundary("uac_qualification_outcome_unknown"); unknown.Data["OriginalError"] = Program.Code(error); throw unknown; }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { Console.Error.WriteLine("uac_qualification_pending_cleanup"); }
        }
    }
    private UacQualificationSnapshot Current(UacQualificationSnapshot expected)
    {
        var current = Snapshot(ReadBytes());
        if (!Revision(expected.Revision) || expected.Revision != current.Revision) throw new Boundary("uac_qualification_changed");
        return current;
    }
    internal UacQualificationSnapshot Issue(UacQualificationSnapshot expected) => Locked(() =>
    {
        var owner = role(true); var current = Current(expected);
        // Expiration never grants takeover; an unknown old executor may remain.
        if (current.Record.Active is not null) throw new Boundary("uac_qualification_cleanup_required");
        var now = context();
        var lease = new UacQualificationLease(Guid.NewGuid().ToString("N"), version, owner, now.PolicyRevision,
            now.BootId, now.SharedStopEpoch, now.ProtectedStopEpoch, now.Tick, checked(now.Tick + LifetimeMilliseconds));
        return Write(current, current.Record with { Epoch = checked(current.Record.Epoch + 1), Active = lease });
    });
    internal UacQualificationSnapshot Revoke(UacQualificationSnapshot expected) => Locked(() =>
    {
        var current = Current(expected);
        return Write(current, current.Record with { Epoch = checked(current.Record.Epoch + 1), Active = null });
    });
    internal UacQualificationSnapshot CloseOwned(UacQualificationSnapshot expected) => Locked(() =>
    {
        var owner = role(true); var current = Current(expected);
        if (current.Record.Active is not { } active || active.Owner != owner
            || expected.Record.Epoch != current.Record.Epoch || expected.Record.Active?.LeaseId != active.LeaseId)
            throw new Boundary("uac_qualification_owner_changed");
        return Write(current, current.Record with { Epoch = checked(current.Record.Epoch + 1), Active = null });
    });
    internal void RequireCurrent(UacQualificationSnapshot expected)
    {
        role(false);
        if (!Ensure(false)) throw new Boundary("uac_qualification_changed");
        var current = Current(expected);
        if (current.Record.Active is not { } active || active.Version != version || !liveOwner(active.Owner))
            throw new Boundary("uac_qualification_not_current");
        var now = context();
        if (now.Tick < active.IssuedTick || now.Tick >= active.ExpiresTick || now.PolicyRevision != active.PolicyRevision
            || now.BootId != active.BootId || now.SharedStopEpoch != active.SharedStopEpoch
            || now.ProtectedStopEpoch != active.ProtectedStopEpoch) throw new Boundary("uac_qualification_not_current");
    }
}
