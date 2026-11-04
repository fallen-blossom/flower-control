using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record UacChatAuthorizationSnapshot(string UserSid, int Session, string SessionHash,
    string HostKind, string? TurnId, string? MessageRef, long MessageRevision, string? ReviewedRef,
    string State, string? GrantId, string? GrantMessageRef, string? GrantTurnId, string? GrantPromptMac,
    string? ScopeKind, UacApplicationPermission[] Programs,
    bool GrantActive, string Revision, string PolicyRevision, long StopEpoch, bool Stopped,
    string BootId, long CapturedTick)
{
    public string Provenance => "host_message_restrictions_only";
    public bool Pending => MessageRef is null || ReviewedRef != MessageRef;
    // Response metadata only: never persisted, and not an authority identity.
    public bool Changed { get; init; }
}

internal sealed record UacChatAuthorizationEvaluation(bool SemanticVerified, bool ScopeMatches,
    bool ExplicitlyDenied, bool Pending);
internal sealed record UacChatMessage(string TurnId, string MessageRef, string PromptMac);
internal sealed record UacChatRecord(int Schema, string UserSid, int Session, string SessionHash,
    string HostKind, string TurnId, string MessageRef, long MessageRevision, string? ReviewedRef,
    string State, string? GrantId, string? GrantMessageRef, string? GrantTurnId, string? GrantPromptMac,
    string? ScopeKind, UacApplicationPermission[] Programs,
    bool GrantActive, UacChatMessage[] Messages);
internal sealed record UacChatDecisionPreparation(UacChatRecord Prior, byte[] Bytes,
    string PolicyRevision, SharedWriteGate.Status Stop);

// Host events retain restriction/review context, not elevation authority.
// Legacy grant fields remain serializable so old protected records can still
// be checked and revoked; no reader or writer may activate those grants.
// This layer receives no prompt, quote or transcript.
internal static class UacChatAuthorization
{
    private const int Schema = 1, ByteLimit = 128000, MessageLimit = 128, ProgramLimit = 32, RecordLimit = 2048;
    internal const long SnapshotLifetimeMilliseconds = 60000;
    private sealed record Envelope(int Schema, UacChatRecord Record, string Mac);
    [StructLayout(LayoutKind.Sequential)] private struct Attributes
    { internal uint Size; internal IntPtr Descriptor; internal int Inherit; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate int QuerySystemInformation(
        int informationClass, IntPtr information, uint length, out uint returned);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateMutexW(ref Attributes attributes, bool owner, string name);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")] private static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string path, uint access,
        uint sharing, ref Attributes attributes, uint disposition, uint flags, IntPtr template);

    private sealed class Storage
    {
        internal readonly BrokerPolicy Policy;
        internal readonly int Session;
        internal readonly string SessionHash, Root, Permissions, Directory, Path, KeyPath, FaultPath, UserKey;
        internal Storage(BrokerPolicy policy, int session, string sessionHash, bool write)
        {
            ValidateContext(policy.UserSid, session, sessionHash, "codex");
            if (policy.Fixture || policy.Schema != 1 || policy.Mode != "high" || !Hex(policy.Version, 16, 64))
                throw new Boundary("uac_chat_context_rejected");
            Root = InstallationLocation.Current().ProgramRoot;
            var expectedDirectory = System.IO.Path.GetFullPath(System.IO.Path.Combine(Root, "versions", policy.Version));
            if (!System.IO.Path.GetFullPath(policy.Directory).Equals(expectedDirectory, StringComparison.OrdinalIgnoreCase)
                || !System.IO.Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(System.IO.Path.DirectorySeparatorChar)
                    .Equals(expectedDirectory, StringComparison.OrdinalIgnoreCase)) throw new Boundary("uac_chat_context_rejected");
            Policy = policy; Session = session; SessionHash = sessionHash;
            Permissions = System.IO.Path.Combine(Root, "permissions");
            Directory = System.IO.Path.Combine(Permissions, "uac-chat");
            UserKey = Hash(Encoding.UTF8.GetBytes(policy.UserSid));
            Path = System.IO.Path.Combine(Directory, UserKey + "." + session.ToString(CultureInfo.InvariantCulture) + "." + sessionHash + ".json");
            KeyPath = System.IO.Path.Combine(Directory, UserKey + ".key");
            FaultPath = Path + ".fault";
            RequireRole(write);
        }
        internal void RequireRole(bool write)
        {
            var peer = Native.Process(Environment.ProcessId, digestImage: false).Identity;
            if (peer.Session != Session || Native.UiAccess(peer.Pid)) throw new Boundary("uac_chat_context_rejected");
            if (!write && peer.User == "S-1-5-18" && peer.Integrity == 16384)
            { UacSystemBootstrap.VerifyInteractiveUser(Session, Policy.UserSid); return; }
            if (peer.User != Policy.UserSid || peer.Integrity != 12288) throw new Boundary("uac_chat_high_role_required");
        }
        internal T Locked<T>(Func<T> action)
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;HI)",
                1, out var descriptor, out _)) throw new Boundary("uac_chat_lock_unavailable");
            IntPtr mutex = IntPtr.Zero;
            try
            {
                var attributes = new Attributes { Size = (uint)Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
                mutex = CreateMutexW(ref attributes, false, "Local\\FlowerControl.UacChat." + UserKey);
                if (mutex == IntPtr.Zero) throw new Boundary("uac_chat_lock_unavailable");
                var wait = WaitForSingleObject(mutex, 5000);
                if (wait is not (0 or 0x80)) throw new Boundary("uac_chat_store_busy");
                try { return action(); }
                finally { if (!ReleaseMutex(mutex)) throw new Boundary("uac_chat_lock_release_unconfirmed"); }
            }
            finally { if (mutex != IntPtr.Zero) CloseHandle(mutex); LocalFree(descriptor); }
        }
        private static void Parent(string path, bool high)
        {
            BrokerPolicy.RejectLinks(path);
            if (high) { UserPermissions.CheckProtectionForDirectory(path); return; }
            var info = new DirectoryInfo(path);
            if (!info.Exists) throw new DirectoryNotFoundException();
            var security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null
                || security.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw new Boundary("uac_chat_store_unprotected");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (UacClaimJournal.UntrustedAncestorMutation(rule)) throw new Boundary("uac_chat_store_unprotected");
        }
        internal bool Ensure(bool create)
        {
            Parent(System.IO.Path.GetDirectoryName(Root)!, false); Parent(Root, false);
            foreach (var path in new[] { Permissions, Directory })
            {
                try { Parent(path, true); }
                catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
                {
                    if (!create) return false;
                    try { SecurityLabel.CreateDirectory(path, Policy.UserSid); Parent(path, true); }
                    catch (Exception failure) { throw PersistenceFailure(failure); }
                }
            }
            return true;
        }
        internal byte[]? ReadBytes(string path, int maximum)
        {
            try
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                    throw new Boundary("uac_chat_record_invalid");
            }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { return null; }
            UserPermissions.CheckProtection(path);
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (file.Length is < 1 || file.Length > maximum) throw new Boundary("uac_chat_record_invalid");
            var bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes); return bytes;
        }
        internal byte[] Key(bool create)
        {
            var bytes = ReadBytes(KeyPath, 32);
            if (bytes is not null) { if (bytes.Length != 32) throw new Boundary("uac_chat_key_invalid"); return bytes; }
            if (!create || System.IO.Directory.EnumerateFiles(Directory, UserKey + ".*.json").Any())
                throw new Boundary("uac_chat_key_missing");
            bytes = RandomNumberGenerator.GetBytes(32);
            // The per-user HMAC key has no ordinary-user read ACE. Otherwise a
            // low-entropy prompt digest could be guessed from readable state.
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;HI)",
                1, out var descriptor, out _)) throw new Boundary("uac_chat_key_unavailable");
            try
            {
                var attributes = new Attributes { Size = (uint)Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
                using var handle = CreateFileW(KeyPath, 0x40000000, 1, ref attributes, 1, 0x80000000, IntPtr.Zero);
                if (handle.IsInvalid) throw new Boundary("uac_chat_key_unavailable");
                using var output = new FileStream(handle, FileAccess.Write); output.Write(bytes); output.Flush(true);
            }
            catch (Exception error) { throw PersistenceFailure(error); }
            finally { LocalFree(descriptor); }
            try
            {
                UserPermissions.CheckProtection(KeyPath);
                var saved = ReadBytes(KeyPath, 32);
                if (saved is null || !CryptographicOperations.FixedTimeEquals(bytes, saved)) throw new Boundary("uac_chat_key_unconfirmed");
            }
            catch (Exception error) { throw PersistenceFailure(error); }
            return bytes;
        }
        private Boundary PersistenceFailure(Exception original)
        {
            // Only callers that actually attempted a durable write use this
            // path. Bad references, scopes and ordinary validation never do.
            original.Data["PersistenceFailure"] = true;
            try
            {
                if (ReadBytes(FaultPath, 1024) is null)
                {
                    var bytes = Encoding.UTF8.GetBytes("{\"Schema\":1,\"Reason\":\"uac_chat_persistence_failed\"}");
                    SecurityLabel.Write(FaultPath, bytes, Policy.UserSid); UserPermissions.CheckProtection(FaultPath);
                    var saved = ReadBytes(FaultPath, 1024);
                    if (saved is null || !bytes.SequenceEqual(saved)) throw new Boundary("uac_chat_fault_unconfirmed");
                }
                return Failure("uac_chat_persistence_failed");
            }
            catch { return Failure("uac_chat_fault_persistence_failed"); }
        }
        private void RequireNoFault()
        {
            if (ReadBytes(FaultPath, 1024) is not null) throw Failure("uac_chat_authorization_recovery_required");
        }
        internal (UacChatRecord? Record, byte[]? Bytes) Current()
        {
            if (!Ensure(false)) return (null, null);
            RequireNoFault();
            var bytes = ReadBytes(Path, ByteLimit);
            if (bytes is null) return (null, null);
            var key = Key(false);
            try { return (Decode(bytes, key, Policy.UserSid, Session, SessionHash), bytes); }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        internal void Save(UacChatRecord record, byte[]? priorBytes, byte[] key)
        {
            ValidateRecord(record); RequireRole(true); Ensure(true);
            if (priorBytes is null && System.IO.Directory.EnumerateFiles(Directory, "*.json").Take(RecordLimit).Count() >= RecordLimit)
                throw new Boundary("uac_chat_store_capacity_reached");
            var bytes = Encode(record, key);
            var temporary = System.IO.Path.Combine(Directory, UserKey + "." + Guid.NewGuid().ToString("N") + ".tmp");
            var rollback = System.IO.Path.Combine(Directory, UserKey + "." + Guid.NewGuid().ToString("N") + ".rollback");
            bool committed = false, preserveRollback = false, writeAttempted = false;
            try
            {
                writeAttempted = true;
                SecurityLabel.Write(temporary, bytes, Policy.UserSid); UserPermissions.CheckProtection(temporary);
                var current = ReadBytes(Path, ByteLimit);
                if ((priorBytes is null) != (current is null) || priorBytes is not null && !priorBytes.SequenceEqual(current!))
                    throw new Boundary("uac_chat_record_changed");
                if (priorBytes is null) File.Move(temporary, Path);
                else File.Replace(temporary, Path, rollback);
                committed = true;
                try
                {
                    var verified = ReadBytes(Path, ByteLimit);
                    if (verified is null || !verified.SequenceEqual(bytes)) throw new Boundary("uac_chat_write_unconfirmed");
                    _ = Decode(verified, key, Policy.UserSid, Session, SessionHash);
                }
                catch
                {
                    // An uncertain save cannot silently activate a grant. If
                    // rollback itself fails, retain it and report the outcome.
                    try { if (priorBytes is null) File.Delete(Path); else File.Move(rollback, Path, true); committed = false; }
                    catch { preserveRollback = true; throw new Boundary("uac_chat_save_outcome_unknown"); }
                    throw;
                }
            }
            catch (Exception error) when (writeAttempted) { throw PersistenceFailure(error); }
            finally
            {
                foreach (var file in new[] { temporary, rollback })
                    if (!(preserveRollback && file == rollback))
                        try { if (File.Exists(file)) File.Delete(file); }
                        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                        { Console.Error.WriteLine(committed ? "uac_chat_saved_cleanup_pending" : "uac_chat_cleanup_pending"); }
            }
        }
        internal UserPermissionSettings Settings() => WindowsIdentity.GetCurrent().IsSystem
            ? UserPermissions.ReadForInteractiveUser(Policy.UserSid) : UserPermissions.Read();
        internal SharedWriteGate.Status Stop()
        {
            using var gate = WindowsIdentity.GetCurrent().IsSystem
                ? new SharedWriteGate(verifiedInteractiveSid: Policy.UserSid) : new SharedWriteGate();
            return gate.Snapshot();
        }
        internal UacChatAuthorizationSnapshot Snapshot(UacChatRecord? record, byte[]? bytes)
        {
            var settings = Settings(); var stop = Stop();
            return MakeSnapshot(record, Policy.UserSid, Session, SessionHash, bytes is null ? new string('0', 64) : Hash(bytes),
                settings.Revision, stop.Epoch, stop.Stopped, BootId(), Environment.TickCount64);
        }
    }

    internal static UacChatAuthorizationSnapshot RegisterEvent(BrokerPolicy policy, int ownSession,
        string sessionHash, string hostKind, string turnId, string promptDigest)
    {
        ValidateContext(policy.UserSid, ownSession, sessionHash, hostKind); Identifier(turnId, 256);
        if (!Hex(promptDigest, 64, 64)) throw new Boundary("uac_chat_prompt_digest_rejected");
        var storage = new Storage(policy, ownSession, sessionHash, true);
        return storage.Locked(() =>
        {
            storage.Ensure(true); var key = storage.Key(true);
            try
            {
                var (prior, bytes) = storage.Current();
                var promptMac = Mac(key, "flower-uac-prompt-v1\0", Encoding.UTF8.GetBytes(promptDigest));
                var next = ReduceEvent(prior, policy.UserSid, ownSession, sessionHash, hostKind, turnId, promptMac, Guid.NewGuid().ToString("N"));
                if (next != prior) { storage.Save(next, bytes, key); bytes = Encode(next, key); }
                return storage.Snapshot(next, bytes) with { Changed = next != prior };
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        });
    }
    internal static UacChatAuthorizationSnapshot Decide(BrokerPolicy policy, int ownSession, string sessionHash,
        string turnId, string messageRef, string decision, string? scopeKind = null, string[]? programPaths = null)
    {
        bool permissionWriteAttempted = false;
        try
        {
            RequireRestrictionDecision(decision);
            var storage = new Storage(policy, ownSession, sessionHash, true);
            var paths = programPaths?.ToArray();
            return DecideInPhases(
                () => storage.Locked(() =>
                {
                    var (prior, bytes) = storage.Current();
                    if (prior is null || bytes is null) throw new Boundary("uac_chat_message_missing");
                    ValidateDecisionInput(prior, turnId, messageRef, decision, scopeKind, paths);
                    var settings = storage.Settings().Revision; var stop = storage.Stop();
                    RequireDecisionStop(decision, stop.Stopped);
                    return new UacChatDecisionPreparation(prior, bytes, settings, stop);
                }),
                // Restriction decisions never inspect or approve a program.
                () => [],
                (prepared, programs) => storage.Locked(() =>
                {
                    var (prior, bytes) = storage.Current();
                    RequirePreparedState(prepared, prior, bytes, storage.Settings().Revision, storage.Stop(), decision);
                    var next = ReduceDecision(prior!, turnId, messageRef, decision, scopeKind, programs, Guid.NewGuid().ToString("N"));
                    var key = storage.Key(false);
                    try
                    {
                        if (next != prior)
                        {
                            permissionWriteAttempted = true;
                            storage.Save(next, bytes, key); bytes = Encode(next, key);
                        }
                        return storage.Snapshot(next, bytes) with { Changed = next != prior };
                    }
                    finally { CryptographicOperations.ZeroMemory(key); }
                }));
        }
        catch (Exception error)
        {
            error.Data["PermissionWriteAttempted"] = permissionWriteAttempted;
            throw;
        }
    }
    internal static UacChatAuthorizationSnapshot Read(BrokerPolicy policy, int ownSession, string sessionHash)
    {
        var storage = new Storage(policy, ownSession, sessionHash, false);
        return storage.Locked(() => { var current = storage.Current(); return storage.Snapshot(current.Record, current.Bytes); });
    }
    internal static UacChatAuthorizationSnapshot ReduceCurrentAuthority(BrokerPolicy policy, int ownSession,
        string sessionHash, string nativeTurn, string decision)
    {
        bool writeAttempted = false;
        try
        {
            if (decision is not ("deny" or "revoke")) throw new Boundary("uac_chat_reduction_required");
            Identifier(nativeTurn, 256);
            var storage = new Storage(policy, ownSession, sessionHash, true);
            return storage.Locked(() => {
                storage.Ensure(true); var key = storage.Key(true);
                try
                {
                    var (prior, bytes) = storage.Current();
                    // A first denial has no permission-producing source. Its
                    // marker only persists a restriction and cannot grant.
                    var basis = prior ?? ReduceEvent(null, policy.UserSid, ownSession, sessionHash, DshMessageBinding.Known(sessionHash) ? "dsh-desktop" : "codex", nativeTurn,
                        Mac(key, "flower-uac-restriction-v1\0", Encoding.UTF8.GetBytes(decision)), Guid.NewGuid().ToString("N"));
                    var next = ReduceDecision(basis, basis.TurnId, basis.MessageRef, decision, null, [], Guid.NewGuid().ToString("N"));
                    if (next != prior) { writeAttempted = true; storage.Save(next, bytes, key); bytes = Encode(next, key); }
                    return storage.Snapshot(next, bytes) with { Changed = next != prior };
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            });
        }
        catch (Exception error) { error.Data["PermissionWriteAttempted"] = writeAttempted; throw; }
    }
    internal static void RequireCurrent(BrokerPolicy policy, int ownSession, UacChatAuthorizationSnapshot expectedSnapshot)
    {
        if (expectedSnapshot is null) throw new Boundary("uac_chat_snapshot_rejected");
        var current = Read(policy, ownSession, expectedSnapshot.SessionHash);
        RequireSameSnapshot(expectedSnapshot, current, Environment.TickCount64);
    }
    internal static UacChatAuthorizationEvaluation Evaluate(UacChatAuthorizationSnapshot snapshot, UacApplicationPermission? actualProgram)
    {
        // Even a well-formed, MAC-verified legacy grant supplies no authority.
        return new(false, false, snapshot.State is "denied" or "revoked", snapshot.Pending);
    }

    internal static string BootId()
    {
        // SYSTEM_BOOT_ENVIRONMENT_INFORMATION (class 90) begins with a stable
        // per-boot GUID. No UTC-minus-uptime approximation or wall-clock drift.
        // This NT query is version-sensitive: absent/changed APIs fail closed.
        IntPtr library = IntPtr.Zero, buffer = IntPtr.Zero;
        try
        {
            library = NativeLibrary.Load(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll"));
            var query = Marshal.GetDelegateForFunctionPointer<QuerySystemInformation>(NativeLibrary.GetExport(library, "NtQuerySystemInformation"));
            buffer = Marshal.AllocHGlobal(64);
            for (var index = 0; index < 64; index++) Marshal.WriteByte(buffer, index, 0);
            if (query(90, buffer, 64, out var returned) != 0 || returned is < 20 or > 64) throw new Boundary("uac_chat_boot_identity_unavailable");
            var value = Marshal.PtrToStructure<Guid>(buffer);
            if (value == Guid.Empty) throw new Boundary("uac_chat_boot_identity_unavailable");
            return value.ToString("N");
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        { throw new Boundary("uac_chat_boot_identity_unavailable"); }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); if (library != IntPtr.Zero) NativeLibrary.Free(library); }
    }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static Boundary Failure(string code)
    {
        var error = new Boundary(code); error.Data["PersistenceFailure"] = true; return error;
    }
    internal static void RequireDecisionStop(string decision, bool stopped)
    {
        RequireRestrictionDecision(decision);
    }
    internal static void RequireRestrictionDecision(string decision)
    {
        if (decision is "allow" or "keep") throw new Boundary("uac_semantic_expansion_removed");
        if (decision is not ("acknowledge" or "deny" or "revoke")) throw new Boundary("uac_chat_decision_rejected");
    }
    internal static T DecideInPhases<T>(Func<UacChatDecisionPreparation> prepare,
        Func<UacApplicationPermission[]> inspect, Func<UacChatDecisionPreparation, UacApplicationPermission[], T> commit)
    {
        var prepared = prepare();
        var programs = inspect();
        return commit(prepared, programs);
    }
    private static void ValidateDecisionInput(UacChatRecord prior, string turnId, string messageRef, string decision,
        string? scopeKind, string[]? programPaths)
    {
        RequireRestrictionDecision(decision);
        ValidateRecord(prior); Identifier(turnId, 256);
        if (prior.TurnId != turnId || prior.MessageRef != messageRef) throw new Boundary("uac_chat_message_reference_stale");
        if (scopeKind is not null || programPaths is not null) throw new Boundary("uac_chat_scope_rejected");
    }
    internal static void RequirePreparedState(UacChatDecisionPreparation prepared, UacChatRecord? current,
        byte[]? bytes, string policyRevision, SharedWriteGate.Status stop, string decision)
    {
        RequireRestrictionDecision(decision);
        if (current is null || bytes is null || !prepared.Bytes.SequenceEqual(bytes)) throw new Boundary("uac_chat_authority_changed");
    }
    internal static string Mac(byte[] key, string domain, byte[] bytes)
    {
        if (key.Length != 32) throw new Boundary("uac_chat_key_invalid");
        var prefix = Encoding.UTF8.GetBytes(domain); var input = new byte[prefix.Length + bytes.Length];
        prefix.CopyTo(input, 0); bytes.CopyTo(input, prefix.Length);
        return Convert.ToHexString(HMACSHA256.HashData(key, input)).ToLowerInvariant();
    }
    private static bool Hex(string? value, int minimum, int maximum) => value is not null && value.Length >= minimum
        && value.Length <= maximum && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static void Identifier(string value, int maximum)
    {
        if (value is null || value.Length is < 1 || value.Length > maximum || value != value.Trim() || value.Any(char.IsControl))
            throw new Boundary("uac_chat_identifier_rejected");
    }
    private static void ValidateContext(string sid, int session, string sessionHash, string hostKind)
    {
        if (session <= 0 || !Hex(sessionHash, 64, 64) || hostKind is not ("codex" or "dsh-desktop")) throw new Boundary("uac_chat_context_rejected");
        try { if (new SecurityIdentifier(sid).Value != sid || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)) throw new Boundary("uac_chat_context_rejected"); }
        catch (ArgumentException) { throw new Boundary("uac_chat_context_rejected"); }
    }
    internal static void ValidateRecord(UacChatRecord value)
    {
        if (value is null) throw new Boundary("uac_chat_record_invalid");
        ValidateContext(value.UserSid, value.Session, value.SessionHash, value.HostKind); Identifier(value.TurnId, 256);
        if (value.Schema != Schema || !Hex(value.MessageRef, 32, 32) || value.MessageRevision <= 0
            || value.ReviewedRef is not null && value.ReviewedRef != value.MessageRef
            || value.State is not ("not_requested" or "allowed" or "denied" or "revoked")
            || value.Messages is null || value.Messages.Length is < 1 or > MessageLimit
            || value.Messages.Any(message => message is null)
            || value.Messages.Select(message => message.MessageRef).Distinct(StringComparer.Ordinal).Count() != value.Messages.Length)
            throw new Boundary("uac_chat_record_invalid");
        foreach (var message in value.Messages)
        {
            Identifier(message.TurnId, 256);
            if (!Hex(message.MessageRef, 32, 32) || !Hex(message.PromptMac, 64, 64)) throw new Boundary("uac_chat_record_invalid");
        }
        if (value.Messages[^1].TurnId != value.TurnId || value.Messages[^1].MessageRef != value.MessageRef
            || value.GrantActive && (value.State != "allowed" || value.ReviewedRef != value.MessageRef)
            || value.Programs is null || value.Programs.Length > ProgramLimit) throw new Boundary("uac_chat_record_invalid");
        if (value.State == "allowed")
        {
            if (!Hex(value.GrantId, 32, 32) || !Hex(value.GrantMessageRef, 32, 32) || !Hex(value.GrantPromptMac, 64, 64)
                || value.GrantTurnId is null || value.ScopeKind is not ("chat" or "programs")
                || value.ScopeKind == "chat" && value.Programs.Length != 0
                || value.ScopeKind == "programs" && value.Programs.Length == 0) throw new Boundary("uac_chat_record_invalid");
            Identifier(value.GrantTurnId, 256);
            var source = value.Messages.FirstOrDefault(message => message.MessageRef == value.GrantMessageRef);
            if (source is not null && (source.TurnId != value.GrantTurnId || source.PromptMac != value.GrantPromptMac))
                throw new Boundary("uac_chat_record_invalid");
        }
        else if (value.GrantId is not null || value.GrantMessageRef is not null || value.GrantTurnId is not null
            || value.GrantPromptMac is not null || value.ScopeKind is not null || value.Programs.Length != 0 || value.GrantActive)
            throw new Boundary("uac_chat_record_invalid");
        foreach (var program in value.Programs)
            if (program is null || !program.Enabled || !System.IO.Path.IsPathFullyQualified(program.Path)
                || program.Arguments is not null // Program-scoped semantic records retain their original schema and meaning.
                || program.Path.StartsWith("\\\\", StringComparison.Ordinal) || program.Path.Skip(2).Contains(':')
                || program.Path.Any(char.IsControl) || program.Path.IndexOfAny(['*', '?']) >= 0
                || program.IdentityKind is not ("signed" or "sha256") || !Hex(program.Identity, 64, 64)
                || program.DisplayName is null || program.DisplayName.Length > 160 || program.DisplayName.Any(char.IsControl))
                throw new Boundary("uac_chat_record_invalid");
        if (value.Programs.Select(program => program.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != value.Programs.Length)
            throw new Boundary("uac_chat_record_invalid");
    }
    internal static UacChatRecord ReduceEvent(UacChatRecord? prior, string sid, int session, string sessionHash,
        string hostKind, string turnId, string promptMac, string messageRef)
    {
        ValidateContext(sid, session, sessionHash, hostKind); Identifier(turnId, 256);
        if (!Hex(promptMac, 64, 64) || !Hex(messageRef, 32, 32)) throw new Boundary("uac_chat_event_rejected");
        if (prior is not null)
        {
            ValidateRecord(prior);
            if (prior.UserSid != sid || prior.Session != session || prior.SessionHash != sessionHash || prior.HostKind != hostKind)
                throw new Boundary("uac_chat_context_rejected");
            // UserPromptSubmit names the active turn. Steering while it runs
            // may submit a different message under the very same turn id.
            var latest = prior.Messages[^1];
            if (latest.TurnId == turnId && latest.PromptMac == promptMac)
            {
                return prior; // Only the latest exact pair can be a harmless duplicate.
            }
            if (prior.Messages.Any(message => message.MessageRef == messageRef)) throw new Boundary("uac_chat_event_rejected");
        }
        // No independent native event id distinguishes a late old delivery
        // from a real repeated restriction (A -> B -> A). Every nonlatest pair
        // suspends authority, including historical/evicted pairs; a fresh ref
        // never rolls back to an old reference or automatically restores grants.
        var messages = (prior?.Messages ?? []).Append(new UacChatMessage(turnId, messageRef, promptMac)).TakeLast(MessageLimit).ToArray();
        var result = new UacChatRecord(Schema, sid, session, sessionHash, hostKind, turnId, messageRef,
            checked((prior?.MessageRevision ?? 0) + 1), null, prior?.State ?? "not_requested", prior?.GrantId,
            prior?.GrantMessageRef, prior?.GrantTurnId, prior?.GrantPromptMac, prior?.ScopeKind, prior?.Programs ?? [], false, messages);
        ValidateRecord(result); return result;
    }
    internal static UacChatRecord ReduceDecision(UacChatRecord prior, string turnId, string messageRef, string decision,
        string? scopeKind, UacApplicationPermission[] programs, string newGrantId)
    {
        RequireRestrictionDecision(decision);
        ValidateRecord(prior); Identifier(turnId, 256);
        if (prior.TurnId != turnId || prior.MessageRef != messageRef) throw new Boundary("uac_chat_message_reference_stale");
        if (scopeKind is not null || programs.Length != 0) throw new Boundary("uac_chat_scope_rejected");
        if (prior.ReviewedRef == messageRef && (decision == "deny" && prior.State == "denied"
            || decision == "revoke" && prior.State == "revoked")) return prior;
        if (prior.ReviewedRef == messageRef && decision == "acknowledge" && !prior.GrantActive) return prior;
        UacChatRecord result;
        if (decision == "acknowledge") result = prior with { ReviewedRef = messageRef, GrantActive = false };
        else result = prior with { ReviewedRef = messageRef, State = decision == "deny" ? "denied" : "revoked",
            GrantId = null, GrantMessageRef = null, GrantTurnId = null, GrantPromptMac = null,
            ScopeKind = null, Programs = [], GrantActive = false };
        ValidateRecord(result); return result;
    }
    internal static byte[] Encode(UacChatRecord record, byte[] key)
    {
        ValidateRecord(record); var content = JsonSerializer.SerializeToUtf8Bytes(record);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new Envelope(Schema, record, Mac(key, "flower-uac-record-v1\0", content)));
        if (bytes.Length > ByteLimit) throw new Boundary("uac_chat_record_invalid");
        return bytes;
    }
    internal static UacChatRecord Decode(byte[] bytes, byte[] key, string sid, int session, string sessionHash)
    {
        static void Keys(JsonElement element, string[] fields)
        {
            if (element.ValueKind != JsonValueKind.Object || !element.EnumerateObject().Select(row => row.Name)
                .ToHashSet(StringComparer.Ordinal).SetEquals(fields)) throw new Boundary("uac_chat_record_invalid");
        }
        try
        {
            if (bytes.Length is < 1 or > ByteLimit) throw new Boundary("uac_chat_record_invalid");
            using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document);
            Keys(document.RootElement, ["Schema", "Record", "Mac"]);
            var record = document.RootElement.GetProperty("Record");
            Keys(record, ["Schema", "UserSid", "Session", "SessionHash", "HostKind", "TurnId", "MessageRef", "MessageRevision",
                "ReviewedRef", "State", "GrantId", "GrantMessageRef", "GrantTurnId", "GrantPromptMac", "ScopeKind", "Programs", "GrantActive", "Messages"]);
            foreach (var message in record.GetProperty("Messages").EnumerateArray()) Keys(message, ["TurnId", "MessageRef", "PromptMac"]);
            foreach (var program in record.GetProperty("Programs").EnumerateArray()) Keys(program, ["Path", "IdentityKind", "Identity", "DisplayName", "Enabled"]);
            var value = Protocol.Decode<Envelope>(document); ValidateRecord(value.Record);
            if (value.Schema != Schema || value.Record.UserSid != sid || value.Record.Session != session || value.Record.SessionHash != sessionHash
                || !Hex(value.Mac, 64, 64) || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(value.Mac),
                    Convert.FromHexString(Mac(key, "flower-uac-record-v1\0", JsonSerializer.SerializeToUtf8Bytes(value.Record)))))
                throw new Boundary("uac_chat_record_invalid");
            return value.Record;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or NullReferenceException or Boundary)
        { throw new Boundary("uac_chat_record_invalid"); }
    }
    internal static UacChatAuthorizationSnapshot MakeSnapshot(UacChatRecord? record, string sid, int session, string sessionHash,
        string revision, string policyRevision, long stopEpoch, bool stopped, string bootId, long capturedTick)
    {
        return new(sid, session, sessionHash, record?.HostKind ?? (DshMessageBinding.Known(sessionHash) ? "dsh-desktop" : "codex"), record?.TurnId, record?.MessageRef, record?.MessageRevision ?? 0,
            record?.ReviewedRef, record?.State ?? "missing", record?.GrantId, record?.GrantMessageRef, record?.GrantTurnId,
            record?.GrantPromptMac, record?.ScopeKind, record?.Programs.ToArray() ?? [],
            false, revision, policyRevision, stopEpoch, stopped, bootId, capturedTick);
    }
    internal static void RequireSameSnapshot(UacChatAuthorizationSnapshot expected, UacChatAuthorizationSnapshot current, long now)
    {
        if (expected.State == "missing" || current.State == "missing" || expected.Pending || current.Pending
            || expected.Stopped || current.Stopped || current.State is "denied" or "revoked"
            || !Hex(expected.Revision, 64, 64) || !Hex(expected.BootId, 32, 32)
            || expected.CapturedTick < 0 || expected.CapturedTick > now || now - expected.CapturedTick > SnapshotLifetimeMilliseconds)
            throw new Boundary("uac_chat_authority_not_current");
        // Recompare every typed field, not only caller-supplied state booleans.
        var oldValue = JsonSerializer.SerializeToUtf8Bytes(expected with { CapturedTick = 0, Changed = false });
        var newValue = JsonSerializer.SerializeToUtf8Bytes(current with { CapturedTick = 0, Changed = false });
        if (!oldValue.SequenceEqual(newValue)) throw new Boundary("uac_chat_authority_changed");
    }
}

internal static class UacChatAuthorizationTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Require(bool condition) { assertions++; if (!condition) throw new Boundary("uac_chat_selftest_failed"); }
        void Reject(Action action, string code)
        {
            assertions++;
            try { action(); } catch (Boundary error) when (error.Code == code) { return; }
            throw new Boundary("uac_chat_selftest_failed");
        }
        const string sid = "S-1-5-21-1-2-3-1001";
        string sessionHash = new('a', 64), digest = new('b', 64), firstRef = new('c', 32), secondRef = new('d', 32), grant = new('e', 32);
        var key = Enumerable.Range(0, 32).Select(index => (byte)index).ToArray();
        var program = new UacApplicationPermission(@"C:\Games\Launcher.exe", "sha256", new string('f', 64), "Launcher");
        UacChatRecord Event(UacChatRecord? prior, string turn, string messageRef) => UacChatAuthorization.ReduceEvent(prior, sid, 1, sessionHash, "codex", turn, digest, messageRef);
        UacChatRecord Decision(UacChatRecord prior, string decision, string? scope = null, UacApplicationPermission[]? programs = null)
            => UacChatAuthorization.ReduceDecision(prior, prior.TurnId, prior.MessageRef, decision, scope, programs ?? [], grant);
        // Construct old on-disk states explicitly. No production grant API is
        // used: these fixtures must remain readable but confer no authority.
        UacChatRecord LegacyGrant(UacChatRecord prior, string scope, UacApplicationPermission[]? programs = null)
            => prior with { ReviewedRef = prior.MessageRef, State = "allowed", GrantId = grant,
                GrantMessageRef = prior.MessageRef, GrantTurnId = prior.TurnId, GrantPromptMac = prior.Messages[^1].PromptMac,
                ScopeKind = scope, Programs = programs ?? [], GrantActive = true };
        UacChatAuthorizationSnapshot Snapshot(UacChatRecord? record) => UacChatAuthorization.MakeSnapshot(record, sid, 1, sessionHash,
            new string('1', 64), new string('2', 64), 7, false, new string('3', 32), 1000);
        var initial = Event(null, "turn1", firstRef);
        bool beforeWriteMarked = false;
        try { UacChatAuthorization.Decide(new BrokerPolicy { UserSid = sid }, 1, "invalid", "turn1", firstRef, "acknowledge"); }
        catch (Boundary error) when (error.Code == "uac_chat_context_rejected")
        { beforeWriteMarked = error.Data["PermissionWriteAttempted"] is false; }
        Require(beforeWriteMarked); // Rejected before any role, path or storage access.
        Require(Snapshot(initial).Pending);
        Require(!UacChatAuthorization.Evaluate(Snapshot(initial), program).SemanticVerified);
        Require(!UacChatAuthorization.Evaluate(Snapshot(null), null).ExplicitlyDenied);
        foreach (var decision in new[] { "allow", "keep" })
        {
            Reject(() => Decision(initial, decision, "chat"), "uac_semantic_expansion_removed");
            bool rejectedBeforeStorage = false;
            try { UacChatAuthorization.Decide(new BrokerPolicy { UserSid = sid }, 1, sessionHash, "turn1", firstRef, decision, "chat"); }
            catch (Boundary error) when (error.Code == "uac_semantic_expansion_removed")
            { rejectedBeforeStorage = error.Data["PermissionWriteAttempted"] is false; }
            Require(rejectedBeforeStorage);
        }
        Reject(() => Decision(initial, "yes"), "uac_chat_decision_rejected");
        Reject(() => UacChatAuthorization.ReduceDecision(initial, "other", firstRef, "acknowledge", null, [], grant), "uac_chat_message_reference_stale");
        Reject(() => UacChatAuthorization.ReduceDecision(initial, "turn1", secondRef, "acknowledge", null, [], grant), "uac_chat_message_reference_stale");
        var allowed = LegacyGrant(initial, "programs", [program]);
        var barrier = UacChatAuthorization.ReduceEvent(allowed, sid, 1, sessionHash, "codex", "turn1", new string('8', 64), new string('9', 32));
        var sameTextOldRecord = Event(barrier, "turn1", new string('0', 32));
        Require(Snapshot(barrier).Pending && !barrier.GrantActive);
        Require(Snapshot(sameTextOldRecord).Pending && !sameTextOldRecord.GrantActive);
        Require(sameTextOldRecord.MessageRef != allowed.MessageRef && sameTextOldRecord.GrantId == allowed.GrantId);
        Require(!Snapshot(allowed).GrantActive);
        Require(!UacChatAuthorization.Evaluate(Snapshot(allowed) with { GrantActive = true }, program).SemanticVerified);
        Require(!UacChatAuthorization.Evaluate(Snapshot(allowed), program).ScopeMatches);
        Require(!UacChatAuthorization.Evaluate(Snapshot(allowed), program with { Identity = digest }).ScopeMatches);
        Require(!UacChatAuthorization.Evaluate(Snapshot(allowed), program with { Path = @"C:\Games\Other.exe" }).ScopeMatches);
        Require(!UacChatAuthorization.Evaluate(Snapshot(allowed), program with { Path = @"c:\games\launcher.exe" }).ScopeMatches);
        Reject(() => Decision(allowed, "allow", "programs", [program]), "uac_semantic_expansion_removed");
        Reject(() => Decision(allowed, "allow", "chat"), "uac_semantic_expansion_removed");
        var pending = Event(allowed, "turn2", secondRef);
        Require(pending.GrantId == allowed.GrantId && !pending.GrantActive);
        Require(!UacChatAuthorization.Evaluate(Snapshot(pending), program).SemanticVerified);
        var historicalReplay = Event(pending, "turn1", new string('4', 32));
        Require(historicalReplay.MessageRevision == pending.MessageRevision + 1 && Snapshot(historicalReplay).Pending
            && !historicalReplay.GrantActive && historicalReplay.MessageRef != firstRef);
        var steering = UacChatAuthorization.ReduceEvent(allowed, sid, 1, sessionHash, "codex", "turn1", new string('5', 64), new string('6', 32));
        Require(steering.TurnId == allowed.TurnId && steering.MessageRevision == allowed.MessageRevision + 1);
        Require(steering.MessageRef != allowed.MessageRef && Snapshot(steering).Pending && !steering.GrantActive);
        Require(!UacChatAuthorization.Evaluate(Snapshot(steering), program).SemanticVerified);
        Require(steering.GrantId == allowed.GrantId && steering.GrantMessageRef == allowed.GrantMessageRef);
        Require(UacChatAuthorization.Decode(UacChatAuthorization.Encode(steering, key), key, sid, 1, sessionHash).Messages.SequenceEqual(steering.Messages));
        Reject(() => UacChatAuthorization.ReduceDecision(steering, "turn1", firstRef, "acknowledge", null, [], grant), "uac_chat_message_reference_stale");
        var steeringHistory = UacChatAuthorization.ReduceEvent(steering, sid, 1, sessionHash, "codex", "turn1", digest, new string('4', 32));
        Require(steeringHistory.MessageRevision == steering.MessageRevision + 1 && Snapshot(steeringHistory).Pending && !steeringHistory.GrantActive);
        Require(UacChatAuthorization.ReduceEvent(steering, sid, 1, sessionHash, "codex", "turn1", new string('5', 64), new string('8', 32)) == steering);
        var steeringDenied = Decision(steering, "deny");
        var deniedHistory = UacChatAuthorization.ReduceEvent(steeringDenied, sid, 1, sessionHash, "codex", "turn1", digest, new string('4', 32));
        Require(Snapshot(deniedHistory).Pending && deniedHistory.MessageRevision == steeringDenied.MessageRevision + 1
            && UacChatAuthorization.Evaluate(Snapshot(deniedHistory), program).ExplicitlyDenied);
        Require(UacChatAuthorization.Evaluate(Snapshot(steeringDenied), program).ExplicitlyDenied);
        var repeatedPair = steering with { MessageRevision = 3, Messages = [steering.Messages[0],
            steering.Messages[0] with { MessageRef = new string('0', 32) }, steering.Messages[1]] };
        Require(UacChatAuthorization.Decode(UacChatAuthorization.Encode(repeatedPair, key), key, sid, 1, sessionHash).Messages.Length == 3);
        var firstDenial = Decision(initial, "deny");
        var laterAllowance = LegacyGrant(UacChatAuthorization.ReduceEvent(firstDenial, sid, 1, sessionHash, "codex", "turn1",
            new string('5', 64), new string('6', 32)), "chat");
        Require(!UacChatAuthorization.Evaluate(Snapshot(laterAllowance), null).SemanticVerified);
        var repeatedDenial = Event(laterAllowance, "turn1", new string('8', 32));
        Require(Snapshot(repeatedDenial).Pending && repeatedDenial.MessageRevision == laterAllowance.MessageRevision + 1
            && !UacChatAuthorization.Evaluate(Snapshot(repeatedDenial), null).SemanticVerified);
        Require(UacChatAuthorization.Evaluate(Snapshot(Decision(repeatedDenial, "deny")), null).ExplicitlyDenied);
        Reject(() => UacChatAuthorization.ReduceEvent(pending, sid, 1, new string('0', 64), "codex", "turn3", digest, new string('6', 32)), "uac_chat_context_rejected");
        Reject(() => UacChatAuthorization.ReduceEvent(pending, sid, 1, sessionHash, "other", "turn3", digest, new string('6', 32)), "uac_chat_context_rejected");
        Reject(() => Decision(pending, "acknowledge", "chat"), "uac_chat_scope_rejected");
        Reject(() => Decision(pending, "keep"), "uac_semantic_expansion_removed");
        var kept = pending with { ReviewedRef = pending.MessageRef, GrantActive = true };
        Require(kept.GrantId == allowed.GrantId && kept.ScopeKind == "programs" && kept.Programs.SequenceEqual(allowed.Programs));
        Require(kept.GrantMessageRef == firstRef && kept.GrantTurnId == "turn1" && kept.GrantPromptMac == digest);
        Require(!UacChatAuthorization.Evaluate(Snapshot(kept), program).SemanticVerified);
        var acknowledged = Decision(pending, "acknowledge");
        Require(!Snapshot(acknowledged).Pending && !UacChatAuthorization.Evaluate(Snapshot(acknowledged), program).SemanticVerified);
        Reject(() => Decision(acknowledged, "keep"), "uac_semantic_expansion_removed");
        var denied = Decision(pending, "deny");
        Require(UacChatAuthorization.Evaluate(Snapshot(denied), program).ExplicitlyDenied && denied.GrantId is null);
        Require(Decision(denied, "deny") == denied);
        Require(UacChatAuthorization.Evaluate(Snapshot(Decision(denied, "acknowledge")), program).ExplicitlyDenied);
        Reject(() => Decision(denied, "allow", "chat"), "uac_semantic_expansion_removed");
        var third = Event(denied, "turn3", new string('7', 32));
        Reject(() => Decision(third, "keep"), "uac_semantic_expansion_removed");
        var broad = LegacyGrant(third, "chat");
        Require(!UacChatAuthorization.Evaluate(Snapshot(broad), null).ScopeMatches);
        var revoked = Decision(broad, "revoke");
        Require(UacChatAuthorization.Evaluate(Snapshot(revoked), null).ExplicitlyDenied);
        Require(Decision(revoked, "revoke") == revoked);
        var bytes = UacChatAuthorization.Encode(allowed, key);
        Require(!Encoding.UTF8.GetString(bytes).Contains("\"Arguments\"", StringComparison.Ordinal));
        Reject(() => UacChatAuthorization.Encode(allowed with { Programs = [program with { Arguments = "--unrepresented-scope" }] }, key), "uac_chat_record_invalid");
        var stopBefore = new SharedWriteGate.Status(false, 7, 7);
        var preparation = new UacChatDecisionPreparation(allowed, bytes, "policy", stopBefore);
        Reject(() => UacChatAuthorization.RequirePreparedState(preparation, allowed, bytes, "changed-policy", stopBefore, "allow"), "uac_semantic_expansion_removed");
        Reject(() => UacChatAuthorization.RequirePreparedState(preparation, allowed, bytes, "policy", stopBefore with { Stopped = true }, "keep"), "uac_semantic_expansion_removed");
        UacChatAuthorization.RequirePreparedState(preparation, allowed, bytes, "changed-policy", stopBefore with { Stopped = true }, "deny"); assertions++;
        using (var phaseMutex = new Mutex())
        {
            bool inspectorYieldedToNewMessage = false;
            var phaseRecord = allowed; var phaseBytes = bytes;
            Reject(() => UacChatAuthorization.DecideInPhases(
                () => { phaseMutex.WaitOne(); try { return preparation; } finally { phaseMutex.ReleaseMutex(); } },
                () => {
                    // The actual kernel mutex is separate from production.
                    // A new-message writer must run while inspection is busy.
                    inspectorYieldedToNewMessage = Task.Run(() => {
                        if (!phaseMutex.WaitOne(2000)) return false;
                        try { phaseRecord = steering; phaseBytes = UacChatAuthorization.Encode(steering, key); return true; }
                        finally { phaseMutex.ReleaseMutex(); }
                    }).GetAwaiter().GetResult();
                    return new[] { program };
                },
                (prepared, inspected) => {
                    phaseMutex.WaitOne();
                    try {
                        UacChatAuthorization.RequirePreparedState(prepared, phaseRecord, phaseBytes, "policy", stopBefore, "acknowledge");
                        return inspected.Length;
                    }
                    finally { phaseMutex.ReleaseMutex(); }
                }), "uac_chat_authority_changed");
            Require(inspectorYieldedToNewMessage);
        }
        Require(UacChatAuthorization.Decode(bytes, key, sid, 1, sessionHash).Programs.SequenceEqual(allowed.Programs));
        Require(!Encoding.UTF8.GetString(bytes).Contains("allow=true", StringComparison.Ordinal));
        Reject(() => UacChatAuthorization.Decode(bytes, Enumerable.Repeat((byte)32, 32).ToArray(), sid, 1, sessionHash), "uac_chat_record_invalid");
        Reject(() => UacChatAuthorization.Decode(bytes, key, sid, 2, sessionHash), "uac_chat_record_invalid");
        var tampered = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\"State\":\"allowed\"", "\"State\":\"denied\"", StringComparison.Ordinal));
        Reject(() => UacChatAuthorization.Decode(tampered, key, sid, 1, sessionHash), "uac_chat_record_invalid");
        var validTamper = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace(new string('f', 64), new string('9', 64), StringComparison.Ordinal));
        Reject(() => UacChatAuthorization.Decode(validTamper, key, sid, 1, sessionHash), "uac_chat_record_invalid");
        var unknown = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\"Schema\":1,", "\"Unexpected\":true,\"Schema\":1,", StringComparison.Ordinal));
        Reject(() => UacChatAuthorization.Decode(unknown, key, sid, 1, sessionHash), "uac_chat_record_invalid");
        var duplicate = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes).Replace("\"Schema\":1,", "\"Schema\":1,\"Schema\":1,", StringComparison.Ordinal));
        Reject(() => UacChatAuthorization.Decode(duplicate, key, sid, 1, sessionHash), "uac_chat_record_invalid");
        Require(UacChatAuthorization.Mac(key, "prompt\0", Encoding.UTF8.GetBytes(digest)) != digest);
        Require(UacChatAuthorization.Mac(key, "prompt\0", Encoding.UTF8.GetBytes(digest)) != UacChatAuthorization.Mac(key, "record\0", Encoding.UTF8.GetBytes(digest)));
        var snapshot = Snapshot(allowed);
        Require(!snapshot.Changed);
        UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot with { CapturedTick = 2000 }, 2000); assertions++;
        UacChatAuthorization.RequireSameSnapshot(snapshot with { Changed = true }, snapshot, 2000); assertions++;
        UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot with { Changed = true }, 2000); assertions++;
        Reject(() => UacChatAuthorization.RequireSameSnapshot(Snapshot(null), Snapshot(null), 2000), "uac_chat_authority_not_current");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(Snapshot(pending), Snapshot(pending), 2000), "uac_chat_authority_not_current");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot, 1000 + UacChatAuthorization.SnapshotLifetimeMilliseconds + 1), "uac_chat_authority_not_current");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot with { PolicyRevision = "other" }, 2000), "uac_chat_authority_changed");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot with { StopEpoch = 8 }, 2000), "uac_chat_authority_changed");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot with { Stopped = true }, 2000), "uac_chat_authority_not_current");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(snapshot, snapshot with { BootId = new string('8', 32) }, 2000), "uac_chat_authority_changed");
        Reject(() => UacChatAuthorization.RequireSameSnapshot(snapshot with { ScopeKind = "chat", Programs = [] }, snapshot, 2000), "uac_chat_authority_changed");
        Require(!UacChatAuthorization.Evaluate(snapshot with { Stopped = true }, program).SemanticVerified);
        Reject(() => UacChatAuthorization.RequireDecisionStop("allow", true), "uac_semantic_expansion_removed");
        Reject(() => UacChatAuthorization.RequireDecisionStop("keep", true), "uac_semantic_expansion_removed");
        foreach (var decision in new[] { "acknowledge", "deny", "revoke" })
        { UacChatAuthorization.RequireDecisionStop(decision, true); assertions++; }
        var current = broad;
        for (int index = 0; index < 150; index++) current = Event(current, "extra" + index, index.ToString("x32", CultureInfo.InvariantCulture));
        Require(current.Messages.Length == 128 && current.GrantId == broad.GrantId && Snapshot(current).Pending);
        Require(current.GrantMessageRef == broad.GrantMessageRef && current.GrantTurnId == broad.GrantTurnId);
        Reject(() => Decision(current, "keep"), "uac_semantic_expansion_removed");
        var activeAfterRing = current with { ReviewedRef = current.MessageRef, GrantActive = true };
        Require(!UacChatAuthorization.Evaluate(Snapshot(activeAfterRing), null).SemanticVerified);
        Require(!activeAfterRing.Messages.Any(message => message.TurnId == "turn1" && message.PromptMac == digest));
        var expiredReplay = Event(activeAfterRing, "turn1", new string('9', 32));
        Require(expiredReplay.MessageRevision == activeAfterRing.MessageRevision + 1 && Snapshot(expiredReplay).Pending);
        Require(expiredReplay.GrantId == activeAfterRing.GrantId && !expiredReplay.GrantActive);
        Require(!UacChatAuthorization.Evaluate(Snapshot(expiredReplay), null).SemanticVerified);
        Reject(() => UacChatAuthorization.ReduceDecision(expiredReplay, "turn1", firstRef, "acknowledge", null, [], grant), "uac_chat_message_reference_stale");
        var expiredDenialReplay = Event(Decision(activeAfterRing, "revoke"), "turn1", new string('9', 32));
        Require(Snapshot(expiredDenialReplay).Pending && expiredDenialReplay.GrantId is null
            && UacChatAuthorization.Evaluate(Snapshot(expiredDenialReplay), null).ExplicitlyDenied);
        Reject(() => Decision(expiredDenialReplay, "keep"), "uac_semantic_expansion_removed");
        return new { assertions, productionStorageAccessed = false, nativeInputExecuted = false, systemExecuted = false, runtimeAccepted = false };
    }
}
