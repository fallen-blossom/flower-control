using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record WorkAuthorityQuery(string Phase, string Command, string TaskId, string ConnectionId,
    string WorkId, AuditThread Thread, string Goal = "", string Constraints = "", long ExpectedRevision = 0,
    DshCallSourceGuard? DshSource = null);
internal sealed record WorkAuthorityRecord(int Schema, string WorkId, long Revision, string HostKind, string ThreadId,
    string Goal, string Constraints, string State, string Lifetime, string Issuer, string CreatedUtc, string PolicyRevision,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? DelegationId = null,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? MessageDigest = null);

// No allow/keep prompt parser and no model-supplied approval boolean. Approval
// is either local confirmation or a locally selected, protected delegation.
// The model still judges task scope; no boolean supplied by it mints a grant.
internal static class WorkAuthority
{
    private static readonly object Gate = new();
    private sealed record Index(string State, string WorkId, long Revision, string RecordSha256, AuditStamp? Audit);
    private sealed record Verified(WorkAuthorityRecord Record, byte[] IndexBytes);
    private static readonly Dictionary<string, Verified> verified = new();
    [ThreadStatic] private static int lockDepth;
    [ThreadStatic] private static FileStream? fileLock;
    [ThreadStatic] private static string? lockedRoot;
    private static int prompting;
    private sealed class Guard : IDisposable
    {
        private bool held;
        internal Guard(string root)
        {
            Monitor.Enter(Gate);
            try
            {
                if (lockDepth > 0 && lockedRoot != root) throw new Boundary("work_authority_lock_scope_changed");
                if (lockDepth == 0)
                {
                    string path = Path.Combine(root, "writer.lock");
                    if (!File.Exists(path)) { try { AuditFiles.WriteNew(path, []); } catch (IOException) { } }
                    AuditFiles.Check(path, false); long until = Environment.TickCount64 + 1000;
                    while (true)
                    {
                        try { fileLock = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None); break; }
                        catch (IOException error) when ((error.HResult & 0xffff) is 32 or 33)
                        { if (Environment.TickCount64 >= until) throw new Boundary("work_authority_busy"); Thread.Sleep(20); }
                    }
                    lockedRoot = root;
                }
                ++lockDepth; held = true;
            }
            catch { Monitor.Exit(Gate); throw; }
        }
        public void Dispose()
        {
            if (!held) return; held = false;
            try { if (--lockDepth == 0) { fileLock?.Dispose(); fileLock = null; lockedRoot = null; } }
            finally { Monitor.Exit(Gate); }
        }
    }
    private static bool WorkId(string value) => Guid.TryParseExact(value, "N", out _);
    private static bool Description(string value, int maximum, bool required) => value.Length <= maximum
        && (!required || !string.IsNullOrWhiteSpace(value)) && !value.Any(c => char.IsControl(c) && c is not ('\n' or '\r' or '\t'));
    private static string Root(BrokerPolicy policy, Peer own)
    {
        _ = ExecutionAudit.Open(policy, own);
        string install = InstallationLocation.Current().ProgramRoot;
        string root = Path.Combine(install, "work-authority"); AuditFiles.EnsureDirectory(root);
        root = Path.Combine(root, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(own.User + "|" + own.Session))).ToLowerInvariant()); AuditFiles.EnsureDirectory(root); return root;
    }
    private static WorkAuthorityRecord? Latest(ExecutionAudit audit, string workId) => Latest(audit, workId, out _);
    private static WorkAuthorityRecord? Latest(ExecutionAudit audit, string workId, out AuditStamp? proof)
    {
        proof = null;
        using var document = JsonSerializer.SerializeToDocument(audit.History(null, 1, kind: "work_authority", requestId: workId));
        var root = document.RootElement;
        if (root.GetProperty("History").GetProperty("Integrity").GetString() != "verified_local_chain"
            || !root.GetProperty("RecoveryNotesVerified").GetBoolean() || !root.GetProperty("RecoveryPreservationVerified").GetBoolean())
            throw new Boundary("work_authority_audit_unverified");
        var events = root.GetProperty("History").GetProperty("Events");
        if (events.GetArrayLength() == 0) return null;
        var value = events[0].GetProperty("Event").GetProperty("Evidence").Deserialize<WorkAuthorityRecord>()
            ?? throw new Boundary("work_authority_record_invalid");
        bool local = value.Schema == 1 && value.Issuer == "local_high_confirmation" && value.DelegationId is null && value.MessageDigest is null;
        bool delegated = value.Schema == 2 && value.Issuer == "local_ai_delegation"
            && Guid.TryParseExact(value.DelegationId, "N", out _) && value.MessageDigest is not null && AdminProgramLaunch.Digest(value.MessageDigest);
        if ((!local && !delegated) || value.WorkId != workId || value.Revision <= 0 || value.Lifetime != "work"
            || value.State is not ("pending" or "active" or "denied" or "revoked" or "closed"))
            throw new Boundary("work_authority_record_invalid");
        proof = new AuditStamp(root.GetProperty("History").GetProperty("StreamId").GetString()!,
            events[0].GetProperty("Sequence").GetInt64(), events[0].GetProperty("Hash").GetString()!);
        return value;
    }
    private static void Owner(WorkAuthorityRecord record, AuditThread thread)
    {
        if (record.HostKind != thread.HostKind || record.ThreadId != thread.ThreadId) throw new Boundary("work_authority_other_thread");
    }
    private static bool Revoked(string root, string workId)
    {
        string path = Path.Combine(root, workId + ".revoked");
        if (!File.Exists(path)) return false;
        AuditFiles.Check(path, false); return true;
    }
    private static void RequireTier(UserPermissionSettings settings)
    {
        if (!UserPermissions.Effective(settings).AdminLaunchEnabled) throw new Boundary("program_launch_disabled");
    }
    private static WorkAuthorityRecord Pending(UserPermissionSettings settings, Peer own, WorkAuthorityQuery query)
    {
        if (settings.AdminLaunchMode != "semantic")
            return new(1, query.WorkId, 1, query.Thread.HostKind, query.Thread.ThreadId,
                query.Goal, query.Constraints, "pending", "work", "local_high_confirmation", DateTimeOffset.UtcNow.ToString("O"), settings.Revision);
        var delegation = SemanticDelegation.Require(settings, own.User, query.Thread);
        var message = SemanticWorkSource.Current(query.Thread);
        return new(2, query.WorkId, 1, query.Thread.HostKind, query.Thread.ThreadId,
            query.Goal, query.Constraints, "pending", "work", "local_ai_delegation", DateTimeOffset.UtcNow.ToString("O"),
            settings.Revision, delegation.Id, message.EventDigest);
    }
    private static void RequireDelegation(WorkAuthorityRecord record, UserPermissionSettings settings, Peer own, AuditThread thread)
    {
        if (record.Issuer != "local_ai_delegation") return;
        var delegation = SemanticDelegation.Require(settings, own.User, thread);
        if (record.DelegationId != delegation.Id || record.PolicyRevision != settings.Revision)
            throw new Boundary("work_authority_delegation_changed");
        if (SemanticWorkSource.Current(thread).EventDigest != record.MessageDigest)
            throw new Boundary("work_authority_new_message_requires_prepare");
    }
    private static string IndexPath(string root, string workId) => Path.Combine(root, workId + ".index.json");
    private static string RecordHash(WorkAuthorityRecord value) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(value))).ToLowerInvariant();
    private static byte[] ReadIndex(string root, string workId)
    {
        string path = IndexPath(root, workId); AuditFiles.Check(path, false);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 8192) throw new Boundary("work_authority_index_invalid");
        var bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes); return bytes;
    }
    private static void WriteIndex(string root, Index value)
    {
        string path = IndexPath(root, value.WorkId), pending = path + "." + Guid.NewGuid().ToString("N") + ".pending";
        if (File.Exists(path)) AuditFiles.Check(path, false);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value); AuditFiles.WriteNew(pending, bytes); File.Move(pending, path, true);
        if (!ReadIndex(root, value.WorkId).SequenceEqual(bytes)) throw new Boundary("work_authority_index_unconfirmed");
    }
    private static AuditStamp Save(ExecutionAudit audit, string root, WorkAuthorityQuery query, WorkAuthorityRecord value)
        => DshCallSource.Dispatch(() =>
    {
        // Invalidate cached permission before changing authoritative history.
        // A crash mid-commit leaves updating, which never authorizes execution.
        string recordHash = RecordHash(value);
        WriteIndex(root, new Index("updating", value.WorkId, value.Revision, recordHash, null));
        var stamp = audit.Append(new AuditEvent("work_authority", query.TaskId, value.WorkId, value.State,
            Thread: query.Thread, Evidence: value));
        WriteIndex(root, new Index("committed", value.WorkId, value.Revision, recordHash, stamp));
        verified.Remove(IndexPath(root, value.WorkId));
        return stamp;
    });
    private static object View(string root, Peer own, BrokerState core, WorkAuthorityRecord record, AuditStamp? proof, bool? approved = null, string? reason = null)
    {
        bool committed = false;
        try
        {
            var index = JsonSerializer.Deserialize<Index>(ReadIndex(root, record.WorkId));
            committed = proof is not null && index is not null && index.State == "committed" && index.WorkId == record.WorkId
                && index.Revision == record.Revision && index.RecordSha256 == RecordHash(record) && index.Audit == proof;
        }
        catch (Exception) { /* A readable record is not proof of a committed grant. */ }
        bool usable = committed && record.State == "active";
        if (usable)
        {
            try
            {
                var settings = UserPermissions.Read(); RequireTier(settings);
                RequireDelegation(record, settings, own, new(record.HostKind, record.ThreadId));
                if (core.IsPaused || core.Shutdown.IsCancellationRequested)
                    throw new Boundary("work_authority_source_or_stop_changed");
            }
            catch (Boundary error)
            {
                // Preserve committed history if steering/policy/Stop changed
                // during audit I/O, but do not publish it as current approval.
                usable = false; reason = error.Code;
                if (approved == true) approved = false;
            }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
            {
                usable = false; reason = "work_authority_current_context_unavailable";
            }
        }
        if (!usable && approved == true) approved = false;
        if (!committed) reason = "work_authority_commit_unconfirmed";
        return new { Phase = "work_authority", Authority = record, State = committed ? record.State : "commit_unconfirmed",
            ExecutionDenied = !usable, Approved = approved, Reason = reason };
    }
    internal static object Handle(BrokerPolicy policy, Peer own, Peer source, WorkAuthorityQuery query, string connectionId, BrokerState core,
        Func<bool> connectionAlive)
    {
        if (query.Command == "source_status")
        {
            if (query.Phase != "work_authority" || query.ConnectionId != connectionId || !AdminProgramLaunch.Id(query.TaskId)
                || query.Thread is null || query.WorkId != "" || query.Goal != "" || query.Constraints != "" || query.ExpectedRevision != 0)
                throw new Boundary("work_authority_request_invalid");
            ExecutionAudit.ValidateThread(query.Thread);
            string? delegationReason = null;
            try { _ = SemanticDelegation.Require(UserPermissions.Read(), own.User, query.Thread); }
            catch (Exception error) { delegationReason = Program.Code(error); }
            object message;
            if (query.Thread.HostKind == "codex")
                message = UacTranscriptBinding.InspectWorkSource(UacTranscriptBinding.SessionHash(query.Thread.ThreadId));
            else
            {
                string? reason = null;
                try { _ = SemanticWorkSource.Current(query.Thread); }
                catch (Exception error) { reason = Program.Code(error); }
                message = new { SourceReady = reason is null, Reason = reason };
            }
            return new { Phase = "work_authority", State = "source_status", ReadOnly = true, AuthorityCreated = false,
                DelegationAvailable = delegationReason is null, DelegationReason = delegationReason, Paused = core.IsPaused, MessageSource = message };
        }
        if (query.Phase != "work_authority" || query.ConnectionId != connectionId || !AdminProgramLaunch.Id(query.TaskId)
            || !WorkId(query.WorkId) || query.Thread is null || query.Thread.HostKind is not ("codex" or "claude-code" or "dsh-desktop")
            || query.Command is not ("prepare" or "status" or "amend" or "revoke" or "close" or "recover")
            || !Description(query.Goal, 1200, query.Command is "prepare" or "amend") || !Description(query.Constraints, 4000, false))
            throw new Boundary("work_authority_request_invalid");
        ExecutionAudit.ValidateThread(query.Thread);
        string root = Root(policy, own); var audit = ExecutionAudit.Open(policy, own);
        string ownerPath = Path.Combine(root, query.WorkId + ".owner.json");
        WorkAuthorityRecord? prior;
        AuditStamp? priorProof = null;
        using (new Guard(root))
        {
            // Owner metadata is immutable and private. It keeps revocation
            // possible when the audit chain cannot currently be read.
            if (File.Exists(ownerPath))
            {
                AuditFiles.Check(ownerPath, false);
                using var bytes = new FileStream(ownerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (bytes.Length > 8192) throw new Boundary("work_authority_owner_invalid");
                var owner = JsonSerializer.Deserialize<AuditThread>(bytes) ?? throw new Boundary("work_authority_owner_invalid");
                if (owner.HostKind != query.Thread.HostKind || owner.ThreadId != query.Thread.ThreadId)
                    throw new Boundary("work_authority_other_thread");
            }
            else if (query.Command != "prepare") throw new Boundary("work_authority_unknown");
            if (query.Command is "revoke" or "close")
            {
                string marker = Path.Combine(root, query.WorkId + ".revoked");
                if (!File.Exists(marker)) AuditFiles.WriteNew(marker, JsonSerializer.SerializeToUtf8Bytes(new { query.WorkId, query.Command, Utc = DateTimeOffset.UtcNow.ToString("O") }));
                string closed = Path.Combine(root, query.WorkId + ".closed");
                if (query.Command == "close" && !File.Exists(closed)) AuditFiles.WriteNew(closed, JsonSerializer.SerializeToUtf8Bytes(new { query.WorkId, State = "closed" }));
                string effectiveState = File.Exists(closed) ? "closed" : "revoked";
                string? warning = null;
                try
                {
                    prior = Latest(audit, query.WorkId);
                    if (prior is not null)
                    {
                        Owner(prior, query.Thread);
                        Save(audit, root, query, prior with { Revision = checked(prior.Revision + 1), State = effectiveState });
                    }
                }
                catch (Exception error) { warning = Program.Code(error); }
                return new { Phase = "work_authority", query.WorkId, State = effectiveState,
                    ExecutionDenied = true, AuditWarning = warning, RunningProcessesTerminated = false, BusinessComplete = false };
            }
            if (Revoked(root, query.WorkId))
            {
                string state = "revoked";
                using (var marker = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, query.WorkId + ".revoked"))))
                    if (marker.RootElement.GetProperty("Command").GetString() == "close") state = "closed";
                if (File.Exists(Path.Combine(root, query.WorkId + ".closed")))
                { AuditFiles.Check(Path.Combine(root, query.WorkId + ".closed"), false); state = "closed"; }
                WorkAuthorityRecord? recorded = null; string? warning = null;
                try { recorded = Latest(audit, query.WorkId); } catch (Exception error) { warning = Program.Code(error); }
                return new { Phase = "work_authority", query.WorkId, State = state, RecordedAuthority = recorded, ExecutionDenied = true, AuditWarning = warning };
            }
            if (!File.Exists(ownerPath))
            {
                RequireTier(UserPermissions.Read());
                AuditFiles.WriteNew(ownerPath, JsonSerializer.SerializeToUtf8Bytes(query.Thread));
                prior = Pending(UserPermissions.Read(), own, query);
                priorProof = Save(audit, root, query, prior);
            }
            else
            {
                if (query.Command == "prepare")
                    audit.Append(new AuditEvent("work_authority_request", query.TaskId, query.WorkId, "requested", Thread: query.Thread));
                prior = Latest(audit, query.WorkId, out priorProof);
                if (prior is null)
                {
                    // Owner publication may have completed before the first
                    // pending event. No active event means no prior approval.
                    if (query.Command != "prepare") throw new Boundary("work_authority_original_record_missing");
                    RequireTier(UserPermissions.Read());
                    prior = Pending(UserPermissions.Read(), own, query);
                    priorProof = Save(audit, root, query, prior);
                }
            }
            Owner(prior, query.Thread);
            if (query.Command == "recover")
            {
                var index = JsonSerializer.Deserialize<Index>(ReadIndex(root, query.WorkId)) ?? throw new Boundary("work_authority_index_invalid");
                if (priorProof is null || index.WorkId != query.WorkId || index.Revision != prior.Revision || index.RecordSha256 != RecordHash(prior))
                    throw new Boundary("work_authority_update_not_recorded");
                if (index.State == "updating" && index.Audit is null)
                {
                    DshCallSource.Dispatch(() =>
                    {
                        audit.Append(new AuditEvent("work_authority_commit_recovered", query.TaskId, query.WorkId, prior.State,
                            Thread: query.Thread, Evidence: new { prior.Revision, Proof = priorProof }));
                        WriteIndex(root, index with { State = "committed", Audit = priorProof });
                        return true;
                    });
                }
                else if (index.State != "committed" || index.Audit != priorProof) throw new Boundary("work_authority_commit_unconfirmed");
                return View(root, own, core, prior, priorProof);
            }
            if (query.Command == "status")
                return View(root, own, core, prior, priorProof);
            if (query.Command == "prepare" && (prior.Goal != query.Goal || prior.Constraints != query.Constraints))
                throw new Boundary("work_authority_descriptor_drift");
            if (prior.Issuer == "local_ai_delegation" && query.Command is "prepare" or "amend")
            {
                if (prior.State is not ("pending" or "active")) return View(root, own, core, prior, priorProof);
                if (query.Command == "amend" && (prior.State != "active" || query.ExpectedRevision != prior.Revision))
                    throw new Boundary("work_authority_revision_changed");
                var settings = UserPermissions.Read();
                var delegation = SemanticDelegation.Require(settings, own.User, query.Thread);
                if (delegation.Id != prior.DelegationId) throw new Boundary("work_authority_delegation_changed");
                var message = SemanticWorkSource.Current(query.Thread);
                // A disable/re-enable or settings change cannot silently revive
                // an old active work. Re-evaluation needs a fresh real message.
                if (prior.State == "active" && settings.Revision != prior.PolicyRevision && message.EventDigest == prior.MessageDigest)
                    throw new Boundary("work_authority_new_message_requires_prepare");
                if (core.IsPaused || core.Shutdown.IsCancellationRequested || !SourceIdentityCurrent(source) || !connectionAlive())
                    throw new Boundary("work_authority_source_or_stop_changed");
                if (SemanticWorkSource.Current(query.Thread) != message) throw new Boundary("work_authority_message_changed");
                // Approval publication and native new-message invalidation use
                // the same boundary as final process creation. A pre-save check
                // alone could publish an old active approval after new steering.
                return SemanticWorkSource.Dispatch(query.Thread, message.EventDigest, () =>
                {
                    var current = UserPermissions.Read();
                    var currentDelegation = SemanticDelegation.Require(current, own.User, query.Thread);
                    if (current.Revision != settings.Revision || currentDelegation.Id != delegation.Id)
                        throw new Boundary("work_authority_delegation_changed");
                    if (core.IsPaused || core.Shutdown.IsCancellationRequested || !SourceIdentityCurrent(source) || !connectionAlive())
                        throw new Boundary("work_authority_source_or_stop_changed");
                    if (query.Command == "prepare" && prior.State == "active" && prior.PolicyRevision == settings.Revision
                        && prior.MessageDigest == message.EventDigest) return View(root, own, core, prior, priorProof);
                    var delegated = prior with { Revision = checked(prior.Revision + 1), State = "active", Goal = query.Goal,
                        Constraints = query.Constraints, PolicyRevision = settings.Revision, MessageDigest = message.EventDigest };
                    var proof = Save(audit, root, query, delegated);
                    return View(root, own, core, delegated, proof, true, "local_ai_delegation");
                });
            }
            if (query.Command == "prepare" && prior.State != "pending") return View(root, own, core, prior, priorProof);
            if (query.Command == "amend" && (prior.State != "active" || query.ExpectedRevision != prior.Revision))
                throw new Boundary("work_authority_revision_changed");
        }
        if (Interlocked.CompareExchange(ref prompting, 1, 0) != 0) throw new Boundary("work_authority_confirmation_busy");
        try
        {
            var candidate = prior with { Goal = query.Goal, Constraints = query.Constraints };
            audit.Append(new AuditEvent("work_authority_confirmation", query.TaskId, query.WorkId, "requested", Thread: query.Thread,
                Evidence: new { prior.Revision, query.Command }), candidate);
            var decision = WorkAuthorityWindow.Confirm(candidate, query.Thread, () => core.IsPaused || core.Shutdown.IsCancellationRequested
                || !SourceIdentityCurrent(source) || !connectionAlive() || Revoked(root, query.WorkId), query.Command == "amend" ? prior : null);
            bool consent = decision.Approved;
            using (new Guard(root))
            {
                if (Revoked(root, query.WorkId)) throw new Boundary("work_authority_revoked");
                var current = Latest(audit, query.WorkId) ?? throw new Boundary("work_authority_original_record_missing");
                if (current.Revision != prior.Revision || current.State != prior.State) throw new Boundary("work_authority_revision_changed");
                if (consent)
                {
                    RequireTier(UserPermissions.Read());
                    if (core.IsPaused || !SourceIdentityCurrent(source) || !connectionAlive()) throw new Boundary("work_authority_source_or_stop_changed");
                }
                // Rejecting an amendment preserves the old authority; it does
                // not replace an accepted scope with an unapproved candidate.
                var final = consent ? candidate with { Revision = checked(prior.Revision + 1), State = "active", PolicyRevision = UserPermissions.Read().Revision }
                    : query.Command == "amend" ? prior with { Revision = checked(prior.Revision + 1) }
                    : prior with { Revision = checked(prior.Revision + 1), State = "denied" };
                var proof = Save(audit, root, query, final);
                audit.Append(new AuditEvent("work_authority_confirmation", query.TaskId, query.WorkId, consent ? "approved" : "not_approved",
                    Reason: decision.Reason, Thread: query.Thread, Evidence: new { PreviousRevision = prior.Revision, final.Revision, query.Command }));
                return View(root, own, core, final, proof, consent, decision.Reason);
            }
        }
        finally { Volatile.Write(ref prompting, 0); }
    }
    internal static bool SourceIdentityCurrent(Peer source)
    {
        // BrokerHost supplies admission.Peer, including its executable digest.
        // Compare the same representation; omitting the digest always cancels
        // an otherwise live caller on the confirmation window's first tick.
        try { return Native.Process(source.Pid).Identity == source; } catch { return false; }
    }
    // Source metadata recovery only. This does not call Current (the cache is
    // precisely what is missing), write approval, populate verified grants or
    // clear Stop. Normal Require/Dispatch still run after the Hook returns.
    internal static string RestoreSourceAnchor(BrokerPolicy policy, Peer own, AuditThread thread, string workId)
    {
        if (thread.HostKind != "codex" || !WorkId(workId)) throw new Boundary("work_authority_required");
        ExecutionAudit.ValidateThread(thread);
        string root = Root(policy, own);
        using (new Guard(root))
        {
            if (Revoked(root, workId)) throw new Boundary("work_authority_revoked");
            string ownerPath = Path.Combine(root, workId + ".owner.json");
            AuditFiles.Check(ownerPath, false);
            using (var ownerFile = new FileStream(ownerPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (ownerFile.Length > 8192) throw new Boundary("work_authority_owner_invalid");
                var owner = JsonSerializer.Deserialize<AuditThread>(ownerFile) ?? throw new Boundary("work_authority_owner_invalid");
                if (owner.HostKind != thread.HostKind || owner.ThreadId != thread.ThreadId) throw new Boundary("work_authority_other_thread");
            }
            var grant = Latest(ExecutionAudit.Open(policy, own), workId, out var proof) ?? throw new Boundary("work_authority_unknown");
            Owner(grant, thread);
            if (grant.State != "active" || grant.Schema != 2 || grant.Issuer != "local_ai_delegation"
                || grant.MessageDigest is null) throw new Boundary("work_authority_inactive_or_changed");
            var index = JsonSerializer.Deserialize<Index>(ReadIndex(root, workId)) ?? throw new Boundary("work_authority_index_invalid");
            if (index.State != "committed" || index.WorkId != workId || index.Revision != grant.Revision
                || index.RecordSha256 != RecordHash(grant) || index.Audit != proof)
                throw new Boundary("work_authority_commit_unconfirmed");
            var settings = UserPermissions.Read(); RequireTier(settings);
            var delegation = SemanticDelegation.Require(settings, own.User, thread);
            if (grant.DelegationId != delegation.Id || grant.PolicyRevision != settings.Revision)
                throw new Boundary("work_authority_delegation_changed");
            return grant.MessageDigest;
        }
    }
    internal static WorkAuthorityRecord Require(BrokerPolicy policy, Peer own, AuditThread? thread, string workId, long? revision = null)
    {
        if (thread is null || !WorkId(workId)) throw new Boundary("work_authority_required");
        string root = Root(policy, own);
        using (new Guard(root))
        {
            if (Revoked(root, workId)) throw new Boundary("work_authority_revoked");
            string ownerPath = Path.Combine(root, workId + ".owner.json");
            AuditFiles.Check(ownerPath, false);
            using (var ownerFile = new FileStream(ownerPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (ownerFile.Length > 8192) throw new Boundary("work_authority_owner_invalid");
                var owner = JsonSerializer.Deserialize<AuditThread>(ownerFile) ?? throw new Boundary("work_authority_owner_invalid");
                if (owner.HostKind != thread.HostKind || owner.ThreadId != thread.ThreadId) throw new Boundary("work_authority_other_thread");
            }
            var grant = Latest(ExecutionAudit.Open(policy, own), workId, out var proof) ?? throw new Boundary("work_authority_unknown");
            Owner(grant, thread);
            if (grant.State != "active" || revision is not null && revision != grant.Revision) throw new Boundary("work_authority_inactive_or_changed");
            var bytes = ReadIndex(root, workId);
            var index = JsonSerializer.Deserialize<Index>(bytes) ?? throw new Boundary("work_authority_index_invalid");
            if (index.State != "committed" || index.WorkId != workId || index.Revision != grant.Revision
                || index.RecordSha256 != RecordHash(grant) || index.Audit != proof)
                throw new Boundary("work_authority_commit_unconfirmed");
            verified[IndexPath(root, workId)] = new Verified(grant, bytes);
            var settings = UserPermissions.Read(); RequireTier(settings); RequireDelegation(grant, settings, own, thread); return grant;
        }
    }
    internal static T Dispatch<T>(BrokerPolicy policy, Peer own, AuditThread? thread, string workId, long revision, Func<T> create)
    {
        // Revocation acknowledges only after any earlier admitted creation has
        // returned; it cannot claim to retract an already issued Windows token.
        string root = Root(policy, own); using var guard = new Guard(root);
        if (thread is null || Revoked(root, workId) || !verified.TryGetValue(IndexPath(root, workId), out var cached)
            || cached.Record.Revision != revision || cached.Record.State != "active"
            || !ReadIndex(root, workId).SequenceEqual(cached.IndexBytes)) throw new Boundary("work_authority_inactive_or_changed");
        Owner(cached.Record, thread); AuditFiles.Check(Path.Combine(root, workId + ".owner.json"), false);
        var settings = UserPermissions.Read(); RequireTier(settings); RequireDelegation(cached.Record, settings, own, thread);
        return cached.Record.Issuer == "local_ai_delegation"
            ? SemanticWorkSource.Dispatch(thread, cached.Record.MessageDigest!, create) : DshCallSource.Dispatch(create);
    }
}

internal sealed record WorkAuthorityDecision(bool Approved, string Reason);
internal static class WorkAuthorityWindow
{
    private delegate IntPtr Procedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Class
    { internal uint Size, Style; internal IntPtr Proc; internal int Extra, WindowExtra; internal IntPtr Instance, Icon, Cursor, Background; internal string? Menu; internal string Name; internal IntPtr SmallIcon; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern ushort RegisterClassExW(ref Class value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateWindowExW(uint ex, string kind, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr id, IntPtr instance, IntPtr data);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetPropW(IntPtr hwnd, string name, IntPtr value);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern UIntPtr SetTimer(IntPtr hwnd, UIntPtr id, uint milliseconds, IntPtr callback);
    [DllImport("user32.dll")] private static extern int GetMessageW(out HostWindow.Message value, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref HostWindow.Message value);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref HostWindow.Message value);
    [DllImport("user32.dll")] private static extern bool IsDialogMessageW(IntPtr hwnd, ref HostWindow.Message value);
    [DllImport("user32.dll")] private static extern bool PostMessageW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    private static readonly Procedure Proc = WindowProc;
    private static bool registered, approved;
    private static string outcomeReason = "not_confirmed";
    private static Func<bool>? cancelled;
    private static long deadline;
    internal static WorkAuthorityDecision Confirm(WorkAuthorityRecord work, AuditThread thread, Func<bool> stop, WorkAuthorityRecord? previous = null)
    {
        Exception? failure = null; bool result = false;
        var ui = new Thread(() =>
        {
            IntPtr window = IntPtr.Zero;
            try
            {
                approved = false; outcomeReason = "not_confirmed"; cancelled = stop; deadline = Environment.TickCount64 + 120000;
                var instance = GetModuleHandleW(null);
                if (!registered)
                {
                    var cls = new Class { Size = (uint)Marshal.SizeOf<Class>(), Proc = Marshal.GetFunctionPointerForDelegate(Proc), Instance = instance,
                        Background = new IntPtr(6), Name = "FlowerControl.WorkAuthority" };
                    if (RegisterClassExW(ref cls) == 0) throw new Boundary("work_authority_window_unavailable"); registered = true;
                }
                window = CreateWindowExW(0x00040000, "FlowerControl.WorkAuthority", "Flower Control · 本项工作管理员授权", 0x00C80000,
                    160, 120, 760, 600, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
                if (window == IntPtr.Zero || !SetPropW(window, "FlowerControlAuthorizationCard", new IntPtr(1))) throw new Boundary("work_authority_window_unprotected");
                string original = previous is null ? "" : $"原目标：\r\n{previous.Goal}\r\n原约束：\r\n{previous.Constraints}\r\n\r\n以下为本次申请的新范围：\r\n";
                string text = $"宿主：{thread.HostKind}\r\n线程 ID：{thread.ThreadId}\r\n名称快照：{thread.Title ?? "未提供"}\r\n\r\n{original}工作目标：\r\n{work.Goal}\r\n\r\n约束：\r\n{work.Constraints}\r\n\r\n允许本聊天为此工作请求管理员执行，受本机档位与黑名单限制；不逐程序确认。工作结束或撤销后停止新派发。窗口两分钟未确认即结束本次申请。\r\n\r\n这不是沙盒：管理员脚本仍可能影响工作范围外资源；撤销不会终止已运行程序。UAC 语义确认仍需另有实际可用的因果核对路线。";
                var content = CreateWindowExW(0x200, "EDIT", text, 0x503108C4, 18, 18, 704, 458, window, new IntPtr(10), instance, IntPtr.Zero);
                var deny = CreateWindowExW(0, "BUTTON", "不允许", 0x50010001, 430, 492, 130, 36, window, new IntPtr(2), instance, IntPtr.Zero);
                var allow = CreateWindowExW(0, "BUTTON", "允许这项工作", 0x50010000, 574, 492, 148, 36, window, new IntPtr(1), instance, IntPtr.Zero);
                if (content == IntPtr.Zero || deny == IntPtr.Zero || allow == IntPtr.Zero || SetTimer(window, new UIntPtr(1), 250, IntPtr.Zero) == UIntPtr.Zero)
                    throw new Boundary("work_authority_window_controls_unavailable");
                ShowWindow(window, 5);
                SetForegroundWindow(window); // Best effort only; Windows owns foreground admission.
                int read; while ((read = GetMessageW(out var message, IntPtr.Zero, 0, 0)) > 0)
                { if (message.Kind == 0x100 && message.Wp.ToUInt64() == 27) { outcomeReason = "user_cancelled"; PostMessageW(window, 0x10, UIntPtr.Zero, IntPtr.Zero); continue; }
                    if (!IsDialogMessageW(window, ref message)) { TranslateMessage(ref message); DispatchMessageW(ref message); } }
                if (read < 0) throw new Boundary("work_authority_window_message_failed"); result = approved && !stop();
                if (approved && !result) outcomeReason = "source_or_stop_changed";
            }
            catch (Exception error) { failure = error; }
            finally { if (window != IntPtr.Zero) DestroyWindow(window); cancelled = null; }
        });
        ui.SetApartmentState(ApartmentState.STA); ui.Start(); ui.Join();
        if (failure is not null) throw failure; return new(result, outcomeReason);
    }
    private static IntPtr WindowProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        try
        {
            if (message == 0x111 && (wp.ToUInt64() >> 16) == 0)
            {
                int id = (int)(wp.ToUInt64() & 0xffff);
                if (id is 1 or 2)
                {
                    approved = id == 1 && cancelled?.Invoke() == false && Environment.TickCount64 < deadline;
                    outcomeReason = approved ? "user_approved" : id == 2 ? "user_denied" : Environment.TickCount64 >= deadline ? "confirmation_timeout" : "source_or_stop_changed";
                    DestroyWindow(hwnd); return IntPtr.Zero;
                }
            }
            if (message == 0x113 && (Environment.TickCount64 >= deadline || cancelled?.Invoke() != false))
            { approved = false; outcomeReason = Environment.TickCount64 >= deadline ? "confirmation_timeout" : "source_or_stop_changed"; PostMessageW(hwnd, 0x10, UIntPtr.Zero, IntPtr.Zero); return IntPtr.Zero; }
            if (message == 0x10) { approved = false; if (outcomeReason == "not_confirmed") outcomeReason = "user_closed"; DestroyWindow(hwnd); return IntPtr.Zero; }
            if (message == 2) { PostQuitMessage(0); return IntPtr.Zero; }
        }
        catch { approved = false; outcomeReason = "confirmation_callback_failed"; PostMessageW(hwnd, 0x10, UIntPtr.Zero, IntPtr.Zero); }
        return DefWindowProcW(hwnd, message, wp, lp);
    }
}
