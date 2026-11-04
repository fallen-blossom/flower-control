using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record UacPromptIdentity(int Session, int Pid, long Created, long Hwnd);
internal sealed record UacClaimEntry(int Schema, string Nonce, string TaskId, string SourceDigest, string State,
    UacPromptIdentity? Prompt = null, string? PromptRef = null, bool InputFree = false, string? Reason = null);

// Only coordinates ownership of a genuine prompt. A claim is neither UAC
// authorization nor evidence that the prompt belongs to a business executable.
internal sealed class UacClaimJournal
{
    private const int Limit = 4096;
    private readonly BrokerPolicy policy;
    private readonly int session;
    private readonly string key, protectedRoot, recoveryRoot, directory, path, receipts;
    [StructLayout(LayoutKind.Sequential)] private struct Attributes
    { internal uint Size; internal IntPtr Descriptor; internal int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateMutexW(ref Attributes attributes, bool owner, string name);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")] private static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr handle);

    private readonly bool readOnlyRecovery;
    internal UacClaimJournal(BrokerPolicy policy, int session) : this(policy, session, false) { }
    private UacClaimJournal(BrokerPolicy policy, int session, bool readOnlyRecovery)
    {
        this.readOnlyRecovery = readOnlyRecovery;
        if (policy.Fixture || policy.Schema != 1 || policy.Mode != "high" || session <= 0
            || !Hex(policy.Version, 16, 64) || !ValidSid(policy.UserSid)) throw new Boundary("uac_claim_context_rejected");
        var versions = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper", "versions");
        var versionDirectory = Path.GetFullPath(policy.Directory);
        if (!versionDirectory.Equals(Path.GetFullPath(Path.Combine(versions, policy.Version)), StringComparison.OrdinalIgnoreCase)
            || !versionDirectory.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_claim_context_rejected");
        this.policy = policy; this.session = session;
        key = Hash(Encoding.UTF8.GetBytes(policy.UserSid + "|" + session.ToString(CultureInfo.InvariantCulture)));
        protectedRoot = Path.GetFullPath(Path.Combine(versionDirectory, "..", ".."));
        recoveryRoot = Path.Combine(protectedRoot, "recovery");
        directory = Path.Combine(recoveryRoot, "uac");
        path = Path.Combine(directory, key + ".json");
        receipts = Path.Combine(directory, key + ".receipts");
        RequireRole();
    }
    private static bool ValidSid(string value)
    {
        try { return new System.Security.Principal.SecurityIdentifier(value).Value == value
            && value.StartsWith("S-1-5-21-", StringComparison.Ordinal); }
        catch (ArgumentException) { return false; }
    }
    private static bool Hex(string? value, int minimum, int maximum) => value is not null
        && value.Length >= minimum && value.Length <= maximum && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Identifier(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static void Validate(UacClaimEntry value, int session)
    {
        if (value is null || session <= 0 || value.Schema != 1 || !Hex(value.Nonce, 32, 32)
            || !Identifier(value.TaskId, 128) || !Hex(value.SourceDigest, 64, 64)
            || value.State is not ("reserved" or "observed" or "dispatching" or "unknown" or "released")
            || value.Reason is not null && (value.Reason.Length is < 1 or > 96
                || value.Reason.Any(c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '_')))
            || (value.Prompt is null) != (value.PromptRef is null)
            || value.PromptRef is not null && !Hex(value.PromptRef, 64, 64)
            || value.Prompt is { } prompt && (prompt.Session != session || prompt.Pid <= 0 || prompt.Created <= 0 || prompt.Hwnd <= 0)
            || value.State == "reserved" && value.Prompt is not null
            || value.State is "observed" or "dispatching" && value.Prompt is null
            || value.State == "released" && !value.InputFree)
            throw new Boundary("uac_claim_invalid");
    }
    internal static UacClaimEntry Decode(JsonDocument document, int session)
    {
        static void Keys(JsonElement element, string[] required, params string[] optional)
        {
            if (element.ValueKind != JsonValueKind.Object) throw new Boundary("uac_claim_invalid");
            var names = element.EnumerateObject().Select(row => row.Name).ToHashSet(StringComparer.Ordinal);
            if (!names.IsSupersetOf(required) || !names.IsSubsetOf(required.Concat(optional))) throw new Boundary("uac_claim_invalid");
        }
        try
        {
            Protocol.CheckUnique(document);
            var root = document.RootElement;
            Keys(root, ["Schema", "Nonce", "TaskId", "SourceDigest", "State", "InputFree"], "Prompt", "PromptRef", "Reason");
            if (root.TryGetProperty("Prompt", out var prompt) && prompt.ValueKind != JsonValueKind.Null)
                Keys(prompt, ["Session", "Pid", "Created", "Hwnd"]);
            var value = Protocol.Decode<UacClaimEntry>(document); Validate(value, session); return value;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or Boundary)
        { throw new Boundary("uac_claim_invalid"); }
    }
    internal static void RequireOwner(UacClaimEntry? entry, string taskId, string sourceDigest, string? promptRef, bool allowObservedWithoutRef = false)
    {
        if (!Identifier(taskId, 128) || !Hex(sourceDigest, 64, 64) || promptRef is not null && !Hex(promptRef, 64, 64))
            throw new Boundary("uac_claim_request_rejected");
        if (entry is not null) Validate(entry, entry.Prompt?.Session ?? 1);
        if (entry is null || entry.State == "released")
        { if (promptRef is not null) throw new Boundary("uac_prompt_reference_stale"); return; }
        if (entry.State is "unknown" or "dispatching") throw new Boundary("uac_previous_owner_result_unknown");
        if (entry.State is not ("reserved" or "observed")) throw new Boundary("uac_claim_invalid");
        if (entry.TaskId != taskId) throw new Boundary("uac_prompt_owned_by_another_task");
        if (entry.SourceDigest != sourceDigest) throw new Boundary("uac_claim_source_changed");
        if (!entry.InputFree) throw new Boundary("uac_claim_input_release_unconfirmed");
        if (entry.State == "observed")
        {
            if (promptRef is null && allowObservedWithoutRef) return;
            if (promptRef is null || promptRef != entry.PromptRef) throw new Boundary("uac_prompt_reference_mismatch");
        }
        else if (promptRef is not null) throw new Boundary("uac_prompt_reference_stale");
    }
    internal static void RequireTransition(UacClaimEntry? prior, UacClaimEntry next, int session)
    {
        Validate(next, session);
        if (prior is not null) Validate(prior, session);
        if (prior is null || prior.State == "released" && prior.Nonce != next.Nonce)
        {
            if (next.State is not ("reserved" or "observed")) throw new Boundary("uac_claim_transition_rejected");
            return;
        }
        if (prior.Nonce != next.Nonce || prior.TaskId != next.TaskId || prior.SourceDigest != next.SourceDigest)
            throw new Boundary("uac_claim_owner_changed");
        bool refreshedObservation = prior.State == "observed" && next.State == "observed" && prior.InputFree && next.InputFree;
        if (prior.Prompt is not null && (prior.Prompt != next.Prompt || prior.PromptRef != next.PromptRef && !refreshedObservation))
            throw new Boundary("uac_prompt_identity_changed");
        if (prior.State == "unknown" && next.State != "unknown") throw new Boundary("uac_previous_owner_result_unknown");
        bool allowed = prior.State switch
        {
            "reserved" => next.State is "reserved" or "observed" or "unknown" || next.State == "released" && prior.InputFree,
            "observed" => next.State is "observed" or "dispatching" or "unknown" || next.State == "released" && prior.InputFree,
            // Only trusted executor results can mark this released; no MCP writer
            // can supply InputFree. Unknown never becomes released by this API.
            "dispatching" => next.State is "dispatching" or "unknown" or "released",
            "unknown" => next.State == "unknown",
            "released" => next.State == "released",
            _ => false,
        };
        if (!allowed || next.State == "dispatching" && !prior.InputFree && prior.State != "dispatching")
            throw new Boundary("uac_claim_transition_rejected");
    }
    private void RequireRole()
    {
        var own = Native.Process(Environment.ProcessId, false).Identity;
        if (Native.UiAccess(own.Pid)) throw new Boundary("uac_claim_role_rejected");
        if (own.User == "S-1-5-18" && own.Integrity == 16384)
        { UacSystemBootstrap.VerifyInteractiveUser(session, policy.UserSid); return; }
        if (own.User != policy.UserSid || own.Integrity != (readOnlyRecovery ? 8192 : 12288) || own.Session != session)
            throw new Boundary("uac_claim_role_rejected");
    }
    private T Locked<T>(Func<T> action)
    {
        if (readOnlyRecovery) throw new Boundary("uac_recovery_read_only");
        RequireRole();
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;HI)", 1, out var descriptor, out _))
            throw new Boundary("uac_claim_lock_unavailable", Marshal.GetLastWin32Error());
        IntPtr mutex = IntPtr.Zero;
        try
        {
            var attributes = new Attributes { Size = (uint)Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            mutex = CreateMutexW(ref attributes, false, "Global\\FlowerControl.UacClaimJournal." + key);
            if (mutex == IntPtr.Zero) throw new Boundary("uac_claim_lock_unavailable", Marshal.GetLastWin32Error());
            uint result = WaitForSingleObject(mutex, 5000);
            if (result is not (0 or 0x80)) throw new Boundary("uac_claim_journal_busy");
            // Abandonment changes no persisted state and grants no takeover.
            try { RequireRole(); return action(); }
            finally { if (!ReleaseMutex(mutex)) throw new Boundary("uac_claim_lock_release_unconfirmed"); }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { throw new Boundary("uac_claim_journal_unavailable"); }
        finally { if (mutex != IntPtr.Zero) CloseHandle(mutex); LocalFree(descriptor); }
    }
    internal static void CheckParent(string parent, bool requireHigh)
    {
        var attributes = File.GetAttributes(parent);
        if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
            throw new Boundary("uac_claim_storage_unprotected");
        BrokerPolicy.RejectLinks(parent);
        if (requireHigh) { UserPermissions.CheckProtectionForDirectory(parent); return; }
        // The existing shared recovery parent may predate explicit High labels.
        // Its owner/DACL must still prevent every non-admin mutation, including
        // deletion through the parent. The new UAC directory has a High label.
        var security = new DirectoryInfo(parent).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null
            || security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544"))
            throw new Boundary("uac_claim_storage_unprotected");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)))
            if (UntrustedAncestorMutation(rule)) throw new Boundary("uac_claim_storage_unprotected");
    }
    internal static bool UntrustedAncestorMutation(FileSystemAccessRule rule)
    {
        // Windows Program Files ancestors inherit TrustedInstaller's system
        // service ACE and an inherit-only CREATOR OWNER ACE. Neither grants
        // an ordinary caller mutation of this directory or deletion of our
        // protected child. New UAC storage still uses the stricter High check.
        const string trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        return rule.AccessControlType == AccessControlType.Allow
            && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0
            && ((int)rule.FileSystemRights & UserPermissions.PolicyMutationRights) != 0
            && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544")
            && rule.IdentityReference.Value != trustedInstaller;
    }
    private bool EnsureStorage(bool create)
    {
        CheckParent(Path.GetDirectoryName(protectedRoot)!, false);
        CheckParent(protectedRoot, false);
        foreach (var parent in new[] { recoveryRoot, directory })
        {
            try { CheckParent(parent, parent == directory); }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
            {
                if (!create) return false;
                SecurityLabel.CreateDirectory(parent, policy.UserSid); CheckParent(parent, true);
            }
        }
        return true;
    }
    private byte[]? ReadRaw()
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) throw new Boundary("uac_claim_invalid");
        }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
        {
            if (ReceiptsExist())
            {
                if (Directory.EnumerateFileSystemEntries(receipts).Any()) throw new Boundary("uac_claim_current_record_missing");
            }
            return null;
        }
        UserPermissions.CheckProtection(path);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (input.Length is < 1 or > Limit) throw new Boundary("uac_claim_invalid");
        var bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes); return bytes;
    }
    private bool ReceiptsExist()
    {
        try { CheckParent(receipts, true); return true; }
        catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException) { return false; }
    }
    private UacClaimEntry Entry(byte[] raw)
    {
        try { using var document = JsonDocument.Parse(raw); return Decode(document, session); }
        catch (JsonException) { throw new Boundary("uac_claim_invalid"); }
    }
    internal static bool ReadOnlyInputFault(BrokerPolicy policy, int session)
    {
        var journal = new UacClaimJournal(policy, session, true);
        if (!journal.EnsureStorage(false)) return false;
        var raw = journal.ReadRaw();
        if (raw is null) return false;
        var entry = journal.Entry(raw);
        bool fault = ((!entry.InputFree && entry.State is "dispatching" or "unknown")
            || entry.Reason == "explicit_stop_persistence_failed") && !journal.LegacyProof(raw, entry);
        var after = journal.ReadRaw();
        if (after is null || !raw.SequenceEqual(after)) throw new Boundary("uac_recovery_state_changed");
        return fault;
    }
    internal UacClaimEntry? Read() => Locked(() =>
    {
        if (!EnsureStorage(false)) return null;
        var raw = ReadRaw(); return raw is null ? null : Entry(raw);
    });
    internal void WriteTestReceipt(string nonce, JsonElement receipt) => WriteResult("tests", nonce, receipt);
    internal void WriteWorkerReceipt(string nonce, JsonElement receipt) => WriteResult("workers", nonce, receipt);
    private void WriteResult(string category, string nonce, JsonElement receipt) => Locked(() =>
    {
        if (!Hex(nonce, 32, 32)) throw new Boundary("uac_test_nonce_rejected");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(receipt);
        if (bytes.Length > 65536) throw new Boundary("uac_test_receipt_too_large");
        EnsureStorage(true);
        var testDirectory = Path.Combine(directory, key + "." + category);
        SecurityLabel.CreateDirectory(testDirectory, policy.UserSid); CheckParent(testDirectory, true);
        var target = Path.Combine(testDirectory, nonce + ".json");
        // One nonce, one immutable result. Test evidence never alters a claim
        // or clears unknown input; no screenshot/password content is collected.
        if (File.Exists(target)) throw new Boundary("uac_test_receipt_exists");
        SecurityLabel.Write(target, bytes, policy.UserSid); UserPermissions.CheckProtection(target);
        return true;
    });
    internal bool LegacyControlQuiesced() => Locked(() =>
    {
        if (!EnsureStorage(false)) return false;
        var raw = ReadRaw(); return raw is not null && LegacyProof(raw, Entry(raw));
    });
    private bool LegacyProof(byte[] raw, UacClaimEntry entry)
    {
        bool legacy = UacLegacyControlRecovery.IsOriginal(raw, entry);
        if (!legacy && (entry.State != "unknown" || !entry.InputFree)) return false;
        string proof = Path.Combine(directory, key + ".control-recovery." + policy.Version + ".json");
        try
        {
            BrokerPolicy.RejectLinks(proof); UserPermissions.CheckProtection(proof);
            using var stream = new FileStream(proof, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is < 1 or > 32768) throw new Boundary("uac_control_recovery_invalid");
            using var document = JsonDocument.Parse(stream); Protocol.CheckUnique(document);
            if (!(legacy ? UacLegacyControlRecovery.Matches(document.RootElement, policy.Version, policy.UserSid, session)
                : CancelledTestProof(document.RootElement, raw, entry)))
                throw new Boundary("uac_control_recovery_invalid");
            return true;
        }
        catch (FileNotFoundException) { return false; }
    }
    private bool CancelledTestProof(JsonElement proof, byte[] raw, UacClaimEntry entry)
    {
        string? Text(string name) => UacOutcomeEvidence.Text(proof, name);
        int schema = proof.GetProperty("Schema").GetInt32();
        bool preobservation = schema == 4, observedRejection = schema == 5, controlOnly = schema is 3 or 4 or 5;
        if (schema is not (2 or 3 or 4 or 5) || Text("ClaimSha256") != Hash(raw)
            || Text("RecoveryVersion") != policy.Version || Text("UserSid") != policy.UserSid
            || proof.GetProperty("Session").GetInt32() != session
            || Text("Scope") != (observedRejection ? "fixed_test_observed_zero_dispatch_control_only"
                : preobservation ? "fixed_test_preobservation_zero_dispatch_control_only"
                : controlOnly ? "fixed_test_zero_dispatch_control_only" : "cancelled_zero_dispatch_test_only")
            || Text("BusinessOutcome") != (controlOnly ? "unknown" : "business_cancelled") || !UacOutcomeEvidence.True(proof, "InputFree")
            || !UacOutcomeEvidence.True(proof, "OldExecutorsAbsent")
            || !UacOutcomeEvidence.True(proof, controlOnly ? "KnownPeersExited" : "OriginalPeersExited")
            || !UacOutcomeEvidence.True(proof, "OriginalPromptGone") || !UacOutcomeEvidence.True(proof, "TasksDisabledDuringProof")
            || !UacOutcomeEvidence.False(proof, "InputReplay")) return false;
        if (controlOnly && (Text("ExecutorInventoryScope") != "sealed_fixed_test_version"
            || !UacOutcomeEvidence.False(proof, "LauncherIdentityAvailable")
            || !Hex(Text("NativeSha256"), 64, 64) || !Hex(Text("InstallationSha256"), 64, 64))) return false;
        if (preobservation && (!UacOutcomeEvidence.True(proof, "NoNativeObservation")
            || !UacOutcomeEvidence.True(proof, "AllKnownEntriesDisabled"))) return false;
        string? nonce = Text("TestNonce"), workerNonce = Text("WorkerNonce");
        if (!Hex(nonce, 32, 32) || !Hex(workerNonce, 32, 32) || !Hex(Text("PreviousVersion"), 32, 32)
            || !Hex(Text("ImageSha256"), 64, 64) || !Hex(Text("ManagedSha256"), 64, 64)) return false;
        JsonDocument Receipt(string category, string id, string? digest)
        {
            string parent = Path.Combine(directory, key + "." + category); CheckParent(parent, true);
            string source = Path.Combine(parent, id + ".json"); BrokerPolicy.RejectLinks(source); UserPermissions.CheckProtection(source);
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length is < 1 or > 65536) throw new Boundary("uac_control_recovery_invalid");
            var bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
            if (Hash(bytes) != digest) throw new Boundary("uac_control_recovery_evidence_changed");
            var result = JsonDocument.Parse(bytes); Protocol.CheckUnique(result); return result;
        }
        using var worker = Receipt("workers", workerNonce!, Text("WorkerReceiptSha256"));
        using var test = Receipt("tests", nonce!, Text("TestReceiptSha256"));
        if (observedRejection)
            return ObservedRejectionProofMatches(proof, worker.RootElement)
                && ObservedRejectionControlOnlyEvidenceMatches(entry, worker.RootElement, test.RootElement,
                    Text("PreviousVersion")!, Text("ImageSha256")!, Text("ManagedSha256")!, policy.UserSid, session, Text("NativeSha256")!);
        return preobservation
            ? UacCancelledTestRecovery.PreobservationControlOnlyEvidenceMatches(entry, worker.RootElement, test.RootElement,
                Text("PreviousVersion")!, Text("ImageSha256")!, Text("ManagedSha256")!, policy.UserSid, session)
            : controlOnly
            ? UacCancelledTestRecovery.ControlOnlyEvidenceMatches(entry, worker.RootElement, test.RootElement,
                Text("PreviousVersion")!, Text("ImageSha256")!, Text("ManagedSha256")!, policy.UserSid, session)
            : UacCancelledTestRecovery.EvidenceMatches(entry, worker.RootElement, test.RootElement,
                Text("PreviousVersion")!, Text("ImageSha256")!, Text("ManagedSha256")!, policy.UserSid, session);
    }
    // A distinct proof for the fixed accept refused after observation but before
    // ready/go. It cannot retire a production request or infer business success.
    internal static bool ObservedRejectionProofMatches(JsonElement proof, JsonElement worker)
    {
        try
        {
            if (proof.GetProperty("Schema").GetInt32() != 5
                || UacOutcomeEvidence.Text(proof, "Scope") != "fixed_test_observed_zero_dispatch_control_only"
                || UacOutcomeEvidence.Text(proof, "BusinessOutcome") != "unknown") return false;
            foreach (string field in new[] { "AllKnownEntriesDisabled", "OriginalNonceResourcesReleased", "ObservedPromptWithoutClaim", "NoReadyGo" })
                if (!UacOutcomeEvidence.True(proof, field)) return false;
            var original = proof.GetProperty("OriginalPrompt"); var observed = worker.GetProperty("PromptBefore");
            if (original.ValueKind != JsonValueKind.Object
                || !original.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(new[] { "Session", "Pid", "Created", "Hwnd" })
                || UacOutcomeEvidence.Text(proof, "OriginalPromptRef") != UacOutcomeEvidence.Text(observed, "observation_id")) return false;
            foreach (string field in new[] { "Session", "Pid", "Created", "Hwnd" })
                if (original.GetProperty(field).GetInt64() != observed.GetProperty(field.ToLowerInvariant()).GetInt64()) return false;
            return true;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException) { return false; }
    }
    internal static bool ObservedRejectionControlOnlyEvidenceMatches(UacClaimEntry entry, JsonElement worker, JsonElement test,
        string version, string image, string managed, string sid, int session, string native)
    {
        static string? S(JsonElement e, string k) => UacOutcomeEvidence.Text(e, k);
        static bool T(JsonElement e, string k) => UacOutcomeEvidence.True(e, k);
        static bool F(JsonElement e, string k) => UacOutcomeEvidence.False(e, k);
        static bool Nil(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Null;
        bool PeerMatches(JsonElement e, string user, int integrity) => JsonSerializer.Deserialize<Peer>(e) is { } p
            && p.Pid > 0 && p.Created > 0 && p.Session == session && p.User == user && p.Integrity == integrity && p.ImageDigest == image;
        try
        {
            Validate(entry, session);
            string? nonce = S(test, "Nonce"), workerNonce = S(worker, "RequestNonce");
            string task = "uac_test_accept_" + nonce;
            if (!Hex(nonce, 32, 32) || !Hex(workerNonce, 32, 32) || entry.TaskId != task
                || entry.State != "unknown" || !entry.InputFree || entry.Prompt is not null || entry.PromptRef is not null
                || entry.SourceDigest != image || entry.Reason != "test_elevation_result_unknown"
                || test.GetProperty("Schema").GetInt32() != 1 || S(test, "Phase") != "uac_test" || !F(test, "InputReplay")
                || !Nil(test, "Business") || !Nil(test, "ControllerError") || !Nil(test, "QualificationIndex")
                || S(worker, "Phase") != "uac" || S(worker, "TaskId") != task || S(worker, "Action") != "none" || S(worker, "Authority") != "none"
                || S(worker, "Reason") != "uac_prompt_changed_requires_new_observation" || S(worker, "Version") != version
                || S(worker, "ManagedHelperSha256") != managed || S(worker, "TestNonce") != nonce || S(worker, "TestCommand") != "accept"
                || S(worker, "PromptAttribution") != "fixed_test_exact_command" || S(worker, "WorkerNoNativeDispatchScope") != "confirmation_or_cancellation"
                || !T(worker, "WorkerNoNativeDispatch") || !T(worker, "WatchersEnded") || !T(worker, "ControlledExperiment")
                || !F(worker, "InputDispatched") || !F(worker, "PhysicalStopObserved") || !F(worker, "InputReplay")) return false;
            string[] nilFields = ["NativeResult", "PromptInstanceGone", "StopPersistenceError", "WatcherCleanupError", "ProgramBindingCleanupError",
                "LauncherBoundaryCloseError", "ProgramQualificationSample", "ProgramQualificationRegistration"];
            foreach (string field in nilFields) if (!Nil(worker, field)) return false;
            foreach (string field in new[] { "ReadyWrittenTick", "GoReceivedTick", "GoWaitEndedTick" })
                if (worker.GetProperty(field).GetInt64() != 0) return false;
            long started = worker.GetProperty("WorkerStartedTick").GetInt64(), ready = worker.GetProperty("PromptReadyTick").GetInt64(), ended = worker.GetProperty("WorkerEndedTick").GetInt64();
            if (started <= 0 || ready < started || ended < ready) return false;
            var observed = worker.GetProperty("PromptBefore"); var end = worker.GetProperty("StopMonitorEnd");
            if (observed.GetProperty("schema").GetInt32() != 1 || S(observed, "state") != "observed"
                || observed.GetProperty("session").GetInt32() != session || S(observed, "interactive_user_sid") != sid
                || S(observed, "desktop") != "Winlogon" || S(observed, "window_station") != "WinSta0" || !Hex(S(observed, "observation_id"), 64, 64)
                || !F(observed, "credential_prompt") || !F(observed, "input_dispatched") || !T(observed, "desktop_cleanup_verified")
                || S(observed, "input_dispatched_scope") != "confirmation_or_cancellation") return false;
            foreach (string field in new[] { "pid", "created", "hwnd" }) if (observed.GetProperty(field).GetInt64() <= 0) return false;
            bool details = worker.GetProperty("DetailsExpansionAttempted").GetBoolean();
            if (worker.GetProperty("DetailsExpansionReturned").GetBoolean() != details
                || observed.GetProperty("details_expansion_attempted").GetBoolean() != details || observed.GetProperty("details_expansion_returned").GetBoolean() != details
                || S(end, "state") != "monitor_stopped" || !F(end, "input_dispatched") || !T(end, "desktop_cleanup_verified")
                || !T(end, "secure_stop_controller_completed") || !F(end, "continuous_stop_monitor_active") || end.GetProperty("secure_stop_controller_error").GetInt32() != 0) return false;
            var binding = worker.GetProperty("VerificationBinding");
            if (S(binding, "Version") != version || S(binding, "HelperSha256") != image || S(binding, "ManagedHelperSha256") != managed
                || S(binding, "NativeSha256") != native || !Hex(native, 64, 64) || !Hex(S(binding, "ConsentSha256"), 64, 64)
                || string.IsNullOrEmpty(S(binding, "WindowsBuild")) || S(binding, "UserSid") != sid || binding.GetProperty("Session").GetInt32() != session) return false;
            var receipt = test.GetProperty("Receipt");
            foreach (string field in new[] { "Phase", "RequestNonce", "TaskId", "Action", "Authority", "Reason", "Version", "ManagedHelperSha256", "PromptBefore", "StopMonitorEnd",
                "Source", "Worker", "ControlledExperiment", "TestNonce", "TestCommand", "WorkerNoNativeDispatch", "WorkerNoNativeDispatchScope", "DetailsExpansionAttempted", "DetailsExpansionReturned",
                "WatchersEnded", "PhysicalStopObserved", "PromptAttribution", "PromptReadyTick", "ReadyWrittenTick", "GoReceivedTick", "GoWaitEndedTick", "WorkerStartedTick", "WorkerEndedTick", "InputDispatched", "VerificationBinding" }.Concat(nilFields))
                if (!JsonElement.DeepEquals(receipt.GetProperty(field), worker.GetProperty(field))) return false;
            if (S(receipt, "BusinessResultError") != "deadline_expired" || !F(receipt, "InputReplay")) return false;
            foreach (string field in new[] { "InputFree", "ControlComplete", "TestLauncherStarted", "BusinessLaunchAttempted" }) if (!T(receipt, field)) return false;
            foreach (string field in new[] { "BusinessResult", "WorkerEvidenceSaveError", "RelayError", "QualificationHandshakeError", "QualificationCancelError" }) if (!Nil(receipt, field)) return false;
            foreach (string field in new[] { "ReadyReceivedTick", "ObservedJournalWrittenTick", "DispatchJournalWrittenTick", "GoWrittenTick" })
                if (receipt.GetProperty("HighHandshakeTimings").GetProperty(field).GetInt64() != 0) return false;
            return PeerMatches(worker.GetProperty("Worker"), "S-1-5-18", 16384) && PeerMatches(worker.GetProperty("Source"), sid, 12288);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or Boundary) { return false; }
    }
    private string RetiredTaskPath(string task) => Path.Combine(directory, key + ".retired-test." + Hash(Encoding.UTF8.GetBytes(task)) + ".json");
    internal void Write(UacClaimEntry value, bool controlledLegacyRecovery = false) => Locked(() =>
    {
        Validate(value, session); EnsureStorage(true);
        var raw = ReadRaw(); var prior = raw is null ? null : Entry(raw);
        if (value.Nonce == UacLegacyControlRecovery.Nonce || value.TaskId == UacLegacyControlRecovery.Task)
            throw new Boundary("uac_retired_test_replay_rejected");
        if (File.Exists(RetiredTaskPath(value.TaskId)))
        { BrokerPolicy.RejectLinks(RetiredTaskPath(value.TaskId)); UserPermissions.CheckProtection(RetiredTaskPath(value.TaskId)); throw new Boundary("uac_retired_test_replay_rejected"); }
        if (controlledLegacyRecovery)
        {
            if (raw is null || prior is null || prior.Nonce == value.Nonce || prior.TaskId == value.TaskId
                || !LegacyProof(raw, prior) || !UacLegacyControlRecovery.FreshControlled(value))
                throw new Boundary("uac_control_recovery_rejected");
            RequireTransition(null, value, session);
            string retired = RetiredTaskPath(prior.TaskId);
            if (!File.Exists(retired)) SecurityLabel.Write(retired, raw, policy.UserSid);
            BrokerPolicy.RejectLinks(retired); UserPermissions.CheckProtection(retired);
            if (!File.ReadAllBytes(retired).SequenceEqual(raw)) throw new Boundary("uac_control_recovery_retirement_changed");
        }
        else RequireTransition(prior, value, session);
        if (prior == value) return true;
        if (ReceiptsExist())
        {
            if (prior?.Nonce != value.Nonce && Directory.EnumerateFiles(receipts, value.Nonce + ".*.json").Any())
                throw new Boundary("uac_claim_nonce_reused");
        }
        if (prior is not null)
        {
            SecurityLabel.CreateDirectory(receipts, policy.UserSid); CheckParent(receipts, true);
            var archive = Path.Combine(receipts, prior.Nonce + "." + prior.State + "." + Hash(raw!) + ".json");
            try
            {
                var attributes = File.GetAttributes(archive);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) throw new Boundary("uac_claim_receipt_conflict");
                UserPermissions.CheckProtection(archive);
                using var existing = new FileStream(archive, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (existing.Length != raw!.Length || existing.Length > Limit) throw new Boundary("uac_claim_receipt_conflict");
                var bytes = new byte[raw.Length]; existing.ReadExactly(bytes);
                if (!bytes.SequenceEqual(raw)) throw new Boundary("uac_claim_receipt_conflict");
            }
            catch (FileNotFoundException) { SecurityLabel.Write(archive, raw!, policy.UserSid); UserPermissions.CheckProtection(archive); }
        }
        var temporary = Path.Combine(directory, key + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
            if (bytes.Length > Limit) throw new Boundary("uac_claim_invalid");
            SecurityLabel.Write(temporary, bytes, policy.UserSid); UserPermissions.CheckProtection(temporary);
            var latest = ReadRaw();
            if ((raw is null) != (latest is null) || raw is not null && !raw.SequenceEqual(latest!)) throw new Boundary("uac_claim_record_changed");
            File.Move(temporary, path, prior is not null);
            UserPermissions.CheckProtection(path);
            var verified = ReadRaw();
            if (verified is null || !verified.SequenceEqual(bytes) || Entry(verified) != value) throw new Boundary("uac_claim_write_unconfirmed");
            return true;
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { Console.Error.WriteLine("uac_claim_temporary_cleanup_pending"); }
        }
    });
}
