using System.Text.Json;
using System.Text.RegularExpressions;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;

namespace Flower.HighHelper;

// An optional diagnostic attached to one original fixed test call. A match is
// never read as accept authority. The normal launch/Stop/native gates remain.
internal sealed class UacScanLease : IDisposable
{
    private sealed record Journal(int Schema, string Kind, Guid Trace, Peer Owner, string Nonce);
    private static readonly ConcurrentDictionary<string, UacScanLease> pendingCleanup = new(StringComparer.OrdinalIgnoreCase);
    private readonly object sync = new();
    private readonly string journalPath, nonce;
    private readonly ulong generation, revision;
    private readonly string policyRevision;
    private FileStream? singleton;
    private readonly ManualResetEvent cancel = new(false), physicalStop = new(false);
    private CancellationTokenRegistration cancellation, noNewLaunch;
    private bool disposed, started, journalWritten, nativeCleanupComplete;
    private readonly Guid trace;
    private readonly Peer own;
    internal JsonElement? LastObservation { get; private set; }
    internal string? CleanupError { get; private set; }
    internal bool CleanupComplete { get; private set; }

    internal UacScanLease(BrokerPolicy policy, Peer requester, string nonce, ulong generation, string policyRevision,
        CancellationToken stop, CancellationToken preventBegin)
    {
        own = Native.Process(Environment.ProcessId).Identity;
        if (own.Integrity != 12288 || own.User != policy.UserSid || Native.UiAccess(own.Pid)
            || requester.Session != own.Session || requester.User != own.User || requester.Integrity != 8192
            || !Regex.IsMatch(nonce, "\\A[a-f0-9]{32}\\z") || generation == 0 || string.IsNullOrEmpty(policyRevision))
            throw new Boundary("uac_scan_original_rejected");
        this.nonce = nonce; this.generation = generation; this.policyRevision = policyRevision;
        revision = BinaryPrimitives.ReadUInt64BigEndian(SHA256.HashData(Encoding.UTF8.GetBytes(policyRevision))) | 1UL;
        // The journal survives version replacement. It contains no command or
        // UI text. Only a protected exact owner+GUID permits orphan recovery.
        var versionRoot = UacStateStorage.Directory(policy, true);
        var common = Directory.GetParent(versionRoot)!.Parent!.FullName;
        var root = Path.Combine(common, "scan-shadow"); AuditFiles.EnsureDirectory(root);
        journalPath = Path.Combine(root, "session-" + own.Session + ".json");
        try
        {
            var lockPath = Path.Combine(root, "session-" + own.Session + ".lock");
            if (!File.Exists(lockPath))
            {
                try { AuditFiles.WriteNew(lockPath, []); }
                catch (IOException) when (File.Exists(lockPath)) { /* Other owner created the same protected empty lease. */ }
            }
            AuditFiles.Check(lockPath, false);
            // File sharing is process-wide and supports async continuations;
            // a named Mutex would require Dispose on its acquiring thread.
            singleton = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            if (pendingCleanup.TryGetValue(journalPath, out var pending))
            {
                // Only this same live High process can retry its original
                // exact native close/file phase. No original launch is replayed.
                pending.Dispose();
                if (!pending.CleanupComplete) throw new Boundary("uac_scan_previous_capture_unresolved");
            }
            RecoverPrevious(own);
            UacNativeBridge.RequireScanExports();
            Native.VerifyPeer(requester); stop.ThrowIfCancellationRequested(); preventBegin.ThrowIfCancellationRequested();
            trace = Guid.NewGuid();
            AuditFiles.WriteNew(journalPath, JsonSerializer.SerializeToUtf8Bytes(new Journal(1, "uac_scan_shadow", trace, own, nonce)));
            journalWritten = true;
            cancellation = stop.Register(() => cancel.Set());
            noNewLaunch = preventBegin.Register(() => cancel.Set());
            RequireCurrent(requireStarted: false);
            started = true; // A native exception can follow a successful StartTrace.
            var result = UacNativeBridge.StartScan(requester, nonce, generation, revision, trace, cancel, physicalStop);
            if (UacOutcomeEvidence.False(result, "capture_created")) started = false;
            LastObservation = result;
            if (!UacOutcomeEvidence.True(result, "active")) throw new Boundary("uac_scan_capture_start_unconfirmed");
        }
        catch { Dispose(); throw; }
    }
    private void RecoverPrevious(Peer own)
    {
        if (!File.Exists(journalPath)) return;
        AuditFiles.Check(journalPath, false);
        if (new FileInfo(journalPath).Length > 8192) throw new Boundary("uac_scan_journal_invalid");
        using var document = JsonDocument.Parse(File.ReadAllBytes(journalPath)); Protocol.CheckUnique(document);
        var prior = Protocol.Decode<Journal>(document);
        if (prior.Schema != 1 || prior.Kind != "uac_scan_shadow" || prior.Trace == Guid.Empty
            || prior.Owner.Session != own.Session || prior.Owner.User != own.User || prior.Owner.Integrity != 12288
            || prior.Owner.Created <= 0 || prior.Owner.Pid <= 0 || !Regex.IsMatch(prior.Nonce, "\\A[a-f0-9]{32}\\z"))
            throw new Boundary("uac_scan_journal_invalid");
        var recovered = UacNativeBridge.RecoverScan(prior.Trace, prior.Owner);
        if (!UacOutcomeEvidence.True(recovered, "cleanup_complete")) throw new Boundary("uac_scan_orphan_unresolved");
        AuditFiles.Check(journalPath, false); File.Delete(journalPath);
    }
    internal void Arm()
    {
        lock (sync)
        {
            RequireCurrent();
            var result = UacNativeBridge.Scan(nonce, "arm", null, generation, revision); LastObservation = result;
            if (!UacOutcomeEvidence.True(result, "active") || !UacOutcomeEvidence.True(result, "armed"))
                throw new Boundary("uac_scan_original_begin_rejected");
        }
    }
    internal JsonElement Read(UacPromptIdentity prompt)
    {
        lock (sync)
        {
            RequireCurrent();
            var result = UacNativeBridge.Scan(nonce, "read", prompt, generation, revision);
            RequireCurrent();
            // Kept as diagnostic metadata. Never returned as UAC capability.
            LastObservation = result; return result;
        }
    }
    private void RequireCurrent(bool requireStarted = true)
    {
        if (disposed || requireStarted && !started || cancel.WaitOne(0)) throw new Boundary("uac_scan_original_cancelled");
        // The full revision is authoritative. Its native 64-bit diagnostic
        // tag is never used instead of this exact comparison.
        if (UserPermissions.Read().Revision != policyRevision) throw new Boundary("uac_scan_policy_changed");
    }
    public void Dispose()
    {
        lock (sync)
        {
            if (disposed && CleanupComplete) return;
            bool firstClose = !disposed;
            disposed = true;
            if (firstClose) cancel.Set();
            try
            {
                if (started && !nativeCleanupComplete)
                {
                    var result = UacNativeBridge.Scan(nonce, "close", null, generation, revision);
                    if (!UacOutcomeEvidence.True(result, "cleanup_complete")) throw new Boundary("uac_scan_cleanup_unknown");
                    nativeCleanupComplete = true;
                }
                if (journalWritten)
                {
                    // Once native cleanup succeeded, a sharing violation here
                    // retries only this file phase, never the released handle.
                    // If native was never entered there is no trace to close.
                    AuditFiles.Check(journalPath, false); File.Delete(journalPath);
                }
                CleanupComplete = true; CleanupError = null;
                if (pendingCleanup.TryGetValue(journalPath, out var retained) && ReferenceEquals(retained, this))
                    pendingCleanup.TryRemove(journalPath, out _);
            }
            catch (Exception error)
            {
                CleanupError = Program.Code(error);
                if (journalWritten) pendingCleanup[journalPath] = this;
            }
            finally
            {
                if (firstClose)
                {
                    cancellation.Dispose(); noNewLaunch.Dispose(); cancel.Dispose(); physicalStop.Dispose();
                    singleton?.Dispose(); singleton = null;
                }
            }
        }
    }
}
