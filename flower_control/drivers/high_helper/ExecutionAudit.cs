using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// Adapter metadata identifies a conversation, not a human approval receipt.
// Titles are mutable observations and never participate in authority matching.
internal sealed record AuditThread(string HostKind, string ThreadId, string? Title = null,
    string TitleSource = "unavailable", string? TitleObservedUtc = null);
internal sealed record AuditStamp(string StreamId, long Sequence, string Hash);
internal sealed record AuditEvent(string Kind, string TaskId, string RequestId, string State,
    string? Target = null, string? Reason = null, AuditThread? Thread = null,
    object? Evidence = null);

// Append-only event files plus an authenticated checkpoint outside version roots.
// ACLs protect against ordinary callers; administrators can defeat local evidence.
// Never use this audit as a replacement for the executor's recovery journal.
internal sealed class ExecutionAudit
{
    internal static void RequireThreadSource(AuditThread? thread, PeerEvidence source)
    {
        if (thread is null) return;
        string expected = source.Source switch { "codex-flower" => "codex", "claude-code-flower" => "claude-code",
            "dsh-desktop-flower" => "dsh-desktop", _ => "unsupported" };
        if (thread.HostKind != expected) throw new Boundary("execution_audit_host_mismatch");
    }
    internal static void ValidateThread(AuditThread thread)
        => Validate(new AuditEvent("thread_metadata", "", "", "observed", Thread: thread));
    private const int SegmentBytes = 16 * 1024 * 1024, RecordBytes = 256 * 1024;
    private static readonly string Zero = new('0', 64);
    private static readonly ConcurrentDictionary<string, ExecutionAudit> Stores = new();
    private static readonly JsonSerializerOptions Json = new() { MaxDepth = 24 };
    private sealed record Head(int Schema, string StreamId, long Sequence, string Hash, int Segment);
    private sealed record Checkpoint(string Payload, string Mac);
    private sealed record Body(int Schema, string StreamId, long Sequence, string PreviousHash,
        string Utc, AuditEvent Event, string? Nonce, string? Ciphertext, string? Tag);
    private sealed record Line(string Payload, string Hash, string Mac);
    private sealed record SeenFile(string Path, long Length, long Modified);
    private sealed record RecoveryNote(string Note, JsonElement Receipt, bool MacVerified,
        bool PreservedOriginalVerified, string? ActualPreservedPath, string State);
    private readonly object gate = new();
    private readonly string root, sid, keyPath, headPath;
    private readonly int session;
    private byte[] key = [];
    private Head? head;
    private byte[]? headBytes;
    private SeenFile[] files = [];
    private bool faulted;

    private ExecutionAudit(string root, string sid, int session)
    { this.root = root; this.sid = sid; this.session = session; keyPath = Path.Combine(root, "key.bin"); headPath = Path.Combine(root, "checkpoint.json"); }

    internal static ExecutionAudit Open(BrokerPolicy policy, Peer own, bool create = true)
    {
        var install = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper");
        if (policy.Fixture || policy.Mode != "high" || own.Integrity != 12288 || own.User != policy.UserSid
            || own.Session <= 0 || Native.UiAccess(own.Pid)
            || !Path.GetFullPath(policy.Directory).TrimEnd('\\').Equals(Path.Combine(install, "versions", policy.Version), StringComparison.OrdinalIgnoreCase)
            || !Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(Path.GetFullPath(policy.Directory), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("execution_audit_role_rejected");
        UacClaimJournal.CheckParent(Path.GetDirectoryName(install)!, false); UacClaimJournal.CheckParent(install, false);
        string parent = Path.Combine(install, "audit");
        if (create) AuditFiles.EnsureDirectory(parent); else AuditFiles.Check(parent, true);
        string identity = Hash(Encoding.UTF8.GetBytes(own.User + "|" + own.Session));
        string root = Path.Combine(parent, identity);
        if (create) AuditFiles.EnsureDirectory(root); else AuditFiles.Check(root, true);
        return Stores.GetOrAdd(root, _ => new ExecutionAudit(root, own.User, own.Session));
    }

    private void RequireRole()
    {
        var own = Native.Process(Environment.ProcessId, false).Identity;
        if (own.User != sid || own.Session != session || own.Integrity != 12288 || Native.UiAccess(own.Pid))
            throw new Boundary("execution_audit_role_rejected");
        AuditFiles.Check(root, true);
    }
    private T Locked<T>(Func<T> action, bool createLock = true, bool latchFailure = true)
    {
        lock (gate)
        {
            RequireRole();
            // The protected directory lock also serializes distinct High processes.
            // FileShare.None must never be replaced by a model-provided lock name.
            string path = Path.Combine(root, "writer.lock");
            if (createLock && !File.Exists(path)) { try { AuditFiles.WriteNew(path, []); } catch (IOException) { } }
            AuditFiles.Check(path, false);
            using var exclusive = WriterLock(path);
            try { return action(); }
            catch { if (latchFailure) faulted = true; throw; }
        }
    }
    private static FileStream WriterLock(string path)
    {
        long deadline = Environment.TickCount64 + 1000;
        while (true)
        {
            try { return new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException error) when ((error.HResult & 0xffff) is 32 or 33)
            {
                if (Environment.TickCount64 >= deadline) throw new Boundary("execution_audit_busy");
                Thread.Sleep(20);
            }
        }
    }
    private static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    private string Mac(byte[] value) => Convert.ToHexString(HMACSHA256.HashData(key, value)).ToLowerInvariant();
    private void RequireMac(byte[] value, string actual)
    {
        if (!AdminProgramLaunch.Digest(actual) || !CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(Mac(value)), Encoding.ASCII.GetBytes(actual))) throw new Boundary("execution_audit_mac_invalid");
    }
    private static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);
    private static T Decode<T>(byte[] value)
    {
        using var document = JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = 24 }); Protocol.CheckUnique(document);
        return JsonSerializer.Deserialize<T>(value, Json) ?? throw new Boundary("execution_audit_record_invalid");
    }
    private static bool Text(string? value, int maximum, bool empty = false) => value is not null && value.Length <= maximum
        && (empty || value.Length > 0) && !value.Any(char.IsControl);
    private static void Validate(AuditEvent value)
    {
        if (!Text(value.Kind, 80) || !Text(value.TaskId, 256, true) || !Text(value.RequestId, 128, true)
            || !Text(value.State, 80) || value.Target is not null && !Text(value.Target, 32767, true)
            || value.Reason is not null && !Text(value.Reason, 256, true)) throw new Boundary("execution_audit_event_invalid");
        if (value.Thread is { } thread && (thread.HostKind is not ("codex" or "claude-code" or "dsh-desktop")
            || !Text(thread.ThreadId, 256) || thread.Title is not null && !Text(thread.Title, 512, true)
            || !Text(thread.TitleSource, 80) || thread.TitleObservedUtc is not null
                && !DateTimeOffset.TryParseExact(thread.TitleObservedUtc, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out _)))
            throw new Boundary("execution_audit_thread_invalid");
    }
    private byte[] Read(string path, int maximum)
    {
        AuditFiles.Check(path, false);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > maximum) throw new Boundary("execution_audit_record_too_large");
        byte[] bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes); return bytes;
    }
    private Head ReadHead()
    {
        var bytes = Read(headPath, 4096); var checkpoint = Decode<Checkpoint>(bytes);
        var payload = Convert.FromBase64String(checkpoint.Payload); RequireMac(payload, checkpoint.Mac);
        var value = Decode<Head>(payload);
        if (value.Schema != 1 || !Guid.TryParseExact(value.StreamId, "N", out _) || value.Sequence < 0
            || !AdminProgramLaunch.Digest(value.Hash) || value.Segment < 1) throw new Boundary("execution_audit_checkpoint_invalid");
        headBytes = bytes; return value;
    }
    private void WriteHead(Head value)
    {
        byte[] payload = Encode(value), bytes = Encode(new Checkpoint(Convert.ToBase64String(payload), Mac(payload)));
        string pending = Path.Combine(root, "checkpoint." + Guid.NewGuid().ToString("N") + ".pending");
        AuditFiles.WriteNew(pending, bytes); File.Move(pending, headPath, true); AuditFiles.Check(headPath, false);
        if (!Read(headPath, 4096).SequenceEqual(bytes)) throw new Boundary("execution_audit_checkpoint_unconfirmed");
        headBytes = bytes; head = value;
    }
    private string Segment(int number) => Path.Combine(root, number.ToString("D8", CultureInfo.InvariantCulture) + ".jsonl");
    private SeenFile[] Inventory() => Directory.GetFiles(root, "*.jsonl").Order(StringComparer.Ordinal)
        .Select(path => { AuditFiles.Check(path, false); var info = new FileInfo(path); return new SeenFile(path, info.Length, info.LastWriteTimeUtc.Ticks); }).ToArray();

    private void Initialize()
    {
        if (head is not null) return;
        if (!File.Exists(keyPath))
        {
            if (File.Exists(headPath) || File.Exists(Path.Combine(root, "bootstrap.json"))
                || Directory.EnumerateFiles(root, "*.jsonl").Any()) throw new Boundary("execution_audit_key_missing");
            AuditFiles.WriteNew(keyPath, RandomNumberGenerator.GetBytes(32));
        }
        key = Read(keyPath, 32); if (key.Length != 32) throw new Boundary("execution_audit_key_invalid");
        if (!File.Exists(headPath))
        {
            string bootstrap = Path.Combine(root, "bootstrap.json");
            if (Directory.EnumerateFiles(root, "*.jsonl").Any()) throw new Boundary("execution_audit_checkpoint_missing");
            if (File.Exists(bootstrap))
            {
                // The MAC-valid genesis permits completing first initialization,
                // not inventing a new stream after its checkpoint was removed.
                var saved = Decode<Checkpoint>(Read(bootstrap, 4096)); var body = Convert.FromBase64String(saved.Payload);
                RequireMac(body, saved.Mac); var initial = Decode<Head>(body);
                if (initial.Schema != 1 || initial.Sequence != 0 || initial.Hash != Zero || initial.Segment != 1
                    || !Guid.TryParseExact(initial.StreamId, "N", out _)) throw new Boundary("execution_audit_bootstrap_invalid");
                WriteHead(initial);
            }
            else
            {
                var initial = new Head(1, Guid.NewGuid().ToString("N"), 0, Zero, 1); var body = Encode(initial);
                AuditFiles.WriteNew(bootstrap, Encode(new Checkpoint(Convert.ToBase64String(body), Mac(body)))); WriteHead(initial);
            }
        }
        VerifyFull(null, 0, false);
    }

    private void RequireUnchanged()
    {
        if (!Read(keyPath, 32).SequenceEqual(key)) throw new Boundary("execution_audit_storage_changed");
        if (headBytes is null || !Read(headPath, 4096).SequenceEqual(headBytes) || !Inventory().SequenceEqual(files))
            VerifyFull(null, 0, false);
    }
    internal AuditStamp Append(AuditEvent value, object? privateDetails = null)
    {
        // Invalid adapter input is not evidence of corrupt persistent state.
        Validate(value); if (Encode(value).Length > 48 * 1024) throw new Boundary("execution_audit_event_too_large");
        byte[]? detailBytes = privateDetails is null ? null : Encode(privateDetails);
        if (detailBytes?.Length > 64 * 1024) throw new Boundary("execution_audit_details_too_large");
        try { return Locked(() =>
        {
        if (faulted) throw new Boundary("execution_audit_faulted");
        Initialize(); RequireUnchanged(); var prior = head!;
        long sequence = checked(prior.Sequence + 1); string? nonce = null, ciphertext = null, tag = null;
        if (detailBytes is not null)
        {
            var plain = detailBytes;
            byte[] encryptionKey = HMACSHA256.HashData(key, "flower-audit-encryption-v1"u8), iv = RandomNumberGenerator.GetBytes(12), encrypted = new byte[plain.Length], authentication = new byte[16];
            try
            {
                using var aes = new AesGcm(encryptionKey, 16);
                aes.Encrypt(iv, plain, encrypted, authentication, Encoding.UTF8.GetBytes(prior.StreamId + ":" + sequence));
                nonce = Convert.ToBase64String(iv); ciphertext = Convert.ToBase64String(encrypted); tag = Convert.ToBase64String(authentication);
            }
            finally { CryptographicOperations.ZeroMemory(encryptionKey); CryptographicOperations.ZeroMemory(plain); }
        }
        var body = new Body(1, prior.StreamId, sequence, prior.Hash, DateTimeOffset.UtcNow.ToString("O"), value, nonce, ciphertext, tag);
        byte[] payload = Encode(body); string digest = Hash(payload);
        byte[] line = Encode(new Line(Convert.ToBase64String(payload), digest, Mac(payload)));
        if (line.Length > RecordBytes) throw new Boundary("execution_audit_record_too_large");
        int segment = prior.Segment; string path = Segment(segment);
        if (File.Exists(path) && new FileInfo(path).Length + line.Length + 1 > SegmentBytes) path = Segment(++segment);
        if (!File.Exists(path))
        {
            // Never publish an empty new segment; a crash leaves only a private
            // pending file, not an invalid canonical segment.
            var complete = new byte[line.Length + 1]; line.CopyTo(complete, 0); complete[^1] = (byte)'\n';
            string pending = path + "." + Guid.NewGuid().ToString("N") + ".pending";
            AuditFiles.WriteNew(pending, complete); File.Move(pending, path, false);
        }
        else
        {
            AuditFiles.Check(path, false);
            using var output = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
            output.Write(line); output.WriteByte((byte)'\n'); output.Flush(true);
        }
        WriteHead(new Head(1, prior.StreamId, sequence, digest, segment)); files = Inventory();
        return new AuditStamp(prior.StreamId, sequence, digest);
        }); }
        finally { if (detailBytes is not null) CryptographicOperations.ZeroMemory(detailBytes); }
    }

    // Explicit full verification detects historical edits as well as missing tails.
    // Append checks the cached authenticated head/inventory; it does not re-read the
    // whole history for every action. This is not an administrator-resistant seal.
    internal object History(string? taskId, int limit = 100, bool details = false, string? kind = null, string? requestId = null)
    {
        if (limit is < 0 or > 1000) throw new Boundary("execution_audit_limit_invalid");
        // Capture a consistent, bounded-by-segment prefix under the short lock.
        // Verify outside the writer lock; later appends are not part of this view.
        var snapshot = Locked(() =>
        {
            var reader = new ExecutionAudit(root, sid, session) { key = Read(keyPath, 32) };
            if (reader.key.Length != 32) throw new Boundary("execution_audit_key_invalid");
            return (Reader: reader, Head: reader.ReadHead(), Files: Inventory(),
                Notes: Directory.GetFiles(root, "*.recovery.json"),
                Archives: Directory.GetFiles(root, "*.quarantine.*").Where(path => !path.EndsWith(".recovery.json", StringComparison.Ordinal)).ToArray());
        }, createLock: false, latchFailure: false);
        try
        {
            object history;
            try { history = snapshot.Reader.VerifyFull(taskId, limit, details, false, snapshot.Head, snapshot.Files, kind, requestId); }
            catch (Exception error)
            {
                lock (gate) faulted = true;
                history = new { Integrity = "unverified", Reason = Program.Code(error), Snapshot = true };
            }
            // Recovery diagnostics remain visible even if the old bad tail was
            // never repaired before the previous process exited.
            object recoveries;
            bool recoveryVerified = true;
            bool preservationVerified = false;
            try
            {
                var observations = snapshot.Reader.RecoveryNotes(snapshot.Head.StreamId, snapshot.Notes, snapshot.Archives);
                recoveries = observations;
                preservationVerified = observations.All(note => note.State is "original_preserved" or "prepared_original_still_canonical");
            }
            catch (Exception error)
            {
                recoveryVerified = false;
                recoveries = new { Integrity = "unverified", Reason = Program.Code(error) };
            }
            return new { History = history, RecoveryTransactions = recoveries, RecoveryTransactionsIncluded = true,
                RecoveryNotesVerified = recoveryVerified, RecoveryPreservationVerified = preservationVerified };
        }
        finally { CryptographicOperations.ZeroMemory(snapshot.Reader.key); }
    }
    private RecoveryNote[] RecoveryNotes(string streamId, string[] notes, string[] archives)
    {
        var result = new List<RecoveryNote>(); var archiveHashes = new Dictionary<string, string>();
        foreach (string path in notes.Order(StringComparer.Ordinal))
        {
            var signed = Decode<Checkpoint>(Read(path, 16384)); var bytes = Convert.FromBase64String(signed.Payload); RequireMac(bytes, signed.Mac);
            using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document); var value = document.RootElement;
            if (value.GetProperty("Schema").GetInt32() != 1 || value.GetProperty("StreamId").GetString() != streamId)
                throw new Boundary("execution_audit_recovery_note_invalid");
            string digest = value.GetProperty("OriginalSha256").GetString()!;
            string original = value.GetProperty("OriginalPath").GetString()!, preserved = value.GetProperty("PreservedPath").GetString()!;
            if (!AdminProgramLaunch.Digest(digest) || Path.GetDirectoryName(original) != root || Path.GetDirectoryName(preserved) != root
                || !path.Equals(preserved + ".recovery.json", StringComparison.Ordinal)) throw new Boundary("execution_audit_recovery_note_invalid");
            bool saved = false; string? actualArchive = null;
            foreach (string candidate in archives)
            {
                if (!archiveHashes.TryGetValue(candidate, out var candidateDigest))
                    archiveHashes[candidate] = candidateDigest = Hash(Read(candidate, SegmentBytes));
                if (candidateDigest == digest) { saved = true; actualArchive = candidate; break; }
            }
            bool originalRetained = !saved && File.Exists(original) && Hash(Read(original, SegmentBytes)) == digest;
            result.Add(new RecoveryNote(path, value.Clone(), true, saved, actualArchive,
                saved ? "original_preserved" : originalRetained ? "prepared_original_still_canonical" : "preservation_unverified"));
        }
        return result.ToArray();
    }
    private object VerifyFull(string? taskId, int limit, bool details, bool commitRecovery = true, Head? snapshotHead = null, SeenFile[]? snapshotFiles = null,
        string? kind = null, string? requestId = null)
    {
        var cached = head; var expected = snapshotHead ?? ReadHead(); long sequence = 0; string previous = Zero;
        if (cached is not null && (cached.StreamId != expected.StreamId || expected.Sequence < cached.Sequence))
            throw new Boundary("execution_audit_rollback_detected");
        bool cachedSeen = cached is null || cached.Sequence == 0 && cached.Hash == Zero;
        bool checkpointSeen = expected.Sequence == 0 && expected.Hash == Zero;
        int currentSegment = 1; var result = new Queue<object>(); var inventory = snapshotFiles ?? Inventory();
        foreach (var file in inventory)
        {
            if (file.Path != Segment(currentSegment) || file.Length is < 1 or > SegmentBytes) throw new Boundary("execution_audit_segment_invalid");
            using var disk = new FileStream(file.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var prefix = new byte[checked((int)file.Length)]; disk.ReadExactly(prefix);
            if (prefix[^1] != '\n') throw new Boundary("execution_audit_tail_incomplete");
            using var input = new MemoryStream(prefix, false);
            using var reader = new StreamReader(input, new UTF8Encoding(false, true), false);
            while (reader.ReadLine() is { } text)
            {
                if (text.Length is < 1 or > RecordBytes) throw new Boundary("execution_audit_record_invalid");
                var line = Decode<Line>(Encoding.UTF8.GetBytes(text)); var bytes = Convert.FromBase64String(line.Payload);
                if (Hash(bytes) != line.Hash) throw new Boundary("execution_audit_hash_invalid"); RequireMac(bytes, line.Mac);
                var body = Decode<Body>(bytes); Validate(body.Event);
                if (body.Schema != 1 || body.StreamId != expected.StreamId || body.Sequence != ++sequence || body.PreviousHash != previous
                    || !DateTimeOffset.TryParseExact(body.Utc, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                    throw new Boundary("execution_audit_chain_invalid");
                previous = line.Hash;
                if (cached is not null && sequence == cached.Sequence) cachedSeen = line.Hash == cached.Hash;
                if (sequence == expected.Sequence) checkpointSeen = line.Hash == expected.Hash && currentSegment == expected.Segment;
                if (limit > 0 && (taskId is null || taskId == body.Event.TaskId)
                    && (kind is null || kind == body.Event.Kind) && (requestId is null || requestId == body.Event.RequestId))
                {
                    object? decoded = null;
                    if (details && body.Ciphertext is not null)
                    {
                        byte[] encryptionKey = HMACSHA256.HashData(key, "flower-audit-encryption-v1"u8), encrypted = Convert.FromBase64String(body.Ciphertext), plain = new byte[encrypted.Length];
                        try
                        {
                            using var aes = new AesGcm(encryptionKey, 16);
                            aes.Decrypt(Convert.FromBase64String(body.Nonce!), encrypted, Convert.FromBase64String(body.Tag!), plain,
                                Encoding.UTF8.GetBytes(body.StreamId + ":" + sequence));
                            using var document = JsonDocument.Parse(plain); decoded = document.RootElement.Clone();
                        }
                        finally { CryptographicOperations.ZeroMemory(encryptionKey); CryptographicOperations.ZeroMemory(plain); }
                    }
                    result.Enqueue(new { body.Sequence, body.Utc, body.Event, line.Hash, PrivateDetails = decoded, HasPrivateDetails = body.Ciphertext is not null });
                    if (result.Count > limit) result.Dequeue();
                }
            }
            ++currentSegment;
        }
        if (!cachedSeen || !checkpointSeen || expected.Sequence > sequence || sequence == 0 && expected.Segment != 1)
            throw new Boundary("execution_audit_checkpoint_mismatch");
        int lastSegment = Math.Max(1, currentSegment - 1);
        if (sequence > expected.Sequence && commitRecovery)
        {
            // Complete, MAC-valid records beyond the checkpoint can be a crash
            // after Flush(true). Adopt evidence only; never infer business success.
            WriteHead(new Head(1, expected.StreamId, sequence, previous, lastSegment));
        }
        else if (commitRecovery) head = expected;
        if (commitRecovery) files = Inventory();
        return new { Schema = 1, Integrity = "verified_local_chain", StreamId = expected.StreamId, Sequence = sequence,
            Hash = previous, CheckpointRecovered = commitRecovery && sequence > expected.Sequence,
            CheckpointBehind = sequence > expected.Sequence, Snapshot = !commitRecovery, Events = result.ToArray(),
            AdministratorTamperResistance = false, HistoryScope = "this_windows_user_and_session" };
    }

    // Explicit local maintenance only. It never discards committed history and
    // preserves the entire suspect final segment plus a durable recovery note.
    // Missing/changed committed evidence requires investigation, not this repair.
    internal object RecoverUncommittedTail()
    {
        var repair = Locked(() =>
        {
            key = Read(keyPath, 32); if (key.Length != 32) throw new Boundary("execution_audit_key_invalid");
            var committed = ReadHead(); long sequence = 0; string previous = Zero;
            bool committedSeen = committed.Sequence == 0 && committed.Hash == Zero;
            var inventory = Inventory(); string? archived = null, originalHash = null;
            int segment = 0; bool repaired = false;
            foreach (var file in inventory)
            {
                ++segment;
                if (file.Path != Segment(segment) || file.Length > SegmentBytes) throw new Boundary("execution_audit_segment_invalid");
                var bytes = Read(file.Path, SegmentBytes); int offset = 0, goodBytes = 0;
                while (offset < bytes.Length)
                {
                    int end = Array.IndexOf(bytes, (byte)'\n', offset);
                    try
                    {
                        if (end < offset || end - offset > RecordBytes) throw new Boundary("execution_audit_tail_incomplete");
                        var line = Decode<Line>(bytes[offset..end]); var payload = Convert.FromBase64String(line.Payload);
                        if (Hash(payload) != line.Hash) throw new Boundary("execution_audit_hash_invalid"); RequireMac(payload, line.Mac);
                        var body = Decode<Body>(payload); Validate(body.Event);
                        if (body.Schema != 1 || body.StreamId != committed.StreamId || body.Sequence != sequence + 1 || body.PreviousHash != previous
                            || !DateTimeOffset.TryParseExact(body.Utc, "O", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                            throw new Boundary("execution_audit_chain_invalid");
                        ++sequence; previous = line.Hash; goodBytes = end + 1; offset = end + 1;
                        if (sequence == committed.Sequence) committedSeen = line.Hash == committed.Hash && segment == committed.Segment;
                    }
                    catch (Exception error) when (error is Boundary or JsonException or FormatException or ArgumentException)
                    {
                        if (!committedSeen || sequence < committed.Sequence || segment != inventory.Length)
                            throw new Boundary("execution_audit_committed_history_damaged");
                        break;
                    }
                }
                if (goodBytes != bytes.Length || bytes.Length == 0)
                {
                    if (!committedSeen || sequence < committed.Sequence || segment != inventory.Length)
                        throw new Boundary("execution_audit_committed_history_damaged");
                    archived = file.Path + ".quarantine." + Guid.NewGuid().ToString("N"); originalHash = Hash(bytes);
                    var note = new { Schema = 1, committed.StreamId, CommittedSequence = committed.Sequence,
                        LastVerifiedSequence = sequence, LastVerifiedHash = previous, OriginalPath = file.Path, PreservedPath = archived,
                        OriginalSha256 = originalHash, OriginalLength = bytes.Length, VerifiedPrefixLength = goodBytes,
                        Utc = DateTimeOffset.UtcNow.ToString("O"), BusinessOutcome = "unknown" };
                    byte[] noteBytes = Encode(note); var signedNote = Encode(new Checkpoint(Convert.ToBase64String(noteBytes), Mac(noteBytes)));
                    AuditFiles.WriteNew(archived + ".recovery.json", signedNote);
                    if (goodBytes == 0) File.Move(file.Path, archived, false);
                    else
                    {
                        string pending = file.Path + ".repair." + Guid.NewGuid().ToString("N") + ".pending";
                        AuditFiles.WriteNew(pending, bytes[..goodBytes]); File.Replace(pending, file.Path, archived);
                    }
                    AuditFiles.Check(archived, false);
                    if (Hash(Read(archived, SegmentBytes)) != originalHash) throw new Boundary("execution_audit_preservation_unconfirmed");
                    repaired = true;
                    if (goodBytes == 0) --segment;
                    break;
                }
            }
            if (!committedSeen || sequence < committed.Sequence) throw new Boundary("execution_audit_committed_history_damaged");
            if (head is { } cached && (cached.StreamId != committed.StreamId || sequence < cached.Sequence))
                throw new Boundary("execution_audit_rollback_detected");
            WriteHead(new Head(1, committed.StreamId, sequence, previous, Math.Max(1, segment)));
            files = Inventory(); faulted = false;
            return new { RepairedTail = repaired, PreservedPath = archived, PreservedSha256 = originalHash, Sequence = sequence, BusinessOutcome = "unknown" };
        }, createLock: false);
        var stamp = Append(new AuditEvent("audit_recovery", "", "", "original_business_outcome_unchanged", Evidence: repair));
        return new { Repair = repair, Audit = stamp, Replay = false };
    }
}

// Private data and MAC keys must not inherit the normal SID read ACE used by
// permission files. Parent delete rights and reparse points are checked too.
internal static class AuditFiles
{
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { internal int Size; internal IntPtr Descriptor; internal int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateDirectoryW(string path, ref Attributes attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing, ref Attributes attributes, uint disposition, uint flags, IntPtr template);
    private static IntPtr Descriptor() => ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NW;;;HI)", 1, out var data, out _)
        ? data : throw new Boundary("execution_audit_descriptor_failed");
    internal static void Check(string path, bool directory)
    {
        BrokerPolicy.RejectLinks(path);
        if (directory) UserPermissions.CheckProtectionForDirectory(path); else UserPermissions.CheckProtection(path);
        FileSystemSecurity security = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        if (!security.AreAccessRulesProtected || security.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544"))
            throw new Boundary("execution_audit_storage_unprotected");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw new Boundary("execution_audit_storage_unprotected");
    }
    internal static void EnsureDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            var descriptor = Descriptor();
            try
            {
                var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
                if (!CreateDirectoryW(path, ref attributes) && Marshal.GetLastWin32Error() != 183) throw new Boundary("execution_audit_directory_failed");
            }
            finally { LocalFree(descriptor); }
        }
        Check(path, true);
    }
    internal static void WriteNew(string path, byte[] bytes)
    {
        Check(Path.GetDirectoryName(path)!, true); var descriptor = Descriptor();
        // Appending to an already staged binding name can exceed Win32's
        // MAX_PATH even when the destination is valid (249 -> 290 characters).
        // A short sibling keeps native CREATE_NEW and same-directory publication.
        string temporary = Path.Combine(Path.GetDirectoryName(path)!, ".writing." + Guid.NewGuid().ToString("N"));
        try
        {
            var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            using var handle = CreateFileW(temporary, 0x40000000, 1, ref attributes, 1, 0x80000000, IntPtr.Zero);
            if (handle.IsInvalid) throw new IOException("execution_audit_create_failed", Marshal.GetHRForLastWin32Error());
            using var stream = new FileStream(handle, FileAccess.Write); stream.Write(bytes); stream.Flush(true);
        }
        finally { LocalFree(descriptor); }
        File.Move(temporary, path, false);
        Check(path, false);
    }
}
