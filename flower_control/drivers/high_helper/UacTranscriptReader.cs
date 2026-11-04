using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed record UacTranscriptSnapshot(string SessionId, string? TurnId, string PromptDigest,
    string EventDigest, string Timestamp, long Position, long RecordEnd, long Cursor)
{
    internal string? NativeSubmittedPromptDigest { get; init; }
    internal string PromptComparison(string digest) => PromptDigest == digest ? "exact"
        : NativeSubmittedPromptDigest == digest ? "native_text_terminator" : "mismatch";
}

// Only a previously authenticated native Hook may choose path/session. This reader
// observes user-message identity; it does not interpret text or mint authorization.
// Old history is never replayed as a grant. Anchors detect header/cursor mutation,
// NOT arbitrary edits to the already-consumed middle of a large transcript.
internal static class UacTranscriptReader
{
    private const int MaxEntries = 64, AnchorSize = 4096, MaxLine = 16 * 1024 * 1024;
    // A work bound per batch, not a maximum lifetime length for a chat.
    private const long MaxScan = 256L * 1024 * 1024;
    private const int MaxBatches = 3;
    private static readonly object Gate = new();
    private static readonly Dictionary<string, Entry> Entries = new(StringComparer.OrdinalIgnoreCase);
    private static long useOrder;
    private sealed class Entry
    {
        internal readonly object Sync = new();
        internal State? State;
        // Users includes readers waiting for Sync, so eviction can never create
        // two live locks for the same normalized path.
        internal int Users;
        internal long LastUse;
    }
    private sealed class State
    {
        internal required string Session, Identity, ParentIdentity, FinalPath;
        internal long Cursor;
        internal int HeaderLength;
        internal string Header = "", Tail = "";
        internal string? Turn;
        internal UacTranscriptSnapshot? Latest;
        internal bool Invalidated;
    }

    internal static UacTranscriptSnapshot Read(string path, string sessionId)
    {
        ValidateId(sessionId);
        var key = ValidatePath(path);
        Entry entry;
        lock (Gate)
        {
            if (!Entries.TryGetValue(key, out entry!))
            {
                if (Entries.Count >= MaxEntries)
                {
                    var idle = Entries.Where(pair => pair.Value.Users == 0).MinBy(pair => pair.Value.LastUse);
                    if (idle.Value is null) throw Fail("cache_busy");
                    Entries.Remove(idle.Key);
                }
                Entries[key] = entry = new Entry();
            }
            entry.Users++;
            entry.LastUse = ++useOrder;
        }
        try { lock (entry.Sync) return ReadEntry(key, sessionId, entry); }
        finally { lock (Gate) { entry.Users--; entry.LastUse = ++useOrder; } }
    }

    // No global cache lock is held during path opening, hashing or parsing.
    private static UacTranscriptSnapshot ReadEntry(string key, string sessionId, Entry entry)
    {
        for (int batch = 0; batch < MaxBatches; batch++)
        {
            var previous = entry.State;
            if (previous is { Invalidated: true }) throw Fail("identity_invalidated");
            if (previous is not null && previous.Session != sessionId) throw Fail("session_changed");
            using var opened = Open(key);
            var stream = opened.Stream;
            var before = Info(stream.SafeFileHandle);
            var identity = Identity(before);
            if (previous is not null && (previous.Identity != identity
                || previous.ParentIdentity != opened.ParentIdentity || previous.FinalPath != opened.FinalPath
                || before.Size < previous.Cursor)) Invalidate(previous);
            if (previous is not null && (HashRange(stream, 0, previous.HeaderLength) != previous.Header
                || HashRange(stream, Math.Max(0, previous.Cursor - AnchorSize), (int)Math.Min(AnchorSize, previous.Cursor)) != previous.Tail))
                Invalidate(previous);
            var state = new State { Session = sessionId, Identity = identity, ParentIdentity = opened.ParentIdentity,
                FinalPath = opened.FinalPath, Cursor = previous?.Cursor ?? 0, Turn = previous?.Turn,
                Latest = previous?.Latest };
            long batchStart = state.Cursor, limit = Math.Min(before.Size, batchStart + MaxScan);
            stream.Position = state.Cursor;
            using var line = new MemoryStream();
            using var consumed = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536];
            long position = state.Cursor, lineStart = position;
            while (position < limit)
            {
                var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, limit - position));
                if (read == 0) throw Fail("changed_during_read");
                int offset = 0;
                while (offset < read)
                {
                    int newline = buffer.AsSpan(offset, read - offset).IndexOf((byte)'\n');
                    int count = newline < 0 ? read - offset : newline;
                    if (line.Length + count > MaxLine) throw Fail("line_budget");
                    line.Write(buffer, offset, count);
                    offset += count; position += count;
                    if (newline >= 0)
                    {
                        offset++; position++;
                        var bytes = line.GetBuffer().AsMemory(0, (int)line.Length);
                        Parse(bytes, state, lineStart, position);
                        // Only successful complete records enter the checkpoint
                        // digest. Include the original CR (if any) and LF bytes.
                        consumed.AppendData(bytes.Span);
                        consumed.AppendData("\n"u8);
                        line.SetLength(0); lineStart = position;
                    }
                }
            }

            // A growing file is safe to checkpoint only if the exact bytes that
            // were parsed still match. Size growth alone is NOT append proof:
            // a writer could overwrite an earlier user record and append too.
            long completeEnd = lineStart;
            // Do not cache a zero-length header anchor before session_meta is
            // complete. It would otherwise remain empty after later appends.
            if (completeEnd == 0)
                throw Fail(line.Length != 0 ? "incomplete_record" : "user_message_unavailable");
            var verifyBefore = Info(stream.SafeFileHandle);
            if (Identity(verifyBefore) != identity || verifyBefore.Size < before.Size)
                throw Fail("changed_during_read");
            var observed = Convert.ToHexString(consumed.GetHashAndReset()).ToLowerInvariant();
            if (HashRange(stream, batchStart, completeEnd - batchStart) != observed)
                throw Fail("prefix_changed");
            if (previous is not null && (HashRange(stream, 0, previous.HeaderLength) != previous.Header
                || HashRange(stream, Math.Max(0, previous.Cursor - AnchorSize), Math.Min(AnchorSize, previous.Cursor)) != previous.Tail))
                Invalidate(previous);
            state.Cursor = completeEnd;
            state.HeaderLength = previous?.HeaderLength ?? (int)Math.Min(AnchorSize, completeEnd);
            state.Header = HashRange(stream, 0, state.HeaderLength);
            state.Tail = HashRange(stream, Math.Max(0, completeEnd - AnchorSize), Math.Min(AnchorSize, completeEnd));
            ValidatePath(key);
            using (var current = CreateFileW(key, 0, 3, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
                if (current.IsInvalid || Identity(Info(current)) != identity || FinalPath(current) != opened.FinalPath)
                    throw Fail("path_changed");
            var after = Info(stream.SafeFileHandle);
            if (verifyBefore != after) throw Fail("changed_during_read");
            if (previous is not null && state.Header != previous.Header) Invalidate(previous);
            if (state.Latest is not null) state.Latest = state.Latest with { Cursor = completeEnd };
            // The broker's protected grant is bound to EventDigest and NEVER
            // reconstructed from these observations. Eviction may cause a fresh
            // scan, not a new grant; replacement has a different file identity.
            entry.State = state;
            // A true EOF partial record can hide a newer user message; a batch
            // boundary partial is instead reread from its complete predecessor.
            if (position == before.Size && line.Length != 0) throw Fail("incomplete_record");
            if (completeEnd == after.Size)
                return state.Latest ?? throw Fail("user_message_unavailable");
        }
        // Retain verified progress without ever returning a stale Latest.
        throw Fail("scan_in_progress");
    }

    private static void Parse(ReadOnlyMemory<byte> bytes, State state, long start, long end)
    {
        if (bytes.Length == 0) throw Fail("empty_record");
        using var json = JsonDocument.Parse(bytes);
        CheckUnique(json.RootElement);
        var root = json.RootElement;
        var type = Text(root, "type");
        if (start == 0)
        {
            if (type != "session_meta" || !root.TryGetProperty("payload", out var meta)
                || Text(meta, "id") != state.Session) throw Fail("session_header_mismatch");
            return;
        }
        if (type == "session_meta") throw Fail("repeated_session_header");
        if (!root.TryGetProperty("payload", out var payload)) return;
        if (type == "turn_context")
        {
            state.Turn = Text(payload, "turn_id");
            if (state.Turn is not null) ValidateId(state.Turn);
            return;
        }
        if (type != "response_item" || Text(payload, "type") != "message" || Text(payload, "role") != "user") return;
        if (!payload.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array)
            throw Fail("user_content_unavailable");
        if (IsInjectedNativeContext(payload, content)) return;
        var parts = new List<string>();
        foreach (var part in content.EnumerateArray())
        {
            var kind = Text(part, "type");
            if (kind is "text" or "input_text")
            {
                var text = Text(part, "text");
                if (text is null) throw Fail("user_content_unavailable");
                parts.Add(text);
            }
        }
        if (parts.Count == 0) throw Fail("user_content_unavailable");
        var timestamp = Text(root, "timestamp");
        // Require an explicit offset and preserve the exact source timestamp.
        if (timestamp is null || timestamp.Length > 64 || !HasOffset(timestamp)
            || !DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
            throw Fail("timestamp_invalid");
        var turn = payload.TryGetProperty("internal_chat_message_metadata_passthrough", out var metadata)
            ? Text(metadata, "turn_id") : null;
        turn ??= Text(payload, "turn_id") ?? state.Turn;
        if (turn is not null) ValidateId(turn);
        state.Latest = new(state.Session, turn, Hash(Encoding.UTF8.GetBytes(string.Join("\n", parts))),
            Hash(Encoding.UTF8.GetBytes(state.Identity + "\0" + start.ToString(CultureInfo.InvariantCulture) + "\0" + Hash(bytes.Span))),
            timestamp, start, end, end)
        { NativeSubmittedPromptDigest = SubmittedNativeTextDigest(payload, content, parts) };
    }

    private static string? SubmittedNativeTextDigest(JsonElement payload, JsonElement content, List<string> parts)
    {
        // Codex serializes an attributed single user.text item with one final LF
        // that is absent from UserPromptSubmit.prompt. Keep the raw digest and
        // record identity intact; admit only this exact native representation.
        // Never Trim/TrimEnd: user-authored whitespace and original newlines
        // must survive, and unknown/mixed/legacy provenance stays exact-only.
        if (content.GetArrayLength() != 1 || parts.Count != 1 || !parts[0].EndsWith('\n')
            || !payload.TryGetProperty("internal_chat_message_metadata_passthrough", out var metadata)
            || metadata.ValueKind != JsonValueKind.Object
            || !metadata.TryGetProperty("content_item_kinds", out var kinds)
            || kinds.ValueKind != JsonValueKind.Array || kinds.GetArrayLength() != 1
            || kinds[0].ValueKind != JsonValueKind.String || kinds[0].GetString() != "user.text"
            || !metadata.TryGetProperty("content_item_metadata", out var items)
            || items.ValueKind != JsonValueKind.Array || items.GetArrayLength() != 1
            || items[0].ValueKind != JsonValueKind.Object
            || !items[0].TryGetProperty("provenance", out var provenance)
            || Text(provenance, "type") != "user") return null;
        return Hash(Encoding.UTF8.GetBytes(parts[0][..^1]));
    }

    private static bool IsInjectedNativeContext(JsonElement payload, JsonElement content)
    {
        // Native Codex context refreshes use role=user too. Only the paired
        // host provenance marks them as context; matching '# AGENTS.md' text
        // must never hide a real user's restriction or select an older prompt.
        if (!payload.TryGetProperty("internal_chat_message_metadata_passthrough", out var metadata)
            || metadata.ValueKind != JsonValueKind.Object) return false;
        bool hasKinds = metadata.TryGetProperty("content_item_kinds", out var kinds);
        bool hasItems = metadata.TryGetProperty("content_item_metadata", out var items);
        if (!hasKinds && !hasItems) return false; // Older native records.
        int count = content.GetArrayLength();
        if (hasKinds && !hasItems)
        {
            // Older Codex records have kinds but no paired provenance. They
            // remain ordinary latest-message candidates, even for AGENTS kinds:
            // an unproven context record must never revive a prior user's grant.
            if (kinds.ValueKind != JsonValueKind.Array || kinds.GetArrayLength() != count
                || kinds.EnumerateArray().Any(kind => kind.ValueKind != JsonValueKind.String))
                throw Fail("user_provenance_invalid");
            return false;
        }
        if (!hasKinds || !hasItems || kinds.ValueKind != JsonValueKind.Array || items.ValueKind != JsonValueKind.Array
            || kinds.GetArrayLength() != count || items.GetArrayLength() != count)
            throw Fail("user_provenance_invalid");
        int context = 0, environments = 0;
        for (int i = 0; i < count; ++i)
        {
            var kind = kinds[i].ValueKind == JsonValueKind.String ? kinds[i].GetString() : null;
            var origin = items[i].ValueKind == JsonValueKind.Object
                && items[i].TryGetProperty("provenance", out var provenance) ? Text(provenance, "type") : null;
            if (kind == "agents_md.instructions" || origin == "agents_md")
            {
                if (kind != "agents_md.instructions" || origin != "agents_md") throw Fail("user_provenance_invalid");
                ++context;
            }
            else if (kind == "environments.environment_context" && origin == "harness"
                && items[i].GetProperty("provenance").TryGetProperty("hook", out var hook)
                && hook.ValueKind == JsonValueKind.False)
                ++environments;
        }
        // Codex also appends standalone harness environment refreshes during
        // compaction. Their exact paired kind/provenance is context regardless
        // of whether AGENTS accompanies it; never replace the human watermark.
        // Unknown provenance, hook-produced text and real user records remain
        // latest candidates. A mixed recognized-context/user bundle is invalid.
        int recognized = context + environments;
        if (recognized != 0 && recognized != count) throw Fail("user_provenance_invalid");
        return recognized != 0;
    }

    private static bool HasOffset(string text)
    {
        int t = text.IndexOf('T');
        return t > 0 && (text.EndsWith('Z') || text.LastIndexOf('+') > t || text.LastIndexOf('-') > t);
    }
    private static string? Text(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
    private static void CheckUnique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var prop in value.EnumerateObject())
            { if (!names.Add(prop.Name)) throw Fail("duplicate_field"); CheckUnique(prop.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) CheckUnique(item);
    }
    private static void ValidateId(string value)
    {
        if (value.Length is < 1 or > 256 || value != value.Trim() || value.Any(char.IsControl)) throw Fail("identity_invalid");
    }
    internal static string NormalizeLocalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 32000 || path.Any(char.IsControl))
            throw Fail("path_invalid");
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            // Accept only the canonical extended spelling of a DOS drive
            // path, never UNC, device namespaces, ADS or aliases whose Win32
            // normalization could change the selected file.
            if (path.Length < 7 || !char.IsAsciiLetter(path[4]) || path[5] != ':' || path[6] != '\\')
                throw Fail("path_invalid");
            path = path[4..];
            var parts = path[3..].Split('\\');
            if (path.Contains('/') || parts.Any(part => part.Length == 0 || part is "." or ".."
                    || part.EndsWith(' ') || part.EndsWith('.')
                    || System.Text.RegularExpressions.Regex.IsMatch(part.Split('.')[0].TrimEnd(' '),
                        "\\A(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\\$|CONOUT\\$)\\z",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant)))
                throw Fail("path_invalid");
        }
        if (path.StartsWith("\\", StringComparison.Ordinal) || path.Length < 3 || path[1] != ':'
            || !char.IsAsciiLetter(path[0]) || (path[2] != '\\' && path[2] != '/') || path[2..].Contains(':'))
            throw Fail("path_invalid");
        return Path.GetFullPath(path);
    }
    private static string ValidatePath(string path)
    {
        var full = NormalizeLocalPath(path);
        // The user's configured .codex junction is an admitted path alias, never
        // the identity. No other lexical reparse component is allowed.
        var allowed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".codex");
        for (string? current = full; current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0
                && !current.Equals(allowed, StringComparison.OrdinalIgnoreCase)) throw Fail("reparse_path");
        return full;
    }
    private sealed class Opened(FileStream stream, string finalPath, string parentIdentity, List<SafeFileHandle> parents) : IDisposable
    {
        internal FileStream Stream = stream;
        internal string FinalPath = finalPath, ParentIdentity = parentIdentity;
        public void Dispose() { Stream.Dispose(); foreach (var parent in parents) parent.Dispose(); }
    }
    private static Opened Open(string path)
    {
        var parents = new List<SafeFileHandle>();
        FileStream? stream = null;
        try
        {
            var file = CreateFileW(path, 0x80000000, 3, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            if (file.IsInvalid) { file.Dispose(); throw Fail("open_failed"); }
            stream = new FileStream(file, FileAccess.Read);
            var info = Info(file);
            if ((info.Attributes & (0x400u | 0x10u)) != 0) throw Fail("reparse_file");
            var final = FinalPath(file);
            var identities = new List<string>();
            // Pin each REAL parent against replacement while reading. Resolve the
            // .codex junction first, then reject reparse points on the real chain.
            for (string? current = Path.GetDirectoryName(final); current is not null; current = Path.GetDirectoryName(current))
            {
                var parent = CreateFileW(current, 0, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                parents.Add(parent);
                if (parent.IsInvalid) throw Fail("parent_unavailable");
                var parentInfo = Info(parent);
                if ((parentInfo.Attributes & 0x400) != 0) throw Fail("reparse_parent");
                identities.Add(Identity(parentInfo));
            }
            // Verify the supplied alias still resolves to the same handle path.
            using var again = CreateFileW(path, 0, 3, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            if (again.IsInvalid || Identity(Info(again)) != Identity(info) || FinalPath(again) != final) throw Fail("path_changed");
            return new Opened(stream, final, string.Join("/", identities), parents);
        }
        catch { stream?.Dispose(); foreach (var parent in parents) parent.Dispose(); throw; }
    }
    private static string FinalPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(32768);
        var count = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (count == 0 || count >= buffer.Capacity) throw Fail("final_path_unavailable");
        var path = buffer.ToString();
        if (!path.StartsWith("\\\\?\\", StringComparison.Ordinal) || path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            throw Fail("remote_path");
        var normalized = path[4..];
        if (normalized.Length < 3 || normalized[1] != ':' || normalized[2..].Contains(':')) throw Fail("final_path_invalid");
        return normalized;
    }
    private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static string HashRange(FileStream stream, long offset, long count)
    {
        stream.Position = offset;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[(int)Math.Min(65536, count)];
        while (count > 0)
        {
            int read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, count));
            if (read == 0) throw Fail("changed_during_read");
            hash.AppendData(buffer, 0, read); count -= read;
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
    private static void Invalidate(State state) { state.Invalidated = true; state.Latest = null; throw Fail("identity_changed"); }
    private static InvalidDataException Fail(string code) => new("uac_transcript_" + code);
    private readonly record struct FileInfo(uint Attributes, uint Volume, uint IndexHigh, uint IndexLow, long Size, long Written, long Created);
    private static FileInfo Info(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var value)) throw Fail("identity_unavailable");
        return new(value.Attributes, value.Volume, value.IndexHigh, value.IndexLow,
            ((long)value.SizeHigh << 32) | value.SizeLow, ((long)value.WriteHigh << 32) | value.WriteLow,
            ((long)value.CreateHigh << 32) | value.CreateLow);
    }
    private static string Identity(FileInfo info) => $"{info.Volume:x8}:{info.IndexHigh:x8}{info.IndexLow:x8}:{info.Created:x16}";
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleInfo
    {
        internal uint Attributes, CreateLow, CreateHigh, AccessLow, AccessHigh, WriteLow, WriteHigh,
            Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}

// Fixtures create only synthetic JSONL under the OS temporary root. No actual
// chats, UI, UAC, broker policy, protected storage or installation are accessed.
internal static class UacTranscriptReaderTests
{
    internal static int Run()
    {
        var directory = Path.Combine(Path.GetTempPath(), "flower-transcript-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        int checks = 0;
        void Check(bool value) { if (!value) throw new InvalidOperationException("transcript_fixture_failed"); checks++; }
        string Meta(string session) => JsonSerializer.Serialize(new { type = "session_meta", payload = new { id = session } }) + "\n";
        string Message(string text, string role = "user", string timestamp = "2026-10-15T01:00:00.000Z") => JsonSerializer.Serialize(new
        { timestamp, type = "response_item", payload = new { type = "message", role, turn_id = "turn", content = new[] { new { type = "input_text", text } } } }) + "\n";
        string FileOf(string name, string body) { var path = Path.Combine(directory, name + ".jsonl"); File.WriteAllText(path, body, new UTF8Encoding(false)); return path; }
        void Rejected(Action action) { try { action(); } catch (InvalidDataException) { checks++; return; } throw new InvalidOperationException("transcript_fixture_not_rejected"); }
        var main = FileOf("aba", Meta("session") + Message("A"));
        var a = UacTranscriptReader.Read(main, "session");
        Check(UacTranscriptReader.NormalizeLocalPath(@"\\?\" + main) == main);
        Check(UacTranscriptReader.Read(@"\\?\" + main, "session").EventDigest == a.EventDigest);
        foreach (var invalid in new[] { @"\\?\UNC\server\share\file.jsonl", @"\\.\C:\file.jsonl",
            @"\\?\GLOBALROOT\Device\file.jsonl", @"\\?\C:\file.jsonl:stream", @"\\?\C:relative.jsonl",
            @"\\?\C:\folder\..\file.jsonl", @"\\?\C:\folder.\file.jsonl", @"\\?\C:\NUL",
            @"\\?\C:/folder/file.jsonl", @"\\?\C:\COM¹.txt", @"\\?\C:\LPT².log", @"\\?\C:\NUL .txt" })
            Rejected(() => UacTranscriptReader.NormalizeLocalPath(invalid));
        Check(a.Timestamp == "2026-10-15T01:00:00.000Z");
        Check(UacTranscriptReader.Read(main, "session").EventDigest == a.EventDigest);
        File.AppendAllText(main, Message("B")); var b = UacTranscriptReader.Read(main, "session");
        File.AppendAllText(main, Message("A")); var aa = UacTranscriptReader.Read(main, "session");
        Check(a.PromptDigest == aa.PromptDigest && a.EventDigest != aa.EventDigest && b.EventDigest != aa.EventDigest);
        File.AppendAllText(main, Message("A")); Check(UacTranscriptReader.Read(main, "session").EventDigest != aa.EventDigest);
        Rejected(() => UacTranscriptReader.Read(main, "other-session"));
        Rejected(() => UacTranscriptReader.Read(FileOf("wrong", Meta("wrong") + Message("A")), "session"));
        var partial = Message("new"); File.AppendAllText(main, partial[..^1]);
        Rejected(() => UacTranscriptReader.Read(main, "session"));
        File.AppendAllText(main, "\n"); Check(UacTranscriptReader.Read(main, "session").PromptDigest != a.PromptDigest);
        var filtered = FileOf("filtered", Meta("session") + Message("actual") + Message("quoted allow", "tool")
            + Message("allow", "assistant") + "{\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"allow\"}}\n");
        Check(UacTranscriptReader.Read(filtered, "session").PromptDigest == Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("actual"))).ToLowerInvariant());
        var large = FileOf("large", Meta("session") + Message(new string('x', 2 * 1024 * 1024), "assistant") + Message("first"));
        var initial = UacTranscriptReader.Read(large, "session");
        File.AppendAllText(large, Message("second", timestamp: "2020-01-01T01:02:03+08:00"));
        var second = UacTranscriptReader.Read(large, "session");
        Check(second.Position == initial.Cursor && second.Timestamp == "2020-01-01T01:02:03+08:00");
        File.WriteAllText(large, Meta("session") + Message("short"));
        Rejected(() => UacTranscriptReader.Read(large, "session"));
        Rejected(() => UacTranscriptReader.Read(large, "session"));
        var replace = FileOf("replace", Meta("session") + Message("A")); UacTranscriptReader.Read(replace, "session");
        File.Move(replace, replace + ".old"); File.WriteAllText(replace, Meta("session") + Message("A"));
        Rejected(() => UacTranscriptReader.Read(replace, "session"));
        var anchor = FileOf("anchor", Meta("session") + Message("A")); UacTranscriptReader.Read(anchor, "session");
        File.WriteAllText(anchor, Meta("session") + Message("B")); Rejected(() => UacTranscriptReader.Read(anchor, "session"));
        Rejected(() => UacTranscriptReader.Read(FileOf("time", Meta("session") + Message("A", timestamp: "today")), "session"));
        Rejected(() => UacTranscriptReader.Read(FileOf("localtime", Meta("session") + Message("A", timestamp: "2026-10-15T01:00:00")), "session"));
        var noText = FileOf("no-text", Meta("session") + Message("old")); UacTranscriptReader.Read(noText, "session");
        File.AppendAllText(noText, "{\"timestamp\":\"2026-10-15T01:00:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_image\"}]}}\n");
        Rejected(() => UacTranscriptReader.Read(noText, "session"));
        Rejected(() => UacTranscriptReader.Read(FileOf("duplicate", Meta("session") + Message("A")
            + "{\"type\":\"response_item\",\"type\":\"event_msg\"}\n"), "session"));
        Rejected(() => UacTranscriptReader.Read(FileOf("misplaced-header", Message("A") + Meta("session")), "session"));
        Rejected(() => UacTranscriptReader.Read(main + ":stream", "session"));
        Rejected(() => UacTranscriptReader.Read("\\\\localhost\\c$\\fake.jsonl", "session"));
        string? firstEvent = null;
        for (int i = 0; i < 70; i++)
        {
            var item = UacTranscriptReader.Read(FileOf("lru-" + i, Meta("session") + Message("A")), "session");
            if (i == 0) firstEvent = item.EventDigest;
            Check(item.PromptDigest == a.PromptDigest);
        }
        // A rescan after eviction retains the same event identity and does not
        // refresh source time. It is not evidence of fresh user authorization.
        var firstLru = Path.Combine(directory, "lru-0.jsonl");
        var reread = UacTranscriptReader.Read(firstLru, "session");
        Check(reread.Timestamp == a.Timestamp && reread.PromptDigest == a.PromptDigest && reread.EventDigest == firstEvent);
        var contextual = "{\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"context-turn\"}}\n";
        var nativeTurn = Message("A").Replace("\"turn_id\":\"turn\"",
            "\"turn_id\":\"payload-turn\",\"internal_chat_message_metadata_passthrough\":{\"turn_id\":\"native-turn\"}", StringComparison.Ordinal);
        Check(UacTranscriptReader.Read(FileOf("native-turn", Meta("session") + contextual + nativeTurn), "session").TurnId == "native-turn");
        Check(UacTranscriptReader.Read(FileOf("payload-turn", Meta("session") + contextual + Message("A")), "session").TurnId == "turn");
        Check(UacTranscriptReader.Read(FileOf("context-turn", Meta("session") + contextual
            + Message("A").Replace("\"turn_id\":\"turn\",", "", StringComparison.Ordinal)), "session").TurnId == "context-turn");

        // Deterministic lock test: hold one already-created entry's gate, wait
        // until its reader is queued, then require another path to finish. This
        // tests isolation without depending on file size or disk timing. Also
        // churn LRU while the first reader waits: its entry must not be evicted.
        var blockedPath = FileOf("parallel-blocked", Meta("session") + Message("A"));
        var otherPath = FileOf("parallel-other", Meta("session") + Message("B"));
        UacTranscriptReader.Read(blockedPath, "session");
        var readerType = typeof(UacTranscriptReader);
        var staticFlags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static;
        var instanceFlags = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance;
        var cacheGate = readerType.GetField("Gate", staticFlags)!.GetValue(null)!;
        var entries = (System.Collections.IDictionary)readerType.GetField("Entries", staticFlags)!.GetValue(null)!;
        object blockedEntry;
        lock (cacheGate) blockedEntry = entries[blockedPath]!;
        var entryGate = blockedEntry.GetType().GetField("Sync", instanceFlags)!.GetValue(blockedEntry)!;
        var usersField = blockedEntry.GetType().GetField("Users", instanceFlags)!;
        Task<UacTranscriptSnapshot> blockedRead;
        lock (entryGate)
        {
            blockedRead = Task.Factory.StartNew(() => UacTranscriptReader.Read(blockedPath, "session"),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Check(SpinWait.SpinUntil(() =>
            {
                if (!Monitor.TryEnter(cacheGate, 20)) return false;
                try { return (int)usersField.GetValue(blockedEntry)! > 0; }
                finally { Monitor.Exit(cacheGate); }
            }, 3000));
            var otherRead = Task.Factory.StartNew(() => UacTranscriptReader.Read(otherPath, "session"),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Check(otherRead.Wait(3000) && otherRead.Result.PromptDigest == b.PromptDigest);
            for (int i = 0; i < 70; i++)
                UacTranscriptReader.Read(FileOf("parallel-churn-" + i, Meta("session") + Message("A")), "session");
            lock (cacheGate) Check(ReferenceEquals(entries[blockedPath], blockedEntry));
        }
        Check(blockedRead.Wait(3000) && blockedRead.Result.PromptDigest == a.PromptDigest);
        return checks;
    }
}
