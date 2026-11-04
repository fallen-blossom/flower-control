using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed record DshTranscriptSnapshot(UacTranscriptSnapshot Message, long RelevantSequence, long Sequence);

// Read one exact, flushed DSH session. The decoder receives bytes from this
// already-open handle, never a caller-selected file to open by itself.
internal static class DshTranscriptReader
{
    private const int Limit = 128 * 1024 * 1024;
    private sealed record Seen(string FileId, int Length, string Digest, DshTranscriptSnapshot Snapshot);
    private static readonly object Gate = new();
    private static readonly Dictionary<string, Seen> Files = new(StringComparer.OrdinalIgnoreCase);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    [StructLayout(LayoutKind.Sequential, Pack = 4)] private struct FileInfo
    { internal uint Attributes; internal long Created, Accessed, Written; internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint count, uint flags);

    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static string Hash(string text) => Hash(Utf8.GetBytes(text));
    internal static string SessionHash(string id) => Hash("flower-session-v1\0dsh-desktop\0" + id);

    internal static void CheckHandle(FileStream file, string path)
    {
        var canonical = new StringBuilder(32768);
        uint count = GetFinalPathNameByHandleW(file.SafeFileHandle, canonical, (uint)canonical.Capacity, 0);
        if (count == 0 || count >= canonical.Capacity || !canonical.ToString().StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Path.GetFullPath(canonical.ToString()[4..]).Equals(Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("dsh_transcript_identity_unavailable");
    }

    internal static void CheckPath(string path, string root)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal)
            || path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).Any(p => p is "." or ".."))
            throw new Boundary("dsh_transcript_path_rejected");
        string full = Path.GetFullPath(path), parent = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!full.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || Path.GetRelativePath(parent, full).Split(Path.DirectorySeparatorChar).Length != 3
            || Path.GetFileName(full) is not ("session.v4.jsonl" or "session.v4.jsonl.zstd"))
            throw new Boundary("dsh_transcript_path_rejected");
        BrokerPolicy.RejectLinks(full);
    }

    internal static DshTranscriptSnapshot Read(string path, string session, string root, NativeHostRule decoder)
    {
        CheckPath(path, root);
        lock (Gate)
        {
            if (!Files.ContainsKey(path) && Files.Count >= 2048) throw new Boundary("dsh_transcript_binding_limit");
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var canonical = new StringBuilder(32768);
            uint count = GetFinalPathNameByHandleW(file.SafeFileHandle, canonical, (uint)canonical.Capacity, 0);
            if (count == 0 || count >= canonical.Capacity || !canonical.ToString().StartsWith(@"\\?\", StringComparison.Ordinal)
                || !Path.GetFullPath(canonical.ToString()[4..]).Equals(Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase)
                || !GetFileInformationByHandle(file.SafeFileHandle, out var identity))
                throw new Boundary("dsh_transcript_identity_unavailable");
            string fileId = identity.Volume + ":" + identity.IndexHigh + ":" + identity.IndexLow;
            if (file.Length is <= 0 or > Limit) throw new Boundary("dsh_transcript_size_rejected");
            var raw = new byte[(int)file.Length]; file.ReadExactly(raw);
            if (Files.TryGetValue(path, out var seen) && (seen.FileId != fileId || raw.Length < seen.Length
                || Hash(raw.AsSpan(0, seen.Length)) != seen.Digest)) throw new Boundary("dsh_transcript_history_changed");
            if (seen is not null && seen.Snapshot.Message.SessionId != session)
                throw new Boundary("dsh_transcript_header_rejected");
            var result = seen is not null && raw.Length == seen.Length ? seen.Snapshot
                : Parse(path.EndsWith(".zstd", StringComparison.Ordinal) ? Decode(raw, decoder) : raw, session);
            // An append, replacement or same-length rewrite while decoding is
            // unavailable, rather than permission to use the earlier prefix.
            if (file.Length != raw.Length) throw new Boundary("dsh_transcript_changed_during_read");
            file.Position = 0; var current = new byte[raw.Length]; file.ReadExactly(current);
            if (file.Length != raw.Length || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(raw), SHA256.HashData(current)))
                throw new Boundary("dsh_transcript_changed_during_read");
            BrokerPolicy.RejectLinks(path);
            Files[path] = new(fileId, raw.Length, Hash(raw), result);
            return result;
        }
    }

    private static byte[] Decode(byte[] raw, NativeHostRule rule)
    {
        if (rule.Kind != "dsh-desktop") throw new Boundary("dsh_transcript_decoder_rejected");
        BrokerPolicy.RejectLinks(rule.Path);
        using var pin = new FileStream(rule.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Convert.ToHexString(SHA256.HashData(pin)).ToLowerInvariant() != rule.Sha256)
            throw new Boundary("dsh_transcript_decoder_changed");
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("Flower.Dsh.ZstdDecoder.cjs")
            ?? throw new Boundary("dsh_transcript_decoder_unavailable");
        using var reader = new StreamReader(resource, Utf8);
        // Only this fixed embedded source is evaluated. No source, module or
        // path comes from a tool argument or from session text.
        string code = reader.ReadToEnd().Replace("if(require.main===module){", "{", StringComparison.Ordinal);
        var info = new ProcessStartInfo(rule.Path) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.Environment.Clear(); info.Environment["ELECTRON_RUN_AS_NODE"] = "1";
        info.Environment["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        info.ArgumentList.Add("--eval"); info.ArgumentList.Add(code);
        using var child = Process.Start(info) ?? throw new Boundary("dsh_transcript_decoder_unavailable");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        async Task<byte[]> Output(Stream stream, int maximum)
        {
            using var output = new MemoryStream(); var buffer = new byte[8192]; int size;
            while ((size = await stream.ReadAsync(buffer, deadline.Token)) != 0)
            { if (output.Length + size > maximum) throw new Boundary("dsh_transcript_size_rejected"); output.Write(buffer, 0, size); }
            return output.ToArray();
        }
        var output = Output(child.StandardOutput.BaseStream, Limit);
        var errors = Output(child.StandardError.BaseStream, 16384);
        try
        {
            child.StandardInput.BaseStream.WriteAsync(raw, deadline.Token).AsTask().GetAwaiter().GetResult();
            child.StandardInput.Close();
            child.WaitForExitAsync(deadline.Token).GetAwaiter().GetResult();
            var bytes = output.GetAwaiter().GetResult(); _ = errors.GetAwaiter().GetResult();
            if (child.ExitCode != 0) throw new Boundary("dsh_transcript_decode_rejected");
            return bytes;
        }
        catch
        {
            if (!child.HasExited) { child.Kill(entireProcessTree: true); child.WaitForExit(3000); }
            try { Task.WhenAll(output, errors).GetAwaiter().GetResult(); } catch { }
            throw new Boundary("dsh_transcript_decode_rejected");
        }
    }

    internal static DshTranscriptSnapshot Parse(byte[] bytes, string session)
    {
        if (bytes.Length is <= 0 or > Limit || bytes[^1] != 10) throw new Boundary("dsh_transcript_partial_record");
        int offset = 0, lineNumber = 0; long sequence = -1, relevant = -1;
        bool seeded = false; UacTranscriptSnapshot? latest = null;
        long seedCut = -1;
        // A fork may contain nested inherited end-seed markers. The official
        // codec cuts at the LAST inherited marker, not the first marker.
        foreach (var row in Utf8.GetString(bytes).Split('\n').Skip(1).SkipLast(1))
        {
            using var seedRecord = JsonDocument.Parse(row); Protocol.CheckUnique(seedRecord);
            var entry = seedRecord.RootElement;
            if (entry.GetProperty("type").GetString() == "session/end-seed"
                && entry.TryGetProperty("data", out var marker)
                && marker.TryGetProperty("inherited", out var inherited) && inherited.ValueKind == JsonValueKind.True)
                seedCut = entry.GetProperty("seq").GetInt64();
        }
        var messages = new Dictionary<string, string>();
        var canceledIds = new HashSet<string>();
        foreach (var line in Utf8.GetString(bytes).Split('\n').SkipLast(1))
        {
            int start = offset; offset += Utf8.GetByteCount(line) + 1;
            if (line.Length == 0 || line.Length > 16 * 1024 * 1024) throw new Boundary("dsh_transcript_record_rejected");
            using var doc = JsonDocument.Parse(line); Protocol.CheckUnique(doc); var item = doc.RootElement;
            if (lineNumber++ == 0)
            {
                if (item.GetProperty("type").GetString() != "session" || item.GetProperty("version").GetInt32() != 4
                    || item.GetProperty("id").GetString() != session) throw new Boundary("dsh_transcript_header_rejected");
                seeded = item.TryGetProperty("isSeeded", out var seed) && seed.ValueKind == JsonValueKind.True;
                if (!seeded && seedCut >= 0) throw new Boundary("dsh_transcript_seed_rejected");
                continue;
            }
            if (item.GetProperty("seq").GetInt64() != ++sequence) throw new Boundary("dsh_transcript_sequence_rejected");
            string type = item.GetProperty("type").GetString() ?? "";
            if (seeded && sequence <= seedCut) continue;
            if (seeded && seedCut < 0) continue;
            if (type == "session/end-seed") continue;
            var data = item.GetProperty("data");
            void User(JsonElement message, bool submitted = false)
            {
                if (!message.TryGetProperty("source", out var source) || source.ValueKind != JsonValueKind.Object
                    || !source.TryGetProperty("kind", out var kind) || kind.GetString() != "user") return;
                string id = message.GetProperty("id").GetString() ?? "";
                string rpc = source.GetProperty("rpcId").GetString() ?? "";
                if (id.Length is < 1 or > 256 || rpc.Length is < 1 or > 256 || message.GetProperty("role").GetString() != "user")
                    throw new Boundary("dsh_transcript_user_rejected");
                string signature = Hash(message.GetRawText());
                if (!submitted && canceledIds.Contains(id)) return;
                if (submitted) canceledIds.Remove(id);
                if (!submitted && messages.TryGetValue(id, out var prior))
                {
                    if (prior != signature) throw new Boundary("dsh_user_message_changed_without_submission");
                    // Consuming either inbox queue is not another human
                    // submission. In particular old A cannot supersede new B.
                    return;
                }
                var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(item.GetProperty("time").GetInt64()).ToString("O", CultureInfo.InvariantCulture);
                latest = new(session, "message:" + Hash(id), Hash(message.GetProperty("content").GetRawText()),
                    Hash("flower-dsh-user-v1\0" + sequence + "\0" + line), timestamp, start, offset, bytes.Length);
                relevant = sequence; messages[id] = signature;
            }
            if (type == "user/message") User(data);
            else if (type == "agent/inbox/spliced")
            {
                if (data.TryGetProperty("outcome", out var outcome) && outcome.GetString() == "canceled"
                    && data.TryGetProperty("removedCount", out var removed) && removed.GetInt32() > 0)
                {
                    // A removal cannot restore an earlier user's authority.
                    latest = null; relevant = sequence;
                    foreach (var id in messages.Keys) canceledIds.Add(id);
                }
                if (data.TryGetProperty("inserted", out var inserted)) foreach (var message in inserted.EnumerateArray()) User(message, submitted: true);
            }
        }
        if (seeded && seedCut < 0 || latest is null) throw new Boundary("dsh_user_message_unavailable");
        return new(latest, relevant, sequence);
    }
}
