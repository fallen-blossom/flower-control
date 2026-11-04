using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// The caller holds the signed executable and archive against write/delete.
// No downloaded metadata, cached first-seen hash or archive-supplied trust root.
internal static class DshSignedArchive
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint LoadLibraryExW(string path, nint file, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint FindResourceW(nint module, string name, string type);
    [DllImport("kernel32.dll")] private static extern uint SizeofResource(nint module, nint resource);
    [DllImport("kernel32.dll")] private static extern nint LoadResource(nint module, nint resource);
    [DllImport("kernel32.dll")] private static extern nint LockResource(nint resource);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(nint module);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, nint security, uint creation, uint flags, nint template);
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { internal uint Flags, Tag; }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int kind, out Attributes attributes, uint size);

    private static void RequireObject(SafeFileHandle file, string path, bool directory)
    {
        if (file.IsInvalid || !GetFileInformationByHandleEx(file, 9, out var attributes, 8)
            || (attributes.Flags & 0x400) != 0 || ((attributes.Flags & 0x10) != 0) != directory)
            throw new Boundary("dsh_signed_archive_path_changed");
        DshHostIdentity.Canonical(file, path);
    }

    private static void PinParents(string path, List<SafeFileHandle> held, HashSet<string> pinned)
    {
        var parents = new Stack<string>();
        for (var parent = Path.GetDirectoryName(path); parent is not null; parent = Path.GetDirectoryName(parent))
            parents.Push(parent);
        while (parents.TryPop(out var parent))
        {
            if (pinned.Contains(parent)) continue;
            var file = CreateFileW(parent, 0x80, 1, 0, 3, 0x02200000, 0);
            try { RequireObject(file, parent, true); }
            catch { file.Dispose(); throw; }
            held.Add(file); pinned.Add(parent);
        }
    }

    internal static string HeaderDigest(string executable)
    {
        var module = LoadLibraryExW(executable, 0, 0x22); // data/image resource only
        if (module == 0) throw new Boundary("dsh_signed_archive_unavailable");
        try
        {
            var resource = FindResourceW(module, "ElectronAsar", "Integrity");
            var size = resource == 0 ? 0 : SizeofResource(module, resource);
            if (size is 0 or > 16384) throw new Boundary("dsh_signed_archive_unavailable");
            var address = LockResource(LoadResource(module, resource));
            if (address == 0) throw new Boundary("dsh_signed_archive_unavailable");
            byte[] bytes = new byte[size]; Marshal.Copy(address, bytes, 0, bytes.Length);
            using var json = JsonDocument.Parse(bytes); Protocol.CheckUnique(json);
            string? found = null;
            foreach (var row in json.RootElement.EnumerateArray())
            {
                if (row.GetProperty("file").GetString() != @"resources\app.asar") continue;
                if (found is not null || !string.Equals(row.GetProperty("alg").GetString(), "SHA256", StringComparison.OrdinalIgnoreCase))
                    throw new Boundary("dsh_signed_archive_invalid");
                found = row.GetProperty("value").GetString();
            }
            return HashText(found);
        }
        finally { FreeLibrary(module); }
    }

    private static string HashText(string? value)
    {
        if (value is not { Length: 64 } || value.Any(c => !Uri.IsHexDigit(c)))
            throw new Boundary("dsh_signed_archive_invalid");
        return value.ToLowerInvariant();
    }

    internal static void Verify(FileStream archive, string expectedHeader, string unpackedRoot,
        List<FileStream> held, List<SafeFileHandle> directories)
    {
        archive.Position = 0;
        Span<byte> lead = stackalloc byte[16]; archive.ReadExactly(lead);
        uint size = BinaryPrimitives.ReadUInt32LittleEndian(lead[4..]);
        uint pickle = BinaryPrimitives.ReadUInt32LittleEndian(lead[8..]);
        uint text = BinaryPrimitives.ReadUInt32LittleEndian(lead[12..]);
        if (BinaryPrimitives.ReadUInt32LittleEndian(lead) != 4 || size < 8 || size > 64 * 1024 * 1024
            || pickle != size - 4 || text > pickle - 4 || text == 0 || 8L + size > archive.Length)
            throw new Boundary("dsh_signed_archive_invalid");
        byte[] header = new byte[text]; archive.ReadExactly(header);
        if (!Convert.ToHexString(SHA256.HashData(header)).Equals(HashText(expectedHeader), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("dsh_signed_archive_changed");
        using var json = JsonDocument.Parse(header); Protocol.CheckUnique(json);
        var pending = new Stack<(JsonElement Node, string Relative)>(); pending.Push((json.RootElement, ""));
        var files = new List<(JsonElement Node, string Relative)>();
        int entries = 0; long start = 8L + size;
        byte[] buffer = new byte[65536];
        var pinned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (pending.TryPop(out var item))
        {
            if (++entries > 200000 || item.Node.ValueKind != JsonValueKind.Object || item.Node.TryGetProperty("link", out _))
                throw new Boundary("dsh_signed_archive_invalid");
            if (item.Node.TryGetProperty("files", out var children))
            {
                foreach (var child in children.EnumerateObject())
                {
                    if (child.Name is "" or "." or ".." || child.Name.IndexOfAny(['\\', '/', ':']) >= 0
                        || child.Name.Any(char.IsControl) || child.Name.TrimEnd(' ', '.') != child.Name)
                        throw new Boundary("dsh_signed_archive_invalid");
                    pending.Push((child.Value, Path.Combine(item.Relative, child.Name)));
                }
                continue;
            }
            files.Add(item);
        }
        // ASAR entries are not guaranteed to enumerate in payload order.
        // Hash packed bytes in order so a single validation does not turn a
        // sequential archive read into thousands of random disk seeks.
        long Offset((JsonElement Node, string Relative) item)
            => item.Node.TryGetProperty("offset", out var offset) && long.TryParse(offset.GetString(),
                System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var value)
                    ? value : long.MaxValue;
        foreach (var item in files.OrderBy(Offset))
        {
            long length = item.Node.GetProperty("size").GetInt64();
            if (length < 0) throw new Boundary("dsh_signed_archive_invalid");
            var integrity = item.Node.GetProperty("integrity");
            if (integrity.GetProperty("algorithm").GetString() != "SHA256") throw new Boundary("dsh_signed_archive_invalid");
            var expected = HashText(integrity.GetProperty("hash").GetString());
            Stream stream = archive;
            if (item.Node.TryGetProperty("unpacked", out var unpacked) && unpacked.GetBoolean())
            {
                var path = Path.GetFullPath(Path.Combine(unpackedRoot, item.Relative));
                if (!path.StartsWith(Path.GetFullPath(unpackedRoot) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new Boundary("dsh_signed_archive_invalid");
                PinParents(path, directories, pinned);
                var handle = CreateFileW(path, 0x80000000, 1, 0, 3, 0x00200000, 0);
                try { RequireObject(handle, path, false); }
                catch { handle.Dispose(); throw; }
                var file = new FileStream(handle, FileAccess.Read); held.Add(file);
                if (file.Length != length) throw new Boundary("dsh_signed_archive_changed");
                stream = file;
            }
            else
            {
                if (!long.TryParse(item.Node.GetProperty("offset").GetString(),
                    System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long offset)
                    || offset < 0 || length > archive.Length - start || offset > archive.Length - start - length)
                    throw new Boundary("dsh_signed_archive_invalid");
                archive.Position = start + offset;
            }
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long remaining = length;
            while (remaining > 0)
            {
                int read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read == 0) throw new Boundary("dsh_signed_archive_changed");
                hash.AppendData(buffer, 0, read); remaining -= read;
            }
            if (!Convert.ToHexString(hash.GetHashAndReset()).Equals(expected, StringComparison.OrdinalIgnoreCase))
                throw new Boundary("dsh_signed_archive_changed");
        }
        archive.Position = 0;
    }
}
