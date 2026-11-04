using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Flower.HighHelper;

// Local presentation state only. This record is never an execution offer,
// permission grant, delegation, resume request or source of effective policy.
internal static class RoleDraftRecovery
{
    private sealed record Envelope(int Schema, string UserSid, int Session, string Version, SettingsSurfaceHandoff Surface);
    private static (string Path, string Digest)? imported;
    private const int Limit = 1024 * 1024;
    [StructLayout(LayoutKind.Sequential)] private struct Blob { internal int Size; internal IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptProtectData(ref Blob input, string? description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    private static void RejectLinks(string path)
    {
        for (FileSystemInfo? item = new FileInfo(path); item is not null;
            item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
        {
            try { if ((File.GetAttributes(item.FullName) & FileAttributes.ReparsePoint) != 0) throw new Boundary("settings_draft_recovery_link_rejected"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }
    internal static byte[] Crypt(byte[] bytes, bool encrypt)
    {
        if (bytes.Length is < 1 or > Limit) throw new Boundary("settings_draft_recovery_invalid");
        var pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        Blob output = default;
        try
        {
            var input = new Blob { Size = bytes.Length, Data = pin.AddrOfPinnedObject() };
            bool ok = encrypt ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok || output.Size is < 1 or > Limit) throw new Boundary("settings_draft_recovery_crypto_failed", Marshal.GetLastWin32Error());
            var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length); return result;
        }
        finally { if (output.Data != IntPtr.Zero) LocalFree(output.Data); pin.Free(); }
    }
    private static string PathFor(BrokerPolicy policy, Peer own)
    {
        if (policy.Fixture || own.User != policy.UserSid || own.Session <= 0 || !Path.IsPathFullyQualified(policy.DataRoot)
            || policy.DataRoot.StartsWith(@"\\", StringComparison.Ordinal)) throw new Boundary("settings_draft_recovery_context_rejected");
        var path = Path.Combine(policy.DataRoot, "control", "role-draft-" + own.Session + ".bin");
        RejectLinks(path); return path;
    }
    internal static void Preserve(BrokerPolicy policy, Peer own, SettingsSurfaceHandoff surface)
    {
        SettingsSurfaceHandoffValidator.Validate(surface, own.User);
        var path = PathFor(policy, own);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); RejectLinks(path);
        // Do not silently replace an older, still unimported draft.
        var plain = JsonSerializer.SerializeToUtf8Bytes(new Envelope(1, own.User, own.Session, policy.Version, surface));
        byte[] encrypted;
        try { encrypted = Crypt(plain, true); } finally { CryptographicOperations.ZeroMemory(plain); }
        string temporary = path + ".new-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { output.Write(encrypted); output.Flush(true); }
            File.Move(temporary, path, false);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        imported = (path, Convert.ToHexString(SHA256.HashData(encrypted)));
    }
    internal static void Restore(BrokerPolicy policy, Peer own)
    {
        var path = PathFor(policy, own);
        try
        {
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length is < 1 or > Limit) throw new Boundary("settings_draft_recovery_invalid");
            var encrypted = new byte[input.Length]; input.ReadExactly(encrypted);
            var plain = Crypt(encrypted, false);
            try
            {
                using var document = JsonDocument.Parse(plain);
                Protocol.CheckUnique(document);
                var value = Protocol.Decode<Envelope>(document);
                if (value.Schema != 1 || value.UserSid != own.User || value.Session != own.Session || value.Surface is null)
                    throw new Boundary("settings_draft_recovery_context_rejected");
                SettingsSurfaceHandoffValidator.Validate(value.Surface, own.User);
                // Old version data may recover only an editable draft. Import
                // rereads current protected policy and preserves CAS conflicts.
                SettingsWorkspace.QueueHandoff(value.Surface);
                imported = (path, Convert.ToHexString(SHA256.HashData(encrypted)));
            }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }
    internal static void AcceptImported()
    {
        if (imported is not { } expected) return;
        RejectLinks(expected.Path);
        using (var input = new FileStream(expected.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (input.Length is < 1 or > Limit || Convert.ToHexString(SHA256.HashData(input)) != expected.Digest)
                throw new Boundary("settings_draft_recovery_changed");
        }
        File.Delete(expected.Path); imported = null;
    }
}
