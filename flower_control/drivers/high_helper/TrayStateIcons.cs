using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Flower.HighHelper;

// Fixed embedded assets only. No external icon path or permission is accepted.
internal static class TrayStateIcons
{
    internal static readonly string[] Names = ["01-normal", "02-admin-window", "03-admin-launch",
        "04-system-uac", "05-disabled", "06-fault"];
    private static readonly Dictionary<(int, int, int), IntPtr> handles = [];
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr CreateIconFromResourceEx(
        byte[] bytes, uint size, bool icon, uint version, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    // Keep the original resource bytes and indexes. Public 01/02/03/04 use
    // white/blue/orange/red artwork at indexes 4/1/2/3 respectively. Index 3
    // reuses only the red artwork; it grants no access to the frozen UAC tier.
    // Pauses and unavailable/faulted routes use the original fault artwork.
    internal static int Select(int tier, bool available, bool fault)
    {
        if (fault) return 5;
        if (tier < -1 || tier > 2 || !available) return 5;
        return tier < 0 ? 4 : tier + 1;
    }
    internal static string DisplayName(int state) => state switch {
        4 => "01-stopped", 1 => "02-normal", 2 => "03-admin-window", 3 => "04-admin-launch",
        _ => "fault" };
    internal static IntPtr Load(int state, int width, int height)
    {
        if (state < 0 || state >= Names.Length || width < 1 || height < 1) throw new Boundary("tray_icon_state_rejected");
        if (handles.TryGetValue((state, width, height), out var prior)) return prior;
        using var stream = typeof(TrayStateIcons).Assembly.GetManifestResourceStream("Flower.Tray." + Names[state] + ".ico")
            ?? throw new Boundary("tray_icon_resource_missing");
        using var memory = new MemoryStream(); stream.CopyTo(memory);
        var bytes = memory.ToArray();
        if (bytes.Length < 22 || BinaryPrimitives.ReadUInt16LittleEndian(bytes) != 0 ||
            BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(2)) != 1) throw new Boundary("tray_icon_resource_invalid");
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(4)), chosen = -1, score = int.MaxValue;
        if (count is < 1 or > 32 || 6 + count * 16 > bytes.Length) throw new Boundary("tray_icon_resource_invalid");
        for (int i = 0; i < count; i++)
        {
            int start = 6 + i * 16;
            int w = bytes[start] == 0 ? 256 : bytes[start], h = bytes[start + 1] == 0 ? 256 : bytes[start + 1];
            int distance = Math.Abs(w - width) + Math.Abs(h - height);
            if (distance < score) { chosen = start; score = distance; }
        }
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(chosen + 8));
        uint offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(chosen + 12));
        if (length == 0 || offset > bytes.Length || length > bytes.Length - offset) throw new Boundary("tray_icon_resource_invalid");
        var image = bytes.AsSpan((int)offset, (int)length).ToArray();
        var handle = CreateIconFromResourceEx(image, length, true, 0x00030000, width, height, 0);
        if (handle == IntPtr.Zero) throw new Boundary("tray_icon_load_failed", Marshal.GetLastWin32Error());
        handles.Add((state, width, height), handle); return handle;
    }
    internal static void Release()
    {
        foreach (var handle in handles.Values) DestroyIcon(handle);
        handles.Clear();
    }
    // Reports the bytes that were actually linked into this build. Comparing
    // these hashes with the original tray-states-v4 files is what proves the
    // executable is not still carrying an older icon folder.
    internal static object SelfTest()
    {
        var rows = new List<object>();
        for (int state = 0; state < Names.Length; state++)
        {
            using var stream = typeof(TrayStateIcons).Assembly.GetManifestResourceStream("Flower.Tray." + Names[state] + ".ico")
                ?? throw new Boundary("tray_icon_resource_missing");
            using var memory = new MemoryStream(); stream.CopyTo(memory);
            var bytes = memory.ToArray();
            var handle = Load(state, 16, 16);
            rows.Add(new { state, name = Names[state], length = bytes.Length,
                sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16].ToLowerInvariant(),
                loaded16 = handle != IntPtr.Zero });
        }
        return new { count = rows.Count, rows };
    }
}
