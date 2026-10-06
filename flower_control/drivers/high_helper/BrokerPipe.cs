using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal static class BrokerPipe
{
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { public int Size; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint instances, uint output, uint input, uint timeout, ref Attributes attributes);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(
        SafeAccessTokenHandle token, int kind, IntPtr info, int size, out int needed);
    [StructLayout(LayoutKind.Sequential)] private struct SidAttributes { public IntPtr Sid; public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct TokenGroups { public uint Count; public SidAttributes First; }
    internal static string Name(Peer own) => "Flower.HighBroker.v1." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{own.User}|{own.Session}"))).ToLowerInvariant()[..32];
    internal static string LogonSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        // WindowsIdentity.Groups filters the logon SID from its managed list.
        // Read TokenLogonSid directly; do not weaken to a per-user SID fallback.
        GetTokenInformation(identity.AccessToken, 28, IntPtr.Zero, 0, out var needed);
        var offset = Marshal.OffsetOf<TokenGroups>(nameof(TokenGroups.First)).ToInt32();
        var stride = Marshal.SizeOf<SidAttributes>();
        if (needed < offset + stride || needed > 65536) throw new Boundary("logon_identity_unavailable");
        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!GetTokenInformation(identity.AccessToken, 28, buffer, needed, out _))
                throw new Boundary("logon_identity_unavailable", Marshal.GetLastWin32Error());
            var count = Marshal.ReadInt32(buffer);
            if (count is < 1 or > 16 || offset + count * stride > needed) throw new Boundary("logon_identity_unavailable");
            var groups = Enumerable.Range(0, count).Select(i => Marshal.PtrToStructure<SidAttributes>(buffer + offset + i * stride));
            return groups.Where(g => (g.Flags & 0xC0000000) == 0xC0000000)
                .Select(g => new SecurityIdentifier(g.Sid).Value).SingleOrDefault(s => s.StartsWith("S-1-5-5-", StringComparison.Ordinal))
                ?? throw new Boundary("logon_identity_unavailable");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    internal static NamedPipeServerStream Create(string name, bool first)
    {
        // Object-local Medium label lets approved Medium clients write this new pipe.
        // There is no global ACL, service, firewall or UAC-policy mutation.
        var sddl = $"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{LogonSid()})S:(ML;;NW;;;ME)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var descriptor, out _))
            throw new Boundary("pipe_acl_failed", Marshal.GetLastWin32Error());
        try
        {
            var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            var handle = CreateNamedPipeW(@"\\.\pipe\" + name, 3 | 0x40000000U | (first ? 0x80000U : 0), 8, 64, 8192, 8192, 0, ref attributes);
            if (handle.IsInvalid) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Boundary("pipe_create_failed", error); }
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally { LocalFree(descriptor); }
    }
}
