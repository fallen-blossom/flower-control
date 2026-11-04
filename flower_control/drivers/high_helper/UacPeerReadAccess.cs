using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// Only exposes identity queries on this short-lived SYSTEM process and its
// primary token. No debugging privilege, token duplication, memory or writes.
internal static class UacPeerReadAccess
{
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityInfo(IntPtr handle, int kind, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint SetSecurityInfo(IntPtr handle, int kind, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    internal static RawAcl QueryAcl(RawAcl? original, string sid, int rights)
    {
        if (original is null || !sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || rights is not (0x1000 or 8))
            throw new Boundary("uac_peer_query_acl_rejected");
        var bytes = new byte[original.BinaryLength]; original.GetBinaryForm(bytes, 0);
        var result = new RawAcl(bytes, 0);
        result.InsertAce(result.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
            rights, new SecurityIdentifier(sid), false, null));
        return result;
    }
    private static void Grant(IntPtr handle, string sid, int rights)
    {
        uint code = GetSecurityInfo(handle, 6, 4, out _, out _, out _, out _, out var descriptor);
        if (code != 0) throw new Boundary("uac_peer_query_acl_unavailable", (int)code);
        try
        {
            var bytes = new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            var acl = QueryAcl(new RawSecurityDescriptor(bytes, 0).DiscretionaryAcl, sid, rights);
            var encoded = new byte[acl.BinaryLength]; acl.GetBinaryForm(encoded, 0);
            var memory = Marshal.AllocHGlobal(encoded.Length);
            try
            {
                Marshal.Copy(encoded, 0, memory, encoded.Length);
                code = SetSecurityInfo(handle, 6, 4, IntPtr.Zero, IntPtr.Zero, memory, IntPtr.Zero);
                if (code != 0) throw new Boundary("uac_peer_query_acl_failed", (int)code);
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        finally { LocalFree(descriptor); }
    }
    internal static void PrepareOwn(BrokerPolicy policy)
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        if (policy.Fixture || own.User != "S-1-5-18" || own.Integrity != 16384 || Native.UiAccess(own.Pid))
            throw new Boundary("uac_peer_query_role_rejected");
        Grant(GetCurrentProcess(), policy.UserSid, 0x1000);
        if (!OpenProcessToken(GetCurrentProcess(), 0x60008, out var token))
            throw new Boundary("uac_peer_query_token_unavailable", Marshal.GetLastWin32Error());
        using (token) Grant(token.DangerousGetHandle(), policy.UserSid, 8);
    }
}
