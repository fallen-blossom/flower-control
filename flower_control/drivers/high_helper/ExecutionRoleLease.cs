using System.Runtime.InteropServices;

namespace Flower.HighHelper;

// Both production roles use one logon-local lease. Its Medium label permits
// an orderly handoff from High; holding it never grants a privileged token.
internal sealed class ExecutionRoleLease : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { internal uint Size; internal IntPtr Descriptor; internal int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateMutexW(ref Attributes attributes, bool owner, string name);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")] private static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    private IntPtr handle;
    internal ExecutionRoleLease()
    {
        string logon = BrokerPipe.LogonSid();
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW($"D:P(A;;GA;;;SY)(A;;GA;;;{logon})S:(ML;;NW;;;ME)", 1, out var descriptor, out _))
            throw new Boundary("executor_role_security_failed", Marshal.GetLastWin32Error());
        try
        {
            var attributes = new Attributes { Size = (uint)Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            handle = CreateMutexW(ref attributes, false, "Local\\FlowerControl.ExecutionRole.v1." + logon);
            if (handle == IntPtr.Zero) throw new Boundary("executor_role_unavailable", Marshal.GetLastWin32Error());
            uint result = WaitForSingleObject(handle, 0);
            if (result != 0)
            {
                // An abandoned role may have held input. Do not promote the
                // abandoned mutex result into proof that cleanup completed.
                if (result == 0x80) ReleaseMutex(handle);
                CloseHandle(handle); handle = IntPtr.Zero;
                throw new Boundary(result == 0x80 ? "executor_role_abandoned" : "executor_role_busy");
            }
        }
        finally { LocalFree(descriptor); }
    }
    public void Dispose()
    {
        var owned = handle; handle = IntPtr.Zero;
        if (owned == IntPtr.Zero) return;
        bool released = ReleaseMutex(owned); CloseHandle(owned);
        if (!released) throw new Boundary("executor_role_release_unconfirmed");
    }
}
