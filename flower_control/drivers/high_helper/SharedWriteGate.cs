using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Flower.HighHelper;

// Same session-local names, ACL and 32-byte layout as control/write_gate.py.
internal sealed class SharedWriteGate : IDisposable
{
    private const int Magic = 0x46435731;
    private IntPtr mutex, mapping, view;
    [StructLayout(LayoutKind.Sequential)] private struct Attributes
    { internal uint Size; internal IntPtr Descriptor; internal int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateMutexW(ref Attributes attributes, bool owner, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateFileMappingW(IntPtr file, ref Attributes attributes, uint protect, uint high, uint low, string name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint high, uint low, UIntPtr size);
    [DllImport("kernel32.dll")] private static extern bool UnmapViewOfFile(IntPtr view);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll")] private static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    internal record Status(bool Stopped, long Epoch, long ResumeAllEpoch);

    internal SharedWriteGate(string? testNamespace = null)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value ?? throw new Boundary("write_gate_user_unavailable");
        var name = "Local\\FlowerControl.WriteGate.v1." + sid;
        if (testNamespace is not null)
        {
            if (testNamespace.Length == 0 || testNamespace.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('_' or '-')))
                throw new Boundary("write_gate_namespace_rejected");
            name += ".test." + testNamespace;
        }
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW($"D:P(A;;GA;;;SY)(A;;GA;;;{sid})S:(ML;;NW;;;ME)", 1, out var descriptor, out _))
            throw new Boundary("write_gate_security_failed", Marshal.GetLastWin32Error());
        try
        {
            var attributes = new Attributes { Size = (uint)Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            mutex = CreateMutexW(ref attributes, false, name + ".lock");
            mapping = CreateFileMappingW(new IntPtr(-1), ref attributes, 4, 0, 32, name);
            if (mutex == IntPtr.Zero || mapping == IntPtr.Zero) throw new Boundary("write_gate_unavailable", Marshal.GetLastWin32Error());
            view = MapViewOfFile(mapping, 6, 0, 0, new UIntPtr(32));
            if (view == IntPtr.Zero) throw new Boundary("write_gate_unavailable", Marshal.GetLastWin32Error());
            Locked(() => {
                int magic = Marshal.ReadInt32(view);
                if (magic == 0) Write(new(false, 0, 0));
                else if (magic != Magic) throw new Boundary("write_gate_layout_rejected");
                return true;
            });
        }
        catch { Dispose(); throw; }
        finally { LocalFree(descriptor); }
    }
    private T Locked<T>(Func<T> action)
    {
        if (view == IntPtr.Zero) throw new Boundary("write_gate_unavailable");
        uint result = WaitForSingleObject(mutex, 250);
        if (result is not (0 or 0x80)) throw new Boundary("write_gate_busy");
        try
        {
            if (result == 0x80) { var old = Read(); Write(old with { Stopped = true, Epoch = old.Epoch + 1 }); }
            return action();
        }
        finally { if (!ReleaseMutex(mutex)) throw new Boundary("write_gate_release_unconfirmed"); }
    }
    private Status Read()
    {
        int magic = Marshal.ReadInt32(view), stopped = Marshal.ReadInt32(view, 4);
        long epoch = Marshal.ReadInt64(view, 8), resumed = Marshal.ReadInt64(view, 16);
        if (magic != Magic || stopped is not (0 or 1) || epoch < 0 || resumed < 0 || resumed > epoch || Marshal.ReadInt64(view, 24) != 0)
            throw new Boundary("write_gate_layout_rejected");
        return new(stopped == 1, epoch, resumed);
    }
    private void Write(Status status)
    {
        Marshal.WriteInt32(view, Magic); Marshal.WriteInt32(view, 4, status.Stopped ? 1 : 0);
        Marshal.WriteInt64(view, 8, status.Epoch); Marshal.WriteInt64(view, 16, status.ResumeAllEpoch);
        Marshal.WriteInt64(view, 24, 0);
    }
    internal Status Snapshot() => Locked(Read);
    internal Status Stop() => Locked(() => {
        var old = Read();
        if (!old.Stopped) Write(old with { Stopped = true, Epoch = old.Epoch + 1 });
        return Read();
    });
    internal Status Resume(long? expectedEpoch = null)
    {
        long expected = expectedEpoch ?? Snapshot().Epoch;
        return Locked(() => {
            var old = Read();
            if (old.Epoch != expected) throw new Boundary("resume_state_changed");
            Write(old with { Stopped = false, ResumeAllEpoch = old.Epoch }); return Read();
        });
    }
    internal void Admit(long epoch) => Locked(() => {
        var status = Read();
        if (status.Stopped || epoch != status.Epoch) throw new Boundary("global_write_stopped");
        return true;
    });
    public void Dispose()
    {
        if (view != IntPtr.Zero) { UnmapViewOfFile(view); view = IntPtr.Zero; }
        if (mapping != IntPtr.Zero) { CloseHandle(mapping); mapping = IntPtr.Zero; }
        if (mutex != IntPtr.Zero) { CloseHandle(mutex); mutex = IntPtr.Zero; }
    }
}
