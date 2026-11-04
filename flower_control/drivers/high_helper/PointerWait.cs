using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// One action owns one high-resolution timer; no global timer-resolution change.
internal sealed class PointerWait : IDisposable
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeWaitHandle CreateWaitableTimerExW(IntPtr attributes, string? name, uint flags, uint access);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWaitableTimerEx(SafeWaitHandle timer, ref long due, int period, IntPtr routine,
        IntPtr argument, IntPtr wakeContext, uint tolerance);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(SafeWaitHandle handle, uint timeout);
    private readonly SafeWaitHandle timer;
    internal PointerWait()
    {
        timer = CreateWaitableTimerExW(IntPtr.Zero, null, 2, 0x100002);
        if (timer.IsInvalid) { timer.Dispose(); throw new Boundary("pointer_timer_unavailable"); }
    }
    internal void Delay(int milliseconds)
    {
        if (milliseconds <= 0) return;
        if (milliseconds > 20) throw new Boundary("pointer_wait_out_of_bounds");
        long due = -milliseconds * 10000L;
        if (!SetWaitableTimerEx(timer, ref due, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0)
            || WaitForSingleObject(timer, (uint)(milliseconds + 50)) != 0)
            throw new Boundary("pointer_timer_failed");
    }
    public void Dispose() => timer.Dispose();
}
