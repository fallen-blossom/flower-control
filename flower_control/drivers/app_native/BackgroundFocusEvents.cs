using System.Runtime.InteropServices;

// Observe only focus transitions into this exact target/owner chain. Unrelated
// user switching is allowed. No focus restoration or input is performed here.
internal sealed class BackgroundFocusEvents : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct Message
    { public IntPtr Hwnd; public uint Id; public UIntPtr Wp; public IntPtr Lp; public uint Time; public int X, Y; public uint Private; }
    private delegate void Event(IntPtr hook, uint kind, IntPtr hwnd, int objectId, int childId, uint thread, uint time);
    [DllImport("user32.dll")] private static extern IntPtr SetWinEventHook(uint min, uint max, IntPtr module, Event callback, uint pid, uint thread, uint flags);
    [DllImport("user32.dll")] private static extern bool UnhookWinEvent(IntPtr hook);
    [DllImport("user32.dll")] private static extern int GetMessageW(out Message message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool PeekMessageW(out Message message, IntPtr hwnd, uint min, uint max, uint remove);
    [DllImport("user32.dll")] private static extern bool PostThreadMessageW(uint thread, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    private static readonly List<BackgroundFocusEvents> retained = [];
    private readonly Event callback;
    private readonly Thread pump;
    private readonly ManualResetEventSlim ready = new();
    private readonly AutoResetEvent checkpoint = new(false);
    private uint thread;
    private int changed, away, closing;
    private bool released;
    private bool finalUnchanged;
    internal BackgroundFocusEvents(IntPtr target)
    {
        away = Native.GetForegroundWindow() == target ? 0 : 1;
        callback = (_, _, hwnd, _, _, _, _) =>
        {
            try
            {
                bool related = hwnd != IntPtr.Zero && (Native.GetAncestor(hwnd, 2) == target || Native.GetAncestor(hwnd, 3) == target);
                if (!related) Interlocked.Exchange(ref away, 1);
                else if (Volatile.Read(ref away) != 0) Interlocked.Exchange(ref changed, 1);
            }
            catch { Interlocked.Exchange(ref changed, 1); }
        };
        pump = new Thread(() =>
        {
            IntPtr hook = IntPtr.Zero;
            try
            {
                thread = GetCurrentThreadId(); PeekMessageW(out _, IntPtr.Zero, 0, 0, 0);
                hook = SetWinEventHook(3, 3, IntPtr.Zero, callback, 0, 0, 0);
                if (hook == IntPtr.Zero) Interlocked.Exchange(ref changed, 1);
                ready.Set();
                while (Volatile.Read(ref closing) == 0)
                {
                    int status = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                    if (status <= 0) { if (status < 0) Interlocked.Exchange(ref changed, 1); break; }
                    if (message.Id == 0x8000)
                    {
                        while (PeekMessageW(out var queued, IntPtr.Zero, 0, 0, 1)) if (queued.Id == 0x12) return;
                        checkpoint.Set();
                    }
                }
            }
            catch { Interlocked.Exchange(ref changed, 1); ready.Set(); }
            finally
            {
                released = hook == IntPtr.Zero || UnhookWinEvent(hook);
                if (!released) lock (retained) retained.Add(this);
            }
        }) { IsBackground = true, Name = "Flower background focus evidence" };
        pump.Start();
        if (!ready.Wait(500)) { Dispose(); throw new ArgumentException("background_focus_watch_unavailable"); }
    }
    internal bool Unchanged
    {
        get
        {
            if (Volatile.Read(ref closing) != 0) return finalUnchanged && released;
            if (Volatile.Read(ref changed) != 0) return false;
            if (!PostThreadMessageW(thread, 0x8000, UIntPtr.Zero, IntPtr.Zero) || !checkpoint.WaitOne(500)) return false;
            return Volatile.Read(ref changed) == 0;
        }
    }
    public void Dispose()
    {
        if (Volatile.Read(ref closing) != 0) return;
        finalUnchanged = Unchanged;
        Interlocked.Exchange(ref closing, 1);
        if (thread != 0) PostThreadMessageW(thread, 0x12, UIntPtr.Zero, IntPtr.Zero);
        if (!pump.Join(500) || !released) throw new ArgumentException("background_focus_watch_release_unconfirmed");
        finalUnchanged &= Volatile.Read(ref changed) == 0;
    }
}
