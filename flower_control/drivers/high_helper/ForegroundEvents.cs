using System.Runtime.InteropServices;

namespace Flower.HighHelper;

// Event history belongs only to one activated short phase. Returning to the
// target or restoring it cannot erase an earlier foreground/minimize event.
internal sealed class ForegroundEventLatch(long target, Func<long, bool> allowed)
{
    private string? reason;
    internal string? Reason => Volatile.Read(ref reason);
    internal void Fault(string code) => Interlocked.CompareExchange(ref reason, code, null);
    internal void Observe(uint kind, long hwnd, int objectId, int childId)
    {
        if (kind == 3)
        {
            if (!allowed(hwnd)) Fault("foreground_changed");
        }
        else if (hwnd == target && objectId == 0 && childId == 0)
        {
            if (kind == 0x16) Fault("target_minimized");
            else if (kind == 0x8001) Fault("target_identity_changed");
        }
    }
    internal void Check()
    {
        if (Reason is { } value) throw new Boundary(value);
    }
}

internal sealed class ForegroundEvents : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct Message
    { public IntPtr Hwnd; public uint Id; public UIntPtr WParam; public IntPtr LParam; public uint Time; public Native.Point Point; public uint Private; }
    private delegate void WinEvent(IntPtr hook, uint kind, IntPtr hwnd, int objectId, int childId, uint thread, uint time);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr SetWinEventHook(uint min, uint max, IntPtr module, WinEvent callback, uint process, uint thread, uint flags);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool UnhookWinEvent(IntPtr hook);
    [DllImport("user32.dll", SetLastError = true)] private static extern int GetMessageW(out Message message, IntPtr window, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool PeekMessageW(out Message message, IntPtr window, uint min, uint max, uint remove);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Message message);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref Message message);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool PostThreadMessageW(uint thread, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    private readonly Thread pump;
    private readonly ManualResetEventSlim ready = new(false);
    private readonly AutoResetEvent checkpoint = new(false);
    private readonly ForegroundEventLatch latch;
    private readonly WinEvent callback;
    private GCHandle callbackRoot;
    private uint threadId;
    private int closing;
    private bool released;
    internal ForegroundEvents(Bound bound, Func<bool>? allowPopup = null)
    {
        latch = new ForegroundEventLatch(bound.Hwnd, hwnd => Native.TargetOrOwnedPopup(bound, hwnd, allowPopup?.Invoke() == true));
        callback = (_, kind, hwnd, objectId, childId, _, _) =>
        {
            try { latch.Observe(kind, hwnd.ToInt64(), objectId, childId); }
            catch { latch.Fault("foreground_watch_failed"); }
        };
        callbackRoot = GCHandle.Alloc(callback);
        pump = new Thread(Pump) { IsBackground = true, Name = "Flower phase foreground events" };
        try { pump.Start(); }
        catch { callbackRoot.Free(); ready.Dispose(); checkpoint.Dispose(); throw; }
        if (!ready.Wait(500)) { Dispose(); throw new Boundary("foreground_watch_unavailable"); }
        try
        {
            latch.Check();
            // Register first and then sample so no input starts during setup.
            latch.Observe(3, Native.GetForegroundWindow().ToInt64(), 0, 0);
            if (Native.IsIconic(new IntPtr(bound.Hwnd))) latch.Fault("target_minimized");
            latch.Check();
        }
        catch { Dispose(); throw; }
    }
    private void Pump()
    {
        var hooks = new List<IntPtr>();
        try
        {
            threadId = GetCurrentThreadId();
            PeekMessageW(out _, IntPtr.Zero, 0, 0, 0); // Create the thread's message queue before signalling ready.
            foreach (var kind in new[] { 3U, 0x16U, 0x8001U })
            {
                var hook = SetWinEventHook(kind, kind, IntPtr.Zero, callback, 0, 0, 0);
                if (hook == IntPtr.Zero) throw new Boundary("foreground_watch_unavailable", Marshal.GetLastWin32Error());
                hooks.Add(hook);
            }
            ready.Set();
            if (Volatile.Read(ref closing) == 0)
            {
                int status;
                while ((status = GetMessageW(out var message, IntPtr.Zero, 0, 0)) > 0)
                {
                    if (message.Id == 0x8000)
                    {
                        // Posted messages can precede internal system events.
                        // Pump the pending queue before acknowledging the fence.
                        while (PeekMessageW(out var queued, IntPtr.Zero, 0, 0, 1))
                        {
                            if (queued.Id == 0x12) return;
                            TranslateMessage(ref queued); DispatchMessageW(ref queued);
                        }
                        checkpoint.Set();
                    }
                    else { TranslateMessage(ref message); DispatchMessageW(ref message); }
                }
                if (status < 0) latch.Fault("foreground_watch_failed");
            }
        }
        catch { latch.Fault("foreground_watch_unavailable"); }
        finally
        {
            released = true;
            foreach (var hook in hooks) if (!UnhookWinEvent(hook)) released = false;
            // Retain the callback if native unhooking is unconfirmed. A stale
            // native callback must never target a collected managed delegate.
            if (released) callbackRoot.Free();
            ready.Set();
            GC.KeepAlive(callback);
        }
    }
    internal void Check()
    {
        latch.Check();
        // An out-of-context hook delivers on this pump. A checkpoint makes
        // already queued event callbacks observable before another dispatch,
        // including a foreground-away/back pair between ordinary samples.
        if (Volatile.Read(ref closing) != 0 || !PostThreadMessageW(threadId, 0x8000, UIntPtr.Zero, IntPtr.Zero)
            || !checkpoint.WaitOne(500)) throw new Boundary("foreground_watch_failed");
        latch.Check();
    }
    public void Dispose()
    {
        if (Interlocked.Exchange(ref closing, 1) == 0 && Volatile.Read(ref threadId) != 0)
            PostThreadMessageW(threadId, 0x12, UIntPtr.Zero, IntPtr.Zero);
        if (!pump.Join(500) || !released) throw new Boundary("foreground_watch_release_unconfirmed");
        ready.Dispose();
        checkpoint.Dispose();
    }
}
