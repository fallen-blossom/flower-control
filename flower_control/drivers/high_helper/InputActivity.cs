using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Flower.HighHelper;

internal sealed class InputActivityLatch
{
    private string? reason;
    internal static readonly UIntPtr OwnTag = new(Math.Max(1u, BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4))));
    internal void Observe(bool keyboard, UIntPtr tag)
    {
        if (tag != OwnTag)
            Interlocked.CompareExchange(ref reason, keyboard ? "external_keyboard_activity" : "external_mouse_activity", null);
    }
    internal void Check() { if (Volatile.Read(ref reason) is { } code) throw new Boundary(code); }
    internal static uint Send(Native.Input[] events)
    {
        foreach (ref var value in events.AsSpan())
        {
            if (value.Type == 0) value.Data.Mouse.Extra = OwnTag;
            else if (value.Type == 1) value.Data.Key.Extra = OwnTag;
        }
        return Native.SendInput((uint)events.Length, events, Marshal.SizeOf<Native.Input>());
    }
}

// Only activity category is retained. No key code, text, pointer position or
// event history is read or recorded; CallNextHookEx always passes user input.
internal sealed class InputActivityEvents : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct Keyboard
    { public uint UnusedVk, UnusedScan, UnusedFlags, UnusedTime; public UIntPtr Tag; }
    [StructLayout(LayoutKind.Sequential)] private struct Mouse
    { public Native.Point UnusedPoint; public uint UnusedData, UnusedFlags, UnusedTime; public UIntPtr Tag; }
    [StructLayout(LayoutKind.Sequential)] private struct Message
    { public IntPtr Hwnd; public uint Id; public UIntPtr Wp; public IntPtr Lp; public uint Time; public Native.Point Point; public uint Private; }
    private delegate IntPtr Hook(int code, UIntPtr message, IntPtr data);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr SetWindowsHookExW(int kind, Hook callback, IntPtr module, uint thread);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hook, int code, UIntPtr message, IntPtr data);
    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(IntPtr hook);
    [DllImport("user32.dll")] private static extern int GetMessageW(out Message message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool PeekMessageW(out Message message, IntPtr hwnd, uint min, uint max, uint remove);
    [DllImport("user32.dll")] private static extern bool PostThreadMessageW(uint thread, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? name);
    private static readonly List<InputActivityEvents> retained = [];
    private readonly InputActivityLatch latch = new();
    private readonly ManualResetEventSlim ready = new();
    private readonly AutoResetEvent checkpoint = new(false);
    private readonly object checkGate = new();
    private readonly Thread pump;
    private readonly Hook keyboard, mouse;
    private uint threadId;
    private int closing;
    private string? fault;
    private bool released;
    internal InputActivityEvents()
    {
        keyboard = (code, message, data) => Observe(true, code, message, data);
        mouse = (code, message, data) => Observe(false, code, message, data);
        pump = new Thread(Pump) { IsBackground = true, Name = "Flower phase input activity" };
        pump.Start();
        if (!ready.Wait(500) || fault is not null) { Dispose(); throw new Boundary(fault ?? "input_activity_watch_unavailable"); }
    }
    private IntPtr Observe(bool key, int code, UIntPtr message, IntPtr data)
    {
        if (code >= 0 && data != IntPtr.Zero)
        {
            try
            {
                int offset = key ? Marshal.OffsetOf<Keyboard>(nameof(Keyboard.Tag)).ToInt32()
                    : Marshal.OffsetOf<Mouse>(nameof(Mouse.Tag)).ToInt32();
                latch.Observe(key, new UIntPtr(unchecked((ulong)Marshal.ReadIntPtr(data, offset).ToInt64())));
            }
            catch { fault = "input_activity_watch_failed"; }
        }
        return CallNextHookEx(IntPtr.Zero, code, message, data);
    }
    private void Pump()
    {
        var hooks = new List<IntPtr>();
        try
        {
            threadId = GetCurrentThreadId(); PeekMessageW(out _, IntPtr.Zero, 0, 0, 0);
            foreach (var pair in new[] { (13, keyboard), (14, mouse) })
            {
                if (Volatile.Read(ref closing) != 0) return;
                var hook = SetWindowsHookExW(pair.Item1, pair.Item2, GetModuleHandleW(null), 0);
                if (hook == IntPtr.Zero) throw new Boundary("input_activity_watch_unavailable");
                hooks.Add(hook);
            }
            ready.Set();
            while (Volatile.Read(ref closing) == 0)
            {
                int result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result == 0) break;
                if (result < 0) throw new Boundary("input_activity_watch_failed");
                if (message.Id == 0x8000)
                {
                    while (PeekMessageW(out var queued, IntPtr.Zero, 0, 0, 1))
                        if (queued.Id == 0x12) return;
                    checkpoint.Set();
                }
            }
        }
        catch { fault = "input_activity_watch_unavailable"; ready.Set(); }
        finally
        {
            released = true;
            foreach (var hook in hooks) if (!UnhookWindowsHookEx(hook)) released = false;
            if (!released) { fault = "input_activity_release_unconfirmed"; lock (retained) retained.Add(this); }
        }
    }
    internal void Check()
    {
        if (fault is { } code) throw new Boundary(code);
        if (!pump.IsAlive) throw new Boundary("input_activity_watch_unavailable");
        latch.Check();
        lock (checkGate)
            if (Volatile.Read(ref closing) != 0 || !PostThreadMessageW(threadId, 0x8000, UIntPtr.Zero, IntPtr.Zero)
                || !checkpoint.WaitOne(500)) throw new Boundary("input_activity_watch_failed");
        if (fault is { } fresh) throw new Boundary(fresh);
        latch.Check();
    }
    public void Dispose()
    {
        Interlocked.Exchange(ref closing, 1);
        if (threadId != 0) PostThreadMessageW(threadId, 0x12, UIntPtr.Zero, IntPtr.Zero);
        if (!pump.Join(500) || !released) throw new Boundary("input_activity_release_unconfirmed");
    }
}
