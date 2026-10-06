using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Collections.Concurrent;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed class Boundary(string code, int? native = null) : Exception(code)
{
    public string Code { get; } = code;
    public int? NativeCode { get; } = native;
}

internal record Peer(int Pid, long Created, int Session, string User, string ImageDigest, int Integrity);
internal record Target(long Hwnd, int Pid, long Created, int Session, string ImageDigest,
                       int Integrity, long Nonce, int[] Bounds, int[]? ClientRect = null,
                       int[]? ClientOrigin = null, uint? WindowDpi = null);
internal record Bound(long Hwnd, int Pid, long Created, long WindowNonce);

internal static class Native
{
    internal const string WindowProperty = "FlowerControl.WindowNonce.v1";
    private static readonly string[] Protected = ["FlowerControlAuthorizationCard",
        "FlowerControlAuthorizationVerifier", "FlowerControlResumePrompt", "FlowerControlTaskIndicator"];
    private static readonly string[] Excluded = ["consent.exe", "credentialuibroker.exe", "logonui.exe"];
    private static readonly ConcurrentDictionary<(int, long, string), Lazy<string>> ImageDigests = new();
    internal static string Digest(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ProcessIdToSessionId(int pid, out uint session);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32FirstW(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32NextW(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern int GetPackageFamilyName(SafeProcessHandle process, ref uint length, StringBuilder? name);
    internal static string? PackageFamily(int pid)
    {
        using var process = OpenProcess(0x1000, false, pid);
        Require(!process.IsInvalid, "process_unavailable");
        uint size = 0;
        var result = GetPackageFamilyName(process, ref size, null);
        if (result == 15700) return null;
        if (result != 122 || size is < 1 or > 512) throw new Boundary("package_identity_unavailable", result);
        var name = new StringBuilder((int)size);
        result = GetPackageFamilyName(process, ref size, name);
        if (result != 0) throw new Boundary("package_identity_unavailable", result);
        return name.ToString();
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct ProcessEntry
    {
        public uint Size, Usage, Pid; public UIntPtr Heap; public uint Module, Threads, Parent;
        public int Priority; public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Image;
    }
    internal static int ParentPid(int pid)
    {
        var snapshot = CreateToolhelp32Snapshot(2, 0);
        Require(snapshot != new IntPtr(-1), "process_snapshot_failed");
        try
        {
            var entry = new ProcessEntry { Size = (uint)Marshal.SizeOf<ProcessEntry>(), Image = "" };
            if (Process32FirstW(snapshot, ref entry)) do { if (entry.Pid == pid) return (int)entry.Parent; } while (Process32NextW(snapshot, ref entry));
            throw new Boundary("process_parent_unavailable");
        }
        finally { CloseHandle(snapshot); }
    }
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr info, int size, out int needed);
    internal static bool UiAccess(int pid)
    {
        using var process = OpenProcess(0x1000, false, pid);
        Require(!process.IsInvalid, "process_unavailable");
        Require(OpenProcessToken(process, 8, out var token), "token_unavailable");
        using (token)
        {
            var data = Marshal.AllocHGlobal(4);
            try { Require(GetTokenInformation(token, 26, data, 4, out _), "token_unavailable"); return Marshal.ReadInt32(data) != 0; }
            finally { Marshal.FreeHGlobal(data); }
        }
    }
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool GetUserObjectInformationW(IntPtr handle, int index, StringBuilder name, uint size, out uint needed);
    [DllImport("user32.dll")] internal static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] internal static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] internal static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern IntPtr GetPropW(IntPtr hwnd, string name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool SetPropW(IntPtr hwnd, string name, IntPtr value);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool GetClientRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool ClientToScreen(IntPtr hwnd, ref Point point);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] internal static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int size);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr FindWindowExW(IntPtr parent, IntPtr after, string? className, string? title);
    [DllImport("user32.dll")] internal static extern IntPtr GetWindow(IntPtr hwnd, uint command);
    [DllImport("user32.dll", SetLastError = true)] internal static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)] internal static extern bool BringWindowToTop(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError = true)] internal static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] internal static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] internal static extern bool ShowWindowAsync(IntPtr hwnd, int command);
    [DllImport("user32.dll", SetLastError = true)] internal static extern IntPtr SendMessageTimeoutW(IntPtr hwnd, uint message, IntPtr wp, IntPtr lp, uint flags, uint timeout, out IntPtr result);
    [DllImport("user32.dll")] internal static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")] internal static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] internal static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll")] private static extern IntPtr GetThreadDpiAwarenessContext();
    [DllImport("user32.dll")] private static extern int GetAwarenessFromDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll", SetLastError = true)] internal static extern uint SendInput(uint count, Input[] inputs, int size);

    [StructLayout(LayoutKind.Sequential)] internal struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] internal struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] internal struct Mouse { public int Dx, Dy; public uint Data, Flags, Time; public UIntPtr Extra; }
    [StructLayout(LayoutKind.Sequential)] internal struct Key { public ushort Vk, Scan; public uint Flags, Time; public UIntPtr Extra; }
    [StructLayout(LayoutKind.Explicit)] internal struct Union { [FieldOffset(0)] public Mouse Mouse; [FieldOffset(0)] public Key Key; }
    [StructLayout(LayoutKind.Sequential)] internal struct Input { public uint Type; public Union Data; }

    private static void Require(bool value, string code)
    {
        if (!value) throw new Boundary(code, Marshal.GetLastWin32Error());
    }
    private static string ObjectName(IntPtr handle)
    {
        Require(handle != IntPtr.Zero, "desktop_unavailable");
        var name = new StringBuilder(256);
        Require(GetUserObjectInformationW(handle, 2, name, 512, out _), "desktop_unavailable");
        return name.ToString();
    }
    internal static void Desktop(uint targetThread = 0)
    {
        if (ObjectName(GetProcessWindowStation()) != "WinSta0"
            || !ObjectName(GetThreadDesktop(GetCurrentThreadId())).Equals("Default", StringComparison.OrdinalIgnoreCase))
            throw new Boundary("non_default_desktop");
        if (targetThread != 0 && !ObjectName(GetThreadDesktop(targetThread)).Equals("Default", StringComparison.OrdinalIgnoreCase))
            throw new Boundary("target_desktop_mismatch");
        var input = OpenInputDesktop(0, false, 1);
        Require(input != IntPtr.Zero, "input_desktop_unavailable");
        try
        {
            if (!ObjectName(input).Equals("Default", StringComparison.OrdinalIgnoreCase)) throw new Boundary("secure_desktop_rejected");
        }
        finally { CloseDesktop(input); }
        if (GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()) != 2)
            throw new Boundary("physical_dpi_required");
    }

    internal static (Peer Identity, string Image) Process(int pid, bool digestImage = true)
    {
        using var process = OpenProcess(0x1000, false, pid);
        Require(!process.IsInvalid, "process_unavailable");
        Require(GetProcessTimes(process, out var created, out _, out _, out _), "process_unavailable");
        var image = new StringBuilder(2048); uint size = 2048;
        Require(QueryFullProcessImageNameW(process, 0, image, ref size), "image_unavailable");
        Require(ProcessIdToSessionId(pid, out var session), "session_unavailable");
        Require(OpenProcessToken(process, 8, out var token), "token_unavailable");
        using (token)
        {
            GetTokenInformation(token, 25, IntPtr.Zero, 0, out var needed);
            if (needed <= 0 || needed > 4096) throw new Boundary("token_size_invalid");
            var data = Marshal.AllocHGlobal(needed);
            try
            {
                Require(GetTokenInformation(token, 25, data, needed, out _), "token_unavailable");
                var sid = Marshal.ReadIntPtr(data);
                var count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                if (count == 0) throw new Boundary("token_size_invalid");
                var integrity = Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
                using var identity = new WindowsIdentity(token.DangerousGetHandle());
                var path = image.ToString();
                var key = (pid, created, path);
                string digest = "";
                if (digestImage)
                {
                    digest = ImageDigests.GetOrAdd(key, value => new Lazy<string>(() => Digest(value.Item3),
                        LazyThreadSafetyMode.ExecutionAndPublication)).Value;
                    // Avoid eight-entry wholesale invalidation in a multi-client host.
                    if (ImageDigests.Count > 256)
                        foreach (var old in ImageDigests.Keys.OrderBy(value => value.Item2).Take(32))
                            ImageDigests.TryRemove(old, out _);
                }
                return (new Peer(pid, created, (int)session, identity.User?.Value ?? throw new Boundary("user_unavailable"),
                                 digest, integrity), path);
            }
            finally { Marshal.FreeHGlobal(data); }
        }
    }
    internal static void VerifyPeer(Peer expected)
    {
        var current = Process(expected.Pid).Identity;
        var own = Process(Environment.ProcessId).Identity;
        if (current != expected || current.User != own.User || current.Session != own.Session)
            throw new Boundary("peer_identity_changed");
    }

    internal static Bound CheckTarget(Target target, bool bind)
    {
        var hwnd = new IntPtr(target.Hwnd);
        if (!IsWindow(hwnd) || !IsWindowVisible(hwnd) || GetAncestor(hwnd, 2) != hwnd)
            throw new Boundary("target_not_ordinary_root");
        if (Protected.Any(name => GetPropW(hwnd, name) != IntPtr.Zero)) throw new Boundary("protected_target");
        var thread = GetWindowThreadProcessId(hwnd, out var pid);
        if (pid != target.Pid || thread == 0) throw new Boundary("target_identity_changed");
        Desktop(thread);
        var process = Process((int)pid);
        var own = Process(Environment.ProcessId).Identity;
        if (process.Identity.Created != target.Created || process.Identity.Session != target.Session
            || process.Identity.ImageDigest != target.ImageDigest || process.Identity.Integrity != target.Integrity
            || process.Identity.Session != own.Session || process.Identity.User != own.User
            || process.Identity.Integrity < 8192 || process.Identity.Integrity > own.Integrity || process.Identity.Integrity >= 16384)
            throw new Boundary("target_identity_changed");
        if (Excluded.Contains(Path.GetFileName(process.Image), StringComparer.OrdinalIgnoreCase))
            throw new Boundary("protected_target");
        var nonce = GetPropW(hwnd, WindowProperty).ToInt64();
        if (target.Nonce != 0 && nonce != target.Nonce) throw new Boundary("window_nonce_changed");
        if (bind && nonce == 0)
        {
            nonce = RandomNumberGenerator.GetInt32(1, int.MaxValue);
            Require(SetPropW(hwnd, WindowProperty, new IntPtr(nonce)), "window_identity_access_denied");
        }
        if (nonce <= 0 || GetPropW(hwnd, WindowProperty).ToInt64() != nonce
            || !IsWindow(hwnd) || GetWindowThreadProcessId(hwnd, out var finalPid) == 0 || finalPid != pid
            || Process((int)pid).Identity != process.Identity)
            throw new Boundary("target_identity_changed");
        return new Bound(target.Hwnd, target.Pid, target.Created, nonce);
    }
    internal static int[] Bounds(long hwnd)
    {
        Require(GetWindowRect(new IntPtr(hwnd), out var rect), "bounds_unavailable");
        return [rect.Left, rect.Top, rect.Right, rect.Bottom];
    }
    internal static bool Foreground(long hwnd) => GetAncestor(GetForegroundWindow(), 2).ToInt64() == hwnd;
    internal static bool ShellDesktopIdentity(long hwnd, long shell, string className, int pid, int shellPid, bool hasDesktopView) =>
        shell > 0 && (hwnd == shell || className == "WorkerW" && pid > 0 && pid == shellPid && hasDesktopView);
    internal static bool IsShellDesktop(Bound bound)
    {
        var hwnd = new IntPtr(bound.Hwnd); var shell = GetShellWindow();
        var name = new StringBuilder(256);
        GetClassNameW(hwnd, name, name.Capacity);
        GetWindowThreadProcessId(shell, out var shellPid);
        return ShellDesktopIdentity(bound.Hwnd, shell.ToInt64(), name.ToString(), bound.Pid, (int)shellPid,
            FindWindowExW(hwnd, IntPtr.Zero, "SHELLDLL_DefView", null) != IntPtr.Zero);
    }
    internal static bool ForegroundOrOwnedPopup(Bound bound, bool allowPopup)
    {
        return TargetOrOwnedPopup(bound, GetForegroundWindow().ToInt64(), allowPopup);
    }
    internal static bool TargetOrOwnedPopup(Bound bound, long hwnd, bool allowPopup)
    {
        var window = GetAncestor(new IntPtr(hwnd), 2);
        if (window.ToInt64() == bound.Hwnd) return true;
        if (!allowPopup || Protected.Any(name => GetPropW(window, name) != IntPtr.Zero)) return false;
        var seen = new HashSet<IntPtr>();
        for (int depth = 0; depth < 16 && window != IntPtr.Zero && seen.Add(window); ++depth)
        {
            GetWindowThreadProcessId(window, out var pid);
            if (pid != bound.Pid) return false;
            window = GetWindow(window, 4); // GW_OWNER, not an arbitrary same-process window.
            if (window.ToInt64() == bound.Hwnd) return true;
        }
        return false;
    }
    internal static void CheckGeometry(Target target, bool clientRequired = false)
    {
        if (!Bounds(target.Hwnd).SequenceEqual(target.Bounds)) throw new Boundary("geometry_changed");
        if (target.ClientRect is null || target.ClientOrigin is null || target.WindowDpi is null)
        { if (clientRequired) throw new Boundary("client_geometry_required"); return; }
        var hwnd = new IntPtr(target.Hwnd);
        Require(GetClientRect(hwnd, out var rect), "client_geometry_unavailable");
        var origin = new Point();
        Require(ClientToScreen(hwnd, ref origin), "client_geometry_unavailable");
        if (!new[] { rect.Left, rect.Top, rect.Right, rect.Bottom }.SequenceEqual(target.ClientRect)
            || !new[] { origin.X, origin.Y }.SequenceEqual(target.ClientOrigin)
            || GetDpiForWindow(hwnd) != target.WindowDpi) throw new Boundary("client_geometry_changed");
    }
    internal static bool ProtectedForeground()
    {
        var hwnd = GetAncestor(GetForegroundWindow(), 2);
        if (hwnd == IntPtr.Zero) return false;
        if (Protected.Any(name => GetPropW(hwnd, name) != IntPtr.Zero)) return true;
        GetWindowThreadProcessId(hwnd, out var pid);
        var process = Process((int)pid);
        return process.Identity.Integrity >= 16384 || Excluded.Contains(Path.GetFileName(process.Image), StringComparer.OrdinalIgnoreCase);
    }
}
