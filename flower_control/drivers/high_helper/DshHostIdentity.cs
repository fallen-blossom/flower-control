using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// Desktop's signed exe also has a Node role. Image identity alone is insufficient.
internal static class DshHostIdentity
{
    // One reviewed Windows x64 Electron v8-compatible PEB adapter. Unknown
    // architecture or invalid user pointers fail closed before any read.
    private static class X64PebLayout
    {
        internal const nint ProcessParameters = 0x20;
        internal const nint CurrentDirectory = 0x38;
        internal const nint CommandLine = 0x70;
        internal const nint Environment = 0x80;
        internal const int UnicodeString = 16;
    }
    private static readonly object RuntimeGate = new();
    private static readonly Dictionary<string, RuntimePin> Runtimes = new(StringComparer.OrdinalIgnoreCase);
    private static Timer? runtimeReaper;
    private sealed class RuntimePin
    {
        internal readonly List<SafeFileHandle> Parents = [];
        internal FileStream? File;
        internal FileStream? Image;
        internal readonly List<FileStream> Unpacked = [];
        internal readonly Dictionary<int, long> Owners = [];
        internal void Dispose()
        {
            File?.Dispose(); Image?.Dispose();
            foreach (var file in Unpacked) file.Dispose();
            foreach (var parent in Parents) parent.Dispose();
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicInfo
    { internal nint Reserved, Peb, Reserved2, Reserved3, Pid, Parent; }
    private sealed record Startup(string[] Args, bool RunAsNode, bool NodeOptions, string? DshHome = null, string? WorkingDirectory = null);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint rights, bool inherit, int pid);
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(SafeProcessHandle handle, int kind, out BasicInfo info, int size, out int length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadProcessMemory(SafeProcessHandle handle, nint address, byte[] bytes, nuint size, out nuint read);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")] private static extern nint LocalFree(nint pointer);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);
    private delegate bool WindowCallback(nint hwnd, nint parameter);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback, nint parameter);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint hwnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(nint hwnd, StringBuilder name, int length);

    internal static void Verify(Peer host, NativeHostRule rule)
    {
        var mainPid = Native.ParentPid(host.Pid);
        var (main, mainPath) = Native.Process(mainPid);
        if (main.Created > host.Created || main.User != host.User || main.Session != host.Session
            || main.ImageDigest != host.ImageDigest || !Same(mainPath, rule.Path))
            throw new Boundary("dsh_desktop_parent_unverified");
        var root = Path.GetDirectoryName(rule.Path)!;
        var hostStart = ReadStartup(host.Pid);
        var mainStart = ReadStartup(main.Pid);
        if (!ValidHostArguments(hostStart.Args, rule.Path, root) || !hostStart.RunAsNode || hostStart.NodeOptions
            || !ValidMainArguments(mainStart.Args, rule.Path)
            || mainStart.RunAsNode || mainStart.NodeOptions || !OwnsDesktopWindow(main.Pid))
            throw new Boundary("dsh_desktop_role_unverified");
        var runtime = Path.Combine(root, "resources", "app.asar");
        PinRuntime(runtime, host.ImageDigest == rule.Sha256 ? rule.RuntimeSha256! : null, host, rule.Path);
        if (Native.Process(host.Pid, digestImage: false).Identity.Created != host.Created
            || Native.Process(main.Pid, digestImage: false).Identity.Created != main.Created)
            throw new Boundary("dsh_desktop_instance_changed");
    }

    internal static bool RegisteredImageMatches(Peer host, NativeHostRule rule)
        => host.ImageDigest == rule.Sha256 || rule.Kind == "dsh-desktop"
            && SignedImageMatches(host, rule.Path);

    private static bool SignedImageMatches(Peer host, string imagePath)
        => CodexHostIdentity.IsPublisherImage(imagePath, "DeepSeek Harness.exe",
            "Hangzhou DeepSeek Artificial Intelligence Co., Ltd.", host.Pid, host.Created);

    internal static string SessionRoot(Peer host, NativeHostRule rule)
    {
        Verify(host, rule);
        var startup = ReadStartup(host.Pid);
        string home = ResolveHome(startup.DshHome, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), startup.WorkingDirectory!);
        if (home.StartsWith(@"\\", StringComparison.Ordinal))
            throw new Boundary("dsh_session_root_rejected");
        var root = Path.Combine(Path.GetFullPath(home), "sessions");
        BrokerPolicy.RejectLinks(root);
        Native.VerifyPeer(host);
        return root;
    }

    internal static string ResolveHome(string? configured, string userHome, string workingDirectory)
    {
        string value = string.IsNullOrWhiteSpace(configured) ? Path.Combine(userHome, ".dsh") : configured;
        if (value == "~") value = userHome;
        else if (value.StartsWith("~/", StringComparison.Ordinal) || value.StartsWith(@"~\", StringComparison.Ordinal))
            value = Path.Combine(userHome, value[2..]);
        if (!Path.IsPathFullyQualified(workingDirectory)) throw new Boundary("dsh_session_root_rejected");
        return Path.GetFullPath(value, workingDirectory);
    }

    private static void PinRuntime(string path, string? expected, Peer host, string imagePath)
    {
        BrokerPolicy.RejectLinks(path);
        lock (RuntimeGate)
        {
            string key = Path.GetFullPath(path) + "|" + (expected ?? host.ImageDigest);
            if (Runtimes.TryGetValue(key, out var existing))
            { existing.Owners[host.Pid] = host.Created; return; }
            var pin = new RuntimePin();
            try
            {
                var parents = new Stack<string>();
                for (var item = Path.GetDirectoryName(path); item is not null; item = Path.GetDirectoryName(item)) parents.Push(item);
                while (parents.TryPop(out var parent))
                {
                    BrokerPolicy.RejectLinks(parent);
                    var handle = CreateFileW(parent, 0x20080, 1, 0, 3, 0x02000000 | 0x00200000, 0);
                    if (handle.IsInvalid) { handle.Dispose(); throw new Boundary("dsh_runtime_pin_failed"); }
                    pin.Parents.Add(handle); Canonical(handle, parent);
                }
                pin.File = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                Canonical(pin.File.SafeFileHandle, path);
                if (expected is not null)
                {
                    if (Convert.ToHexString(SHA256.HashData(pin.File)).ToLowerInvariant() != expected)
                        throw new Boundary("dsh_runtime_changed");
                }
                else
                {
                    pin.Image = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    Canonical(pin.Image.SafeFileHandle, imagePath);
                    if (!SignedImageMatches(host, imagePath))
                        throw new Boundary("native_host_image_changed");
                    DshSignedArchive.Verify(pin.File, DshSignedArchive.HeaderDigest(imagePath), path + ".unpacked", pin.Unpacked, pin.Parents);
                }
                // Keep verified objects stable only for the owning host lifetime.
                // A normal host exit releases them so its updater can proceed.
                pin.Owners[host.Pid] = host.Created;
                Runtimes.Add(key, pin);
                runtimeReaper ??= new Timer(_ => ReapRuntimePins(), null, 2000, 2000);
            }
            catch { pin.Dispose(); throw; }
        }
    }
    private static bool OwnerAlive(int pid, long created)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return !process.HasExited && process.StartTime.ToFileTimeUtc() == created;
        }
        catch (ArgumentException) { return false; }
        catch { return true; } // An unqueryable owner is not evidence of exit.
    }
    private static void ReapRuntimePins()
    {
        lock (RuntimeGate)
            foreach (var (key, pin) in Runtimes.ToArray())
            {
                foreach (var (pid, created) in pin.Owners.ToArray())
                    if (!OwnerAlive(pid, created)) pin.Owners.Remove(pid);
                if (pin.Owners.Count != 0) continue;
                pin.Dispose(); Runtimes.Remove(key);
            }
    }
    internal static void Canonical(SafeFileHandle handle, string expected)
    {
        var path = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
        if (length == 0 || length >= path.Capacity || !path.ToString().StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Same(path.ToString()[4..], expected)) throw new Boundary("dsh_runtime_pin_changed");
    }

    internal static bool ValidHostArguments(string[] args, string image, string root)
    {
        var runtime = Path.Combine(root, "resources", "app.asar", "dsh");
        return args.Length is 6 or 8 && Same(args[0], image) && args[1] == "--expose-internals"
            && Same(args[2], Path.Combine(runtime, "node_modules", "@deepseek-ai", "dsh-desktop-host", "lib", "index.js"))
            && Same(args[3], runtime) && Path.IsPathFullyQualified(args[4]) && !args[4].StartsWith(@"\\", StringComparison.Ordinal)
            && Same(args[5], Path.Combine(root, "resources", "runtime", "primary-runtime"))
            && (args.Length == 6 || (Same(args[6], Path.Combine(root, "resources", "runtime", "pnpm", "bin", "pnpm.mjs"))
                    || Same(args[6], Path.Combine(root, "resources", "runtime", "primary-runtime", "dependencies", "pnpm", "bin", "pnpm.mjs")))
                && Same(args[7], Path.Combine(root, "resources", "runtime", "bin")));
    }

    internal static bool ValidMainArguments(string[] args, string image)
    {
        if (args.Length == 0 || !Same(args[0], image)) return false;
        if (args.Length == 1) return true;
        var uriArg = args.Length == 2 ? args[1] : args.Length == 3 && args[1] == "--" ? args[2] : null;
        return uriArg is not null && Uri.TryCreate(uriArg, UriKind.Absolute, out var uri)
            && uri.Scheme == "dsh" && uri.Host == "open" && uri.UserInfo.Length == 0
            && uri.AbsolutePath is "" or "/";
    }

    private static bool Same(string left, string right) => Path.GetFullPath(left).Equals(Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
    private static bool OwnsDesktopWindow(int pid)
    {
        bool found = false;
        if (!EnumWindows((window, _) => {
            GetWindowThreadProcessId(window, out var owner);
            if (owner != pid) return true;
            var name = new StringBuilder(128);
            GetClassNameW(window, name, name.Capacity);
            if (name.ToString() == "Chrome_WidgetWin_1") found = true;
            return true;
        }, 0)) throw new Boundary("dsh_desktop_window_unavailable");
        return found;
    }

    private static byte[] Read(SafeProcessHandle process, nint address, int count)
    {
        var bytes = new byte[count];
        if (!ReadProcessMemory(process, address, bytes, (nuint)count, out var read) || read != (nuint)count)
            throw new Boundary("dsh_startup_metadata_unavailable");
        return bytes;
    }

    private static Startup ReadStartup(int pid)
    {
        // This fixed Windows x64 Desktop build uses the native x64 PEB layout.
        // Unknown layout/access fails closed; no environment text is returned or logged.
        if (IntPtr.Size != 8) throw new Boundary("dsh_startup_architecture_unsupported");
        using var process = OpenProcess(0x1010, false, pid);
        if (process.IsInvalid || NtQueryInformationProcess(process, 0, out var basic, Marshal.SizeOf<BasicInfo>(), out _) != 0)
            throw new Boundary("dsh_startup_metadata_unavailable");
        if (basic.Peb == 0 || (ulong)basic.Peb >= 0x00007ffffffeffffUL)
            throw new Boundary("dsh_startup_metadata_unavailable");
        var parameters = (nint)BitConverter.ToInt64(Read(process, basic.Peb + X64PebLayout.ProcessParameters, 8));
        if (parameters == 0 || (ulong)parameters >= 0x00007ffffffeffffUL)
            throw new Boundary("dsh_startup_metadata_unavailable");
        var currentDirectory = Read(process, parameters + X64PebLayout.CurrentDirectory, X64PebLayout.UnicodeString);
        int directoryLength = BitConverter.ToUInt16(currentDirectory);
        if (directoryLength == 0 || directoryLength % 2 != 0) throw new Boundary("dsh_startup_metadata_unavailable");
        string cwd = Encoding.Unicode.GetString(Read(process, (nint)BitConverter.ToInt64(currentDirectory, 8), directoryLength));
        var command = Read(process, parameters + X64PebLayout.CommandLine, X64PebLayout.UnicodeString);
        int length = BitConverter.ToUInt16(command);
        if (length == 0 || length % 2 != 0) throw new Boundary("dsh_startup_metadata_unavailable");
        var text = Encoding.Unicode.GetString(Read(process, (nint)BitConverter.ToInt64(command, 8), length));
        var argv = CommandLineToArgvW(text, out var count);
        if (argv == 0 || count is < 1 or > 16) throw new Boundary("dsh_startup_arguments_unavailable");
        string[] args;
        try {
            args = Enumerable.Range(0, count).Select(i => Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * 8))
                ?? throw new Boundary("dsh_startup_arguments_unavailable")).ToArray();
        } finally { LocalFree(argv); }
        var environment = (nint)BitConverter.ToInt64(Read(process, parameters + X64PebLayout.Environment, 8));
        var buffer = new List<byte>();
        for (var offset = 0; offset < 262144; offset += 4096) {
            var page = new byte[4096];
            ReadProcessMemory(process, environment + offset, page, 4096, out var available);
            if (available == 0) break;
            int prior = buffer.Count;
            buffer.AddRange(page.Take((int)available));
            for (int i = Math.Max(0, prior - 2); i + 3 < buffer.Count; i += 2)
                if (buffer[i] == 0 && buffer[i+1] == 0 && buffer[i+2] == 0 && buffer[i+3] == 0) {
                    var values = Encoding.Unicode.GetString(buffer.Take(i).ToArray()).Split('\0');
                    bool Present(string name) => values.Any(v => v.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase)
                        && v.Length > name.Length + 1);
                    string? home = values.FirstOrDefault(v => v.StartsWith("DSH_HOME=", StringComparison.OrdinalIgnoreCase))?[9..];
                    return new(args, Present("ELECTRON_RUN_AS_NODE"), Present("NODE_OPTIONS"), string.IsNullOrEmpty(home) ? null : home, cwd);
                }
            if (available < 4096) break;
        }
        throw new Boundary("dsh_startup_environment_unavailable");
    }
}
