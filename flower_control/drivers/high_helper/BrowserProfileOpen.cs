using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// Local settings buttons only. This is not a broker phase or chat authority.
// The fixed ordinary program inherits the verified desktop shell's token,
// following Microsoft's documented unelevated-process creation pattern.
internal static partial class BrowserProfileOpen
{
    private sealed record Pending(string Kind, string Id, string Result, SafeProcessHandle Process, int Pid);
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly Dictionary<string, Pending> Requests = [];

    internal static async Task<SettingsBrowserOpenResult> RequestAsync(string kind, CancellationToken cancellation)
        => await RequestCoreAsync(kind, null, null, cancellation).ConfigureAwait(false);

    internal static Task<SettingsBrowserOpenResult> RequestBrowserAsync(string kind, string? browser, CancellationToken cancellation)
        => RequestCoreAsync(kind, browser, null, cancellation);

    internal static Task<SettingsBrowserOpenResult> SavePreferenceAsync(string browser, string? revision, CancellationToken cancellation)
        => RequestCoreAsync("browser-preferences", browser, revision ?? "missing", cancellation);
    internal static Task<SettingsBrowserOpenResult> SaveDisplayPreferenceAsync(string language, string? revision, CancellationToken cancellation)
        => RequestCoreAsync("display-preferences", language, revision ?? "missing", cancellation);

    private static async Task<SettingsBrowserOpenResult> RequestCoreAsync(string kind, string? browser, string? revision, CancellationToken cancellation)
    {
        bool display = kind == "display-preferences";
        if (kind is not ("ai" or "luohua" or "temporary" or "browser-preferences" or "display-preferences")
            || (display ? browser is null || !DisplayPreferences.ValidLanguage(browser)
                : browser is not (null or "brave" or "edge" or "chrome") && !(kind == "browser-preferences" && browser == "system")))
            return new("unavailable", "invalid_user_profile_request");
        string key = kind + ":" + browser + ":" + revision;
        await Gate.WaitAsync(cancellation).ConfigureAwait(false);
        try
        {
            if (!Requests.TryGetValue(key, out var pending))
            {
                cancellation.ThrowIfCancellationRequested();
                try { pending = Start(kind, browser, revision); Requests.Add(key, pending); }
                catch (Exception error) { return new("unavailable", Program.Code(error)); }
            }
            // A lost UI wait never creates a second temporary window. A later
            // click first resolves the original exact receipt/process.
            var clock = Stopwatch.StartNew();
            while (clock.Elapsed < TimeSpan.FromSeconds(25))
            {
                cancellation.ThrowIfCancellationRequested();
                if (File.Exists(pending.Result))
                {
                    try
                    {
                        BrokerPolicy.RejectLinks(pending.Result);
                        using var input = new FileStream(pending.Result, FileMode.Open, FileAccess.Read, FileShare.Read);
                        if (input.Length is < 1 or > 8192) return new("outcome_uncertain");
                        using var document = JsonDocument.Parse(input); Protocol.CheckUnique(document);
                        var value = document.RootElement;
                        if (value.GetProperty("request_id").GetString() != pending.Id
                            || value.GetProperty("kind").GetString() != kind
                            || browser is not null && (!value.TryGetProperty(display ? "language" : "browser", out var selected) || selected.GetString() != browser)
                            || value.GetProperty("helper_pid").GetInt32() != pending.Pid)
                            return new("outcome_uncertain");
                        string? state = value.GetProperty("state").GetString();
                        // A valid child report can itself be uncertain after
                        // starting a browser. Retain its exact request just as
                        // for a missing receipt; another click cannot replay it.
                        if (state == "outcome_uncertain") return new("outcome_uncertain");
                        if (display && state is "opened" or "reused") return new("outcome_uncertain");
                        if (state is not ("opened" or "reused" or "unavailable" or "saved")
                            || state == "saved" && kind is not ("browser-preferences" or "display-preferences")) return new("outcome_uncertain");
                        string? reason = value.TryGetProperty("reason", out var why) ? why.GetString() : null;
                        Requests.Remove(key); pending.Process.Dispose();
                        return new(state, reason);
                    }
                    catch (Exception) { return new("outcome_uncertain"); }
                }
                // Exiting without a receipt cannot prove no browser was opened.
                if (WaitForSingleObject(pending.Process, 0) == 0) return new("outcome_uncertain");
                await Task.Delay(100, cancellation).ConfigureAwait(false);
            }
            return new("outcome_uncertain");
        }
        finally { Gate.Release(); }
    }

    private static Pending Start(string kind, string? browser, string? revision)
    {
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        if (policy.RuntimeInventorySha256 == "" || policy.DataRoot == "")
            throw new Boundary("browser_profile_bundle_unavailable");
        policy.VerifySource("flower-web");
        string script = Path.Combine(policy.Repository, "tools", "open_flower_browser.py");
        BrokerPolicy.RejectLinks(script); BrokerPolicy.RejectLinks(policy.Python.Path);
        // Protected bundle files cannot be changed by the ordinary child. Keep
        // the exact entry objects pinned through creation and token verification.
        using var scriptPin = new FileStream(script, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var pythonPin = new FileStream(policy.Python.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!policy.SourceHashes.TryGetValue("tools/open_flower_browser.py", out var expected)
            || Native.Digest(script) != expected) throw new Boundary("browser_profile_bundle_unavailable");
        var own = Native.Process(Environment.ProcessId, false).Identity;
        IntPtr shellWindow = GetShellWindow();
        if (shellWindow == IntPtr.Zero || Native.GetWindowThreadProcessId(shellWindow, out var shellPid) == 0)
            throw new Boundary("browser_profile_shell_unavailable");
        var shell = Native.Process((int)shellPid, false);
        if (!Path.GetFullPath(shell.Image).Equals(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("browser_profile_shell_unverified");
        RequireMedium(shell.Identity, own.User, own.Session);
        using var parent = OpenProcess(0x80 | 0x1000, false, (int)shellPid);
        if (parent.IsInvalid || !GetProcessTimes(parent, out var parentCreated, out _, out _, out _)
            || parentCreated != shell.Identity.Created) throw new Boundary("browser_profile_shell_unverified");
        string id = Guid.NewGuid().ToString("N");
        string directory = Path.Combine(Path.GetTempPath(), "flower-browser-open-" + id);
        BrokerPolicy.RejectLinks(Path.GetTempPath());
        Directory.CreateDirectory(directory); BrokerPolicy.RejectLinks(directory);
        string receipt = Path.Combine(directory, "result.json");
        List<string> argv = [policy.Python.Path, "-I", "-B", script, "--kind", kind, "--window-mode", "visible",
            "--data-root", policy.DataRoot, "--request-id", id, "--result-path", receipt];
        if (browser is not null) { argv.Add(kind == "display-preferences" ? "--language" : "--browser"); argv.Add(browser); }
        if (revision is not null) { argv.Add("--expected-revision"); argv.Add(revision); }
        var environment = AdminProgramLaunch.OrdinaryEnvironment(Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>().Select(pair => new KeyValuePair<string, string>((string)pair.Key, (string)pair.Value!)));
        var block = string.Join('\0', environment.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
        IntPtr env = Marshal.StringToHGlobalUni(block), size = IntPtr.Zero, attributes = IntPtr.Zero, parentValue = IntPtr.Zero;
        bool initialized = false;
        try
        {
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size.ToInt64() is < 1 or > 65536) throw new Boundary("browser_profile_parent_setup_failed");
            attributes = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Boundary("browser_profile_parent_setup_failed");
            initialized = true; parentValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(parentValue, parent.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20000), parentValue, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw new Boundary("browser_profile_parent_setup_failed");
            if (GetShellWindow() != shellWindow || Native.Process((int)shellPid, false).Identity != shell.Identity)
                throw new Boundary("browser_profile_shell_changed");
            var startup = new StartupEx { Startup = new Startup { Size = (uint)Marshal.SizeOf<StartupEx>(), Desktop = "winsta0\\default" }, Attributes = attributes };
            if (!CreateProcessW(policy.Python.Path, new StringBuilder(string.Join(' ', argv.Select(Quote))), IntPtr.Zero, IntPtr.Zero,
                    false, 0x80000 | 0x400 | 0x4 | 0x08000000, env, policy.Repository, ref startup, out var created))
                throw new Boundary("browser_profile_start_failed", Marshal.GetLastWin32Error());
            var process = new SafeProcessHandle(created.Process, true);
            var pending = new Pending(kind, id, receipt, process, created.Pid);
            try
            {
                RequireMedium(Native.Process(created.Pid, false).Identity, own.User, own.Session);
                if (ResumeThread(created.Thread) == uint.MaxValue) throw new Boundary("browser_profile_start_unconfirmed");
                return pending;
            }
            catch
            {
                // Only this never-resumed process may be cleaned up. If even
                // that cannot be confirmed, retain the exact request as unknown.
                if (TerminateProcess(process, 1) && WaitForSingleObject(process, 1000) == 0)
                { process.Dispose(); throw; }
                return pending;
            }
            finally
            {
                CloseHandle(created.Thread);
            }
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (parentValue != IntPtr.Zero) Marshal.FreeHGlobal(parentValue);
            Marshal.FreeHGlobal(env);
        }
    }
    private static void RequireMedium(Peer process, string user, int session)
    {
        if (process.User != user || process.Session != session || process.Integrity != 8192 || Native.UiAccess(process.Pid))
            throw new Boundary("browser_profile_medium_required");
        using var handle = OpenProcess(0x1000, false, process.Pid);
        if (handle.IsInvalid || !GetProcessTimes(handle, out var created, out _, out _, out _) || created != process.Created
            || !OpenProcessToken(handle, 8, out var token)) throw new Boundary("browser_profile_token_unavailable");
        using (token)
        {
            var data = Marshal.AllocHGlobal(4);
            try
            {
                if (!GetTokenInformation(token, 20, data, 4, out _) || Marshal.ReadInt32(data) != 0)
                    throw new Boundary("browser_profile_medium_required");
            }
            finally { Marshal.FreeHGlobal(data); }
        }
    }
    internal static string Quote(string value)
    {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { ++slashes; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; result.Append(c);
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Startup
    {
        internal uint Size; internal string? Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        internal ushort Show, ReservedSize; internal IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupEx { internal Startup Startup; internal IntPtr Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { internal IntPtr Process, Thread; internal int Pid, Tid; }
    [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr attributes, int count, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr attributes, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcessW(string application, StringBuilder command, IntPtr processSecurity, IntPtr threadSecurity, bool inherit, uint flags, IntPtr environment, string directory, ref StartupEx startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeProcessHandle process, uint code);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint milliseconds);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr data, int bytes, out int needed);
}
