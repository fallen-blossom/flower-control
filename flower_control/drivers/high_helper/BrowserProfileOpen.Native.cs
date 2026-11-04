using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal static partial class BrowserProfileOpen
{
    // Fixed native role entry only, reusing the same verified Explorer-parent
    // token creation as browser opening. No shell text or arbitrary executable.
    internal static Peer StartOrdinaryRole(string[] arguments)
    {
        if (arguments.Length == 0 || arguments[0] is not ("--serve-user" or "--serve-user-staging"))
            throw new Boundary("ordinary_role_arguments_rejected");
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        var own = Native.Process(Environment.ProcessId).Identity;
        string application = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        if (own.User != policy.UserSid || own.Integrity != 12288 || Native.UiAccess(own.Pid))
            throw new Boundary("ordinary_role_launcher_high_required");
        using var pinned = new FileStream(application, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Native.Digest(application) != own.ImageDigest) throw new Boundary("ordinary_role_binary_changed");
        IntPtr shellWindow = GetShellWindow();
        if (shellWindow == IntPtr.Zero || Native.GetWindowThreadProcessId(shellWindow, out var shellPid) == 0)
            throw new Boundary("ordinary_role_shell_unavailable");
        var shell = Native.Process((int)shellPid, false);
        if (!Path.GetFullPath(shell.Image).Equals(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("ordinary_role_shell_unverified");
        RequireMedium(shell.Identity, own.User, own.Session);
        using var parent = OpenProcess(0x80 | 0x1000, false, (int)shellPid);
        if (parent.IsInvalid || !GetProcessTimes(parent, out var parentCreated, out _, out _, out _) || parentCreated != shell.Identity.Created)
            throw new Boundary("ordinary_role_shell_unverified");
        var environment = AdminProgramLaunch.OrdinaryEnvironment(Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>().Select(pair => new KeyValuePair<string, string>((string)pair.Key, (string)pair.Value!)));
        var block = string.Join('\0', environment.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
        IntPtr env = Marshal.StringToHGlobalUni(block), size = IntPtr.Zero, attributes = IntPtr.Zero, parentValue = IntPtr.Zero;
        bool initialized = false;
        try
        {
            _ = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            if (size.ToInt64() is < 1 or > 65536) throw new Boundary("ordinary_role_parent_setup_failed");
            attributes = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw new Boundary("ordinary_role_parent_setup_failed");
            initialized = true; parentValue = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(parentValue, parent.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20000), parentValue, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw new Boundary("ordinary_role_parent_setup_failed");
            if (GetShellWindow() != shellWindow || Native.Process((int)shellPid, false).Identity != shell.Identity)
                throw new Boundary("ordinary_role_shell_changed");
            var startup = new StartupEx { Startup = new Startup { Size = (uint)Marshal.SizeOf<StartupEx>(), Desktop = "winsta0\\default" }, Attributes = attributes };
            var argv = new[] { application }.Concat(arguments);
            if (!CreateProcessW(application, new StringBuilder(string.Join(' ', argv.Select(Quote))), IntPtr.Zero, IntPtr.Zero,
                false, 0x80000 | 0x400 | 0x4 | 0x08000000, env, policy.Directory, ref startup, out var created))
                throw new Boundary("ordinary_role_start_failed", Marshal.GetLastWin32Error());
            using var process = new SafeProcessHandle(created.Process, true);
            try
            {
                var child = Native.Process(created.Pid).Identity;
                RequireMedium(child, own.User, own.Session);
                NativeRoleIdentity.Require(child, policy, 8192);
                if (child.ImageDigest != own.ImageDigest) throw new Boundary("ordinary_role_binary_changed");
                if (ResumeThread(created.Thread) == uint.MaxValue) throw new Boundary("ordinary_role_start_unconfirmed");
                return child;
            }
            catch
            {
                // Only a child that has never been resumed is terminated here.
                if (!TerminateProcess(process, 1) || WaitForSingleObject(process, 1000) != 0)
                    throw new Boundary("ordinary_role_suspended_cleanup_unknown");
                throw;
            }
            finally { CloseHandle(created.Thread); }
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (parentValue != IntPtr.Zero) Marshal.FreeHGlobal(parentValue);
            Marshal.FreeHGlobal(env);
        }
    }
}
