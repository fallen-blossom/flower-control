using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

// Explicit full-path loading: neither PATH nor the current directory chooses
// the SYSTEM native component. A fixture is allowed only in a Medium selftest.
internal static class UacNativeBridge
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int Publisher(string path, StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int Observe(StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int ObserveWithStop(StringBuilder output, uint capacity, UIntPtr cancel, UIntPtr physicalStop);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int Execute(string expected, string action, StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int StartMonitor(UIntPtr cancel, UIntPtr physicalStop, StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int QualificationSample(uint index, uint targetPid, string observationNonce, StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int ScanStart(uint pid, ulong created, string nonce, ulong generation, ulong revision, string traceGuid,
        UIntPtr cancel, UIntPtr physicalStop, StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int ScanCommand(string nonce, string command, uint promptPid, ulong promptCreated, ulong generation,
        ulong revision, StringBuilder output, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int ScanRecover(string traceGuid, uint ownerPid, ulong ownerCreated, uint session, StringBuilder output, uint capacity);
    private static IntPtr library;
    private static string? testPath;
    internal static void UseMediumFixture(string path, string digest)
    {
        if (Native.Process(Environment.ProcessId).Identity.Integrity != 8192 || library != IntPtr.Zero
            || !Path.IsPathFullyQualified(path) || Native.Digest(path) != digest)
            throw new Boundary("uac_fixture_rejected");
        testPath = Path.GetFullPath(path);
    }
    private static IntPtr Library()
    {
        if (library != IntPtr.Zero) return library;
        var path = testPath ?? Path.Combine(AppContext.BaseDirectory, "Flower.UacNative.dll");
        if (testPath is null)
        {
            var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
            BrokerPolicy.RejectLinks(path); UserPermissions.CheckProtection(path);
            using var seal = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(policy.Directory, "installation.json")));
            if (!seal.RootElement.GetProperty("hashes").TryGetProperty("Flower.UacNative.dll", out var digest)
                || Native.Digest(path) != digest.GetString()) throw new Boundary("uac_native_source_mismatch");
        }
        library = NativeLibrary.Load(path);
        return library;
    }
    internal static (int Code, string Identity) PublisherIdentity(string path)
    {
        var call = Marshal.GetDelegateForFunctionPointer<Publisher>(NativeLibrary.GetExport(Library(), "FlowerUacPublisher"));
        var output = new StringBuilder(128); int code = call(path, output, 128);
        return (code, output.ToString());
    }
    private static JsonElement ScanResponse(int code, StringBuilder output)
    {
        if (code == 3 || output.Length == 0) throw new Boundary("uac_scan_response_unavailable");
        using var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document);
        return document.RootElement.Clone();
    }
    internal static JsonElement StartScan(Peer requester, string nonce, ulong generation, ulong revision, Guid trace,
        ManualResetEvent cancel, ManualResetEvent physicalStop)
    {
        var call = Marshal.GetDelegateForFunctionPointer<ScanStart>(NativeLibrary.GetExport(Library(), "FlowerUacScanStart"));
        var output = new StringBuilder(4096);
        int code = call(checked((uint)requester.Pid), checked((ulong)requester.Created), nonce, generation, revision,
            trace.ToString("B"), new UIntPtr((ulong)cancel.SafeWaitHandle.DangerousGetHandle().ToInt64()),
            new UIntPtr((ulong)physicalStop.SafeWaitHandle.DangerousGetHandle().ToInt64()), output, 4096);
        return ScanResponse(code, output);
    }
    internal static void RequireScanExports()
    {
        var library = Library();
        foreach (var name in new[] { "FlowerUacScanStart", "FlowerUacScanCommand", "FlowerUacScanRecover" })
            if (!NativeLibrary.TryGetExport(library, name, out _)) throw new Boundary("uac_scan_export_unavailable");
    }
    internal static JsonElement Scan(string nonce, string command, UacPromptIdentity? prompt, ulong generation, ulong revision)
    {
        if (command is not ("arm" or "read" or "close")) throw new Boundary("uac_scan_command_rejected");
        var call = Marshal.GetDelegateForFunctionPointer<ScanCommand>(NativeLibrary.GetExport(Library(), "FlowerUacScanCommand"));
        var output = new StringBuilder(4096);
        int code = call(nonce, command, checked((uint)(prompt?.Pid ?? 0)), checked((ulong)(prompt?.Created ?? 0)),
            generation, revision, output, 4096);
        return ScanResponse(code, output);
    }
    internal static JsonElement RecoverScan(Guid trace, Peer owner)
    {
        var call = Marshal.GetDelegateForFunctionPointer<ScanRecover>(NativeLibrary.GetExport(Library(), "FlowerUacScanRecover"));
        var output = new StringBuilder(4096);
        return ScanResponse(call(trace.ToString("B"), checked((uint)owner.Pid), checked((ulong)owner.Created),
            checked((uint)owner.Session), output, 4096), output);
    }
    internal static JsonDocument ObservePrompt()
    {
        var call = Marshal.GetDelegateForFunctionPointer<Observe>(NativeLibrary.GetExport(Library(), "FlowerUacObserve"));
        var output = new StringBuilder(32768); int code = call(output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document);
        return document;
    }
    internal static JsonDocument ObservePrompt(ManualResetEvent cancel, ManualResetEvent physicalStop)
        => ObservePrompt(cancel, physicalStop, false);
    internal static JsonDocument ObservePrompt(ManualResetEvent cancel, ManualResetEvent physicalStop, bool requestBinding)
    {
        var call = Marshal.GetDelegateForFunctionPointer<ObserveWithStop>(NativeLibrary.GetExport(Library(),
            requestBinding ? "FlowerUacObserveBoundWithStop" : "FlowerUacObserveWithStop"));
        var output = new StringBuilder(32768);
        int code = call(output, 32768, new UIntPtr((ulong)cancel.SafeWaitHandle.DangerousGetHandle().ToInt64()),
            new UIntPtr((ulong)physicalStop.SafeWaitHandle.DangerousGetHandle().ToInt64()));
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
    internal static JsonDocument ObserveProgramQualificationFields(ManualResetEvent cancel, ManualResetEvent physicalStop)
    {
        var call = Marshal.GetDelegateForFunctionPointer<ObserveWithStop>(NativeLibrary.GetExport(Library(), "FlowerUacObserveProgramFieldsWithStop"));
        var output = new StringBuilder(32768); int code = call(output, 32768,
            new UIntPtr((ulong)cancel.SafeWaitHandle.DangerousGetHandle().ToInt64()), new UIntPtr((ulong)physicalStop.SafeWaitHandle.DangerousGetHandle().ToInt64()));
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
    internal static JsonDocument ProgramIdentity(string path) => ProgramArgument("FlowerUacInspectProgram", path);
    internal static JsonDocument RecheckProgramBinding(string nonce) => ProgramArgument("FlowerUacRecheckProgramBinding", nonce);
    internal static JsonDocument ReleaseProgramBinding(string nonce) => ProgramArgument("FlowerUacReleaseProgramBinding", nonce);
    internal static JsonDocument RegisterProgramQualification(string nonce) => ProgramArgument("FlowerUacRegisterProgramQualification", nonce);
    internal static JsonDocument RecordProgramQualification(uint index, uint targetPid, string observationNonce)
    {
        var call = Marshal.GetDelegateForFunctionPointer<QualificationSample>(NativeLibrary.GetExport(Library(), "FlowerUacRecordProgramQualification"));
        var output = new StringBuilder(32768); int code = call(index, targetPid, observationNonce, output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
    private static JsonDocument ProgramArgument(string export, string argument)
    {
        var call = Marshal.GetDelegateForFunctionPointer<Publisher>(NativeLibrary.GetExport(Library(), export));
        var output = new StringBuilder(32768); int code = call(argument, output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
    internal static JsonDocument ProgramBindingReadiness() => ProgramWithoutArgument("FlowerUacProgramBindingReadiness");
    internal static JsonDocument ProgramQualificationDraft() => ProgramWithoutArgument("FlowerUacProgramQualificationDraft");
    private static JsonDocument ProgramWithoutArgument(string export)
    {
        var call = Marshal.GetDelegateForFunctionPointer<Observe>(NativeLibrary.GetExport(Library(), export));
        var output = new StringBuilder(32768); int code = call(output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
    internal static JsonDocument ExecutePrompt(string expected, string action)
    {
        if (action is not ("esc" or "accept")) throw new Boundary("uac_action_rejected");
        var call = Marshal.GetDelegateForFunctionPointer<Execute>(NativeLibrary.GetExport(Library(), "FlowerUacExecute"));
        var output = new StringBuilder(32768); int code = call(expected, action, output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document);
        return document;
    }
    internal static JsonDocument StartStopMonitor(ManualResetEvent cancel, ManualResetEvent physicalStop)
    {
        var call = Marshal.GetDelegateForFunctionPointer<StartMonitor>(NativeLibrary.GetExport(Library(), "FlowerUacStartStopMonitor"));
        var output = new StringBuilder(32768);
        int code = call(new UIntPtr((ulong)cancel.SafeWaitHandle.DangerousGetHandle().ToInt64()),
            new UIntPtr((ulong)physicalStop.SafeWaitHandle.DangerousGetHandle().ToInt64()), output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
    internal static JsonDocument StopStopMonitor()
    {
        var call = Marshal.GetDelegateForFunctionPointer<Observe>(NativeLibrary.GetExport(Library(), "FlowerUacStopStopMonitor"));
        var output = new StringBuilder(32768); int code = call(output, 32768);
        if (code == 3 || output.Length == 0) throw new Boundary("uac_native_response_unavailable");
        var document = JsonDocument.Parse(output.ToString()); Protocol.CheckUnique(document); return document;
    }
}

internal static class UacIdentity
{
    // A file-only rule cannot express the payload accepted by these hosts.
    // Keep this restriction local to preauthorization; explicit chat scopes
    // still use Inspect and retain their existing semantic authority checks.
    private static readonly HashSet<string> AllowlistExecutionHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "powershell_ise.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "dotnet.exe",
        "java.exe", "javaw.exe", "perl.exe", "ruby.exe", "php.exe", "lua.exe", "luajit.exe",
        "msiexec.exe", "rundll32.exe", "regsvr32.exe", "dllhost.exe", "msbuild.exe",
        "installutil.exe", "regasm.exe", "regsvcs.exe", "runas.exe", "pcalua.exe",
        "forfiles.exe", "wmic.exe", "schtasks.exe", "sc.exe", "control.exe", "hh.exe",
        "explorer.exe", "wsl.exe", "bash.exe", "sh.exe", "conhost.exe", "wt.exe", "WindowsTerminal.exe",
    };
    internal static bool AllowlistExecutionHostName(string? pathOrName)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return false;
        var name = Path.GetFileName(pathOrName.Trim());
        // Microsoft's dotnet apphost uses this resource name. Managed shell
        // apphosts can also carry the managed DLL rather than their EXE name.
        if (name.Equals(".NET Host", StringComparison.OrdinalIgnoreCase)) return true;
        if (Path.GetExtension(name).Equals(".dll", StringComparison.OrdinalIgnoreCase)) name = Path.ChangeExtension(name, ".exe");
        else if (Path.GetExtension(name).Length == 0) name += ".exe";
        return AllowlistExecutionHosts.Contains(name)
            || System.Text.RegularExpressions.Regex.IsMatch(name, @"\Apython\d+(?:\.\d+)*w?(?:\.exe)?\z",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }
    internal static bool AllowlistSupported(string path)
    {
        if (AllowlistExecutionHostName(path)) return false;
        try
        {
            // Prevent writing/replacing this file while reading its version
            // resource. Actual matching is reached only after native binding
            // has pinned its ancestors and verified the file/hash/signature.
            // OriginalFilename is a veto, never an alternate granting identity.
            using var pinned = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return !KnownManagedPayloadHost(pinned)
                && !AllowlistExecutionHostName(FileVersionInfo.GetVersionInfo(path).OriginalFilename);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
            or NotSupportedException or Win32Exception or BadImageFormatException or System.Security.SecurityException)
        { return false; }
    }
    private static bool KnownManagedPayloadHost(FileStream pinned)
    {
        // Apphost resources normally name the application, not dotnet.exe or
        // .NET Host. The approved EXE therefore does not pin its managed DLL.
        // Reject the CLR header and known hostfxr entry-point family from the
        // same pinned bytes. This is a veto, not a general loader proof.
        if (pinned.Length < 64 || pinned.ReadByte() != 'M' || pinned.ReadByte() != 'Z') return false;
        pinned.Position = 0;
        using (var pe = new PEReader(pinned, PEStreamOptions.LeaveOpen))
            if (pe.PEHeaders.PEHeader is { } header
                && (header.CorHeaderTableDirectory.Size != 0 || header.CorHeaderTableDirectory.RelativeVirtualAddress != 0)) return true;
        pinned.Position = 0;
        ReadOnlySpan<byte> marker = "hostfxr_main"u8;
        var chunk = new byte[65536]; int matched = 0, count;
        while ((count = pinned.Read(chunk)) > 0)
            foreach (var value in chunk.AsSpan(0, count))
            {
                matched = value == marker[matched] ? matched + 1 : value == marker[0] ? 1 : 0;
                if (matched == marker.Length) return true;
            }
        return false;
    }
    internal static void RequireAllowlistSupported(string path)
    {
        if (!AllowlistSupported(path)) throw new Boundary("uac_allowlist_payload_host_rejected");
    }
    internal static UacApplicationPermission InspectForAllowlist(string path)
    {
        if (AllowlistExecutionHostName(path)) throw new Boundary("uac_allowlist_payload_host_rejected");
        using var document = UacNativeBridge.ProgramIdentity(NormalizePath(path));
        var inspected = UacProgramBinding.DecodeIdentity(document.RootElement);
        var identity = inspected.Permission;
        RequireAllowlistSupported(identity.Path);
        if (!inspected.AllowlistProtected) throw new Boundary("uac_allowlist_program_writable");
        return identity with { Arguments = "" };
    }
    internal static UacApplicationPermission Inspect(string path)
    {
        using var document = UacNativeBridge.ProgramIdentity(NormalizePath(path));
        return UacProgramBinding.DecodeIdentity(document.RootElement).Permission;
    }
    private static string NormalizePath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.Any(char.IsControl) || path.Skip(2).Contains(':') || path.Contains('*') || path.Contains('?'))
            throw new Boundary("uac_program_path_rejected");
        return Path.GetFullPath(path);
    }
}
