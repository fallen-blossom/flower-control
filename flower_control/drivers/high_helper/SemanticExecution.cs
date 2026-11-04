using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed record ExecutionPayload(string Path, string Sha256);
internal sealed record ExecutionContinuation(string PreviousRequestId, string Outcome, string Evidence);
internal sealed record IndependentNewRun(string ExitReference, string Evidence);
internal sealed record SemanticExecutionSpec(string[] Argv, string WorkingDirectory, string ExecutableSha256,
    ExecutionPayload[] Payloads, string Purpose, ExecutionContinuation? Continuation = null, IndependentNewRun? NewRun = null);

// One immutable execution snapshot within a separately approved work. This
// pins entry files; it is not a sandbox or proof of all imports/child effects.
internal sealed class SemanticExecution : IDisposable
{
    private sealed record Entry(string Kind, string Host, string? File = null, int? FileArgument = null, int? CodeArgument = null,
        string[]? AdditionalFiles = null);
    private sealed record Binding(int Schema, string TaskId, string RequestId, string ProgramRef, string Target,
        string WorkId, long GrantRevision, Entry Entry, string ExecutionKey, AuditStamp Audit);
    private sealed record UnknownExecution(string Target, string ExecutionKey, string OriginalRequestId, string State);
    private sealed record ClosedExecution(string ExitReference, uint ExitCode);
    private static readonly ConcurrentDictionary<string, SemanticExecution> Retained = new();
    // 32 bound paths of 1024 UTF-16 chars can occupy ~192KiB when JSON escaped.
    private const int BindingBytesLimit = 256 * 1024;
    private readonly string retentionId = Guid.NewGuid().ToString("N");
    private readonly List<FileStream> files = [];
    private readonly List<SafeFileHandle> directories = [];
    private readonly SemanticExecutionSpec spec;
    private readonly ProgramLaunchQuery query;
    private object? continuationReceipt;
    private readonly Action check;
    private readonly Entry entry;
    private readonly string canonicalImage;
    private readonly Dictionary<string, string> environment;
    private bool retained, closed;
    internal string WorkingDirectory => spec.WorkingDirectory;
    internal string Arguments { get; }
    internal IReadOnlyDictionary<string, string> Environment => environment;
    internal bool HasNewRun => spec.NewRun is not null;
    internal object Evidence => new { spec.ExecutableSha256, spec.Payloads, spec.Purpose, Entry = entry, ExecutionKey = ExecutionKey(canonicalImage),
        EnvironmentSha256 = EnvironmentHash(environment), PinnedPayloadCount = spec.Payloads.Length,
        BindingLifetime = "helper_and_tracked_workload", DependencyIsolation = false,
        Continuation = spec.Continuation is null ? null : new { spec.Continuation.PreviousRequestId, spec.Continuation.Outcome,
            ReviewKind = "host_agent_attestation", NativeBusinessVerified = false, OriginalReceipt = continuationReceipt },
        IndependentNewRun = spec.NewRun is null ? null : new { spec.NewRun.ExitReference,
            PreviousBusinessState = "unknown", CurrentWorkAuthorityOnly = true, ExitProof = continuationReceipt } };
    internal object Details => new { spec.Argv, EffectiveArguments = Arguments, spec.WorkingDirectory, spec.Payloads, spec.Purpose, spec.Continuation, spec.NewRun };

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, SafeProcessHandle source, IntPtr targetProcess,
        out SafeWaitHandle target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();

    internal static string Reference(string image, SemanticExecutionSpec spec)
    {
        using var bytes = new MemoryStream();
        using var writer = new BinaryWriter(bytes, Encoding.UTF8, true);
        void Put(string value) { var data = Encoding.UTF8.GetBytes(value); writer.Write(data.Length); writer.Write(data); }
        Put("flower-semantic-launch-v2"); Put(image); Put(spec.WorkingDirectory); Put(spec.ExecutableSha256);
        writer.Write(spec.Argv.Length); foreach (string value in spec.Argv) Put(value);
        writer.Write(spec.Payloads.Length); foreach (var value in spec.Payloads) { Put(value.Path); Put(value.Sha256); }
        if (spec.Continuation is { } next) {
            Put("flower-semantic-next-run-v1"); Put(next.PreviousRequestId); Put(next.Outcome); Put(next.Evidence);
        }
        if (spec.NewRun is { } independent) {
            Put("flower-independent-new-run-v1"); Put(independent.ExitReference); Put(independent.Evidence);
        }
        return Convert.ToHexString(SHA256.HashData(bytes.ToArray())).ToLowerInvariant();
    }
    private static string EnvironmentHash(IReadOnlyDictionary<string, string> environment)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\0', environment
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => pair.Key + "=" + pair.Value))))).ToLowerInvariant();
    private string ExecutionKey(string image)
    {
        // The wire reference preserves exact parameters. This narrower key
        // detects known repeats despite path spelling or display-text changes.
        int entryIndex = entry.FileArgument ?? entry.CodeArgument ?? 0;
        var args = spec.Argv.Select((value, index) => {
            if (index == entry.FileArgument) return AdminProgramLaunch.Target(entry.File!);
            if (index < entryIndex && entry.Host is "powershell.exe" or "pwsh.exe")
                return value.ToLowerInvariant() switch { "-c" => "-command", "-f" => "-file", "-ec" or "-enc" => "-encodedcommand", var other => other };
            if (index < entryIndex && entry.Host == "cmd.exe") return value.ToLowerInvariant();
            return value;
        }).ToArray();
        var paths = (entry.File is null ? Array.Empty<string>() : [entry.File]).Concat(entry.AdditionalFiles ?? [])
            .Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase);
        ExecutionPayload[] payloads = paths.Select(path => new ExecutionPayload(AdminProgramLaunch.Target(path),
            spec.Payloads.First(v => Path.GetFullPath(v.Path).Equals(path, StringComparison.OrdinalIgnoreCase)).Sha256)).ToArray();
        return Reference(AdminProgramLaunch.Target(image), spec with { Argv = args,
            WorkingDirectory = AdminProgramLaunch.Target(spec.WorkingDirectory), Payloads = payloads, Purpose = "", Continuation = null, NewRun = null });
    }
    internal static void Validate(ProgramLaunchQuery query)
    {
        var spec = query.Execution ?? throw new Boundary("program_launch_execution_binding_required");
        if (query.Arguments != "" || !SemanticLaunchPolicy.ValidPath(query.ProgramPath)
            || !SemanticLaunchPolicy.ValidPath(spec.WorkingDirectory) || !AdminProgramLaunch.Digest(spec.ExecutableSha256)
            || spec.Argv is null || spec.Argv.Length > 128 || spec.Argv.Any(v => v is null || v.Length > 8192 || v.Contains('\0'))
            || spec.Argv.Sum(v => v.Length) > 24000 || spec.Payloads is null || spec.Payloads.Length > 32
            || spec.Payloads.Any(v => v is null || !SemanticLaunchPolicy.ValidPath(v.Path) || !AdminProgramLaunch.Digest(v.Sha256))
            || spec.Payloads.Select(v => Path.GetFullPath(v.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count() != spec.Payloads.Length
            || string.IsNullOrWhiteSpace(spec.Purpose) || spec.Purpose.Length > 1024 || spec.Purpose.Any(char.IsControl))
            throw new Boundary("program_launch_execution_binding_invalid");
        if (Reference(query.ProgramPath, spec) != query.ProgramRef) throw new Boundary("program_launch_execution_reference_changed");
        if (spec.Continuation is { } next && (!AdminProgramLaunch.Id(next.PreviousRequestId) || next.PreviousRequestId == query.RequestId
            || next.Outcome is not ("completed" or "failed" or "partial") || string.IsNullOrWhiteSpace(next.Evidence)
            || next.Evidence.Length > 2048 || next.Evidence.Any(char.IsControl)))
            throw new Boundary("program_launch_continuation_invalid");
        if (spec.NewRun is { } independent && (spec.Continuation is not null || !AdminProgramLaunch.Digest(independent.ExitReference)
            || string.IsNullOrWhiteSpace(independent.Evidence) || independent.Evidence.Length > 2048 || independent.Evidence.Any(char.IsControl)))
            throw new Boundary("program_launch_new_run_invalid");
        _ = BindEntry(query.ProgramPath, spec);
    }
    private static Entry BindEntry(string image, SemanticExecutionSpec spec)
    {
        string name = Path.GetFileName(image).ToLowerInvariant();
        if (!UacIdentity.AllowlistExecutionHostName(name))
        {
            if (UacIdentity.AllowlistSupported(image)) return new("native_image", name);
            // A CLR PE contains its managed entry code in the pinned image.
            // Native apphosts are different: their actual DLL is not inferred
            // from a matching stem or a string somewhere in their bytes.
            using (var stream = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var pe = new PEReader(stream))
                if (pe.HasMetadata && pe.PEHeaders.CorHeader is not null) return new("native_image", name);
            name = Path.GetFileName(FileVersionInfo.GetVersionInfo(image).OriginalFilename ?? "").ToLowerInvariant();
            if (name == "" || name == ".net host" || name.EndsWith(".dll", StringComparison.Ordinal))
                throw new Boundary("program_launch_apphost_payload_unbound");
        }
        var args = spec.Argv;
        Entry FileEntry(string value, int index)
        {
            if (value == "-") throw new Boundary("program_launch_stdin_payload_unbound");
            string path = Path.GetFullPath(value, spec.WorkingDirectory);
            if (!SemanticLaunchPolicy.ValidPath(path) || !spec.Payloads.Any(v =>
                    Path.GetFullPath(v.Path).Equals(path, StringComparison.OrdinalIgnoreCase)))
                throw new Boundary("program_launch_entry_file_not_bound");
            return new("file", name, path, index);
        }
        Entry Inline(int index)
        {
            if (index >= args.Length || string.IsNullOrWhiteSpace(args[index])) throw new Boundary("program_launch_inline_code_missing");
            return new("inline_argv", name, CodeArgument: index);
        }
        string BoundFile(string path)
        {
            path = Path.GetFullPath(path, spec.WorkingDirectory);
            if (!SemanticLaunchPolicy.ValidPath(path) || !spec.Payloads.Any(v =>
                    Path.GetFullPath(v.Path).Equals(path, StringComparison.OrdinalIgnoreCase)))
                throw new Boundary("program_launch_entry_file_not_bound");
            return path;
        }
        if (name is "python.exe" or "pythonw.exe" || System.Text.RegularExpressions.Regex.IsMatch(name, @"\Apython\d+(?:\.\d+)*w?\.exe\z"))
        {
            for (int i = 0; i < args.Length; ++i)
            {
                string value = args[i];
                if (value == "-c") return Inline(i + 1);
                if (value == "-m") throw new Boundary("program_launch_module_resolution_unbound");
                if (value == "--") { if (++i < args.Length) return FileEntry(args[i], i); break; }
                if (value is "-I" or "-P" or "-E" or "-s" or "-S" or "-u" or "-B" or "-O" or "-OO" or "-q" or "-v" or "-b" or "-bb" or "-d" or "-i") continue;
                if (value is "-W" or "-X") { if (++i < args.Length) continue; break; }
                if (value.StartsWith("-W", StringComparison.Ordinal) || value.StartsWith("-X", StringComparison.Ordinal)) continue;
                if (value.StartsWith('-') || value == "-") break;
                return FileEntry(value, i); // Later -c/-m are script arguments.
            }
        }
        else if (name is "node.exe")
        {
            for (int i = 0; i < args.Length; ++i)
            {
                string value = args[i];
                if (value is "-e" or "--eval" or "-p" or "--print") return Inline(i + 1);
                if (value.StartsWith("--eval=", StringComparison.Ordinal) && value.Length > 7) return new("inline_argv", name);
                if (value == "--") { if (++i < args.Length) return FileEntry(args[i], i); break; }
                if (value is "--no-warnings" or "--no-deprecation" or "--trace-warnings" or "--use-strict"
                    or "--input-type=module" or "--input-type=commonjs") continue;
                if (value.StartsWith('-')) break;
                return FileEntry(value, i);
            }
        }
        else if (name is "powershell.exe" or "pwsh.exe")
        {
            for (int i = 0; i < args.Length; ++i)
            {
                string value = args[i].ToLowerInvariant();
                if (value is "-command" or "-c" or "-encodedcommand" or "-enc" or "-ec")
                {
                    if (i + 1 < args.Length && args[i + 1] == "-") throw new Boundary("program_launch_stdin_payload_unbound");
                    return Inline(i + 1);
                }
                if (value is "-file" or "-f") { if (++i < args.Length) return FileEntry(args[i], i); break; }
                if (value is "-noprofile" or "-noninteractive" or "-nologo" or "-sta" or "-mta") continue;
                if (value is "-executionpolicy" or "-windowstyle") { if (++i < args.Length) continue; break; }
                break; // Do not guess prefix aliases, stdin or implicit commands.
            }
        }
        else if (name is "dotnet.exe")
        {
            int index = args.Length > 0 && args[0] == "exec" ? 1 : 0;
            var extra = new List<string>(); var seen = new HashSet<string>(StringComparer.Ordinal);
            while (index < args.Length && args[index].StartsWith('-'))
            {
                string option = args[index++];
                if (!seen.Add(option) || index >= args.Length) throw new Boundary("program_launch_dotnet_option_unbound");
                string value = args[index++];
                if (option is "--runtimeconfig" or "--depsfile")
                {
                    if (args[0] != "exec" || !Path.GetExtension(value).Equals(".json", StringComparison.OrdinalIgnoreCase))
                        throw new Boundary("program_launch_dotnet_option_unbound");
                    extra.Add(BoundFile(value));
                }
                else if (option == "--fx-version" && Regex.IsMatch(value, @"\A[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\z", RegexOptions.CultureInvariant)) { }
                else if (option == "--roll-forward" && value is "LatestPatch" or "Minor" or "LatestMinor" or "Major" or "LatestMajor" or "Disable") { }
                else throw new Boundary("program_launch_dotnet_option_unbound");
            }
            if (index < args.Length && !args[index].StartsWith('-') && Path.GetExtension(args[index]).Equals(".dll", StringComparison.OrdinalIgnoreCase))
                return FileEntry(args[index], index) with { AdditionalFiles = extra.ToArray() };
        }
        else if (name == "cmd.exe")
        {
            int index = Array.FindIndex(args, value => value.Equals("/c", StringComparison.OrdinalIgnoreCase));
            var options = args.Take(Math.Max(0, index)).Select(value => value.ToLowerInvariant()).ToArray();
            if (index < 0 || index + 1 >= args.Length || !options.Contains("/d") || !options.Contains("/s")
                || options.Any(value => value is not ("/d" or "/s" or "/q" or "/v:off" or "/v:on" or "/e:on" or "/e:off")))
                throw new Boundary("program_launch_cmd_literal_arguments_required");
            if (index + 2 == args.Length && Path.GetExtension(args[index + 1]).ToLowerInvariant() is not (".cmd" or ".bat"))
                return Inline(index + 1); // Exactly one explicit shell-code string, never joined argv.
            if (options.Contains("/v:on") || args.Skip(index + 1).Any(value =>
                    value.Any(c => char.IsControl(c) || "\"%!^&|<>()".Contains(c))))
                throw new Boundary("program_launch_cmd_literal_arguments_required");
            if (Path.GetExtension(args[index + 1]).ToLowerInvariant() is not (".cmd" or ".bat"))
                throw new Boundary("program_launch_cmd_batch_required");
            return FileEntry(args[index + 1], index + 1);
        }
        else if (name == "msiexec.exe")
        {
            if (args.Any(value => value.Contains('"') || value.Any(char.IsControl)))
                throw new Boundary("program_launch_msi_option_unbound");
            if (args.Length < 3 || !args.Any(value => value.Equals("/norestart", StringComparison.OrdinalIgnoreCase)))
                throw new Boundary("program_launch_msi_norestart_required");
            string action = args[0].ToLowerInvariant();
            bool repair = Regex.IsMatch(action, @"\A/f[pocedamusv]*\z", RegexOptions.CultureInvariant);
            if (action is not ("/i" or "/package" or "/x" or "/uninstall" or "/a") && !repair
                || !Path.GetExtension(args[1]).Equals(".msi", StringComparison.OrdinalIgnoreCase))
                throw new Boundary("program_launch_msi_package_required");
            var package = FileEntry(args[1], 1); var extra = new List<string>();
            for (int i = 2; i < args.Length; ++i)
            {
                string value = args[i], lower = value.ToLowerInvariant();
                if (value.Any(char.IsControl)) throw new Boundary("program_launch_msi_option_unbound");
                if (lower is "/norestart" or "/quiet" or "/passive" or "/qn" or "/qn+" or "/qb" or "/qb+" or "/qb!" or "/qb+!" or "/qb!+" or "/qr" or "/qf") continue;
                if (lower == "/log" || Regex.IsMatch(lower, @"\A/l[iwearucmopvx+!*]*\z", RegexOptions.CultureInvariant))
                {
                    if (++i >= args.Length || !SemanticLaunchPolicy.ValidPath(args[i])) throw new Boundary("program_launch_msi_log_invalid");
                    continue;
                }
                int equal = value.IndexOf('=');
                if (equal <= 0 || !Regex.IsMatch(value[..equal], @"\A[A-Za-z_][A-Za-z0-9_]*\z", RegexOptions.CultureInvariant))
                    throw new Boundary("program_launch_msi_option_unbound");
                string key = value[..equal].ToUpperInvariant(), content = value[(equal + 1)..];
                if (key is "REBOOT" or "TRANSFORMS" or "PATCH" && value[..equal] != key)
                    throw new Boundary("program_launch_msi_option_unbound");
                if (key == "REBOOT" && !content.Equals("ReallySuppress", StringComparison.OrdinalIgnoreCase))
                    throw new Boundary("program_launch_msi_restart_rejected");
                if (key is "TRANSFORMS" or "PATCH")
                    foreach (var path in content.Split(';'))
                    {
                        string extension = key == "PATCH" ? ".msp" : ".mst";
                        if (path.Length == 0 || !Path.GetExtension(path).Equals(extension, StringComparison.OrdinalIgnoreCase))
                            throw new Boundary("program_launch_msi_option_unbound");
                        extra.Add(BoundFile(path));
                    }
            }
            return package with { AdditionalFiles = extra.Distinct(StringComparer.OrdinalIgnoreCase).ToArray() };
        }
        else if (name is "py.exe" or "pyw.exe") throw new Boundary("program_launch_python_launcher_resolution_unbound");
        else if (name is "cscript.exe" or "wscript.exe")
        {
            for (int i = 0; i < args.Length; ++i)
            {
                string value = args[i];
                if (value.Equals("//nologo", StringComparison.OrdinalIgnoreCase) || value.Equals("//b", StringComparison.OrdinalIgnoreCase)) continue;
                if (value.StartsWith("//", StringComparison.Ordinal)) break;
                return FileEntry(value, i);
            }
        }
        // Unknown hosts and dynamic/module/stdin forms are explicit gaps.
        // An unrelated payload or a script argument resembling -c never binds them.
        throw new Boundary("program_launch_execution_host_form_unsupported");
    }
    internal SemanticExecution(ProgramLaunchQuery query, string actualExecutableSha256, Action check, string canonicalImage)
    {
        this.query = query;
        this.canonicalImage = canonicalImage;
        this.check = check; check();
        spec = query.Execution ?? throw new Boundary("program_launch_execution_binding_required");
        entry = BindEntry(query.ProgramPath, spec);
        if (actualExecutableSha256 != spec.ExecutableSha256) throw new Boundary("program_launch_executable_changed");
        // No caller environment, profiles or provider credentials are copied.
        environment = AdminProgramLaunch.OrdinaryEnvironment(System.Environment.GetEnvironmentVariables()
            .Cast<System.Collections.DictionaryEntry>().Select(v => new KeyValuePair<string, string>((string)v.Key, (string)v.Value!)));
        Arguments = entry.Host == "cmd.exe" ? CmdArguments(entry, spec) : string.Join(' ', spec.Argv.Select(Quote));
        if (entry.Host == "cmd.exe" && Arguments.Length + query.ProgramPath.Length + 4 > 8191)
            throw new Boundary("program_launch_cmd_command_line_too_long");
        if (Arguments.Length + query.ProgramPath.Length + 4 > 32767) throw new Boundary("program_launch_command_line_too_long");
        string pinStage = "workdir_pin"; int payloadIndex = -1;
        try
        {
            PinDirectory(spec.WorkingDirectory);
            foreach (var payload in spec.Payloads)
            {
                pinStage = "payload_pin"; ++payloadIndex;
                check();
                PinDirectory(Path.GetDirectoryName(payload.Path)!);
                BrokerPolicy.RejectLinks(payload.Path);
                var file = new FileStream(payload.Path, FileMode.Open, FileAccess.Read, FileShare.Read); files.Add(file);
                RequireCanonical(file.SafeFileHandle, payload.Path);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[256 * 1024]; int count;
                while ((count = file.Read(buffer)) > 0) { check(); hash.AppendData(buffer, 0, count); }
                check();
                if (Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant() != payload.Sha256)
                    throw new Boundary("program_launch_payload_changed");
            }
            Recheck();
        }
        catch (Exception error) { AdminLaunchFailure.TagPin(error, pinStage, payloadIndex); Close(); throw; }
    }
    private static string CmdArguments(Entry entry, SemanticExecutionSpec spec)
    {
        if (entry.CodeArgument is { } code)
            return string.Join(' ', spec.Argv.Take(code - 1)) + " /c \"" + spec.Argv[code] + "\"";
        int index = entry.FileArgument!.Value;
        var options = spec.Argv.Take(index - 1).Where(value => !value.Equals("/v:off", StringComparison.OrdinalIgnoreCase));
        // cmd /s consumes its own outer quotes. CRT backslash escaping would
        // change batch arguments or allow a quoted path to become a command.
        return string.Join(' ', options) + " /v:off /c \"" + string.Join(' ', spec.Argv.Skip(index).Select(value => "\"" + value + "\"")) + "\"";
    }
    private static string Quote(string value)
    {
        // Windows CRT/CommandLineToArgvW quoting, including empty args and
        // trailing backslashes. No additional cmd/PowerShell layer is inserted.
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value)
        {
            if (c == '\\') { ++slashes; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; result.Append(c);
        }
        result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
    }
    private static void RequireCanonical(SafeFileHandle file, string expected)
    {
        var path = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(file, path, (uint)path.Capacity, 0);
        if (length == 0 || length >= path.Capacity || !path.ToString().StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Path.GetFullPath(path.ToString()[4..]).Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("program_launch_payload_path_changed");
    }
    private void PinDirectory(string path)
    {
        var ancestors = new Stack<string>();
        for (string? item = Path.GetFullPath(path); item is not null; item = Path.GetDirectoryName(item)) ancestors.Push(item);
        while (ancestors.TryPop(out var item))
        {
            check();
            BrokerPolicy.RejectLinks(item);
            var handle = CreateFileW(item, 0x20080, 1, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new Boundary("program_launch_context_pin_failed", Marshal.GetLastWin32Error()); }
            directories.Add(handle); RequireCanonical(handle, item);
        }
    }
    internal void Recheck()
    {
        if (closed) throw new Boundary("program_launch_execution_binding_released");
        // Files deny writes/deletion while held. Check path objects again just
        // before CreateProcess without rescanning their contents under desktop locks.
        BrokerPolicy.RejectLinks(spec.WorkingDirectory);
        for (int i = 0; i < files.Count; ++i) RequireCanonical(files[i].SafeFileHandle, spec.Payloads[i].Path);
    }
    private static string BindingPath(BrokerPolicy policy, Peer own, string requestId, bool create = false)
    {
        if (policy.Fixture || own.Integrity != 12288 || own.User != policy.UserSid) throw new Boundary("program_launch_binding_role_rejected");
        string root = Path.Combine(InstallationLocation.Current().ProgramRoot, "execution-bindings");
        if (create) AuditFiles.EnsureDirectory(root);
        root = Path.Combine(root, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(own.User + "|" + own.Session))).ToLowerInvariant());
        if (create) AuditFiles.EnsureDirectory(root);
        else if (Directory.Exists(root)) AuditFiles.Check(root, true);
        if (!AdminProgramLaunch.Id(requestId)) throw new Boundary("program_launch_binding_request_invalid");
        return Path.Combine(root, requestId + ".json");
    }
    internal void SealIntent(BrokerPolicy policy, Peer own, ProgramLaunchQuery query, WorkAuthorityRecord grant,
        string target, AuditStamp audit)
    {
        var binding = new Binding(1, query.TaskId, query.RequestId, query.ProgramRef, target, grant.WorkId, grant.Revision, entry, ExecutionKey(canonicalImage), audit);
        AuditFiles.WriteNew(BindingPath(policy, own, query.RequestId, create: true), JsonSerializer.SerializeToUtf8Bytes(binding));
    }
    internal static bool CanContinueAfterExit(BrokerPolicy policy, Peer own, AdminLaunchEntry entry)
    {
        // Creation/identity/exit must be known. This permits a new operation;
        // it never replays the old request or asserts its business outcome.
        if (entry.State != "handoff_unknown" || entry.Dispatched != true || entry.Process is null || entry.ExitCode is null) return false;
        if (entry.WorkloadState is not ("legacy" or "exited")) return false;
        try
        {
            string path = BindingPath(policy, own, entry.RequestId);
            AuditFiles.Check(path, false);
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length is < 1 or > BindingBytesLimit) return false;
            var binding = JsonSerializer.Deserialize<Binding>(file);
            return binding is not null && binding.Schema == 1 && binding.TaskId == entry.TaskId && binding.RequestId == entry.RequestId
                && binding.ProgramRef == entry.ProgramRef && binding.Target == entry.Target && binding.GrantRevision > 0
                && Guid.TryParseExact(binding.WorkId, "N", out _) && AdminProgramLaunch.Digest(binding.ExecutionKey)
                && binding.Entry.Kind is "native_image" or "file" or "inline_argv"
                && (entry.WorkloadState == "exited" || binding.Entry.Kind is "file" or "inline_argv")
                && AdminProgramLaunch.Digest(binding.Audit.Hash) && binding.Audit.Sequence > 0;
        }
        catch (Exception) { return false; }
    }
    internal static AdminLaunchEntry? FindClosed(BrokerPolicy policy, Peer own, string requestId)
    {
        string path = BindingPath(policy, own, requestId) + ".closed";
        if (!File.Exists(path)) return null;
        AuditFiles.Check(path, false);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 16384) throw new Boundary("program_launch_closed_receipt_invalid");
        var entry = JsonSerializer.Deserialize<AdminLaunchEntry>(file);
        if (entry is null || entry.RequestId != requestId || entry.User != own.User || entry.Session != own.Session
            || !CanContinueAfterExit(policy, own, entry)) throw new Boundary("program_launch_closed_receipt_invalid");
        return entry;
    }
    internal static void ArchiveClosed(BrokerPolicy policy, Peer own, AdminLaunchEntry entry)
    {
        if (!CanContinueAfterExit(policy, own, entry)) throw new Boundary("program_launch_bound_exit_required");
        // Called only under AdminProgramLaunch.Gate. An already archived old
        // receipt must never roll the latest execution pointer backwards.
        var prior = FindClosed(policy, own, entry.RequestId);
        if (prior is not null)
        { if (prior != entry) throw new Boundary("program_launch_closed_receipt_conflict"); return; }
        using (var input = new FileStream(BindingPath(policy, own, entry.RequestId), FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var binding = JsonSerializer.Deserialize<Binding>(input) ?? throw new Boundary("program_launch_execution_binding_invalid");
            string blocked = UnknownPath(policy, own, entry.Target, binding.ExecutionKey, create: true);
            var head = ReadUnknown(blocked, entry.Target, binding.ExecutionKey);
            var next = new UnknownExecution(entry.Target, binding.ExecutionKey, entry.RequestId, "business_unresolved");
            if (head != next) {
                if (head is not null && FindClosed(policy, own, head.OriginalRequestId) is null)
                    throw new Boundary("program_launch_previous_exit_receipt_missing");
                // Derived head only: immutable original receipts and append
                // audit events remain unchanged. Persist and read back the new
                // unresolved head before removing the active creation intent.
                string pending = blocked + ".head." + Guid.NewGuid().ToString("N");
                AuditFiles.WriteNew(pending, JsonSerializer.SerializeToUtf8Bytes(next));
                File.Move(pending, blocked, true);
                if (ReadUnknown(blocked, entry.Target, binding.ExecutionKey) != next)
                    throw new Boundary("program_launch_execution_head_unconfirmed");
            }
        }
        AuditFiles.WriteNew(BindingPath(policy, own, entry.RequestId, create: true) + ".closed", JsonSerializer.SerializeToUtf8Bytes(entry));
        if (FindClosed(policy, own, entry.RequestId) != entry) throw new Boundary("program_launch_closed_receipt_unconfirmed");
    }
    private static string UnknownPath(BrokerPolicy policy, Peer own, string target, string key, bool create = false)
    {
        string id = "unknown-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(target + "\n" + key))).ToLowerInvariant();
        return BindingPath(policy, own, id, create) + ".blocked";
    }
    private ClosedExecution? IndependentExit(BrokerPolicy policy, Peer own, string target, WorkAuthorityRecord current)
    {
        if (query.Thread is null || current.WorkId != query.WorkId || current.HostKind != query.Thread.HostKind
            || current.ThreadId != query.Thread.ThreadId || current.State != "active" || current.Revision <= 0)
            throw new Boundary("program_launch_new_run_current_work_required");
        string key = ExecutionKey(canonicalImage);
        var head = ReadUnknown(UnknownPath(policy, own, target, key), target, key);
        if (head is null) return null;
        if (head.OriginalRequestId == query.RequestId) throw new Boundary("program_launch_new_run_new_request_required");
        var previous = FindClosed(policy, own, head.OriginalRequestId)
            ?? throw new Boundary("program_launch_new_run_exit_unconfirmed");
        // Legacy entrypoint exit is not proof that its tracked tree exited.
        if (previous.WorkloadState != "exited" || previous.Dispatched != true || previous.Process is null || previous.ExitCode is null)
            throw new Boundary("program_launch_new_run_tree_exit_required");
        string bindingPath = BindingPath(policy, own, previous.RequestId);
        AuditFiles.Check(bindingPath, false);
        byte[] bytes;
        using (var file = new FileStream(bindingPath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            if (file.Length is < 1 or > BindingBytesLimit) throw new Boundary("program_launch_execution_binding_invalid");
            bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes);
        }
        using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document);
        var binding = Protocol.Decode<Binding>(document);
        if (binding.TaskId != previous.TaskId || binding.RequestId != previous.RequestId || binding.ProgramRef != previous.ProgramRef
            || binding.Target != previous.Target || previous.Target != target || binding.ExecutionKey != key)
            throw new Boundary("program_launch_new_run_exit_binding_rejected");
        if (binding.WorkId == query.WorkId) throw new Boundary("program_launch_new_run_independent_work_required");
        // Opaque version proof only: do not expose another chat's request,
        // process, work, goal, arguments or audit records to the current host.
        string version = string.Join('\n', "flower-independent-exit-v1", target, key,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            Native.Digest(bindingPath + ".closed"), query.TaskId, current.HostKind, current.ThreadId, current.WorkId,
            current.Revision.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return new(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(version))).ToLowerInvariant(), previous.ExitCode.Value);
    }
    internal object? IndependentNewRunReview(BrokerPolicy policy, Peer own, string target, WorkAuthorityRecord current)
    {
        if (spec.Continuation is not null) return null;
        try {
            var proof = IndependentExit(policy, own, target, current);
            return proof is null ? null : new { Eligible = true, proof.ExitReference, proof.ExitCode,
                PreviousTreeExited = true, PreviousBusinessState = "unknown", AuthorityTransferred = false };
        }
        catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or JsonException) {
            return new { Eligible = false, Reason = Program.Code(error), AuthorityTransferred = false };
        }
    }
    internal object? IndependentRootExitReview(BrokerPolicy policy, Peer own, string target, WorkAuthorityRecord current,
        IReadOnlyList<AdminLaunchEntry> blockers, Func<AdminLaunchEntry, string> processState, Func<string, bool> workloadTracked,
        out string? exitReference)
    {
        exitReference = null;
        if (spec.Continuation is not null) return null;
        try
        {
            if (query.Thread is null || current.WorkId != query.WorkId || current.HostKind != query.Thread.HostKind
                || current.ThreadId != query.Thread.ThreadId || current.State != "active" || current.Revision <= 0)
                throw new Boundary("program_launch_new_run_current_work_required");
            var rows = blockers.OrderBy(r => r.RequestId, StringComparer.Ordinal).ToArray();
            if (rows.Length == 0 || !rows.Any(r => r.WorkloadState == "unknown")
                || rows.Any(r => r.Target != target || r.User != own.User || r.Session != own.Session
                    || r.RequestId == query.RequestId || r.State is not ("created" or "unknown" or "handoff_unknown")
                    || r.Dispatched != true || r.WorkloadState is not ("unknown" or "exited")
                    || r.EnvironmentPolicy != "ordinary-app-allowlist-v1"
                    || r.WorkloadState == "unknown" && workloadTracked(r.RequestId)
                    || r.Process is not { } process || r.NativePid != process.Pid || r.NativeCreated != process.Created
                    || process.User != own.User || process.Session != own.Session || process.Integrity != 12288
                    || AdminProgramLaunch.Target(process.Image) != target)) return null;
            var observed = rows.Select(entry => new { Entry = entry, RootProcessState = processState(entry) }).ToArray();
            if (observed.Any(value => value.RootProcessState is not ("exited" or "root_exited")
                || value.RootProcessState == "exited" && value.Entry.ExitCode is null
                || value.RootProcessState == "root_exited" && value.Entry.ExitCode is not null)) return null;
            string key = ExecutionKey(canonicalImage);
            var bindings = new List<(AdminLaunchEntry Entry, string Digest)>();
            foreach (var previous in rows)
            {
                string path = BindingPath(policy, own, previous.RequestId);
                AuditFiles.Check(path, false);
                byte[] bytes;
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (file.Length is < 1 or > BindingBytesLimit) throw new Boundary("program_launch_execution_binding_invalid");
                    bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes);
                }
                using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document);
                var binding = Protocol.Decode<Binding>(document);
                if (binding.Schema != 1 || binding.TaskId != previous.TaskId || binding.RequestId != previous.RequestId
                    || binding.ProgramRef != previous.ProgramRef || binding.Target != previous.Target || binding.Target != target
                    || binding.ExecutionKey != key || binding.WorkId == query.WorkId || binding.GrantRevision <= 0
                    || binding.Entry.Kind is not ("native_image" or "file" or "inline_argv")
                    || !AdminProgramLaunch.Digest(binding.Audit.Hash) || binding.Audit.Sequence <= 0) return null;
                bindings.Add((previous, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()));
            }
            var evidence = JsonSerializer.SerializeToUtf8Bytes(new { Kind = "flower-independent-root-exit-tracking-lost-v1",
                Target = target, ExecutionKey = key, Bindings = bindings.Select(value => new { value.Entry.RequestId, value.Digest }),
                Entries = observed.Select(value => new { value.Entry.RequestId, value.Entry.State, value.Entry.WorkloadState,
                    value.Entry.ExitCode, value.RootProcessState }), query.TaskId, current.HostKind, current.ThreadId,
                current.WorkId, current.Revision });
            exitReference = Convert.ToHexString(SHA256.HashData(evidence)).ToLowerInvariant();
            return new { Eligible = true, ExitReference = exitReference, RootProcessExited = true, PreviousTreeExited = false,
                ProofKind = "root_exit_tracking_lost", TreeEvidence = "helper_restart_workload_tracking_unavailable",
                PreviousBusinessState = "unknown", AuthorityTransferred = false };
        }
        catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or JsonException)
        { return new { Eligible = false, Reason = Program.Code(error), AuthorityTransferred = false }; }
    }
    internal void RequireFreshExecution(BrokerPolicy policy, Peer own, string target, WorkAuthorityRecord? current = null,
        string? rootExitReference = null)
    {
        if (spec.NewRun is { } independent) {
            ClosedExecution? proof = null;
            try { proof = IndependentExit(policy, own, target, current ?? throw new Boundary("program_launch_new_run_current_work_required")); }
            catch (Exception error) when (rootExitReference is not null
                && (error is Boundary || error is IOException || error is UnauthorizedAccessException || error is JsonException)) { }
            if (proof?.ExitReference != independent.ExitReference && rootExitReference != independent.ExitReference)
                throw new Boundary("program_launch_new_run_exit_reference_changed");
            continuationReceipt = proof?.ExitReference == independent.ExitReference
                ? new { proof.ExitReference, proof.ExitCode, PreviousTreeExited = true, PreviousBusinessState = "unknown", AuthorityTransferred = false }
                : new { independent.ExitReference, RootProcessExited = true, PreviousTreeExited = false,
                    ProofKind = "root_exit_tracking_lost", PreviousBusinessState = "unknown", AuthorityTransferred = false };
            return;
        }
        string path = UnknownPath(policy, own, target, ExecutionKey(canonicalImage));
        var head = ReadUnknown(path, target, ExecutionKey(canonicalImage));
        if (head is null && spec.Continuation is null) return;
        if (spec.Continuation is not { } next)
            throw new Boundary("program_launch_same_execution_business_unresolved");
        if (head is null || head.OriginalRequestId != next.PreviousRequestId)
            throw new Boundary("program_launch_continuation_latest_exit_required");
        var previous = FindClosed(policy, own, next.PreviousRequestId)
            ?? throw new Boundary("program_launch_continuation_exit_unconfirmed");
        var bindingPath = BindingPath(policy, own, previous.RequestId);
        AuditFiles.Check(bindingPath, false);
        using var file = new FileStream(bindingPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > BindingBytesLimit) throw new Boundary("program_launch_execution_binding_invalid");
        using var document = JsonDocument.Parse(file); Protocol.CheckUnique(document);
        var binding = Protocol.Decode<Binding>(document);
        if (previous.TaskId != query.TaskId || previous.Target != target || binding.TaskId != query.TaskId
            || binding.RequestId != previous.RequestId || binding.ProgramRef != previous.ProgramRef
            || binding.Target != target || binding.ExecutionKey != head.ExecutionKey)
            throw new Boundary("program_launch_continuation_work_binding_rejected");
        // Current WorkAuthority has been independently required before this
        // path and is checked again at dispatch. A later approved work may use
        // an earlier result in the same authenticated chat; it never inherits
        // the earlier (possibly closed/revoked) authority.
        continuationReceipt = new { previous.RequestId, previous.ExitCode, previous.Process, PreviousWorkId = binding.WorkId,
            CurrentWorkId = query.WorkId,
            OriginalIntent = binding.Audit, OriginalBusinessState = "unresolved_by_native",
            ClosedSha256 = Native.Digest(BindingPath(policy, own, previous.RequestId) + ".closed") };
    }
    private static UnknownExecution? ReadUnknown(string path, string target, string key)
    {
        if (!File.Exists(path)) return null;
        AuditFiles.Check(path, false);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 4096) throw new Boundary("program_launch_execution_head_invalid");
        using var document = JsonDocument.Parse(file); Protocol.CheckUnique(document);
        var head = Protocol.Decode<UnknownExecution>(document);
        if (head.Target != target || head.ExecutionKey != key || !AdminProgramLaunch.Id(head.OriginalRequestId)
            || head.State != "business_unresolved") throw new Boundary("program_launch_execution_head_invalid");
        return head;
    }
    internal void OwnCreated()
    {
        // Ownership transfers before any fallible handle/wait registration.
        // A real child must never lose its pins as ordinary failure cleanup.
        retained = true; Retained[retentionId] = this;
    }
    internal void RetainUntilExit(SafeProcessHandle process)
    {
        if (!retained) OwnCreated();
        if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), out var handle, 0, false, 2))
            throw new Boundary("program_launch_payload_lifetime_unconfirmed", Marshal.GetLastWin32Error());
        var wait = new EventWaitHandle(false, EventResetMode.AutoReset) { SafeWaitHandle = handle };
        try { ThreadPool.RegisterWaitForSingleObject(wait, (_, _) => { Close(); wait.Dispose(); }, null, Timeout.Infinite, true); }
        catch { wait.Dispose(); throw new Boundary("program_launch_payload_lifetime_unconfirmed"); }
    }
    internal void RetainUntilWorkloadExit(string requestId)
    {
        if (!retained) OwnCreated();
        AdminProgramLaunch.RetainPayloads(requestId, Close);
    }
    private void Close()
    {
        if (closed) return; closed = true;
        foreach (var file in files) file.Dispose(); files.Clear();
        foreach (var directory in directories) directory.Dispose(); directories.Clear();
        Retained.TryRemove(retentionId, out _);
    }
    public void Dispose() { if (!retained) Close(); }
}
