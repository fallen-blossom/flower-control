using System.Reflection;
using System.Text.Json;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// Dedicated StartupObject. Never calls broker Main, real permissions, launch,
// work authorization, SYSTEM, UAC, input, or a requested program.
internal static class ExecutionFormsFixture
{
    internal static string Root = "";
    internal static string BindingPath(string requestId) => Path.Combine(Root, requestId + ".json");
    internal static void Check(string path, bool directory)
    {
        var full = Path.GetFullPath(path);
        if (!full.StartsWith(Path.GetFullPath(Root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new Exception("fixture_storage_outside_temp");
        if (directory && !Directory.Exists(path)) throw new DirectoryNotFoundException();
        if (!directory && !File.Exists(path)) throw new FileNotFoundException();
    }
    internal static void WriteNew(string path, byte[] body)
    {
        if (!Path.GetFullPath(path).StartsWith(Path.GetFullPath(Root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new Exception("fixture_storage_outside_temp");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        stream.Write(body); stream.Flush(true);
    }
    private static object Call(object target, string name, params object?[] values)
    {
        try { return target.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, values)!; }
        catch (TargetInvocationException error) { throw error.InnerException!; }
    }
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint rights, out SafeFileHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeFileHandle token, int kind, out int value, int length, out int returned);
    private static bool Elevated(Process process)
    {
        if (!OpenProcessToken(process.Handle, 8, out var token)) throw new Exception("fixture_token_open_failed");
        using (token)
        {
            if (!GetTokenInformation(token, 20, out int value, 4, out _)) throw new Exception("fixture_token_read_failed");
            return value != 0;
        }
    }
    private static int CmdRuntime(string requestPath, string digest)
    {
        // The independent launcher pins this exact fixture/request and starts
        // it with a verified linked Medium token. There is no elevation fallback.
        using var self = Process.GetCurrentProcess();
        var own = Native.Process(self.Id, false).Identity;
        if (own.Integrity != 8192 || Elevated(self)) throw new Exception("fixture_actual_medium_required");
        using var file = new FileStream(requestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[file.Length]; file.ReadExactly(bytes);
        if (Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() != digest) throw new Exception("fixture_request_changed");
        using var json = JsonDocument.Parse(bytes); var results = new List<object>();
        foreach (var item in json.RootElement.GetProperty("cases").EnumerateArray())
        {
            var spec = item.GetProperty("spec").Deserialize<SemanticExecutionSpec>()!;
            string image = item.GetProperty("image").GetString()!;
            string expectedImage = Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.System), "cmd.exe");
            if (!image.Equals(expectedImage, StringComparison.OrdinalIgnoreCase) || spec.ExecutableSha256 != Native.Digest(image)
                || spec.WorkingDirectory != Root || spec.Payloads.Any(p => !Path.GetFullPath(p.Path).StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
                throw new Exception("fixture_exact_cmd_request_required");
            var query = new ProgramLaunchQuery("program_launch", "launch", "fixture-task", "fixture-connection",
                SemanticExecution.Reference(image, spec), "fixture-request", image, Execution: spec);
            SemanticExecution.Validate(query);
            using var execution = new SemanticExecution(query, Native.Digest(image), () => { }, image);
            if (execution.Arguments != item.GetProperty("expected_arguments").GetString()) throw new Exception("fixture_rendering_changed");
            var start = new ProcessStartInfo(image, execution.Arguments) { UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = Root, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.Environment.Clear(); foreach (var pair in execution.Environment) start.Environment[pair.Key] = pair.Value;
            using var child = Process.Start(start) ?? throw new Exception("fixture_cmd_start_failed");
            try
            {
                var actual = Native.Process(child.Id, false).Identity; bool elevated = Elevated(child);
                if (actual.Integrity != 8192 || elevated || actual.User != own.User || actual.Session != own.Session)
                    throw new Exception("fixture_cmd_not_medium");
                var stdout = child.StandardOutput.ReadToEndAsync(); var stderr = child.StandardError.ReadToEndAsync();
                child.StandardInput.WriteLine("go"); child.StandardInput.Close();
                if (!child.WaitForExit(10000)) throw new Exception("fixture_cmd_wait_expired");
                string outputPath = item.GetProperty("output").GetString()!;
                Check(outputPath, false);
                byte[] observed = File.ReadAllBytes(outputPath);
                byte[] expected = Convert.FromBase64String(item.GetProperty("expected_base64").GetString()!);
                if (child.ExitCode != 0 || !observed.SequenceEqual(expected)) throw new Exception("fixture_cmd_bytes_mismatch");
                results.Add(new { kind = item.GetProperty("kind").GetString(), integrity = actual.Integrity, elevated,
                    same_user = actual.User == own.User, same_session = actual.Session == own.Session, child.ExitCode,
                    output_base64 = Convert.ToBase64String(observed), stdout = stdout.GetAwaiter().GetResult(), stderr = stderr.GetAwaiter().GetResult() });
            }
            finally { if (!child.HasExited) { child.Kill(); child.WaitForExit(); } }
        }
        WriteNew(Path.Combine(Root, "result.json"), JsonSerializer.SerializeToUtf8Bytes(new { own_integrity = own.Integrity,
            own_elevated = Elevated(self), source = "actual_current_production_cmd_rendering", cases = results }));
        return 0;
    }
    private static object IndependentRun(JsonElement data, ProgramLaunchQuery query, SemanticExecution execution, string image)
    {
        var own = new Peer(1, 1, 1, "fixture-user", new string('d', 64), 8192);
        var policy = new BrokerPolicy(); string target = AdminProgramLaunch.Target(image);
        var current = new WorkAuthorityRecord(2, query.WorkId, 2, "codex", "fixture-session", "new user requested run", "fixture only",
            "active", "work", "fixture", "fixture-time", "fixture-policy");
        var old = query with { TaskId = "old-other-chat", RequestId = "old-request", WorkId = new string('b',32) };
        execution.SealIntent(policy, own, old, current with { WorkId = old.WorkId }, target, new("fixture", 1, new string('c',64)));
        var closed = new AdminLaunchEntry(old.TaskId, old.RequestId, old.ProgramRef, target, own.User, own.Session,
            "handoff_unknown", Process: new(99, 100, image, 12288, own.User, own.Session), Dispatched: true, ExitCode: 0,
            WorkloadState: "exited");
        SemanticExecution.ArchiveClosed(policy, own, closed);
        var original = Directory.GetFiles(Root, "*.json*").ToDictionary(p=>p,File.ReadAllBytes);
        bool originalBlocked = false;
        try { execution.RequireFreshExecution(policy, own, target, current); }
        catch (Boundary error) when (error.Code == "program_launch_same_execution_business_unresolved") { originalBlocked = true; }
        string change = data.TryGetProperty("change", out var altered) ? altered.GetString()! : "none";
        if (change == "legacy") File.WriteAllBytes(BindingPath(old.RequestId)+".closed", JsonSerializer.SerializeToUtf8Bytes(closed with { WorkloadState="legacy" }));
        if (change == "running") File.WriteAllBytes(BindingPath(old.RequestId)+".closed", JsonSerializer.SerializeToUtf8Bytes(closed with { WorkloadState="running" }));
        if (change == "unknown_dispatch") File.WriteAllBytes(BindingPath(old.RequestId)+".closed", JsonSerializer.SerializeToUtf8Bytes(closed with { Dispatched=null }));
        if (change == "missing_exit") File.Move(BindingPath(old.RequestId)+".closed",BindingPath(old.RequestId)+".missing");
        if (change == "same_work") current=current with { WorkId=old.WorkId };
        var review = JsonSerializer.SerializeToElement(execution.IndependentNewRunReview(policy, own, target, current));
        if (!review.GetProperty("Eligible").GetBoolean()) return new { originalBlocked, review, allowed=false };
        var nativeReport=typeof(AdminProgramLaunch).GetMethod("Report",BindingFlags.Static|BindingFlags.NonPublic)!
            .Invoke(null,[query,null,"rejected","program_launch_same_execution_business_unresolved","unknown",null,false,null,null,
                execution.IndependentNewRunReview(policy,own,target,current)]);
        string reference = review.GetProperty("ExitReference").GetString()!;
        var spec = query.Execution! with { NewRun=new(reference,"Current user explicitly requested a new run; native review confirms the old full tree exited.") };
        var next = query with { RequestId="new-independent-request",Execution=spec,ProgramRef=SemanticExecution.Reference(image,spec) };
        if (change == "work_revision") current=current with { Revision=current.Revision+1 };
        if (change == "other_thread") current=current with { ThreadId="different-thread" };
        if (change == "stale_head") {
            var newer=old with { RequestId="newer-old-request" };
            execution.SealIntent(policy,own,newer,current with {WorkId=old.WorkId},target,new("fixture",2,new string('e',64)));
            SemanticExecution.ArchiveClosed(policy,own,closed with {RequestId=newer.RequestId});
        }
        if (change == "foreign_task") next=next with {TaskId="another-current-task"};
        if (change == "same_old_request") next=next with {RequestId=old.RequestId};
        if (change == "forged_reference") {
            spec=spec with {NewRun=spec.NewRun! with {ExitReference=new string('f',64)}};
            next=next with {Execution=spec,ProgramRef=SemanticExecution.Reference(image,spec)};
        }
        string? rejection=null;
        using (var requested=new SemanticExecution(next,spec.ExecutableSha256,()=>{},image)) {
            SemanticExecution.Validate(next);
            try { requested.RequireFreshExecution(policy,own,target,change=="missing_current_work"?null:current); }
            catch (Boundary error) { rejection=error.Code; }
            return new { originalBlocked,review,allowed=rejection is null,rejection,
                nativeReport,
                originalPreserved=original.All(p=>File.Exists(p.Key)&&File.ReadAllBytes(p.Key).SequenceEqual(p.Value)),
                referenceChanged=next.ProgramRef!=query.ProgramRef,
                executionKeyPreserved=Equals(Call(requested,"ExecutionKey",image),Call(execution,"ExecutionKey",image)),
                actualProgramExecuted=false,productionWorkAuthorityCreated=false };
        }
    }
    private static object RootExitTrackingLostRun(JsonElement data, ProgramLaunchQuery query, SemanticExecution execution, string image)
    {
        var own = new Peer(1, 1, 1, "fixture-user", new string('d', 64), 8192);
        var policy = new BrokerPolicy(); string target = AdminProgramLaunch.Target(image);
        var current = new WorkAuthorityRecord(2, query.WorkId, 2, "codex", "fixture-session", "new user requested run",
            "fixture only", "active", "work", "fixture", "fixture-time", "fixture-policy");
        var old = query with { TaskId = "old-other-chat", RequestId = "old-root-request", WorkId = new string('b', 32) };
        execution.SealIntent(policy, own, old, current with { WorkId = old.WorkId }, target, new("fixture", 1, new string('c', 64)));
        var process = new AdminLaunchedProcess(99, 100, image, 12288, own.User, own.Session);
        var blocker = new AdminLaunchEntry(old.TaskId, old.RequestId, old.ProgramRef, target, own.User, own.Session,
            "created", "helper_restart_workload_tracking_unavailable", Process: process, NativePid: 99, NativeCreated: 100,
            Dispatched: true, LaunchKind: "gui", EnvironmentPolicy: "ordinary-app-allowlist-v1", WorkloadState: "unknown");
        string change = data.TryGetProperty("change", out var altered) ? altered.GetString()! : "none";
        bool tracked = change == "tracked";
        string rootState = change == "running_root" ? "running" : change == "unknown_root" ? "unknown" : "root_exited";
        if (change == "same_work") current = current with { WorkId = old.WorkId };
        if (change == "missing_binding") File.Move(BindingPath(old.RequestId), BindingPath(old.RequestId) + ".unavailable");
        if (change is "different_execution" or "same_work_binding")
        {
            var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(File.ReadAllBytes(BindingPath(old.RequestId)))!;
            if (change == "different_execution") fields["ExecutionKey"] = JsonSerializer.SerializeToElement(new string('e', 64));
            else fields["WorkId"] = JsonSerializer.SerializeToElement(query.WorkId);
            File.WriteAllBytes(BindingPath(old.RequestId), JsonSerializer.SerializeToUtf8Bytes(fields));
        }
        var preserved = Directory.GetFiles(Root).ToDictionary(path => path, File.ReadAllBytes);
        var reviewObject = execution.IndependentRootExitReview(policy, own, target, current, [blocker], _ => rootState,
            _ => tracked, out var reference);
        var review = reviewObject is null ? (JsonElement?)null : JsonSerializer.SerializeToElement(reviewObject);
        if (reference is null)
        {
            var nativeReport = typeof(AdminProgramLaunch).GetMethod("Report", BindingFlags.Static | BindingFlags.NonPublic)!
                .Invoke(null, [query, null, "rejected", "program_launch_target_pending", "unknown", null, false, null, null, reviewObject]);
            return new { eligible = false, allowed = false, review, reference, nativeReport,
                originalPreserved = preserved.All(item => File.ReadAllBytes(item.Key).SequenceEqual(item.Value)),
                actualProgramExecuted = false, productionWorkAuthorityCreated = false };
        }
        var spec = query.Execution! with { NewRun = new(reference,
            "Current user requested a new run; helper restart lost anonymous job tracking, the recorded root is gone, and the old tree/business result remains unknown.") };
        if (change == "forged_reference") spec = spec with { NewRun = spec.NewRun! with { ExitReference = new string('f', 64) } };
        var next = query with { RequestId = "new-root-request", Execution = spec, ProgramRef = SemanticExecution.Reference(image, spec) };
        string? rejection = null;
        using (var requested = new SemanticExecution(next, spec.ExecutableSha256, () => { }, image))
        {
            SemanticExecution.Validate(next);
            try { requested.RequireFreshExecution(policy, own, target, current, reference); }
            catch (Boundary error) { rejection = error.Code; }
        }
        return new { eligible = true, allowed = rejection is null, rejection, review, reference,
            actualProgramExecuted = false, productionWorkAuthorityCreated = false,
            rootProcessExited = review!.Value.GetProperty("RootProcessExited").GetBoolean(),
            previousTreeExited = review.Value.GetProperty("PreviousTreeExited").GetBoolean(),
            proofKind = review.Value.GetProperty("ProofKind").GetString() };
    }
    internal static int Main(string[] args)
    {
        try
        {
            Root = Path.GetFullPath(args[0]);
            if (args.Length == 4 && args[1] == "--cmd-runtime-fixed") return CmdRuntime(args[2], args[3]);
            using var input = JsonDocument.Parse(Console.In.ReadToEnd());
            var data = input.RootElement;
            var spec = data.GetProperty("spec").Deserialize<SemanticExecutionSpec>()!;
            string image = data.GetProperty("image").GetString()!;
            var query = new ProgramLaunchQuery("program_launch", "launch", "fixture-task", "fixture-connection",
                SemanticExecution.Reference(image, spec), "fixture-request", image, Thread: new("codex", "fixture-session"),
                WorkId: new string('a', 32), Execution: spec);
            SemanticExecution.Validate(query);
            using var execution = new SemanticExecution(query, spec.ExecutableSha256, () => { }, image);
            if (data.TryGetProperty("mode",out var independentMode) && independentMode.GetString()=="independent_run") {
                Console.WriteLine(JsonSerializer.Serialize(IndependentRun(data,query,execution,image))); return 0;
            }
            if (data.TryGetProperty("mode",out var rootMode) && rootMode.GetString()=="root_exit_tracking_lost") {
                Console.WriteLine(JsonSerializer.Serialize(RootExitTrackingLostRun(data,query,execution,image))); return 0;
            }
            var entry = typeof(SemanticExecution).GetField("entry", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(execution)!;
            if (data.TryGetProperty("mode", out var requested) && requested.GetString() == "binding")
            {
                string kind = data.TryGetProperty("kind", out var suppliedKind) ? suppliedKind.GetString()! : "native_image";
                var storedEntry = JsonSerializer.SerializeToNode(entry)!;
                storedEntry["Kind"] = kind;
                if (data.TryGetProperty("large", out var large) && large.GetBoolean())
                    storedEntry["AdditionalFiles"] = new System.Text.Json.Nodes.JsonArray(Enumerable.Range(0, 31)
                        .Select(i => System.Text.Json.Nodes.JsonValue.Create("C:\\" + new string('\u732b', 990) + i)).ToArray());
                string target = AdminProgramLaunch.Target(image);
                string binding = JsonSerializer.Serialize(new { Schema = 1, query.TaskId, query.RequestId, query.ProgramRef,
                    Target = target, query.WorkId, GrantRevision = 1, Entry = storedEntry, ExecutionKey = new string('b', 64),
                    Audit = new AuditStamp("fixture", 1, new string('c', 64)) });
                File.WriteAllText(BindingPath(query.RequestId), binding);
                string workload = data.GetProperty("workload").GetString()!;
                var record = new AdminLaunchEntry(query.TaskId, query.RequestId, query.ProgramRef, target, "fixture", 1,
                    "handoff_unknown", Process: new(99, 100, image, 12288, "fixture", 1), Dispatched: true, ExitCode: 0,
                    WorkloadState: workload);
                Console.WriteLine(JsonSerializer.Serialize(new { state = "supported", allowed = SemanticExecution.CanContinueAfterExit(null!, null!, record), binding_bytes = System.Text.Encoding.UTF8.GetByteCount(binding) }));
                return 0;
            }
            bool retainFailureKeptPins = false;
            if (data.TryGetProperty("mode", out requested) && requested.GetString() == "retention")
            {
                try { execution.RetainUntilWorkloadExit("missing-fixture-workload"); throw new Exception("fixture_missing_retention_failure"); }
                catch (Boundary error) when (error.Code == "program_launch_payload_lifetime_unconfirmed") { }
                try
                {
                    using var changed = new FileStream(spec.Payloads[0].Path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                }
                catch (IOException) { retainFailureKeptPins = true; }
                finally { Call(execution, "Close"); }
            }
            Console.WriteLine(JsonSerializer.Serialize(new { state = "supported", entry, execution.Arguments, query.ProgramRef,
                key = Call(execution, "ExecutionKey", image), retainFailureKeptPins }));
            return 0;
        }
        catch (Boundary error) { Console.WriteLine(JsonSerializer.Serialize(new { state = "rejected", reason = error.Code })); return 0; }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
