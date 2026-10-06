using System.Diagnostics;
using System.Text.Json;

namespace Flower.HighHelper;

internal record AppPlan(string Command, JsonElement Arguments, InputBinding Binding);
internal static class AppExecutor
{
    private static readonly string[] Commands = ["observe", "read_text", "invoke", "set_value", "set_toggle",
        "select_item", "expand_collapse", "scroll", "realize_item", "close_window", "focus", "guarded_input"];
    // Synthetic diagnostics are identified by the private CLR type, never a worker-supplied JSON marker.
    internal static void AttachFailure(Receipt result, string command, AppCheckpointFrame? checkpoint, string code)
    {
        if (result.AppResult is not null || checkpoint is null) return;
        bool mutating = command is not ("observe" or "read_text");
        result.AppResult = new AppCheckpointFailure(
            mutating && result.SemanticBusinessDispatched is not false ? "outcome_uncertain" : "not_verified",
            mutating ? result.SemanticBusinessDispatched : false, checkpoint.Stage, checkpoint.ElapsedMs, code, null);
    }
    internal static void ReconcileFailure(Receipt result)
    {
        // Call once after Request's catch and cleanup have determined the final receipt reason.
        if (result.AppResult is AppCheckpointFailure diagnostic)
            result.AppResult = diagnostic with { reason = result.Reason ?? "app_high_result_missing" };
    }

    internal static AppPlan Parse(JsonElement value, Target target)
    {
        try
        {
            Fields(value, ["schema_version", "command", "arguments", "binding"]);
            if (value.GetProperty("schema_version").GetInt32() != 1) throw new Boundary("app_request_rejected");
            var command = value.GetProperty("command").GetString()!;
            if (!Commands.Contains(command)) throw new Boundary("app_request_rejected");
            var arguments = value.GetProperty("arguments");
            var keys = command == "observe" ? new List<string> { "target", "limits", "privacy", "privacy_scope" }
                : command == "close_window" ? new List<string> { "target" }
                : new List<string> { "target", "reference", "observation", "privacy", "privacy_scope" };
            if (command == "set_value") keys.Add("value");
            if (command == "guarded_input") keys.Add("text");
            if (command == "guarded_input" && arguments.TryGetProperty("replace", out var replace))
            {
                if (replace.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Boundary("app_request_rejected");
                keys.Add("replace");
            }
            if (command is "set_toggle" or "expand_collapse") keys.Add("desired");
            if (command == "select_item" && arguments.TryGetProperty("desired", out _)) keys.Add("desired");
            if (command == "observe" && arguments.TryGetProperty("tree", out _)) keys.Add("tree");
            if (command == "scroll") { keys.Add("direction"); keys.Add("amount"); }
            if (command == "realize_item") keys.Add("item_name");
            if (command == "read_text") keys.Add("text");
            if (command != "close_window" && arguments.TryGetProperty("local", out _)) keys.Add("local");
            Fields(arguments, keys.ToArray());
            if (command == "guarded_input")
                _ = ComputerPlans.TextBatches(arguments.GetProperty("text").GetString()!, splitTabs: true);
            var destination = arguments.GetProperty("target");
            Fields(destination, ["pid", "hwnd", "process_start_filetime", "root_runtime_id"]);
            if (destination.GetProperty("pid").GetInt32() != target.Pid
                || destination.GetProperty("hwnd").GetInt64() != target.Hwnd
                || destination.GetProperty("process_start_filetime").GetInt64() != target.Created)
                throw new Boundary("app_target_binding_mismatch");
            var binding = value.GetProperty("binding");
            Fields(binding, ["task_id", "action_id", "observation_id", "generation", "sequence_step"]);
            string Text(string name, int max)
            {
                var text = binding.GetProperty(name).GetString()!;
                if (string.IsNullOrEmpty(text) || text.Length > max || text.Any(char.IsControl)) throw new Boundary("app_binding_rejected");
                return text;
            }
            var sequence = binding.GetProperty("sequence_step");
            int? step = sequence.ValueKind == JsonValueKind.Null ? null : sequence.GetInt32();
            if (step is < 0 or > 2) throw new Boundary("app_binding_rejected");
            bool noObservation = binding.GetProperty("observation_id").ValueKind == JsonValueKind.Null;
            if (noObservation != (binding.GetProperty("generation").ValueKind == JsonValueKind.Null)
                || noObservation && (command is not ("observe" or "close_window") || step is not null))
                throw new Boundary("app_binding_rejected");
            if (value.GetRawText().Length > 98304) throw new Boundary("app_request_rejected");
            return new(command, arguments.Clone(), new(Text("task_id", 128), Text("action_id", 512),
                noObservation ? null : Text("observation_id", 256), noObservation ? null : Text("generation", 4096), step));
        }
        catch (Boundary) { throw; }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException)
        { throw new Boundary("app_request_rejected"); }
    }
    private static void Fields(JsonElement value, string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(fields)
            || value.EnumerateObject().Count() != fields.Length) throw new Boundary("app_request_rejected");
    }
    internal static void Execute(BrokerPolicy policy, Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, Receipt result,
        SharedWriteGate? writeGate = null, InputLedger? inputLedger = null)
    {
        var plan = Parse(prepare.Operation.Plan!.Value, prepare.Target);
        long stopEpoch = writeGate?.Snapshot().Epoch ?? 0;
        var guardedBatches = plan.Command == "guarded_input"
            ? ComputerPlans.TextBatches(plan.Arguments.GetProperty("text").GetString()!, splitTabs: true) : null;
        if (guardedBatches is not null && plan.Arguments.TryGetProperty("replace", out var replace) && replace.GetBoolean())
        {
            var ctrl = Executor.KeyPair(0x11, false); var keyA = Executor.KeyPair(0x41, false);
            guardedBatches = [new(0, [new(0, [ctrl[0], keyA[0], keyA[1], ctrl[1]], [])]), ..guardedBatches];
            if (guardedBatches.Length > 131) throw new Boundary("input_plan_rejected");
        }
        int guardedSent = 0;
        if (guardedBatches is not null && (!prepare.Operation.Activate || inputLedger is null))
            throw new Boundary("guarded_input_requires_foreground_ledger");
        bool childGo = false;
        using var foregroundEvents = prepare.Operation.Activate
            ? new ForegroundEvents(bound, () => Volatile.Read(ref childGo)) : null;
        void Check()
        {
            foregroundEvents?.Check();
            Executor.Check(prepare, bound, stopped, clock, false, false);
            if (prepare.Operation.Activate && !Native.ForegroundOrOwnedPopup(bound, childGo))
                throw new Boundary("foreground_changed");
        }
        Check();
        var dispatchAt = clock.Elapsed.TotalMilliseconds;
        if (plan.Command == "close_window")
        {
            result.SemanticExecutor = Native.Process(Environment.ProcessId).Identity;
            Check();
            writeGate?.Admit(stopEpoch);
            result.SemanticBusinessDispatched = null;
            if (!Native.PostMessageW(new IntPtr(bound.Hwnd), 0x0010, IntPtr.Zero, IntPtr.Zero))
            { result.SemanticBusinessDispatched = false; throw new Boundary("close_dispatch_failed", System.Runtime.InteropServices.Marshal.GetLastWin32Error()); }
            result.SemanticBusinessDispatched = true;
            result.AppResult = new { state = "not_verified", dispatched = true, verification = "business_postcondition_required" };
            result.State = "dispatched_unverified";
            result.TimingsMs["dispatch"] = clock.Elapsed.TotalMilliseconds - dispatchAt;
            return;
        }
        if (!policy.AppWorkerHashes.ContainsKey("Flower.AppWorker.exe") || policy.AppWorkerHashes.Count is < 4 or > 128)
            throw new Boundary("app_worker_not_installed");
        var root = Path.Combine(policy.Directory, "app");
        foreach (var (file, hash) in policy.AppWorkerHashes)
        {
            if (Path.GetFileName(file) != file || !System.Text.RegularExpressions.Regex.IsMatch(hash, "^[a-f0-9]{64}$"))
                throw new Boundary("app_worker_policy_rejected");
            var path = Path.Combine(root, file);
            BrokerPolicy.RejectLinks(path);
            if (Native.Digest(path) != hash) throw new Boundary("app_worker_changed");
        }
        Check();
        var info = new ProcessStartInfo(Path.Combine(root, "Flower.AppWorker.exe"))
        { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root,
            // AppWorker reads strict UTF-8; a console-less broker otherwise uses
            // the Windows ANSI code page and corrupts unescaped Unicode JSON.
            StandardInputEncoding = new System.Text.UTF8Encoding(false, true),
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        var system = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(system) || !Path.IsPathFullyQualified(system)) throw new Boundary("windows_system_root_missing");
        info.Environment.Clear();
        info.Environment["SystemRoot"] = system; info.Environment["WINDIR"] = system;
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        foreach (var name in new[] { "TEMP", "TMP" })
        { var path = Environment.GetEnvironmentVariable(name); if (path is not null && Path.IsPathFullyQualified(path)) info.Environment[name] = path; }
        using var child = new OwnedChild(info, exitSink: value => result.SemanticExecutorExited = value);
        var peer = Native.Process(child.Process.Id).Identity;
        var own = Native.Process(Environment.ProcessId).Identity;
        if (peer.User != own.User || peer.Session != own.Session || peer.Integrity != own.Integrity
            || peer.ImageDigest != policy.AppWorkerHashes["Flower.AppWorker.exe"])
            throw new Boundary("app_worker_identity_rejected");
        result.SemanticExecutor = peer;
        result.SemanticExecutorExited = false;
        // Keep only validated, fixed checkpoint fields while always draining stderr.
        var checkpoints = new AppCheckpointReader();
        var diagnostics = child.Process.StandardError.BaseStream;
        _ = Task.Run(() => checkpoints.Drain(diagnostics));
        try
        {
            child.Process.StandardInput.WriteLine(JsonSerializer.Serialize(new { command = plan.Command, arguments = plan.Arguments },
                new JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
            child.Process.StandardInput.Flush();
            while (true)
            {
                Check();
                // The retained owned process handle and private stdout remain the
                // source even when a fast worker has already exited with a result.
                using var stop = new CancellationTokenSource();
                var read = Task.Run(() => Protocol.Read(child.Process.StandardOutput.BaseStream,
                    Math.Max(1, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds), stop.Token, 98304));
                try
                {
                    while (!read.IsCompleted) { Thread.Sleep(20); Check(); }
                    using var reply = read.GetAwaiter().GetResult();
                    if (reply is null) throw new Boundary("app_worker_disconnected");
                    if (reply.RootElement.TryGetProperty("phase", out var guardedPhase)
                        && guardedPhase.GetString() is "guarded_focus_ready" or "guarded_focus_checked")
                    {
                        if (guardedBatches is null || !childGo || inputLedger is null)
                            throw new Boundary("app_worker_result_rejected");
                        Check(); Native.VerifyPeer(peer);
                        if (guardedPhase.GetString() == "guarded_focus_checked")
                        {
                            if (reply.RootElement.EnumerateObject().Count() != 2
                                || reply.RootElement.GetProperty("focused").ValueKind != JsonValueKind.True
                                || guardedSent >= guardedBatches.Length) throw new Boundary("app_focus_guard_rejected");
                            var input = new ComputerPlan(plan.Binding, "text", null, [guardedBatches[guardedSent]]);
                            ComputerPlans.Execute(input, prepare, bound, stopped, clock, inputLedger, result);
                            ++guardedSent;
                            result.InputResult!.CompletedPlans = guardedSent;
                            result.InputResult.CompletedSegments = guardedSent;
                            result.InputResult.BusinessComplete = guardedSent == guardedBatches.Length;
                        }
                        else if (reply.RootElement.EnumerateObject().Count() != 1 || guardedSent != 0)
                            throw new Boundary("app_worker_result_rejected");
                        child.Process.StandardInput.WriteLine(guardedSent == guardedBatches.Length ? "finish_input" : "check_input");
                        child.Process.StandardInput.Flush();
                        continue;
                    }
                    if (reply.RootElement.TryGetProperty("phase", out var phase) && phase.GetString() == "ready")
                    {
                        if (childGo || reply.RootElement.EnumerateObject().Count() != 1) throw new Boundary("app_worker_duplicate_go");
                        Check();
                        Native.VerifyPeer(peer);
                        if (plan.Command is not ("observe" or "read_text")) writeGate?.Admit(stopEpoch);
                        Volatile.Write(ref childGo, true);
                        if (plan.Command is not ("observe" or "read_text")) result.SemanticBusinessDispatched = null;
                        child.Process.StandardInput.WriteLine("go");
                        child.Process.StandardInput.Flush();
                        continue;
                    }
                    if (!reply.RootElement.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String)
                        throw new Boundary("app_worker_result_rejected");
                    if (reply.RootElement.TryGetProperty("dispatched", out var dispatched)
                        && dispatched.ValueKind is JsonValueKind.True or JsonValueKind.False)
                        result.SemanticBusinessDispatched = dispatched.GetBoolean() || guardedSent > 0;
                    result.AppResult = reply.RootElement.Clone();
                    result.State = result.SemanticBusinessDispatched == false && state.GetString() == "rejected" ? "rejected" : "dispatched_unverified";
                    result.Reason = reply.RootElement.TryGetProperty("reason", out var reason) && reason.ValueKind == JsonValueKind.String ? reason.GetString() : null;
                    child.Process.StandardInput.Close();
                    while (!child.Process.WaitForExit(20)) Check();
                    foregroundEvents?.Check();
                    result.TimingsMs["dispatch"] = clock.Elapsed.TotalMilliseconds - dispatchAt;
                    return;
                }
                finally
                {
                    stop.Cancel();
                    try { read.Wait(500); } catch (AggregateException) { }
                }
            }
        }
        catch (Exception error)
        {
            AttachFailure(result, plan.Command, checkpoints.Last, Program.Code(error));
            throw;
        }
    }
}


internal sealed record AppCheckpointFrame(string Stage, int ElapsedMs);
internal sealed record AppCheckpointFailure(string state, bool? dispatched, string stage,
    int checkpoint_elapsed_ms, string checkpoint_failure_code, string? reason);

// A private stderr line is capped before decoding. Unrecognized bytes never leave this reader.
internal sealed class AppCheckpointReader
{
    private const int MaxLineBytes = 256, MaxLines = 128;
    private static readonly string[] Stages = ["request_validated", "uia_initialize_enter", "uia_initialize_exit",
        "root_bind_enter", "root_bind_exit", "exact_lookup_enter", "exact_lookup_exit", "pattern_enter",
        "pattern_exit", "ready", "business_enter", "dispose_enter", "disposed"];
    private readonly byte[] line = new byte[MaxLineBytes];
    private int length, lines;
    private bool oversized;
    private AppCheckpointFrame? last;
    internal AppCheckpointFrame? Last => Volatile.Read(ref last);
    internal async Task Drain(Stream stream)
    {
        var bytes = new byte[1024];
        try
        {
            int count;
            while ((count = await stream.ReadAsync(bytes)) > 0) Feed(bytes.AsSpan(0, count));
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
        finally { Array.Clear(line); length = 0; }
    }
    internal void Feed(ReadOnlySpan<byte> bytes)
    {
        if (lines >= MaxLines) return; // Drain continues even after the parsing budget is exhausted.
        foreach (byte value in bytes)
        {
            if (value == (byte)'\n')
            {
                ++lines;
                if (!oversized && length > 0) ParseLine();
                Array.Clear(line); length = 0; oversized = false;
                if (lines >= MaxLines) return;
            }
            else if (!oversized)
            {
                if (length == MaxLineBytes) { Array.Clear(line); length = 0; oversized = true; }
                else line[length++] = value;
            }
        }
    }
    private void ParseLine()
    {
        try
        {
            using var document = JsonDocument.Parse(line.AsMemory(0, length));
            var value = document.RootElement;
            if (value.ValueKind != JsonValueKind.Object) return;
            int fields = 0, seen = 0, elapsed = -1;
            string? stage = null;
            foreach (var property in value.EnumerateObject())
            {
                ++fields;
                int bit = property.Name switch { "flower_app_checkpoint" => 1, "stage" => 2, "elapsed_ms" => 4, _ => 0 };
                if (bit == 0 || (seen & bit) != 0) return;
                seen |= bit;
                if (bit == 1)
                {
                    if (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt32(out int schema) || schema != 1) return;
                }
                else if (bit == 2)
                {
                    if (property.Value.ValueKind != JsonValueKind.String) return;
                    string? candidate = property.Value.GetString();
                    stage = Stages.FirstOrDefault(allowed => allowed == candidate);
                    if (stage is null) return;
                }
                else
                {
                    if (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetInt32(out elapsed)
                        || elapsed is < 0 or > 600_000) return;
                }
            }
            if (fields == 3 && seen == 7 && stage is not null)
                Volatile.Write(ref last, new AppCheckpointFrame(stage, elapsed));
        }
        catch (JsonException) { }
        catch (InvalidOperationException) { }
        catch (FormatException) { }
    }
}
