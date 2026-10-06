using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal record LayoutWorkerRequest(Peer Parent, Prepare Prepare, string LedgerIdentity, int DeadlineMs);
internal record LayoutWorkerReady(string Phase, Peer Worker, string AssemblyDigest, Bound Target,
    InputBinding Binding, string LedgerIdentity, string ConnectionId, long DesktopRevision);
internal record LayoutWorkerDone(string Phase, Peer Worker, string LedgerIdentity, InputBinding Binding,
    WindowLayoutResult Result, string State, string? Reason, int? Winerror);

internal static class LayoutWorker
{
    internal static LayoutWorkerDone DecodeDone(JsonDocument document, LayoutPlan plan)
    {
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(
            ["Phase", "Worker", "LedgerIdentity", "Binding", "Result", "State", "Reason", "Winerror"])
            || !root.TryGetProperty("Result", out var result) || result.ValueKind != JsonValueKind.Object
            || !result.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(
                ["Binding", "Command", "RequestedRect", "ObservedRect", "DispatchAttempted", "CallReturned", "ApiSucceeded", "Dispatched", "RequestedReached"]))
            throw new Boundary("layout_worker_result_rejected");
        var done = Protocol.Decode<LayoutWorkerDone>(document);
        WindowLayout.ValidateResult(plan, done.Result);
        return done;
    }
    internal static int Run()
    {
        var clock = Stopwatch.StartNew();
        using var input = Console.OpenStandardInput(); using var output = Console.OpenStandardOutput();
        using var document = Protocol.Read(input, 3000, limit: 98304);
        if (document is null) throw new Boundary("layout_worker_disconnected");
        var request = Protocol.Decode<LayoutWorkerRequest>(document);
        var own = Native.Process(Environment.ProcessId);
        var parent = Native.Process(Native.ParentPid(Environment.ProcessId));
        if (request.Parent != parent.Identity || parent.Identity.User != own.Identity.User
            || parent.Identity.Session != own.Identity.Session || parent.Identity.Integrity != own.Identity.Integrity
            || !parent.Image.Equals(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"), StringComparison.OrdinalIgnoreCase)
            || parent.Identity.ImageDigest != own.Identity.ImageDigest || request.DeadlineMs is < 1 or > 5000
            || !Regex.IsMatch(request.LedgerIdentity, "^[a-f0-9]{64}$") || request.Prepare.Operation.Kind != "window_layout")
            throw new Boundary("layout_worker_parent_rejected");
        Protocol.Validate(request.Prepare, own.Identity.Integrity == 8192);
        var plan = WindowLayout.Parse(request.Prepare.Operation.Plan!.Value, request.Prepare.Target.Bounds);
        var receipt = new Receipt { RequestBinding = plan.Binding, LayoutResult = WindowLayout.NewResult(plan) };
        try
        {
            var bound = Native.CheckTarget(request.Prepare.Target, false);
            void Check(bool geometry)
            {
                Native.VerifyPeer(request.Parent);
                if (clock.ElapsedMilliseconds >= request.DeadlineMs) throw new Boundary("deadline_expired");
                Native.Desktop();
                if (Native.CheckTarget(request.Prepare.Target, false) != bound) throw new Boundary("target_identity_changed");
                if (geometry) Native.CheckGeometry(request.Prepare.Target, true);
                WindowLayout.CheckDesktop(plan); WindowLayout.CheckNormal(plan, bound);
            }
            Check(true);
            Protocol.Write(output, new LayoutWorkerReady("ready", own.Identity, Program.AssemblyDigest, bound,
                plan.Binding, request.LedgerIdentity, request.Prepare.ConnectionId, request.Prepare.DesktopRevision));
            using var go = Protocol.Read(input, Math.Max(1, request.DeadlineMs - (int)clock.ElapsedMilliseconds), limit: 98304);
            if (go is null || !Protocol.Phase(go, "go")) throw new Boundary("layout_worker_go_rejected");
            WindowLayout.Perform(plan, receipt, () => Check(true), () => Check(false), () => WindowLayout.Call(plan, bound), () => Native.Bounds(bound.Hwnd));
        }
        catch (Exception error)
        {
            receipt.State = receipt.LayoutResult!.DispatchAttempted ? "interrupted" : "rejected";
            receipt.Reason = Program.Code(error); receipt.Winerror ??= error is Boundary boundary ? boundary.NativeCode : null;
        }
        Protocol.Write(output, new LayoutWorkerDone("done", own.Identity, request.LedgerIdentity, plan.Binding,
            receipt.LayoutResult!, receipt.State, receipt.Reason, receipt.Winerror));
        return 0;
    }

    internal static void Execute(Prepare prepare, Bound bound, Func<bool> stopped, Stopwatch clock, InputLedger ledger, Receipt result)
    {
        var plan = WindowLayout.Parse(prepare.Operation.Plan!.Value, prepare.Target.Bounds);
        bool childGo = false;
        void Check()
        {
            if (!childGo)
            {
                Executor.Check(prepare, bound, stopped, clock, false, true, ledger);
                Native.CheckGeometry(prepare.Target, true); WindowLayout.CheckDesktop(plan); WindowLayout.CheckNormal(plan, bound);
            }
            else
            {
                if (stopped()) throw new Boundary("input_stopped");
                if (clock.ElapsedMilliseconds >= prepare.DeadlineMs) throw new Boundary("deadline_expired");
                Native.Desktop(); // Target/geometry are checked by the actual child around its synchronous call.
            }
        }
        Check();
        var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"))
        { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("--layout-worker");
        var system = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(system) || !Path.IsPathFullyQualified(system)) throw new Boundary("windows_system_root_missing");
        info.Environment.Clear(); info.Environment["SystemRoot"] = system; info.Environment["WINDIR"] = system;
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        foreach (var name in new[] { "TEMP", "TMP" })
        { var path = Environment.GetEnvironmentVariable(name); if (path is not null && Path.IsPathFullyQualified(path)) info.Environment[name] = path; }
        using var child = new OwnedChild(info, exitSink: value => result.SemanticExecutorExited = value);
        var peer = Native.Process(child.Process.Id).Identity; var own = Native.Process(Environment.ProcessId).Identity;
        if (peer.User != own.User || peer.Session != own.Session || peer.Integrity != own.Integrity || peer.ImageDigest != own.ImageDigest)
            throw new Boundary("layout_worker_identity_rejected");
        result.SemanticExecutor = peer; result.SemanticExecutorExited = false;
        _ = Task.Run(async () => { var bytes = new byte[1024]; while (await child.Process.StandardError.BaseStream.ReadAsync(bytes) > 0) { } });
        Protocol.Write(child.Process.StandardInput.BaseStream, new LayoutWorkerRequest(own, prepare, result.LedgerIdentity!,
            Math.Max(1, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds)));
        while (true)
        {
            Check();
            using var stop = new CancellationTokenSource();
            var read = Task.Run(() => Protocol.Read(child.Process.StandardOutput.BaseStream,
                Math.Max(1, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds), stop.Token, 98304));
            try
            {
                while (!read.IsCompleted) { Thread.Sleep(20); if (!read.IsCompleted) Check(); }
                using var message = read.GetAwaiter().GetResult();
                if (message is null) throw new Boundary("layout_worker_disconnected");
                if (message.RootElement.TryGetProperty("Phase", out var phase) && phase.GetString() == "ready")
                {
                    var ready = Protocol.Decode<LayoutWorkerReady>(message);
                    if (childGo || ready.Worker != peer || ready.AssemblyDigest != Program.AssemblyDigest || ready.Target != bound
                        || ready.Binding != plan.Binding || ready.LedgerIdentity != result.LedgerIdentity
                        || ready.ConnectionId != prepare.ConnectionId || ready.DesktopRevision != prepare.DesktopRevision)
                        throw new Boundary("layout_worker_ready_rejected");
                    Check(); Native.VerifyPeer(peer);
                    childGo = true;
                    result.BusinessAttempted = true; result.RequiresNewObservation = true; result.State = "interrupted";
                    result.LayoutResult!.DispatchAttempted = true; result.LayoutResult.CallReturned = null;
                    result.LayoutResult.ApiSucceeded = null; result.LayoutResult.Dispatched = null; result.LayoutResult.RequestedReached = null;
                    result.SemanticBusinessDispatched = null;
                    Protocol.Write(child.Process.StandardInput.BaseStream, new { Phase = "go" });
                    continue;
                }
                var done = DecodeDone(message, plan);
                if (done.Phase != "done" || done.Worker != peer || done.LedgerIdentity != result.LedgerIdentity
                    || done.Binding != plan.Binding || done.Result.Binding != plan.Binding || done.Result.Command != plan.Command
                    || !done.Result.RequestedRect.SequenceEqual(plan.RequestedRect)
                    || !childGo && done.Result.DispatchAttempted || done.State is not ("rejected" or "interrupted" or "dispatched_unverified"))
                    throw new Boundary("layout_worker_result_rejected");
                result.LayoutResult = done.Result;
                result.BusinessAttempted = done.Result.DispatchAttempted;
                result.SemanticBusinessDispatched = done.Result.Dispatched;
                result.RequiresNewObservation |= done.Result.DispatchAttempted;
                result.State = done.State; result.Reason = done.Reason; result.Winerror = done.Winerror;
                child.Process.StandardInput.Close();
                while (!child.Process.WaitForExit(20)) Check();
                return;
            }
            finally { stop.Cancel(); try { read.Wait(500); } catch (AggregateException) { } }
        }
    }
}
