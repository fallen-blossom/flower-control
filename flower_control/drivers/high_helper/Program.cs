using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class Program
{
    internal static string AssemblyDigest { get; } = Native.Digest(Assembly.GetExecutingAssembly().Location);
    internal static bool AcceptPreGoStop(JsonDocument signal, string ledger, Prepare prepare, BrokerRequest request)
    {
        if (!Protocol.Signal(signal, "stop", ledger, prepare)) return false;
        request.ActionId = signal.RootElement.GetProperty("ActionId").GetString()!;
        request.Cancel("input_stopped");
        return true;
    }
    internal static void WatchPostGo(Stream pipe, Prepare prepare, string ledger, BrokerRequest request,
        Stopwatch clock, CancellationToken watchStop)
    {
        try
        {
            using var next = Protocol.Read(pipe, Math.Max(1, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds), watchStop);
            if (watchStop.IsCancellationRequested) return;
            if (next is null) request.Cancel("client_disconnected");
            else request.Cancel(Protocol.Signal(next, "stop", ledger, prepare, request.ActionId) ? "input_stopped" : "duplicate_go_rejected");
        }
        catch (OperationCanceledException) when (watchStop.IsCancellationRequested) { }
        // Protocol.Read owns a separate timeout token. Its cancellation means the
        // request deadline elapsed, even though the client pipe is still open.
        catch (OperationCanceledException) { request.Cancel("deadline_expired"); }
        catch (IOException) { request.Cancel("client_disconnected"); }
        catch (Exception error) { request.Cancel(Code(error)); }
    }
    internal static Receipt Request(Stream pipe, Prepare prepare, Peer own, bool medium, BrokerState core, BrokerRequest request, BrokerPolicy? policy = null)
    {
        var receipt = new Receipt { HighVerified = !medium, TaskId = prepare.TaskId,
            ConnectionId = prepare.ConnectionId, DesktopRevision = prepare.DesktopRevision };
        var clock = Stopwatch.StartNew();
        request.ReadOnly = Protocol.ReadOnly(prepare.Operation);
        var ledger = new InputLedger(writeGate: core.WriteGate);
        receipt.LedgerIdentity = ledger.Identity;
        request.LedgerIdentity = ledger.Identity;
        if (prepare.Operation.Kind == "computer_input_plan")
        {
            receipt.RequestBinding = ComputerPlans.Parse(prepare.Operation.Plan!.Value).Binding;
            receipt.InputResult = new InputProgress { Binding = receipt.RequestBinding };
        }
        else if (prepare.Operation.Kind == "app_request") receipt.RequestBinding = AppExecutor.Parse(prepare.Operation.Plan!.Value, prepare.Target).Binding;
        else if (prepare.Operation.Kind == "window_layout")
        {
            var plan = WindowLayout.Parse(prepare.Operation.Plan!.Value, prepare.Target.Bounds);
            receipt.RequestBinding = plan.Binding; receipt.LayoutResult = WindowLayout.NewResult(plan);
        }
        request.ActionId = receipt.RequestBinding?.ActionId ?? "";
        ResourceLocks? locks = null;
        Task? watcher = null;
        using var watchStop = new CancellationTokenSource();
        using var linkedStop = CancellationTokenSource.CreateLinkedTokenSource(core.Shutdown.Token, request.Stop.Token);
        try
        {
            core.Check(prepare.DesktopRevision, write: !request.ReadOnly);
            var lockAt = clock.Elapsed.TotalMilliseconds;
            locks = new ResourceLocks(prepare.Resources);
            receipt.TimingsMs["queue_wait"] = clock.Elapsed.TotalMilliseconds - lockAt;
            var bound = Native.CheckTarget(prepare.Target, prepare.Operation.Kind == "bind");
            if (Executor.InitialGeometryRequired(prepare.Operation, Native.IsIconic(new IntPtr(bound.Hwnd))))
                Native.CheckGeometry(prepare.Target, true);
            receipt.Target = bound;
            if (prepare.Operation.Kind == "window_layout")
            {
                var plan = WindowLayout.Parse(prepare.Operation.Plan!.Value, prepare.Target.Bounds);
                WindowLayout.CheckNormal(plan, bound); WindowLayout.CheckDesktop(plan);
            }
            Protocol.Write(pipe, new Ready("ready", own, AssemblyDigest, bound, prepare.Resources, true, ledger.Identity,
                prepare.TaskId, prepare.ConnectionId, prepare.DesktopRevision));
            receipt.TimingsMs["prepare_ready"] = clock.Elapsed.TotalMilliseconds;
            using var go = Protocol.Read(pipe, Math.Max(1, Math.Min(2000, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds)), linkedStop.Token);
            if (go is null) { request.Cancel("client_disconnected"); throw new Boundary("input_stopped"); }
            if (AcceptPreGoStop(go, ledger.Identity, prepare, request)) throw new Boundary("input_stopped");
            if (!Protocol.Signal(go, "go", ledger.Identity, prepare)) throw new Boundary("go_rejected");
            request.ActionId = go.RootElement.GetProperty("ActionId").GetString()!;
            core.Check(prepare.DesktopRevision, write: !request.ReadOnly);
            receipt.TimingsMs["wait_go"] = clock.Elapsed.TotalMilliseconds - receipt.TimingsMs["prepare_ready"];
            watcher = Task.Run(() => WatchPostGo(pipe, prepare, ledger.Identity, request, clock, watchStop.Token));
            bool Stopped() { core.Check(prepare.DesktopRevision, write: !request.ReadOnly); return request.Stop.IsCancellationRequested; }
            if (prepare.Operation.Kind == "window_layout")
                LayoutWorker.Execute(prepare, bound, Stopped, clock, ledger, receipt);
            else if (prepare.Operation.Kind == "app_request")
            {
                if (prepare.Operation.Activate)
                    Executor.Execute(prepare with { Operation = new Operation("activate", RestoreMinimized: prepare.Operation.RestoreMinimized) }, bound, Stopped, clock, ledger, receipt);
                AppExecutor.Execute(policy ?? throw new Boundary("app_worker_not_installed"), prepare, bound, Stopped, clock, receipt, core.WriteGate, ledger);
            }
            else Executor.Execute(prepare, bound, Stopped, clock, ledger, receipt);
            receipt.TimingsMs["execute"] = clock.Elapsed.TotalMilliseconds - receipt.TimingsMs["prepare_ready"] - receipt.TimingsMs["wait_go"];
            if (request.Reason == "duplicate_go_rejected") throw new Boundary("duplicate_go_rejected");
        }
        catch (Exception error)
        {
            receipt.State = receipt.ActivationRequested || receipt.RequestedEvents != 0 || receipt.SemanticBusinessDispatched != false ? "interrupted" : "rejected";
            receipt.Reason = request.Reason ?? Code(error);
            receipt.Winerror = error is Boundary boundary ? boundary.NativeCode : null;
            receipt.RequiresNewObservation = true;
        }
        finally
        {
            var cleanupAt = clock.Elapsed.TotalMilliseconds;
            watchStop.Cancel();
            if (watcher is not null && !watcher.Wait(1000))
            {
                pipe.Dispose(); receipt.Reason = "watcher_exit_unconfirmed"; core.Fault();
            }
            if (locks is not null)
            {
                try { if (ledger.State != "released") { Native.Desktop(); ledger.Release(receipt); } }
                catch (Exception error) { receipt.Reason = Code(error); receipt.State = "interrupted"; }
                receipt.InputRelease = ledger.State;
                try { locks.Dispose(); receipt.MutexReleased = true; }
                catch { receipt.MutexReleased = false; receipt.Reason = "mutex_release_unconfirmed"; receipt.State = "interrupted"; }
            }
            else receipt.MutexReleased = receipt.Reason != "mutex_release_unconfirmed";
            receipt.TimingsMs["cleanup"] = clock.Elapsed.TotalMilliseconds - cleanupAt;
            receipt.TimingsMs["total"] = clock.Elapsed.TotalMilliseconds;
            receipt.NativeCountKnown = ledger.CountKnown;
            if (receipt.InputResult is { } progress)
            {
                progress.BusinessStarted = receipt.BusinessEvents > 0 ? true : receipt.BusinessAttempted && !ledger.CountKnown ? null : false;
                progress.AcceptedEvents = ledger.CountKnown ? receipt.BusinessEvents : null;
                progress.CleanupEvents = receipt.ReleaseEvents;
                progress.NativeCountKnown = ledger.CountKnown;
            }
        }
        AppExecutor.ReconcileFailure(receipt);
        return receipt;
    }
    internal static string Code(Exception error) => error switch
    {
        Boundary boundary => boundary.Code, OperationCanceledException => "deadline_expired",
        JsonException => "schema_rejected", IOException => "pipe_disconnected",
        UnauthorizedAccessException => "object_access_denied", WaitHandleCannotBeOpenedException => "resource_object_unavailable",
        _ => "helper_failure"
    };
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || (args.Length == 1 && args[0] == "--describe"))
            {
                Console.WriteLine(JsonSerializer.Serialize(new { executor = "global-high-broker", protocol = 2,
                    operations = new[] { "bind", "activate", "click", "text", "computer_input_plan", "app_request", "window_layout" },
                    crossCallHold = false, windowsSessionSingleton = true, idleExit = false,
                    defaultExecution = false, uiAccess = false, runasExecuted = false, highVerified = false }));
                return 0;
            }
            if (args.Length == 1 && args[0] == "--selftest") { Console.WriteLine(JsonSerializer.Serialize(SelfTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-daily-stop")
            { Console.WriteLine(JsonSerializer.Serialize(DailyStopTests.Run())); return 0; }
            if (args.Length == 3 && args[0] == "--selftest-write-gate")
            {
                using var gate = new SharedWriteGate(args[1]); // Always the isolated .test namespace.
                var status = args[2] switch { "stop" => gate.Stop(), "resume" => gate.Resume(), "read" => gate.Snapshot(),
                    _ => throw new Boundary("selftest_write_gate_command_rejected") };
                Console.WriteLine(JsonSerializer.Serialize(new { stopped = status.Stopped, epoch = status.Epoch,
                    resume_all_epoch = status.ResumeAllEpoch, nativeInputExecuted = false })); return 0;
            }
            if (args.Length == 2 && args[0] == "--selftest-computer-plan")
            {
                var bytes = File.ReadAllBytes(args[1]);
                if (bytes.Length > Protocol.Limit) throw new Boundary("input_plan_rejected");
                using var json = JsonDocument.Parse(bytes); Protocol.CheckUnique(json);
                var plan = ComputerPlans.Parse(json.RootElement);
                Console.WriteLine(JsonSerializer.Serialize(new { batches = plan.Plans.Length,
                    events = plan.Plans.Sum(p => p.Segments.Sum(s => s.Steps.Length)), command = plan.Command,
                    nativeInputExecuted = false })); return 0;
            }
            if (args.Length == 1 && args[0] == "--selftest-request-signals")
            { Console.WriteLine(JsonSerializer.Serialize(new { assertions = RequestSignalTests.Run(), nativeInputExecuted = false, highVerified = false })); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-lifecycle") { Console.WriteLine(JsonSerializer.Serialize(LifecycleTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-icon")
            { Console.WriteLine(JsonSerializer.Serialize(new { embeddedTrayIconLoaded = HostWindow.LoadTrayIcon() != IntPtr.Zero,
                windowCreated = false, nativeInputExecuted = false })); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-stdio") return LifecycleTests.StdioSupervisor(false);
            if (args.Length == 1 && args[0] == "--selftest-stdio-early") return LifecycleTests.StdioSupervisor(true);
            if (args.Length == 1 && args[0] == "--stdio-child") return LifecycleTests.StdioChild();
            if (args.Length == 1 && args[0] == "--stdio-early-child") return 17;
            if (args.Length == 1 && args[0] == "--lifecycle-child") return LifecycleTests.Child();
            if (args.Length == 1 && args[0] == "--lifecycle-leaf") return LifecycleTests.Leaf();
            if (args.Length == 1 && args[0] == "--layout-worker") return LayoutWorker.Run();
            if (args.Length == 1 && args[0] == "--shell-desktop-worker") return ShellDesktopWorker.Run();
            if (args.Length == 1 && args[0] == "--serve")
                return BrokerHost.Run(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false));
            if (args.Length == 2 && args[0] == "--serve-fixture")
                return BrokerHost.Run(BrokerPolicy.Load(args[1], true));
            if (args.Length == 2 && args[0] == "--flower-client")
                return ClientAdmission.LaunchFlower(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1]);
            if (args.Length == 2 && args[0] == "--flower-probe")
                return ClientAdmission.LaunchFlower(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1], probe: true);
            if (args.Length == 2 && args[0] == "--flower-admin")
                return BrokerHost.Admin(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1]);
            throw new Boundary("arguments_rejected");
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { reason = Code(error),
                winerror = error is Boundary boundary ? boundary.NativeCode : null, highVerified = false, inputRelease = "unknown" }));
            return 2;
        }
    }
}
