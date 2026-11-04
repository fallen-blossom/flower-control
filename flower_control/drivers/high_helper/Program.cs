using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class Program
{
    private static int RunHumanHandoff()
    {
        UiText.SetLanguage(DisplayPreferences.Read().Language);
        Console.InputEncoding = new System.Text.UTF8Encoding(false, true);
        Console.OutputEncoding = new System.Text.UTF8Encoding(false);
        string? line = Console.ReadLine();
        if (line is null || line.Length > 2048) throw new Boundary("handoff_request_rejected");
        using var document = JsonDocument.Parse(line);
        var request = document.RootElement;
        if (request.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(new[] { "Message", "RequestId", "TimeoutSeconds" }) != true)
            throw new Boundary("handoff_request_rejected");
        string id = request.GetProperty("RequestId").GetString()!, message = request.GetProperty("Message").GetString()!;
        int seconds = request.GetProperty("TimeoutSeconds").GetInt32();
        if (!System.Text.RegularExpressions.Regex.IsMatch(id, "^handoff-[a-f0-9]{32}$") || message.Length is < 1 or > 240
            || message.Any(char.IsControl) || seconds is < 10 or > 3600) throw new Boundary("handoff_request_rejected");
        using var cancellation = new CancellationTokenSource();
        using var available = new AutoResetEvent(false);
        var queue = new System.Collections.Concurrent.ConcurrentQueue<object>();
        int explicitStop = 0, writerDone = 0;
        var writer = new Thread(() =>
        {
            try
            {
                while (Volatile.Read(ref writerDone) == 0 || !queue.IsEmpty)
                {
                    while (queue.TryDequeue(out var value)) { Console.WriteLine(JsonSerializer.Serialize(value)); Console.Out.Flush(); }
                    if (Volatile.Read(ref writerDone) == 0) available.WaitOne(100);
                }
            }
            catch { cancellation.Cancel(); }
        }) { IsBackground = true, Name = "Flower handoff receipts" };
        writer.Start();
        new Thread(() =>
        {
            try
            {
                while (Console.ReadLine() is { } signal)
                {
                    if (signal.Length > 128) break;
                    using var parsed = JsonDocument.Parse(signal);
                    if (parsed.RootElement.TryGetProperty("Stop", out var stop) && stop.ValueKind == JsonValueKind.True)
                    { Interlocked.Exchange(ref explicitStop, 1); break; }
                }
            }
            catch { }
            finally { cancellation.Cancel(); }
        }) { IsBackground = true, Name = "Flower handoff cancellation" }.Start();
        HumanHandoffResult? result = null;
        Exception? failure = null;
        var ui = new Thread(() =>
        {
            try
            {
                result = HumanHandoffWindow.Run(id, message, seconds, cancellation.Token, (action, extension) =>
                {
                    if (action == "stopped") { Interlocked.Exchange(ref explicitStop, 1); cancellation.Cancel(); }
                    queue.Enqueue(new { RequestId = id, Action = action, ExtensionSeconds = extension, Terminal = false });
                    available.Set();
                }, () => Volatile.Read(ref explicitStop) != 0);
            }
            catch (Exception error) { failure = error; }
        });
        ui.SetApartmentState(ApartmentState.STA); ui.Start(); ui.Join();
        queue.Enqueue(new { RequestId = id, Resolution = result?.Resolution ?? "cancelled",
            ExtensionSeconds = result?.ExtensionSeconds ?? 0, Terminal = true, NativeInputExecuted = false,
            Reason = failure is null ? null : "human_popup_unavailable" });
        Interlocked.Exchange(ref writerDone, 1); available.Set(); writer.Join(500);
        return failure is null ? 0 : 2;
    }

    internal static string AssemblyDigest { get; } = Native.Digest(Assembly.GetExecutingAssembly().Location);
    internal static bool AcceptPreGoStop(JsonDocument signal, string ledger, Prepare prepare, BrokerRequest request,
        string? expectedAction = null)
    {
        if (!Protocol.Signal(signal, "stop", ledger, prepare, expectedAction)) return false;
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
    internal static Receipt Request(Stream pipe, Prepare prepare, Peer own, bool medium, BrokerState core, BrokerRequest request,
        BrokerPolicy? policy = null, ComputerPlan? inputPlan = null)
    {
        var receipt = new Receipt { HighVerified = !medium, TaskId = prepare.TaskId,
            ConnectionId = prepare.ConnectionId, DesktopRevision = prepare.DesktopRevision };
        var clock = Stopwatch.StartNew();
        request.ReadOnly = Protocol.ReadOnly(prepare.Operation);
        var ledger = new InputLedger(writeGate: core.WriteGate, stopped: () => request.Stop.IsCancellationRequested);
        receipt.LedgerIdentity = ledger.Identity;
        request.LedgerIdentity = ledger.Identity;
        if (prepare.Operation.Kind == "computer_input_plan")
        {
            inputPlan ??= ComputerPlans.Parse(prepare.Operation.Plan!.Value);
            receipt.RequestBinding = inputPlan.Binding;
            receipt.InputResult = new InputProgress { Binding = receipt.RequestBinding,
                PlannedPlans = inputPlan.Plans.Length, PlannedSegments = inputPlan.Plans.Sum(batch => batch.Segments.Length) };
        }
        else if (prepare.Operation.Kind == "app_request") receipt.RequestBinding = AppExecutor.Parse(prepare.Operation.Plan!.Value, prepare.Target).Binding;
        else if (prepare.Operation.Kind == "window_layout")
        {
            var plan = WindowLayout.Parse(prepare.Operation.Plan!.Value, prepare.Target.Bounds);
            receipt.RequestBinding = plan.Binding; receipt.LayoutResult = WindowLayout.NewResult(plan);
        }
        request.ActionId = receipt.RequestBinding?.ActionId ?? "";
        ResourceLocks? locks = null;
        PasswordMetadata.InputSession? privacySession = null;
        Task? privacyWarm = null;
        Task<PointerPath.PreparedApproach?>? approachWarm = null;
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
            if (policy is not null && !request.ReadOnly && prepare.Operation.Kind == "computer_input_plan")
            {
                void PrewarmCheck()
                {
                    if (linkedStop.IsCancellationRequested || request.Stop.IsCancellationRequested)
                        throw new Boundary("input_stopped");
                    core.Check(prepare.DesktopRevision, write: true);
                    Native.VerifyPeer(prepare.Parent);
                }
                void PrewarmWaitCheck()
                {
                    if (linkedStop.IsCancellationRequested || request.Stop.IsCancellationRequested)
                        throw new Boundary("input_stopped");
                    core.CheckInputWait(prepare.DesktopRevision, write: true);
                }
                privacySession = new PasswordMetadata.InputSession(policy, bound, receipt);
                privacyWarm = Task.Run(() => privacySession.Warm(PrewarmCheck, PrewarmWaitCheck));
                if (ComputerPlans.CanPrepareApproach(inputPlan!))
                    approachWarm = Task.Run(() => {
                        try
                        {
                            PrewarmCheck();
                            return ComputerPlans.PrepareApproach(inputPlan!, PrewarmWaitCheck);
                        }
                        // Speculation must not alter the request. A miss or
                        // failure falls back to the normal fresh approach.
                        catch { return null; }
                    });
            }
            using var go = Protocol.Read(pipe, Math.Max(1, Math.Min(2000, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds)), linkedStop.Token);
            if (go is null) { request.Cancel("client_disconnected"); throw new Boundary("input_stopped"); }
            if (AcceptPreGoStop(go, ledger.Identity, prepare, request, receipt.RequestBinding?.ActionId)) throw new Boundary("input_stopped");
            if (!Protocol.Signal(go, "go", ledger.Identity, prepare, receipt.RequestBinding?.ActionId)) throw new Boundary("go_rejected");
            request.ActionId = go.RootElement.GetProperty("ActionId").GetString()!;
            core.Check(prepare.DesktopRevision, write: !request.ReadOnly);
            if (privacyWarm is not null) privacyWarm.GetAwaiter().GetResult();
            var preparedApproach = approachWarm is not null && approachWarm.IsCompletedSuccessfully
                ? approachWarm.Result : null;
            receipt.TimingsMs["wait_go"] = clock.Elapsed.TotalMilliseconds - receipt.TimingsMs["prepare_ready"];
            watcher = Task.Run(() => WatchPostGo(pipe, prepare, ledger.Identity, request, clock, watchStop.Token));
            bool Stopped() { core.Check(prepare.DesktopRevision, write: !request.ReadOnly); return request.Stop.IsCancellationRequested; }
            bool WaitStopped() { core.CheckInputWait(prepare.DesktopRevision, write: !request.ReadOnly); return request.Stop.IsCancellationRequested; }
            if (policy is not null && !request.ReadOnly)
            {
                ledger.InvalidatePrivacy = () => { privacySession?.Dispose(); privacySession = null; };
                ledger.PrivacyCheck = steps => {
                    void FullCheck() { Executor.Check(prepare, bound, Stopped, clock, true,
                        prepare.Operation.Kind == "computer_input_plan", ledger, receipt); }
                    // Metadata preparation cannot send input. Do not repeatedly
                    // parse protected policy and query the entire target while
                    // waiting for the same fresh provider response. A full
                    // target/focus/policy check still runs in Send's final
                    // preflight after this callback and before any event count.
                    void Check() { Executor.CheckAuthority(prepare, Stopped, clock, ledger); Native.Desktop(); }
                    // Hashing and response waits cannot dispatch. Keep all
                    // durable Stop gates live; held input additionally retains
                    // a full target/policy check at the 80ms motion cadence.
                    void WaitCheck() => ledger.CheckMotionWait(WaitStopped, clock, prepare.DeadlineMs, FullCheck);
                    var desktop = new DesktopShape(Native.GetSystemMetrics(76), Native.GetSystemMetrics(77), Native.GetSystemMetrics(78), Native.GetSystemMetrics(79));
                    privacySession ??= new PasswordMetadata.InputSession(policy, bound, receipt);
                    privacySession.RequireInput(steps, desktop, Check, ledger.OwnTokens.Any(token => token.StartsWith("mouse:", StringComparison.Ordinal)),
                        WaitCheck, ledger, finalCheck: prepare.Operation.Kind != "computer_input_plan");
                };
            }
            if (prepare.Operation.Kind == "window_layout")
                LayoutWorker.Execute(prepare, bound, Stopped, clock, ledger, receipt);
            else if (prepare.Operation.Kind == "app_request")
            {
                if (prepare.Operation.Activate)
                    Executor.Execute(prepare with { Operation = new Operation("activate", RestoreMinimized: prepare.Operation.RestoreMinimized) }, bound, Stopped, clock, ledger, receipt, implicitActivation: true);
                AppExecutor.Execute(policy ?? throw new Boundary("app_worker_not_installed"), prepare, bound, Stopped, clock, receipt, core.WriteGate, ledger);
            }
            else Executor.Execute(prepare, bound, Stopped, clock, ledger, receipt, waitStopped: WaitStopped,
                inputPlan: inputPlan, preparedApproach: preparedApproach);
            receipt.TimingsMs["execute"] = clock.Elapsed.TotalMilliseconds - receipt.TimingsMs["prepare_ready"] - receipt.TimingsMs["wait_go"];
            if (request.Reason == "duplicate_go_rejected") throw new Boundary("duplicate_go_rejected");
        }
        catch (Exception error)
        {
            receipt.State = receipt.ActivationRequested || receipt.RequestedEvents != 0 || receipt.SemanticBusinessDispatched != false ? "interrupted" : "rejected";
            receipt.Reason = request.Reason ?? Code(error);
            receipt.Winerror = error is Boundary boundary ? boundary.NativeCode : null;
            receipt.PrivacyDiagnostics = PrivacyDiagnostics.From(error);
            receipt.RequiresNewObservation = true;
        }
        finally
        {
            var cleanupAt = clock.Elapsed.TotalMilliseconds;
            watchStop.Cancel();
            linkedStop.Cancel();
            if (privacyWarm is not null) try { privacyWarm.Wait(1000); } catch (AggregateException) { }
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
            try { privacySession?.Dispose(); }
            catch (Exception error) { receipt.Reason = Code(error); receipt.State = "interrupted"; }
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
        InvalidDataException invalid when System.Text.RegularExpressions.Regex.IsMatch(invalid.Message,
            "\\Auac_transcript_[a-z_]{1,60}\\z") => invalid.Message,
        FileNotFoundException => "file_not_found",
        JsonException => "schema_rejected", IOException { Message: "execution_audit_create_failed" } => "execution_audit_create_failed",
        IOException => "pipe_disconnected",
        UnauthorizedAccessException => "object_access_denied", WaitHandleCannotBeOpenedException => "resource_object_unavailable",
        _ => "helper_failure"
    };
    internal static (long Shared, long Protected) ParseAdminResumeEpochs(string[] args)
    {
        if (args.Length != 4 || args[0] != "--flower-admin" || args[1] != "resume"
            || !long.TryParse(args[2], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long shared)
            || !long.TryParse(args[3], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long authority)
            || shared < 0 || authority < 0) throw new Boundary("arguments_rejected");
        return (shared, authority);
    }
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
            if (args.Length == 1 && args[0] == "--human-handoff") return RunHumanHandoff();
            // Retire host secure-desktop execution. The host event and preflight
            // switches still serve 04 work provenance and are kept separately.
            if (args[0] is "--uac-bootstrap" or "--uac-worker" or "--uac-enable-production"
                or "--uac-local-esc-experiment" or "--uac-prepare-experiments"
                or "--uac-local-experiment" or "--uac-program-qualification-launcher"
                or "--uac-test-launcher" or "--uac-test-target" or "--uac-register-verification"
                or "--selftest-uac-native" or "--selftest-uac-offline" or "--uac-witness-preflight")
                throw new Boundary("host_uac_feature_retired");
            if (args.Length == 1 && args[0] == "--uac-host-event") return UacHostHook.Run();
            if (args.Length == 1 && args[0] == "--dsh-host-event") return DshHostHook.Run();
            if (args.Length == 1 && args[0] == "--dsh-phase-event") return DshPhaseHook.Run();
            if (args.Length == 1 && args[0] == "--uac-host-preflight") return UacHostHook.Run(preflight: true);
            if (args.Length == 1 && args[0] == "--uac-local-settings") throw new Boundary("uac_settings_frozen");
            if (args.Length == 1 && args[0] == "--flower-role-policy")
            {
                var selected = UserPermissions.Read();
                Console.WriteLine(JsonSerializer.Serialize(new { Phase = "role_policy", selected.Revision, Tier = UserPermissions.TierOf(selected), selected.UserSid,
                    Stop = RoleHandoff.ReadDurableBeforePreparation(Native.Process(Environment.ProcessId).Identity) }));
                return 0;
            }
            if (args.Length == 1 && args[0] == "--selftest-uac-verification")
            { Console.WriteLine(JsonSerializer.Serialize(UacVerificationTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-admin-launch")
            { Console.WriteLine(JsonSerializer.Serialize(AdminProgramLaunchTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--uac-status")
            { Console.WriteLine(JsonSerializer.Serialize(UacRuntime.Capabilities())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-uac")
            { Console.WriteLine(JsonSerializer.Serialize(UacSelfTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-uac-authorization")
            { Console.WriteLine(JsonSerializer.Serialize(UacChatAuthorizationTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-uac-transcript")
            { Console.WriteLine(JsonSerializer.Serialize(new { assertions = UacTranscriptReaderTests.Run(), actualChatsRead = false, inputExecuted = false })); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-human-handoff")
            { Console.WriteLine(JsonSerializer.Serialize(HumanHandoffWindow.NativeLayoutProbe())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-human-handoff-en")
            { UiText.UseEnglishPreview(); Console.WriteLine(JsonSerializer.Serialize(HumanHandoffWindow.NativeLayoutProbe())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest") { Console.WriteLine(JsonSerializer.Serialize(SelfTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--audit-permission-layout")
            { Console.WriteLine(JsonSerializer.Serialize(PermissionSettingsWindow.AuditLayout())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-permission-authority")
            { Console.WriteLine(JsonSerializer.Serialize(PermissionSettingsWindow.NativeAuthorityProbe())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-permission-window")
            { Console.WriteLine(JsonSerializer.Serialize(PermissionSettingsWindow.WindowInteractionProbe())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-permission-layout")
            { Console.WriteLine(JsonSerializer.Serialize(PermissionSettingsWindow.NativeLayoutProbe())); return 0; }
            if (args.Length == 1 && args[0] == "--preview-permission-interface")
                return PermissionSettingsWindow.RunPreview();
            if (args.Length == 2 && args[0] == "--snapshot-permission-window")
                return PermissionSettingsWindow.RunSnapshot(args[1]);
            if (args.Length == 1 && args[0] == "--settings-workspace")
                return SettingsWorkspace.Run(null);
            if (args.Length == 1 && args[0] == "--settings-workspace-preview")
                return SettingsWorkspace.RunPreview();
            if (args.Length == 1 && args[0] == "--settings-workspace-preview-en")
            { UiText.UseEnglishPreview(); return SettingsWorkspace.RunPreview(); }
            if (args.Length == 1 && args[0] == "--selftest-ui-localization")
            { Console.WriteLine(JsonSerializer.Serialize(UiText.SelfTest())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-display-preferences")
            { Console.WriteLine(JsonSerializer.Serialize(DisplayPreferenceTests.Run())); return 0; }
            if (args.Length == 2 && args[0] == "--selftest-settings-language")
            { Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.LanguageSelfTest(args[1]))); return 0; }
            if (args.Length == 1 && args[0] == "--settings-workspace-permission-preview")
                return SettingsWorkspace.RunPreview(1);
            if (args.Length == 2 && args[0] == "--settings-workspace-snapshot")
                return SettingsWorkspace.Run(args[1]);
            if (args.Length == 3 && args[0] == "--settings-workspace-snapshot" && int.TryParse(args[2], out int snapshotPage) && snapshotPage is >= 0 and <= 4)
                return SettingsWorkspace.Run(args[1], snapshotPage);
            if (args.Length is 1 or 2 && args[0] == "--selftest-settings-workspace")
            { try{Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.SelfTest(args.Length==2?args[1]:null)));return 0;}
              catch(Exception error){Console.Error.WriteLine(error);throw;} }
            if (args.Length is 1 or 2 && args[0] == "--selftest-decision-settings")
            { Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.DecisionSettingsSelfTest(args.Length == 2 ? args[1] : null))); return 0; }
            if (args.Length == 2 && args[0] == "--selftest-settings-selection")
            { Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.SelectionSelfTest(args[1]))); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-settings-menu-timing")
            { Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.MenuTimingProbe())); return 0; }
            if (args.Length == 2 && args[0] == "--selftest-settings-ux")
            { Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.UxSelfTest(args[1]))); return 0; }
            if (args.Length == 2 && args[0] == "--selftest-settings-lifecycle")
            { Console.WriteLine(JsonSerializer.Serialize(SettingsWorkspace.LifecycleSelfTest(args[1]))); return 0; }
            if (args.Length == 1 && args[0] == "--preview-tray-menu")
                return TrayMenu.Preview();
            if (args.Length == 1 && args[0] == "--preview-tray-menu-en")
            { UiText.UseEnglishPreview(); return TrayMenu.Preview(); }
            if (args.Length == 1 && args[0] == "--selftest-daily-stop")
            {
                var result = JsonSerializer.SerializeToNode(DailyStopTests.Run())!.AsObject();
                result["adminResumeAssertions"] = BrokerHost.AdminResumeSelfTest();
                Console.WriteLine(result.ToJsonString()); return 0;
            }
            if (args.Length == 1 && args[0] == "--selftest-role-state")
            { Console.WriteLine(JsonSerializer.Serialize(RoleStateTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-local-settings")
            { Console.WriteLine(JsonSerializer.Serialize(LocalSettingsTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-bound-maintenance")
            { Console.WriteLine(JsonSerializer.Serialize(BoundMaintenanceWriterTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-bound-maintenance-high")
            { Console.WriteLine(JsonSerializer.Serialize(BoundMaintenanceWriterTests.RunHigh())); return 0; }
            if (args.Length == 2 && args[0] == "--selftest-bound-maintenance-high")
            {
                string path = Path.GetFullPath(args[1]);
                if (!Path.GetDirectoryName(path)!.Equals(Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
                    || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(path), "\\Aflower-bound-maintenance-high-[a-f0-9]{32}\\.json\\z") || File.Exists(path))
                    throw new Boundary("bound_writer_test_output_rejected");
                object result; int code = 0;
                try { result = BoundMaintenanceWriterTests.RunHigh(); }
                catch (Exception error) { result = new { state = "failed", reason = error is InvalidOperationException && error.Message.StartsWith("bound_writer_test_failed:", StringComparison.Ordinal) ? error.Message : Code(error) }; code = 2; }
                using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                JsonSerializer.Serialize(output, result); output.Flush(true); return code;
            }
            if (args.Length == 4 && args[0] == "--selftest-bound-writer")
                return BoundMaintenanceWriterTests.Writer(args.Skip(1).ToArray());
            if (args.Length == 2 && args[0] == "--selftest-bound-child")
                return BoundMaintenanceWriterTests.Child(args.Skip(1).ToArray());
            if (args.Length == 1 && args[0] == "--selftest-computer-stop")
            { Console.WriteLine(JsonSerializer.Serialize(ComputerStopTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-work-source")
            { Console.WriteLine(JsonSerializer.Serialize(WorkSourceDiagnosticsTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-native-phase")
            { Console.WriteLine(JsonSerializer.Serialize(new { assertions = NativePhaseTests.Run(), inputDispatched = false,
                productionStopTouched = false, scope = "pure event/input ledgers; fixed child EOF and invalid request only" })); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-ordinary-maintenance")
            { Console.WriteLine(JsonSerializer.Serialize(OrdinaryMaintenanceTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-permission-role")
            { Console.WriteLine(JsonSerializer.Serialize(PermissionSettingsRoleTests.Run())); return 0; }
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
                    execution_budget_ms = ComputerPlans.ExecutionBudget(plan),
                    input_progress = new InputProgress { Binding = plan.Binding, AcceptedEvents = 0 },
                    nativeInputExecuted = false })); return 0;
            }
            if (args.Length == 1 && args[0] == "--selftest-request-signals")
            { Console.WriteLine(JsonSerializer.Serialize(new { assertions = RequestSignalTests.Run(), nativeInputExecuted = false, highVerified = false })); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-lifecycle") { Console.WriteLine(JsonSerializer.Serialize(LifecycleTests.Run())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-tray-menu") { Console.WriteLine(JsonSerializer.Serialize(TrayMenu.SelfTest())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-icon")
            { Console.WriteLine(JsonSerializer.Serialize(new { embeddedTrayIconLoaded = HostWindow.LoadTrayIcon() != IntPtr.Zero,
                windowCreated = false, nativeInputExecuted = false })); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-tray-icons")
            { Console.WriteLine(JsonSerializer.Serialize(TrayStateIcons.SelfTest())); return 0; }
            if (args.Length == 1 && args[0] == "--selftest-stdio") return LifecycleTests.StdioSupervisor(false);
            if (args.Length == 1 && args[0] == "--selftest-stdio-early") return LifecycleTests.StdioSupervisor(true);
            if (args.Length == 1 && args[0] == "--stdio-child") return LifecycleTests.StdioChild();
            if (args.Length == 1 && args[0] == "--stdio-early-child") return 17;
            if (args.Length == 1 && args[0] == "--lifecycle-child") return LifecycleTests.Child();
            if (args.Length == 1 && args[0] == "--lifecycle-leaf") return LifecycleTests.Leaf();
            if (args.Length == 1 && args[0] == "--layout-worker") return LayoutWorker.Run();
            if (args.Length == 1 && args[0] == "--shell-desktop-worker") return ShellDesktopWorker.Run();
            if (args.Length == 1 && args[0] is "--audit-verify" or "--audit-history" or "--audit-history-details" or "--audit-recover-tail")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                var audit = ExecutionAudit.Open(policy, Native.Process(Environment.ProcessId).Identity, create: false);
                object report = args[0] == "--audit-recover-tail" ? audit.RecoverUncommittedTail()
                    : audit.History(null, args[0] == "--audit-verify" ? 0 : 100, details: args[0] == "--audit-history-details");
                Console.WriteLine(JsonSerializer.Serialize(report));
                if (args[0] != "--audit-recover-tail")
                {
                    using var document = JsonSerializer.SerializeToDocument(report);
                    if (document.RootElement.GetProperty("History").GetProperty("Integrity").GetString() != "verified_local_chain"
                        || !document.RootElement.GetProperty("RecoveryNotesVerified").GetBoolean()
                        || !document.RootElement.GetProperty("RecoveryPreservationVerified").GetBoolean()) return 2;
                }
                return 0;
            }
            if (args.Length == 1 && args[0] == "--preserve-legacy-computer-pause")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                var own = Native.Process(Environment.ProcessId).Identity;
                if (own.User != policy.UserSid || own.Integrity != 12288 || Native.UiAccess(own.Pid))
                    throw new Boundary("protected_stop_role_required");
                Console.WriteLine(JsonSerializer.Serialize(ProtectedStop.InitializeComputer(own.User, own.Session)));
                return 0;
            }
            // One-time offline migration closes both gates. This local High
            // entry never resumes, dispatches input, or impersonates the old
            // broker. The installer owns the session singleton separately.
            if (args.Length == 1 && args[0] is "--latch-offline-update-stop" or "--offline-update-state")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                var own = Native.Process(Environment.ProcessId).Identity;
                if (own.User != policy.UserSid || own.Integrity != 12288 || Native.UiAccess(own.Pid))
                    throw new Boundary("protected_stop_role_required");
                var computer = ProtectedStop.ReadComputer(own.User, own.Session);
                using var shared = args[0] == "--latch-offline-update-stop" ? new SharedWriteGate() : null;
                if (shared is not null)
                    ProtectedStop.Latch(shared, () => ProtectedStop.Set(own.User, own.Session, true));
                var stop = ProtectedStop.Read(own.User, own.Session);
                var status = shared?.Snapshot();
                if (shared is not null && (!stop.Stopped || status?.Stopped != true)
                    || ProtectedStop.ReadComputer(own.User, own.Session) != computer)
                    throw new Boundary("offline_stop_unconfirmed");
                string? journalHash = null; int? pending = null;
                // Latching runs while the old broker still drains. Do not pin
                // its journal against atomic replacement by terminal cleanup.
                // Only the offline state check (after exit + singleton) reads
                // and validates the final journal.
                if (args[0] == "--offline-update-state") {
                    var journal = Path.GetFullPath(Path.Combine(policy.Directory, "..", "..", "recovery",
                        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(BrokerPipe.LogonSid()))).ToLowerInvariant() + ".json"));
                    BrokerPolicy.RejectLinks(journal);
                    UserPermissions.CheckProtection(journal);
                    using var file = new FileStream(journal, FileMode.Open, FileAccess.Read, FileShare.Read);
                    if (file.Length is < 1 or > 16 * 1024 * 1024) throw new Boundary("offline_journal_rejected");
                    var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
                    pending = OfflineRecovery.Validate(bytes);
                    journalHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
                }
                Console.WriteLine(JsonSerializer.Serialize(new { Stop = stop, Computer = computer, Shared = status,
                    version = policy.Version, JournalSha256 = journalHash, Pending = pending, nativeInputExecuted = false, resumed = false }));
                return 0;
            }
            if (args.Length == 1 && args[0] == "--serve")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                var own = Native.Process(Environment.ProcessId).Identity;
                if (own.User != policy.UserSid || own.Integrity != 12288 || Native.UiAccess(own.Pid)) throw new Boundary("broker_user_integrity_rejected");
                OrdinaryStopJournal.Prepare(own);
                if (UserPermissions.TierOf(UserPermissions.Read()) <= 0)
                {
                    // The protected logon task remains a fixed bootstrap. It
                    // never exposes a High listener in the ordinary/off tier.
                    var reconciliation = new BrokerState(protectedStop: true);
                    UacInstallation.ReconcileOff(policy, reconciliation);
                    BrowserProfileOpen.StartOrdinaryRole(["--serve-user"]); return 0;
                }
                return BrokerHost.Run(policy);
            }
            if (args.Length == 1 && args[0] == "--serve-user")
                return BrokerHost.Run(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), ordinary: true);
            if (args.Length == 4 && args[0] is "--serve-user-staging" or "--local-ui-writer"
                && int.TryParse(args[1], out int roleSourcePid) && long.TryParse(args[2], out long roleSourceCreated))
                return args[0] == "--local-ui-writer" ? LocalUiWriter.Run(roleSourcePid, roleSourceCreated, args[3])
                    : RoleHandoff.RunStaged(true, roleSourcePid, roleSourceCreated, args[3]);
            if (args.Length == 2 && args[0] == "--serve-fixture")
            {
                var fixture = BrokerPolicy.Load(args[1], true);
                // The exact admitted Medium fixture must never read the daily
                // protected user policy. No production branch accepts this.
                UserPermissions.FixturePath = Path.Combine(fixture.Directory, "permissions.json");
                if (!File.Exists(UserPermissions.FixturePath)) throw new Boundary("fixture_policy_missing");
                return BrokerHost.Run(fixture);
            }
            if (args.Length == 2 && args[0] == "--flower-client")
                return ClientAdmission.LaunchFlower(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1]);
            if (args.Length == 2 && args[0] == "--flower-connection-client")
                return ClientAdmission.LaunchFlower(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1], connection: true);
            if (args.Length == 2 && args[0] == "--flower-probe")
                return ClientAdmission.LaunchFlower(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1], probe: true);
            if (args.Length == 1 && args[0] == "--flower-capabilities")
            { Console.WriteLine(JsonSerializer.Serialize(new { schema = 1, bound_maintenance_writer_protocol = 1,
                AssemblyDigest, AuthorityGranted = false, InputDispatched = false })); return 0; }
            if (args.Length == 2 && args[0] == "--flower-update-status")
                return BrokerHost.Admin(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false),
                    "status", maintenanceOperation: args[1]);
            if (args.Length == 9 && args[0] == "--flower-update-maintenance")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                var command = MaintenanceCommand.Parse(new[] { "--flower-maintenance" }.Concat(args.Skip(2)).ToArray(), policy.Version);
                return BrokerHost.Admin(policy, command.Command, maintenance: command.Expected, maintenanceOperation: args[1]);
            }
            if (args.Length == 2 && args[0] == "--flower-admin")
                return BrokerHost.Admin(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), args[1]);
            if (args.Length == 8 && args[0] == "--flower-maintenance")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                var command = MaintenanceCommand.Parse(args, policy.Version);
                return BrokerHost.Admin(policy, command.Command, maintenance: command.Expected);
            }
            if (args.Length == 3 && args[0] == "--flower-maintenance-ordinary")
            {
                var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
                return OrdinaryMaintenance.Client(policy, OrdinaryMaintenanceCommand.Parse(args, policy.Version));
            }
            if (args.Length == 4 && args[0] == "--flower-admin")
            {
                var (shared, authority) = ParseAdminResumeEpochs(args);
                return BrokerHost.Admin(BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), "resume", shared, authority);
            }
            throw new Boundary("arguments_rejected");
        }
        catch (Exception error)
        {
            // Scheduled SYSTEM children have no captured stderr. Retain their
            // local failure without storing arguments, prompts or user input.
            try
            {
                if (args.Length > 0 && args[0] is "--uac-bootstrap" or "--uac-worker" or "--uac-test-launcher" or "--uac-test-target"
                    or "--uac-local-settings" or "--uac-local-experiment" or "--uac-prepare-experiments")
                {
                    var identity = Native.Process(Environment.ProcessId).Identity;
                    if (identity.Integrity >= 12288)
                    {
                        UserPermissions.CheckProtectionForDirectory(AppContext.BaseDirectory);
                        var path = Path.Combine(AppContext.BaseDirectory, "uac-process-error." + Environment.ProcessId + "." + Guid.NewGuid().ToString("N") + ".json");
                        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                        JsonSerializer.Serialize(output, new { Role = args[0], identity.User, identity.Integrity, identity.Session,
                            Reason = Code(error), NativeCode = (error as Boundary)?.NativeCode, Operation = error.Data["Operation"], Stack = error.StackTrace });
                        output.Flush(true);
                    }
                }
            }
            catch { /* Original failure remains authoritative. */ }
            Console.Error.WriteLine(JsonSerializer.Serialize(new { reason = Code(error),
                winerror = error is Boundary boundary ? boundary.NativeCode : null, highVerified = false, inputRelease = "unknown" }));
            return 2;
        }
    }
}
