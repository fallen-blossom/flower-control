using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal static class BrokerHost
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool PeekNamedPipe(IntPtr pipe, IntPtr buffer, uint size, IntPtr read, IntPtr available, IntPtr remaining);
    // Structured requests must reach their own strict Decode<T>. Protocol.Phase
    // intentionally accepts only the one-field control/status messages.
    internal static bool StructuredPhase(JsonDocument data, string phase)
    {
        var root = data.RootElement;
        return root.ValueKind == JsonValueKind.Object && root.TryGetProperty("Phase", out var value)
            && value.ValueKind == JsonValueKind.String && value.GetString() == phase;
    }
    // Work authority and High launch are App capabilities. Web/Computer have
    // their own structured routes and must not retain a hidden administrator path.
    internal static bool AdministrativeChannel(string? channel) => channel == "flower-app";
    internal static int Run(BrokerPolicy policy, bool ordinary = false)
    {
        if (!policy.Fixture) UiText.LoadProduction(policy.DataRoot);
        var own = Native.Process(Environment.ProcessId).Identity;
        if (ordinary && policy.Fixture) throw new Boundary("ordinary_role_fixture_rejected");
        if (own.User != policy.UserSid || own.Integrity != (policy.Fixture || ordinary ? 8192 : 12288) || Native.UiAccess(own.Pid))
            throw new Boundary("broker_user_integrity_rejected");
        if (!policy.Fixture && !ordinary && UserPermissions.TierOf(UserPermissions.Read()) <= 0)
            throw new Boundary("high_role_not_selected");
        if (!policy.Fixture && !ordinary) OrdinaryStopJournal.Prepare(own);
        using var singleton = new Mutex(false, "Local\\FlowerControl." + (ordinary ? "UserBroker." : "HighBroker.") + (policy.Fixture ? policy.FixturePipe : BrokerPipe.LogonSid()));
        bool owned;
        try { owned = singleton.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
        if (!owned) return 0;
        using var executionRole = policy.Fixture ? null : new ExecutionRoleLease();
        if (!policy.Fixture && !SettingsWorkspace.HasIncomingHandoff)
            try { RoleDraftRecovery.Restore(policy, own); }
            catch (Exception error) { Console.Error.WriteLine(JsonSerializer.Serialize(new { settingsDraftRecovery = Program.Code(error) })); }
        string? recoveryPath = null;
        if (!policy.Fixture)
        {
            var root = ordinary ? Path.Combine(policy.DataRoot, "control", "ordinary-recovery")
                : Path.GetFullPath(Path.Combine(policy.Directory, "..", "..", "recovery"));
            if (ordinary && !Path.IsPathFullyQualified(policy.DataRoot)) throw new Boundary("ordinary_data_root_required");
            Directory.CreateDirectory(root);
            BrokerPolicy.RejectLinks(root);
            recoveryPath = Path.Combine(root, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(BrokerPipe.LogonSid()))).ToLowerInvariant() + ".json");
        }
        using var writeGate = new SharedWriteGate(policy.Fixture ? "fixture_" + own.Pid : null);
        var core = new BrokerState(recoveryPath, writeGate, protectedStop: !policy.Fixture,
            shutdownObserver: ordinary ? null : notice => BrokerLifecycle.Record(policy, own, notice)) { OrdinaryResident = ordinary };
        UacRuntime.RestoreInputFault(policy, own, core);
        if (!policy.Fixture && !ordinary)
        {
            try { UacInstallation.ReconcileOff(policy, core); }
            catch (Exception error) { core.CancelUacRequests("uac_disable_unverified"); Console.Error.WriteLine(JsonSerializer.Serialize(new { uacOffReconciliation = Program.Code(error) })); }
        }
        var handlers = new ConcurrentDictionary<Task, byte>();
        var accept = Accept(policy, own, core, handlers);
        _ = accept.ContinueWith(failed => {
            if (failed.IsFaulted)
            {
                var error = failed.Exception!.GetBaseException();
                Console.Error.WriteLine(JsonSerializer.Serialize(new { reason = Program.Code(error), stage = "pipe_accept",
                    exception_type = error.GetType().Name, winerror = error is Boundary boundary ? boundary.NativeCode : null }));
                core.Fault(); core.Stop(BrokerShutdownReason.PipeAcceptFailure);
            }
        }, TaskScheduler.Default);
        try
        {
            if (policy.Fixture)
            {
                while (!core.Shutdown.Token.WaitHandle.WaitOne(100)) PollDesktop(core);
            }
            else HostWindow.Run(core);
        }
        finally
        {
            core.Stop();
            try { accept.GetAwaiter().GetResult(); } catch (Exception) { core.Fault(); }
            // Threads own their locks and release there. Never force-kill an executor.
            try
            {
                if (!Task.WaitAll(handlers.Keys.ToArray(), 6500))
                {
                    core.Fault();
                    Console.Error.WriteLine("{\"reason\":\"broker_drain_unconfirmed\",\"inputRelease\":\"unknown\"}");
                    // Do not terminate a thread still holding keys or its mutex.
                    Task.WaitAll(handlers.Keys.ToArray());
                }
            }
            catch (AggregateException) { core.Fault(); }
            // A pipe-accept continuation can initiate shutdown outside the
            // handler set; do not exit while its first reason is still writing.
            core.DrainShutdownEvidence();
            singleton.ReleaseMutex();
        }
        return handlers.Count == 0 && !core.IsFault ? 0 : 2;
    }
    internal static void PollDesktop(BrokerState state)
    {
        try { Native.Desktop(); state.Desktop(true); }
        catch (Boundary error) { state.Desktop(false, error.Code); }
    }
    private static async Task Accept(BrokerPolicy policy, Peer own, BrokerState core, ConcurrentDictionary<Task, byte> handlers)
    {
        bool first = true;
        while (!core.Shutdown.IsCancellationRequested)
        {
            var pipe = BrokerPipe.Create(policy.Fixture ? policy.FixturePipe : core.OrdinaryResident ? BrokerPipe.OrdinaryName(own) : BrokerPipe.Name(own), first);
            first = false;
            try { await pipe.WaitForConnectionAsync(core.Shutdown.Token); }
            catch { pipe.Dispose(); if (core.Shutdown.IsCancellationRequested) return; throw; }
            if (Volatile.Read(ref core.Connections) >= 32) { pipe.Dispose(); continue; }
            Interlocked.Increment(ref core.Connections);
            // Each handler stays synchronous on one dedicated thread for mutex ownership.
            var task = Task.Factory.StartNew(() => Handle(pipe, policy, own, core), CancellationToken.None,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            handlers[task] = 0;
            _ = task.ContinueWith(completed => { handlers.TryRemove(completed, out _); }, TaskScheduler.Default);
        }
    }
    private static void Handle(NamedPipeServerStream pipe, BrokerPolicy policy, Peer own, BrokerState core)
    {
        var connectionId = Guid.NewGuid().ToString("N");
        try
        {
            if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
                throw new Boundary("client_identity_unavailable");
            var physical = Native.Process((int)pid);
            var physicalCaller = physical.Identity;
            bool localUiOnly = !policy.Fixture && (RoleHandoff.ExpectedPeer(physicalCaller, core) || LocalUiWriter.ExpectedPeer(physicalCaller, core));
            // A runas/Explorer child has no Codex ancestry. Admit only its
            // already-bound exact Peer to the narrow in-memory UI transaction,
            // never to generic admin, host provenance, MCP or input phases.
            using var first = Protocol.Read(pipe, 3000, core.Shutdown.Token);
            if (first is null) return;
            var hello = Protocol.Decode<ClientHello>(first);
            if (hello.Channel == LocalSettingsEntry.Channel)
            {
                LocalSettingsEntry.Serve(pipe, policy, own, core, physicalCaller, physical.Image,
                    hello.Phase, hello.Parent, hello.MaintenanceOperation);
                return;
            }
            bool boundWriter = !policy.Fixture && !localUiOnly && hello.Channel == "flower-admin"
                && hello.MaintenanceOperation is not null;
            if (hello.MaintenanceOperation is not null && !boundWriter) throw new Boundary("maintenance_writer_channel_rejected");
            var admission = localUiOnly ? new Admission(physicalCaller,
                new(physicalCaller.Pid, physicalCaller.Created, physicalCaller.Session, "native-local-ui", null, false, null, null, null), true)
                : boundWriter ? BoundMaintenanceWriter.Verify((int)pid, hello.MaintenanceOperation!, policy, own)
                : ClientAdmission.Verify((int)pid, policy);
            if (hello.Phase != "hello" || hello.Parent != admission.Peer
                || (localUiOnly ? hello.Channel != "flower-local-ui" : policy.Fixture ? hello.Channel != "fixture" : admission.Admin ? hello.Channel is not ("flower-admin" or "flower-uac-hook")
                    : hello.Channel is not ("flower-web" or "flower-app" or "flower-computer")))
                throw new Boundary("client_hello_rejected");
            var evidence = admission.Evidence with { Channel = hello.Channel };
            // Actual admitted host sources may recover terminal release metadata
            // across host restarts. No input or private grant is issued.
            var source = policy.Fixture || localUiOnly || boundWriter ? own : Native.Process(admission.Evidence.SourcePid, digestImage: false).Identity;
            Protocol.Write(pipe, new { Phase = "hello", Helper = own, AssemblyDigest = Program.AssemblyDigest,
                Version = policy.Version, ConnectionId = connectionId, PeerEvidence = evidence, Status = core.Snapshot(policy, own) });
            if (hello.Channel == "flower-uac-hook")
            {
                if (core.OrdinaryResident) throw new Boundary("high_role_required");
                if (admission.Evidence.Source == "dsh-desktop-flower")
                {
                    using var dshPacket = Protocol.Read(pipe, 3000);
                    if (dshPacket is not null) Protocol.Write(pipe, DshMessageBinding.Observe(policy, own, core, admission,
                        Protocol.Decode<DshHostMessage>(dshPacket)));
                    return;
                }
                if (policy.Fixture || !admission.Admin || admission.Peer.Integrity != 8192 || admission.Evidence.Source != "codex-flower")
                    throw new Boundary("uac_prompt_host_unverified");
                using var packet = Protocol.Read(pipe, 3000);
                if (packet is null) return;
                var prompt = Protocol.Decode<UacHostMessage>(packet);
                if (prompt.Phase != "uac_host_event" || prompt.HostKind != "codex" || prompt.Purpose != "work")
                    throw new Boundary("uac_prompt_event_required");
                var hookSettings = UserPermissions.Read();
                bool workSource = hookSettings.AdminLaunchEnabled && hookSettings.AdminLaunchMode == "semantic"
                    && hookSettings.SemanticDelegation is not null;
                WorkHostMessage? workMessage = null; Exception? workMessageError = null;
                if (workSource) try { workMessage = UacTranscriptBinding.ObserveWorkHook(policy, own, prompt); }
                catch (Exception error) { workMessageError = error; }
                if (workMessageError is not null) throw workMessageError;
                if (workMessage is null) Protocol.Write(pipe, new { Phase = "uac_host_event", Ignored = true });
                else Protocol.Write(pipe, new { Phase = "uac_host_event", Scope = "work_message",
                    Snapshot = new { MessageRef = workMessage.EventDigest } });
                return;
            }
            while (!core.Shutdown.IsCancellationRequested)
            {
                using var message = Protocol.Read(pipe, int.MaxValue, core.Shutdown.Token);
                long computerStopGeneration = core.ComputerStopGeneration;
                if (message is null) return; // This connection only; the singleton continues.
                Native.VerifyPeer(admission.Peer);
                if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out pid) || pid != admission.Peer.Pid)
                    throw new Boundary("client_identity_changed");
                if (boundWriter)
                {
                    var currentWriter = BoundMaintenanceWriter.Verify(admission.Peer.Pid, hello.MaintenanceOperation!, policy, own);
                    BoundMaintenanceWriter.RequirePhase(UacOutcomeEvidence.Text(message.RootElement, "Phase"), core.OrdinaryResident);
                    BoundMaintenanceWriter.RequireMessage(currentWriter, message.RootElement);
                }
                if (localUiOnly)
                {
                    if (LocalUiWriter.TryHandle(message, pipe, admission.Peer, core, policy.Version)
                        || RoleHandoff.TryHandle(message, pipe, admission.Peer, core)) continue;
                    throw new Boundary("local_ui_phase_rejected");
                }
                if (core.OrdinaryResident)
                {
                    // Reject every privileged protocol family before parsing
                    // or any user-policy, UAC, launch or work-authority write.
                    if (!message.RootElement.TryGetProperty("Phase", out var ordinaryPhase)
                        || ordinaryPhase.GetString() is not ("status" or "computer_run_status" or "request_status" or "password_metadata"
                            or "release_recovery" or "release_recovery_ack" or "open_settings" or "prepare" or "maintenance_ordinary"
                            or "local_ui_get" or "local_ui_result" or "local_ui_preflight" or "local_ui_begin_commit" or "role_handoff_get" or "role_handoff_ready"))
                        throw new Boundary("high_role_required");
                }
                if (admission.Admin && (LocalUiWriter.TryHandle(message, pipe, admission.Peer, core, policy.Version)
                    || RoleHandoff.TryHandle(message, pipe, admission.Peer, core))) continue;
                if (StructuredPhase(message, "dsh_context"))
                {
                    if (policy.Fixture || admission.Admin || admission.Evidence.Source != "dsh-desktop-flower")
                        throw new Boundary("dsh_host_event_rejected");
                    var context = message.RootElement;
                    string? session = UacOutcomeEvidence.Text(context, "SessionId");
                    if (UacOutcomeEvidence.Text(context, "ConnectionId") != connectionId || session is null
                        || session.Length is < 1 or > 256 || session.Trim() != session || session.Any(char.IsControl))
                        throw new Boundary("dsh_host_event_rejected");
                    Protocol.Write(pipe, DshMessageBinding.Context(session)); continue;
                }
                if (StructuredPhase(message, "work_authority"))
                {
                    if (policy.Fixture || admission.Admin || !AdministrativeChannel(hello.Channel)
                        || admission.Evidence.Source is not ("codex-flower" or "claude-code-flower" or "dsh-desktop-flower"))
                        throw new Boundary("work_authority_source_rejected");
                    var query = Protocol.Decode<WorkAuthorityQuery>(message);
                    ExecutionAudit.RequireThreadSource(query.Thread, admission.Evidence);
                    using var callSource = DshCallSource.Enter(admission.Evidence.Source, query.Thread?.ThreadId, query.DshSource,
                        query.Command is "prepare" or "amend" or "recover");
                    var report = WorkAuthority.Handle(policy, own, admission.Peer, query, connectionId, core,
                        () => pipe.IsConnected && PeekNamedPipe(pipe.SafePipeHandle.DangerousGetHandle(), IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero));
                    Protocol.Write(pipe, report); continue;
                }
                if (StructuredPhase(message, "uac_permission"))
                {
                    // The retired host-UAC route is unavailable even to an old
                    // client that still knows its wire protocol. Existing
                    // durable denial and release records are left untouched.
                    throw new Boundary("host_uac_feature_retired");
                }
                if (StructuredPhase(message, "program_launch"))
                {
                    if (policy.Fixture || admission.Admin || admission.Evidence.Source is not ("codex-flower" or "claude-code-flower" or "dsh-desktop-flower")
                        || !AdministrativeChannel(hello.Channel)) throw new Boundary("program_launch_source_rejected");
                    var launch = Protocol.Decode<ProgramLaunchQuery>(message);
                    ExecutionAudit.RequireThreadSource(launch.Thread, admission.Evidence);
                    using var callSource = DshCallSource.Enter(admission.Evidence.Source, launch.Thread?.ThreadId, launch.DshSource,
                        launch.Command == "launch");
                    if (launch.ConnectionId != connectionId || !AdminProgramLaunch.Id(launch.TaskId))
                        throw new Boundary("program_launch_binding_rejected");
                    if (launch.Command != "launch")
                    {
                        Protocol.Write(pipe, AdminProgramLaunch.Handle(policy, own, source, launch, connectionId, core, new BrokerRequest()));
                        continue;
                    }
                    // High launch permission is independent of SYSTEM/UAC mode.
                    var launchOwner = new BrokerRequest { Owner = admission.Peer, TaskId = launch.TaskId, AdminLaunch = true,
                        Channel = hello.Channel,
                        AdminLaunchCaller = source, AdminLaunchRequestId = launch.RequestId, AdminLaunchProgramRef = launch.ProgramRef };
                    using var launchActivity = core.BeginMaintenanceActivity();
                    if (!core.Requests.TryAdd(connectionId, launchOwner)) throw new Boundary("connection_request_busy");
                    using var ready = new ManualResetEvent(false);
                    string? nonce = null;
                    launchOwner.AdminLaunchLastPreflight = () => {
                        ready.Reset(); Volatile.Write(ref nonce, Guid.NewGuid().ToString("N"));
                        Protocol.Write(pipe, new { Phase = "program_launch_preflight", TaskId = launch.TaskId,
                            ConnectionId = connectionId, launch.RequestId, launch.ProgramRef, Nonce = Volatile.Read(ref nonce) });
                        if (WaitHandle.WaitAny([launchOwner.Stop.Token.WaitHandle, ready], 5000) != 1)
                            throw new Boundary(launchOwner.Reason ?? "program_launch_caller_preflight_unconfirmed");
                    };
                    using var finished = new CancellationTokenSource();
                    var watching = Task.Run(() => {
                        try
                        {
                            while (!finished.IsCancellationRequested)
                            {
                                using var signal = Protocol.Read(pipe, 65000, finished.Token);
                                if (finished.IsCancellationRequested) return;
                                bool bound = signal is not null && signal.RootElement.GetProperty("TaskId").GetString() == launch.TaskId
                                    && signal.RootElement.GetProperty("ConnectionId").GetString() == connectionId
                                    && signal.RootElement.GetProperty("RequestId").GetString() == launch.RequestId
                                    && signal.RootElement.GetProperty("ProgramRef").GetString() == launch.ProgramRef;
                                var signalPhase = signal is null ? null : signal.RootElement.GetProperty("Phase").GetString();
                                if (bound && signalPhase == "program_launch_preflight_ready" && Volatile.Read(ref nonce) is { } expected
                                    && signal!.RootElement.GetProperty("Nonce").GetString() == expected)
                                { ready.Set(); continue; }
                                launchOwner.Cancel(bound && signalPhase == "program_launch_cancel" ? "program_launch_task_cancelled"
                                    : signal is null ? "client_disconnected" : "program_launch_cancel_binding_rejected"); return;
                            }
                        }
                        catch (OperationCanceledException) when (finished.IsCancellationRequested) { }
                        catch (Exception error) { launchOwner.CaptureAdminLaunchFailure(error, "caller_watch", finished.IsCancellationRequested); launchOwner.Cancel(Program.Code(error)); }
                    });
                    object report;
                    try { report = AdminProgramLaunch.Handle(policy, own, source, launch, connectionId, core, launchOwner); }
                    finally
                    {
                        finished.Cancel(); watching.GetAwaiter().GetResult();
                        core.Requests.TryRemove(connectionId, out _); launchOwner.Stop.Dispose();
                    }
                    Protocol.Write(pipe, AdminProgramLaunch.CompleteReport(report, launchOwner.AdminLaunchFailure)); continue;
                }
                if (Protocol.Phase(message, "status"))
                {
                    PollDesktop(core);
                    Protocol.Write(pipe, new { Phase = "status", Status = core.Snapshot(policy, own) });
                    continue;
                }
                if (Protocol.Phase(message, "computer_run_status"))
                {
                    if (hello.Channel != "flower-computer" || admission.Admin)
                        throw new Boundary("input_role_rejected");
                    Protocol.Write(pipe, new { Phase = "computer_run_status", Run = new {
                        pid = own.Pid, created = own.Created, version = policy.Version,
                        computer_stop_generation = core.ComputerStopGeneration } });
                    continue;
                }
                if (message.RootElement.TryGetProperty("Phase", out var queryPhase) && queryPhase.GetString() == "request_status")
                {
                    var query = Protocol.Decode<RequestQuery>(message);
                    if (!Regex.IsMatch(query.LedgerIdentity, "^[a-f0-9]{64}$")
                        || !Regex.IsMatch(query.ConnectionId, "^[a-f0-9]{32}$")
                        || !Regex.IsMatch(query.TaskId, "^[a-zA-Z0-9_-]{1,128}$")) throw new Boundary("request_status_rejected");
                    Protocol.Write(pipe, core.RequestStatus(admission.Peer, query.TaskId, query.ConnectionId, query.LedgerIdentity));
                    continue;
                }
                if (message.RootElement.TryGetProperty("Phase", out var metadataPhase) && metadataPhase.GetString() == "password_metadata")
                {
                    var query = Protocol.Decode<MetadataQuery>(message);
                    if (admission.Admin || query.ConnectionId != connectionId || !Regex.IsMatch(query.TaskId, "^[a-zA-Z0-9_-]{1,128}$")
                        || query.Target.Nonce <= 0 || query.Target.Pid <= 0 || query.Target.Created <= 0)
                        throw new Boundary("privacy_metadata_binding_rejected");
                    PollDesktop(core); core.CheckCapacity();
                    var metadataRequest = new BrokerRequest { Owner = admission.Peer, TaskId = query.TaskId, ReadOnly = true, Channel = hello.Channel };
                    using var metadataActivity = core.BeginMaintenanceActivity();
                    if (!core.Requests.TryAdd(connectionId, metadataRequest)) throw new Boundary("connection_request_busy");
                    var clock = Stopwatch.StartNew();
                    try
                    {
                        void Check()
                        {
                            core.Check(query.DesktopRevision, write: false);
                            if (metadataRequest.Stop.IsCancellationRequested || core.Shutdown.IsCancellationRequested || clock.ElapsedMilliseconds >= 3000)
                                throw new Boundary("privacy_password_scan_incomplete");
                            Native.CheckTarget(query.Target, false);
                        }
                        Check(); var bound = Native.CheckTarget(query.Target, false);
                        var metadata = PasswordMetadata.Scan(policy, bound, Check); Check();
                        Protocol.Write(pipe, new { Phase = "password_metadata", query.TaskId, query.ConnectionId,
                            query.DesktopRevision, Target = bound, Metadata = metadata, Dispatched = false });
                    }
                    finally { core.Requests.TryRemove(connectionId, out _); metadataRequest.Stop.Dispose(); }
                    continue;
                }
                if (message.RootElement.TryGetProperty("Phase", out var recoveryPhase)
                    && recoveryPhase.GetString() is "release_recovery" or "release_recovery_ack")
                {
                    var query = Protocol.Decode<RecoveryQuery>(message);
                    if ((!policy.Fixture && admission.Admin) || !Regex.IsMatch(query.LedgerIdentity, "^[a-f0-9]{64}$")
                        || !Regex.IsMatch(query.TaskId, "^[a-zA-Z0-9_-]{1,128}$") || query.ActionId.Length is < 1 or > 512
                        || query.ActionId.Any(char.IsControl) || query.ExecutorProcess.Length is < 8 or > 128)
                        throw new Boundary("release_recovery_rejected");
                    if (query.Phase == "release_recovery_ack")
                    {
                        core.AcknowledgeRecovery(source, query.TaskId, query.ActionId, query.ExecutorProcess, query.LedgerIdentity);
                        Protocol.Write(pipe, new { Phase = "release_recovery_ack", LedgerIdentity = query.LedgerIdentity });
                    }
                    else Protocol.Write(pipe, core.RecoverRelease(source, query.TaskId, query.ActionId, query.ExecutorProcess, query.LedgerIdentity));
                    continue;
                }
                if (StructuredPhase(message, "maintenance_ordinary"))
                {
                    if (policy.Fixture || !core.OrdinaryResident || !admission.Admin || admission.Peer.Integrity != 12288)
                        throw new Boundary("maintenance_local_high_required");
                    NativeRoleIdentity.Require(admission.Peer, policy, 12288);
                    var command = OrdinaryMaintenanceCommand.Decode(message);
                    var status = core.MaintainOrdinary(command.Command, command.Expected, policy, own, pipe,
                        boundWriter ? hello.MaintenanceOperation : null);
                    if (command.Command == "shutdown")
                    {
                        try { Protocol.Write(pipe, new { Phase = "control", Command = command.Command, Status = status }); }
                        finally { core.Stop(BrokerShutdownReason.AdminShutdown, admission.Peer); }
                        return;
                    }
                    if (command.Command != "resume") Protocol.Write(pipe, new { Phase = "control", Command = command.Command, Status = status });
                    continue;
                }
                if (StructuredPhase(message, "maintenance"))
                {
                    if (policy.Fixture || !admission.Admin || admission.Peer.Integrity != 12288)
                        throw new Boundary("maintenance_local_high_required");
                    var command = Protocol.Decode<MaintenanceCommand>(message);
                    var status = core.Maintain(command, policy, own);
                    if (command.Command == "shutdown")
                    {
                        try { Protocol.Write(pipe, new { Phase = "maintenance", Command = command.Command, Status = status }); }
                        finally { core.Stop(BrokerShutdownReason.AdminShutdown, admission.Peer); }
                        return;
                    }
                    Protocol.Write(pipe, new { Phase = "maintenance", Command = command.Command, Status = status });
                    continue;
                }
                if (StructuredPhase(message, "open_settings"))
                {
                    if (!admission.Admin || policy.Fixture) throw new Boundary("settings_window_source_rejected");
                    HostWindow.RequestSettings(core);
                    Protocol.Write(pipe, new { Phase = "settings_open_requested", PolicyChanged = false, InputDispatched = false });
                    continue;
                }
                if (message.RootElement.TryGetProperty("Phase", out var phase) && phase.GetString() == "control")
                {
                    var control = Protocol.Decode<Control>(message);
                    if (!admission.Admin || control.Command is not ("pause" or "resume" or "shutdown")) throw new Boundary("control_rejected");
                    if (control.Command == "pause") core.Pause(true); // Publish Stop before any maintenance lock.
                    else core.UnboundAdminControl(() => {
                        if (control.Command == "resume")
                        {
                            if (!policy.Fixture && admission.Peer.Integrity != 12288) throw new Boundary("resume_local_high_required");
                            if (control.ExpectedEpoch is null) throw new Boundary("resume_snapshot_required");
                            PollDesktop(core); core.Pause(false, control.ExpectedEpoch, control.ExpectedProtectedEpoch);
                        }
                        else core.BeginMaintenanceShutdown();
                    });
                    if (control.Command == "shutdown") {
                        // Freeze the tray mutation and reject persistence faults
                        // before reporting success. Keep this handler alive for
                        // its sole response, then close listeners even on EOF.
                        try { Protocol.Write(pipe, new { Phase = "control", Command = control.Command, Status = core.Snapshot(policy, own) }); }
                        finally { core.Stop(BrokerShutdownReason.AdminShutdown, admission.Peer); }
                        return;
                    }
                    Protocol.Write(pipe, new { Phase = "control", Command = control.Command, Status = core.Snapshot(policy, own) });
                    continue;
                }
                if (message.RootElement.TryGetProperty("Phase", out var uacPhase) && uacPhase.GetString() == "uac")
                {
                    throw new Boundary("host_uac_feature_retired");
                }
                if (!policy.Fixture && admission.Admin) throw new Boundary("input_role_rejected");
                var prepare = Protocol.Decode<Prepare>(message);
                var inputPlan = Protocol.Validate(prepare, policy.Fixture || core.OrdinaryResident);
                bool readOnly = Protocol.ReadOnly(prepare.Operation);
                if (hello.Channel == "flower-computer" && !readOnly
                        && prepare.ComputerStopGeneration is not >= 0)
                    throw new Boundary("computer_run_binding_required");
                if (prepare.Parent != admission.Peer || prepare.ConnectionId != connectionId
                    || !Regex.IsMatch(prepare.TaskId, "^[a-zA-Z0-9_-]{1,128}$")) throw new Boundary("request_binding_rejected");
                // Bind metadata is not physical input. Classify before admission
                // so pause/Stop cannot cancel a read in the registration gap.
                PollDesktop(core);
                core.CheckCapacity();
                var request = new BrokerRequest { Owner = admission.Peer, TaskId = prepare.TaskId, Channel = hello.Channel, ReadOnly = readOnly };
                using var inputActivity = core.BeginMaintenanceActivity();
                core.RegisterInputRequest(connectionId, request, computerStopGeneration, prepare.ComputerStopGeneration);
                Receipt receipt;
                try { receipt = Program.Request(pipe, prepare, own, policy.Fixture || core.OrdinaryResident, core, request, policy, inputPlan); }
                finally { core.Requests.TryRemove(connectionId, out _); request.Stop.Dispose(); }
                try { core.Completed(admission.Peer, receipt, source, own, request.ActionId); }
                catch { core.Fault(); throw; }
                if (!BrokerState.InputReleased(receipt)) core.Fault();
                try { Protocol.Write(pipe, receipt); } catch (IOException) { return; }
                if (!BrokerState.InputReleased(receipt)) return;
                var ackClock = Stopwatch.StartNew();
                while (true)
                {
                    using var ack = Protocol.Read(pipe, Math.Max(1, 2000 - (int)ackClock.ElapsedMilliseconds), core.Shutdown.Token);
                    if (ack is null) return;
                    if (Protocol.Signal(ack, "ack", receipt.LedgerIdentity!, prepare, request.ActionId))
                    { core.Acknowledge(admission.Peer, receipt.LedgerIdentity!); break; }
                    if (!Protocol.Signal(ack, "stop", receipt.LedgerIdentity!, prepare, request.ActionId) || ackClock.ElapsedMilliseconds >= 2000)
                        throw new Boundary("ack_rejected");
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception error)
        {
            UacRuntime.AuthorizationFault(core, error);
            try { Protocol.Write(pipe, new { Phase = "error", Reason = Program.Code(error),
                PrivacyDiagnostics = PrivacyDiagnostics.From(error),
                StopPersistenceError = error.Data["StopPersistenceError"],
                PermissionWriteAttempted = error.Data["PermissionWriteAttempted"] }); } catch { }
        }
        finally
        {
            pipe.Dispose();
            Interlocked.Decrement(ref core.Connections);
        }
    }
    internal static (long? Shared, long? Protected) AdminResumeEpochs(JsonElement status,
        long? fixedShared = null, long? fixedProtected = null)
    {
        if ((fixedShared is null) != (fixedProtected is null) || fixedShared < 0 || fixedProtected < 0)
            throw new Boundary("control_rejected");
        long shared = status.GetProperty("global_stop_epoch").GetInt64();
        long? protectedEpoch = status.TryGetProperty("protected_stop_epoch", out var value)
            && value.ValueKind == JsonValueKind.Number ? value.GetInt64() : null;
        // A maintenance caller supplies its prechecked immutable snapshot.
        // A newer hello must not silently authorize clearing a newer Stop.
        if (fixedShared is not null && (shared != fixedShared || protectedEpoch != fixedProtected))
            throw new Boundary("resume_state_changed");
        return (fixedShared ?? shared, fixedProtected ?? protectedEpoch);
    }
    internal static int AdminResumeSelfTest()
    {
        int assertions = 0;
        void Require(bool condition) { ++assertions; if (!condition) throw new Boundary("admin_resume_selftest_failed"); }
        void Reject(Action action, string code)
        {
            try { action(); }
            catch (Boundary error) { Require(error.Code == code); return; }
            throw new Boundary("admin_resume_selftest_failed");
        }
        using var document = JsonDocument.Parse("{\"global_stop_epoch\":1,\"protected_stop_epoch\":3}");
        var status = document.RootElement;
        Require(AdminResumeEpochs(status, 1, 3) == (1L, 3L));
        Require(AdminResumeEpochs(status) == (1L, 3L));
        Reject(() => AdminResumeEpochs(status, 0, 3), "resume_state_changed");
        Reject(() => AdminResumeEpochs(status, 1, 2), "resume_state_changed");
        Reject(() => AdminResumeEpochs(status, 1, null), "control_rejected");
        using var legacy = JsonDocument.Parse("{\"global_stop_epoch\":1}");
        Require(AdminResumeEpochs(legacy.RootElement) == (1L, (long?)null));
        Reject(() => AdminResumeEpochs(legacy.RootElement, 1, 3), "resume_state_changed");
        Require(Program.ParseAdminResumeEpochs(["--flower-admin", "resume", "0", long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture)]) == (0L, long.MaxValue));
        foreach (string invalid in new[] { "-1", "+1", " 1", "1 ", "", "1.0", "1e2", "9223372036854775808" })
        {
            Reject(() => Program.ParseAdminResumeEpochs(["--flower-admin", "resume", invalid, "1"]), "arguments_rejected");
            Reject(() => Program.ParseAdminResumeEpochs(["--flower-admin", "resume", "1", invalid]), "arguments_rejected");
        }
        Reject(() => Program.ParseAdminResumeEpochs(["--flower-admin", "status", "1", "3"]), "arguments_rejected");
        Reject(() => Program.ParseAdminResumeEpochs(["--flower-admin", "resume", "1", "3", "extra"]), "arguments_rejected");
        return assertions;
    }
    internal static int Admin(BrokerPolicy policy, string command, long? fixedSharedEpoch = null, long? fixedProtectedEpoch = null,
        MaintenanceBinding? maintenance = null, string? maintenanceOperation = null)
    {
        if (command is not ("status" or "pause" or "resume" or "shutdown" or "settings")) throw new Boundary("control_rejected");
        if ((fixedSharedEpoch is null) != (fixedProtectedEpoch is null) || fixedSharedEpoch < 0 || fixedProtectedEpoch < 0
            || command != "resume" && fixedSharedEpoch is not null) throw new Boundary("control_rejected");
        maintenance?.RequireValid(command);
        if (maintenanceOperation is not null && (command != "status" && maintenance is null))
            throw new Boundary("maintenance_writer_command_rejected");
        var parent = Native.Process(Environment.ProcessId).Identity;
        bool highPresent = BrokerPipe.Present(BrokerPipe.Name(parent)), ordinaryPresent = BrokerPipe.Present(BrokerPipe.OrdinaryName(parent));
        if (highPresent && ordinaryPresent) throw new Boundary("executor_role_ambiguous");
        bool ordinary = !highPresent && ordinaryPresent;
        if (ordinary && (maintenance is not null || command is not ("status" or "settings"))) throw new Boundary("ordinary_maintenance_requires_bound_writer");
        using var pipe = new NamedPipeClientStream(".", ordinary ? BrokerPipe.OrdinaryName(parent) : BrokerPipe.Name(parent), PipeDirection.InOut,
            PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
        pipe.ConnectAsync(1500).GetAwaiter().GetResult();
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var server)) throw new Boundary("server_identity_unavailable");
        var (peer, image) = Native.Process((int)server);
        if (peer.Integrity != (ordinary ? 8192 : 12288) || peer.User != parent.User || peer.Session != parent.Session
            || !image.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)
            || peer.ImageDigest != parent.ImageDigest) throw new Boundary("server_identity_mismatch");
        maintenance?.RequireProcess(peer.Pid, peer.Created, policy.Version);
        Protocol.Write(pipe, new ClientHello("hello", parent, "flower-admin", maintenanceOperation));
        using var hello = Protocol.Read(pipe, 3000);
        AdminHandshake.RequireHello(hello);
        if (maintenance is not null)
        {
            maintenance.RequireSnapshot(hello!.RootElement.GetProperty("Status"));
            // The exact connected server was checked before hello. A later
            // service replacement cannot take over this existing pipe handle.
            Protocol.Write(pipe, new MaintenanceCommand("maintenance", command, maintenance));
        }
        else
        {
        var (expectedEpoch, protectedEpoch) = command == "resume"
            ? AdminResumeEpochs(hello!.RootElement.GetProperty("Status"), fixedSharedEpoch, fixedProtectedEpoch)
            : ((long?)null, (long?)null);
        Protocol.Write(pipe, command == "status" ? new { Phase = "status" }
            : command == "settings" ? new { Phase = "open_settings" } : (object)new Control("control", command, expectedEpoch, protectedEpoch));
        }
        using var result = Protocol.Read(pipe, 3000);
        if (result is null) throw new Boundary("pipe_disconnected");
        Console.WriteLine(result.RootElement.GetRawText());
        return result.RootElement.TryGetProperty("Phase", out var phase) && phase.GetString() == "error" ? 2 : 0;
    }
    private sealed record ClientHello(string Phase, Peer Parent, string Channel,
        [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
        string? MaintenanceOperation = null);
    private sealed record Control(string Phase, string Command, long? ExpectedEpoch = null, long? ExpectedProtectedEpoch = null);
    private sealed record RequestQuery(string Phase, string TaskId, string ConnectionId, string LedgerIdentity);
    private sealed record MetadataQuery(string Phase, string TaskId, string ConnectionId, long DesktopRevision, Target Target);
    private sealed record RecoveryQuery(string Phase, string TaskId, string ActionId, string ExecutorProcess, string LedgerIdentity);
}
