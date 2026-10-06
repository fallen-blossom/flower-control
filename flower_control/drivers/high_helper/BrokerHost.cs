using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal static class BrokerHost
{
    internal static int Run(BrokerPolicy policy)
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        if (own.User != policy.UserSid || own.Integrity != (policy.Fixture ? 8192 : 12288) || Native.UiAccess(own.Pid))
            throw new Boundary("broker_user_integrity_rejected");
        using var singleton = new Mutex(false, "Local\\FlowerControl.HighBroker." + (policy.Fixture ? policy.FixturePipe : BrokerPipe.LogonSid()));
        bool owned;
        try { owned = singleton.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
        if (!owned) return 0;
        string? recoveryPath = null;
        if (!policy.Fixture)
        {
            var root = Path.GetFullPath(Path.Combine(policy.Directory, "..", "..", "recovery"));
            Directory.CreateDirectory(root);
            BrokerPolicy.RejectLinks(root);
            recoveryPath = Path.Combine(root, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(BrokerPipe.LogonSid()))).ToLowerInvariant() + ".json");
        }
        using var writeGate = new SharedWriteGate(policy.Fixture ? "fixture_" + own.Pid : null);
        var core = new BrokerState(recoveryPath, writeGate);
        var handlers = new ConcurrentDictionary<Task, byte>();
        var accept = Accept(policy, own, core, handlers);
        _ = accept.ContinueWith(failed => {
            if (failed.IsFaulted)
            {
                var error = failed.Exception!.GetBaseException();
                Console.Error.WriteLine(JsonSerializer.Serialize(new { reason = Program.Code(error), stage = "pipe_accept",
                    exception_type = error.GetType().Name, winerror = error is Boundary boundary ? boundary.NativeCode : null }));
                core.Fault(); core.Stop();
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
            var pipe = BrokerPipe.Create(policy.Fixture ? policy.FixturePipe : BrokerPipe.Name(own), first);
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
            var admission = ClientAdmission.Verify((int)pid, policy);
            using var first = Protocol.Read(pipe, 3000, core.Shutdown.Token);
            if (first is null) return;
            var hello = Protocol.Decode<ClientHello>(first);
            if (hello.Phase != "hello" || hello.Parent != admission.Peer
                || (policy.Fixture ? hello.Channel != "fixture" : admission.Admin ? hello.Channel != "flower-admin"
                    : hello.Channel is not ("flower-web" or "flower-app" or "flower-computer")))
                throw new Boundary("client_hello_rejected");
            var evidence = admission.Evidence with { Channel = hello.Channel };
            // Actual admitted host sources may recover terminal release metadata
            // across host restarts. No input or private grant is issued.
            var source = policy.Fixture ? own : Native.Process(admission.Evidence.SourcePid, digestImage: false).Identity;
            Protocol.Write(pipe, new { Phase = "hello", Helper = own, AssemblyDigest = Program.AssemblyDigest,
                Version = policy.Version, ConnectionId = connectionId, PeerEvidence = evidence, Status = core.Snapshot(policy, own) });
            while (!core.Shutdown.IsCancellationRequested)
            {
                using var message = Protocol.Read(pipe, int.MaxValue, core.Shutdown.Token);
                if (message is null) return; // This connection only; the singleton continues.
                Native.VerifyPeer(admission.Peer);
                if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out pid) || pid != admission.Peer.Pid)
                    throw new Boundary("client_identity_changed");
                if (Protocol.Phase(message, "status"))
                {
                    PollDesktop(core);
                    Protocol.Write(pipe, new { Phase = "status", Status = core.Snapshot(policy, own) });
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
                if (message.RootElement.TryGetProperty("Phase", out var phase) && phase.GetString() == "control")
                {
                    var control = Protocol.Decode<Control>(message);
                    if (!admission.Admin || control.Command is not ("pause" or "resume" or "shutdown")) throw new Boundary("control_rejected");
                    if (control.Command == "pause") core.Pause(true);
                    else if (control.Command == "resume")
                    {
                        if (control.ExpectedEpoch is null) throw new Boundary("resume_snapshot_required");
                        PollDesktop(core); core.Pause(false, control.ExpectedEpoch);
                    }
                    // Reply before closing the listeners on shutdown.
                    Protocol.Write(pipe, new { Phase = "control", Command = control.Command, Status = core.Snapshot(policy, own) });
                    if (control.Command == "shutdown") { core.Stop(); return; }
                    continue;
                }
                if (!policy.Fixture && admission.Admin) throw new Boundary("input_role_rejected");
                var prepare = Protocol.Decode<Prepare>(message);
                Protocol.Validate(prepare, policy.Fixture);
                if (prepare.Parent != admission.Peer || prepare.ConnectionId != connectionId
                    || !Regex.IsMatch(prepare.TaskId, "^[a-zA-Z0-9_-]{1,128}$")) throw new Boundary("request_binding_rejected");
                PollDesktop(core);
                core.CheckCapacity();
                var request = new BrokerRequest { Owner = admission.Peer, TaskId = prepare.TaskId };
                if (!core.Requests.TryAdd(connectionId, request)) throw new Boundary("connection_request_busy");
                Receipt receipt;
                try { receipt = Program.Request(pipe, prepare, own, policy.Fixture, core, request, policy); }
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
            try { Protocol.Write(pipe, new { Phase = "error", Reason = Program.Code(error) }); } catch { }
        }
        finally
        {
            pipe.Dispose();
            Interlocked.Decrement(ref core.Connections);
        }
    }
    internal static int Admin(BrokerPolicy policy, string command)
    {
        if (command is not ("status" or "pause" or "resume" or "shutdown")) throw new Boundary("control_rejected");
        var parent = Native.Process(Environment.ProcessId).Identity;
        using var pipe = new NamedPipeClientStream(".", BrokerPipe.Name(parent), PipeDirection.InOut,
            PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
        pipe.ConnectAsync(1500).GetAwaiter().GetResult();
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var server)) throw new Boundary("server_identity_unavailable");
        var (peer, image) = Native.Process((int)server);
        if (peer.Integrity != 12288 || peer.User != parent.User || peer.Session != parent.Session
            || !image.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)
            || peer.ImageDigest != parent.ImageDigest) throw new Boundary("server_identity_mismatch");
        Protocol.Write(pipe, new ClientHello("hello", parent, "flower-admin"));
        using var hello = Protocol.Read(pipe, 3000);
        if (hello is null || !hello.RootElement.TryGetProperty("Phase", out var phase) || phase.GetString() != "hello") throw new Boundary("hello_rejected");
        long? expectedEpoch = command == "resume"
            ? hello.RootElement.GetProperty("Status").GetProperty("global_stop_epoch").GetInt64() : null;
        Protocol.Write(pipe, command == "status" ? new { Phase = "status" } : (object)new Control("control", command, expectedEpoch));
        using var result = Protocol.Read(pipe, 3000);
        if (result is null) throw new Boundary("pipe_disconnected");
        Console.WriteLine(result.RootElement.GetRawText());
        return result.RootElement.TryGetProperty("Phase", out phase) && phase.GetString() == "error" ? 2 : 0;
    }
    private sealed record ClientHello(string Phase, Peer Parent, string Channel);
    private sealed record Control(string Phase, string Command, long? ExpectedEpoch = null);
    private sealed record RequestQuery(string Phase, string TaskId, string ConnectionId, string LedgerIdentity);
    private sealed record RecoveryQuery(string Phase, string TaskId, string ActionId, string ExecutorProcess, string LedgerIdentity);
}
