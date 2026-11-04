using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Protocol 2 belongs only to the production Medium resident. Protocol 1 and
// its High reducer are deliberately unchanged.
internal sealed record OrdinaryMaintenanceBinding(
    [property: JsonRequired] string Version,
    [property: JsonRequired] int Pid,
    [property: JsonRequired] long Created,
    [property: JsonRequired] string PolicyRevision,
    [property: JsonRequired] int Tier,
    [property: JsonRequired] RoleStopSnapshot Stop,
    [property: JsonRequired] bool Paused,
    [property: JsonRequired] bool ComputerPaused)
{
    internal void RequireValid(string command)
    {
        if (Version is null || !Regex.IsMatch(Version, "\\A[a-f0-9]{32}\\z") || Pid <= 0 || Created <= 0
            || string.IsNullOrEmpty(PolicyRevision) || PolicyRevision.Length > 128 || PolicyRevision.Any(char.IsControl)
            || Tier is < -1 or > 0 || command is not ("pause" or "resume" or "shutdown")
            || Paused != (command != "pause")) throw new Boundary("maintenance_binding_invalid");
        RequireStop(Stop);
        if (Stop.Shared.Stopped != Paused || ComputerPaused != (Stop.Computer.Stopped || Stop.OrdinaryComputer.Stopped)
            || !Paused && (Stop.Protected.Stopped || Stop.Ordinary.Stopped))
            throw new Boundary("maintenance_binding_invalid");
        if (command == "pause" && (Stop.Shared.Epoch == long.MaxValue || Stop.Ordinary.Count == long.MaxValue)
            || command == "resume" && Stop.Protected.Epoch == long.MaxValue)
            throw new Boundary("stop_epoch_exhausted");
    }

    private static void RequireStop(RoleStopSnapshot? value)
    {
        if (value?.Shared is null || value.Protected is null || value.Computer is null
            || value.Ordinary is null || value.OrdinaryComputer is null
            || value.Shared.Epoch < 0 || value.Shared.ResumeAllEpoch < 0 || value.Shared.ResumeAllEpoch > value.Shared.Epoch
            || value.Protected.Schema != 1 || value.Computer.Schema != 1 || value.Protected.Session <= 0
            || value.Computer.Session != value.Protected.Session || value.Computer.UserSid != value.Protected.UserSid
            || value.Protected.UserSid is null || !Regex.IsMatch(value.Protected.UserSid, "\\AS-1-5-21-[0-9]+(?:-[0-9]+)*\\z")
            || value.Protected.Epoch < 0 || value.Computer.Epoch < 0
            || value.Ordinary.Count < 0 || value.Ordinary.Acknowledged < 0 || value.Ordinary.Acknowledged > value.Ordinary.Count
            || value.OrdinaryComputer.Count < 0 || value.OrdinaryComputer.Acknowledged < 0
            || value.OrdinaryComputer.Acknowledged > value.OrdinaryComputer.Count)
            throw new Boundary("maintenance_binding_invalid");
    }

    internal void RequireProcess(Peer own, BrokerPolicy policy)
    {
        if (own.Pid != Pid || own.Created != Created || policy.Version != Version)
            throw new Boundary("maintenance_instance_changed");
        if (own.User != policy.UserSid || own.User != Stop.Protected.UserSid || own.Session != Stop.Protected.Session
            || own.Integrity != 8192 || policy.Fixture)
            throw new Boundary("maintenance_role_rejected");
    }

    internal void RequirePolicy(UserPermissionSettings actual)
    {
        if (actual.Revision != PolicyRevision || UserPermissions.TierOf(actual) != Tier
            || actual.UserSid != Stop.Protected.UserSid) throw new Boundary("maintenance_state_changed");
    }

    internal static void Keys(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(names)
            || value.EnumerateObject().Count() != names.Length) throw new Boundary("maintenance_status_invalid");
    }

    private static RoleStopSnapshot DecodeStop(JsonElement value)
    {
        // The older role records have optional constructor defaults. Require
        // every nested wire field here, including false and zero values.
        Keys(value, "Shared", "Protected", "Computer", "Ordinary", "OrdinaryComputer");
        Keys(value.GetProperty("Shared"), "Stopped", "Epoch", "ResumeAllEpoch");
        foreach (string name in new[] { "Protected", "Computer" }) Keys(value.GetProperty(name), "Schema", "UserSid", "Session", "Stopped", "Epoch");
        foreach (string name in new[] { "Ordinary", "OrdinaryComputer" }) Keys(value.GetProperty(name), "Count", "Acknowledged");
        using var document = JsonDocument.Parse(value.GetRawText());
        var result = Protocol.Decode<RoleStopSnapshot>(document); RequireStop(result); return result;
    }

    internal static OrdinaryMaintenanceBinding Decode(JsonElement value)
    {
        Keys(value, "Version", "Pid", "Created", "PolicyRevision", "Tier", "Stop", "Paused", "ComputerPaused");
        _ = DecodeStop(value.GetProperty("Stop"));
        using var document = JsonDocument.Parse(value.GetRawText());
        return Protocol.Decode<OrdinaryMaintenanceBinding>(document);
    }

    internal void RequireSnapshot(JsonElement status, bool stopping = false)
    {
        if (status.ValueKind != JsonValueKind.Object) throw new Boundary("maintenance_status_invalid");
        long Number(string name)
        {
            if (!status.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long number))
                throw new Boundary("maintenance_status_invalid");
            return number;
        }
        bool Flag(string name)
        {
            if (!status.TryGetProperty(name, out var value) || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new Boundary("maintenance_status_invalid");
            return value.GetBoolean();
        }
        string Text(string name)
        {
            if (!status.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
                throw new Boundary("maintenance_status_invalid");
            return value.GetString()!;
        }
        if (Number("maintenance_protocol") != 2) throw new Boundary("maintenance_binding_unsupported");
        if (Text("broker_role") != "ordinary" || !Flag("ordinary_verified") || Flag("high_verified"))
            throw new Boundary("maintenance_role_rejected");
        if (Text("version") != Version || Number("pid") != Pid || Number("created") != Created)
            throw new Boundary("maintenance_instance_changed");
        if (Text("policy_revision") != PolicyRevision || Number("authority_tier") != Tier
            || Number("global_stop_epoch") != Stop.Shared.Epoch || Number("protected_stop_epoch") != Stop.Protected.Epoch
            || Flag("paused") != Paused || Flag("global_write_stopped") != Stop.Shared.Stopped
            || Flag("computer_paused") != ComputerPaused
            || !status.TryGetProperty("role_stop", out var roleStop) || DecodeStop(roleStop) != Stop)
            throw new Boundary("maintenance_state_changed");
        if (Flag("stopping") != stopping || Flag("release_fault") || Flag("role_transition")
            || Number("active_requests") != 0 || Number("pending_release_recoveries") != 0 || Number("maintenance_activities") != 0)
            throw new Boundary("maintenance_not_idle");
        foreach (string name in new[] { "stop_persistence_error", "computer_pause_persistence_error" })
            if (!status.TryGetProperty(name, out var error) || error.ValueKind != JsonValueKind.Null)
                throw new Boundary("maintenance_persistence_unconfirmed");
    }

    internal OrdinaryMaintenanceBinding AfterPause() => this with { Paused = true, Stop = Stop with {
        Shared = Stop.Shared with { Stopped = true, Epoch = checked(Stop.Shared.Epoch + 1) },
        Ordinary = Stop.Ordinary with { Count = checked(Stop.Ordinary.Count + 1) } } };

    internal OrdinaryMaintenanceBinding AfterResume() => this with { Paused = false, Stop = Stop with {
        Shared = Stop.Shared with { Stopped = false, ResumeAllEpoch = Stop.Shared.Epoch },
        Protected = Stop.Protected with { Stopped = false, Epoch = checked(Stop.Protected.Epoch + 1) },
        Ordinary = new(Stop.Ordinary.Count, Stop.Ordinary.Count) } };
}

internal sealed record OrdinaryMaintenanceCommand(
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string Command,
    [property: JsonRequired] OrdinaryMaintenanceBinding Expected)
{
    internal void RequireValid()
    {
        if (Phase != "maintenance_ordinary" || Expected is null) throw new Boundary("maintenance_binding_invalid");
        Expected.RequireValid(Command);
    }

    internal static OrdinaryMaintenanceCommand Decode(JsonDocument document)
    {
        Protocol.CheckUnique(document);
        var result = Protocol.Decode<OrdinaryMaintenanceCommand>(document);
        _ = OrdinaryMaintenanceBinding.Decode(document.RootElement.GetProperty("Expected"));
        result.RequireValid(); return result;
    }

    internal static OrdinaryMaintenanceCommand Parse(string[] args, string version)
    {
        if (args.Length != 3 || args[0] != "--flower-maintenance-ordinary" || args[2].Length is < 4 or > 32768)
            throw new Boundary("maintenance_binding_invalid");
        try
        {
            byte[] bytes = Convert.FromBase64String(args[2]);
            if (Convert.ToBase64String(bytes) != args[2]) throw new Boundary("maintenance_binding_invalid");
            using var document = JsonDocument.Parse(new UTF8Encoding(false, true).GetString(bytes));
            Protocol.CheckUnique(document);
            var result = new OrdinaryMaintenanceCommand("maintenance_ordinary", args[1], OrdinaryMaintenanceBinding.Decode(document.RootElement));
            result.RequireValid();
            if (result.Expected.Version != version) throw new Boundary("maintenance_instance_changed");
            return result;
        }
        catch (Exception error) when (error is FormatException or JsonException or DecoderFallbackException)
        { throw new Boundary("maintenance_binding_invalid"); }
    }
}

internal sealed record OrdinaryMaintenanceReady(
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string Nonce,
    [property: JsonRequired] OrdinaryMaintenanceBinding Expected);
internal sealed record OrdinaryMaintenanceCompleted(
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string Nonce,
    [property: JsonRequired] ProtectedStop.State Protected,
    [property: JsonRequired] OrdinaryStopState Ordinary);
internal sealed record OrdinaryMaintenanceReply(
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string Command,
    [property: JsonRequired] JsonElement Status);

internal static class OrdinaryMaintenance
{
    internal sealed record Authority(ProtectedStop.State Protected, OrdinaryStopState Ordinary,
        ProtectedStop.State Computer, OrdinaryStopState OrdinaryComputer);

    internal static void RequireNotError(JsonDocument document)
    {
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("Phase", out var phase)
            || phase.ValueKind != JsonValueKind.String) throw new Boundary("maintenance_result_unconfirmed");
        if (phase.GetString() != "error") return;
        if (root.TryGetProperty("Reason", out var reason) && reason.ValueKind == JsonValueKind.String
            && reason.GetString() is { } code && Regex.IsMatch(code, "\\A[a-z][a-z0-9_]{0,95}\\z")) throw new Boundary(code);
        throw new Boundary("maintenance_result_unconfirmed");
    }

    // Never acquire the shared mutex here: the Medium server deliberately
    // owns it throughout ready/completed. Only independent durable records.
    private static Authority ReadAuthority(Peer own) => new(ProtectedStop.Read(own.User, own.Session),
        OrdinaryStopJournal.Read(own.User, own.Session, forceAcknowledgement: true),
        ProtectedStop.ReadComputer(own.User, own.Session), OrdinaryStopJournal.Read(own.User, own.Session, true, true));

    internal static void RequireAuthority(RoleStopSnapshot expected, Authority actual)
    {
        if (actual.Protected != expected.Protected || actual.Ordinary != expected.Ordinary
            || actual.Computer != expected.Computer || actual.OrdinaryComputer != expected.OrdinaryComputer)
            throw new Boundary("maintenance_state_changed");
    }

    internal static void RequireCompleted(OrdinaryMaintenanceCompleted value, string nonce, OrdinaryMaintenanceBinding expected)
    {
        var after = expected.AfterResume();
        if (value.Phase != "maintenance_ordinary_completed" || value.Nonce != nonce
            || value.Protected != after.Stop.Protected || value.Ordinary != after.Stop.Ordinary)
            throw new Boundary("maintenance_resume_unconfirmed");
    }

    internal static OrdinaryMaintenanceCompleted DecodeCompleted(JsonDocument document)
    {
        var root = document.RootElement;
        OrdinaryMaintenanceBinding.Keys(root, "Phase", "Nonce", "Protected", "Ordinary");
        OrdinaryMaintenanceBinding.Keys(root.GetProperty("Protected"), "Schema", "UserSid", "Session", "Stopped", "Epoch");
        OrdinaryMaintenanceBinding.Keys(root.GetProperty("Ordinary"), "Count", "Acknowledged");
        return Protocol.Decode<OrdinaryMaintenanceCompleted>(document);
    }

    internal static int Client(BrokerPolicy policy, OrdinaryMaintenanceCommand command)
    {
        command.RequireValid();
        var own = Native.Process(Environment.ProcessId).Identity;
        if (policy.Fixture || own.Integrity != 12288) throw new Boundary("maintenance_local_high_required");
        NativeRoleIdentity.Require(own, policy, 12288);
        // Keep the original Codex/native-host ancestry admission. This is not
        // the UI writer's exceptional, nonce-bound flower-local-ui channel.
        if (!ClientAdmission.Verify(own.Pid, policy).Admin) throw new Boundary("maintenance_local_high_required");
        command.Expected.RequirePolicy(UserPermissions.Read());
        if (BrokerPipe.Present(BrokerPipe.Name(own))) throw new Boundary("executor_role_ambiguous");
        using var pipe = new NamedPipeClientStream(".", BrokerPipe.OrdinaryName(own), PipeDirection.InOut,
            PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
        pipe.ConnectAsync(1500).GetAwaiter().GetResult();
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid))
            throw new Boundary("server_identity_unavailable");
        var server = Native.Process((int)pid).Identity;
        NativeRoleIdentity.Require(server, policy, 8192);
        if (server.User != own.User || server.Session != own.Session || server.ImageDigest != own.ImageDigest)
            throw new Boundary("server_identity_mismatch");
        command.Expected.RequireProcess(server, policy);
        Protocol.Write(pipe, new { Phase = "hello", Parent = own, Channel = "flower-admin" });
        using var hello = Protocol.Read(pipe, 3000);
        AdminHandshake.RequireHello(hello);
        if (hello!.RootElement.GetProperty("Version").GetString() != policy.Version
            || hello.RootElement.GetProperty("AssemblyDigest").GetString() != Program.AssemblyDigest)
            throw new Boundary("server_identity_mismatch");
        command.Expected.RequireSnapshot(hello.RootElement.GetProperty("Status"));
        bool attemptedResume = false;
        try
        {
            Protocol.Write(pipe, command);
            if (command.Command == "resume")
            {
                using var readyDocument = Protocol.Read(pipe, 15000);
                if (readyDocument is null) throw new Boundary("maintenance_resume_unconfirmed");
                RequireNotError(readyDocument);
                var ready = Protocol.Decode<OrdinaryMaintenanceReady>(readyDocument);
                _ = OrdinaryMaintenanceBinding.Decode(readyDocument.RootElement.GetProperty("Expected"));
                if (ready.Phase != "maintenance_ordinary_ready" || ready.Expected != command.Expected
                    || ready.Nonce is null || !Regex.IsMatch(ready.Nonce, "\\A[a-f0-9]{32}\\z"))
                    throw new Boundary("maintenance_resume_unconfirmed");
                Native.VerifyPeer(server);
                command.Expected.RequirePolicy(UserPermissions.Read());
                RequireAuthority(command.Expected.Stop, ReadAuthority(own));
                // Set this before the first write: even an exception during
                // write/readback can leave running authority on disk.
                attemptedResume = true;
                ProtectedStop.Set(own.User, own.Session, false, command.Expected.Stop.Protected.Epoch);
                OrdinaryStopJournal.Acknowledge(own, command.Expected.Stop.Ordinary);
                var after = ReadAuthority(own);
                RequireAuthority(command.Expected.AfterResume().Stop, after);
                command.Expected.RequirePolicy(UserPermissions.Read());
                Protocol.Write(pipe, new OrdinaryMaintenanceCompleted("maintenance_ordinary_completed", ready.Nonce, after.Protected, after.Ordinary));
            }
            using var result = Protocol.Read(pipe, 15000);
            if (result is null) throw new Boundary("maintenance_result_unconfirmed");
            RequireNotError(result);
            var reply = Protocol.Decode<OrdinaryMaintenanceReply>(result);
            if (reply.Phase != "control" || reply.Command != command.Command) throw new Boundary("maintenance_result_unconfirmed");
            var afterBinding = command.Command switch { "pause" => command.Expected.AfterPause(), "resume" => command.Expected.AfterResume(), _ => command.Expected };
            afterBinding.RequireSnapshot(reply.Status, stopping: command.Command == "shutdown");
            if (command.Command == "resume")
            {
                Native.VerifyPeer(server);
                afterBinding.RequirePolicy(UserPermissions.Read());
                RequireAuthority(afterBinding.Stop, ReadAuthority(own));
            }
            Console.WriteLine(result.RootElement.GetRawText());
            return 0;
        }
        catch (Exception error) when (attemptedResume)
        {
            var failure = new Boundary("ordinary_maintenance_resume_outcome_unknown");
            failure.Data["OriginalReason"] = Program.Code(error);
            // No shared gate access, including during compensation. A new
            // protected Stop closes future admission in both execution roles.
            try { ProtectedStop.Set(own.User, own.Session, true); }
            catch (Exception compensation) { failure.Data["StopCompensationError"] = Program.Code(compensation); }
            throw failure;
        }
    }

    internal static void RequireCaller(NamedPipeServerStream pipe, BrokerPolicy policy, Peer own)
    {
        if (policy.Fixture || own.Integrity != 8192) throw new Boundary("maintenance_role_rejected");
        NativeRoleIdentity.Require(own, policy, 8192);
        if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid))
            throw new Boundary("client_identity_unavailable");
        var admission = ClientAdmission.Verify((int)pid, policy);
        if (!admission.Admin || admission.Peer.Integrity != 12288 || admission.Peer.User != own.User
            || admission.Peer.Session != own.Session) throw new Boundary("maintenance_local_high_required");
        NativeRoleIdentity.Require(admission.Peer, policy, 12288);
    }
}

internal sealed partial class BrokerState
{
    // Resume writes its own final response under the maintenance/shared locks.
    // The outer handler must not write a second response for that command.
    internal object MaintainOrdinary(string command, OrdinaryMaintenanceBinding expected, BrokerPolicy policy, Peer own,
        NamedPipeServerStream pipe)
    {
        expected.RequireValid(command); expected.RequireProcess(own, policy);
        OrdinaryMaintenance.RequireCaller(pipe, policy, own);
        if (!OrdinaryResident) throw new Boundary("maintenance_role_rejected");
        bool changed = false, failureLatched = false, shutdownPrepared = false;
        void CloseAfterFailure()
        {
            if (!changed || failureLatched) return;
            failureLatched = true;
            // An acknowledged maintenance Stop must never be the last durable
            // event after a failed resume. This also runs if releasing the
            // outer shared mutex fails after its callback already returned.
            try { Pause(true); }
            catch (Exception failure) { lock (gate) { paused = true; protectedStopError = Program.Code(failure); } }
            try { WriteGate?.Stop(newStop: false); }
            catch (Exception failure) { lock (gate) { paused = true; protectedStopError = Program.Code(failure); } }
        }
        try { return MaintenanceCommit(() =>
        {
            if (maintenanceActivities != 0) throw new Boundary("maintenance_not_idle");
            if (Volatile.Read(ref pendingStops) != 0) throw new Boundary("maintenance_state_changed");
            lock (stopMutationGate)
            lock (computerPauseGate)
            lock (gate)
            {
                if (localTransition || highRoleRevoked) throw new Boundary("maintenance_not_idle");
                var shared = WriteGate ?? throw new Boundary("maintenance_binding_unsupported");
                return shared.WithStableStatus(_ =>
                {
                    long generation = LocalStopGeneration;
                    void RequireUnchanged()
                    {
                        if (Volatile.Read(ref pendingStops) != 0 || LocalStopGeneration != generation)
                            throw new Boundary("maintenance_state_changed");
                    }
                    RequireUnchanged();
                    expected.RequirePolicy(UserPermissions.Read());
                    expected.RequireSnapshot(JsonSerializer.SerializeToElement(Snapshot(policy, own)));
                    if (command == "shutdown")
                    {
                        BeginMaintenanceShutdown();
                        shutdownPrepared = true;
                        try
                        {
                            RequireUnchanged();
                            var status = Snapshot(policy, own);
                            expected.RequireSnapshot(JsonSerializer.SerializeToElement(status), stopping: true);
                            RequireUnchanged(); return status;
                        }
                        catch { stopping = false; ++revision; throw; }
                    }
                    try
                    {
                        if (command == "pause")
                        {
                            changed = true; Pause(true);
                            generation = checked(generation + 1);
                            RequireUnchanged();
                            var status = Snapshot(policy, own);
                            expected.AfterPause().RequireSnapshot(JsonSerializer.SerializeToElement(status));
                            return status;
                        }
                        string nonce = Guid.NewGuid().ToString("N");
                        changed = true;
                        Protocol.Write(pipe, new OrdinaryMaintenanceReady("maintenance_ordinary_ready", nonce, expected));
                        using var completed = Protocol.Read(pipe, 15000, Shutdown.Token);
                        if (completed is null) throw new Boundary("maintenance_resume_unconfirmed");
                        OrdinaryMaintenance.RequireCaller(pipe, policy, own);
                        var value = OrdinaryMaintenance.DecodeCompleted(completed);
                        OrdinaryMaintenance.RequireCompleted(value, nonce, expected);
                        RequireUnchanged();
                        var after = expected.AfterResume();
                        expected.RequirePolicy(UserPermissions.Read());
                        var durable = RoleHandoff.Stops(own, shared);
                        OrdinaryMaintenance.RequireAuthority(after.Stop, new(durable.Protected, durable.Ordinary, durable.Computer, durable.OrdinaryComputer));
                        shared.Resume(expected.Stop.Shared.Epoch, () =>
                        {
                            RequireUnchanged();
                            expected.RequirePolicy(UserPermissions.Read());
                            var now = RoleHandoff.Stops(own, shared);
                            OrdinaryMaintenance.RequireAuthority(after.Stop, new(now.Protected, now.Ordinary, now.Computer, now.OrdinaryComputer));
                        });
                        ConfirmBoundLocalResumeState(expected.Stop, RoleHandoff.Stops(own, shared), generation);
                        RequireUnchanged();
                        var resumed = Snapshot(policy, own);
                        after.RequireSnapshot(JsonSerializer.SerializeToElement(resumed));
                        RequireUnchanged();
                        Protocol.Write(pipe, new { Phase = "control", Command = command, Status = resumed });
                        RequireUnchanged();
                        return resumed;
                    }
                    catch
                    {
                        CloseAfterFailure();
                        throw;
                    }
                });
            }
        }); }
        catch
        {
            // No shutdown reply has escaped this method. A shared-mutex
            // release failure must not strand an otherwise live resident in
            // an uncommitted stopping state.
            if (shutdownPrepared) lock (gate)
                if (!Shutdown.IsCancellationRequested) { stopping = false; ++revision; }
            CloseAfterFailure(); throw;
        }
    }
}
