using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record LocalUiOperation(string Kind, string Revision, UserPermissionSettings? Submitted = null,
    bool PolicyChanged = false, string? Words = null, string? WordsRevision = null, string? Mode = null,
    string? ModeRevision = null, int? Tier = null, bool? ComputerPaused = null, RoleStopSnapshot? Stop = null);
internal sealed record LocalUiResult(UserPermissionSettings Current, SettingsUiPreference? Preference = null,
    SettingsWordSnapshot? Words = null, string? PreferenceError = null, string? WordError = null);
internal sealed record LocalUiQuery(string Phase, string Nonce, string? Digest = null, LocalUiResult? Result = null);
internal sealed record LocalUiOffer(string Phase, string Version, string Nonce, string Digest, LocalUiOperation Operation);

// Only a live native settings action can create this in-memory transaction.
// MCP, command-line payloads and files cannot supply a permission descriptor.
internal static class LocalUiWriter
{
    private sealed class Pending(string nonce, BrokerState core, LocalUiOperation operation, SettingsSurfaceHandoff? surface, CancellationToken cancellation)
    {
        internal readonly string Nonce = nonce, Digest = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(operation))).ToLowerInvariant();
        internal readonly BrokerState Core = core;
        internal readonly LocalUiOperation Operation = operation;
        internal readonly SettingsSurfaceHandoff? Surface = surface;
        internal readonly CancellationToken Cancellation = cancellation;
        internal readonly long Started = Environment.TickCount64;
        internal readonly TaskCompletionSource<LocalUiResult> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Peer? Writer;
        internal bool Taken;
        internal bool CommitStarted;
        internal string? Handoff;
    }
    private static Pending? pending;
    private static Pending? uncertain;
    internal static bool ExpectedPeer(Peer caller, BrokerState core)
    {
        var current = pending;
        if (current is null || !ReferenceEquals(current.Core, core) || Environment.TickCount64 - current.Started > 95000) return false;
        var clock = Stopwatch.StartNew();
        while (Volatile.Read(ref current.Writer) is null && clock.ElapsedMilliseconds < 1000) Thread.Yield();
        return Volatile.Read(ref current.Writer) == caller;
    }
    internal static LocalUiResult Execute(BrokerState core, LocalUiOperation operation, SettingsSurfaceHandoff? surface, CancellationToken cancellation)
    {
        if (!core.OrdinaryResident) throw new Boundary("local_writer_medium_source_required");
        var priorUnknown = Volatile.Read(ref uncertain);
        if (priorUnknown is not null)
        {
            if (priorUnknown.Writer is not { } oldWriter) throw new Boundary("local_writer_prior_outcome_unknown");
            try
            {
                using var process = Process.GetProcessById(oldWriter.Pid);
                if (!process.HasExited && process.StartTime.ToUniversalTime().ToFileTimeUtc() == oldWriter.Created)
                    throw new Boundary("local_writer_prior_outcome_unknown");
            }
            catch (ArgumentException) { }
            Interlocked.CompareExchange(ref uncertain, null, priorUnknown);
        }
        var caller = Native.Process(Environment.ProcessId).Identity;
        long expectedStopGeneration = core.LocalStopGeneration;
        operation = operation with { Stop = RoleHandoff.Stops(caller, core.WriteGate ?? throw new Boundary("write_gate_unavailable")) };
        Validate(operation);
        core.BeginLocalTransition(cancellation);
        var next = new Pending(Guid.NewGuid().ToString("N"), core, operation, surface, cancellation);
        if (Interlocked.CompareExchange(ref pending, next, null) is not null) { core.EndLocalTransition(); throw new Boundary("local_writer_busy"); }
        bool switched = false;
        try
        {
            var own = Native.Process(Environment.ProcessId).Identity;
            UserPermissions.RequireCurrentRevision(operation.Revision, UserPermissions.Read().Revision);
            cancellation.ThrowIfCancellationRequested();
            var start = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"))
                { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory, WindowStyle = ProcessWindowStyle.Normal };
            start.ArgumentList.Add("--local-ui-writer"); start.ArgumentList.Add(own.Pid.ToString()); start.ArgumentList.Add(own.Created.ToString()); start.ArgumentList.Add(next.Nonce);
            using var writer = Process.Start(start) ?? throw new Boundary("local_writer_start_failed");
            var writerPeer = Native.Process(writer.Id).Identity;
            NativeRoleIdentity.Require(writerPeer, BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false), 12288);
            if (writerPeer.Integrity != 12288 || writerPeer.User != own.User || writerPeer.Session != own.Session
                || writerPeer.ImageDigest != own.ImageDigest || Native.UiAccess(writerPeer.Pid)) throw new Boundary("local_writer_identity_rejected");
            Volatile.Write(ref next.Writer, writerPeer);
            while (!next.Completion.Task.Wait(30, cancellation))
            {
                if (Environment.TickCount64 - next.Started >= 90000) throw new Boundary("local_writer_outcome_unknown");
                if (writer.HasExited) throw new Boundary(UserPermissions.Read().Revision == operation.Revision
                    ? "local_writer_operation_failed" : "local_writer_outcome_unknown");
            }
            var result = next.Completion.Task.GetAwaiter().GetResult();
            if (next.Handoff is not null)
            {
                RoleHandoff.WaitReady(next.Handoff, cancellation); switched = true;
            }
            else
            {
                // A temporary settings writer must actually exit. It never
                // registers an input listener or acquires the execution lease.
                if (!writer.WaitForExit(5000)) throw new Boundary("local_writer_exit_unconfirmed");
                if (writer.ExitCode != 0) throw new Boundary("local_writer_outcome_unknown");
                if (operation.Kind == "resume_all") core.ConfirmBoundLocalResume(operation.Stop!, expectedStopGeneration);
            }
            return result;
        }
        catch (System.ComponentModel.Win32Exception error) when (error.NativeErrorCode == 1223)
        { throw new Boundary("local_writer_user_cancelled"); }
        catch (OperationCanceledException) when (next.CommitStarted)
        { Interlocked.CompareExchange(ref uncertain, next, null); throw new Boundary("local_writer_outcome_unknown"); }
        catch (Exception) when (next.CommitStarted && !next.Completion.Task.IsCompletedSuccessfully)
        { Interlocked.CompareExchange(ref uncertain, next, null); throw new Boundary("local_writer_outcome_unknown"); }
        finally
        {
            // Never terminate a writer whose commit may already be in flight.
            // If no handoff completed the old executor remains, at its actual
            // Medium token, and its protected read determines current policy.
            Interlocked.CompareExchange(ref pending, null, next);
            if (!switched && next.Handoff is not null) RoleHandoff.Cancel(next.Handoff);
            try { core.RefreshPermissions(); core.ReloadComputerPause(); }
            finally { if (!switched) core.EndLocalTransition(); }
        }
    }
    private static void Validate(LocalUiOperation operation)
    {
        if (operation.Revision.Length is < 1 or > 128 || operation.Kind is not ("save" or "tier" or "prepare" or "disable" or "semantic" or "computer_pause" or "resume_all"))
            throw new Boundary("local_ui_operation_rejected");
        if (operation.Kind == "save")
        {
            if (operation.Submitted is null || operation.Submitted.Revision != operation.Revision) throw new Boundary("local_ui_operation_rejected");
            UserPermissions.Validate(operation.Submitted);
            if (operation.Words is not null) { UserPermissions.ValidateSettingsWords(operation.Words); if (operation.WordsRevision is null) throw new Boundary("local_ui_operation_rejected"); }
            if (operation.Mode is not null && (operation.Mode is not ("allowlist" or "semantic") || operation.ModeRevision is null)) throw new Boundary("local_ui_operation_rejected");
        }
        if (operation.Kind == "tier" && operation.Tier is not (>= -1 and <= 3)) throw new Boundary("local_ui_operation_rejected");
        if (operation.Kind == "computer_pause" && operation.ComputerPaused is null) throw new Boundary("local_ui_operation_rejected");
        if (operation.Kind is "computer_pause" or "resume_all" && operation.Stop is null) throw new Boundary("local_ui_stop_snapshot_required");
    }
    internal static bool TryHandle(JsonDocument message, NamedPipeServerStream pipe, Peer caller, BrokerState core, string version)
    {
        if (!BrokerHost.StructuredPhase(message, "local_ui_get") && !BrokerHost.StructuredPhase(message, "local_ui_result")
            && !BrokerHost.StructuredPhase(message, "local_ui_preflight") && !BrokerHost.StructuredPhase(message, "local_ui_begin_commit")) return false;
        var query = Protocol.Decode<LocalUiQuery>(message);
        var current = pending;
        if (!core.OrdinaryResident || current is null || !ReferenceEquals(current.Core, core) || query.Nonce != current.Nonce
            || Environment.TickCount64 - current.Started > 95000) throw new Boundary("local_ui_transaction_rejected");
        var wait = Stopwatch.StartNew();
        while (current.Writer is null && wait.ElapsedMilliseconds < 1000) Thread.Yield();
        if (current.Writer != caller || caller.Integrity != 12288) throw new Boundary("local_ui_writer_rejected");
        Native.VerifyPeer(caller);
        if (query.Phase is "local_ui_preflight" or "local_ui_begin_commit")
        {
            lock (current)
            {
                if (current.Cancellation.IsCancellationRequested || !current.Taken || query.Digest != current.Digest)
                    throw new Boundary("local_ui_preflight_rejected");
                if (query.Phase == "local_ui_begin_commit")
                {
                    if (current.CommitStarted) throw new Boundary("local_ui_commit_already_started");
                    current.CommitStarted = true;
                }
                Protocol.Write(pipe, new { Phase = query.Phase }); return true;
            }
        }
        if (query.Phase == "local_ui_get")
        {
            lock (current)
            {
                if (current.Cancellation.IsCancellationRequested || current.Taken) throw new Boundary("local_ui_transaction_consumed");
                UserPermissions.RequireCurrentRevision(current.Operation.Revision, UserPermissions.Read().Revision);
                current.Taken = true;
            }
            Protocol.Write(pipe, new LocalUiOffer("local_ui_offer", version, current.Nonce, current.Digest, current.Operation)); return true;
        }
        if (!current.Taken || !current.CommitStarted || query.Digest != current.Digest || query.Result is null) throw new Boundary("local_ui_result_rejected");
        var actual = UserPermissions.Read();
        if (actual.Revision != query.Result.Current.Revision) throw new Boundary("local_ui_commit_unconfirmed");
        var result = query.Result with { Current = actual };
        if (UserPermissions.TierOf(actual) > 0 && current.Operation.Kind == "tier" && !current.Cancellation.IsCancellationRequested)
            current.Handoff = RoleHandoff.OfferExisting(core, caller, current.Surface, current.Cancellation);
        Protocol.Write(pipe, new { Phase = "local_ui_result", Handoff = current.Handoff });
        current.Completion.TrySetResult(result);
        return true;
    }
    internal static int Run(int sourcePid, long sourceCreated, string nonce)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(nonce, "^[a-f0-9]{32}$")) throw new Boundary("local_writer_arguments_rejected");
        var own = Native.Process(Environment.ProcessId).Identity; var source = Native.Process(sourcePid).Identity;
        if (own.Integrity != 12288 || source.Created != sourceCreated) throw new Boundary("local_writer_identity_rejected");
        using var pipe = RoleHandoff.Connect(own, source, "ordinary");
        Protocol.Write(pipe, new LocalUiQuery("local_ui_get", nonce));
        using var packet = Protocol.Read(pipe, 3000);
        if (packet is null) throw new Boundary("local_ui_offer_missing");
        var offer = Protocol.Decode<LocalUiOffer>(packet);
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        if (offer.Phase != "local_ui_offer" || offer.Nonce != nonce || offer.Version != policy.Version
            || offer.Digest != Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(offer.Operation))).ToLowerInvariant())
            throw new Boundary("local_ui_offer_rejected");
        Validate(offer.Operation);
        UserPermissions.RequireCurrentRevision(offer.Operation.Revision, UserPermissions.Read().Revision);
        // The source has frozen new work and confirmed actual old requests are
        // released before this descriptor can be issued. This empty core only
        // supplies existing local High storage functions, not cleanup evidence.
        using var gate = new SharedWriteGate();
        var storage = new BrokerState(writeGate: gate, protectedStop: true);
        using var operationStop = new CancellationTokenSource();
        void CheckLivePhase(string phase)
        {
            using var check = RoleHandoff.Connect(own, source, "ordinary");
            Protocol.Write(check, new LocalUiQuery(phase, nonce, offer.Digest));
            using var response = Protocol.Read(check, 3000);
            if (response?.RootElement.GetProperty("Phase").GetString() != phase) throw new Boundary("local_ui_source_cancelled");
        }
        void CheckLive() => CheckLivePhase("local_ui_preflight");
        using var watchingStop = new CancellationTokenSource();
        var watching = Task.Run(() =>
        {
            while (!watchingStop.Token.WaitHandle.WaitOne(100))
                try { CheckLive(); } catch { operationStop.Cancel(); return; }
        });
        LocalUiResult result;
        try { CheckLivePhase("local_ui_begin_commit"); result = Apply(offer.Operation, storage, operationStop.Token, CheckLive); }
        finally { watchingStop.Cancel(); watching.GetAwaiter().GetResult(); }
        Protocol.Write(pipe, new LocalUiQuery("local_ui_result", nonce, offer.Digest, result));
        using var reply = Protocol.Read(pipe, 3000);
        if (reply?.RootElement.GetProperty("Phase").GetString() != "local_ui_result") throw new Boundary("local_ui_result_unconfirmed");
        string? handoff = reply.RootElement.GetProperty("Handoff").GetString();
        pipe.Dispose();
        return handoff is null ? 0 : RoleHandoff.RunStaged(false, sourcePid, sourceCreated, handoff);
    }
    private static LocalUiResult Apply(LocalUiOperation operation, BrokerState storage, CancellationToken cancellation, Action check)
    {
        var prior = UserPermissions.Read();
        UserPermissions.RequireCurrentRevision(operation.Revision, prior.Revision);
        void Before() { cancellation.ThrowIfCancellationRequested(); check(); cancellation.ThrowIfCancellationRequested(); }
        Before();
        UserPermissionSettings current = prior; SettingsUiPreference? preference = null; SettingsWordSnapshot? words = null;
        string? prefError = null, wordError = null;
        switch (operation.Kind)
        {
            case "tier":
                var selected = UserPermissions.Effective(prior with { AuthorityTier = operation.Tier!.Value });
                if (operation.Tier == 3)
                {
                    Before(); UacInstallation.PrepareForTierSelection(cancellation);
                    if (!UacRuntime.Capabilities().AllowlistAvailable) throw new Boundary("uac_component_unavailable");
                }
                current = UacInstallation.SaveSettings(selected, storage, cancellation); break;
            case "save":
                if (operation.Submitted!.AuthorityTier != prior.AuthorityTier) throw new Boundary("tier_requires_local_selection");
                current = operation.PolicyChanged ? UacInstallation.SaveSettings(operation.Submitted, storage, cancellation) : prior;
                if (operation.Mode is not null)
                    try { Before(); preference = UserPermissions.SaveUiPreference(current.Revision, operation.ModeRevision!, operation.Mode, cancellation); }
                    catch (Exception error) { prefError = Program.Code(error); }
                if (operation.Words is not null)
                    try { Before(); words = UserPermissions.SaveSettingsWords(operation.Words, operation.WordsRevision!, current.Revision, cancellation); }
                    catch (Exception error) { wordError = Program.Code(error); }
                break;
            case "prepare": UacInstallation.PrepareForTierSelection(cancellation); break;
            case "disable": UacInstallation.Disable(); current = UserPermissions.Read(); break;
            case "semantic": current = UacInstallation.ConfirmSemanticDelegation(prior.Revision, storage, cancellation); break;
            case "computer_pause": storage.SetComputerPaused(operation.ComputerPaused!.Value, operation.Stop!.Computer.Epoch, operation.Stop.OrdinaryComputer); break;
            case "resume_all":
                var snapshot = operation.Stop ?? throw new Boundary("resume_snapshot_required");
                var shared = storage.WriteGate!;
                long epoch = shared.WithStableStatus(now =>
                {
                    if (now != snapshot.Shared) throw new Boundary("resume_state_changed");
                    return !now.Stopped && (snapshot.Protected.Stopped || snapshot.Ordinary.Stopped) ? shared.Stop(newStop: false).Epoch : now.Epoch;
                });
                storage.PauseWithOrdinaryStop(false, epoch, snapshot.Protected.Epoch, snapshot.Ordinary); break;
        }
        return new(current, preference, words, prefError, wordError);
    }
}
