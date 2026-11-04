using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record RoleStopSnapshot(SharedWriteGate.Status Shared, ProtectedStop.State Protected, ProtectedStop.State Computer,
    OrdinaryStopState Ordinary, OrdinaryStopState OrdinaryComputer);
internal sealed record RoleDurableStopSnapshot(ProtectedStop.State Protected, ProtectedStop.State Computer,
    OrdinaryStopState Ordinary, OrdinaryStopState OrdinaryComputer);
internal sealed record RoleOffer(string Phase, string Version, Peer Source, string Revision, int Tier,
    RoleStopSnapshot Stop, SettingsSurfaceHandoff? Surface);
internal sealed record RoleHandoffQuery(string Phase, string Nonce);

internal static class RoleHandoff
{
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(uint pid);
    internal static RoleDurableStopSnapshot ReadDurableBeforePreparation(Peer own) => new(
        ProtectedStop.Read(own.User, own.Session), ProtectedStop.ReadComputer(own.User, own.Session),
        OrdinaryStopJournal.ReadBeforePreparation(own.User, own.Session), OrdinaryStopJournal.ReadBeforePreparation(own.User, own.Session, true));
    private sealed record Pending(string Nonce, BrokerState Core, RoleOffer Offer, long Started, CancellationToken Cancellation)
    {
        internal Peer? Target;
        internal readonly TaskCompletionSource<bool> Ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    private static Pending? pending;
    internal static bool ExpectedPeer(Peer caller, BrokerState core)
    {
        var current = pending;
        if (current is null || !ReferenceEquals(current.Core, core) || Environment.TickCount64 - current.Started > 45000) return false;
        var clock = Stopwatch.StartNew();
        while (Volatile.Read(ref current.Target) is null && clock.ElapsedMilliseconds < 1000) Thread.Yield();
        return Volatile.Read(ref current.Target) == caller;
    }
    internal static RoleStopSnapshot Stops(Peer own, SharedWriteGate gate) => new(gate.Snapshot(),
        ProtectedStop.Read(own.User, own.Session), ProtectedStop.ReadComputer(own.User, own.Session),
        OrdinaryStopJournal.Read(own.User, own.Session, forceAcknowledgement: true), OrdinaryStopJournal.Read(own.User, own.Session, true, true));
    internal static string OfferExisting(BrokerState core, Peer target, SettingsSurfaceHandoff? surface, CancellationToken cancellation)
    {
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        var own = Native.Process(Environment.ProcessId).Identity;
        var saved = UserPermissions.Read();
        int tier = UserPermissions.TierOf(saved);
        NativeRoleIdentity.Require(target, policy, tier <= 0 ? 8192 : 12288);
        if (target.User != own.User || target.Session != own.Session || target.ImageDigest != own.ImageDigest
            || target.Integrity != (tier <= 0 ? 8192 : 12288) || target.Integrity == own.Integrity)
            throw new Boundary("role_handoff_target_rejected");
        var offer = new RoleOffer("role_handoff_offer", policy.Version, own, saved.Revision, tier,
            Stops(own, core.WriteGate ?? throw new Boundary("write_gate_unavailable")), surface);
        var next = new Pending(Guid.NewGuid().ToString("N"), core, offer, Environment.TickCount64, cancellation) { Target = target };
        if (Interlocked.CompareExchange(ref pending, next, null) is not null) throw new Boundary("role_handoff_busy");
        return next.Nonce;
    }
    internal static void ToOrdinary(BrokerState core, SettingsSurfaceHandoff? surface, CancellationToken cancellation)
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        var saved = UserPermissions.Read();
        if (own.Integrity != 12288 || UserPermissions.TierOf(saved) > 0 || saved.UacMode != "off" || saved.AdminLaunchEnabled)
            throw new Boundary("role_downgrade_policy_unconfirmed");
        // The target starts without a listener/lease and can only fetch this
        // one frozen handoff from the old, verified role.
        string nonce = Guid.NewGuid().ToString("N");
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        var offer = new RoleOffer("role_handoff_offer", policy.Version, own, saved.Revision, UserPermissions.TierOf(saved),
            Stops(own, core.WriteGate ?? throw new Boundary("write_gate_unavailable")), surface);
        var next = new Pending(nonce, core, offer, Environment.TickCount64, cancellation);
        if (Interlocked.CompareExchange(ref pending, next, null) is not null) throw new Boundary("role_handoff_busy");
        try
        {
            next.Target = BrowserProfileOpen.StartOrdinaryRole(["--serve-user-staging", own.Pid.ToString(), own.Created.ToString(), nonce]);
            next.Ready.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellation).GetAwaiter().GetResult();
        }
        catch { Interlocked.CompareExchange(ref pending, null, next); throw; }
    }
    internal static void Cancel(string nonce)
    {
        var current = pending;
        if (current?.Nonce == nonce) Interlocked.CompareExchange(ref pending, null, current);
    }
    internal static void WaitReady(string nonce, CancellationToken cancellation)
    {
        var current = pending;
        if (current is null || current.Nonce != nonce) throw new Boundary("role_handoff_missing");
        try { current.Ready.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellation).GetAwaiter().GetResult(); }
        catch { Interlocked.CompareExchange(ref pending, null, current); throw; }
    }
    internal static bool TryHandle(JsonDocument message, NamedPipeServerStream pipe, Peer caller, BrokerState core)
    {
        if (!BrokerHost.StructuredPhase(message, "role_handoff_get") && !BrokerHost.StructuredPhase(message, "role_handoff_ready")) return false;
        var query = Protocol.Decode<RoleHandoffQuery>(message);
        var current = pending;
        if (current is null || !ReferenceEquals(current.Core, core) || query.Nonce != current.Nonce
            || current.Cancellation.IsCancellationRequested || Environment.TickCount64 - current.Started > 45000) throw new Boundary("role_handoff_rejected");
        // StartOrdinaryRole can be in its final token/readback stage while the
        // resumed child reaches this pipe. Wait only for that exact target ID.
        var wait = Stopwatch.StartNew();
        while (current.Target is null && wait.ElapsedMilliseconds < 1000) Thread.Yield();
        if (current.Target != caller) throw new Boundary("role_handoff_peer_rejected");
        Native.VerifyPeer(caller);
        var own = Native.Process(Environment.ProcessId).Identity;
        if (UserPermissions.Read().Revision != current.Offer.Revision || Stops(own, core.WriteGate!) != current.Offer.Stop)
            throw new Boundary("role_handoff_state_changed");
        if (query.Phase == "role_handoff_get") { Protocol.Write(pipe, current.Offer); return true; }
        // Transfer only Windows foreground eligibility to the exact authenticated
        // successor; no input injection or general ASFW_ANY grant.
        if (current.Offer.Surface is not null) AllowSetForegroundWindow((uint)caller.Pid);
        Protocol.Write(pipe, new { Phase = "role_handoff_ready", Version = current.Offer.Version });
        current.Ready.TrySetResult(true);
        core.Stop(BrokerShutdownReason.AdminShutdown, caller);
        return true;
    }
    internal static NamedPipeClientStream Connect(Peer own, Peer source, string role)
    {
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        NativeRoleIdentity.Require(own, policy, own.Integrity);
        NativeRoleIdentity.Require(source, policy, role == "ordinary" ? 8192 : 12288);
        var pipe = new NamedPipeClientStream(".", role == "ordinary" ? BrokerPipe.OrdinaryName(own) : BrokerPipe.Name(own),
            PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
        try
        {
            pipe.ConnectAsync(1500).GetAwaiter().GetResult();
            if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid)
                || Native.Process((int)pid).Identity != source || source.User != own.User || source.Session != own.Session
                || source.ImageDigest != own.ImageDigest || source.Integrity != (role == "ordinary" ? 8192 : 12288) || Native.UiAccess(source.Pid))
                throw new Boundary("role_source_identity_rejected");
            Protocol.Write(pipe, new { Phase = "hello", Parent = own, Channel = "flower-local-ui" });
            using var hello = Protocol.Read(pipe, 3000); AdminHandshake.RequireHello(hello);
            if (hello!.RootElement.GetProperty("Version").GetString() != policy.Version
                || hello.RootElement.GetProperty("AssemblyDigest").GetString() != Program.AssemblyDigest)
                throw new Boundary("role_source_version_changed");
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
    }
    internal static int RunStaged(bool ordinary, int sourcePid, long sourceCreated, string nonce)
    {
        if (sourcePid <= 0 || sourceCreated <= 0 || !System.Text.RegularExpressions.Regex.IsMatch(nonce, "^[a-f0-9]{32}$"))
            throw new Boundary("role_handoff_arguments_rejected");
        var own = Native.Process(Environment.ProcessId).Identity;
        var source = Native.Process(sourcePid).Identity;
        if (source.Created != sourceCreated || own.Integrity != (ordinary ? 8192 : 12288)) throw new Boundary("role_token_rejected");
        using var sourceProcess = Process.GetProcessById(sourcePid);
        if (sourceProcess.StartTime.ToUniversalTime().ToFileTimeUtc() != sourceCreated) throw new Boundary("role_source_identity_rejected");
        using var pipe = Connect(own, source, ordinary ? "high" : "ordinary");
        Protocol.Write(pipe, new RoleHandoffQuery("role_handoff_get", nonce));
        using var offerDocument = Protocol.Read(pipe, 3000);
        if (offerDocument is null) throw new Boundary("role_handoff_offer_missing");
        var offer = Protocol.Decode<RoleOffer>(offerDocument);
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        using var gate = new SharedWriteGate();
        RequireOffer(offer, own, source, policy, gate, ordinary);
        // Persist only the editable surface before the source is allowed to
        // exit. Failure/version drift after ready must not discard its draft.
        if (offer.Surface is not null) RoleDraftRecovery.Preserve(policy, own, offer.Surface);
        Protocol.Write(pipe, new RoleHandoffQuery("role_handoff_ready", nonce));
        using var acknowledged = Protocol.Read(pipe, 3000);
        if (acknowledged?.RootElement.GetProperty("Phase").GetString() != "role_handoff_ready") throw new Boundary("role_handoff_unconfirmed");
        pipe.Dispose();
        if (!sourceProcess.WaitForExit(30000)) throw new Boundary("role_source_exit_unconfirmed");
        RequireOffer(offer, own, source, policy, gate, ordinary, allowLaterStop: true);
        if (offer.Surface is not null) SettingsWorkspace.QueueHandoff(offer.Surface);
        return BrokerHost.Run(policy, ordinary);
    }
    internal static bool ConservativeStopAdvance(RoleStopSnapshot before, RoleStopSnapshot after)
    {
        bool Durable(ProtectedStop.State a, ProtectedStop.State b) => a == b
            || a.Schema == b.Schema && a.UserSid == b.UserSid && a.Session == b.Session && b.Epoch > a.Epoch && b.Stopped;
        bool Append(OrdinaryStopState a, OrdinaryStopState b) => b.Count >= a.Count && b.Acknowledged == a.Acknowledged;
        bool shared = before.Shared == after.Shared || after.Shared.Stopped && after.Shared.Epoch > before.Shared.Epoch
            && after.Shared.ResumeAllEpoch == before.Shared.ResumeAllEpoch;
        return shared && Durable(before.Protected, after.Protected) && Durable(before.Computer, after.Computer)
            && Append(before.Ordinary, after.Ordinary) && Append(before.OrdinaryComputer, after.OrdinaryComputer);
    }
    private static void RequireOffer(RoleOffer offer, Peer own, Peer source, BrokerPolicy policy, SharedWriteGate gate, bool ordinary, bool allowLaterStop = false)
    {
        var current = UserPermissions.Read();
        if (offer.Phase != "role_handoff_offer" || offer.Version != policy.Version || offer.Source != source
            || offer.Revision != current.Revision || offer.Tier != UserPermissions.TierOf(current)
            || (offer.Tier <= 0) != ordinary)
            throw new Boundary("role_handoff_state_changed");
        var actual = Stops(own, gate);
        if (allowLaterStop ? !ConservativeStopAdvance(offer.Stop, actual) : actual != offer.Stop)
            throw new Boundary("role_handoff_state_changed");
    }
}
