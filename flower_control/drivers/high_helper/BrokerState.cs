using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed class BrokerRequest
{
    internal Peer? Owner;
    internal string TaskId = "", ActionId = "", LedgerIdentity = "";
    // Admitted hello channel; used to scope the daily Computer Use stop.
    internal string Channel = "";
    internal readonly CancellationTokenSource Stop = new();
    internal string? Reason;
    internal bool ReadOnly;
    internal bool Uac;
    internal bool AdminLaunch;
    internal bool IsComputerInput => Channel == "flower-computer" && !ReadOnly && !Uac && !AdminLaunch;
    internal string AdminLaunchRequestId { get; init; } = "";
    internal string AdminLaunchProgramRef { get; init; } = "";
    internal Peer? AdminLaunchCaller { get; init; }
    private readonly object adminLaunchCommitGate = new();
    private bool adminLaunchSubmitted;
    private bool adminLaunchWithdrawn;
    internal volatile bool AdminLaunchOwnsIntent;
    internal bool AdminLaunchWasWithdrawn { get { lock (adminLaunchCommitGate) return adminLaunchWithdrawn; } }
    // Kept for legacy recovery structures; retired UAC requests never set these.
    internal string? UacSessionHash = null;
    internal Action? UacLastPreflight = null;
    internal Action? AdminLaunchLastPreflight;
    private AdminLaunchFailure? adminLaunchFailure;
    internal AdminLaunchFailure? AdminLaunchFailure => Volatile.Read(ref adminLaunchFailure);
    internal void CaptureAdminLaunchFailure(Exception error, string stage, bool finishing = false)
    {
        // Diagnostics cannot become a prerequisite for cancellation/cleanup.
        try { Interlocked.CompareExchange(ref adminLaunchFailure, Flower.HighHelper.AdminLaunchFailure.Describe(error, stage, finishing), null); }
        catch { }
    }
    internal bool WithdrawAdminLaunch(string reason)
    {
        lock (adminLaunchCommitGate)
        {
            if (adminLaunchSubmitted) return false;
            adminLaunchWithdrawn = true;
            Cancel(reason);
            return true;
        }
    }
    internal T SubmitAdminLaunch<T>(Func<T> create)
    {
        lock (adminLaunchCommitGate)
        {
            if (Stop.IsCancellationRequested) throw new Boundary(Reason ?? "program_launch_task_cancelled");
            if (adminLaunchSubmitted) throw new Boundary("program_launch_original_status_required");
            // Withdrawal and submission are ordered on this exact request. A
            // withdrawal acknowledged first permanently excludes this callback.
            adminLaunchSubmitted = true;
        }
        // No journal/global gate is held during the short CreateProcess call.
        // A later cancel sees submitted, never promises withdrawal or kills it.
        return create();
    }
    internal void Cancel(string reason)
    {
        Interlocked.CompareExchange(ref Reason, reason, null);
        try { Stop.Cancel(); } catch (ObjectDisposedException) { } // Concurrent finished-request removal.
    }
}
internal sealed partial class BrokerState
{
    private readonly object gate = new();
    private readonly object maintenanceGate = new();
    private int maintenanceActivities;
    private int maintenanceIntent;
    private long maintenanceGeneration;
    internal IDisposable BeginMaintenanceActivity() => BeginMaintenanceActivityAt(Volatile.Read(ref maintenanceGeneration));
    private IDisposable BeginMaintenanceActivityAt(long generation)
    {
        var waiting = new SpinWait();
        while (true)
        {
            if (Volatile.Read(ref maintenanceIntent) != 0 || Volatile.Read(ref maintenanceGeneration) != generation)
                throw new Boundary("broker_maintenance_busy");
            if (Monitor.TryEnter(maintenanceGate)) break;
            // Ordinary registrations/releases hold only this short counter
            // lock. They may contend without being mistaken for maintenance.
            waiting.SpinOnce();
        }
        try
        {
            if (Volatile.Read(ref maintenanceIntent) != 0 || Volatile.Read(ref maintenanceGeneration) != generation)
                throw new Boundary("broker_maintenance_busy");
            if (Volatile.Read(ref pendingStops) != 0) throw new Boundary("broker_paused");
            if (Volatile.Read(ref stopping)) throw new Boundary("broker_stopping");
            ++maintenanceActivities;
            return new MaintenanceActivity(this);
        }
        finally { Monitor.Exit(maintenanceGate); }
    }
    private sealed class MaintenanceActivity(BrokerState owner) : IDisposable
    {
        private BrokerState? current = owner;
        public void Dispose()
        {
            var prior = Interlocked.Exchange(ref current, null);
            if (prior is not null) lock (prior.maintenanceGate) --prior.maintenanceActivities;
        }
    }
    internal void UnboundAdminControl(Action action)
    {
        // Keep legacy/manual controls, but they must not interleave with a
        // bound maintenance commit or new request registration.
        MaintenanceCommit(() => { action(); return true; });
    }
    private T MaintenanceCommit<T>(Func<T> commit)
    {
        // Publish before taking the counter lock, so requests never wait for
        // a resume and execute afterward as though newly submitted.
        if (Interlocked.CompareExchange(ref maintenanceIntent, 1, 0) != 0)
            throw new Boundary("broker_maintenance_busy");
        // Intent can return to zero before a descheduled request runs again.
        // The generation prevents that ABA from admitting an old arrival.
        Interlocked.Increment(ref maintenanceGeneration);
        try { lock (maintenanceGate) return commit(); }
        finally { Volatile.Write(ref maintenanceIntent, 0); }
    }
    internal object Maintain(MaintenanceCommand command, BrokerPolicy policy, Peer own)
    {
        command.RequireValid();
        command.Expected.RequireProcess(own.Pid, own.Created, policy.Version);
        // Pause(false) already takes stopMutationGate before its final gate.
        // SetComputerPaused takes computerPauseGate before gate. Never reverse
        // either order, nor acquire the shared mutex before gate.
        return MaintenanceCommit(() => {
        if (localTransition || highRoleRevoked) throw new Boundary("executor_transition_busy");
        if (maintenanceActivities != 0) throw new Boundary("maintenance_not_idle");
        if (Volatile.Read(ref pendingStops) != 0) throw new Boundary("maintenance_state_changed");
        lock (stopMutationGate)
        lock (computerPauseGate)
        lock (gate)
        {
            var shared = WriteGate ?? throw new Boundary("maintenance_binding_unsupported");
            return shared.WithStableStatus(_ =>
            {
                if (Volatile.Read(ref pendingStops) != 0) throw new Boundary("maintenance_state_changed");
                command.Expected.RequireSnapshot(JsonSerializer.SerializeToElement(Snapshot(policy, own)));
                if (command.Command == "pause") Pause(true);
                else if (command.Command == "resume") Pause(false, command.Expected.SharedEpoch, command.Expected.ProtectedEpoch);
                else BeginMaintenanceShutdown();
                if (Volatile.Read(ref pendingStops) != 0)
                {
                    if (command.Command == "resume")
                    {
                        // Pause(false)'s final check can precede this Stop's
                        // arrival. Close both channels before releasing the
                        // shared mutex; High-only lease rejection is not enough
                        // for the independent ordinary Python/System actors.
                        paused = true;
                        try
                        {
                            void Persist() { if (protectedStopOwner is { } owner) ProtectedStop.Set(owner.User, owner.Session, true); }
                            ProtectedStop.Latch(shared, Persist, newStop: false);
                        }
                        catch (Exception error) { protectedStopError = error.Data["ProtectedStopPersistenceError"] as string ?? Program.Code(error); }
                    }
                    // No shutdown response/Stop has escaped these locks yet.
                    // Withdraw only our uncommitted shutdown latch, leaving
                    // every Stop/epoch intact so the arriving Stop can finish.
                    if (command.Command == "shutdown") { stopping = false; ++revision; }
                    throw new Boundary("maintenance_state_changed");
                }
                return Snapshot(policy, own);
            });
        }
        });
    }
    // A fresh host also invalidates previous host observations; no grants live here.
    private long revision = DateTime.UtcNow.Ticks;
    private bool paused, unavailable, stopping, releaseFault;
    private BrokerShutdownNotice? shutdownNotice;
    private string? shutdownAuditError;
    private readonly Func<BrokerShutdownNotice, string?>? shutdownObserver;
    private readonly ManualResetEventSlim shutdownEvidenceFinished = new(false);
    internal BrokerShutdownNotice? ShutdownNotice { get { lock (gate) return shutdownNotice; } }
    internal string? ShutdownAuditError { get { lock (gate) return shutdownAuditError; } }
    internal void DrainShutdownEvidence() => shutdownEvidenceFinished.Wait();
    private bool computerPaused;
    private string? computerPauseError;
    private readonly object computerPauseGate = new();
    private string? desktopReason;
    private bool? trayAvailable;
    private bool? hotkeyAvailable;
    private string trayIconState = "not_loaded";
    internal void TrayVisualState(string value) { lock (gate) trayIconState = value; }
    private int? hotkeyError;
    internal readonly SharedWriteGate? WriteGate;
    // A production Medium executor is a separate role, never a fixture or a
    // High capability. The actual token is checked before its listener starts.
    internal bool OrdinaryResident { get; init; }
    private bool localTransition;
    private bool highRoleRevoked;
    internal void BeginLocalTransition(CancellationToken cancellation)
    {
        lock (gate)
        {
            if (stopping || localTransition) throw new Boundary("executor_transition_busy");
            localTransition = true; ++revision;
        }
        foreach (var request in Requests.Values) request.Cancel("executor_role_transition");
        var clock = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            while (Requests.Count != 0 || Volatile.Read(ref maintenanceActivities) != 0)
            {
                cancellation.ThrowIfCancellationRequested();
                if (clock.ElapsedMilliseconds >= 8000) throw new Boundary("executor_transition_release_pending");
                cancellation.WaitHandle.WaitOne(20);
            }
            lock (gate)
                if (releaseFault || completed.Values.Any(c => !c.Acknowledged))
                    throw new Boundary("executor_transition_recovery_required");
        }
        catch { EndLocalTransition(); throw; }
    }
    internal void EndLocalTransition() { lock (gate) { localTransition = false; ++revision; } }
    private readonly Peer? protectedStopOwner;
    private string? protectedStopError;
    private readonly object stopMutationGate = new();
    private long stopGeneration;
    private int pendingStops;
    internal long LocalStopGeneration => Interlocked.Read(ref stopGeneration);
    internal void HotkeyAvailable(bool value, int? error = null) { lock (gate) { hotkeyAvailable = value; hotkeyError = error; } }
    internal void TrayAvailable(bool value) { lock (gate) trayAvailable = value; }
    internal readonly CancellationTokenSource Shutdown = new();
    internal readonly ConcurrentDictionary<string, BrokerRequest> Requests = new();
    internal void CancelUacRequests(string reason)
    { foreach (var request in Requests.Values) if (request.Uac) request.Cancel(reason); }
    internal void CancelAdminLaunchRequests(string reason)
    { foreach (var request in Requests.Values) if (request.AdminLaunch) request.Cancel(reason); }
    // The daily stop ends the Computer Use run only: in-flight computer work is
    // cancelled and released, nothing durable is written, and the next call is
    // free to start a fresh run. App/Web and the UAC bridge are not touched.
    private readonly object computerRunGate = new();
    private long computerStopGeneration;
    internal long ComputerStopGeneration => Interlocked.Read(ref computerStopGeneration);
    internal void RegisterInputRequest(string key, BrokerRequest request, long observedGeneration, long? runGeneration = null)
    {
        lock (computerRunGate)
        {
            if (request.IsComputerInput && ComputerPaused) throw new Boundary("computer_paused");
            if (request.IsComputerInput && (observedGeneration != computerStopGeneration
                    || runGeneration is not null && runGeneration != computerStopGeneration))
                throw new Boundary("computer_stopped");
            if (!Requests.TryAdd(key, request)) throw new Boundary("connection_request_busy");
        }
    }
    internal void StopComputerUse()
    {
        BrokerRequest[] current;
        lock (computerRunGate)
        {
            ++computerStopGeneration;
            current = Requests.Values.Where(request => request.IsComputerInput).ToArray();
        }
        // Cancellation never retains the short admission lock. A prepare that
        // crossed this Stop is fenced; a later independent call is still new.
        foreach (var request in current) request.Cancel("computer_stopped");
    }
    internal bool ComputerPaused { get { lock (gate) return computerPaused; } }
    internal void SetComputerPaused(bool value, long? expectedComputerEpoch = null, OrdinaryStopState? expectedOrdinary = null)
    {
        lock (computerPauseGate)
        {
            lock (gate) if (stopping) throw new Boundary("broker_stopping");
            if (value) {
                lock (gate) computerPaused = true;
                CancelComputer();
            }
            try {
                if (protectedStopOwner is { } owner) {
                    if (owner.Integrity == 8192)
                    {
                        if (!value) throw new Boundary("computer_resume_local_high_required");
                        OrdinaryStopJournal.Append(owner, true);
                    }
                    else
                    {
                        var prior = ProtectedStop.ReadComputer(owner.User, owner.Session);
                        var ordinary = OrdinaryStopJournal.Read(owner.User, owner.Session, true, true);
                        if (!value && expectedOrdinary is not null && expectedOrdinary != ordinary) throw new Boundary("computer_pause_state_changed");
                        if (!value && expectedComputerEpoch is not null && prior.Epoch != expectedComputerEpoch) throw new Boundary("computer_pause_state_changed");
                        ProtectedStop.SetComputer(owner.User, owner.Session, value, value ? null : expectedComputerEpoch ?? prior.Epoch);
                        if (!value && ordinary.Stopped) OrdinaryStopJournal.Acknowledge(owner, ordinary, true);
                    }
                }
                lock (gate) { computerPaused = value; computerPauseError = null; }
                if (!value) ReloadComputerPause();
            }
            catch (Exception error) {
                lock (gate) { computerPaused = true; computerPauseError = Program.Code(error); }
                CancelComputer(); throw;
            }
        }
        void CancelComputer() {
            BrokerRequest[] current;
            lock (computerRunGate) {
                ++computerStopGeneration;
                current = Requests.Values.Where(request => request.IsComputerInput).ToArray();
            }
            foreach (var request in current) request.Cancel("computer_paused");
        }
    }
    internal void ReloadComputerPause()
    {
        if (protectedStopOwner is not { } owner) return;
        var current = ProtectedStop.ReadComputer(owner.User, owner.Session);
        bool stopped = current.Stopped || OrdinaryStopJournal.Read(owner.User, owner.Session, true, true).Stopped;
        lock (gate) { computerPaused = stopped; computerPauseError = null; }
        if (stopped) StopComputerUse();
    }
    internal (bool Found, bool Withdrawn, BrokerRequest[] Owners) WithdrawAdminLaunch(Peer caller, string taskId, string programRef, string requestId)
    {
        var matching = Requests.Values.Where(request => request.AdminLaunch && request.TaskId == taskId
            && request.AdminLaunchCaller == caller && request.AdminLaunchProgramRef == programRef
            && request.AdminLaunchRequestId == requestId).ToArray();
        bool withdrawn = matching.Length != 0;
        foreach (var request in matching)
            withdrawn &= request.WithdrawAdminLaunch("program_launch_task_cancelled");
        return (matching.Length != 0, withdrawn, matching);
    }
    internal sealed record Completion(Peer Owner, Peer Source, Peer Helper, string TaskId, string ActionId,
        string ConnectionId, string LedgerIdentity, string InputRelease, bool MutexReleased,
        bool? SemanticExecutorExited, bool NativeCountKnown, long Finished, bool Acknowledged = false,
        bool PhysicalInputFree = false);
    internal sealed record RecoverySnapshot(int Schema, Completion[] Pending);
    private readonly ConcurrentDictionary<string, Completion> completed = new();
    private readonly string? recoveryPath;
    internal BrokerState(string? recoveryPath = null, SharedWriteGate? writeGate = null, bool protectedStop = false,
        Func<BrokerShutdownNotice, string?>? shutdownObserver = null)
    {
        this.shutdownObserver = shutdownObserver;
        WriteGate = writeGate;
        if (protectedStop) {
            protectedStopOwner = Native.Process(Environment.ProcessId).Identity;
            try
            {
                computerPaused = ProtectedStop.ReadComputer(protectedStopOwner.User, protectedStopOwner.Session).Stopped
                    || OrdinaryStopJournal.Read(protectedStopOwner.User, protectedStopOwner.Session, true).Stopped;
                bool durableStop = ProtectedStop.Read(protectedStopOwner.User, protectedStopOwner.Session).Stopped
                    || OrdinaryStopJournal.Read(protectedStopOwner.User, protectedStopOwner.Session).Stopped;
                if (durableStop) { paused = true; WriteGate?.Stop(newStop: false); }
            }
            catch (Exception error) { computerPaused = true; computerPauseError = Program.Code(error); }
        }
        this.recoveryPath = recoveryPath;
        if (recoveryPath is null) return;
        BrokerPolicy.RejectLinks(Path.GetDirectoryName(recoveryPath)!);
        if (!File.Exists(recoveryPath)) return;
        BrokerPolicy.RejectLinks(recoveryPath);
        var bytes = File.ReadAllBytes(recoveryPath);
        if (bytes.Length > 16 * 1024 * 1024) throw new Boundary("recovery_journal_rejected");
        using var document = JsonDocument.Parse(bytes);
        Protocol.CheckUnique(document);
        var snapshot = Protocol.Decode<RecoverySnapshot>(document);
        if (snapshot.Schema != 1 || snapshot.Pending.Length > 4128) throw new Boundary("recovery_journal_rejected");
        foreach (var terminal in snapshot.Pending)
        {
            if (terminal.Acknowledged || !Regex.IsMatch(terminal.LedgerIdentity, "^[a-f0-9]{64}$")
                || !Regex.IsMatch(terminal.TaskId, "^[a-zA-Z0-9_-]{1,128}$")
                || terminal.ActionId.Length > 512 || terminal.ActionId.Any(char.IsControl)
                || terminal.InputRelease is not ("released" or "unknown" or "release_pending")
                || !completed.TryAdd(terminal.LedgerIdentity, terminal)) throw new Boundary("recovery_journal_rejected");
        }
    }
    private void Persist()
    {
        if (recoveryPath is null) return;
        var temporary = recoveryPath + ".new";
        if (File.Exists(temporary)) BrokerPolicy.RejectLinks(temporary);
        if (File.Exists(recoveryPath)) BrokerPolicy.RejectLinks(recoveryPath);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new RecoverySnapshot(1, completed.Values.Where(c => !c.Acknowledged).ToArray()));
        using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
        { stream.Write(bytes); stream.Flush(true); }
        File.Move(temporary, recoveryPath, true);
    }
    internal void CheckCapacity()
    {
        lock (gate) if (localTransition) throw new Boundary("executor_role_transition");
        lock (gate) if (completed.Values.Count(c => !c.Acknowledged) + Requests.Count >= 4096)
            throw new Boundary("pending_recovery_capacity");
    }
    internal void Completed(Peer owner, Receipt receipt, Peer? source = null, Peer? helper = null, string? actionId = null)
    {
        lock (gate)
        {
            completed[receipt.LedgerIdentity!] = new(owner, source ?? owner, helper ?? owner, receipt.TaskId,
                actionId ?? receipt.RequestBinding?.ActionId ?? "", receipt.ConnectionId, receipt.LedgerIdentity!,
                receipt.InputRelease, receipt.MutexReleased, receipt.SemanticExecutorExited, receipt.NativeCountKnown,
                DateTime.UtcNow.Ticks, PhysicalInputFree: IsPhysicalInputFree(receipt));
            Persist(); // Actual terminal cleanup is durable before Done is exposed.
            foreach (var key in completed.Where(p => p.Value.Acknowledged).OrderByDescending(p => p.Value.Finished)
                .Skip(256).Select(p => p.Key)) completed.TryRemove(key, out _);
        }
    }
    internal static bool IsPhysicalInputFree(Receipt receipt) => receipt.LayoutResult is not null
        && receipt.NativeCountKnown && receipt.RequestedEvents == 0 && receipt.SentEvents == 0
        && receipt.ActivationEvents == 0 && receipt.BusinessEvents == 0 && receipt.ImeEvents == 0
        && receipt.ReleaseEvents == 0 && !receipt.ActivationRequested && receipt.InputResult is null && receipt.AppResult is null;
    internal static bool InputReleased(Receipt receipt) => receipt.MutexReleased && receipt.InputRelease == "released"
        && (receipt.SemanticExecutorExited != false || IsPhysicalInputFree(receipt));
    private static object InputFreeMetadata(object value, bool free)
    {
        if (!free) return value; // Preserve ordinary reply fields exactly.
        var fields = JsonSerializer.SerializeToElement(value).EnumerateObject().ToDictionary(p => p.Name, p => (object)p.Value.Clone());
        fields["PhysicalInputFree"] = true;
        return fields;
    }
    internal static string ExecutorIdentity(Peer helper)
    {
        var instant = DateTime.FromFileTimeUtc(helper.Created);
        // Existing StateStore process_identity uses pywin32 GetProcessTimes,
        // whose SYSTEMTIME conversion has millisecond precision. Preserve that
        // exact persisted format; Peer.Created still retains raw FILETIME.
        var micros = (instant.Ticks % TimeSpan.TicksPerSecond) / TimeSpan.TicksPerMillisecond * 1000;
        return helper.Pid + ":" + instant.ToString("yyyy-MM-dd'T'HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture)
            + (micros == 0 ? "" : "." + micros.ToString("D6", System.Globalization.CultureInfo.InvariantCulture)) + "+00:00";
    }
    internal object RecoverRelease(Peer source, string taskId, string actionId, string executor, string ledger)
    {
        bool found = completed.TryGetValue(ledger, out var terminal)
            && terminal.Source.User == source.User && terminal.Source.Session == source.Session
            && terminal.TaskId == taskId && (terminal.ActionId == actionId || terminal.ActionId == "")
            && ExecutorIdentity(terminal.Helper) == executor;
        return InputFreeMetadata(new { Phase = "release_recovery", TaskId = taskId, ActionId = actionId, ExecutorProcess = executor,
            LedgerIdentity = ledger, State = found ? "finished" : "unknown",
            InputRelease = found ? terminal!.InputRelease : "unknown", MutexReleased = found && terminal!.MutexReleased,
            SemanticExecutorExited = found ? terminal!.SemanticExecutorExited : null, NativeCountKnown = found && terminal!.NativeCountKnown },
            found && terminal!.PhysicalInputFree);
    }
    internal void Acknowledge(Peer owner, string ledger)
    {
        lock (gate)
        {
            if (!completed.TryGetValue(ledger, out var terminal) || terminal.Owner != owner) throw new Boundary("ack_rejected");
            completed[ledger] = terminal with { Acknowledged = true };
            Persist();
        }
    }
    internal void AcknowledgeRecovery(Peer source, string taskId, string actionId, string executor, string ledger)
    {
        lock (gate)
        {
            if (!completed.TryGetValue(ledger, out var terminal) || terminal.Source.User != source.User || terminal.Source.Session != source.Session
                || terminal.TaskId != taskId || terminal.ActionId != "" && terminal.ActionId != actionId
                || ExecutorIdentity(terminal.Helper) != executor || terminal.InputRelease != "released"
                || !terminal.MutexReleased || !terminal.NativeCountKnown || terminal.SemanticExecutorExited == false && !terminal.PhysicalInputFree)
                throw new Boundary("release_recovery_unconfirmed");
            completed[ledger] = terminal with { Acknowledged = true };
            Persist();
        }
    }
    internal object RequestStatus(Peer owner, string taskId, string connectionId, string ledger)
    {
        if (completed.TryGetValue(ledger, out var terminal) && terminal.Owner == owner
            && terminal.TaskId == taskId && terminal.ConnectionId == connectionId)
            return InputFreeMetadata(new { Phase = "request_status", TaskId = taskId, ConnectionId = connectionId, LedgerIdentity = ledger,
                State = "finished", InputRelease = terminal.InputRelease, MutexReleased = terminal.MutexReleased,
                SemanticExecutorExited = terminal.SemanticExecutorExited }, terminal.PhysicalInputFree);
        bool active = Requests.TryGetValue(connectionId, out var request) && request.Owner == owner
            && request.TaskId == taskId && request.LedgerIdentity == ledger;
        return new { Phase = "request_status", TaskId = taskId, ConnectionId = connectionId, LedgerIdentity = ledger,
            State = active ? "active" : "unknown", InputRelease = "unknown", MutexReleased = false,
            SemanticExecutorExited = (bool?)null };
    }
    internal int Connections;
    internal long Revision { get { lock (gate) return revision; } }
    internal bool IsPaused { get { lock (gate) return paused || localTransition || highRoleRevoked || Volatile.Read(ref pendingStops) != 0 || ProtectedPaused() || WriteGate?.Snapshot().Stopped == true; } }
    internal bool HasRecoverableGlobalStop
    {
        get
        {
            lock (gate)
            {
                if (WriteGate?.Snapshot().Stopped == true) return true;
                if (protectedStopOwner is not { } owner) return false;
                try { return ProtectedStop.Read(owner.User, owner.Session).Stopped || OrdinaryStopJournal.Read(owner.User, owner.Session).Stopped; }
                catch (Exception error) { protectedStopError = Program.Code(error); return false; }
            }
        }
    }
    internal bool TrayFaulted { get { lock (gate) return releaseFault || protectedStopError is not null || hotkeyAvailable == false; } }
    internal bool TrayUnavailable { get { lock (gate) return stopping || unavailable; } }
    private bool ProtectedPaused()
    {
        if (protectedStopOwner is not { } owner) return false;
        try { return ProtectedStop.Read(owner.User, owner.Session).Stopped || OrdinaryStopJournal.Read(owner.User, owner.Session).Stopped; }
        catch (Exception error) { protectedStopError = Program.Code(error); return true; }
    }
    internal long? ProtectedStopEpoch
    {
        get
        {
            if (protectedStopOwner is not { } owner) return null;
            try { return ProtectedStop.Read(owner.User, owner.Session).Epoch; }
            catch (Exception error) { protectedStopError = Program.Code(error); return null; }
        }
    }
    internal bool IsFault { get { lock (gate) return releaseFault; } }
    internal void CheckUac(bool write = true)
    {
        RefreshPermissions();
        lock (gate)
        {
            if (stopping || Shutdown.IsCancellationRequested) throw new Boundary("broker_stopping");
            if (write && releaseFault) throw new Boundary("broker_release_fault");
            if (paused || Volatile.Read(ref pendingStops) != 0) throw new Boundary("broker_paused");
            if (ProtectedPaused() || WriteGate?.Snapshot().Stopped == true) throw new Boundary("global_write_stopped");
            // Winlogon is checked by the dedicated SYSTEM actor. Ordinary
            // Check()/Native.Desktop() still require Default and stay unchanged.
        }
    }
    internal string Summary { get { lock (gate) return stopping ? "正在退出" : releaseFault ? "释放未确认，输入已停用" : unavailable ? "桌面锁定或不可用" : IsPaused ? "全部写入已停止" : hotkeyAvailable == false ? "运行中；停止热键注册失败" : "运行中"; } }
    internal void Check(long expected, bool write = true)
    {
        RefreshPermissions();
        CheckInputWait(expected, write);
    }
    // No input is dispatched by a timer wait. Keep every original durable,
    // shared and in-memory Stop/state check live without re-parsing the same
    // policy at a 4 ms timer cadence. Every dispatch still calls Check(), and
    // held-input waits retain their full preflight at least every 80 ms.
    internal void CheckInputWait(long expected, bool write = true)
    {
        lock (gate)
        {
            if (stopping) throw new Boundary("broker_stopping");
            if (localTransition) throw new Boundary("executor_role_transition");
            if (highRoleRevoked) throw new Boundary("high_role_not_selected");
            if (write && releaseFault) throw new Boundary("broker_release_fault");
            if (write && (paused || Volatile.Read(ref pendingStops) != 0)) throw new Boundary("broker_paused");
            if (write && (ProtectedPaused() || WriteGate?.Snapshot().Stopped == true)) throw new Boundary("global_write_stopped");
            if (unavailable) throw new Boundary(desktopReason ?? "desktop_locked");
            if (expected != revision) throw new Boundary("fresh_broker_observation_required");
        }
    }
    private string policyRevision = UserPermissions.Revision;
    internal void RefreshPermissions()
    {
        string current; bool revoked;
        try
        {
            var value = UserPermissions.Read(); current = value.Revision;
            revoked = protectedStopOwner?.Integrity == 12288 && !OrdinaryResident && UserPermissions.TierOf(value) <= 0;
        }
        catch (Boundary error) { current = "invalid:" + error.Code; revoked = protectedStopOwner?.Integrity == 12288 && !OrdinaryResident; }
        lock (gate)
        {
            highRoleRevoked = revoked;
            if (current == policyRevision) return;
            policyRevision = current; ++revision;
        }
        foreach (var request in Requests.Values) request.Cancel("user_policy_changed");
    }
    internal void Desktop(bool available, string? reason = null)
    {
        bool changed;
        lock (gate)
        {
            changed = unavailable == available;
            if (!changed) return;
            unavailable = !available; desktopReason = available ? null : reason; ++revision;
        }
        if (!available) foreach (var request in Requests.Values) request.Cancel(reason ?? "desktop_locked");
    }
    internal void Pause(bool value, long? expectedEpoch = null, long? expectedProtectedEpoch = null)
        => PauseWithOrdinaryStop(value, expectedEpoch, expectedProtectedEpoch, null);
    internal void PauseWithOrdinaryStop(bool value, long? expectedEpoch, long? expectedProtectedEpoch, OrdinaryStopState? expectedOrdinary)
    {
        // Stop takes effect in memory before disk or cross-process operations.
        if (value)
        {
            // Visible even while a maintenance commit owns gate/shared locks.
            // No new request lease or resume may outrun this arriving Stop.
            Interlocked.Increment(ref pendingStops); Interlocked.Increment(ref stopGeneration);
            try
            {
                lock (gate)
                {
                    if (WriteGate is null && !paused) ++revision;
                    paused = true;
                }
                foreach (var request in Requests.Values.Where(r => !r.ReadOnly)) request.Cancel("broker_paused");
                Exception? ordinaryPersistenceFailure = null;
                if (protectedStopOwner is { Integrity: 8192 } ordinaryOwner)
                {
                    // A maintenance transaction may hold the coordination
                    // locks while a High writer acknowledges an older Stop.
                    // Persist this new Medium Stop before waiting for those
                    // locks so the writer's exact-count CAS cannot erase it.
                    try { OrdinaryStopJournal.Append(ordinaryOwner); }
                    catch (Exception error)
                    { ordinaryPersistenceFailure = error; Volatile.Write(ref protectedStopError, Program.Code(error)); }
                }
                lock (stopMutationGate)
                {
                    try
                    {
                        void Persist()
                        {
                            if (protectedStopOwner is not { } stopOwner) return;
                            if (stopOwner.Integrity == 8192)
                            { if (ordinaryPersistenceFailure is not null) throw ordinaryPersistenceFailure; }
                            else ProtectedStop.Set(stopOwner.User, stopOwner.Session, true);
                        }
                        if (WriteGate is { } shared) ProtectedStop.Latch(shared, Persist);
                        else Persist();
                    }
                    catch (Exception error) { protectedStopError = error.Data["ProtectedStopPersistenceError"] as string ?? Program.Code(error); }
                }
            }
            finally { Interlocked.Decrement(ref pendingStops); }
            return;
        }
        lock (stopMutationGate)
        {
            long generation = Interlocked.Read(ref stopGeneration);
            bool NewStop() => Volatile.Read(ref pendingStops) != 0 || Interlocked.Read(ref stopGeneration) != generation;
            bool authorityResumeAttempted = false;
            void RestoreAuthority(Exception error)
            {
                if (!authorityResumeAttempted || protectedStopOwner is not { } owner) return;
                try { ProtectedStop.Set(owner.User, owner.Session, true); authorityResumeAttempted = false; }
                catch (Exception compensation) { error.Data["StopCompensationError"] = Program.Code(compensation); }
            }
            void AuthorizeResume()
            {
                if (NewStop()) throw new Boundary("resume_state_changed");
                if (protectedStopOwner is { } resumeOwner)
                {
                    try
                    {
                        var ordinary = OrdinaryStopJournal.Read(resumeOwner.User, resumeOwner.Session, forceAcknowledgement: true);
                        if (ordinary.Stopped && expectedOrdinary is null) throw new Boundary("ordinary_stop_snapshot_required");
                        if (expectedOrdinary is not null && expectedOrdinary != ordinary) throw new Boundary("resume_state_changed");
                        authorityResumeAttempted = true;
                        ProtectedStop.Set(resumeOwner.User, resumeOwner.Session, false, expectedProtectedEpoch);
                        if (expectedOrdinary?.Stopped == true) OrdinaryStopJournal.Acknowledge(resumeOwner, expectedOrdinary);
                        if (NewStop()) throw new Boundary("resume_state_changed");
                    }
                    catch (Exception error)
                    {
                        // A failed post-write read can leave a running record.
                        // Reassert Stop before releasing the shared mutex; a
                        // failed compensation remains explicit and RAM stays shut.
                        if (error is Boundary { Code: "resume_state_changed" } && !NewStop()) authorityResumeAttempted = false;
                        else RestoreAuthority(error);
                        throw;
                    }
                }
                else if (NewStop()) throw new Boundary("resume_state_changed");
            }
            if (NewStop()) throw new Boundary("resume_state_changed");
            try
            {
                if (WriteGate is { } shared) shared.Resume(expectedEpoch, AuthorizeResume);
                else AuthorizeResume();
            }
            catch (Exception error)
            {
                lock (gate) paused = true;
                // The shared gate can also fail after its authority callback
                // returned (for example during final readback or mutex release).
                RestoreAuthority(error);
                try { WriteGate?.Stop(newStop: false); }
                catch (Exception compensation) { error.Data["SharedStopCompensationError"] = Program.Code(compensation); }
                if (error.Data["StopCompensationError"] is string compensationError) protectedStopError = compensationError;
                else if (error.Data["SharedStopCompensationError"] is string sharedError) protectedStopError = sharedError;
                else if (error is not Boundary { Code: "resume_state_changed" }) protectedStopError = Program.Code(error);
                throw;
            }
            bool superseded;
            lock (gate)
            {
                superseded = NewStop();
                if (!superseded)
                {
                    protectedStopError = null;
                    if (paused) { paused = false; if (WriteGate is null) ++revision; }
                }
            }
            if (superseded)
            {
                // A Stop may arrive just after the lock-internal callback.
                // Keep its RAM latch and close the hint before allowing its
                // queued durable write to run; this is not another Stop event.
                try { WriteGate?.Stop(newStop: false); }
                catch (Exception error) { protectedStopError = Program.Code(error); }
                throw new Boundary("resume_state_changed");
            }
        }
    }
    internal static bool RequiresSharedStopLatch(bool sharedStopped, bool protectedStopped)
        => !sharedStopped && protectedStopped;
    internal bool ResumeGlobalFromLocalUser()
    {
        var shared = WriteGate ?? throw new Boundary("global_resume_unavailable");
        var current = shared.Snapshot();
        long? protectedEpoch = null;
        var protectedStopped = false;
        if (protectedStopOwner is { } owner)
        {
            var protectedStop = ProtectedStop.Read(owner.User, owner.Session);
            protectedEpoch = protectedStop.Epoch;
            protectedStopped = protectedStop.Stopped;
        }
        var ordinaryStop = protectedStopOwner is { } ordinaryOwner
            ? OrdinaryStopJournal.Read(ordinaryOwner.User, ordinaryOwner.Session, forceAcknowledgement: true) : null;
        bool durableStopped = protectedStopped || ordinaryStop?.Stopped == true;
        if (!current.Stopped && !durableStopped && !IsPaused) return false;
        // A process restart can reinitialize the shared mapping while the
        // durable protected record remains stopped. Close the coordination
        // gate first, then clear both epochs through the ordinary double-CAS.
        if (RequiresSharedStopLatch(current.Stopped, durableStopped)) current = shared.Stop(newStop: false);
        PauseWithOrdinaryStop(false, current.Epoch, protectedEpoch, ordinaryStop);
        if (IsPaused) throw new Boundary("global_resume_unconfirmed");
        return true;
    }
    internal static bool IsBoundGlobalResume(RoleStopSnapshot before, RoleStopSnapshot after)
    {
        long epoch = checked(before.Shared.Epoch + (!before.Shared.Stopped && (before.Protected.Stopped || before.Ordinary.Stopped) ? 1 : 0));
        return after.Shared == new SharedWriteGate.Status(false, epoch, epoch)
            && after.Protected == before.Protected with { Stopped = false, Epoch = checked(before.Protected.Epoch + 1) }
            && after.Ordinary == new OrdinaryStopState(before.Ordinary.Count, before.Ordinary.Count);
    }
    internal void ConfirmBoundLocalResume(RoleStopSnapshot before, long expectedGeneration)
    {
        if (!OrdinaryResident || protectedStopOwner is not { } owner || WriteGate is null)
            throw new Boundary("local_resume_source_rejected");
        lock (stopMutationGate)
        {
            ConfirmBoundLocalResumeState(before, RoleHandoff.Stops(owner, WriteGate), expectedGeneration);
        }
    }
    internal void ConfirmBoundLocalResumeState(RoleStopSnapshot before, RoleStopSnapshot after, long expectedGeneration)
    {
        if (!OrdinaryResident) throw new Boundary("local_resume_source_rejected");
        lock (stopMutationGate)
        {
            bool Changed() => Volatile.Read(ref pendingStops) != 0 || LocalStopGeneration != expectedGeneration;
            if (Changed() || !IsBoundGlobalResume(before, after)) throw new Boundary("resume_state_changed");
            lock (gate)
            {
                if (Changed()) throw new Boundary("resume_state_changed");
                // Only the confirmed, exact High writer completion can drop
                // this Medium process's old RAM latch. Reading running bytes
                // during a later unrelated request never clears it.
                paused = false; protectedStopError = null; ++revision;
            }
        }
    }
    internal void Fault()
    {
        lock (gate) { releaseFault = true; ++revision; }
        foreach (var request in Requests.Values) request.Cancel("broker_release_fault");
    }
    internal void Stop(BrokerShutdownReason reason = BrokerShutdownReason.RunCleanup, Peer? caller = null)
    {
        BrokerShutdownNotice? first = null;
        lock (gate) {
            stopping = true; ++revision;
            if (shutdownNotice is null) shutdownNotice = first = new(reason,
                DateTimeOffset.UtcNow.ToString("O"), Environment.CurrentManagedThreadId, caller?.Pid, caller?.Created);
        }
        try
        {
            foreach (var request in Requests.Values) request.Cancel("broker_stopping");
            Shutdown.Cancel();
        }
        finally
        {
            if (first is not null)
            {
                try
                {
                    string? error;
                    try { error = shutdownObserver?.Invoke(first); }
                    catch (Exception failure) { error = Program.Code(failure); }
                    lock (gate) shutdownAuditError = error;
                }
                finally { shutdownEvidenceFinished.Set(); }
            }
        }
    }
    internal void BeginMaintenanceShutdown()
    {
        lock (computerPauseGate)
        {
            lock (gate) {
                if (computerPauseError is not null) throw new Boundary("computer_pause_persistence_unconfirmed");
                stopping = true; ++revision;
            }
        }
    }
    internal object Snapshot(BrokerPolicy policy, Peer own) { lock (gate) {
        var writeStatus = WriteGate?.Snapshot();
        var ordinaryPolicy = !policy.Fixture && protectedStopOwner is not null ? UserPermissions.Read() : null;
        var roleStop = ordinaryPolicy is not null && WriteGate is not null ? RoleHandoff.Stops(own, WriteGate) : null;
        return new {
        version = policy.Version, session_id = own.Session, pid = own.Pid, created = own.Created, maintenance_protocol = OrdinaryResident ? 2 : 1,
        bound_maintenance_writer_protocol = 1,
        policy_revision = ordinaryPolicy?.Revision, authority_tier = ordinaryPolicy is null ? (int?)null : UserPermissions.TierOf(ordinaryPolicy), role_stop = roleStop,
        connected_clients = Volatile.Read(ref Connections), active_requests = Requests.Count,
        maintenance_activities = Volatile.Read(ref maintenanceActivities),
        pending_release_recoveries = completed.Values.Count(c => !c.Acknowledged),
        paused = paused || localTransition || highRoleRevoked || Volatile.Read(ref pendingStops) != 0 || ProtectedPaused() || writeStatus?.Stopped == true, protected_stop_epoch = ProtectedStopEpoch,
        role_transition = localTransition || highRoleRevoked,
        computer_paused = computerPaused,
        computer_stop_generation = ComputerStopGeneration,
        computer_pause_persistence_error = computerPauseError,
        stop_persistence_error = protectedStopError, desktop_locked = unavailable, desktop_reason = desktopReason, desktop_revision = revision,
        stopping, shutdown_reason = shutdownNotice?.Reason.ToString(), shutdown_audit_error = shutdownAuditError,
        release_fault = releaseFault, high_verified = !policy.Fixture && own.Integrity == 12288,
        ordinary_verified = !policy.Fixture && OrdinaryResident && own.Integrity == 8192,
        bound_ordinary_maintenance_protocol = 1,
        bound_exit_maintenance_protocol = 1,
        broker_role = OrdinaryResident ? "ordinary" : policy.Fixture ? "fixture" : "high", ui_access = false,
        tray_available = trayAvailable, tray_icon_state = trayIconState,
        settings_window = SettingsWorkspace.SurfaceDiagnostics,
        host_window_failure = HostWindow.CallbackDiagnostics,
        stop_hotkey = "Ctrl+Alt+9", stop_hotkey_registered = hotkeyAvailable, stop_hotkey_error = hotkeyError,
        emergency_stop_hotkey = "Ctrl+Alt+Shift+9", emergency_stop_hotkey_registered = EmergencyHotkeyRegistered,
        emergency_stop_hotkey_error = EmergencyHotkeyError,
        global_write_stopped = writeStatus?.Stopped,
        global_stop_epoch = writeStatus?.Epoch,
        scope = "windows-interactive-session", input_replay = false
    }; } }
}
