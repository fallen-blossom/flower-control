using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed class BrokerRequest
{
    internal Peer? Owner;
    internal string TaskId = "", ActionId = "", LedgerIdentity = "";
    internal readonly CancellationTokenSource Stop = new();
    internal string? Reason;
    internal bool ReadOnly;
    internal void Cancel(string reason)
    {
        Interlocked.CompareExchange(ref Reason, reason, null);
        try { Stop.Cancel(); } catch (ObjectDisposedException) { } // Concurrent finished-request removal.
    }
}
internal sealed class BrokerState
{
    private readonly object gate = new();
    // A fresh host also invalidates previous host observations; no grants live here.
    private long revision = DateTime.UtcNow.Ticks;
    private bool paused, unavailable, stopping, releaseFault;
    private string? desktopReason;
    private bool? trayAvailable;
    private bool? hotkeyAvailable;
    private int? hotkeyError;
    internal readonly SharedWriteGate? WriteGate;
    internal void HotkeyAvailable(bool value, int? error = null) { lock (gate) { hotkeyAvailable = value; hotkeyError = error; } }
    internal void TrayAvailable(bool value) { lock (gate) trayAvailable = value; }
    internal readonly CancellationTokenSource Shutdown = new();
    internal readonly ConcurrentDictionary<string, BrokerRequest> Requests = new();
    private sealed record Completion(Peer Owner, Peer Source, Peer Helper, string TaskId, string ActionId,
        string ConnectionId, string LedgerIdentity, string InputRelease, bool MutexReleased,
        bool? SemanticExecutorExited, bool NativeCountKnown, long Finished, bool Acknowledged = false,
        bool PhysicalInputFree = false);
    private sealed record RecoverySnapshot(int Schema, Completion[] Pending);
    private readonly ConcurrentDictionary<string, Completion> completed = new();
    private readonly string? recoveryPath;
    internal BrokerState(string? recoveryPath = null, SharedWriteGate? writeGate = null)
    {
        WriteGate = writeGate;
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
    internal bool IsPaused { get { lock (gate) return paused || WriteGate?.Snapshot().Stopped == true; } }
    internal bool IsFault { get { lock (gate) return releaseFault; } }
    internal string Summary { get { lock (gate) return stopping ? "正在退出" : releaseFault ? "释放未确认，输入已停用" : unavailable ? "桌面锁定或不可用" : IsPaused ? "全部写入已停止" : hotkeyAvailable == false ? "运行中；停止热键注册失败" : "运行中"; } }
    internal void Check(long expected, bool write = true)
    {
        lock (gate)
        {
            if (stopping) throw new Boundary("broker_stopping");
            if (write && releaseFault) throw new Boundary("broker_release_fault");
            if (write && paused) throw new Boundary("broker_paused");
            if (write && WriteGate?.Snapshot().Stopped == true) throw new Boundary("global_write_stopped");
            if (unavailable) throw new Boundary(desktopReason ?? "desktop_locked");
            if (expected != revision) throw new Boundary("fresh_broker_observation_required");
        }
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
    internal void Pause(bool value, long? expectedEpoch = null)
    {
        if (WriteGate is not null) { if (value) WriteGate.Stop(); else WriteGate.Resume(expectedEpoch); }
        // Shared Stop has its own epoch. It must not invalidate a read-only
        // request's desktop revision when the desktop itself did not change.
        if (WriteGate is null)
        {
            lock (gate) { if (paused == value) return; paused = value; ++revision; }
        }
        if (value) foreach (var request in Requests.Values.Where(r => !r.ReadOnly)) request.Cancel("broker_paused");
    }
    internal void Fault()
    {
        lock (gate) { releaseFault = true; ++revision; }
        foreach (var request in Requests.Values) request.Cancel("broker_release_fault");
    }
    internal void Stop()
    {
        lock (gate) { stopping = true; ++revision; }
        foreach (var request in Requests.Values) request.Cancel("broker_stopping");
        Shutdown.Cancel();
    }
    internal object Snapshot(BrokerPolicy policy, Peer own) { lock (gate) {
        var writeStatus = WriteGate?.Snapshot();
        return new {
        version = policy.Version, session_id = own.Session, pid = own.Pid, created = own.Created,
        connected_clients = Volatile.Read(ref Connections), active_requests = Requests.Count,
        pending_release_recoveries = completed.Values.Count(c => !c.Acknowledged),
        paused = paused || writeStatus?.Stopped == true, desktop_locked = unavailable, desktop_reason = desktopReason, desktop_revision = revision,
        stopping, release_fault = releaseFault, high_verified = !policy.Fixture, ui_access = false,
        tray_available = trayAvailable,
        stop_hotkey = "Ctrl+Alt+9", stop_hotkey_registered = hotkeyAvailable, stop_hotkey_error = hotkeyError,
        global_write_stopped = writeStatus?.Stopped,
        global_stop_epoch = writeStatus?.Epoch,
        scope = "windows-interactive-session", input_replay = false
    }; } }
}
