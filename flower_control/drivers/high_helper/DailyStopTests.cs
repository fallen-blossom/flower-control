namespace Flower.HighHelper;

internal static class DailyStopTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("daily_stop_selftest_failed"); }
        using var gate = new SharedWriteGate(Guid.NewGuid().ToString("N"));
        var core = new BrokerState(writeGate: gate);
        Require(!TrayMenu.BuildRows(false, "管理员执行", "fixture").Any(row => row.Id == 5));
        var globalRows = TrayMenu.BuildRows(false, "管理员执行", "fixture", globalPaused: true);
        Require(globalRows.Count(row => row.Id == 5 && row.Label.Contains("继续全部写入", StringComparison.Ordinal) && row.Enabled) == 1);
        var unrecoverableRows = TrayMenu.BuildRows(false, "管理员执行", "fixture", stoppedWithoutRecovery: true);
        Require(!unrecoverableRows.Any(row => row.Id == 5)
            && unrecoverableRows[0].Label.Contains("保护记录不可恢复", StringComparison.Ordinal));
        using var stoppedGate = new SharedWriteGate(Guid.NewGuid().ToString("N"));
        stoppedGate.Stop();
        var stoppedCore = new BrokerState(writeGate: stoppedGate);
        Require(stoppedCore.IsPaused && stoppedCore.ResumeGlobalFromLocalUser() && !stoppedGate.Snapshot().Stopped);
        // A restarted process can rebuild the RAM gate as running while the
        // durable protected Stop still blocks. The resume path must first
        // close that new gate rather than treating it as "nothing to resume".
        using var restartedGate = new SharedWriteGate(Guid.NewGuid().ToString("N"));
        Require(!restartedGate.Snapshot().Stopped && BrokerState.RequiresSharedStopLatch(false, true));
        Require(!BrokerState.RequiresSharedStopLatch(false, false));
        Require(!BrokerState.RequiresSharedStopLatch(true, false));
        if (Environment.GetEnvironmentVariable("CODEX_CLI_PATH") is { Length: > 0 } codex)
        {
            Require(CodexHostIdentity.IsOfficialCodexImage(codex));
            Require(!CodexHostIdentity.IsOfficialCodexImage(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell/v1.0/powershell.exe")));
            if (int.TryParse(Environment.GetEnvironmentVariable("CODEX_CLI_PID"), out var codexPid) && codexPid > 0)
            {
                var peer = Native.Process(codexPid).Identity;
                Require(CodexHostIdentity.IsOfficialCodexImage(codex, codexPid, peer.Created));
            }
        }
        var write = new BrokerRequest(); var read = new BrokerRequest { ReadOnly = true };
        core.Requests["write"] = write; core.Requests["read"] = read;
        var calls = new List<Native.Input[]>();
        var ledger = new InputLedger(inputs => { calls.Add(inputs); return (uint)inputs.Length; }, gate);
        var receipt = new Receipt();
        var key = Executor.KeyPair(0x57, false); // One simulated Flower-owned W; no OS input.
        ledger.Send([key[0]], receipt);
        long revision = core.Revision;
        core.Pause(true);
        Require(gate.Snapshot().Stopped);
        Require(write.Stop.IsCancellationRequested && !read.Stop.IsCancellationRequested);
        Require(gate.Snapshot().Epoch == 1);
        core.Pause(true); Require(gate.Snapshot().Epoch == 2);
        try { core.Check(core.Revision); Require(false); }
        catch (Boundary error) { Require(error.Code == "broker_paused"); }
        core.Check(revision, write: false); Require(true);
        Require(core.Revision == revision);
        ledger.Release(receipt);
        Require(ledger.State == "released" && receipt.ReleaseEvents == 1);
        Require(calls.Count == 2 && calls[1].Length == 1 && calls[1][0].Data.Key.Vk == 0x57 && calls[1][0].Data.Key.Flags == 2);
        core.Pause(false); Require(!gate.Snapshot().Stopped);
        var previousStop = gate.Snapshot();
        core.Pause(true);
        try { core.Pause(false, previousStop.Epoch); Require(false); }
        catch (Boundary error) { Require(error.Code == "resume_state_changed"); }
        Require(gate.Snapshot().Stopped && gate.Snapshot().ResumeAllEpoch == previousStop.ResumeAllEpoch);
        var stopped = gate.Snapshot();
        try { gate.Resume(stopped.Epoch, () => throw new Boundary("fixture_protected_cas_rejected")); Require(false); }
        catch (Boundary error) { Require(error.Code == "fixture_protected_cas_rejected"); }
        Require(gate.Snapshot() == stopped); // Failed protected CAS never exposes running to ordinary channels.
        int staleAuthorizations = 0;
        try { gate.Resume(stopped.Epoch - 1, () => ++staleAuthorizations); Require(false); }
        catch (Boundary error) { Require(error.Code == "resume_state_changed"); }
        Require(staleAuthorizations == 0 && gate.Snapshot() == stopped);
        try { gate.Resume(stopped.Epoch, () => gate.Stop()); Require(false); }
        catch (Boundary error) { Require(error.Code == "resume_state_changed"); }
        Require(gate.Snapshot().Stopped && gate.Snapshot().Epoch == stopped.Epoch + 1);
        var beforePersistence = gate.Snapshot();
        try { gate.Stop(() => throw new IOException("fixture_stop_write_failed")); Require(false); }
        catch (IOException) { Require(true); }
        Require(gate.Snapshot().Stopped && gate.Snapshot().Epoch == beforePersistence.Epoch + 1);
        var failedStop = gate.Snapshot();
        gate.Stop(newStop: false); Require(gate.Snapshot() == failedStop); // Same physical event's cleanup is not another Stop.
        // Contention uses a separate owned test gate. The shared bytes remain
        // running while a second thread holds only its coordination mutex.
        var contendedName = Guid.NewGuid().ToString("N");
        using (var contended = new SharedWriteGate(contendedName))
        using (var held = new ManualResetEvent(false))
        using (var release = new ManualResetEvent(false))
        {
            var sid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
            var holder = Task.Run(() => {
                using var mutex = Mutex.OpenExisting("Local\\FlowerControl.WriteGate.v1." + sid + ".test." + contendedName + ".lock");
                mutex.WaitOne();
                try { held.Set(); if (!release.WaitOne(5000)) throw new Boundary("stop_fixture_release_timeout"); }
                finally { mutex.ReleaseMutex(); }
            });
            Require(held.WaitOne(1500));
            int persisted = 0;
            try
            {
                try { ProtectedStop.Latch(contended, () => ++persisted); Require(false); }
                catch (Boundary error) { Require(error.Code == "write_gate_busy"); }
                Require(persisted == 1); // Independent authority survives a lost RAM latch/restart.
                try { ProtectedStop.Latch(contended, () => throw new IOException("owned fixture")); Require(false); }
                catch (Boundary error)
                { Require(error.Code == "write_gate_busy" && error.Data["ProtectedStopPersistenceError"] is string); }
            }
            finally { release.Set(); holder.GetAwaiter().GetResult(); }
            Require(!contended.Snapshot().Stopped);
            ProtectedStop.Latch(contended, () => ++persisted);
            Require(contended.Snapshot().Stopped && persisted == 2);
        }
        // Hold only the internal mutation queue, never desktop/input resources.
        // The arriving Stop must latch RAM before waiting for its durable turn;
        // an older reentrant restore cannot clear it using the still-old epoch.
        var mutationQueue = typeof(BrokerState).GetField("stopMutationGate",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(core)!;
        var pendingWrite = new BrokerRequest(); core.Requests["pending_write"] = pendingWrite;
        Task pendingStop;
        lock (mutationQueue)
        {
            pendingStop = Task.Run(() => core.Pause(true));
            Require(pendingWrite.Stop.Token.WaitHandle.WaitOne(1500));
            try { core.Pause(false, failedStop.Epoch); Require(false); }
            catch (Boundary error) { Require(error.Code == "resume_state_changed"); }
            Require(core.IsPaused && gate.Snapshot() == failedStop);
        }
        Require(pendingStop.Wait(1500));
        Require(core.IsPaused && gate.Snapshot().Stopped && gate.Snapshot().Epoch == failedStop.Epoch + 1);
        core.Check(revision, write: false); Require(core.Revision == revision && !read.Stop.IsCancellationRequested);
        core.Requests.TryRemove("pending_write", out _); pendingWrite.Stop.Dispose();
        try { ledger.Send(key, receipt); Require(false); }
        catch (Boundary error) { Require(error.Code == "global_write_stopped"); }
        Require(calls.Count == 2); // Explicit resume never revives the earlier input ledger.
        var text = ComputerPlans.TextBatches("\r\n\t中文\r🌸");
        Require(text.Sum(b => b.Segments.Sum(s => s.Steps.Length)) == 14);
        Require(text[0].Segments[0].Steps[0].Token == "vk:13");
        Require(text[0].Segments[0].Steps.Length == 2 && text[1].Segments[0].Steps[0].Token == "vk:9");
        var boundary = ComputerPlans.TextBatches(new string('a', 63) + "🌸");
        Require(boundary.Length == 2 && boundary[0].Segments[0].Steps.Length == 126 && boundary[1].Segments[0].Steps.Length == 4);
        Require(ComputerPlans.TextBatches("a\tb", splitTabs: true).Length == 3);
        write.Stop.Dispose(); read.Stop.Dispose();
        return new { assertions, nativeInputExecuted = false, windowCreated = false, highVerified = false };
    }
}
