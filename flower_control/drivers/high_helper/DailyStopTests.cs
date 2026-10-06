namespace Flower.HighHelper;

internal static class DailyStopTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("daily_stop_selftest_failed"); }
        using var gate = new SharedWriteGate(Guid.NewGuid().ToString("N"));
        var core = new BrokerState(writeGate: gate);
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
        core.Pause(true); Require(gate.Snapshot().Epoch == 1);
        try { core.Check(core.Revision); Require(false); }
        catch (Boundary error) { Require(error.Code == "global_write_stopped"); }
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
        try { ledger.Send(key, receipt); Require(false); }
        catch (Boundary error) { Require(error.Code == "global_write_stopped"); }
        Require(calls.Count == 2); // Explicit resume never revives the earlier input ledger.
        var text = ComputerPlans.TextBatches("\r\n\t中文\r🌸");
        Require(text.Sum(b => b.Segments.Sum(s => s.Steps.Length)) == 14);
        Require(text[0].Segments[0].Steps[0].Token == "vk:13");
        Require(text[0].Segments[0].Steps[2].Token == "vk:9");
        var boundary = ComputerPlans.TextBatches(new string('a', 63) + "🌸");
        Require(boundary.Length == 2 && boundary[0].Segments[0].Steps.Length == 126 && boundary[1].Segments[0].Steps.Length == 4);
        Require(ComputerPlans.TextBatches("a\tb", splitTabs: true).Length == 3);
        write.Stop.Dispose(); read.Stop.Dispose();
        return new { assertions, nativeInputExecuted = false, windowCreated = false, highVerified = false };
    }
}
