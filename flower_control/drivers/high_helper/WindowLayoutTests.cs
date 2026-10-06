using System.Text.Json;

namespace Flower.HighHelper;

internal static class WindowLayoutTests
{
    internal static int Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("window_layout_selftest_failed"); }
        void Rejected(Action action, string reason)
        { try { action(); Require(false); } catch (Boundary error) { Require(error.Code == reason); } }
        int[] original = [10, 20, 110, 120];
        var payload = JsonSerializer.SerializeToElement(new { kind = "window_layout", schema_version = 1, command = "window_move",
            binding = new { task_id = "task", action_id = "task:layout:1", observation_id = "original", generation = "geometry", sequence_step = (int?)null },
            requested_rect = new[] { 1010, 20, 1110, 120 }, desktop = new { left = 0, top = 0, width = 2000, height = 1000 },
            work_areas = new[] { new[] { 1000, 0, 2000, 960 }, new[] { 0, 0, 1000, 960 } } });
        var plan = WindowLayout.Parse(payload, original);
        Require(plan.Binding.ActionId == "task:layout:1" && plan.WorkAreas[0][0] == 0 && plan.RequestedRect[0] == 1010);
        Require(WindowLayout.Covered([900, 20, 1100, 120], plan.WorkAreas));
        Require(!WindowLayout.Covered([900, 20, 1100, 120], [[0, 0, 950, 960], [1000, 0, 2000, 960]]));
        Require(!WindowLayout.Covered([10, 950, 110, 970], plan.WorkAreas));
        Rejected(() => WindowLayout.Parse(JsonSerializer.SerializeToElement(new { Script = "fixture" }), original), "window_layout_rejected");
        Rejected(() => WindowLayout.Parse(JsonDocument.Parse(payload.GetRawText().Replace("1110", "1111")).RootElement, original), "window_layout_rejected");
        Rejected(() => WindowLayout.Parse(JsonDocument.Parse(payload.GetRawText().Replace("\"window_move\"", "\"window_resize\"")).RootElement, original), "window_layout_rejected");
        Rejected(() => WindowLayout.ValidateNormal("window_move", true, false, true), "window_not_normal");
        Rejected(() => WindowLayout.ValidateNormal("window_move", false, true, true), "window_not_normal");
        Rejected(() => WindowLayout.ValidateNormal("window_resize", false, false, false), "window_resize_unavailable");
        WindowLayout.ValidateNormal("window_move", false, false, false);
        Require(WindowLayout.Flags == 0x14);
        int calls = 0, before = 0, after = 0;
        var receipt = new Receipt { RequestBinding = plan.Binding };
        WindowLayout.Perform(plan, receipt, () => ++before, () => ++after, () => { ++calls; return (true, 0); },
            () => plan.RequestedRect);
        Require(calls == 1 && before == 1 && after == 1 && receipt.LayoutResult!.CallReturned == true && receipt.LayoutResult.RequestedReached == true);
        Require(receipt.LayoutResult!.ObservedRect!.SequenceEqual(plan.RequestedRect) && receipt.SemanticBusinessDispatched == true);
        Require(receipt.BusinessAttempted && receipt.RequiresNewObservation && receipt.State == "dispatched_unverified");
        Require(receipt.RequestedEvents == 0 && receipt.SentEvents == 0 && receipt.BusinessEvents == 0 && receipt.NativeCountKnown && receipt.InputRelease == "released" && !receipt.MutexReleased);
        calls = 0; receipt = new Receipt();
        Rejected(() => WindowLayout.Perform(plan, receipt, () => throw new Boundary("input_stopped"), () => { },
            () => { ++calls; return (true, 0); }, () => original), "input_stopped");
        Require(calls == 0 && receipt.LayoutResult!.DispatchAttempted == false && receipt.LayoutResult.CallReturned == false && !receipt.BusinessAttempted);
        calls = 0; receipt = new Receipt();
        WindowLayout.Perform(plan, receipt, () => { }, () => { }, () => { ++calls; return (true, 0); }, () => original);
        Require(calls == 1 && receipt.LayoutResult!.CallReturned == true && receipt.LayoutResult.Dispatched == true && receipt.LayoutResult.RequestedReached == false);
        Require(receipt.Reason == "window_layout_adjusted" && receipt.SentEvents == 0 && receipt.InputRelease == "released");
        calls = 0; receipt = new Receipt();
        WindowLayout.Perform(plan, receipt, () => { }, () => { }, () => { ++calls; return (false, 5); }, () => original);
        Require(calls == 1 && receipt.LayoutResult!.CallReturned == true && receipt.LayoutResult.ApiSucceeded == false && receipt.LayoutResult.Dispatched == false);
        Require(receipt.Reason == "window_layout_api_failed" && receipt.Winerror == 5 && receipt.LayoutResult!.ObservedRect!.SequenceEqual(original));
        calls = 0; receipt = new Receipt();
        try { WindowLayout.Perform(plan, receipt, () => { }, () => { }, () => { ++calls; throw new IOException(); }, () => original); Require(false); }
        catch (IOException) { Require(receipt.LayoutResult!.DispatchAttempted && receipt.LayoutResult.CallReturned is null && receipt.LayoutResult.RequestedReached is null); }
        Require(calls == 1);
        calls = 0; receipt = new Receipt();
        Rejected(() => WindowLayout.Perform(plan, receipt, () => { }, () => throw new Boundary("input_stopped"),
            () => { ++calls; return (true, 0); }, () => plan.RequestedRect), "input_stopped");
        Require(calls == 1 && receipt.LayoutResult!.CallReturned == true && receipt.LayoutResult.RequestedReached is null && receipt.LayoutResult.Dispatched == true);
        WindowLayout.ValidateResult(plan, receipt.LayoutResult!); // Actual return survives a failed post-check.
        calls = 0; receipt = new Receipt();
        Rejected(() => WindowLayout.Perform(plan, receipt, () => { }, () => { }, () => { ++calls; return (false, 5); },
            () => throw new Boundary("target_destroyed")), "target_destroyed");
        Require(calls == 1 && receipt.LayoutResult!.CallReturned == true && receipt.LayoutResult.ApiSucceeded == false && receipt.Winerror == 5);
        WindowLayout.ValidateResult(plan, receipt.LayoutResult!);
        var adjusted = WindowLayout.NewResult(plan) with { DispatchAttempted = true, CallReturned = true, ApiSucceeded = true,
            Dispatched = true, ObservedRect = original, RequestedReached = false };
        WindowLayout.ValidateResult(plan, adjusted);
        Rejected(() => WindowLayout.ValidateResult(plan, adjusted with { RequestedReached = true }), "layout_worker_result_rejected");
        Rejected(() => WindowLayout.ValidateResult(plan, adjusted with { CallReturned = null }), "layout_worker_result_rejected");
        var childPeer = new Peer(11, 21, 1, "fixture", new string('a', 64), 8192);
        var done = new LayoutWorkerDone("done", childPeer, new string('b', 64), plan.Binding, adjusted, "dispatched_unverified", "window_layout_adjusted", null);
        using (var complete = JsonDocument.Parse(JsonSerializer.Serialize(done))) Require(LayoutWorker.DecodeDone(complete, plan).Result.RequestedReached == false);
        using (var missing = JsonDocument.Parse(JsonSerializer.Serialize(done).Replace("\"CallReturned\":true,", "")))
            Rejected(() => LayoutWorker.DecodeDone(missing, plan), "layout_worker_result_rejected");
        using (var closedGo = JsonDocument.Parse("{\"Phase\":\"go\",\"Script\":\"fixture\"}")) Require(!Protocol.Phase(closedGo, "go"));
        var terminal = new Receipt { LedgerIdentity = new string('b', 64), TaskId = "task", ConnectionId = new string('c', 32),
            InputRelease = "released", MutexReleased = true, SemanticExecutor = childPeer, SemanticExecutorExited = false,
            LayoutResult = adjusted, RequestBinding = plan.Binding };
        Require(BrokerState.IsPhysicalInputFree(terminal) && BrokerState.InputReleased(terminal));
        Require(!BrokerState.InputReleased(terminal with { LayoutResult = null })); // Ordinary UIA child stays blocking.
        Require(!BrokerState.InputReleased(terminal with { SentEvents = 1 }));
        Require(!BrokerState.InputReleased(terminal with { MutexReleased = false }));
        var broker = new BrokerState(); var owner = childPeer with { Pid = 10, Created = 20 };
        broker.Completed(owner, terminal, owner, owner, plan.Binding.ActionId);
        var metadata = JsonSerializer.SerializeToElement(broker.RequestStatus(owner, "task", terminal.ConnectionId, terminal.LedgerIdentity!));
        Require(metadata.GetProperty("PhysicalInputFree").GetBoolean() && !metadata.GetProperty("SemanticExecutorExited").GetBoolean());
        var recovery = JsonSerializer.SerializeToElement(broker.RecoverRelease(owner, "task", plan.Binding.ActionId, BrokerState.ExecutorIdentity(owner), terminal.LedgerIdentity!));
        Require(recovery.GetProperty("PhysicalInputFree").GetBoolean() && !recovery.GetProperty("SemanticExecutorExited").GetBoolean());
        broker.AcknowledgeRecovery(owner, "task", plan.Binding.ActionId, BrokerState.ExecutorIdentity(owner), terminal.LedgerIdentity!);
        Require(!broker.IsFault);
        broker.Completed(owner, terminal with { LayoutResult = null });
        Rejected(() => broker.AcknowledgeRecovery(owner, "task", plan.Binding.ActionId, BrokerState.ExecutorIdentity(owner), terminal.LedgerIdentity!), "release_recovery_unconfirmed");
        var journalRoot = Path.Combine(Path.GetTempPath(), "flower-layout-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(journalRoot);
        var journal = Path.Combine(journalRoot, "pending.json");
        new BrokerState(journal).Completed(owner, terminal, owner, owner, plan.Binding.ActionId);
        var reopened = new BrokerState(journal);
        var persisted = JsonSerializer.SerializeToElement(reopened.RecoverRelease(owner, "task", plan.Binding.ActionId, BrokerState.ExecutorIdentity(owner), terminal.LedgerIdentity!));
        Require(persisted.GetProperty("PhysicalInputFree").GetBoolean() && !persisted.GetProperty("SemanticExecutorExited").GetBoolean());
        reopened.AcknowledgeRecovery(owner, "task", plan.Binding.ActionId, BrokerState.ExecutorIdentity(owner), terminal.LedgerIdentity!);
        Require(JsonSerializer.SerializeToElement(new BrokerState(journal).RecoverRelease(owner, "task", plan.Binding.ActionId,
            BrokerState.ExecutorIdentity(owner), terminal.LedgerIdentity!)).GetProperty("State").GetString() == "unknown");
        var target = new Target(30, 10, 20, 1, new string('a', 64), 8192, 1, original, [0, 0, 100, 100], [10, 20], 96);
        var prepare = new Prepare("prepare", new Peer(10, 20, 1, "fixture", new string('a', 64), 8192), target,
            new Operation("window_layout", Plan: payload), ["desktop-foreground-input-v1", "physical-window-v1:10:20:30"], 3000, "task", new string('c', 32), 1);
        Protocol.Validate(prepare, true);
        Require(!Protocol.UsesPhysicalInput(prepare.Operation) && !Protocol.NeedsForeground(prepare.Operation));
        Rejected(() => Protocol.Validate(prepare with { Operation = prepare.Operation with { RestoreMinimized = true } }, true), "operation_rejected");
        Rejected(() => Protocol.Validate(prepare with { Resources = ["physical-window-v1:10:20:30"] }, true), "resources_rejected");
        using var wrongStop = JsonDocument.Parse(JsonSerializer.Serialize(new { Phase = "stop", ActionId = "task:other", LedgerIdentity = "ledger", prepare.TaskId, prepare.ConnectionId, prepare.DesktopRevision }));
        Require(!Protocol.Signal(wrongStop, "stop", "ledger", prepare));
        return assertions;
    }
}
