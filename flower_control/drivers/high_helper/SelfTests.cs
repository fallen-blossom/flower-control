using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class SelfTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("selftest_failed"); }
        long waitElapsed = 1999;
        int waitChecks = 0, waitSleeps = 0;
        foreach (long crossed in new long[] { 2001, 2002 })
        {
            waitElapsed = 1999; waitChecks = 0; waitSleeps = 0;
            ComputerPlans.WaitForOffset(2000, () => waitElapsed,
                () => { ++waitChecks; waitElapsed = crossed; },
                delay => { ++waitSleeps; Require(delay > 0 && delay <= 20); waitElapsed += delay; });
            Require(waitChecks == 1 && waitSleeps == 0);
        }
        waitElapsed = 0; waitChecks = 0; waitSleeps = 0;
        ComputerPlans.WaitForOffset(45, () => waitElapsed, () => ++waitChecks,
            delay => { ++waitSleeps; Require(delay > 0 && delay <= 20); waitElapsed += delay; });
        Require(waitElapsed == 45 && waitChecks == 3 && waitSleeps == 3);
        waitElapsed = 0; waitSleeps = 0;
        try {
            ComputerPlans.WaitForOffset(2000, () => waitElapsed,
                () => throw new Boundary("input_stopped"), delay => ++waitSleeps);
            Require(false);
        } catch (Boundary error) { Require(error.Code == "input_stopped" && waitSleeps == 0); }
        waitElapsed = 2000; waitChecks = 0;
        ComputerPlans.WaitForOffset(2000, () => waitElapsed, () => ++waitChecks, delay => ++waitSleeps);
        Require(waitChecks == 0 && waitSleeps == 0);
        waitElapsed = 1999; waitChecks = 0;
        ComputerPlans.WaitForOffset(2000, () => waitElapsed,
            () => { ++waitChecks; waitElapsed = 2000; }, delay => ++waitSleeps);
        Require(waitChecks == 1 && waitSleeps == 0);
        Require(!Executor.InitialGeometryRequired(new Operation("computer_input_plan", RestoreMinimized: true), true));
        Require(Executor.InitialGeometryRequired(new Operation("computer_input_plan", RestoreMinimized: true), false));
        Require(Executor.InitialGeometryRequired(new Operation("computer_input_plan"), true));
        Require(!Executor.InitialGeometryRequired(new Operation("activate", RestoreMinimized: true), true));
        var down = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 2 } } };
        var up = new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Flags = 4 } } };
        Step[] pair = [new Step(down, "mouse:left", true, up), new Step(up, "mouse:left")];
        var calls = new List<Native.Input[]>();
        var partial = new InputLedger(inputs => { calls.Add(inputs); return 1; });
        var result = new Receipt();
        try { partial.Send(pair, result); Require(false); } catch (Boundary error) { Require(error.Code == "input_partial"); }
        Require(partial.State == "release_pending");
        partial.Release(result);
        Require(partial.State == "released" && result.SentEvents == 1 && result.ReleaseEvents == 1);
        Require(calls.Count == 2 && calls[1].Length == 1 && calls[1][0].Data.Mouse.Flags == 4);

        int count = 0;
        var failedRelease = new InputLedger(inputs => ++count == 1 ? 1U : 0U);
        result = new Receipt();
        try { failedRelease.Send(pair, result); } catch (Boundary) { }
        try { failedRelease.Release(result); Require(false); } catch (Boundary error) { Require(error.Code == "release_partial"); }
        Require(failedRelease.State == "release_pending");

        var unknown = new InputLedger(inputs => throw new IOException());
        try { unknown.Send(pair, new Receipt()); } catch (IOException) { }
        Require(unknown.State == "unknown");
        unknown.Release(new Receipt());
        Require(unknown.State == "unknown");

        var balanced = new InputLedger(inputs => (uint)inputs.Length);
        result = new Receipt(); balanced.Send(pair, result); balanced.Release(result);
        Require(balanced.State == "released" && result.SentEvents == 2 && result.ReleaseEvents == 0);
        Require(System.Runtime.InteropServices.Marshal.SizeOf<Native.Input>() == (IntPtr.Size == 8 ? 40 : 28));
        Require(ResourceLocks.Name("desktop-foreground-input-v1") == "Local\\FlowerControl.Resource.v1.b6918b905f1abda1b0a99f406ff6e6ecbe11115e12b0330c5d0e5bf4bb9fe65c");

        using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes("{\"Phase\":\"go\",\"Phase\":\"stop\"}\n")))
        {
            try { Protocol.Read(bytes, 100); Require(false); } catch (Boundary error) { Require(error.Code == "schema_rejected"); }
        }
        using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes(new string('a', Protocol.Limit))))
        {
            try { Protocol.Read(bytes, 100); Require(false); } catch (Boundary error) { Require(error.Code == "message_too_large"); }
        }
        using (var bytes = new MemoryStream(Encoding.UTF8.GetBytes("{\"Phase\":\"stop\",\"LedgerIdentity\":\"old\"}\n{\"Phase\":\"go\",\"LedgerIdentity\":\"new\"}\n")))
        {
            using var first = Protocol.Read(bytes, 100);
            using var second = Protocol.Read(bytes, 100);
            Require(first is not null && Protocol.Signal(first, "stop", "old") && !Protocol.Signal(first, "stop", "new"));
            Require(second is not null && Protocol.Signal(second, "go", "new"));
        }
        var state = new BrokerState();
        var negotiating = new BrokerState();
        var pendingInput = new BrokerRequest();
        negotiating.Requests["pending"] = pendingInput;
        var negotiationRevision = negotiating.Revision;
        Require(HostWindow.EndSessionMessage(negotiating, 0x11, false) == new IntPtr(1));
        Require(!negotiating.Shutdown.IsCancellationRequested && !pendingInput.Stop.IsCancellationRequested);
        Require(HostWindow.EndSessionMessage(negotiating, 0x16, false) == IntPtr.Zero);
        Require(!negotiating.Shutdown.IsCancellationRequested && !negotiating.IsPaused && negotiating.Revision == negotiationRevision);
        negotiating.Check(negotiationRevision);
        Require(HostWindow.EndSessionMessage(negotiating, 0x16, true) == IntPtr.Zero);
        Require(negotiating.Shutdown.IsCancellationRequested && pendingInput.Stop.IsCancellationRequested);
        Require(HostWindow.EndSessionMessage(new BrokerState(), 0x113, false) is null);
        var observed = state.Revision;
        var firstRequest = new BrokerRequest(); var secondRequest = new BrokerRequest();
        state.Requests["one"] = firstRequest; state.Requests["two"] = secondRequest;
        firstRequest.Cancel("client_disconnected");
        Require(firstRequest.Stop.IsCancellationRequested && !secondRequest.Stop.IsCancellationRequested && !state.Shutdown.IsCancellationRequested);
        state.Pause(true);
        Require(secondRequest.Stop.IsCancellationRequested && state.Revision > observed);
        state.Pause(false);
        try { state.Check(observed); Require(false); } catch (Boundary error) { Require(error.Code == "fresh_broker_observation_required"); }
        state.Check(state.Revision);
        Require(firstRequest.Stop.IsCancellationRequested && secondRequest.Stop.IsCancellationRequested);
        observed = state.Revision; state.Desktop(false, "desktop_locked"); state.Desktop(true);
        Require(state.Revision > observed);
        state.Fault(); state.Pause(false);
        try { state.Check(state.Revision); Require(false); } catch (Boundary error) { Require(error.Code == "broker_release_fault"); }

        var planObject = new { kind = "computer_input_plan", schema_version = 1, command = "key",
            binding = new { task_id = "fixture", action_id = "fixture:computer:action", observation_id = "observation",
                generation = new string('g', 260), sequence_step = (int?)null }, desktop = (object?)null,
            plans = new[] { new { duration_ms = 0, segments = new[] { new { offset_ms = 0,
                events = new[] { new { kind = "virtual_key", code = 65, down = true }, new { kind = "virtual_key", code = 65, down = false } } } } } } };
        var planElement = JsonSerializer.SerializeToElement(planObject);
        var parsed = ComputerPlans.Parse(planElement);
        Require(parsed.Binding.Generation?.Length == 260 && parsed.Plans[0].Segments[0].Steps.Length == 2);
        object Segment(int offset, params object[] events) => new { offset_ms = offset, events };
        ComputerPlan EventPlan(string command, int duration, params object[] segments) => ComputerPlans.Parse(JsonSerializer.SerializeToElement(new {
            kind = "computer_input_plan", schema_version = 1, command, planObject.binding,
            desktop = new { left = 0, top = 0, width = 1920, height = 1080 },
            plans = new[] { new { duration_ms = duration, segments } } }));
        var mouseDown = new { kind = "mouse_button", button = "left", down = true };
        var mouseUp = new { kind = "mouse_button", button = "left", down = false };
        var absolute = new { kind = "mouse_absolute", nx = 32767, ny = 32767 };
        var relative = new { kind = "mouse_relative", dx = 1, dy = 0 };
        var keyDown = new { kind = "virtual_key", code = 17, down = true };
        var keyUp = new { kind = "virtual_key", code = 17, down = false };
        foreach (var mousePlan in new[] {
            EventPlan("click", 0, Segment(0, absolute, mouseDown, mouseUp)),
            EventPlan("double_click", 0, Segment(0, absolute, mouseDown, mouseUp, mouseDown, mouseUp)),
            EventPlan("scroll", 0, Segment(0, absolute, new { kind = "mouse_wheel", axis = "vertical", delta = 120 })),
            EventPlan("drag", 10, Segment(0, absolute, mouseDown), Segment(10, relative, mouseUp)),
            EventPlan("move_relative", 0, Segment(0, relative)),
            EventPlan("mouse_hold", 10, Segment(0, absolute, mouseDown), Segment(10, mouseUp)) })
            Require(!ComputerPlans.HasKeyboardEvents(mousePlan));
        Require(ComputerPlans.HasKeyboardEvents(parsed));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("text", 0, Segment(0,
            new { kind = "unicode_key", unit = 97, down = true }, new { kind = "unicode_key", unit = 97, down = false }))));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("key_mouse", 10,
            Segment(0, keyDown, mouseDown, relative), Segment(10, mouseUp, keyUp))));
        Require(!ComputerPlans.HasKeyboardEvents(EventPlan("key_mouse", 10,
            Segment(0, mouseDown, relative), Segment(10, mouseUp))));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("drag", 10,
            Segment(0, mouseDown), Segment(5, keyDown, relative), Segment(10, keyUp, mouseUp))));
        Require(ComputerPlans.HasKeyboardEvents(EventPlan("click", 0, Segment(0, keyDown, keyUp))));
        var keyboardContext = new InputContext(10, 20, "inactive");
        Require(InputContext.MergeComposition("unknown", true) == "active");
        Require(InputContext.MergeComposition("inactive", true) == "active");
        Require(InputContext.MergeComposition("unknown", false) == "inactive");
        Require(InputContext.MergeComposition("unknown", null) == "unknown");
        Require(InputContext.MergeComposition("active", false) == "active");
        var activeIme = keyboardContext with { Composition = "active" };
        int escapes = 0, reads = 0;
        var prepared = InputContext.PrepareCore(() => ++reads < 3 ? activeIme : keyboardContext,
            () => { }, () => ++escapes, _ => { });
        Require(prepared == keyboardContext && escapes == 1 && reads == 3);
        reads = escapes = 0;
        prepared = InputContext.PrepareCore(() => ++reads == 1 ? activeIme : keyboardContext,
            () => { }, () => ++escapes, _ => { });
        Require(prepared == keyboardContext && escapes == 0);
        foreach (var changed in new[] { activeIme with { Focus = 30 }, activeIme with { Layout = 40 }, activeIme with { Composition = "unknown" } })
        {
            reads = escapes = 0;
            try { InputContext.PrepareCore(() => ++reads == 1 ? activeIme : changed, () => { }, () => ++escapes, _ => { }); Require(false); }
            catch (Boundary error) { Require(error.Code == "input_context_changed" && escapes == 0); }
        }
        try { InputContext.PrepareCore(() => activeIme, () => throw new Boundary("broker_paused"), () => ++escapes, _ => { }); Require(false); }
        catch (Boundary error) { Require(error.Code == "broker_paused" && escapes == 0); }
        var mouseContext = new InputContextGuard(keyboardContext, false);
        var changedMouseContext = new InputContext(30, 40, "active");
        mouseContext.Recheck(changedMouseContext, 120);
        Require(mouseContext.Baseline == changedMouseContext);
        mouseContext.Recheck(new(null, null, "unknown"), 140);
        Require(mouseContext.Baseline == new InputContext(null, null, "unknown"));
        void ContextRejected(InputContextGuard guard, InputContext current, long now)
        { try { guard.Recheck(current, now); Require(false); } catch (Boundary error) { Require(error.Code == "input_context_changed"); } }
        ContextRejected(new(keyboardContext, true), keyboardContext with { Focus = 30 }, 20);
        var ownClick = new InputContextGuard(keyboardContext, true);
        ownClick.MouseDispatched(30, 10);
        ownClick.Recheck(keyboardContext, 40); // Focus can arrive asynchronously while the hold is supervised.
        ownClick.Recheck(keyboardContext with { Focus = 30 }, 120);
        Require(ownClick.Baseline == keyboardContext with { Focus = 30 });
        ContextRejected(ownClick, keyboardContext with { Focus = 10 }, 130); // The permission was consumed.
        InputContextGuard PendingClick()
        { var guard = new InputContextGuard(keyboardContext, true); guard.MouseDispatched(30, 10); return guard; }
        ContextRejected(PendingClick(), keyboardContext with { Focus = 31 }, 20);
        ContextRejected(PendingClick(), keyboardContext with { Focus = 30 }, 161);
        ContextRejected(PendingClick(), keyboardContext with { Focus = 30, Layout = 21 }, 20);
        ContextRejected(PendingClick(), keyboardContext with { Focus = 30, Composition = "active" }, 20);
        ContextRejected(PendingClick(), keyboardContext with { Focus = null }, 20);
        var unknownReceiver = PendingClick(); unknownReceiver.MouseDispatched(null, 15);
        ContextRejected(unknownReceiver, keyboardContext with { Focus = 30 }, 20);
        var unknownContext = new InputContextGuard(new(10, null, "unknown"), true);
        unknownContext.MouseDispatched(30, 10); unknownContext.Recheck(new(30, 20, "inactive"), 20);
        Require(unknownContext.Baseline == new InputContext(30, null, "unknown"));
        var initialPoint = new Native.Point { X = 9, Y = 8 };
        Require(InputContext.FocusPoint(pair, null, initialPoint) is { X: 9, Y: 8 });
        var mouseAbsoluteStep = new Step(new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Dx = 65535, Dy = 0, Flags = 0xc001 } } });
        var mouseRelativeStep = new Step(new Native.Input { Data = new Native.Union { Mouse = new Native.Mouse { Dx = 1, Dy = 0, Flags = 1 } } });
        var desktop = new DesktopShape(-100, -50, 1000, 500);
        Require(InputContext.FocusPoint([mouseAbsoluteStep, pair[0]], desktop, initialPoint) is { X: 899, Y: -50 });
        Require(InputContext.FocusPoint([mouseRelativeStep, pair[0]], desktop, initialPoint) is null);
        Require(InputContext.FocusPoint([pair[0], mouseRelativeStep], desktop, initialPoint) is { X: 9, Y: 8 });
        Require(InputContext.FocusPoint([mouseRelativeStep, mouseAbsoluteStep, pair[0]], desktop, initialPoint) is { X: 899, Y: -50 });
        Require(InputContext.FocusPoint([pair[0], mouseRelativeStep, pair[0]], desktop, initialPoint) is null);
        Require(InputContext.FocusPoint([mouseAbsoluteStep, pair[1]], desktop, initialPoint) is null);
        Require(InputContext.MouseDown(pair[0]) && !InputContext.MouseDown(pair[1]) && !InputContext.MouseDown(parsed.Plans[0].Segments[0].Steps[0]));
        using (var malformed = JsonDocument.Parse(planElement.GetRawText().Replace("\"down\":false", "\"down\":true")))
        { try { ComputerPlans.Parse(malformed.RootElement); Require(false); } catch (Boundary error) { Require(error.Code == "input_plan_unbalanced"); } }
        using (var malformed = JsonDocument.Parse(planElement.GetRawText().Replace("\"code\":65", "\"code\":true")))
        { try { ComputerPlans.Parse(malformed.RootElement); Require(false); } catch (Boundary error) { Require(error.Code == "input_plan_rejected"); } }
        int prefixCalls = 0;
        var prefixUnknown = new InputLedger(inputs => ++prefixCalls == 2 ? throw new IOException() : (uint)inputs.Length);
        result = new Receipt(); prefixUnknown.Send([pair[0]], result);
        try { prefixUnknown.Send([pair[1]], result); Require(false); } catch (IOException) { Require(!prefixUnknown.CountKnown); }
        prefixUnknown.Release(result);
        Require(prefixUnknown.State == "unknown" && result.BusinessEvents == 1 && result.ReleaseEvents == 1);
        var prepareOnly = new InputLedger(inputs => (uint)inputs.Length);
        result = new Receipt(); prepareOnly.Send(pair, result, activation: true); prepareOnly.Send(pair, result, preparation: true);
        Require(!result.BusinessAttempted && result.BusinessEvents == 0 && result.ActivationEvents == 2 && result.ImeEvents == 2);
        var owner = new Peer(10, 20, 1, "fixture", new string('a', 64), 8192);
        result = new Receipt { LedgerIdentity = new string('b', 64), TaskId = "task", ConnectionId = new string('c', 32),
            InputRelease = "released", MutexReleased = true };
        state.Completed(owner, result);
        var released = JsonSerializer.SerializeToElement(state.RequestStatus(owner, "task", new string('c', 32), new string('b', 64)));
        Require(released.GetProperty("State").GetString() == "finished" && released.GetProperty("MutexReleased").GetBoolean());
        var unrelated = JsonSerializer.SerializeToElement(state.RequestStatus(owner with { Created = 21 }, "task", new string('c', 32), new string('b', 64)));
        Require(unrelated.GetProperty("State").GetString() == "unknown" && !unrelated.GetProperty("MutexReleased").GetBoolean());
        var source = owner with { Pid = 99, Created = 100 };
        var helper = owner with { Pid = 55, Created = 133000000000000001 };
        var recoveryLedger = new string('d', 64);
        var recoveryReceipt = new Receipt { LedgerIdentity = recoveryLedger, TaskId = "task", ConnectionId = new string('c', 32),
            InputRelease = "released", MutexReleased = true, NativeCountKnown = true };
        state.Completed(owner, recoveryReceipt, source, helper, "task:action");
        for (int i = 0; i < 257; ++i)
            state.Completed(owner, new Receipt { LedgerIdentity = i.ToString("x64"), TaskId = "task", ConnectionId = new string('c', 32),
                InputRelease = "released", MutexReleased = true }, source, helper, "task:other");
        var recovered = JsonSerializer.SerializeToElement(state.RecoverRelease(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(recovered.GetProperty("State").GetString() == "finished" && recovered.GetProperty("NativeCountKnown").GetBoolean());
        var newCodex = JsonSerializer.SerializeToElement(state.RecoverRelease(source with { Pid = 100, Created = 101 }, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(newCodex.GetProperty("State").GetString() == "finished");
        foreach (var wrongSource in new[] { source with { User = "other-user" }, source with { Session = 2 } })
        {
            var wrong = JsonSerializer.SerializeToElement(state.RecoverRelease(wrongSource, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
            Require(wrong.GetProperty("State").GetString() == "unknown");
        }
        var wrongTask = JsonSerializer.SerializeToElement(state.RecoverRelease(source, "other-task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(wrongTask.GetProperty("State").GetString() == "unknown");
        var journalRoot = Path.Combine(Path.GetTempPath(), "flower-broker-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(journalRoot);
        var journal = Path.Combine(journalRoot, "pending.json");
        var durable = new BrokerState(journal);
        durable.Completed(owner, recoveryReceipt, source, helper, "task:action");
        var reopened = new BrokerState(journal);
        var persisted = JsonSerializer.SerializeToElement(reopened.RecoverRelease(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(persisted.GetProperty("State").GetString() == "finished" && persisted.GetProperty("InputRelease").GetString() == "released");
        reopened.AcknowledgeRecovery(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger);
        var acknowledged = JsonSerializer.SerializeToElement(new BrokerState(journal).RecoverRelease(source, "task", "task:action", BrokerState.ExecutorIdentity(helper), recoveryLedger));
        Require(acknowledged.GetProperty("State").GetString() == "unknown");
        var readArguments = new { target = new { pid = 10, hwnd = 30L, process_start_filetime = 20L, root_runtime_id = Array.Empty<int>() },
            limits = new { max_nodes = 16, max_depth = 2 }, privacy = "structure_only", privacy_scope = "" };
        var readPlan = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "observe", arguments = readArguments,
            binding = new { task_id = "task", action_id = "task:app:read", observation_id = "observation", generation = "geometry", sequence_step = (int?)null } });
        var readOperation = new Operation("app_request", Plan: readPlan);
        var readTarget = new Target(30, 10, 20, 1, new string('a', 64), 8192, 1, [0, 0, 100, 100]);
        var readPrepare = new Prepare("prepare", owner, readTarget, readOperation, ["physical-window-v1:10:20:30"], 3000, "task", new string('c', 32), 1);
        Protocol.Validate(readPrepare, true);
        Require(!Protocol.NeedsForeground(readOperation) && !Protocol.UsesPhysicalInput(readOperation));
        var initial = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "observe", arguments = readArguments,
            binding = new { task_id = "task", action_id = "initial", observation_id = (string?)null, generation = (string?)null, sequence_step = (int?)null } });
        Require(AppExecutor.Parse(initial, readTarget).Binding.ObservationId is null);
        var noObservedWrite = JsonSerializer.SerializeToElement(new { schema_version = 1, command = "invoke",
            arguments = new { target = readArguments.target, reference = new { }, observation = new { }, privacy = "structure_only", privacy_scope = "" },
            binding = new { task_id = "task", action_id = "write", observation_id = (string?)null, generation = (string?)null, sequence_step = (int?)null } });
        try { AppExecutor.Parse(noObservedWrite, readTarget); Require(false); }
        catch (Boundary error) { Require(error.Code == "app_binding_rejected"); }
        Protocol.Validate(readPrepare with { Operation = new Operation("bind") }, true);
        Require(!Protocol.NeedsForeground(new Operation("bind")));
        try { Protocol.Validate(readPrepare with { Operation = new Operation("activate") }, true); Require(false); }
        catch (Boundary error) { Require(error.Code == "resources_rejected"); }
        int adds = 0, modifies = 0, removes = 0;
        bool shell = false;
        var tray = new TrayRegistration(() => { ++adds; return shell; }, () => { ++modifies; return shell; }, () => ++removes);
        tray.Tick(0, "running");
        Require(!tray.Registered && adds == 1);
        tray.Tick(999, "running");
        Require(!tray.Registered && adds == 1);
        shell = true; tray.Tick(1000, "running");
        Require(tray.Registered && adds == 2);
        shell = false; tray.Tick(2000, "running");
        Require(!tray.Registered && modifies == 1);
        shell = true; tray.ExplorerRestarted(2001); tray.Tick(2001, "running");
        Require(tray.Registered && adds == 4);
        tray.Close(); Require(!tray.Registered && removes == 1);
        using var emptyAck = JsonDocument.Parse("{\"Phase\":\"ack\",\"LedgerIdentity\":\"ledger\",\"TaskId\":\"task\",\"ConnectionId\":\"connection\",\"DesktopRevision\":1,\"ActionId\":\"\"}");
        var unclaimed = readPrepare with { Operation = new Operation("bind"), ConnectionId = "connection" };
        Require(Protocol.Signal(emptyAck, "ack", "ledger", unclaimed, ""));
        Require(!Protocol.Signal(emptyAck, "go", "ledger", unclaimed));
        JsonDocument Signal(string phase, string action, string ledger, Prepare prepare) => JsonDocument.Parse(JsonSerializer.Serialize(new {
            Phase = phase, ActionId = action, LedgerIdentity = ledger, prepare.TaskId, prepare.ConnectionId, prepare.DesktopRevision }));
        var stopJournal = Path.Combine(journalRoot, "pre-go-stop-pending.json");
        var stopState = new BrokerState(stopJournal);
        int stopCase = 100;
        foreach (var kind in new[] { "bind", "activate", "click", "text" })
        {
            var raw = unclaimed with { Operation = new Operation(kind) };
            var stoppedRequest = new BrokerRequest();
            var stopLedger = (++stopCase).ToString("x64");
            var action = "task:" + kind + ":stopped";
            using var stop = Signal("stop", action, stopLedger, raw);
            Require(Program.AcceptPreGoStop(stop, stopLedger, raw, stoppedRequest));
            Require(stoppedRequest.ActionId == action && stoppedRequest.Stop.IsCancellationRequested && stoppedRequest.Reason == "input_stopped");
            stopState.Completed(owner, new Receipt { LedgerIdentity = stopLedger, TaskId = raw.TaskId, ConnectionId = raw.ConnectionId,
                InputRelease = "released", MutexReleased = true, NativeCountKnown = true }, source, helper, stoppedRequest.ActionId);
            var boundStop = JsonSerializer.SerializeToElement(new BrokerState(stopJournal).RecoverRelease(source, raw.TaskId, action, BrokerState.ExecutorIdentity(helper), stopLedger));
            Require(boundStop.GetProperty("State").GetString() == "finished");
            using var ack = Signal("ack", action, stopLedger, raw);
            Require(Protocol.Signal(ack, "ack", stopLedger, raw, stoppedRequest.ActionId));
            using var wrongAck = Signal("ack", action + ":wrong", stopLedger, raw);
            Require(!Protocol.Signal(wrongAck, "ack", stopLedger, raw, stoppedRequest.ActionId));
            stopState.Acknowledge(owner, stopLedger);
            using var pending = JsonDocument.Parse(File.ReadAllText(stopJournal));
            Require(pending.RootElement.GetProperty("Pending").GetArrayLength() == 0);
        }
        foreach (var phase in new[] { "go", "stop" })
        {
            using var empty = Signal(phase, "", "ledger", unclaimed);
            Require(!Protocol.Signal(empty, phase, "ledger", unclaimed));
            var rejectedRequest = new BrokerRequest();
            Require(!Program.AcceptPreGoStop(empty, "ledger", unclaimed, rejectedRequest));
            Require(rejectedRequest.ActionId == "" && !rejectedRequest.Stop.IsCancellationRequested);
        }
        foreach (var typed in new[] { readPrepare, readPrepare with { TaskId = "fixture", Operation = new Operation("computer_input_plan", Plan: planElement) } })
        {
            var expectedAction = typed.Operation.Kind == "app_request" ? "task:app:read" : "fixture:computer:action";
            var typedRequest = new BrokerRequest { ActionId = expectedAction };
            using var wrongStop = Signal("stop", expectedAction + ":wrong", "ledger", typed);
            Require(!Program.AcceptPreGoStop(wrongStop, "ledger", typed, typedRequest));
            Require(typedRequest.ActionId == expectedAction && !typedRequest.Stop.IsCancellationRequested);
            using var typedStop = Signal("stop", expectedAction, "ledger", typed);
            Require(Program.AcceptPreGoStop(typedStop, "ledger", typed, typedRequest));
            using var typedAck = Signal("ack", expectedAction, "ledger", typed);
            Require(Protocol.Signal(typedAck, "ack", "ledger", typed, typedRequest.ActionId));
        }
        using var mismatchedStop = Signal("stop", "task:bind:stopped", "other-ledger", unclaimed);
        var mismatchedRequest = new BrokerRequest();
        Require(!Program.AcceptPreGoStop(mismatchedStop, "ledger", unclaimed, mismatchedRequest));
        Require(mismatchedRequest.ActionId == "" && !mismatchedRequest.Stop.IsCancellationRequested);
        assertions += WindowLayoutTests.Run();
        assertions += NativePhaseTests.Run();
        return new { assertions, nativeInputExecuted = false, mutexAcquired = false, highVerified = false, journalFixture = journalRoot };
    }
}
