namespace Flower.HighHelper;

internal static class ComputerStopTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Check(bool value) { ++assertions; if (!value) throw new Boundary("computer_stop_test_failed"); }
        void Rejected(Action action)
        {
            try { action(); Check(false); }
            catch (Boundary error) { Check(error.Code is "input_stopped" or "computer_stopped"); }
        }
        bool cancelled = false; int sends = 0;
        double elapsed = 10; int waitChecks = 0, waits = 0;
        PointerPath.WaitForOffset(10, () => elapsed, () => ++waitChecks, _ => ++waits);
        Check(waitChecks == 0 && waits == 0);
        elapsed = 0;
        PointerPath.WaitForOffset(9, () => elapsed, () => ++waitChecks, delay => {
            Check(delay is > 0 and <= 4); elapsed += delay; ++waits;
        });
        Check(elapsed == 9 && waitChecks == 3 && waits == 3);
        elapsed = 0; waitChecks = waits = 0;
        PointerPath.WaitForOffset(9, () => elapsed, () => { ++waitChecks; elapsed = 20; }, _ => ++waits);
        Check(waitChecks == 1 && waits == 0);
        var pair = Executor.KeyPair(0x57, false);
        var ledger = new InputLedger(events => { ++sends; return (uint)events.Length; }, stopped: () => cancelled);
        var receipt = new Receipt();
        // The receiver/provider changes cancellation after its initial check.
        Rejected(() => ledger.Send(pair, receipt, finalPreflight: () => cancelled = true));
        Check(sends == 0 && receipt.RequestedEvents == 0 && ledger.State == "released");
        Rejected(() => ledger.CheckMotionWait(() => true, System.Diagnostics.Stopwatch.StartNew(), 5000));
        int activationChecks = 0, activationWaits = 0;
        Executor.WaitActivationInputsReleased(() => activationWaits < 2,
            () => ++activationChecks, () => ++activationWaits);
        Check(activationChecks == 2 && activationWaits == 2 && sends == 0);
        Rejected(() => Executor.WaitActivationInputsReleased(() => true,
            () => throw new Boundary("input_stopped"), () => ++activationWaits));
        Check(sends == 0 && ledger.State == "released");
        var activationReceipt = new Receipt(); int authority = 0, targets = 0, retries = 0;
        Check(Executor.RecoverInitialActivation("foreground_changed", ledger, activationReceipt,
            () => ++authority, () => ++targets, () => ++retries));
        Check(authority == 1 && targets == 1 && retries == 1 && activationReceipt.ForegroundRecoveries == 1);
        Check(!Executor.RecoverInitialActivation("foreground_changed", ledger, activationReceipt,
            () => ++authority, () => ++targets, () => ++retries));
        Check(!Executor.RecoverInitialActivation("new_window_detected", ledger, new(),
            () => ++authority, () => ++targets, () => ++retries));
        var deniedActivation = new Receipt();
        Rejected(() => Executor.RecoverInitialActivation("foreground_changed", ledger, deniedActivation,
            () => throw new Boundary("input_stopped"), () => ++targets, () => ++retries));
        Check(deniedActivation.ForegroundRecoveries == 0 && targets == 1 && retries == 1 && sends == 0);
        cancelled = false;
        ledger.Send([pair[0]], receipt);
        Check(sends == 1 && ledger.State == "release_pending");
        Check(!Executor.RecoverInitialActivation("foreground_changed", ledger, new(),
            () => ++authority, () => ++targets, () => ++retries));
        int heldChecks = 0;
        ledger.CheckMotionWait(() => false, System.Diagnostics.Stopwatch.StartNew(), 5000, () => ++heldChecks);
        Check(heldChecks == 0);
        System.Threading.Thread.Sleep(85);
        ledger.CheckMotionWait(() => false, System.Diagnostics.Stopwatch.StartNew(), 5000, () => ++heldChecks);
        Check(heldChecks == 1);
        cancelled = true;
        Rejected(() => ledger.Send([pair[1]], receipt));
        ledger.Release(receipt); // Exact owned ups must remain possible on Stop.
        Check(sends == 2 && ledger.State == "released" && receipt.ReleaseEvents == 1);
        int checks = 0, preparationSends = 0; cancelled = false;
        var preparation = new InputLedger(events => { ++preparationSends; return (uint)events.Length; }, stopped: () => cancelled);
        Rejected(() => preparation.KeyboardUps([pair[1]], new Receipt(), () => { if (++checks == 2) cancelled = true; }));
        Check(preparationSends == 0);

        var core = new BrokerState();
        core.CheckInputWait(core.Revision);
        bool staleWait = false, staleFull = false;
        try { core.CheckInputWait(core.Revision - 1); } catch (Boundary error) { staleWait = error.Code == "fresh_broker_observation_required"; }
        try { core.Check(core.Revision - 1); } catch (Boundary error) { staleFull = error.Code == "fresh_broker_observation_required"; }
        Check(staleWait && staleFull);
        long before = core.ComputerStopGeneration;
        var old = new BrokerRequest { Channel = "flower-computer" };
        var app = new BrokerRequest { Channel = "flower-app" };
        core.RegisterInputRequest("old", old, before);
        core.RegisterInputRequest("app", app, before);
        core.StopComputerUse();
        Check(old.Stop.IsCancellationRequested && !app.Stop.IsCancellationRequested);
        var crossed = new BrokerRequest { Channel = "flower-computer" };
        Rejected(() => core.RegisterInputRequest("crossed", crossed, before));
        Check(!core.Requests.ContainsKey("crossed"));
        var fresh = new BrokerRequest { Channel = "flower-computer" };
        core.RegisterInputRequest("fresh", fresh, core.ComputerStopGeneration);
        Check(!fresh.Stop.IsCancellationRequested);
        // No request exists in this run's readback/dwell gap. Its captured
        // generation still fences every next step, including a new ActionId.
        core.Requests.Clear();
        long run = core.ComputerStopGeneration;
        core.StopComputerUse();
        var suffix = new BrokerRequest { Channel = "flower-computer", ActionId = "new-child" };
        Rejected(() => core.RegisterInputRequest("suffix", suffix, core.ComputerStopGeneration, run));
        Check(!core.Requests.ContainsKey("suffix"));
        var later = new BrokerRequest { Channel = "flower-computer" };
        core.RegisterInputRequest("later", later, core.ComputerStopGeneration, core.ComputerStopGeneration);
        Check(!later.Stop.IsCancellationRequested);
        var binding = new BrokerRequest { Channel = "flower-computer", ReadOnly = true };
        var metadata = new BrokerRequest { Channel = "flower-computer", ReadOnly = true };
        var launch = new BrokerRequest { Channel = "flower-computer", AdminLaunch = true };
        core.RegisterInputRequest("bind", binding, before);
        core.RegisterInputRequest("metadata", metadata, before);
        core.RegisterInputRequest("launch", launch, before);
        long beforePause = core.ComputerStopGeneration;
        core.SetComputerPaused(true);
        Check(core.ComputerPaused && core.ComputerStopGeneration > beforePause);
        Check(later.Stop.IsCancellationRequested);
        Check(!binding.Stop.IsCancellationRequested && !metadata.Stop.IsCancellationRequested && !launch.Stop.IsCancellationRequested);
        var pausedInput = new BrokerRequest { Channel = "flower-computer" };
        bool pausedRejected = false;
        try { core.RegisterInputRequest("paused-input", pausedInput, core.ComputerStopGeneration); }
        catch (Boundary error) { pausedRejected = error.Code == "computer_paused"; }
        Check(pausedRejected && !core.Requests.ContainsKey("paused-input"));
        var pausedRead = new BrokerRequest { Channel = "flower-computer", ReadOnly = true };
        var pausedApp = new BrokerRequest { Channel = "flower-app" };
        core.RegisterInputRequest("paused-read", pausedRead, before);
        core.RegisterInputRequest("paused-app", pausedApp, before);
        Check(!pausedRead.Stop.IsCancellationRequested && !pausedApp.Stop.IsCancellationRequested);
        core.SetComputerPaused(false);
        var staleAfterResume = new BrokerRequest { Channel = "flower-computer" };
        Rejected(() => core.RegisterInputRequest("stale-after-resume", staleAfterResume, core.ComputerStopGeneration, beforePause));
        core.StopComputerUse();
        Check(!pausedRead.Stop.IsCancellationRequested && !metadata.Stop.IsCancellationRequested && !pausedApp.Stop.IsCancellationRequested);
        foreach (var request in new[] { old, app, crossed, fresh, suffix, later, binding, metadata, launch, pausedInput, pausedRead, pausedApp, staleAfterResume }) request.Stop.Dispose();
        return new { assertions, productionStopTouched = false, inputDispatched = false,
            scope = "fake sender; request cancellation and private BrokerState admission only" };
    }
}
