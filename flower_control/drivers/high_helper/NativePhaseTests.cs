using System.Diagnostics;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class NativePhaseTests
{
    internal static int Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("native_phase_selftest_failed"); }
        void Rejected(Action action, string code)
        {
            try { action(); Require(false); }
            catch (Boundary error) { Require(error.Code == code); }
        }
        var measured = new Receipt();
        measured.TimingsMs["dispatch"] = 5;
        PointerPath.MeasureApproach(measured, () => measured.TimingsMs["dispatch"] += 3, () => 10);
        Require(measured.TimingsMs["dispatch"] == 8 && measured.TimingsMs["pointer_approach"] == 7);
        PointerPath.MeasureApproach(measured, () => measured.TimingsMs["dispatch"] += 2, () => 4);
        Require(measured.TimingsMs["dispatch"] == 10 && measured.TimingsMs["pointer_approach"] == 9);
        Rejected(() => PointerPath.MeasureApproach(measured, () => {
            measured.TimingsMs["dispatch"] += 1; throw new Boundary("partial_fixture");
        }, () => 8), "partial_fixture");
        Require(measured.TimingsMs["dispatch"] == 11 && measured.TimingsMs["pointer_approach"] == 16);
        PointerPath.MeasureApproach(measured, () => {}, () => .25);
        Require(measured.TimingsMs["pointer_approach"] == 16.25);
        Require(UacHostHook.HostFailureReason("work_host_message_source_unavailable") == "work_host_message_source_unavailable");
        Require(UacHostHook.HostFailureReason("semantic_delegation_changed") == "semantic_delegation_changed");
        Require(UacHostHook.HostFailureReason("uac_prompt_broker_unavailable") == "uac_prompt_broker_unavailable");
        Require(UacHostHook.HostFailureReason("process_unavailable") == "process_unavailable");
        foreach (var reason in new[] { "image_unavailable", "client_user_session_rejected", "flower_entry_rejected",
            "codex_launch_chain_unverified", "native_host_image_changed", "dsh_direct_host_required" })
        {
            Require(UacHostHook.HostFailureReason(reason) == reason);
            var failure = UacHostHook.Failure(new Boundary(reason), "admission");
            Require(failure.State == "unavailable" && failure.Reason == reason && failure.Stage == "admission");
        }
        Require(UacHostHook.HostFailureReason("private/path or prompt") == "uac_prompt_record_unconfirmed");
        Require(UacHostHook.HostFailureReason("uac_" + new string('x', 71)) == "uac_prompt_record_unconfirmed");
        Require(Native.ShellDesktopIdentity(10, 10, "Progman", 20, 20, true));
        Require(Native.ShellDesktopIdentity(11, 10, "WorkerW", 20, 20, true));
        Require(!Native.ShellDesktopIdentity(11, 10, "WorkerW", 21, 20, true));
        Require(!Native.ShellDesktopIdentity(11, 10, "WorkerW", 20, 20, false));
        Require(!Native.ShellDesktopIdentity(11, 10, "CabinetWClass", 20, 20, true));
        Require(!Native.ShellDesktopIdentity(11, 0, "WorkerW", 20, 20, true));
        var latch = new ForegroundEventLatch(10, hwnd => hwnd == 10);
        latch.Observe(3, 10, 0, 0); latch.Check();
        latch.Observe(3, 11, 0, 0); latch.Observe(3, 10, 0, 0);
        Rejected(latch.Check, "foreground_changed"); // A later sample at the target must not erase history.
        latch.Observe(0x16, 10, 0, 0);
        Require(latch.Reason == "foreground_changed");
        var minimized = new ForegroundEventLatch(10, hwnd => hwnd == 10);
        minimized.Observe(0x16, 11, 0, 0); minimized.Observe(0x16, 10, -4, 0); minimized.Check();
        minimized.Observe(0x16, 10, 0, 0); minimized.Observe(0x17, 10, 0, 0); minimized.Observe(3, 10, 0, 0);
        Rejected(minimized.Check, "target_minimized");
        var destroyed = new ForegroundEventLatch(10, hwnd => hwnd == 10);
        destroyed.Observe(0x8001, 10, 0, 1); destroyed.Check();
        destroyed.Observe(0x8001, 10, 0, 0); Rejected(destroyed.Check, "target_identity_changed");
        bool invoked = false;
        var popup = new ForegroundEventLatch(10, hwnd => hwnd == 10 || invoked && hwnd == 12);
        invoked = true; popup.Observe(3, 12, 0, 0); popup.Observe(3, 10, 0, 0); popup.Check();
        popup.Observe(3, 13, 0, 0); popup.Observe(3, 12, 0, 0);
        Rejected(popup.Check, "foreground_changed"); // An unrelated same-process/protected window is not the allowed modal.
        invoked = false;
        var earlyPopup = new ForegroundEventLatch(10, hwnd => hwnd == 10 || invoked && hwnd == 12);
        earlyPopup.Observe(3, 12, 0, 0); invoked = true;
        Rejected(earlyPopup.Check, "foreground_changed");
        string PopupReason(long hwnd) => hwnd == 12 ? "new_window_detected" : "foreground_changed";
        // The initial activation retry must consult the original history,
        // including an owned popup that already returned to the parent.
        var initialHistory = new ForegroundEventLatch(10, hwnd => hwnd != 12, rejectedForeground: PopupReason);
        initialHistory.Observe(3, 13, 0, 0); initialHistory.Check();
        initialHistory.Observe(3, 12, 0, 0); initialHistory.Observe(3, 10, 0, 0);
        int initialRetries = 0;
        var initialReceipt = new Receipt(); var initialLedger = new InputLedger(_ => throw new Exception("no input expected"));
        Rejected(() => Executor.RecoverInitialActivation("foreground_changed", initialLedger, initialReceipt,
            () => { }, initialHistory.Check, () => ++initialRetries), "new_window_detected");
        Require(initialRetries == 0 && initialReceipt.ForegroundRecoveries == 0);
        var ordinaryInitial = new ForegroundEventLatch(10, _ => true);
        ordinaryInitial.Observe(3, 13, 0, 0); ordinaryInitial.Observe(3, 10, 0, 0);
        Require(Executor.RecoverInitialActivation("foreground_changed", initialLedger, initialReceipt,
            () => { }, ordinaryInitial.Check, () => ++initialRetries));
        Require(initialRetries == 1 && !Executor.RecoverInitialActivation("foreground_changed", initialLedger, initialReceipt,
            () => { }, ordinaryInitial.Check, () => ++initialRetries));
        var failedInitial = new ForegroundEventLatch(10, _ => true);
        failedInitial.Fault("foreground_watch_failed");
        Rejected(() => Executor.RecoverInitialActivation("foreground_changed", initialLedger, new Receipt(),
            () => { }, failedInitial.Check, () => ++initialRetries), "foreground_watch_failed");
        Require(initialRetries == 1);
        var phase = new Dictionary<string, object> { ["session_id"] = "synthetic-root", ["instance_id"] = new string('a', 32),
            ["event_seq"] = 1, ["kind"] = "turn_end",
            ["observed_ns"] = ((ulong)((decimal)Stopwatch.GetTimestamp() * 1000000000 / Stopwatch.Frequency)).ToString() };
        DshPhaseHook.Validate(JsonSerializer.SerializeToElement(phase)); Require(true);
        foreach (var invalid in new (string Key, object Value)[] { ("event_seq", true), ("event_seq", -1),
            ("event_seq", 9007199254740992L), ("instance_id", "arbitrary"), ("session_id", " root"),
            ("kind", "resume"), ("observed_ns", "NaN"), ("observed_ns", "999999999999999999999"), ("grant", true) })
        {
            var malformed = new Dictionary<string, object>(phase) { [invalid.Key] = invalid.Value };
            Rejected(() => DshPhaseHook.Validate(JsonSerializer.SerializeToElement(malformed)), "dsh_phase_rejected");
        }
        phase["observed_ns"] = "0";
        Rejected(() => DshPhaseHook.Validate(JsonSerializer.SerializeToElement(phase)), "dsh_phase_expired");
        foreach (var (kind, implicitActivation) in new[] { ("computer_input_plan", false), ("activate", true) })
        {
            int keyboardUps = 0, activations = 0, business = 0;
            Rejected(() => {
                Executor.RequireActivationTarget(kind, implicitActivation, () => true);
                ++keyboardUps; ++activations; ++business;
            }, "new_window_detected");
            Require(keyboardUps == 0 && activations == 0 && business == 0);
            Executor.RequireActivationTarget(kind, implicitActivation, () => false);
        }
        Executor.RequireActivationTarget("activate", false, () => true); // Explicit activation remains available.
        foreach (bool ordinaryAwayFirst in new[] { false, true })
        {
            int suffixEvents = 0, popupRestores = 0;
            var suffix = new ForegroundEventLatch(10, hwnd => hwnd == 10,
                rejectedForeground: PopupReason);
            if (ordinaryAwayFirst) suffix.Observe(3, 13, 0, 0);
            suffix.Observe(3, 12, 0, 0); suffix.Observe(3, 10, 0, 0);
            var popupPriority = new ForegroundPriority(() => "released", () => { },
                () => ++popupRestores, () => { });
            Rejected(() => { popupPriority.Check(suffix.Check); ++suffixEvents; }, "new_window_detected");
            Require(suffixEvents == 0 && popupRestores == 0);
        }
        bool suffixPending = true;
        var guardedPopup = new ForegroundEventLatch(10,
            hwnd => hwnd == 10 || invoked && !suffixPending && hwnd == 12,
            rejectedForeground: PopupReason);
        invoked = true; guardedPopup.Observe(3, 12, 0, 0); suffixPending = false;
        Rejected(guardedPopup.Check, "new_window_detected");
        var invokeDrain = new ForegroundEventLatch(10,
            hwnd => hwnd == 10 || invoked && !suffixPending && hwnd == 12,
            rejectedForeground: PopupReason);
        invokeDrain.Observe(3, 12, 0, 0); invokeDrain.Observe(3, 10, 0, 0); invokeDrain.Check();
        Require(invokeDrain.Reason is null);
        long closingTime = 0;
        var closeDrain = new AppCloseDrain(() => closingTime);
        Require(!closeDrain.Allows(false, false));
        Require(closeDrain.Allows(false, true));
        closingTime = 250; Require(closeDrain.Allows(false, true));
        closingTime = 251; Require(closeDrain.Allows(false, true));
        closingTime = 2000; Require(closeDrain.Allows(false, true));
        Require(closeDrain.Allows(true, true));
        Require(!closeDrain.Allows(true, false));
        Require(AppCloseDrain.HiddenTargetCanDrain(true, true, false, true, true));
        Require(!AppCloseDrain.HiddenTargetCanDrain(false, true, false, true, true));
        Require(!AppCloseDrain.HiddenTargetCanDrain(true, true, true, true, true));
        Require(!AppCloseDrain.HiddenTargetCanDrain(true, true, false, false, true));
        Require(!AppCloseDrain.HiddenTargetCanDrain(true, true, false, true, false));
        int destroyCallbacks = 0;
        bool originalInvokeSent = false;
        var teardownDrain = new AppCloseDrain(() => closingTime);
        closingTime = 1000;
        var destroyingChild = new ForegroundEventLatch(10, hwnd => hwnd == 10 || hwnd == 12,
            () => { ++destroyCallbacks; return originalInvokeSent && teardownDrain.Allows(false, true); });
        destroyingChild.Observe(0x8001, 13, 0, 0);
        Require(destroyCallbacks == 0); // A sibling destroy cannot arm this original target.
        originalInvokeSent = true;
        destroyingChild.Observe(0x8001, 10, 0, 0); destroyingChild.Check();
        Require(destroyCallbacks == 1 && teardownDrain.TransitionStarted);
        closingTime = 1251;
        destroyingChild.Observe(0x8001, 10, 0, 0);
        destroyingChild.Check(); // Normal delayed teardown still drains the original Invoke.
        Require(teardownDrain.Allows(true, true));
        var ownActivity = new InputActivityLatch();
        ownActivity.Observe(true, InputActivityLatch.OwnTag);
        ownActivity.Observe(false, InputActivityLatch.OwnTag); ownActivity.Check();
        Require(true);
        ownActivity.Observe(true, UIntPtr.Zero);
        Rejected(ownActivity.Check, "external_keyboard_activity");
        var mouseActivity = new InputActivityLatch(); mouseActivity.Observe(false, UIntPtr.Zero);
        Rejected(mouseActivity.Check, "external_mouse_activity");
        string releaseState = "released"; int restores = 0, restarts = 0, authorityChecks = 0;
        var priority = new ForegroundPriority(() => releaseState, () => ++authorityChecks,
            () => ++restores, () => ++restarts);
        bool switched = true; int checks = 0;
        priority.Check(() => { ++checks; if (switched) { switched = false; throw new Boundary("foreground_changed"); } });
        Require(restores == 1 && restarts == 1 && checks == 2 && authorityChecks == 3);
        Require(!priority.Recover("foreground_changed")); // Repeated switching never creates a focus loop.
        foreach (string state in new[] { "release_pending", "unknown" })
        {
            releaseState = state;
            var heldPriority = new ForegroundPriority(() => releaseState, () => ++authorityChecks,
                () => ++restores, () => ++restarts);
            Require(!heldPriority.Recover("foreground_changed"));
        }
        releaseState = "released";
        foreach (string reason in new[] { "input_stopped", "target_identity_changed", "user_policy_invalid", "input_partial", "new_window_detected" })
        {
            var blockedPriority = new ForegroundPriority(() => releaseState, () => ++authorityChecks,
                () => ++restores, () => ++restarts);
            Require(!blockedPriority.Recover(reason));
        }
        var deniedPriority = new ForegroundPriority(() => "released", () => throw new Boundary("input_stopped"),
            () => ++restores, () => ++restarts);
        Rejected(() => deniedPriority.Recover("foreground_changed"), "input_stopped");
        Require(restores == 1 && restarts == 1);
        var keyboardUpsLedger = new InputLedger(events => {
            Require(events.All(value => value.Type == 1 && (value.Data.Key.Flags & 2) != 0));
            return (uint)events.Length;
        });
        var keyboardReceipt = new Receipt();
        keyboardUpsLedger.KeyboardUps([Executor.KeyPair(17, false)[1]], keyboardReceipt, () => ++authorityChecks);
        Require(keyboardReceipt.KeyboardReleaseEvents == 1 && keyboardReceipt.BusinessEvents == 0
            && keyboardReceipt.SentEvents == 1 && keyboardUpsLedger.State == "released");
        Rejected(() => keyboardUpsLedger.KeyboardUps([Executor.KeyPair(17, false)[0]], keyboardReceipt, () => { }),
            "keyboard_preparation_requires_ups");
        var unknownUps = new InputLedger(_ => throw new Boundary("synthetic_send_unknown"));
        Rejected(() => unknownUps.KeyboardUps([Executor.KeyPair(17, false)[1]], new Receipt(), () => { }), "synthetic_send_unknown");
        Require(unknownUps.State == "unknown");
        var own = Native.Process(Environment.ProcessId).Identity;
        var target = new Target(30, 10, 20, own.Session, own.ImageDigest, own.Integrity, 1, [0, 0, 100, 100]);
        var bound = new Bound(30, 10, 20, 1);
        var done = new ShellWorkerDone("done", own, bound, new string('a', 64), true, true, null, null);
        using (var valid = JsonDocument.Parse(JsonSerializer.Serialize(done))) Require(ShellDesktopWorker.DecodeDone(valid) == done);
        using (var invalid = JsonDocument.Parse(JsonSerializer.Serialize(done with { Requested = false })))
            Rejected(() => ShellDesktopWorker.DecodeDone(invalid), "shell_worker_result_rejected");
        using (var invalid = JsonDocument.Parse(JsonSerializer.Serialize(done with { Completed = false })))
            Rejected(() => ShellDesktopWorker.DecodeDone(invalid), "shell_worker_result_rejected");
        using (var interrupted = JsonDocument.Parse(JsonSerializer.Serialize(done with { Completed = false, Reason = "shell_activation_failed" })))
            Require(ShellDesktopWorker.DecodeDone(interrupted).Requested);
        using (var extra = JsonDocument.Parse(JsonSerializer.Serialize(done)[..^1] + ",\"BusinessEvents\":0}"))
            Rejected(() => ShellDesktopWorker.DecodeDone(extra), "shell_worker_result_rejected");

        // Worker completion during a slow guard must not add a 10ms sleep.
        bool metadataDone = false; int metadataChecks = 0, metadataDelays = 0;
        PasswordMetadata.WaitForResponse(() => metadataDone, () => { metadataChecks++; metadataDone = true; },
            () => 0, _ => metadataDelays++);
        Require(metadataChecks == 1 && metadataDelays == 0);
        metadataDone = false; metadataChecks = metadataDelays = 0;
        PasswordMetadata.WaitForResponse(() => metadataDone, () => metadataChecks++, () => 0,
            delay => { Require(delay == 10); metadataDelays++; metadataDone = true; });
        Require(metadataChecks == 1 && metadataDelays == 1);
        Rejected(() => PasswordMetadata.WaitForResponse(() => false, () => throw new Boundary("input_stopped"),
            () => 0, _ => throw new Exception("stop_must_prevent_sleep")), "input_stopped");
        Rejected(() => PasswordMetadata.WaitForResponse(() => false, () => { }, () => 2500,
            _ => throw new Exception("expiry_must_prevent_sleep")), "privacy_password_scan_incomplete");

        // Exercise the actual fixed worker's EOF and invalid-operation paths.
        // Both reject before any target/UI/COM operation; no foreground input.
        foreach (var eof in new[] { true, false })
        {
            var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"))
            { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            info.ArgumentList.Add("--shell-desktop-worker");
            using var child = new OwnedChild(info);
            if (!eof)
            {
                var prepare = new Prepare("prepare", own, target, new Operation("bind"), [], 1000);
                Protocol.Write(child.Process.StandardInput.BaseStream, new ShellWorkerRequest(own, prepare, new string('b', 64), 0, 1000));
            }
            child.Process.StandardInput.Close();
            Require(child.Process.WaitForExit(5000));
            Require(child.Process.ExitCode == 2 && child.Process.StandardOutput.ReadToEnd() == "");
            using var error = JsonDocument.Parse(child.Process.StandardError.ReadToEnd());
            Require(error.RootElement.GetProperty("reason").GetString() == (eof ? "shell_worker_disconnected" : "shell_worker_parent_rejected"));
        }
        return assertions;
    }
}
