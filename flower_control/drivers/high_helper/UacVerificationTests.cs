using System.Text.Json;
using System.Text.Json.Nodes;
namespace Flower.HighHelper;

internal static class UacVerificationTests
{
    internal static object Run()
    {
        int count = 0;
        void Check(bool value) { ++count; if (!value) throw new Boundary("uac_verification_selftest_failed"); }
        var hash = new string('a', 64); var nonce = new string('b', 32);
        var binding = new UacVerificationBinding(new string('c', 32), hash, hash, hash, hash, "test-build", "S-1-5-21-1", 1);
        var source = new Peer(1, 1, 1, binding.UserSid, hash, 12288);
        var worker = new Peer(2, 2, 1, "S-1-5-18", hash, 16384);
        var launcher = source with { Pid = 3, Integrity = 8192 };
        var business = new UacTestResult(nonce, launcher, "business_cancelled", 1223, null, null);
        JsonObject Stop() => JsonSerializer.SerializeToNode(new {
            // Reconstructed producer envelope from b31 worker/test shapes;
            // fake identities and a new synthetic Binding, never a b31 attestation.
            Phase = "uac", Authority = "local_test", Reason = "explicit_stop", BusinessResult = "unverified", InputReplay = false,
            ManagedHelperSha256 = hash, StopPersistenceError = (string?)null, WatcherCleanupError = (string?)null,
            ProgramBindingCleanupError = (string?)null, ProgramQualificationSample = (object?)null,
            ProgramQualificationRegistration = (object?)null, StopMonitorStart = new { continuous_stop_monitor_active = true },
            PromptInstanceGone = (bool?)null,
            VerificationBinding = binding, Version = binding.Version, ControlledExperiment = true,
            TestCommand = "stop", TestNonce = nonce, RequestNonce = new string('d', 32), TaskId = "uac_test_stop_" + nonce,
            Worker = worker, Source = source, PhysicalStopObserved = true, WorkerNoNativeDispatch = true,
            Action = "none", WatchersEnded = true, StopMonitorAttempted = true,
            PromptBefore = new { desktop = "Winlogon" }, StopState = new { Stopped = true, Epoch = 2 }, InitialStopEpoch = 1,
            NativeResult = new { input_dispatched = false, desktop_cleanup_verified = true },
            StopMonitorEnd = new { desktop_cleanup_verified = true, secure_stop_controller_error = 0,
                secure_stop_controller_completed = true, secure_stop_signal_succeeded = true,
                secure_stop_cancel_signal_succeeded = true, secure_stop_hotkey_received = false, secure_stop_key_polling = true }
        })!.AsObject();
        var report = Stop(); Check(UacVerification.StopConsistent(report, business));
        foreach (var field in new[] { "PhysicalStopObserved", "WorkerNoNativeDispatch", "WatchersEnded" })
        { var changed = Stop(); changed[field] = false; Check(!UacVerification.StopConsistent(changed, business)); }
        foreach (var field in new[] { "secure_stop_signal_succeeded", "secure_stop_cancel_signal_succeeded", "desktop_cleanup_verified" })
        { var changed = Stop(); changed["StopMonitorEnd"]![field] = false; Check(!UacVerification.StopConsistent(changed, business)); }
        var unstopped = Stop(); unstopped["StopState"]!["Stopped"] = false; Check(!UacVerification.StopConsistent(unstopped, business));
        var oldEpoch = Stop(); oldEpoch["StopState"]!["Epoch"] = 1; Check(!UacVerification.StopConsistent(oldEpoch, business));
        Check(!UacVerification.StopConsistent(report, business with { Status = "unknown" }));
        Check(!UacVerification.StopConsistent(report, business with { Target = source }));
        Check(!UacVerification.StopConsistent(report, null));
        var receipt = report.DeepClone().AsObject(); receipt["InputFree"] = true; receipt["ControlComplete"] = true;
        receipt["BusinessResult"] = JsonSerializer.SerializeToNode(business);
        foreach (var name in new[] { "WorkerEvidenceSaveError", "QualificationHandshakeError", "QualificationCancelError", "BusinessResultError", "RelayError", "PromptRef" }) receipt[name] = null;
        receipt["TestLauncherStarted"] = true; receipt["BusinessLaunchAttempted"] = true;
        var test = JsonSerializer.SerializeToNode(new { Schema = 1, Phase = "uac_test", InputReplay = false, Nonce = nonce, Receipt = receipt, Business = business })!.AsObject();
        JsonElement Element(JsonNode node) => JsonSerializer.SerializeToElement(node);
        Check(UacVerification.Matches("stop", Element(test), Element(report), binding));
        Check(!UacVerification.Matches("accept", Element(test), Element(report), binding));
        Check(!UacVerification.Matches("stop", Element(test), Element(report), binding with { ManagedHelperSha256 = new string('e', 64) }));
        Check(!UacVerification.Matches("stop", Element(test), Element(report), binding with { Session = 2 }));
        var fake = test.DeepClone(); fake["Receipt"]!["PhysicalStopObserved"] = false;
        Check(!UacVerification.Matches("stop", Element(fake), Element(report), binding));
        var elevatedLauncher = test.DeepClone(); elevatedLauncher["Business"]!["Launcher"]!["Integrity"] = 12288;
        Check(!UacVerification.Matches("stop", Element(elevatedLauncher), Element(report), binding));
        var missing = report.DeepClone(); missing.AsObject().Remove("VerificationBinding");
        Check(!UacVerification.Matches("stop", Element(test), Element(missing), binding));
        foreach (var command in new[] { "cancel", "accept" })
        {
            var actionWorker = Stop(); actionWorker["TestCommand"] = command;
            actionWorker["TaskId"] = "uac_test_" + command + "_" + nonce;
            actionWorker["Action"] = command == "cancel" ? "esc" : "accept";
            actionWorker["WorkerNoNativeDispatch"] = false; actionWorker["PromptInstanceGone"] = true;
            actionWorker["NativeResult"] = JsonSerializer.SerializeToNode(new {
                action = command == "cancel" ? "esc" : "accept", input_dispatched = true,
                route = command == "cancel" ? "window_message" : "uia_invoke", messages_queued = 2,
                uia_invoke_returned = command == "accept", desktop_cleanup_verified = true });
            var outcome = command == "cancel" ? business : business with { Status = "high_target_exited_zero", Win32Error = 0, Target = source, ExitCode = 0 };
            JsonObject ActionTest(JsonObject original)
            {
                var copied = original.DeepClone().AsObject(); copied["InputFree"] = true; copied["ControlComplete"] = true;
                foreach (var name in new[] { "WorkerEvidenceSaveError", "QualificationHandshakeError", "QualificationCancelError", "BusinessResultError", "RelayError", "PromptRef" }) copied[name] = null;
                copied["TestLauncherStarted"] = true; copied["BusinessLaunchAttempted"] = true;
                copied["BusinessResult"] = JsonSerializer.SerializeToNode(outcome);
                return JsonSerializer.SerializeToNode(new { Schema = 1, Phase = "uac_test", InputReplay = false, Nonce = nonce, Receipt = copied, Business = outcome })!.AsObject();
            }
            Check(UacVerification.Matches(command, Element(ActionTest(actionWorker)), Element(actionWorker), binding));
            actionWorker["PromptInstanceGone"] = false;
            Check(!UacVerification.Matches(command, Element(ActionTest(actionWorker)), Element(actionWorker), binding));
            actionWorker["PromptInstanceGone"] = true;
            actionWorker["NativeResult"]![command == "cancel" ? "input_dispatched" : "uia_invoke_returned"] = false;
            Check(!UacVerification.Matches(command, Element(ActionTest(actionWorker)), Element(actionWorker), binding));
        }
        // Exact producer transformation is allowed only for BusinessResult.
        var wrongPlaceholder = report.DeepClone(); wrongPlaceholder["BusinessResult"] = "verified";
        Check(!UacVerification.Matches("stop", Element(test), Element(wrongPlaceholder), binding));
        foreach (var role in new[] { "Worker", "Source" })
            foreach (var field in new[] { "Pid", "Created" })
            { var invalid = report.DeepClone(); invalid[role]![field] = 0;
              Check(!UacVerification.Matches("stop", Element(test), Element(invalid), binding)); }
        foreach (var document in new[] { "test", "worker" })
        { var changedTest = test.DeepClone(); var changedWorker = report.DeepClone();
          (document == "test" ? changedTest : changedWorker)["InputReplay"] = true;
          Check(!UacVerification.Matches("stop", Element(changedTest), Element(changedWorker), binding)); }
        var changedBusiness = test.DeepClone(); changedBusiness["Receipt"]!["BusinessResult"]!["Win32Error"] = 0;
        Check(!UacVerification.Matches("stop", Element(changedBusiness), Element(report), binding));
        var fixture = Path.Combine(Path.GetTempPath(), "flower-uac-verification-files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        var destination = Path.Combine(fixture, "capability.json");
        Check(!UacVerification.ExistingWriteTarget(fixture, destination));
        var first = Path.Combine(fixture, "first.tmp"); File.WriteAllText(first, "first");
        UacVerification.CommitPrepared(fixture, first, destination, false);
        Check(File.ReadAllText(destination) == "first" && !File.Exists(first));
        Check(UacVerification.ExistingWriteTarget(fixture, destination));
        var second = Path.Combine(fixture, "second.tmp"); File.WriteAllText(second, "second");
        UacVerification.CommitPrepared(fixture, second, destination, true);
        Check(File.ReadAllText(destination) == "second" && !File.Exists(second));
        Check(Directory.GetFiles(fixture, "*.previous").Length == 1
            && File.ReadAllText(Directory.GetFiles(fixture, "*.previous")[0]) == "first");
        var racing = Path.Combine(fixture, "racing.tmp"); File.WriteAllText(racing, "racing");
        bool changedRejected = false;
        try { UacVerification.CommitPrepared(fixture, racing, destination, false); }
        catch (Boundary error) when (error.Code == "uac_verification_destination_changed") { changedRejected = true; }
        Check(changedRejected && File.ReadAllText(destination) == "second" && File.Exists(racing));
        bool directoryRejected = false;
        var child = Path.Combine(fixture, "directory"); Directory.CreateDirectory(child);
        try { UacVerification.ExistingWriteTarget(fixture, child); }
        catch (Boundary error) when (error.Code == "installation_link_rejected") { directoryRejected = true; }
        Check(directoryRejected);
        bool siblingRejected = false;
        try { UacVerification.ExistingWriteTarget(child, destination); }
        catch (Boundary error) when (error.Code == "uac_verification_destination_rejected") { siblingRejected = true; }
        Check(siblingRejected);
        // These are actual OS-temp filesystem transitions, not High ACL or
        // production capability writes. Keep the tiny evidence files intact.
        return new { assertions = count, SyntheticAuthorityEvidenceOnly = true, RealFilesystemFixture = fixture,
            SystemExecuted = false, InputDispatched = false, ProductionEnabled = false };
    }
}
