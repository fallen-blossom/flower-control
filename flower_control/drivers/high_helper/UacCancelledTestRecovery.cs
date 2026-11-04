using System.Text.Json;

namespace Flower.HighHelper;

// Schema 2 proves a cancelled harmless test; schemas 3/4 retire only its control
// ownership while preserving unknown business. Schema 4 is limited to the
// pre-observation resource-open failure. Production and unknown input are
// never admitted by these recovery paths.
internal static class UacCancelledTestRecovery
{
    internal static bool PreobservationControlOnlyEvidenceMatches(UacClaimEntry entry, JsonElement worker, JsonElement test,
        string version, string image, string managed, string sid, int session)
    {
        static string? S(JsonElement e, string k) => UacOutcomeEvidence.Text(e, k);
        static bool T(JsonElement e, string k) => UacOutcomeEvidence.True(e, k);
        static bool F(JsonElement e, string k) => UacOutcomeEvidence.False(e, k);
        static bool Nil(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Null;
        static bool Hex32(string? value) => value is { Length: 32 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
        bool PeerMatches(JsonElement e, string user, int integrity) => JsonSerializer.Deserialize<Peer>(e) is { } p
            && p.Pid > 0 && p.Created > 0 && p.Session == session && p.User == user && p.Integrity == integrity && p.ImageDigest == image;
        try
        {
            string? nonce = S(test, "Nonce"), workerNonce = S(worker, "RequestNonce");
            bool accept = entry.TaskId == "uac_test_accept_" + nonce;
            if (!Hex32(nonce) || !Hex32(workerNonce) || !accept && entry.TaskId != "uac_test_cancel_" + nonce
                || entry.State != "unknown" || !entry.InputFree || entry.SourceDigest != image
                || entry.Reason != "test_elevation_result_unknown" || entry.Prompt is not null || entry.PromptRef is not null
                || test.GetProperty("Schema").GetInt32() != 1 || S(test, "Phase") != "uac_test"
                || S(worker, "Phase") != "uac" || S(worker, "TaskId") != entry.TaskId
                || S(worker, "Version") != version || S(worker, "ManagedHelperSha256") != managed
                || S(worker, "Action") != "none" || S(worker, "Authority") != "none" || S(worker, "Reason") != "resource_object_unavailable"
                || !T(worker, "ControlledExperiment") || S(worker, "TestNonce") != nonce || S(worker, "TestCommand") != (accept ? "accept" : "cancel")
                || S(worker, "PromptAttribution") != "fixed_test_exact_command" || !T(worker, "WorkerNoNativeDispatch")
                || S(worker, "WorkerNoNativeDispatchScope") != "confirmation_or_cancellation" || !F(worker, "InputDispatched")
                || !F(worker, "DetailsExpansionAttempted") || !F(worker, "DetailsExpansionReturned")
                || !T(worker, "WatchersEnded") || !F(worker, "PhysicalStopObserved") || !F(worker, "InputReplay") || !F(test, "InputReplay")
                || !Nil(worker, "NativeResult") || !Nil(worker, "PromptBefore") || !Nil(worker, "PromptInstanceGone")
                || worker.GetProperty("PromptReadyTick").GetInt64() != 0 || worker.GetProperty("ReadyWrittenTick").GetInt64() != 0
                || worker.GetProperty("GoReceivedTick").GetInt64() != 0
                || worker.GetProperty("WorkerStartedTick").GetInt64() <= 0
                || worker.GetProperty("WorkerEndedTick").GetInt64() < worker.GetProperty("WorkerStartedTick").GetInt64()
                || !Nil(worker, "StopPersistenceError") || !Nil(worker, "WatcherCleanupError") || !Nil(worker, "ProgramBindingCleanupError")
                || !Nil(worker, "ProgramQualificationSample") || !Nil(worker, "ProgramQualificationRegistration")
                || !Nil(test, "Business") || !Nil(test, "ControllerError") || !Nil(test, "QualificationIndex")) return false;
            var end = worker.GetProperty("StopMonitorEnd");
            if (S(end, "state") != "monitor_stopped" || !T(end, "desktop_cleanup_verified") || !T(end, "secure_stop_controller_completed")
                || !F(end, "continuous_stop_monitor_active") || !F(end, "input_dispatched")
                || end.GetProperty("secure_stop_controller_error").GetInt32() != 0) return false;
            var receipt = test.GetProperty("Receipt");
            if (S(receipt, "Phase") != "uac" || S(receipt, "TaskId") != entry.TaskId || S(receipt, "RequestNonce") != workerNonce
                || S(receipt, "Action") != "none" || S(receipt, "Authority") != "none" || S(receipt, "Reason") != "resource_object_unavailable"
                || S(receipt, "Version") != version || S(receipt, "ManagedHelperSha256") != managed
                || S(receipt, "BusinessResultError") != "deadline_expired" || !Nil(receipt, "BusinessResult")
                || !T(receipt, "WorkerNoNativeDispatch") || !F(receipt, "InputDispatched")
                || !T(receipt, "InputFree") || !T(receipt, "ControlComplete") || !T(receipt, "TestLauncherStarted") || !T(receipt, "BusinessLaunchAttempted")
                || !F(receipt, "InputReplay") || !Nil(receipt, "WorkerEvidenceSaveError") || !Nil(receipt, "RelayError")
                || !Nil(receipt, "QualificationHandshakeError") || !Nil(receipt, "QualificationCancelError")) return false;
            foreach (string field in new[] { "NativeResult", "PromptBefore", "PromptInstanceGone", "StopMonitorEnd", "Source", "Worker",
                "ControlledExperiment", "TestNonce", "TestCommand", "WorkerNoNativeDispatchScope", "DetailsExpansionAttempted",
                "DetailsExpansionReturned", "WatchersEnded", "PhysicalStopObserved", "PromptAttribution", "PromptReadyTick",
                "ReadyWrittenTick", "GoReceivedTick", "WorkerStartedTick", "WorkerEndedTick",
                "StopPersistenceError", "WatcherCleanupError", "ProgramBindingCleanupError", "ProgramQualificationSample", "ProgramQualificationRegistration" })
                if (!JsonElement.DeepEquals(receipt.GetProperty(field), worker.GetProperty(field))) return false;
            return PeerMatches(worker.GetProperty("Worker"), "S-1-5-18", 16384) && PeerMatches(worker.GetProperty("Source"), sid, 12288);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { return false; }
    }
    // Distinct control-only proof: a timed-out business oracle is NOT cancellation.
    // The launcher identity is unavailable; the High preparation must prove the
    // entire sealed fixed-test version's executor set absent instead.
    internal static bool ControlOnlyEvidenceMatches(UacClaimEntry entry, JsonElement worker, JsonElement test,
        string version, string image, string managed, string sid, int session)
    {
        static string? S(JsonElement e, string k) => UacOutcomeEvidence.Text(e, k);
        static bool T(JsonElement e, string k) => UacOutcomeEvidence.True(e, k);
        static bool F(JsonElement e, string k) => UacOutcomeEvidence.False(e, k);
        static bool Nil(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Null;
        bool PeerMatches(JsonElement e, string user, int integrity) => JsonSerializer.Deserialize<Peer>(e) is { } p
            && p.Pid > 0 && p.Created > 0 && p.Session == session && p.User == user && p.Integrity == integrity && p.ImageDigest == image;
        try
        {
            string? nonce = S(test, "Nonce");
            if (nonce is null || nonce.Length != 32 || !nonce.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) return false;
            bool accept = entry.TaskId == "uac_test_accept_" + nonce;
            if (!accept && entry.TaskId != "uac_test_cancel_" + nonce) return false;
            string action = accept ? "accept" : "esc", reason = accept ? "fixed_harmless_accept_test" : "fixed_harmless_cancel_test";
            if (entry.State != "unknown" || !entry.InputFree || entry.SourceDigest != image || entry.Prompt is not { } prompt
                || entry.Reason != "test_elevation_result_unknown" || test.GetProperty("Schema").GetInt32() != 1
                || S(test, "Phase") != "uac_test" || S(worker, "Phase") != "uac" || S(worker, "TaskId") != entry.TaskId
                || S(worker, "Action") != action || S(worker, "Authority") != "local_test" || S(worker, "Reason") != reason
                || S(worker, "Version") != version || S(worker, "ManagedHelperSha256") != managed
                || !T(worker, "WatchersEnded") || !F(worker, "InputReplay") || !F(test, "InputReplay")
                || !Nil(test, "Business") || !Nil(test, "ControllerError") || !Nil(test, "QualificationIndex")
                || !Nil(worker, "ProgramQualificationSample") || !Nil(worker, "ProgramQualificationRegistration")
                || !Nil(worker, "StopPersistenceError") || !Nil(worker, "WatcherCleanupError") || !Nil(worker, "ProgramBindingCleanupError")) return false;
            var native = worker.GetProperty("NativeResult"); var end = worker.GetProperty("StopMonitorEnd");
            if (S(native, "state") != "not_dispatched" || S(native, "action") != action || S(native, "route") is not ("uia_invoke" or "window_message")
                || !F(native, "input_dispatched") || !F(native, "uia_invoke_attempted") || !F(native, "uia_invoke_returned")
                || !T(native, "inserted_count_known") || !T(native, "desktop_cleanup_verified") || S(native, "input_release") != "not_required"
                || native.GetProperty("requested_events").GetInt32() != 0 || native.GetProperty("inserted_events").GetInt32() != 0
                || native.GetProperty("messages_queued").GetInt32() != 0 || !T(end, "desktop_cleanup_verified")
                || !T(end, "secure_stop_controller_completed") || !F(end, "continuous_stop_monitor_active")
                || end.GetProperty("secure_stop_controller_error").GetInt32() != 0) return false;
            var observation = worker.GetProperty("PromptBefore");
            if (observation.GetProperty("session").GetInt32() != session || prompt.Session != session
                || observation.GetProperty("pid").GetInt32() != prompt.Pid || observation.GetProperty("created").GetInt64() != prompt.Created
                || observation.GetProperty("hwnd").GetInt64() != prompt.Hwnd || S(observation, "observation_id") != entry.PromptRef
                || S(observation, "interactive_user_sid") != sid || S(observation, "desktop") != "Winlogon"
                || S(observation, "window_station") != "WinSta0") return false;
            var receipt = test.GetProperty("Receipt");
            if (S(receipt, "TaskId") != entry.TaskId || S(receipt, "RequestNonce") != S(worker, "RequestNonce")
                || S(receipt, "BusinessResultError") != "deadline_expired" || !Nil(receipt, "BusinessResult")
                || !T(receipt, "InputFree") || !T(receipt, "ControlComplete") || !T(receipt, "TestLauncherStarted")
                || !T(receipt, "BusinessLaunchAttempted") || !F(receipt, "InputReplay")
                || !Nil(receipt, "WorkerEvidenceSaveError") || !Nil(receipt, "RelayError")
                || !Nil(receipt, "QualificationHandshakeError") || !Nil(receipt, "QualificationCancelError")) return false;
            foreach (string field in new[] { "NativeResult", "PromptBefore", "StopMonitorEnd", "Source", "Worker" })
                if (!JsonElement.DeepEquals(receipt.GetProperty(field), worker.GetProperty(field))) return false;
            return PeerMatches(worker.GetProperty("Worker"), "S-1-5-18", 16384)
                && PeerMatches(worker.GetProperty("Source"), sid, 12288);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { return false; }
    }
    internal static bool EvidenceMatches(UacClaimEntry entry, JsonElement worker, JsonElement test,
        string version, string image, string managed, string sid, int session)
    {
        static string? S(JsonElement e, string k) => UacOutcomeEvidence.Text(e, k);
        static bool T(JsonElement e, string k) => UacOutcomeEvidence.True(e, k);
        static bool F(JsonElement e, string k) => UacOutcomeEvidence.False(e, k);
        static bool Nil(JsonElement e, string k) => e.TryGetProperty(k, out var value) && value.ValueKind == JsonValueKind.Null;
        static Peer P(JsonElement e) => JsonSerializer.Deserialize<Peer>(e)!;
        bool PeerMatches(Peer? p, string user, int integrity) => p is not null && p.Pid > 0 && p.Created > 0
            && p.Session == session && p.User == user && p.Integrity == integrity && p.ImageDigest == image;
        try
        {
            string? nonce = S(test, "Nonce");
            if (nonce is null || nonce.Length != 32 || !nonce.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
                || test.GetProperty("Schema").GetInt32() != 1 || S(test, "Phase") != "uac_test" || S(worker, "Phase") != "uac"
                || entry.State != "unknown" || !entry.InputFree || entry.SourceDigest != image
                || entry.Reason != "test_elevation_result_unknown" || entry.Prompt is not null
                || entry.TaskId != "uac_test_cancel_" + nonce && entry.TaskId != "uac_test_accept_" + nonce
                || S(worker, "TaskId") != entry.TaskId || S(worker, "Version") != version
                || S(worker, "ManagedHelperSha256") != managed || S(worker, "Action") != "none"
                || !T(worker, "WorkerNoNativeDispatch") || !T(worker, "WatchersEnded") || !F(worker, "InputReplay")
                || !Nil(worker, "StopPersistenceError") || !Nil(worker, "WatcherCleanupError") || !Nil(worker, "ProgramBindingCleanupError")) return false;
            var native = worker.GetProperty("NativeResult"); var end = worker.GetProperty("StopMonitorEnd");
            if (!F(native, "input_dispatched") || !T(end, "desktop_cleanup_verified")
                || !T(end, "secure_stop_controller_completed") || !F(end, "continuous_stop_monitor_active")
                || end.GetProperty("secure_stop_controller_error").GetInt32() != 0) return false;
            var receipt = test.GetProperty("Receipt"); var business = test.GetProperty("Business");
            if (S(receipt, "TaskId") != entry.TaskId || S(receipt, "RequestNonce") != S(worker, "RequestNonce")
                || !T(receipt, "WorkerNoNativeDispatch") || !T(receipt, "InputFree")
                || !F(test, "InputReplay") || !F(receipt, "InputReplay") || !Nil(test, "ControllerError")
                || !Nil(receipt, "WorkerEvidenceSaveError") || !Nil(receipt, "RelayError")
                || !Nil(receipt, "BusinessResultError") || !Nil(receipt, "QualificationHandshakeError")
                || !Nil(receipt, "QualificationCancelError") || !JsonElement.DeepEquals(receipt.GetProperty("NativeResult"), native)
                || !JsonElement.DeepEquals(receipt.GetProperty("StopMonitorEnd"), end)
                || !JsonElement.DeepEquals(receipt.GetProperty("BusinessResult"), business)
                || S(business, "Nonce") != nonce || S(business, "Status") != "business_cancelled"
                || business.GetProperty("Win32Error").GetInt32() != 1223 || !Nil(business, "Target") || !Nil(business, "ExitCode")) return false;
            var source = P(worker.GetProperty("Source")); var executor = P(worker.GetProperty("Worker"));
            return PeerMatches(source, sid, 12288) && PeerMatches(executor, "S-1-5-18", 16384)
                && PeerMatches(P(business.GetProperty("Launcher")), sid, 8192)
                && P(receipt.GetProperty("Source")) == source && P(receipt.GetProperty("Worker")) == executor;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { return false; }
    }
}
