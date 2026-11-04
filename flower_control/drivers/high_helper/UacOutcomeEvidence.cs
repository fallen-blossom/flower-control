using System.Text.Json;

namespace Flower.HighHelper;

// These are separate facts: our input resources, the exact consent instance,
// and the program started by ShellExecute. None implies the other two.
internal static class UacOutcomeEvidence
{
    internal static bool CommandRouteAvailable(string mode, string command, UacCapabilities capabilities)
        => command == "release" || (mode is "observe" or "cancel" or "allowlist" or "semantic") && command == "observe" && capabilities.ObserveAvailable
            || (mode is "cancel" or "allowlist" or "semantic") && command == "reserve"
            || command == "cancel" && RouteAvailable(mode, "esc", capabilities)
            || command == "accept" && RouteAvailable(mode, "accept", capabilities)
            || command == "auto" && (RouteAvailable(mode, "esc", capabilities) || RouteAvailable(mode, "accept", capabilities));
    internal static bool AuthorityRouteAvailable(string mode, string action, string authority, UacCapabilities capabilities, bool needsProgramBinding = false)
        => RouteAvailable(mode, action, capabilities) && (!needsProgramBinding || capabilities.ProgramBindingAvailable)
            && (action != "accept"
            // Semantic work / original-launch / prompt causality is not yet
            // implemented. It cannot borrow the local allowlist route.
            || authority == "local_allowlist"
                && capabilities.AllowlistAvailable && capabilities.ProgramBindingAvailable);
    internal static bool RouteAvailable(string mode, string action, UacCapabilities capabilities) => action == "esc"
        ? (mode is "cancel" or "allowlist" or "semantic") && capabilities.CancelAvailable
        : action == "accept" && capabilities.CancelAvailable
            && mode == "allowlist" && capabilities.AllowlistAvailable && capabilities.ProgramBindingAvailable;
    internal static bool True(JsonElement value, string field) => value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(field, out var item) && item.ValueKind == JsonValueKind.True;
    internal static bool False(JsonElement value, string field) => value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(field, out var item) && item.ValueKind == JsonValueKind.False;
    internal static string? Text(JsonElement value, string field) => value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(field, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
    // Dismissal belongs only to the selected consent instance. It does not
    // establish ShellExecute ERROR_CANCELLED or any original business result.
    internal static bool PromptDismissed(string action, bool? instanceGone, JsonElement native)
        => action == "esc" && instanceGone == true && True(native, "input_dispatched")
            && Text(native, "route") == "window_message"
            && native.TryGetProperty("messages_queued", out var count) && count.TryGetInt32(out var sent) && sent == 2;
    internal static bool? InputDispatched(bool bridgeSent, JsonElement? originalReport)
    {
        if (!bridgeSent) return false; // No worker request was sent this time.
        if (originalReport is not { } report) return null;
        if (report.TryGetProperty("NativeResult", out var native) && native.ValueKind == JsonValueKind.Object)
        {
            if (True(native, "input_dispatched")) return true;
            if (False(native, "input_dispatched")) return false;
        }
        return True(report, "WorkerNoNativeDispatch") || True(report, "NoWorkerActions") ? false : null;
    }
    internal static bool InputFree(bool goSent, JsonElement report)
    {
        if (!goSent || True(report, "WorkerNoNativeDispatch")) return true;
        if (!report.TryGetProperty("NativeResult", out var native) || native.ValueKind != JsonValueKind.Object) return false;
        if (False(native, "input_dispatched")) return true;
        // Invoke and PostMessage never insert a global keyboard-down event.
        // A queued message still has an unknown business/prompt result.
        return True(native, "desktop_cleanup_verified") && (Text(native, "input_release") == "released"
            || Text(native, "input_release") == "not_required" && Text(native, "route") is "uia_invoke" or "window_message");
    }
    internal static bool CleanupComplete(JsonElement report)
    {
        if (!True(report, "WatchersEnded") || Text(report, "StopPersistenceError") is not null
            || Text(report, "ProgramBindingCleanupError") is not null || Text(report, "LauncherBoundaryCloseError") is not null) return false;
        bool nativeAbsent = !report.TryGetProperty("NativeResult", out var action) || action.ValueKind == JsonValueKind.Null;
        if (False(report, "StopMonitorAttempted") && nativeAbsent && Text(report, "Action") == "none") return true;
        if (!report.TryGetProperty("StopMonitorEnd", out var monitor) || !True(monitor, "desktop_cleanup_verified")
            || !monitor.TryGetProperty("secure_stop_controller_error", out var error) || !error.TryGetInt32(out var code) || code != 0
            || !(True(monitor, "secure_stop_controller_completed") || Text(monitor, "state") == "monitor_not_running"
                && False(monitor, "continuous_stop_monitor_active"))) return false;
        return !report.TryGetProperty("NativeResult", out var native) || native.ValueKind == JsonValueKind.Null
            || True(native, "desktop_cleanup_verified");
    }
    internal static bool ControlComplete(bool goSent, JsonElement report)
    {
        if (!goSent && True(report, "NoWorkerActions")) return true;
        if (!CleanupComplete(report) || !InputFree(goSent, report)) return false;
        if (!goSent || True(report, "WorkerNoNativeDispatch")) return true;
        if (!report.TryGetProperty("NativeResult", out var native)) return false;
        if (False(native, "input_dispatched")) return true;
        if (!True(report, "PromptInstanceGone")) return false;
        return Text(native, "route") switch
        {
            "uia_invoke" => True(native, "uia_invoke_returned"),
            "window_message" => native.TryGetProperty("messages_queued", out var count) && count.TryGetInt32(out var sent) && sent == 2,
            _ => false,
        };
    }
}
