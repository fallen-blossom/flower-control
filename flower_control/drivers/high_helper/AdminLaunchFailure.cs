using System.ComponentModel;

namespace Flower.HighHelper;

// A closed, content-free description. Never serialize exception messages,
// paths, argv, stack traces or payload text from an administrator request.
internal sealed record AdminLaunchFailure(string Stage, string ErrorKind, int HResult, int? Winerror, int? PayloadIndex = null, bool Finishing = false)
{
    internal static void TagPin(Exception error, string stage, int payloadIndex)
    {
        try { error.Data["AdminLaunchStage"] = stage; if (payloadIndex >= 0) error.Data["AdminLaunchPayloadIndex"] = payloadIndex; }
        catch { } // Preserve the original exception and mandatory pin cleanup.
    }
    internal static AdminLaunchFailure Describe(Exception error, string stage, bool finishing = false)
    {
        if (error.Data["AdminLaunchStage"] is string detail && detail is "workdir_pin" or "payload_pin") stage = detail;
        if (stage is not ("journal_read" or "archive_closed_execution" or "audit_request" or "policy_check" or "semantic_row_identity"
            or "executable_pin" or "execution_binding" or "workdir_pin" or "payload_pin" or "target_refresh"
            or "caller_preflight" or "creation_resource" or "intent_journal_write" or "execution_seal"
            or "dispatch_preflight" or "create_process" or "created_identity" or "result_journal_write" or "audit_intent" or "caller_watch")) stage = "unknown";
        string kind = error is Win32Exception ? "win32" : error is IOException ? "io"
            : error is Boundary ? "boundary" : error is OperationCanceledException ? "cancelled" : "component";
        int? code = error is Win32Exception native ? native.NativeErrorCode : error is Boundary boundary && boundary.NativeCode is { } original ? original
            : ((uint)error.HResult & 0xffff0000u) == 0x80070000u ? error.HResult & 0xffff : null;
        int? index = stage == "payload_pin" && error.Data["AdminLaunchPayloadIndex"] is int value && value is >= 0 and < 32 ? value : null;
        return new(stage, kind, error.HResult, code, index, finishing);
    }
}
