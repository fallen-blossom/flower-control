using System.Text.Json;

namespace Flower.HighHelper;

internal enum BrokerShutdownReason
{
    RunCleanup, TrayExit, AdminShutdown, SessionEnded, SessionLogoff,
    PipeAcceptFailure, HostMessageQuit
}

internal sealed record BrokerShutdownNotice(BrokerShutdownReason Reason, string Utc,
    int ManagedThreadId, int? CallerPid, long? CallerCreated);

internal static class BrokerLifecycle
{
    private static void Diagnostic(object value)
    {
        try { Console.Error.WriteLine(JsonSerializer.Serialize(value)); }
        catch (Exception error) when (error is IOException or ObjectDisposedException) { }
    }
    // Release input even if evidence storage is unavailable. Never clear an
    // audit fault or repair its tail as part of normal process shutdown.
    internal static string? Record(BrokerPolicy policy, Peer own, BrokerShutdownNotice notice)
    {
        Diagnostic(new { brokerLifecycle = "shutdown_requested",
            version = policy.Version, pid = own.Pid, created = own.Created, notice });
        if (policy.Fixture) return null;
        try
        {
            ExecutionAudit.Open(policy, own).Append(new AuditEvent("broker_lifecycle", "", "",
                "shutdown_requested", Reason: notice.Reason.ToString(), Evidence: new {
                    version = policy.Version, pid = own.Pid, created = own.Created,
                    session = own.Session, notice }));
            return null;
        }
        catch (Exception error)
        {
            string reason = Program.Code(error);
            Diagnostic(new { brokerLifecycle = "shutdown_audit_failed", reason });
            return reason;
        }
    }
}
