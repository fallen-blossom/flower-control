using System.Text.Json;
namespace Flower.HighHelper;

internal static class WorkSourceDiagnosticsTests
{
    private sealed class StalledWrite : MemoryStream
    {
        internal bool FlushCalled;
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => new(Task.Delay(Timeout.Infinite, cancellationToken));
        public override Task FlushAsync(CancellationToken cancellationToken)
        { FlushCalled = true; return Task.CompletedTask; }
    }
    internal static object Run()
    {
        int assertions = 0;
        void Check(bool value) { ++assertions; if (!value) throw new Boundary("work_source_diagnostics_test_failed"); }
        Check(Program.Code(new InvalidDataException("uac_transcript_path_rejected")) == "uac_transcript_path_rejected");
        foreach (string value in new[] { "private body", "C:/private/file", "uac_transcript_bad\nbody",
                     "uac_transcript_" + new string('a', 61), "uac_transcript_bad123" })
            Check(Program.Code(new InvalidDataException(value)) == "helper_failure");
        foreach (string stage in new[] { "admission", "pipe_connect", "hello_read", "record_read" })
        {
            var failure = UacHostHook.Failure(new OperationCanceledException("private body"), stage);
            Check(failure == new UacHostHook.PreflightFailure("unavailable", "deadline_expired", stage));
            Check(!JsonSerializer.Serialize(failure).Contains("private body"));
        }
        Check(UacHostHook.Failure(new TimeoutException("private path"), "pipe_connect").Reason == "deadline_expired");
        Check(UacHostHook.Failure(new Boundary("codex_launch_chain_unverified"), "admission").Reason == "codex_launch_chain_unverified");
        Check(UacHostHook.Failure(new Boundary("private_body"), "private path") ==
            new UacHostHook.PreflightFailure("unavailable", "helper_failure", "policy"));
        Check(UacHostHook.PreflightTimeout(1500, 0) == 1500);
        Check(UacHostHook.PreflightTimeout(3000, 500) == 3000);
        Check(UacHostHook.PreflightTimeout(3000, 5500) == 2500);
        Check(UacHostHook.PreflightTimeout(5000, 7999) == 1);
        foreach (var (limit, elapsed) in new[] { (0, 0L), (3000, -1L), (3000, 8000L), (3000, long.MaxValue) })
        {
            try { _ = UacHostHook.PreflightTimeout(limit, elapsed); Check(false); }
            catch (Boundary error) { Check(error.Code == "deadline_expired"); }
        }
        using (var stalled = new StalledWrite())
        {
            var clock = System.Diagnostics.Stopwatch.StartNew();
            try { Protocol.Write(stalled, new { Phase = "fixture" }, 1); Check(false); }
            catch (OperationCanceledException) { Check(clock.ElapsedMilliseconds < 400); }
            Check(!stalled.FlushCalled);
        }
        using var source = JsonSerializer.SerializeToDocument(UacTranscriptBinding.InspectWorkSource(new string('f', 64)));
        Check(!source.RootElement.GetProperty("BindingPresent").GetBoolean());
        Check(source.RootElement.GetProperty("Reason").GetString() == "work_host_message_unavailable");
        Check(source.RootElement.EnumerateObject().Count() == 2);
        var query = new WorkAuthorityQuery("work_authority", "source_status", "task", "connection", "", new AuditThread("codex", "thread"));
        foreach (var invalid in new[] { query with { Phase = "wrong" }, query with { ConnectionId = "wrong" },
                     query with { WorkId = new string('a', 32) }, query with { Goal = "goal" },
                     query with { Constraints = "constraint" }, query with { ExpectedRevision = 1 }, query with { Thread = null! } })
        {
            try { _ = WorkAuthority.Handle(null!, null!, null!, invalid, "connection", null!, () => true); Check(false); }
            catch (Boundary error) { Check(error.Code == "work_authority_request_invalid"); }
        }
        return new { assertions, productionPolicyRead = false, productionStopTouched = false,
            transcriptRead = false, authorityCreated = false, inputDispatched = false };
    }
}
