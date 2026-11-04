using System.Collections.Concurrent;

namespace Flower.HighHelper;

internal static class BrokerLifecycleTests
{
    internal static int Run()
    {
        int assertions = 0;
        void Require(bool value) { assertions++; if (!value) throw new Boundary("broker_lifecycle_selftest_failed"); }
        var observations = new List<BrokerShutdownNotice>();
        var request = new BrokerRequest();
        var core = new BrokerState(shutdownObserver: notice => {
            Require(request.Stop.IsCancellationRequested);
            observations.Add(notice); return null;
        });
        core.Requests["synthetic"] = request;
        var caller = new Peer(10, 20, 1, "fixture", "", 12288);
        core.Stop(BrokerShutdownReason.AdminShutdown, caller);
        Require(core.Shutdown.IsCancellationRequested && observations.Count == 1);
        Require(core.ShutdownNotice?.Reason == BrokerShutdownReason.AdminShutdown);
        Require(core.ShutdownNotice?.CallerPid == 10 && core.ShutdownNotice?.CallerCreated == 20);
        Require(DateTimeOffset.TryParse(core.ShutdownNotice?.Utc, out _));
        Require(core.ShutdownNotice?.ManagedThreadId == Environment.CurrentManagedThreadId);
        core.Stop(BrokerShutdownReason.RunCleanup);
        core.DrainShutdownEvidence();
        Require(observations.Count == 1 && core.ShutdownNotice?.Reason == BrokerShutdownReason.AdminShutdown);
        Require(core.ShutdownAuditError is null);

        var failed = new BrokerState(shutdownObserver: _ => throw new Boundary("fixture_audit_unavailable"));
        failed.Stop(BrokerShutdownReason.TrayExit); failed.DrainShutdownEvidence();
        Require(failed.Shutdown.IsCancellationRequested);
        Require(failed.ShutdownAuditError == "fixture_audit_unavailable");

        var notices = new ConcurrentQueue<BrokerShutdownNotice>();
        var concurrent = new BrokerState(shutdownObserver: notice => { notices.Enqueue(notice); return null; });
        Task.WaitAll(Enumerable.Range(0, 24).Select(i => Task.Run(() => concurrent.Stop(
            i % 2 == 0 ? BrokerShutdownReason.SessionEnded : BrokerShutdownReason.HostMessageQuit))).ToArray());
        concurrent.DrainShutdownEvidence();
        Require(notices.Count == 1 && concurrent.Shutdown.IsCancellationRequested);
        Require(notices.Single() == concurrent.ShutdownNotice);

        var blank = new BrokerState(); blank.Stop(); blank.DrainShutdownEvidence();
        Require(blank.ShutdownNotice?.Reason == BrokerShutdownReason.RunCleanup);
        return assertions;
    }
}
