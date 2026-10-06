using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class RequestSignalTests
{
    private sealed class ObservedRead(Stream inner, ManualResetEventSlim started) : Stream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken stop = default)
        {
            var read = inner.ReadAsync(buffer, stop);
            started.Set();
            return read;
        }
        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
    internal static int Run()
    {
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("request_signal_selftest_failed"); }
        var own = Native.Process(Environment.ProcessId).Identity;
        var target = new Target(30, 10, 20, own.Session, own.ImageDigest, own.Integrity, 1, [0, 0, 100, 100]);
        const string ledger = "test-ledger", action = "test-action";
        var prepare = new Prepare("prepare", own, target, new Operation("bind"), [], 200, "test-task", "test-connection", 17);

        // Use actual asynchronous pipes and the production framing reader. These
        // connections never enter target checking, input dispatch, or a broker.
        void Case(string mode, string? reason, string? payload = null)
        {
            var name = "flower-signal-selftest-" + Guid.NewGuid().ToString("N");
            using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var connected = server.WaitForConnectionAsync();
            client.Connect(1000);
            Require(connected.Wait(1000));
            var request = new BrokerRequest { ActionId = action };
            using var watchStop = new CancellationTokenSource();
            using var readStarted = new ManualResetEventSlim();
            using var observed = new ObservedRead(server, readStarted);
            var clock = Stopwatch.StartNew();
            var watcher = Task.Run(() =>
            {
                if (mode != "pre-deadline") Program.WatchPostGo(observed, prepare, ledger, request, clock, watchStop.Token);
                else
                {
                    // The pre-go path lets the production reader's timeout reach
                    // Request's outer error classifier, rather than its watcher.
                    try { using var go = Protocol.Read(observed, prepare.DeadlineMs, watchStop.Token); }
                    catch (Exception error) { request.Cancel(Program.Code(error)); }
                }
            });
            Require(readStarted.Wait(1000));
            if (mode == "finish") watchStop.Cancel();
            else if (mode == "eof") client.Dispose();
            else if (payload is not null)
            {
                client.Write(Encoding.UTF8.GetBytes(payload + "\n")); client.Flush();
            }
            Require(watcher.Wait(1500));
            Require(request.Reason == reason);
            Require(request.Stop.IsCancellationRequested == (reason is not null));
            if (mode is "deadline" or "pre-deadline") Require(client.IsConnected && server.IsConnected && clock.ElapsedMilliseconds < 1500);
            request.Stop.Dispose();
        }
        string Signal(string phase, string signalAction = action) => JsonSerializer.Serialize(new
        {
            Phase = phase, LedgerIdentity = ledger, ActionId = signalAction,
            TaskId = prepare.TaskId, ConnectionId = prepare.ConnectionId, DesktopRevision = prepare.DesktopRevision
        });
        Case("finish", null);
        Case("deadline", "deadline_expired");
        Case("pre-deadline", "deadline_expired");
        Case("eof", "client_disconnected");
        Case("signal", "input_stopped", Signal("stop"));
        Case("signal", "duplicate_go_rejected", Signal("go"));
        Case("signal", "duplicate_go_rejected", Signal("stop", "other-action"));
        Case("signal", "schema_rejected", "{bad-json");
        Case("signal", "schema_rejected", "{\"Phase\":\"stop\",\"Phase\":\"stop\"}");

        using (var stop = JsonDocument.Parse(Signal("stop")))
        {
            var request = new BrokerRequest();
            Require(Program.AcceptPreGoStop(stop, ledger, prepare, request));
            Require(request.Reason == "input_stopped" && request.ActionId == action && request.Stop.IsCancellationRequested);
            request.Stop.Dispose();
        }
        using (var go = JsonDocument.Parse(Signal("go")))
        {
            var request = new BrokerRequest();
            Require(!Program.AcceptPreGoStop(go, ledger, prepare, request));
            Require(request.Reason is null && !request.Stop.IsCancellationRequested);
            request.Stop.Dispose();
        }
        // Drive the actual production completion wait with a deterministic
        // queue oracle. No foreground API or input is called by this regression.
        var previous = new IntPtr(10);
        var targetWindow = new IntPtr(20);
        long elapsed = 0;
        int fences = 0, checks = 0;
        var foreground = IntPtr.Zero;
        var completed = Executor.WaitForegroundCompletion(previous, () => ++checks,
            () => (foreground, foreground == targetWindow), () => false,
            () => elapsed, () => 5000 - (int)elapsed,
            timeout => { Require(timeout is > 0 and <= 20); elapsed += timeout; if (++fences == 2) foreground = targetWindow; return true; },
            milliseconds => elapsed += milliseconds);
        Require(completed && fences == 2 && checks >= 4 && elapsed <= 200);

        void WaitCase(string? expected, IntPtr initial, bool protectedWindow = false,
            string? checkFailure = null, bool responsive = true, bool switchDuringFence = false, int deadline = 5000)
        {
            elapsed = 0; foreground = initial; fences = 0;
            bool result = true;
            string? reason = null;
            try
            {
                result = Executor.WaitForegroundCompletion(previous,
                    () =>
                    {
                        if (elapsed >= deadline) throw new Boundary("deadline_expired");
                        if (fences > 0 && checkFailure is not null) throw new Boundary(checkFailure);
                    },
                    () => (foreground, foreground == targetWindow), () => protectedWindow,
                    () => elapsed, () => deadline - (int)elapsed,
                    timeout =>
                    {
                        Require(timeout is > 0 and <= 20 && timeout <= deadline - elapsed);
                        elapsed += timeout; ++fences;
                        if (switchDuringFence) foreground = new IntPtr(30);
                        return responsive;
                    }, milliseconds => { Require(milliseconds <= deadline - elapsed); elapsed += milliseconds; });
            }
            catch (Boundary error) { reason = error.Code; }
            Require(reason == expected);
            if (expected is null) Require(!result && elapsed == 200);
            if (checkFailure is not null || switchDuringFence) Require(fences == 1);
            if (deadline < 200) Require(elapsed <= deadline);
        }
        WaitCase(null, previous); // Responsive queue denied activation: allow the single Alt fallback.
        WaitCase("foreground_changed", new IntPtr(30));
        WaitCase("foreground_changed", previous, protectedWindow: true);
        WaitCase("foreground_changed", previous, switchDuringFence: true);
        WaitCase("input_stopped", IntPtr.Zero, checkFailure: "input_stopped");
        WaitCase("target_identity_changed", previous, checkFailure: "target_identity_changed");
        WaitCase("deadline_expired", IntPtr.Zero, deadline: 35);
        WaitCase("target_unresponsive", previous, responsive: false);
        return assertions;
    }
}
