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
