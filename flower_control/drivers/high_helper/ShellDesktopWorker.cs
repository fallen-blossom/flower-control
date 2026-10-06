using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal record ShellWorkerRequest(Peer Parent, Prepare Prepare, string LedgerIdentity, long PreviousForeground, int DeadlineMs);
internal record ShellWorkerReady(string Phase, Peer Worker, string AssemblyDigest, Bound Target, string LedgerIdentity);
internal record ShellWorkerDone(string Phase, Peer Worker, Bound Target, string LedgerIdentity,
    bool Requested, bool Completed, string? Reason, int? Winerror);

// Shell COM can block inside the server. Only this fixed disposable STA worker
// owns that call; the broker keeps checking Stop/identity/deadline while waiting.
internal static class ShellDesktopWorker
{
    internal static int Run()
    {
        int result = 2; Exception? failure = null;
        var thread = new Thread(() => { try { result = RunSta(); } catch (Exception error) { failure = error; } });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start(); thread.Join();
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
        return result;
    }
    private static int RunSta()
    {
        var clock = Stopwatch.StartNew();
        using var input = Console.OpenStandardInput(); using var output = Console.OpenStandardOutput();
        using var document = Protocol.Read(input, 3000, limit: 98304);
        if (document is null) throw new Boundary("shell_worker_disconnected");
        var request = Protocol.Decode<ShellWorkerRequest>(document);
        var own = Native.Process(Environment.ProcessId); var parent = Native.Process(Native.ParentPid(Environment.ProcessId));
        if (request.Parent != parent.Identity || parent.Identity.User != own.Identity.User
            || parent.Identity.Session != own.Identity.Session || parent.Identity.Integrity != own.Identity.Integrity
            || !parent.Image.Equals(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"), StringComparison.OrdinalIgnoreCase)
            || parent.Identity.ImageDigest != own.Identity.ImageDigest || request.DeadlineMs is < 1 or > 5000
            || !Regex.IsMatch(request.LedgerIdentity, "^[a-f0-9]{64}$") || !Protocol.UsesPhysicalInput(request.Prepare.Operation))
            throw new Boundary("shell_worker_parent_rejected");
        Protocol.Validate(request.Prepare, own.Identity.Integrity == 8192);
        var bound = Native.CheckTarget(request.Prepare.Target, false);
        bool requested = false, completed = false; string? reason = null; int? winerror = null;
        object? shell = null;
        try
        {
            bool Check()
            {
                Native.VerifyPeer(request.Parent); Native.VerifyPeer(request.Prepare.Parent); Native.Desktop();
                if (clock.ElapsedMilliseconds >= request.DeadlineMs) throw new Boundary("deadline_expired");
                if (Native.CheckTarget(request.Prepare.Target, false) != bound) throw new Boundary("target_identity_changed");
                if (!Native.IsShellDesktop(bound)) throw new Boundary("shell_desktop_identity_changed");
                if (Native.Foreground(bound.Hwnd)) return false;
                if (Native.GetForegroundWindow().ToInt64() != request.PreviousForeground) throw new Boundary("foreground_changed");
                if (Native.ProtectedForeground()) throw new Boundary("activation_foreground_protected");
                Executor.ExternalInput();
                return true;
            }
            Check();
            var type = Type.GetTypeFromProgID("Shell.Application") ?? throw new Boundary("shell_activation_unavailable");
            shell = Activator.CreateInstance(type) ?? throw new Boundary("shell_activation_unavailable");
            Check();
            Protocol.Write(output, new ShellWorkerReady("ready", own.Identity, Program.AssemblyDigest, bound, request.LedgerIdentity));
            using var go = Protocol.Read(input, Math.Max(1, request.DeadlineMs - (int)clock.ElapsedMilliseconds), limit: 98304);
            if (go is null || !Protocol.Phase(go, "go")) throw new Boundary("shell_worker_go_rejected");
            if (Check())
            {
                requested = true;
                try { type.InvokeMember("MinimizeAll", BindingFlags.InvokeMethod, null, shell, null); }
                catch (TargetInvocationException) { throw new Boundary("shell_activation_failed"); }
                completed = true;
            }
        }
        catch (Exception error)
        { reason = Program.Code(error); winerror = error is Boundary boundary ? boundary.NativeCode : null; }
        finally
        {
            if (shell is not null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
        }
        Protocol.Write(output, new ShellWorkerDone("done", own.Identity, bound, request.LedgerIdentity, requested, completed, reason, winerror));
        return 0;
    }

    internal static ShellWorkerDone DecodeDone(JsonDocument document)
    {
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(
            ["Phase", "Worker", "Target", "LedgerIdentity", "Requested", "Completed", "Reason", "Winerror"]))
            throw new Boundary("shell_worker_result_rejected");
        var done = Protocol.Decode<ShellWorkerDone>(document);
        if (done.Phase != "done" || done.Completed && (!done.Requested || done.Reason is not null)
            || done.Requested && !done.Completed && done.Reason is null)
            throw new Boundary("shell_worker_result_rejected");
        return done;
    }
    internal static void Execute(Prepare prepare, Bound bound, IntPtr previous, Func<bool> stopped, Stopwatch clock, InputLedger ledger, Receipt result)
    {
        bool childGo = false;
        void Check()
        {
            Executor.Check(prepare, bound, stopped, clock, false, false, ledger);
            if (!Native.IsShellDesktop(bound)) throw new Boundary("shell_desktop_identity_changed");
            if (!childGo && !Native.Foreground(bound.Hwnd) && Native.GetForegroundWindow() != previous)
                throw new Boundary("foreground_changed");
        }
        Check();
        var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"))
        { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("--shell-desktop-worker");
        var system = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(system) || !Path.IsPathFullyQualified(system)) throw new Boundary("windows_system_root_missing");
        info.Environment.Clear(); info.Environment["SystemRoot"] = system; info.Environment["WINDIR"] = system;
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        foreach (var name in new[] { "TEMP", "TMP" })
        { var path = Environment.GetEnvironmentVariable(name); if (path is not null && Path.IsPathFullyQualified(path)) info.Environment[name] = path; }
        // The exact child is supervised. A COM server belongs to the user's
        // Shell and must not become an owned descendant eligible for cleanup.
        using var child = new OwnedChild(info, allowDescendantBreakaway: true, exitSink: value => result.SemanticExecutorExited = value);
        var peer = Native.Process(child.Process.Id).Identity; var own = Native.Process(Environment.ProcessId).Identity;
        if (peer.User != own.User || peer.Session != own.Session || peer.Integrity != own.Integrity || peer.ImageDigest != own.ImageDigest)
            throw new Boundary("shell_worker_identity_rejected");
        result.SemanticExecutor = peer; result.SemanticExecutorExited = false;
        _ = Task.Run(async () => { var bytes = new byte[1024]; while (await child.Process.StandardError.BaseStream.ReadAsync(bytes) > 0) { } });
        Protocol.Write(child.Process.StandardInput.BaseStream, new ShellWorkerRequest(own, prepare, result.LedgerIdentity!, previous.ToInt64(),
            Math.Max(1, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds)));
        while (true)
        {
            Check();
            using var stop = new CancellationTokenSource();
            var read = Task.Run(() => Protocol.Read(child.Process.StandardOutput.BaseStream,
                Math.Max(1, prepare.DeadlineMs - (int)clock.ElapsedMilliseconds), stop.Token, 98304));
            try
            {
                while (!read.IsCompleted) { Thread.Sleep(20); if (!read.IsCompleted) Check(); }
                using var message = read.GetAwaiter().GetResult();
                if (message is null) throw new Boundary("shell_worker_disconnected");
                if (message.RootElement.TryGetProperty("Phase", out var phase) && phase.GetString() == "ready")
                {
                    var ready = Protocol.Decode<ShellWorkerReady>(message);
                    if (childGo || ready.Worker != peer || ready.AssemblyDigest != Program.AssemblyDigest
                        || ready.Target != bound || ready.LedgerIdentity != result.LedgerIdentity)
                        throw new Boundary("shell_worker_ready_rejected");
                    Check(); Native.VerifyPeer(peer);
                    childGo = true; result.ActivationRequested = true; result.RequiresNewObservation = true;
                    // The go fence records a possible activation call even if
                    // the child dies before it can report a native outcome.
                    Protocol.Write(child.Process.StandardInput.BaseStream, new { Phase = "go" });
                    continue;
                }
                var done = DecodeDone(message);
                if (done.Worker != peer || done.Target != bound || done.LedgerIdentity != result.LedgerIdentity
                    || !childGo && (done.Requested || done.Reason is null))
                    throw new Boundary("shell_worker_result_rejected");
                result.ActivationRequested |= done.Requested;
                child.Process.StandardInput.Close();
                while (!child.Process.WaitForExit(20)) Check();
                if (done.Reason is { } reason) throw new Boundary(reason, done.Winerror);
                return;
            }
            finally { stop.Cancel(); try { read.Wait(500); } catch (AggregateException) { } }
        }
    }
}
