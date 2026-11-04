using System.Diagnostics;
using System.Text.Json;

namespace Flower.HighHelper;

// Local metadata only. No input, window activation, names, values or text.
internal static class PasswordMetadata
{
    internal sealed record Info(int[][] Rectangles, int[]? FocusRectangle, bool? FocusPassword);
    internal static void WaitForResponse(Func<bool> completed, Action check, Func<long> elapsedMs, Action<int> delay)
    {
        while (!completed())
        {
            check();
            if (elapsedMs() >= 2500) throw new Boundary("privacy_password_scan_incomplete");
            // A full check can outlast the worker. Never sleep after its reply
            // has already arrived; the caller still performs the final check.
            if (!completed()) delay(10);
        }
    }
    internal static Info Scan(BrokerPolicy policy, Bound bound, Action check)
    {
        var root = Path.Combine(policy.Directory, "app");
        if (!policy.AppWorkerHashes.ContainsKey("Flower.AppWorker.exe") || policy.AppWorkerHashes.Count is < 4 or > 128)
            throw new Boundary("privacy_password_scan_unavailable");
        foreach (var (file, hash) in policy.AppWorkerHashes)
        {
            if (Path.GetFileName(file) != file) throw new Boundary("app_worker_policy_rejected");
            var path = Path.Combine(root, file); BrokerPolicy.RejectLinks(path);
            if (Native.Digest(path) != hash) throw new Boundary("app_worker_changed");
        }
        check();
        var info = new ProcessStartInfo(Path.Combine(root, "Flower.AppWorker.exe"), "--privacy-only")
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root,
            StandardInputEncoding = new System.Text.UTF8Encoding(false, true),
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        var system = Environment.GetEnvironmentVariable("SystemRoot");
        if (system is null || !Path.IsPathFullyQualified(system)) throw new Boundary("windows_system_root_missing");
        info.Environment.Clear(); info.Environment["SystemRoot"] = system; info.Environment["WINDIR"] = system;
        info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        using var child = new OwnedChild(info);
        var own = Native.Process(Environment.ProcessId).Identity; var peer = Native.Process(child.Process.Id).Identity;
        if (peer.User != own.User || peer.Session != own.Session || peer.Integrity != own.Integrity
            || peer.ImageDigest != policy.AppWorkerHashes["Flower.AppWorker.exe"])
            throw new Boundary("app_worker_identity_rejected");
        _ = Task.Run(() => child.Process.StandardError.BaseStream.CopyTo(Stream.Null));
        child.Process.StandardInput.WriteLine(JsonSerializer.Serialize(new { pid = bound.Pid, hwnd = bound.Hwnd,
            process_created = DateTime.FromFileTimeUtc(bound.Created).ToString("O"), window_nonce = bound.WindowNonce }));
        child.Process.StandardInput.Close();
        using var stop = new CancellationTokenSource();
        var read = Task.Run(() => Protocol.Read(child.Process.StandardOutput.BaseStream, 2500, stop.Token, 20000));
        var clock = Stopwatch.StartNew();
        try
        {
            WaitForResponse(() => read.IsCompleted, check, () => clock.ElapsedMilliseconds, Thread.Sleep);
            using var reply = read.GetAwaiter().GetResult(); check();
            if (reply is null) throw new Boundary("privacy_password_scan_incomplete");
            var value = reply.RootElement;
            if (value.TryGetProperty("state", out var state) && state.GetString() == "rejected")
                throw PrivacyDiagnostics.ScanFailure(value);
            if (value.EnumerateObject().Count() != 6 || value.GetProperty("state").GetString() != "observed"
                || value.GetProperty("coverage").GetString() != "uia_password_property"
                || value.GetProperty("dispatched").ValueKind != JsonValueKind.False)
                throw new Boundary("privacy_password_scan_incomplete");
            var rows = value.GetProperty("rectangles").EnumerateArray().Select(row => row.EnumerateArray().Select(n => n.GetInt32()).ToArray()).ToArray();
            if (rows.Length > 128 || rows.Any(r => r.Length != 4 || r[0] >= r[2] || r[1] >= r[3])) throw new Boundary("privacy_password_scan_incomplete");
            var focus = value.GetProperty("focus_rectangle");
            int[]? focusRect = focus.ValueKind == JsonValueKind.Null ? null : focus.EnumerateArray().Select(n => n.GetInt32()).ToArray();
            if (focusRect is not null && (focusRect.Length != 4 || focusRect[0] >= focusRect[2] || focusRect[1] >= focusRect[3])) throw new Boundary("privacy_password_scan_incomplete");
            var password = value.GetProperty("focus_password");
            bool? focusPassword = password.ValueKind == JsonValueKind.Null ? null : password.GetBoolean();
            while (!child.Process.WaitForExit(10)) { check(); if (clock.ElapsedMilliseconds >= 2500) throw new Boundary("privacy_password_scan_incomplete"); }
            if (child.Process.ExitCode != 0) throw new Boundary("privacy_password_scan_incomplete");
            check(); return new(rows, focusRect, focusPassword);
        }
        finally { stop.Cancel(); try { read.Wait(500); } catch (AggregateException) { } }
    }

    internal static void RequireInput(BrokerPolicy policy, Bound bound, Step[] steps, DesktopShape? desktop, Action check, bool heldMouse = false)
    {
        var metadata = Scan(policy, bound, check);
        UserPermissions.RequireInput(bound, steps, desktop, metadata, deferKeyboard: false, heldMouse: heldMouse);
        check();
    }

    // Raw Scan always reads fresh metadata. Gesture reuse is confined to the
    // exact input ledger below; screenshot/focus readers never use it.
    internal sealed class InputSession(BrokerPolicy policy, Bound bound, Receipt? receipt = null) : IDisposable
    {
        private OwnedChild? child;
        private Peer? peer;
        private Task<System.Text.Json.JsonDocument?>? read;
        private readonly CancellationTokenSource stop = new();
        private int scans;
        private readonly Stopwatch sessionLifetime = new();
        private bool failed, disposed;
        private UserPermissionSettings? gesturePermissions;
        private long gesturePermissionsAt = long.MinValue;
        private void Start(Action check, Action waitCheck)
        {
            var clock = Stopwatch.StartNew();
            var root = Path.Combine(policy.Directory, "app");
            if (!policy.AppWorkerHashes.ContainsKey("Flower.AppWorker.exe") || policy.AppWorkerHashes.Count is < 4 or > 128)
                throw new Boundary("privacy_password_scan_unavailable");
            foreach (var (file, hash) in policy.AppWorkerHashes)
            {
                waitCheck();
                if (Path.GetFileName(file) != file) throw new Boundary("app_worker_policy_rejected");
                var path = Path.Combine(root, file); BrokerPolicy.RejectLinks(path);
                if (Native.Digest(path) != hash) throw new Boundary("app_worker_changed");
            }
            if (receipt is not null) receipt.TimingsMs["privacy_worker_validation"] = clock.Elapsed.TotalMilliseconds;
            check();
            var info = new ProcessStartInfo(Path.Combine(root, "Flower.AppWorker.exe"), "--privacy-session") {
                UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = root,
                StandardInputEncoding = new System.Text.UTF8Encoding(false, true),
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
            };
            var system = Environment.GetEnvironmentVariable("SystemRoot");
            if (system is null || !Path.IsPathFullyQualified(system)) throw new Boundary("windows_system_root_missing");
            info.Environment.Clear(); info.Environment["SystemRoot"] = system; info.Environment["WINDIR"] = system;
            info.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
            child = new OwnedChild(info);
            var own = Native.Process(Environment.ProcessId).Identity; peer = Native.Process(child.Process.Id).Identity;
            if (peer.User != own.User || peer.Session != own.Session || peer.Integrity != own.Integrity
                || peer.ImageDigest != policy.AppWorkerHashes["Flower.AppWorker.exe"])
                throw new Boundary("app_worker_identity_rejected");
            _ = Task.Run(() => child.Process.StandardError.BaseStream.CopyTo(Stream.Null));
            scans = 0; sessionLifetime.Restart(); check();
        }
        internal Info Scan(Action check, bool focusOnly = false, Action? waitCheck = null)
        {
            if (failed || disposed) throw new Boundary("privacy_password_scan_incomplete");
            var clock = Stopwatch.StartNew();
            try
            {
                // The fixed companion caps each session at 128 fresh scans.
                // Rotate only after a completed response, never after failure.
                if (child is not null && (scans == 128 || sessionLifetime.ElapsedMilliseconds >= 14000))
                { child.Dispose(); child = null; }
                if (child is null) Start(check, waitCheck ?? check);
                check(); Native.VerifyPeer(peer!);
                var query = new Dictionary<string, object?> { ["pid"] = bound.Pid, ["hwnd"] = bound.Hwnd,
                    ["process_created"] = DateTime.FromFileTimeUtc(bound.Created).ToString("O"), ["window_nonce"] = bound.WindowNonce };
                if (focusOnly) query["scope"] = "keyboard_focus";
                child!.Process.StandardInput.WriteLine(JsonSerializer.Serialize(query));
                child.Process.StandardInput.Flush();
                read = Task.Run(() => Protocol.Read(child.Process.StandardOutput.BaseStream, 2500, stop.Token, 20000));
                var waiting = Stopwatch.StartNew();
                try { WaitForResponse(() => read.IsCompleted, waitCheck ?? check, () => waiting.ElapsedMilliseconds, Thread.Sleep); }
                finally
                {
                    if (receipt is not null) receipt.TimingsMs["privacy_query_wait"] = receipt.TimingsMs.GetValueOrDefault("privacy_query_wait") + waiting.Elapsed.TotalMilliseconds;
                }
                using var reply = read.GetAwaiter().GetResult(); check();
                if (reply is null) throw new Boundary("privacy_password_scan_incomplete");
                // A failed companion writes its bounded rejection and exits.
                // Preserve that rejection before reopening an already-exited
                // peer; success still requires the original live-peer check.
                if (reply.RootElement.ValueKind == JsonValueKind.Object
                    && reply.RootElement.TryGetProperty("state", out var state)
                    && state.ValueKind == JsonValueKind.String && state.GetString() == "rejected")
                    throw PrivacyDiagnostics.ScanFailure(reply.RootElement);
                Native.VerifyPeer(peer!);
                var result = Decode(reply.RootElement, focusOnly); ++scans;
                return result;
            }
            catch { failed = true; throw; }
            finally
            {
                if (receipt is not null) receipt.TimingsMs["privacy_scan"] = receipt.TimingsMs.GetValueOrDefault("privacy_scan") + clock.Elapsed.TotalMilliseconds;
            }
        }
        internal void Warm(Action check, Action waitCheck)
        {
            if (failed || disposed) throw new Boundary("privacy_password_scan_incomplete");
            if (child is null) Start(check, waitCheck);
        }
        internal static Info Decode(JsonElement value, bool focusOnly = false)
        {
            if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty("state", out var state)
                && state.ValueKind == JsonValueKind.String && state.GetString() == "rejected")
                throw PrivacyDiagnostics.ScanFailure(value);
            if (value.EnumerateObject().Count() != 6 || value.GetProperty("state").GetString() != "observed"
                || value.GetProperty("coverage").GetString() != (focusOnly ? "uia_password_focus" : "uia_password_property")
                || value.GetProperty("dispatched").ValueKind != JsonValueKind.False)
                throw new Boundary("privacy_password_scan_incomplete");
            var rows = value.GetProperty("rectangles").EnumerateArray().Select(row => row.EnumerateArray().Select(n => n.GetInt32()).ToArray()).ToArray();
            if (rows.Length > 128 || rows.Any(r => r.Length != 4 || r[0] >= r[2] || r[1] >= r[3])) throw new Boundary("privacy_password_scan_incomplete");
            var focus = value.GetProperty("focus_rectangle");
            int[]? focusRect = focus.ValueKind == JsonValueKind.Null ? null : focus.EnumerateArray().Select(n => n.GetInt32()).ToArray();
            if (focusRect is not null && (focusRect.Length != 4 || focusRect[0] >= focusRect[2] || focusRect[1] >= focusRect[3])) throw new Boundary("privacy_password_scan_incomplete");
            var password = value.GetProperty("focus_password");
            bool? focusPassword = password.ValueKind == JsonValueKind.Null ? null : password.GetBoolean();
            if (focusOnly && (rows.Length != 0 || focusPassword is null))
                throw new Boundary("privacy_keyboard_focus_unverified");
            return new(rows, focusRect, focusPassword);
        }
        internal void RequireInput(Step[] steps, DesktopShape? desktop, Action check, bool heldMouse,
            Action? waitCheck = null, InputLedger? ledger = null, bool finalCheck = true)
        {
            var own = ledger?.OwnTokens;
            bool continuation = steps.Length > 0 && heldMouse && own is not null
                && own.Any(t => t.StartsWith("mouse:", StringComparison.Ordinal))
                && steps.All(s => s.Raw.Type == 0 && (s.Token is null && s.Raw.Data.Mouse.Flags == 0xc001
                    || s.Token?.StartsWith("mouse:", StringComparison.Ordinal) == true && !s.Down && own.Contains(s.Token)))
                && ledger!.GesturePrivacy is { } cached && cached.Target == bound;
            Info metadata;
            try
            {
                if (continuation) metadata = ledger!.GesturePrivacy!.Value.Metadata;
                else
                {
                    ledger?.ClearGesturePrivacy();
                    gesturePermissions = null;
                    metadata = Scan(check, steps.All(step => step.Raw.Type == 1), waitCheck);
                }
                // Current masks and swept regions apply to every segment. The
                // short permission cache only avoids re-parsing the same store
                // file; dispatch still checks target, foreground and Stop at
                // the motion-check cadence and before every non-motion send.
                long now = Stopwatch.GetTimestamp();
                bool refresh = !continuation || gesturePermissions is null
                    || Stopwatch.GetElapsedTime(gesturePermissionsAt, now).TotalMilliseconds >= PointerPath.MotionCheckMs;
                var permissions = refresh ? UserPermissions.Read() : gesturePermissions!;
                if (continuation && refresh) { gesturePermissions = permissions; gesturePermissionsAt = now; }
                UserPermissions.RequireInput(bound, steps, desktop, metadata, deferKeyboard: false,
                    heldMouse: heldMouse, permissions: permissions);
                if (finalCheck) check();
                if (!continuation && ledger is not null && steps.Any(s => s.Down && s.Token?.StartsWith("mouse:", StringComparison.Ordinal) == true))
                    ledger.PendingGesturePrivacy = (bound, new Info(metadata.Rectangles, null, null));
            }
            catch { ledger?.ClearGesturePrivacy(); throw; }
        }
        public void Dispose()
        {
            if (disposed) return;
            disposed = true; stop.Cancel();
            try { child?.Dispose(); }
            finally
            {
                if (read is not null) try { if (!read.Wait(500)) throw new Boundary("privacy_scan_exit_unconfirmed"); } catch (AggregateException) { }
                stop.Dispose();
            }
        }
    }
}
