using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal static class BoundMaintenanceWriterTests
{
    private const string EventPrefix = @"Local\FlowerControl.test.bound.";
    private sealed record FixtureInfo(Peer Writer, string WriterImage, int ChildPid);

    private static void Assert(bool value, string name)
    {
        if (!value) throw new InvalidOperationException("bound_writer_test_failed:" + name);
    }

    private static void Reject(Action action, string name)
    {
        try { action(); }
        catch (Boundary) { return; }
        catch (ArgumentException) { return; }
        catch (InvalidOperationException e) when (!e.Message.StartsWith("bound_writer_test_failed:", StringComparison.Ordinal)) { return; }
        throw new InvalidOperationException("bound_writer_test_failed:" + name);
    }

    private static byte[] Bytes(MaintenanceWriterMarker value) => JsonSerializer.SerializeToUtf8Bytes(value);
    private static MaintenanceWriterMarker Example() => new(1, "active", new string('a', 32),
        "S-1-5-21-1-2-3-1001", 1, new string('b', 32), new string('c', 32), 123,
        134378455699912738L, Path.Combine(Path.GetTempPath(), "writer.exe"), new string('d', 64));

    internal static object Run()
    {
        var value = Example();
        Assert(BoundMaintenanceWriter.ParseMarker(Bytes(value)) == value, "filetime_roundtrip");
        var root = JsonNode.Parse(Bytes(value))!.AsObject();
        root["Unexpected"] = true;
        Reject(() => BoundMaintenanceWriter.ParseMarker(JsonSerializer.SerializeToUtf8Bytes(root)), "extra_field");
        foreach (var bad in new[] {
            value with { State = "closed" }, value with { OperationId = "not-an-operation" },
            value with { OldVersion = value.NewVersion }, value with { WriterImage = "relative.exe" },
            value with { UserSid = "invalid-sid" }, value with { WriterCreated = 0 },
            value with { WriterImageSha256 = new string('z', 64) } })
            Reject(() => BoundMaintenanceWriter.ParseMarker(Bytes(bad)), "bad_marker");
        BoundMaintenanceWriter.RequirePhase("status");
        BoundMaintenanceWriter.RequirePhase("maintenance");
        foreach (string? phase in new[] { "control", "prepare", "program_launch", "work_authority",
                     "open_settings", "uac_host_event", "maintenance_ordinary", null })
            Reject(() => BoundMaintenanceWriter.RequirePhase(phase), "phase_rejected");
        BoundMaintenanceWriter.RequirePhase("status", ordinary: true);
        BoundMaintenanceWriter.RequirePhase("maintenance_ordinary", ordinary: true);
        foreach (string phase in new[] { "maintenance", "program_launch", "control" })
            Reject(() => BoundMaintenanceWriter.RequirePhase(phase, ordinary: true), "ordinary_phase_rejected");
        var exit=value with { Schema=2, Purpose="exit", NewVersion=value.OldVersion };
        Assert(BoundMaintenanceWriter.ParseMarker(Bytes(exit))==exit,"exit_marker_roundtrip");
        Reject(()=>BoundMaintenanceWriter.ParseMarker(Bytes(exit with{NewVersion=value.NewVersion})),"exit_no_version_switch");
        Reject(()=>BoundMaintenanceWriter.ParseMarker(Bytes(exit with{Purpose="resume"})),"exit_purpose_closed");
        BoundMaintenanceWriter.RequireCommandForPurpose("exit","pause");
        BoundMaintenanceWriter.RequireCommandForPurpose("exit","shutdown");
        Reject(()=>BoundMaintenanceWriter.RequireCommandForPurpose("exit","resume"),"exit_cannot_resume");
        return new { assertions = 30, rawFiletime = value.WriterCreated.ToString(), productionAuthorityCreated = false };
    }

    private static Peer RequireFixture()
    {
        var (own, image) = Native.Process(Environment.ProcessId);
        string temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (own.Integrity != 12288 || Native.UiAccess(own.Pid)
            || !Path.GetFullPath(image).StartsWith(temp, StringComparison.OrdinalIgnoreCase)
            || !Path.GetFileName(image).Equals("Flower.HighHelper.exe", StringComparison.OrdinalIgnoreCase))
            throw new Boundary("bound_writer_test_fixture_required");
        BrokerPolicy.RejectLinks(image);
        return own;
    }

    private static string EventId(string name, string suffix)
    {
        string pattern = "\\A" + Regex.Escape(EventPrefix) + "([a-f0-9]{32})\\." + suffix + "\\z";
        var match = Regex.Match(name, pattern);
        if (!match.Success) throw new Boundary("bound_writer_test_event_rejected");
        return match.Groups[1].Value;
    }

    private static string FixtureInfoPath(string path, string id)
    {
        if (!Path.IsPathFullyQualified(path)) throw new Boundary("bound_writer_test_path_rejected");
        string directory = Path.Combine(Path.GetTempPath(), "flower-bound-maintenance-fixture-" + id);
        string expected = Path.GetFullPath(Path.Combine(directory, "info.json"));
        if (!Path.GetFullPath(path).Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("bound_writer_test_path_rejected");
        BrokerPolicy.RejectLinks(directory);
        return expected;
    }

    private static Process Start(string flag, params string[] args)
    {
        var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
        info.ArgumentList.Add(flag);
        foreach (string arg in args) info.ArgumentList.Add(arg);
        return Process.Start(info) ?? throw new Boundary("bound_writer_test_start_failed");
    }

    internal static int Writer(string[] args)
    {
        var own = RequireFixture();
        if (args.Length != 3) throw new Boundary("bound_writer_test_args_rejected");
        string id = EventId(args[0], "writer");
        if (EventId(args[1], "child") != id) throw new Boundary("bound_writer_test_event_rejected");
        string infoPath = FixtureInfoPath(args[2], id);
        using var writerEvent = EventWaitHandle.OpenExisting(args[0]);
        using var child = Start("--selftest-bound-child", args[1]);
        var (_, image) = Native.Process(own.Pid);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new FixtureInfo(own, image, child.Id));
        using (var file = new FileStream(infoPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
        { file.Write(bytes); file.Flush(true); }
        if (!writerEvent.WaitOne(TimeSpan.FromSeconds(60))) throw new Boundary("bound_writer_test_timeout");
        return 0;
    }

    internal static int Child(string[] args)
    {
        _ = RequireFixture();
        if (args.Length != 1) throw new Boundary("bound_writer_test_args_rejected");
        _ = EventId(args[0], "child");
        using var childEvent = EventWaitHandle.OpenExisting(args[0]);
        if (!childEvent.WaitOne(TimeSpan.FromSeconds(60))) throw new Boundary("bound_writer_test_timeout");
        return 0;
    }

    internal static object RunHigh()
    {
        var own = RequireFixture();
        string id = Guid.NewGuid().ToString("N"), operation = Guid.NewGuid().ToString("N");
        string writerName = EventPrefix + id + ".writer", childName = EventPrefix + id + ".child";
        string tempDirectory = Path.Combine(Path.GetTempPath(), "flower-bound-maintenance-fixture-" + id);
        if (Directory.Exists(tempDirectory)) throw new Boundary("bound_writer_test_path_exists");
        Directory.CreateDirectory(tempDirectory);
        string infoPath = FixtureInfoPath(Path.Combine(tempDirectory, "info.json"), id);
        string recovery = Path.Combine(InstallationLocation.Current().ProgramRoot, "recovery");
        string directory = Path.Combine(recovery, "installation-" + operation);
        string markerPath = Path.Combine(directory, "maintenance-writer.json");
        if (Directory.Exists(directory)) throw new Boundary("bound_writer_test_operation_exists");
        using var writerEvent = new EventWaitHandle(false, EventResetMode.ManualReset, writerName, out bool writerCreated);
        using var childEvent = new EventWaitHandle(false, EventResetMode.ManualReset, childName, out bool childCreated);
        if (!writerCreated || !childCreated) throw new Boundary("bound_writer_test_event_exists");
        Process? writer = null;
        Process? child = null;
        MaintenanceWriterMarker? marker = null;
        try
        {
            writer = Start("--selftest-bound-writer", writerName, childName, infoPath);
            var deadline = Stopwatch.StartNew();
            while (!File.Exists(infoPath) && !writer.HasExited && deadline.Elapsed < TimeSpan.FromSeconds(15)) Thread.Sleep(50);
            if (!File.Exists(infoPath)) throw new Boundary("bound_writer_test_writer_not_ready");
            FixtureInfo? info = null;
            // CreateNew exposes the file before the small JSON write completes.
            while (info is null && !writer.HasExited && deadline.Elapsed < TimeSpan.FromSeconds(15))
            {
                try { info = JsonSerializer.Deserialize<FixtureInfo>(File.ReadAllBytes(infoPath)); }
                catch (IOException) { Thread.Sleep(50); }
                catch (JsonException) { Thread.Sleep(50); }
            }
            if (info is null || info.Writer.Pid != writer.Id || info.ChildPid <= 0)
                throw new Boundary("bound_writer_test_info_invalid");
            using var active = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(recovery)!, "active.json")));
            string? installedVersion = active.RootElement.GetProperty("version").GetString();
            string oldVersion = Guid.NewGuid().ToString("N"), newVersion = Guid.NewGuid().ToString("N");
            if (oldVersion == newVersion || oldVersion == installedVersion || newVersion == installedVersion)
                throw new Boundary("bound_writer_test_version_collision");
            marker = new MaintenanceWriterMarker(1, "active", operation, own.User, own.Session, oldVersion, newVersion,
                info.Writer.Pid, info.Writer.Created, info.WriterImage, info.Writer.ImageDigest);
            SecurityLabel.CreateDirectory(directory, own.User);
            SecurityLabel.Write(markerPath, Bytes(marker), own.User);
            var policy = new BrokerPolicy { Version = oldVersion, UserSid = own.User, Mode = "high" };
            typeof(BrokerPolicy).GetProperty("Directory", BindingFlags.Instance | BindingFlags.NonPublic)!
                .SetValue(policy, AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
            var admission = BoundMaintenanceWriter.Verify(info.ChildPid, operation, policy, own);
            Assert(admission.Admin && admission.Evidence.ProductionAdmitted && admission.Evidence.Source == "bound-maintenance-writer"
                && admission.Evidence.SourcePid == writer.Id && admission.Peer.Pid == info.ChildPid, "real_admission");
            void Put(MaintenanceWriterMarker m) => File.WriteAllBytes(markerPath, Bytes(m));
            Put(marker with { WriterCreated = marker.WriterCreated + 1 });
            Reject(() => BoundMaintenanceWriter.Verify(info.ChildPid, operation, policy, own), "created_changed");
            Put(marker with { WriterImageSha256 = new string('0', 64) });
            Reject(() => BoundMaintenanceWriter.Verify(info.ChildPid, operation, policy, own), "hash_changed");
            Put(marker with { OldVersion = Guid.NewGuid().ToString("N") });
            Reject(() => BoundMaintenanceWriter.Verify(info.ChildPid, operation, policy, own), "version_changed");
            Put(marker with { State = "closed" });
            Reject(() => BoundMaintenanceWriter.Verify(info.ChildPid, operation, policy, own), "closed");
            Put(marker);
            child = Process.GetProcessById(info.ChildPid);
            writerEvent.Set();
            Assert(writer.WaitForExit(10000) && writer.ExitCode == 0 && !child.HasExited, "writer_exit_child_live");
            Reject(() => BoundMaintenanceWriter.Verify(info.ChildPid, operation, policy, own), "writer_exited");
            return new { assertions = 7, actual_high_token_verified = true, prodStopTouched = false,
                inputDispatched = false, ProductionAuthorityCreated = false, operationGUID = operation };
        }
        finally
        {
            try
            {
                if (marker is not null && File.Exists(markerPath)) File.WriteAllBytes(markerPath, Bytes(marker with { State = "closed" }));
            }
            finally
            {
                writerEvent.Set(); childEvent.Set();
                if (writer is not null) { writer.WaitForExit(10000); writer.Dispose(); }
                if (child is not null) { child.WaitForExit(10000); child.Dispose(); }
            }
        }
    }
}
