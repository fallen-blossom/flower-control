using System.IO.Pipes;
using System.Text.Json;

namespace Flower.HighHelper;

// A local human-facing convenience channel, not a host or task origin. Only
// the installed helper can ask for read-only status or post the settings-open
// message. It never creates Admission/PeerEvidence or enters the MCP loop.
internal static class LocalSettingsEntry
{
    internal const string Channel = "flower-local-settings";
    private sealed record Hello(string Phase, Peer Parent, string Channel, string? MaintenanceOperation = null);
    private sealed record HelloReply(string Phase, string Channel, Peer Helper, string Version,
        bool AuthorityGranted, bool InputDispatched);

    internal static void RequireClientFacts(bool fixture, string policySid, Peer server, bool ordinary,
        Peer actual, string image, string installedImage, bool uiAccess)
    {
        if (fixture || server.Pid <= 0 || server.Created <= 0 || server.Session <= 0 || server.User != policySid
            || server.Integrity != (ordinary ? 8192 : 12288) || server.ImageDigest.Length != 64
            || actual.Pid <= 0 || actual.Created <= 0 || actual.Pid == server.Pid || actual.Integrity != 8192
            || actual.User != policySid || actual.Session != server.Session || uiAccess
            || actual.ImageDigest != server.ImageDigest || !image.Equals(installedImage, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("local_settings_client_rejected");
    }

    internal static void RequireHello(string phase, Peer declared, Peer actual, string? maintenanceOperation)
    {
        if (phase != "hello" || declared != actual || maintenanceOperation is not null)
            throw new Boundary("local_settings_hello_rejected");
    }

    internal static string RequirePhase(JsonDocument message)
    {
        var root = message.RootElement;
        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1
            || !root.TryGetProperty("Phase", out var phase) || phase.ValueKind != JsonValueKind.String
            || phase.GetString() is not ("status" or "open_settings"))
            throw new Boundary("local_settings_phase_rejected");
        return phase.GetString()!;
    }

    internal static object Dispatch(JsonDocument message, Func<object> status, Action openSettings)
    {
        if (RequirePhase(message) == "status")
            return new { Phase = "status", Status = status(), AuthorityGranted = false, InputDispatched = false };
        openSettings();
        return new { Phase = "settings_open_requested", PolicyChanged = false, AuthorityGranted = false, InputDispatched = false };
    }

    internal static void Serve(NamedPipeServerStream pipe, BrokerPolicy policy, Peer own, BrokerState core,
        Peer actual, string image, string phase, Peer declared, string? maintenanceOperation)
    {
        RequireClientFacts(policy.Fixture, policy.UserSid, own, core.OrdinaryResident, actual, image,
            Path.Combine(policy.Directory, "Flower.HighHelper.exe"), Native.UiAccess(actual.Pid));
        RequireHello(phase, declared, actual, maintenanceOperation);
        // The server's running image is already bound to this protected
        // installation. Check the physical client too, never just its hello.
        BrokerPolicy.RejectLinks(image); UserPermissions.CheckSystemExecutableProtection(image);
        Protocol.Write(pipe, new HelloReply("hello", Channel, own, policy.Version, false, false));
        using var message = Protocol.Read(pipe, 3000, core.Shutdown.Token);
        if (message is null) return;
        Native.VerifyPeer(actual);
        if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid)
            || pid != actual.Pid) throw new Boundary("local_settings_client_changed");
        Protocol.Write(pipe, Dispatch(message, () => core.Snapshot(policy, own), () => HostWindow.RequestSettings(core)));
        // Exactly one request. No subsequent control, writer, work, recovery
        // acknowledgement or task packet can reach the general broker loop.
    }

    private static Peer RequireInstalledClient(BrokerPolicy policy)
    {
        var (own, image) = Native.Process(Environment.ProcessId);
        string executable = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        if (policy.Fixture || own.Integrity != 8192 || own.User != policy.UserSid || own.Session <= 0
            || Native.UiAccess(own.Pid) || !image.Equals(executable, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("local_settings_client_rejected");
        string manifest = Path.Combine(policy.Directory, "installation.json");
        BrokerPolicy.RejectLinks(manifest); UserPermissions.CheckProtection(manifest);
        using var seal = InstallationHealth.ReadManifest(manifest);
        var root = seal.RootElement;
        if (!root.TryGetProperty("version", out var version) || version.GetString() != policy.Version
            || !root.TryGetProperty("hashes", out var hashes) || hashes.ValueKind != JsonValueKind.Object)
            throw new Boundary("local_settings_installation_rejected");
        foreach (string name in new[] { "Flower.HighHelper.exe", "Flower.HighHelper.dll" })
        {
            string path = Path.Combine(policy.Directory, name);
            BrokerPolicy.RejectLinks(path);
            if (name.EndsWith(".exe", StringComparison.Ordinal)) UserPermissions.CheckSystemExecutableProtection(path);
            else UserPermissions.CheckProtection(path);
            if (!hashes.TryGetProperty(name, out var digest) || digest.ValueKind != JsonValueKind.String
                || Native.Digest(path) != digest.GetString()) throw new Boundary("local_settings_installation_rejected");
        }
        if (Native.Digest(executable) != own.ImageDigest) throw new Boundary("local_settings_client_changed");
        return own;
    }

    internal static void RequireServerFacts(Peer client, string clientImage, Peer actual, string image, bool ordinary,
        Peer? declared = null)
    {
        if (client.Integrity != 8192 || actual.Pid <= 0 || actual.Created <= 0 || actual.Pid == client.Pid
            || actual.User != client.User || actual.Session <= 0 || actual.Session != client.Session
            || actual.Integrity != (ordinary ? 8192 : 12288) || actual.ImageDigest != client.ImageDigest
            || !image.Equals(clientImage, StringComparison.OrdinalIgnoreCase) || declared is not null && declared != actual)
            throw new Boundary("local_settings_server_rejected");
    }

    internal static int Run(BrokerPolicy policy, bool openSettings)
    {
        var own = RequireInstalledClient(policy);
        string executable = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        bool highPresent = BrokerPipe.Present(BrokerPipe.Name(own)), ordinaryPresent = BrokerPipe.Present(BrokerPipe.OrdinaryName(own));
        if (highPresent && ordinaryPresent) throw new Boundary("executor_role_ambiguous");
        bool ordinary = !highPresent && ordinaryPresent;
        using var pipe = new NamedPipeClientStream(".", ordinary ? BrokerPipe.OrdinaryName(own) : BrokerPipe.Name(own),
            PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
        pipe.ConnectAsync(1500).GetAwaiter().GetResult();
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var serverPid))
            throw new Boundary("local_settings_server_unavailable");
        var (server, image) = Native.Process(checked((int)serverPid));
        RequireServerFacts(own, executable, server, image, ordinary);
        if (Native.UiAccess(server.Pid)) throw new Boundary("local_settings_server_rejected");
        Protocol.Write(pipe, new Hello("hello", own, Channel));
        using var greeting = Protocol.Read(pipe, 3000);
        if (greeting is null) throw new Boundary("pipe_disconnected");
        var hello = Protocol.Decode<HelloReply>(greeting);
        RequireServerFacts(own, executable, server, image, ordinary, hello.Helper);
        if (hello.Phase != "hello" || hello.Channel != Channel || hello.Version != policy.Version
            || hello.AuthorityGranted || hello.InputDispatched) throw new Boundary("local_settings_hello_rejected");
        Protocol.Write(pipe, new { Phase = openSettings ? "open_settings" : "status" });
        using var response = Protocol.Read(pipe, 5000);
        if (response is null) throw new Boundary("pipe_disconnected");
        Native.VerifyPeer(server);
        if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var finalPid)
            || finalPid != serverPid) throw new Boundary("local_settings_server_rejected");
        string expected = openSettings ? "settings_open_requested" : "status";
        if (!response.RootElement.TryGetProperty("Phase", out var resultPhase) || resultPhase.GetString() != expected
            || !response.RootElement.TryGetProperty("AuthorityGranted", out var authority) || authority.ValueKind != JsonValueKind.False
            || !response.RootElement.TryGetProperty("InputDispatched", out var input) || input.ValueKind != JsonValueKind.False
            || !openSettings && !response.RootElement.TryGetProperty("Status", out _))
            throw new Boundary("local_settings_response_rejected");
        Console.WriteLine(response.RootElement.GetRawText());
        return 0;
    }

    internal static object SelfTest()
    {
        int checks = 0, statusCalls = 0, settingsCalls = 0;
        void Check(bool value) { ++checks; if (!value) throw new Boundary("local_settings_entry_selftest_failed_" + checks); }
        void Reject(Action action, string code)
        {
            try { action(); Check(false); }
            catch (Boundary error) { Check(error.Code == code); }
        }
        const string sid = "S-1-5-21-1-2-3-1001", image = @"D:\FlowerControl\Program\versions\fixed\Flower.HighHelper.exe";
        var server = new Peer(100, 1000, 2, sid, new string('a', 64), 12288);
        var client = new Peer(200, 2000, 2, sid, server.ImageDigest, 8192);
        RequireClientFacts(false, sid, server, false, client, image, image, false); Check(true);
        RequireClientFacts(false, sid, server with { Integrity = 8192 }, true, client, image, image, false); Check(true);
        foreach (var bad in new[] { client with { User = "S-1-5-18" }, client with { Session = 3 },
            client with { Integrity = 12288 }, client with { Integrity = 4096 }, client with { Created = 0 },
            client with { ImageDigest = new string('b', 64) } })
            Reject(() => RequireClientFacts(false, sid, server, false, bad, image, image, false), "local_settings_client_rejected");
        Reject(() => RequireClientFacts(true, sid, server, false, client, image, image, false), "local_settings_client_rejected");
        Reject(() => RequireClientFacts(false, sid, server, false, client, image, image, true), "local_settings_client_rejected");
        Reject(() => RequireClientFacts(false, sid, server, true, client, image, image, false), "local_settings_client_rejected");
        Reject(() => RequireClientFacts(false, sid, server, false, client, @"D:\copy\Flower.HighHelper.exe", image, false), "local_settings_client_rejected");
        RequireHello("hello", client, client, null); Check(true);
        Reject(() => RequireHello("hello", client with { Created = 3000 }, client, null), "local_settings_hello_rejected");
        Reject(() => RequireHello("hello", client, client, "operation"), "local_settings_hello_rejected");
        Reject(() => RequireHello("prepare", client, client, null), "local_settings_hello_rejected");
        RequireServerFacts(client, image, server, image, false, server); Check(true);
        foreach (var bad in new[] { server with { User = "S-1-5-18" }, server with { Session = 3 },
            server with { Integrity = 8192 }, server with { ImageDigest = new string('b', 64) }, server with { Created = 0 } })
            Reject(() => RequireServerFacts(client, image, bad, image, false), "local_settings_server_rejected");
        Reject(() => RequireServerFacts(client, image, server, image, false, server with { Created = 3000 }), "local_settings_server_rejected");
        object Status() { ++statusCalls; return new { version = "fixture", paused = true }; }
        void Open() { ++settingsCalls; }
        foreach (string phase in new[] { "control", "prepare", "work_authority", "program_launch", "maintenance", "maintenance_ordinary",
            "local_ui_get", "local_ui_result", "local_ui_preflight", "local_ui_begin_commit", "role_handoff_get", "role_handoff_ready",
            "release_recovery_ack", "password_metadata", "uac_host_event", "dsh_context" })
        {
            using var packet = JsonDocument.Parse(JsonSerializer.Serialize(new { Phase = phase }));
            Reject(() => Dispatch(packet, Status, Open), "local_settings_phase_rejected");
        }
        foreach (string json in new[] { "{\"Phase\":\"status\",\"approved\":true}", "{\"Phase\":\"open_settings\",\"Tier\":2}", "{\"Phase\":1}", "[]" })
        {
            using var packet = JsonDocument.Parse(json);
            Reject(() => Dispatch(packet, Status, Open), "local_settings_phase_rejected");
        }
        Check(statusCalls == 0 && settingsCalls == 0);
        using var status = JsonDocument.Parse("{\"Phase\":\"status\"}");
        using var statusReply = JsonSerializer.SerializeToDocument(Dispatch(status, Status, Open));
        Check(statusCalls == 1 && settingsCalls == 0 && !statusReply.RootElement.GetProperty("AuthorityGranted").GetBoolean());
        using var settings = JsonDocument.Parse("{\"Phase\":\"open_settings\"}");
        using var settingsReply = JsonSerializer.SerializeToDocument(Dispatch(settings, Status, Open));
        Check(statusCalls == 1 && settingsCalls == 1 && settingsReply.RootElement.GetProperty("Phase").GetString() == "settings_open_requested"
            && !settingsReply.RootElement.GetProperty("PolicyChanged").GetBoolean());
        return new { passed = true, assertions = checks, productionInstallationRead = false,
            permissionOrStopChanged = false, taskAuthorityGranted = false, actualWindowShown = false,
            scope = "synthetic exact-peer admission and closed two-phase dispatcher; no production pipe or GUI" };
    }
}
