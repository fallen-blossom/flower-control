using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Flower.HighHelper;

// Pure binding/transition/wire tests. No token query, pipe connection, mutex,
// protected path, Stop journal, GUI, process start or elevation is performed.
internal static class OrdinaryMaintenanceTests
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private static OrdinaryMaintenanceBinding Binding(bool paused = true) => new(new string('a', 32), 123, 456,
        new string('b', 32), 0, new(new(paused, 7, 3), new(1, Sid, 1, false, 9), new(1, Sid, 1, false, 5),
            new(paused ? 3 : 2, 2), new(1, 1)), paused, false);

    private static Dictionary<string, object?> Snapshot(OrdinaryMaintenanceBinding value) => new()
    {
        ["maintenance_protocol"] = 2, ["broker_role"] = "ordinary", ["ordinary_verified"] = true, ["high_verified"] = false,
        ["version"] = value.Version, ["pid"] = value.Pid, ["created"] = value.Created,
        ["policy_revision"] = value.PolicyRevision, ["authority_tier"] = value.Tier, ["role_stop"] = value.Stop,
        ["global_stop_epoch"] = value.Stop.Shared.Epoch, ["protected_stop_epoch"] = value.Stop.Protected.Epoch,
        ["paused"] = value.Paused, ["global_write_stopped"] = value.Stop.Shared.Stopped, ["computer_paused"] = value.ComputerPaused,
        ["stopping"] = false, ["release_fault"] = false, ["role_transition"] = false,
        ["active_requests"] = 0, ["pending_release_recoveries"] = 0, ["maintenance_activities"] = 0,
        ["stop_persistence_error"] = null, ["computer_pause_persistence_error"] = null
    };

    internal static object Run()
    {
        int checks = 0;
        void Check(bool value) { ++checks; if (!value) throw new Boundary("ordinary_maintenance_selftest_failed"); }
        void Reject(Action action, params string[] codes)
        {
            try { action(); }
            catch (Boundary error) { Check(codes.Contains(error.Code)); return; }
            catch (JsonException) { Check(codes.Contains("schema_rejected")); return; }
            throw new Boundary("ordinary_maintenance_selftest_missing_rejection");
        }
        void AcceptSnapshot(OrdinaryMaintenanceBinding expected, Dictionary<string, object?> value)
        { expected.RequireSnapshot(JsonSerializer.SerializeToElement(value)); Check(true); }
        void RejectSnapshot(OrdinaryMaintenanceBinding expected, string key, object? value, string code)
        { var altered = Snapshot(expected); altered[key] = value; Reject(() => expected.RequireSnapshot(JsonSerializer.SerializeToElement(altered)), code); }

        var running = Binding(false); var stopped = Binding();
        running.RequireValid("pause"); stopped.RequireValid("resume"); stopped.RequireValid("shutdown"); Check(true);
        AcceptSnapshot(running, Snapshot(running)); AcceptSnapshot(stopped, Snapshot(stopped));
        var disabled = stopped with { Tier = -1 }; disabled.RequireValid("resume"); AcceptSnapshot(disabled, Snapshot(disabled));
        var legacy = new MaintenanceBinding(stopped.Version, stopped.Pid, stopped.Created,
            stopped.Stop.Shared.Epoch, stopped.Stop.Protected.Epoch, true, false);
        var high = Snapshot(stopped); high["maintenance_protocol"] = 1; high["broker_role"] = "high";
        high["high_verified"] = true; high["ordinary_verified"] = false;
        legacy.RequireValid("resume"); legacy.RequireSnapshot(JsonSerializer.SerializeToElement(high)); Check(true);
        high["high_verified"] = false;
        Reject(() => legacy.RequireSnapshot(JsonSerializer.SerializeToElement(high)), "maintenance_not_idle");
        Reject(() => legacy.RequireSnapshot(JsonSerializer.SerializeToElement(Snapshot(stopped))), "maintenance_binding_unsupported");
        foreach (var item in new[] { stopped with { Tier = 1 }, stopped with { Tier = -2 }, stopped with { Pid = 0 },
            stopped with { Created = 0 }, stopped with { Version = stopped.Version + "\n" }, stopped with { PolicyRevision = "" },
            stopped with { Paused = false }, stopped with { ComputerPaused = true }, stopped with { Stop = null! },
            stopped with { Stop = stopped.Stop with { Shared = new(true, 1, 2) } },
            stopped with { Stop = stopped.Stop with { Protected = stopped.Stop.Protected with { Schema = 2 } } },
            stopped with { Stop = stopped.Stop with { Computer = stopped.Stop.Computer with { Session = 2 } } },
            stopped with { Stop = stopped.Stop with { Ordinary = new(2, 3) } },
            stopped with { Stop = stopped.Stop with { OrdinaryComputer = new(-1, 0) } } })
            Reject(() => item.RequireValid("resume"), "maintenance_binding_invalid");
        Reject(() => stopped.RequireValid("pause"), "maintenance_binding_invalid");
        Reject(() => running.RequireValid("resume"), "maintenance_binding_invalid");
        Reject(() => stopped.RequireValid("settings"), "maintenance_binding_invalid");
        Reject(() => (running with { Stop = running.Stop with { Shared = new(false, long.MaxValue, 0) } }).RequireValid("pause"), "stop_epoch_exhausted");
        Reject(() => (stopped with { Stop = stopped.Stop with { Protected = stopped.Stop.Protected with { Epoch = long.MaxValue } } }).RequireValid("resume"), "stop_epoch_exhausted");

        RejectSnapshot(stopped, "maintenance_protocol", 1, "maintenance_binding_unsupported");
        RejectSnapshot(stopped, "maintenance_protocol", "2", "maintenance_status_invalid");
        RejectSnapshot(stopped, "broker_role", "high", "maintenance_role_rejected");
        RejectSnapshot(stopped, "broker_role", "fixture", "maintenance_role_rejected");
        RejectSnapshot(stopped, "ordinary_verified", false, "maintenance_role_rejected");
        RejectSnapshot(stopped, "high_verified", true, "maintenance_role_rejected");
        RejectSnapshot(stopped, "pid", 124, "maintenance_instance_changed");
        RejectSnapshot(stopped, "created", 457, "maintenance_instance_changed");
        RejectSnapshot(stopped, "version", new string('c', 32), "maintenance_instance_changed");
        RejectSnapshot(stopped, "policy_revision", "changed", "maintenance_state_changed");
        RejectSnapshot(stopped, "authority_tier", 1, "maintenance_state_changed");
        RejectSnapshot(stopped, "global_stop_epoch", 8, "maintenance_state_changed");
        RejectSnapshot(stopped, "protected_stop_epoch", 10, "maintenance_state_changed");
        RejectSnapshot(stopped, "paused", false, "maintenance_state_changed");
        RejectSnapshot(stopped, "global_write_stopped", false, "maintenance_state_changed");
        RejectSnapshot(stopped, "computer_paused", true, "maintenance_state_changed");
        foreach (string flag in new[] { "stopping", "release_fault", "role_transition" }) RejectSnapshot(stopped, flag, true, "maintenance_not_idle");
        foreach (string count in new[] { "active_requests", "pending_release_recoveries", "maintenance_activities" })
        { RejectSnapshot(stopped, count, 1, "maintenance_not_idle"); RejectSnapshot(stopped, count, false, "maintenance_status_invalid"); }
        foreach (string error in new[] { "stop_persistence_error", "computer_pause_persistence_error" })
            RejectSnapshot(stopped, error, "fixture_failure", "maintenance_persistence_unconfirmed");
        foreach (string missing in Snapshot(stopped).Keys)
        {
            var value = Snapshot(stopped); value.Remove(missing);
            Reject(() => stopped.RequireSnapshot(JsonSerializer.SerializeToElement(value)), "maintenance_status_invalid", "maintenance_state_changed", "maintenance_persistence_unconfirmed");
        }
        foreach (var changed in new[] {
            stopped.Stop with { Shared = stopped.Stop.Shared with { Epoch = 8 } },
            stopped.Stop with { Protected = stopped.Stop.Protected with { Stopped = true, Epoch = 10 } },
            stopped.Stop with { Ordinary = new(4, 2) }, // New Stop, even before shared epoch changes.
            stopped.Stop with { Ordinary = new(3, 3) }, // Another High acknowledgement advanced.
            stopped.Stop with { OrdinaryComputer = new(2, 1) },
            stopped.Stop with { Computer = stopped.Stop.Computer with { Stopped = true, Epoch = 6 } } })
            RejectSnapshot(stopped, "role_stop", changed, "maintenance_state_changed");

        var pause = running.AfterPause();
        Check(pause.Stop.Shared == new SharedWriteGate.Status(true, 8, 3));
        Check(pause.Stop.Ordinary == new OrdinaryStopState(3, 2) && pause.Stop.Protected == running.Stop.Protected);
        pause.RequireValid("resume"); AcceptSnapshot(pause, Snapshot(pause));
        var resumed = pause.AfterResume();
        Check(resumed.Stop.Shared == new SharedWriteGate.Status(false, 8, 8));
        Check(resumed.Stop.Ordinary == new OrdinaryStopState(3, 3) && resumed.Stop.Protected == pause.Stop.Protected with { Epoch = 10, Stopped = false });
        Check(resumed.Stop.Computer == running.Stop.Computer && resumed.Stop.OrdinaryComputer == running.Stop.OrdinaryComputer);
        AcceptSnapshot(resumed, Snapshot(resumed));
        var shutdown = Snapshot(stopped); shutdown["stopping"] = true;
        stopped.RequireSnapshot(JsonSerializer.SerializeToElement(shutdown), stopping: true); Check(true);

        var policy = new UserPermissionSettings { UserSid = Sid, Revision = stopped.PolicyRevision, AuthorityTier = 0 };
        stopped.RequirePolicy(policy); Check(true);
        Reject(() => stopped.RequirePolicy(policy with { Revision = "new-revision" }), "maintenance_state_changed");
        Reject(() => stopped.RequirePolicy(policy with { AuthorityTier = 1 }), "maintenance_state_changed");
        Reject(() => stopped.RequirePolicy(policy with { UserSid = "S-1-5-21-111-222-333-1001" }), "maintenance_state_changed");

        var authority = new OrdinaryMaintenance.Authority(stopped.Stop.Protected, stopped.Stop.Ordinary, stopped.Stop.Computer, stopped.Stop.OrdinaryComputer);
        OrdinaryMaintenance.RequireAuthority(stopped.Stop, authority); Check(true);
        Reject(() => OrdinaryMaintenance.RequireAuthority(stopped.Stop, authority with { Ordinary = new(4, 2) }), "maintenance_state_changed");
        Reject(() => OrdinaryMaintenance.RequireAuthority(stopped.Stop, authority with { Ordinary = new(3, 3) }), "maintenance_state_changed");
        Reject(() => OrdinaryMaintenance.RequireAuthority(stopped.Stop, authority with { OrdinaryComputer = new(2, 2) }), "maintenance_state_changed");
        string nonce = new('d', 32);
        var completed = new OrdinaryMaintenanceCompleted("maintenance_ordinary_completed", nonce, resumed.Stop.Protected, resumed.Stop.Ordinary);
        OrdinaryMaintenance.RequireCompleted(completed, nonce, pause); Check(true);
        foreach (var wrong in new[] { completed with { Nonce = new string('e', 32) }, completed with { Phase = "control" },
            completed with { Ordinary = new(4, 4) }, completed with { Ordinary = new(3, 2) },
            completed with { Protected = completed.Protected with { Epoch = 11 } } })
            Reject(() => OrdinaryMaintenance.RequireCompleted(wrong, nonce, pause), "maintenance_resume_unconfirmed");
        using (var packet = JsonSerializer.SerializeToDocument(completed)) Check(OrdinaryMaintenance.DecodeCompleted(packet) == completed);
        var incompleteCompletion = JsonNode.Parse(JsonSerializer.Serialize(completed))!.AsObject();
        incompleteCompletion["Protected"]!.AsObject().Remove("Stopped");
        using (var packet = JsonDocument.Parse(incompleteCompletion.ToJsonString()))
            Reject(() => OrdinaryMaintenance.DecodeCompleted(packet), "maintenance_status_invalid");

        string encoded = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(stopped));
        var parsed = OrdinaryMaintenanceCommand.Parse(["--flower-maintenance-ordinary", "resume", encoded], stopped.Version);
        Check(parsed.Expected == stopped && parsed.Command == "resume");
        Reject(() => OrdinaryMaintenanceCommand.Parse(["--flower-maintenance-ordinary", "resume", encoded], new string('f', 32)), "maintenance_instance_changed");
        foreach (string[] args in new[] { new[] { "--flower-maintenance-ordinary", "resume" },
            new[] { "--flower-admin", "resume", encoded }, new[] { "--flower-maintenance-ordinary", "settings", encoded },
            new[] { "--flower-maintenance-ordinary", "resume", encoded + " " }, new[] { "--flower-maintenance-ordinary", "resume", "!!!!" } })
            Reject(() => OrdinaryMaintenanceCommand.Parse(args, stopped.Version), "maintenance_binding_invalid");
        string duplicateTier = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(stopped).Replace("\"Tier\":0", "\"Tier\":0,\"Tier\":0")));
        Reject(() => OrdinaryMaintenanceCommand.Parse(["--flower-maintenance-ordinary", "resume", duplicateTier], stopped.Version), "schema_rejected");
        foreach (string path in new[] { "Stop.Shared.ResumeAllEpoch", "Stop.Shared.Stopped", "Stop.Protected.Stopped", "Stop.Ordinary.Acknowledged", "Tier" })
        {
            var node = JsonNode.Parse(JsonSerializer.Serialize(stopped))!.AsObject(); var names = path.Split('.'); JsonObject cursor = node;
            foreach (string name in names[..^1]) cursor = cursor[name]!.AsObject(); cursor.Remove(names[^1]);
            string missing = Convert.ToBase64String(Encoding.UTF8.GetBytes(node.ToJsonString()));
            Reject(() => OrdinaryMaintenanceCommand.Parse(["--flower-maintenance-ordinary", "resume", missing], stopped.Version), "maintenance_status_invalid", "maintenance_binding_invalid");
        }
        using (var packet = JsonSerializer.SerializeToDocument(parsed)) { Check(OrdinaryMaintenanceCommand.Decode(packet) == parsed); }
        var badPacket = JsonNode.Parse(JsonSerializer.Serialize(parsed))!.AsObject(); badPacket["Expected"]!["Stop"]!["Shared"]!.AsObject().Remove("Stopped");
        using (var packet = JsonDocument.Parse(badPacket.ToJsonString())) Reject(() => OrdinaryMaintenanceCommand.Decode(packet), "maintenance_status_invalid");
        using (var packet = JsonDocument.Parse("{\"Phase\":\"error\",\"Reason\":\"maintenance_state_changed\"}"))
            Reject(() => OrdinaryMaintenance.RequireNotError(packet), "maintenance_state_changed");
        using (var packet = JsonDocument.Parse("{\"Phase\":\"error\",\"Reason\":\"untrusted text\"}"))
            Reject(() => OrdinaryMaintenance.RequireNotError(packet), "maintenance_result_unconfirmed");
        return new { passed = true, assertions = checks, productionStopTouched = false, elevated = false,
            inputDispatched = false, evidence = "pure-binding-transition-wire-only" };
    }
}
