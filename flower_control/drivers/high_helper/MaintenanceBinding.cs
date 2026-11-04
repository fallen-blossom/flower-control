using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// A narrower update-only form of the existing local High control. Every value
// is immutable for this one dispatch; no fallback to an unbound control exists.
internal sealed record MaintenanceBinding(
    [property: JsonRequired] string Version,
    [property: JsonRequired] int Pid,
    [property: JsonRequired] long Created,
    [property: JsonRequired] long SharedEpoch,
    [property: JsonRequired] long ProtectedEpoch,
    [property: JsonRequired] bool Paused,
    [property: JsonRequired] bool ComputerPaused)
{
    internal void RequireValid(string command)
    {
        if (Version is null || !Regex.IsMatch(Version, "\\A[a-f0-9]{32}\\z") || Pid <= 0 || Created <= 0
            || SharedEpoch < 0 || ProtectedEpoch < 0 || command is not ("pause" or "resume" or "shutdown")
            || Paused != (command != "pause")) throw new Boundary("maintenance_binding_invalid");
        if (command == "pause" && (SharedEpoch == long.MaxValue || ProtectedEpoch == long.MaxValue)
            || command == "resume" && ProtectedEpoch == long.MaxValue)
            throw new Boundary("stop_epoch_exhausted");
    }

    internal void RequireProcess(int pid, long created, string version)
    {
        if (pid != Pid || created != Created || version != Version)
            throw new Boundary("maintenance_instance_changed");
    }

    internal void RequireSnapshot(JsonElement status)
    {
        if (status.ValueKind != JsonValueKind.Object
            || !status.TryGetProperty("maintenance_protocol", out var protocol)
            || protocol.ValueKind != JsonValueKind.Number || !protocol.TryGetInt32(out var schema) || schema != 1)
            throw new Boundary("maintenance_binding_unsupported");
        long Number(string name)
        {
            if (!status.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number
                || !value.TryGetInt64(out var number) || number < 0)
                throw new Boundary("maintenance_status_invalid");
            return number;
        }
        bool Flag(string name)
        {
            if (!status.TryGetProperty(name, out var value) || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new Boundary("maintenance_status_invalid");
            return value.GetBoolean();
        }
        if (!status.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.String)
            throw new Boundary("maintenance_status_invalid");
        if (version.GetString() != Version || Number("pid") != Pid || Number("created") != Created)
            throw new Boundary("maintenance_instance_changed");
        if (Number("global_stop_epoch") != SharedEpoch || Number("protected_stop_epoch") != ProtectedEpoch
            || Flag("paused") != Paused || Flag("global_write_stopped") != Paused
            || Flag("computer_paused") != ComputerPaused)
            throw new Boundary("maintenance_state_changed");
        if (!Flag("high_verified") || Flag("stopping") || Flag("release_fault")
            || Number("active_requests") != 0 || Number("pending_release_recoveries") != 0 || Number("maintenance_activities") != 0)
            throw new Boundary("maintenance_not_idle");
        foreach (var name in new[] { "stop_persistence_error", "computer_pause_persistence_error" })
        {
            if (!status.TryGetProperty(name, out var error) || error.ValueKind != JsonValueKind.Null)
                throw new Boundary("maintenance_persistence_unconfirmed");
        }
    }
}

internal sealed record MaintenanceCommand(
    [property: JsonRequired] string Phase,
    [property: JsonRequired] string Command,
    [property: JsonRequired] MaintenanceBinding Expected)
{
    internal void RequireValid()
    {
        if (Phase != "maintenance" || Expected is null) throw new Boundary("maintenance_binding_invalid");
        Expected.RequireValid(Command);
    }

    internal static MaintenanceCommand Parse(string[] args, string version)
    {
        if (args.Length != 8 || args[0] != "--flower-maintenance"
            || !int.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var pid)
            || !long.TryParse(args[3], NumberStyles.None, CultureInfo.InvariantCulture, out var created)
            || !long.TryParse(args[4], NumberStyles.None, CultureInfo.InvariantCulture, out var shared)
            || !long.TryParse(args[5], NumberStyles.None, CultureInfo.InvariantCulture, out var authority)
            || args[6] is not ("true" or "false") || args[7] is not ("true" or "false"))
            throw new Boundary("maintenance_binding_invalid");
        var result = new MaintenanceCommand("maintenance", args[1],
            new(version, pid, created, shared, authority, args[6] == "true", args[7] == "true"));
        result.RequireValid();
        return result;
    }
}
