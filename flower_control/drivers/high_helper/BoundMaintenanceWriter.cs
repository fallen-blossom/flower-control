using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Principal;

namespace Flower.HighHelper;

internal sealed record MaintenanceWriterMarker(int Schema, string State, string OperationId,
    string UserSid, int Session, string OldVersion, string NewVersion, int WriterPid,
    long WriterCreated, string WriterImage, string WriterImageSha256,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? Purpose = null);

// A protected installation record binds exactly one live High writer and its
// direct native child. It is not an MCP source or a general admin admission.
// The caller must restrict phases and re-verify before every permitted request.
internal static class BoundMaintenanceWriter
{
    private static readonly string[] Fields = ["Schema", "State", "OperationId", "UserSid", "Session",
        "OldVersion", "NewVersion", "WriterPid", "WriterCreated", "WriterImage", "WriterImageSha256"];
    private static bool Hex32(string? value) => value is not null && Regex.IsMatch(value, "\\A[a-f0-9]{32}\\z");
    private static bool Hex64(string? value) => value is not null && Regex.IsMatch(value, "\\A[a-f0-9]{64}\\z");

    internal static MaintenanceWriterMarker ParseMarker(byte[] bytes)
    {
        if (bytes.Length is < 1 or > 32768) throw new Boundary("maintenance_writer_marker_invalid");
        try
        {
            using var document = JsonDocument.Parse(bytes);
            Protocol.CheckUnique(document);
            var root = document.RootElement;
            var names=root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
            bool exitMarker=names.SetEquals(Fields.Append("Purpose"));
            if (root.ValueKind != JsonValueKind.Object || (!names.SetEquals(Fields) && !exitMarker))
                throw new Boundary("maintenance_writer_marker_invalid");
            var marker = Protocol.Decode<MaintenanceWriterMarker>(document);
            if ((exitMarker ? marker.Schema != 2 || marker.Purpose != "exit" || marker.OldVersion != marker.NewVersion
                    : marker.Schema != 1 || marker.Purpose is not null || marker.OldVersion == marker.NewVersion)
                || marker.State != "active" || !Hex32(marker.OperationId)
                || !Hex32(marker.OldVersion) || !Hex32(marker.NewVersion)
                || marker.UserSid is null || new SecurityIdentifier(marker.UserSid).Value != marker.UserSid
                || marker.Session <= 0 || marker.WriterPid <= 0 || marker.WriterCreated <= 0
                || marker.WriterImage is null || !Path.IsPathFullyQualified(marker.WriterImage)
                || marker.WriterImage.StartsWith(@"\\\\", StringComparison.Ordinal)
                || marker.WriterImage.Any(char.IsControl) || !Hex64(marker.WriterImageSha256))
                throw new Boundary("maintenance_writer_marker_invalid");
            return marker;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or NotSupportedException)
        { throw new Boundary("maintenance_writer_marker_invalid"); }
    }

    internal static void RequirePhase(string? phase, bool ordinary = false)
    {
        if (phase != "status" && phase != (ordinary ? "maintenance_ordinary" : "maintenance"))
            throw new Boundary("maintenance_writer_phase_rejected");
    }

    internal static void RequireCommandForPurpose(string? purpose, string? command)
    {
        if(command is not ("pause" or "resume" or "shutdown") || purpose is not (null or "exit")
            || purpose == "exit" && command == "resume") throw new Boundary("maintenance_writer_command_rejected");
    }

    internal static void RequireMessage(Admission admission, JsonElement message)
    {
        if(admission.Evidence.Source != "bound-maintenance-exit-writer") return;
        if(!message.TryGetProperty("Phase",out var phase) || phase.ValueKind!=JsonValueKind.String)
            throw new Boundary("maintenance_writer_phase_rejected");
        if(phase.GetString()=="status") return;
        if(!message.TryGetProperty("Command",out var command) || command.ValueKind!=JsonValueKind.String)
            throw new Boundary("maintenance_writer_command_rejected");
        RequireCommandForPurpose("exit",command.GetString());
    }

    private static string MarkerPath(string operationId)
    {
        if (!Hex32(operationId)) throw new Boundary("maintenance_writer_operation_invalid");
        string root = InstallationLocation.Current().ProgramRoot;
        string recovery = Path.Combine(root, "recovery");
        string directory = Path.Combine(recovery, "installation-" + operationId);
        // Older shared parents can lack a High label, but cannot grant ordinary
        // users mutation. The operation directory and marker must be High.
        UacClaimJournal.CheckParent(Path.GetDirectoryName(root)!, false);
        UacClaimJournal.CheckParent(root, false);
        UacClaimJournal.CheckParent(recovery, false);
        UacClaimJournal.CheckParent(directory, true);
        string path = Path.Combine(directory, "maintenance-writer.json");
        var attributes = File.GetAttributes(path);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            throw new Boundary("maintenance_writer_marker_unprotected");
        BrokerPolicy.RejectLinks(path);
        UserPermissions.CheckProtection(path);
        return path;
    }

    internal static Admission Verify(int pid, string operationId, BrokerPolicy policy, Peer own)
    {
        if (policy.Fixture || own.Pid != Environment.ProcessId || own.Integrity is not (8192 or 12288)
            || own.User != policy.UserSid || own.Session <= 0 || Native.UiAccess(own.Pid))
            throw new Boundary("maintenance_writer_context_rejected");
        if (own.Integrity == 8192) NativeRoleIdentity.Require(own, policy, 8192);
        string path = MarkerPath(operationId);
        // Prevent a concurrent marker replacement or closure during admission.
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 32768) throw new Boundary("maintenance_writer_marker_invalid");
        var bytes = new byte[checked((int)file.Length)]; file.ReadExactly(bytes);
        var marker = ParseMarker(bytes);
        if (marker.OperationId != operationId || marker.UserSid != policy.UserSid || marker.UserSid != own.User
            || marker.Session != own.Session || policy.Version != marker.OldVersion && policy.Version != marker.NewVersion)
            throw new Boundary("maintenance_writer_binding_rejected");

        using var writerLifetime = Process.GetProcessById(marker.WriterPid);
        using var clientLifetime = Process.GetProcessById(pid);
        if (writerLifetime.HasExited || clientLifetime.HasExited) throw new Boundary("maintenance_writer_exited");
        var (writer, writerImage) = Native.Process(marker.WriterPid);
        var (client, clientImage) = Native.Process(pid);
        var (actualOwn, ownImage) = Native.Process(own.Pid);
        string expectedOwn = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        if (actualOwn != own || !ownImage.Equals(expectedOwn, StringComparison.OrdinalIgnoreCase)
            || own.ImageDigest != Native.Digest(expectedOwn)
            || writer.Pid != marker.WriterPid || writer.Created != marker.WriterCreated
            || writer.User != own.User || writer.Session != own.Session || writer.Integrity != 12288
            || Native.UiAccess(writer.Pid) || !writerImage.Equals(marker.WriterImage, StringComparison.OrdinalIgnoreCase)
            || writer.ImageDigest != marker.WriterImageSha256 || Native.Digest(writerImage) != marker.WriterImageSha256
            || client.Pid != pid || client.User != own.User || client.Session != own.Session || client.Integrity != 12288
            || Native.UiAccess(client.Pid) || !clientImage.Equals(ownImage, StringComparison.OrdinalIgnoreCase)
            || client.ImageDigest != own.ImageDigest || client.Created <= writer.Created
            || Native.ParentPid(client.Pid) != writer.Pid)
            throw new Boundary("maintenance_writer_peer_rejected");
        if (writerLifetime.HasExited || clientLifetime.HasExited
            || Native.Process(writer.Pid).Identity != writer || Native.Process(client.Pid).Identity != client
            || Native.ParentPid(client.Pid) != writer.Pid)
            throw new Boundary("maintenance_writer_peer_changed");
        return new Admission(client, new PeerEvidence(client.Pid, client.Created, client.Session,
            marker.Purpose == "exit" ? "bound-maintenance-exit-writer" : "bound-maintenance-writer",
            null, true, null, null, null, writer.Pid), true);
    }
}
