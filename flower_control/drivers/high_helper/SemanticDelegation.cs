using System.Text.Json.Serialization;

namespace Flower.HighHelper;

// Saved only by the local High settings writer, never decoded from an MCP
// request. Old semantic preferences without this marker remain un-delegated.
internal sealed record LocalSemanticDelegation(int Schema, string Id, string UserSid, string HostKind)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AdditionalHostKind { get; init; }
}
internal sealed record WorkHostMessage(string SessionHash, string EventDigest);

internal static class SemanticDelegation
{
    // Existing Codex-only markers retain their exact scope. Only a fresh local
    // confirmation may add the independently identified DSH host.
    internal static bool IncludesDsh(LocalSemanticDelegation? value)
        => value is { Schema: 2, HostKind: "codex", AdditionalHostKind: "dsh-desktop" };
    internal static LocalSemanticDelegation ForExplicitSelection(string sid)
        => new(2, Guid.NewGuid().ToString("N"), sid, "codex") { AdditionalHostKind = "dsh-desktop" };
    internal static LocalSemanticDelegation? ForLocalSave(UserPermissionSettings before, UserPermissionSettings submitted)
    {
        if (submitted.AdminLaunchMode != "semantic") return null;
        // Off-first saves retain AdminLaunchMode. Enabled/tier transitions are
        // not evidence of selecting semantic and must never migrate old prefs.
        if (before.AdminLaunchMode == "semantic") return before.SemanticDelegation;
        return new(1, Guid.NewGuid().ToString("N"), submitted.UserSid, "codex");
    }

    internal static LocalSemanticDelegation Require(UserPermissionSettings settings, string sid, AuditThread thread)
    {
        var delegation = settings.SemanticDelegation;
        if (!UserPermissions.Effective(settings).AdminLaunchEnabled || settings.AdminLaunchMode != "semantic")
            throw new Boundary("semantic_delegation_disabled");
        if (delegation is null) throw new Boundary("semantic_delegation_local_selection_required");
        Validate(delegation, sid);
        if (thread.HostKind != delegation.HostKind
            && !(delegation.AdditionalHostKind is not null && thread.HostKind == delegation.AdditionalHostKind))
            throw new Boundary("semantic_delegation_host_rejected");
        return delegation;
    }

    internal static void Validate(LocalSemanticDelegation value, string sid)
    {
        if (!Guid.TryParseExact(value.Id, "N", out var id) || id.ToString("N") != value.Id
            || value.UserSid != sid || value.HostKind != "codex"
            || !(value.Schema == 1 && value.AdditionalHostKind is null || IncludesDsh(value)))
            throw new Boundary("semantic_delegation_invalid");
    }
}

internal static class SemanticWorkSource
{
    internal static WorkHostMessage Current(AuditThread thread)
    {
        if (thread.HostKind is not ("codex" or "dsh-desktop")) throw new Boundary("semantic_delegation_host_rejected");
        return UacTranscriptBinding.ReadWorkMessage(SessionHash(thread));
    }
    internal static T Dispatch<T>(AuditThread thread, string expectedDigest, Func<T> create)
        => UacTranscriptBinding.DispatchWorkMessage(SessionHash(thread), expectedDigest, create);
    private static string SessionHash(AuditThread thread) => thread.HostKind == "dsh-desktop"
        ? DshTranscriptReader.SessionHash(thread.ThreadId) : UacTranscriptBinding.SessionHash(thread.ThreadId);
}
