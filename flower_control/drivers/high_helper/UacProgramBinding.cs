using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed record UacProgramBindingAvailability(bool Available, string Reason);
internal sealed record UacProgramFileIdentity(string Path, string Sha256, string IdentityKind, string Identity, string Volume, string FileId, bool AllowlistProtected = false)
{
    internal UacApplicationPermission Permission => new(Path, IdentityKind, Identity, System.IO.Path.GetFileName(Path));
}

// The only binding source is this worker's native observation cache. A model
// path, display name, bool or deserialized qualification file cannot mint it.
internal static class UacProgramBinding
{
    internal static JsonDocument ObservePrompt(ManualResetEvent stop, ManualResetEvent physicalStop, bool requestBinding,
        UacPromptIdentity? expectedPrompt = null)
    {
        if (!requestBinding) return UacNativeBridge.ObservePrompt(stop, physicalStop, false);
        if (expectedPrompt is null) throw new Boundary("uac_details_require_exact_prompt");
        var preview = UacNativeBridge.ObservePrompt(stop, physicalStop, false);
        if (!preview.RootElement.TryGetProperty("observation_id", out _)) return preview;
        try
        {
            var root = preview.RootElement;
            var actual = new UacPromptIdentity(root.GetProperty("session").GetInt32(), root.GetProperty("pid").GetInt32(),
                root.GetProperty("created").GetInt64(), root.GetProperty("hwnd").GetInt64());
            if (actual != expectedPrompt) throw new Boundary("uac_prompt_changed_before_details");
            // Native binds the next expansion to this process-local preview and
            // rechecks the instance before its single Expand/Invoke call.
            using var resources = new ResourceLocks(["desktop-foreground-input-v1"]);
            return UacNativeBridge.ObservePrompt(stop, physicalStop, true);
        }
        finally { preview.Dispose(); }
    }
    internal static UacProgramBindingAvailability Readiness()
    {
        try
        {
            using var document = UacNativeBridge.ProgramBindingReadiness(); var root = document.RootElement;
            return new(root.TryGetProperty("available", out var item) && item.ValueKind == JsonValueKind.True,
                root.GetProperty("reason").GetString() ?? "uac_program_profile_unavailable");
        }
        catch (Exception error) { return new(false, Program.Code(error)); }
    }
    internal static UacProgramFileIdentity DecodeIdentity(JsonElement root)
    {
        if (root.TryGetProperty("reason", out var reason)) throw new Boundary(reason.GetString() ?? "uac_program_identity_unavailable");
        string Read(string name) => root.GetProperty(name).GetString() ?? throw new Boundary("uac_program_identity_rejected");
        var value = new UacProgramFileIdentity(Read("path"), Read("sha256"), Read("identity_kind"), Read("identity"), Read("volume"), Read("file_id"),
            root.TryGetProperty("allowlist_protected", out var protection) && protection.ValueKind == JsonValueKind.True);
        bool Hex(string text, int size) => Regex.IsMatch(text, "\\A[a-f0-9]{" + size + "}\\z");
        if (!System.IO.Path.IsPathFullyQualified(value.Path) || value.Path.StartsWith("\\\\", StringComparison.Ordinal)
            || value.Path.Any(char.IsControl) || value.Path.Skip(2).Contains(':') || value.Path.Contains('*') || value.Path.Contains('?')
            || value.IdentityKind is not ("signed" or "sha256") || !Hex(value.Sha256, 64) || !Hex(value.Identity, 64)
            || !Hex(value.Volume, 16) || !Hex(value.FileId, 32) || value.IdentityKind == "sha256" && value.Identity != value.Sha256)
            throw new Boundary("uac_program_identity_rejected");
        return value;
    }
    internal static UacProgramBindingLease? TryPin(JsonElement observed)
    {
        if (!observed.TryGetProperty("program_binding_verified", out var valid) || valid.ValueKind != JsonValueKind.True) return null;
        var nonce = observed.GetProperty("observation_id").GetString() ?? throw new Boundary("uac_program_binding_rejected");
        if (!Regex.IsMatch(nonce, "\\A[a-f0-9]{64}\\z")) throw new Boundary("uac_program_binding_rejected");
        var expected = DecodeIdentity(observed.GetProperty("program_identity"));
        if (observed.GetProperty("program_path").GetString() != expected.Path) throw new Boundary("uac_program_binding_rejected");
        string? argumentsSha256 = observed.TryGetProperty("program_arguments_sha256", out var digest)
            && digest.ValueKind == JsonValueKind.String ? digest.GetString() : null;
        if (argumentsSha256 is not null && !Regex.IsMatch(argumentsSha256, "\\A[a-f0-9]{64}\\z"))
            throw new Boundary("uac_program_arguments_rejected");
        var lease = new UacProgramBindingLease(nonce, expected, argumentsSha256);
        try { lease.Recheck(); return lease; }
        catch (Boundary error) when (error.Code is "program_binding_stale_or_foreign" or "uac_program_changed"
            or "program_profile_component_changed" or "program_profile_changed" or "uac_program_ancestor_changed"
            or "uac_program_case_sensitive_or_unknown" or "uac_program_signature_unknown")
        { lease.Dispose(); return null; }
    }
    // Reads only a native-issued diagnostic snapshot. Output is explicitly a
    // draft; ordinary production observation does not include all text fields.
    internal static JsonDocument CreateQualificationDraft() => UacNativeBridge.ProgramQualificationDraft();
    internal static JsonDocument ObserveQualificationPrompt(ManualResetEvent stop, ManualResetEvent physicalStop)
    {
        using var resources = new ResourceLocks(["desktop-foreground-input-v1"]);
        return UacNativeBridge.ObserveProgramQualificationFields(stop, physicalStop);
    }
    internal static JsonDocument RecordQualificationSample(uint index, uint actualTargetPid, string nativeObservationNonce)
        => UacNativeBridge.RecordProgramQualification(index, actualTargetPid, nativeObservationNonce);
    // Registration takes an opaque process-local native session, never JSON
    // flags or caller-selected paths/AutomationIds. It succeeds only after all
    // three fixed native witness samples and actual target objects qualify.
    internal static JsonDocument RegisterQualification(string nativeSessionNonce)
        => UacNativeBridge.RegisterProgramQualification(nativeSessionNonce);
}

internal sealed class UacProgramBindingLease : IDisposable
{
    private readonly string nonce;
    private readonly UacProgramFileIdentity expected;
    private bool disposed;
    internal UacApplicationPermission Program => expected.Permission;
    internal string? ArgumentsSha256 { get; }
    internal bool AllowlistProtected => expected.AllowlistProtected;
    internal UacProgramBindingLease(string nonce, UacProgramFileIdentity expected, string? argumentsSha256)
    { this.nonce = nonce; this.expected = expected; ArgumentsSha256 = argumentsSha256; }
    internal void Recheck()
    {
        if (disposed) throw new Boundary("uac_program_binding_released");
        using var current = UacNativeBridge.RecheckProgramBinding(nonce);
        if (UacProgramBinding.DecodeIdentity(current.RootElement) != expected) throw new Boundary("uac_program_changed");
        string? digest = current.RootElement.TryGetProperty("arguments_sha256", out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
        if (digest != ArgumentsSha256) throw new Boundary("uac_program_arguments_changed");
    }
    public void Dispose()
    {
        if (disposed) return; disposed = true;
        using var released = UacNativeBridge.ReleaseProgramBinding(nonce);
        if (!released.RootElement.TryGetProperty("released", out var result) || result.ValueKind != JsonValueKind.True)
            throw new Boundary("uac_program_binding_release_unverified");
    }
}
