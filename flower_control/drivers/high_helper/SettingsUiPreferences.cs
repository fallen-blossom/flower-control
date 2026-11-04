using System.Security.Principal;
using System.Text.Json;

namespace Flower.HighHelper;

// Presentation only. Neither the permission decoder nor an executor consumes
// this file; remembering a choice must never activate UAC or semantic execution.
internal sealed record SettingsUiPreference(string UacSubmode = "allowlist", string Revision = "absent", string? Error = null);
internal sealed record SettingsUiSave(string SubmittedMode, SettingsUiPreference? Saved = null, string? Error = null,
    bool PolicyWritten = false, bool PreferenceRequested = true);

internal static partial class UserPermissions
{
    private static string UiPreferencePath => Path.ChangeExtension(FilePath, ".settings-ui.json");
    internal static string PreferredUacSubmode(string active, SettingsUiPreference preference)
        => active is "allowlist" or "semantic" ? active : preference.UacSubmode;
    internal static bool UiPreferenceNeedsSave(string originalMode, string editedMode, string submittedMode,
        string baselineMode, SettingsUiPreference preference, bool pending)
        => pending || submittedMode != baselineMode
            || originalMode is "allowlist" or "semantic" && editedMode == "off"
                && (preference.Error is not null || preference.Revision == "absent" || preference.UacSubmode != submittedMode);

    internal static SettingsUiPreference ReadUiPreference()
        => ReadUiPreferenceCore(UiPreferencePath, WindowsIdentity.GetCurrent().User!.Value, false);

    private static SettingsUiPreference ReadUiPreferenceCore(string path, string sid, bool fixture)
    {
        byte[]? bytes;
        try { bytes = ReadStorageBytes(path, fixture); }
        catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { return new(Revision: "unreadable", Error: Program.Code(error)); }
        string revision = RawRevision(bytes);
        if (bytes is null) return new();
        try
        {
            using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("Schema", out var schema)
                || !schema.TryGetInt32(out int version)) throw new Boundary("settings_ui_preferences_invalid");
            if (version != 1 || !root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal)
                .SetEquals(["Schema", "UserSid", "UacSubmode"]))
                return new(Revision: revision, Error: "settings_ui_preferences_unsupported");
            if (root.GetProperty("UserSid").GetString() != sid)
                return new(Revision: revision, Error: "settings_ui_preferences_identity_mismatch");
            var mode = root.GetProperty("UacSubmode").GetString();
            if (mode is not ("allowlist" or "semantic")) throw new Boundary("settings_ui_preferences_invalid");
            return new(mode, revision);
        }
        catch (Exception error) when (error is Boundary or JsonException or InvalidOperationException or KeyNotFoundException)
        { return new(Revision: revision, Error: "settings_ui_preferences_invalid"); }
    }

    internal static SettingsUiPreference SaveUiPreference(string policyRevision, string preferenceRevision, string mode,
        CancellationToken cancellation = default)
    {
        if (FixturePath is not null) throw new Boundary("fixture_permission_write_rejected");
        if (WindowsIdentity.GetCurrent().IsSystem || Native.Process(Environment.ProcessId, false).Identity.Integrity != 12288)
            throw new Boundary("user_policy_high_required");
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        cancellation.ThrowIfCancellationRequested();
        using var gate = new Mutex(false, "Local\\FlowerControl.UserPermissions." + sid);
        bool held;
        try { held = gate.WaitOne(5000); } catch (AbandonedMutexException) { held = true; }
        if (!held) throw new Boundary("user_policy_save_busy");
        try
        {
            cancellation.ThrowIfCancellationRequested();
            RequireCurrentRevision(policyRevision, Read().Revision);
            cancellation.ThrowIfCancellationRequested();
            string parent = Path.GetDirectoryName(UiPreferencePath)!;
            CheckStorageParent(parent); SecurityLabel.CreateDirectory(parent, sid);
            return SaveUiPreferenceCore(UiPreferencePath, sid, preferenceRevision, mode, false, null);
        }
        finally { gate.ReleaseMutex(); }
    }

    // Tests invoke only this seam with a fresh caller-owned temporary directory.
    private static SettingsUiPreference SaveUiPreferenceCore(string path, string sid, string expectedRevision,
        string mode, bool fixture, Action<string>? checkpoint)
    {
        if (mode is not ("allowlist" or "semantic")) throw new Boundary("settings_ui_preferences_invalid");
        var before = ReadUiPreferenceCore(path, sid, fixture);
        if (before.Revision != expectedRevision) throw new Boundary("settings_ui_preferences_changed");
        if (before.Error is not (null or "settings_ui_preferences_invalid")) throw new Boundary(before.Error);
        if (before.Error is null && before.Revision != "absent" && before.UacSubmode == mode) return before;
        var previous = ReadStorageBytes(path, fixture);
        if (RawRevision(previous) != expectedRevision) throw new Boundary("settings_ui_preferences_changed");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { Schema = 1, UserSid = sid, UacSubmode = mode });
        bool committed = false; var recovery = new List<string>();
        try
        {
            checkpoint?.Invoke("before_write");
            ReplaceStorageFile(path, bytes, previous, sid, fixture, recovery, ref committed);
            checkpoint?.Invoke("after_write");
            return new(mode, RawRevision(bytes));
        }
        catch (Exception error) when (committed)
        {
            // Never compensate a successful permission save for a presentation
            // failure, or overwrite a newer preference with an old snapshot.
            var unknown = new Boundary("settings_ui_preferences_save_outcome_unknown");
            unknown.Data["OriginalError"] = error;
            throw unknown;
        }
    }
}
