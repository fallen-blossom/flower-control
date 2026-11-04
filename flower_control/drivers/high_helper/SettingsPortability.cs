using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record PortableSettingsDraft(UserPermissionSettings Settings, string? Browser, string? Language);

// Imported JSON can edit the existing UI draft only. It never selects a role,
// writes protected settings or restores a delegation/live execution grant.
internal static class SettingsPortability
{
    internal static PortableSettingsDraft Read(string path, UserPermissionSettings baseline)
    {
        BrokerPolicy.RejectLinks(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > 512000) throw new Boundary("settings_file_too_large");
        using var document = JsonDocument.Parse(stream); Protocol.CheckUnique(document);
        return Decode(document.RootElement, baseline);
    }

    internal static PortableSettingsDraft Decode(JsonElement root, UserPermissionSettings baseline)
    {
        string[] keys = ["schema", "kind", "created_utc", "settings", "preferences", "fixed_shortcuts", "excluded"];
        RequireKeys(root, keys);
        if (root.GetProperty("schema").GetInt32() != 1 || root.GetProperty("kind").GetString() != "flower-control-settings")
            throw new Boundary("settings_portable_schema_invalid");
        var settings = root.GetProperty("settings");
        RequireKeys(settings, ["HudCompact", "HudPosition", "SmoothPointer", "Masks", "DeniedApplications",
            "DeniedAdminWindowApplications", "AllowedAdminApplications", "AdminLaunchAllowlist",
            "DeniedAdminLaunchApplications", "UacAllowlist", "DeniedUacApplications"], subset: true);
        var next = baseline;
        foreach (var field in settings.EnumerateObject())
        {
            next = field.Name switch {
                "HudCompact" => next with { HudCompact = field.Value.GetBoolean() },
                "HudPosition" => next with { HudPosition = field.Value.GetString() ?? "" },
                "SmoothPointer" => next with { SmoothPointer = field.Value.GetBoolean() },
                "DeniedApplications" => next with { DeniedApplications = Windows(field.Value, false) },
                "DeniedAdminWindowApplications" => next with { DeniedAdminWindowApplications = Windows(field.Value, false) },
                "AllowedAdminApplications" => next with { AllowedAdminApplications = Windows(field.Value, true) },
                "AdminLaunchAllowlist" => next with { AdminLaunchAllowlist = Programs(field.Value, true) },
                "DeniedAdminLaunchApplications" => next with { DeniedAdminLaunchApplications = Programs(field.Value, false) },
                "UacAllowlist" => next with { UacAllowlist = Programs(field.Value, true) },
                "DeniedUacApplications" => next with { DeniedUacApplications = Programs(field.Value, false) },
                "Masks" => next with { Masks = Masks(field.Value) },
                _ => throw new Boundary("settings_portable_fields_invalid") };
        }
        UserPermissions.Validate(next);
        var preferences = root.GetProperty("preferences");
        RequireKeys(preferences, ["default_browser", "language"], subset: true);
        string? browser = preferences.TryGetProperty("default_browser", out var selected) ? selected.GetString() : null;
        string? language = preferences.TryGetProperty("language", out var display) ? display.GetString() : null;
        if (browser is not (null or "system" or "brave" or "edge" or "chrome")
            || language is not (null or "zh-CN" or "en")) throw new Boundary("settings_preferences_invalid");
        return new(next, browser, language);
    }

    private static ApplicationPermission[] Windows(JsonElement array, bool allow)
    {
        foreach (var row in Rows(array)) RequireKeys(row, ["Path", "TitleContains", "Enabled"]);
        var rows = array.Deserialize<ApplicationPermission[]>() ?? throw new Boundary("settings_rule_invalid");
        return allow ? rows.Select(row => row with { Enabled = false }).ToArray() : rows;
    }
    private static UacApplicationPermission[] Programs(JsonElement array, bool allow)
    {
        foreach (var row in Rows(array)) RequireKeys(row, ["Path", "IdentityKind", "Identity", "DisplayName", "Enabled", "Arguments"]);
        var rows = array.Deserialize<UacApplicationPermission[]>() ?? throw new Boundary("settings_rule_invalid");
        return rows.Select(row => row with { Enabled = allow ? false : row.Enabled, Arguments = "" }).ToArray();
    }
    private static PrivacyMask[] Masks(JsonElement array)
    {
        foreach (var row in Rows(array)) RequireKeys(row, ["Path", "Rect", "ClientSize", "Enabled"]);
        return array.Deserialize<PrivacyMask[]>() ?? throw new Boundary("settings_rule_invalid");
    }
    private static IEnumerable<JsonElement> Rows(JsonElement array)
    {
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 128) throw new Boundary("settings_rule_limit");
        return array.EnumerateArray();
    }
    private static void RequireKeys(JsonElement element, string[] keys, bool subset = false)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new Boundary("settings_portable_schema_invalid");
        var actual = element.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
        if (subset ? !actual.IsSubsetOf(keys) : !actual.SetEquals(keys)) throw new Boundary("settings_portable_schema_invalid");
    }
}
