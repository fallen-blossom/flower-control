using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record ApplicationPermission(string Path, string TitleContains = "", bool Enabled = true);
internal sealed record UacApplicationPermission(string Path, string IdentityKind, string Identity, string DisplayName, bool Enabled = true,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? Arguments = null);
internal sealed record PrivacyMask(string Path, int[] Rect, int[] ClientSize, bool Enabled = true);
internal sealed record UserPermissionSettings
{
    public int Schema { get; init; } = 2;
    public string Revision { get; init; } = Guid.NewGuid().ToString("N");
    public string UserSid { get; init; } = "";
    public bool AdminWindows { get; init; } = true;
    public string AdminScope { get; init; } = "all";
    public bool AdminLaunchEnabled { get; init; }
    public UacApplicationPermission[] AdminLaunchAllowlist { get; init; } = [];
    public string UacMode { get; init; } = "off";
    public string UacCancellationScope { get; init; } = "task";
    public UacApplicationPermission[] UacAllowlist { get; init; } = [];
    public bool JevEnabled { get; init; } = true;
    public ApplicationPermission[] DeniedApplications { get; init; } = [];
    // The authority ladder is a single exclusive choice: -1 fully disabled,
    // 0 ordinary windows, 1 administrator windows, 2 administrator launch,
    // 3 system/UAC. AdminWindows/AdminLaunchEnabled/UacMode are derived from
    // it so every executor keeps reading the same fields as before.
    public int AuthorityTier { get; init; } = int.MinValue;
    public string AdminLaunchMode { get; init; } = "allowlist";
    [System.Text.Json.Serialization.JsonIgnore] public LocalSemanticDelegation? SemanticDelegation { get; init; }
    public ApplicationPermission[] DeniedAdminWindowApplications { get; init; } = [];
    public UacApplicationPermission[] DeniedAdminLaunchApplications { get; init; } = [];
    public UacApplicationPermission[] DeniedUacApplications { get; init; } = [];
    public ApplicationPermission[] AllowedAdminApplications { get; init; } = [];
    public PrivacyMask[] Masks { get; init; } = [];
    public bool SmoothPointer { get; init; }
    public bool HudCompact { get; init; }
    public string HudPosition { get; init; } = "auto";
    // A damaged UAC sidecar fails closed without disabling ordinary windows.
    [System.Text.Json.Serialization.JsonIgnore] public string? UacPolicyError { get; init; }
}

internal static partial class UserPermissions
{
    // These are privilege capabilities, not the integrity of the broker process:
    // ordinary-window input may still use the High broker with the master off.
    // A missing AuthorityTier means a legacy record; derive it once from the old
    // switches so existing installations keep exactly the grants they had.
    internal static int TierOf(UserPermissionSettings value) => value.AuthorityTier >= -1 ? value.AuthorityTier
        : !value.AdminWindows ? 0
        : !value.AdminLaunchEnabled ? 1
        : value.UacMode == "off" ? 2 : 3;
    internal static UserPermissionSettings WithoutUac(UserPermissionSettings value)
        => value with { AuthorityTier = Math.Min(TierOf(value), 2), UacMode = "off" };
    internal static UserPermissionSettings WithoutElevatedExecution(UserPermissionSettings value)
        => value with { AuthorityTier = Math.Min(TierOf(value), 1), AdminLaunchEnabled = false, UacMode = "off" };
    internal static UserPermissionSettings Effective(UserPermissionSettings value)
    {
        int tier = TierOf(value);
        return value with {
            AuthorityTier = tier,
            AdminWindows = tier >= 1,
            AdminLaunchEnabled = tier >= 2,
            UacMode = tier < 3 ? "off" : value.UacMode is "off" or "" ? "allowlist" : value.UacMode,
            AdminLaunchMode = value.AdminLaunchMode == "semantic" ? "semantic" : "allowlist"
        };
    }
    internal const int PolicyMutationRights = 0x500D0156; // Includes FILE_DELETE_CHILD on parent directories.
    // No environment override and no named-pipe/MCP write operation.
    internal static string? FixturePath { get; set; }
    private static string ProtectedPath(string sid) => Path.Combine(
        InstallationLocation.Current(sid).ProgramRoot,
        "permissions", sid + ".json");
    internal static string FilePath => FixturePath ?? ProtectedPath(WindowsIdentity.GetCurrent().User!.Value);
    private static string UacPath(string path) => Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path) + ".uac.json");
    // Keep the tray and Stop reachable when the policy is damaged. Executors
    // still call Read(), which rejects it instead of granting defaults.
    internal static string Revision
    {
        get { try { return Read().Revision; } catch (Boundary error) { return "invalid:" + error.Code; } }
    }
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool ClientToScreen(IntPtr hwnd, ref Native.Point point);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    internal static void Validate(UserPermissionSettings value)
        => ValidateForUser(value, WindowsIdentity.GetCurrent().User!.Value);
    private static bool ValidUacApplication(UacApplicationPermission row) => row is not null
        && Path.IsPathFullyQualified(row.Path) && !row.Path.StartsWith("\\\\", StringComparison.Ordinal)
        && !row.Path.Contains('*') && !row.Path.Contains('?') && !row.Path.Skip(2).Contains(':')
        && !row.Path.Any(char.IsControl) && row.IdentityKind is "signed" or "sha256"
        && row.Identity is { Length: 64 } && row.Identity.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
        && row.DisplayName is not null && row.DisplayName.Length <= 160 && !row.DisplayName.Any(char.IsControl)
        && (row.Arguments is null || ValidUacArguments(row.Arguments));
    private static UacApplicationPermission[] SafeRows(UacApplicationPermission[] rows) => rows.Select(row =>
        row.Arguments is null || UacIdentity.AllowlistExecutionHostName(row.Path) ? row with { Enabled = false } : row).ToArray();
    internal static bool ValidUacArguments(string arguments) => arguments.Length <= 2048
        && !arguments.Any(char.IsControl) && !arguments.Contains('*') && !arguments.Contains('?');
    private static void ValidateForUser(UserPermissionSettings value, string sid)
    {
        if (value.UserSid != sid) throw new Boundary("user_policy_identity_mismatch");
        bool App(ApplicationPermission row) => row is not null && System.IO.Path.IsPathFullyQualified(row.Path)
            && !row.Path.Contains('*') && !row.Path.Contains('?') && row.TitleContains is not null && row.TitleContains.Length <= 160;
        if (value.Schema != 2 || value.Revision is null || value.Revision.Length is < 1 or > 64
            || value.AdminScope is not ("all" or "allowlist")
            || value.AuthorityTier != int.MinValue && value.AuthorityTier is < -1 or > 3
            || value.AdminLaunchMode is not ("allowlist" or "semantic")
            || value.HudPosition is not ("auto" or "top_left" or "top_right" or "bottom_left" or "bottom_right")
            || value.UacMode is not ("off" or "observe" or "cancel" or "allowlist" or "semantic") || value.UacAllowlist is null
            || value.UacCancellationScope is not ("task" or "selected_prompt_in_session")
            || value.UacAllowlist.Length > 128 || value.UacAllowlist.Any(r => !ValidUacApplication(r))
            || value.AdminLaunchAllowlist is null || value.AdminLaunchAllowlist.Length > 128
            || value.AdminLaunchAllowlist.Any(r => !ValidUacApplication(r))
            || value.DeniedApplications is null || value.AllowedAdminApplications is null || value.Masks is null
            || value.DeniedAdminWindowApplications is null || value.DeniedAdminLaunchApplications is null
            || value.DeniedUacApplications is null
            || value.DeniedApplications.Length > 128 || value.AllowedAdminApplications.Length > 128 || value.Masks.Length > 128
            || value.DeniedAdminWindowApplications.Length > 128 || value.DeniedAdminLaunchApplications.Length > 128
            || value.DeniedUacApplications.Length > 128
            || value.DeniedApplications.Any(r => !App(r)) || value.AllowedAdminApplications.Any(r => !App(r))
            || value.DeniedAdminWindowApplications.Any(r => !App(r))
            || value.DeniedAdminLaunchApplications.Any(r => !ValidUacApplication(r))
            || value.DeniedUacApplications.Any(r => !ValidUacApplication(r)))
            throw new Boundary("user_policy_invalid");
        foreach (var row in value.Masks)
            if (row is null || !App(new(row.Path)) || row.Rect is not { Length: 4 } || row.ClientSize is not { Length: 2 }
                || row.Rect[0] < 0 || row.Rect[1] < 0 || row.Rect[2] <= row.Rect[0] || row.Rect[3] <= row.Rect[1]
                || row.Rect[2] > row.ClientSize[0] || row.Rect[3] > row.ClientSize[1] || row.ClientSize.Any(n => n <= 0 || n > 16384))
                throw new Boundary("user_policy_invalid");
    }
    internal static UserPermissionSettings Read() => Effective(FixturePath is not null
        ? ReadFrom(FilePath, WindowsIdentity.GetCurrent().User!.Value, true)
        : ReadStorage(FilePath, WindowsIdentity.GetCurrent().User!.Value, false).Settings);
    // Only the SYSTEM-only entrypoint may supply its already verified interactive
    // token SID. This is a fixed-root reader, never an arbitrary policy path.
    internal static UserPermissionSettings ReadForInteractiveUser(string verifiedSid)
    {
        if (!WindowsIdentity.GetCurrent().IsSystem) throw new Boundary("uac_system_role_required");
        if (FixturePath is not null) throw new Boundary("uac_interactive_fixture_rejected");
        try
        {
            if (new SecurityIdentifier(verifiedSid).Value != verifiedSid || verifiedSid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20")
                throw new Boundary("user_policy_identity_mismatch");
        }
        catch (ArgumentException) { throw new Boundary("user_policy_identity_mismatch"); }
        return Effective(ReadStorage(ProtectedPath(verifiedSid), verifiedSid, false).Settings);
    }
    private sealed record UacStoredSettings(int Schema, string Revision, string UserSid, string CommonRevision,
        string UacMode, UacApplicationPermission[] UacAllowlist, bool AdminLaunchEnabled = false, string UacCancellationScope = "task",
        UacApplicationPermission[]? AdminLaunchAllowlist = null, int? AuthorityTier = null, string? AdminLaunchMode = null,
        ApplicationPermission[]? DeniedAdminWindowApplications = null, UacApplicationPermission[]? DeniedAdminLaunchApplications = null,
        UacApplicationPermission[]? DeniedUacApplications = null,
        [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] LocalSemanticDelegation? SemanticDelegation = null);
    private sealed record StorageSnapshot(UserPermissionSettings Settings, byte[]? Common, byte[]? Uac, int CommonSchema);
    private static string RawRevision(byte[]? bytes) => bytes is null ? "absent" : Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static string StorageRevision(byte[]? common, byte[]? uac, string? unreadableUacError = null)
    {
        if (common is null && uac is null && unreadableUacError is null) return "absent";
        using var stream = new MemoryStream();
        stream.Write(Encoding.UTF8.GetBytes("FlowerControl.UserPermissions.storage.v1\0"));
        Span<byte> size = stackalloc byte[8];
        foreach (var bytes in new[] { common, uac })
        {
            stream.WriteByte(bytes is null ? (byte)0 : (byte)1);
            if (bytes is not null)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(size, (ulong)bytes.Length);
                stream.Write(size); stream.Write(bytes);
            }
        }
        if (unreadableUacError is not null) stream.Write(Encoding.UTF8.GetBytes("error\0" + unreadableUacError));
        return RawRevision(stream.ToArray());
    }
    private static byte[]? ReadStorageBytes(string path, bool fixture)
    {
        if (!fixture) CheckStorageParent(Path.GetDirectoryName(path)!);
        try
        {
            if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new Boundary("user_policy_invalid");
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        if (!fixture) CheckProtection(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length > 128000) throw new Boundary("user_policy_invalid");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return bytes;
    }
    // The fixture flag is private and used only by reflection tests with owned
    // temporary files. Public Save always rejects FixturePath and uses fixed roots.
    private static StorageSnapshot ReadStorage(string path, string sid, bool fixture)
        => ReadStorageStable(path, sid, fixture, 0);
    private static StorageSnapshot ReadStorageStable(string path, string sid, bool fixture, int attempt)
    {
        try
        {
            var common = ReadStorageBytes(path, fixture); var value = Defaults(sid); int commonSchema = 1;
            if (common is not null)
            {
                using var document = JsonDocument.Parse(common);
                value = Decode(document); ValidateForUser(value, sid);
                commonSchema = document.RootElement.GetProperty("Schema").GetInt32();
            }
            value = value with { UacMode = "off", UacAllowlist = [], AdminLaunchEnabled = false, AdminLaunchAllowlist = [], UacCancellationScope = "task" };
            byte[]? uac = null; string? uacError = null;
            try
            {
                uac = ReadStorageBytes(UacPath(path), fixture);
                if (uac is not null)
                {
                    using var document = JsonDocument.Parse(uac); Protocol.CheckUnique(document);
                    var root = document.RootElement;
                    string[] required = ["Schema", "Revision", "UserSid", "CommonRevision", "UacMode", "UacAllowlist"];
                    var keys = root.ValueKind == JsonValueKind.Object
                        ? root.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal) : [];
                    if (!keys.IsSupersetOf(required) || !keys.IsSubsetOf(required.Concat(["AdminLaunchEnabled",
                        "UacCancellationScope", "AdminLaunchAllowlist", "AuthorityTier", "AdminLaunchMode",
                        "DeniedAdminWindowApplications", "DeniedAdminLaunchApplications", "DeniedUacApplications", "SemanticDelegation"])))
                        throw new Boundary("user_policy_invalid");
                    foreach (var name in new[] { "UacAllowlist", "AdminLaunchAllowlist", "DeniedAdminLaunchApplications", "DeniedUacApplications" })
                    {
                        if (!root.TryGetProperty(name, out var rows)) continue;
                        if (rows.ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
                        foreach (var row in rows.EnumerateArray())
                        {
                            if (row.ValueKind != JsonValueKind.Object) throw new Boundary("user_policy_invalid");
                            var rowKeys = row.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
                            string[] rowRequired = ["Path", "IdentityKind", "Identity", "DisplayName", "Enabled"];
                            if (!rowKeys.IsSupersetOf(rowRequired) || !rowKeys.IsSubsetOf(rowRequired.Append("Arguments")))
                                throw new Boundary("user_policy_invalid");
                        }
                    }
                    if (root.TryGetProperty("DeniedAdminWindowApplications", out var deniedWindows))
                    {
                        if (deniedWindows.ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
                        foreach (var row in deniedWindows.EnumerateArray())
                        {
                            if (row.ValueKind != JsonValueKind.Object) throw new Boundary("user_policy_invalid");
                            var rowKeys = row.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
                            string[] rowRequired = ["Path", "TitleContains", "Enabled"];
                            if (!rowKeys.SetEquals(rowRequired)) throw new Boundary("user_policy_invalid");
                        }
                    }
                    var stored = Protocol.Decode<UacStoredSettings>(document);
                    if (stored.Schema is not (1 or 2) || stored.Revision is null || stored.Revision.Length is < 1 or > 64
                        || stored.CommonRevision is null || stored.CommonRevision != "absent"
                            && !System.Text.RegularExpressions.Regex.IsMatch(stored.CommonRevision, "\\A[a-f0-9]{64}\\z"))
                        throw new Boundary("user_policy_invalid");
                    var merged = value with { UserSid = stored.UserSid, UacMode = stored.UacMode == "full" ? "off" : stored.UacMode,
                        // Existing old sidecars may bind CommonRevision=absent
                        // and omit a tier. Preserve their historical admin-on
                        // baseline only for that exact validated identity.
                        AdminWindows = common is null && stored.UserSid == sid && stored.CommonRevision == "absent"
                            && stored.AuthorityTier is null ? true : value.AdminWindows,
                        UacAllowlist = stored.UacAllowlist, AdminLaunchEnabled = stored.AdminLaunchEnabled,
                        AdminLaunchAllowlist = root.TryGetProperty("AdminLaunchAllowlist", out var launchRows)
                            && launchRows.ValueKind == JsonValueKind.Null ? throw new Boundary("user_policy_invalid") : stored.AdminLaunchAllowlist ?? [],
                        UacCancellationScope = stored.UacCancellationScope,
                        AuthorityTier = stored.AuthorityTier ?? int.MinValue,
                        AdminLaunchMode = stored.AdminLaunchMode ?? "allowlist",
                        DeniedAdminWindowApplications = stored.DeniedAdminWindowApplications ?? [],
                        DeniedAdminLaunchApplications = stored.DeniedAdminLaunchApplications ?? [],
                        DeniedUacApplications = stored.DeniedUacApplications ?? [], SemanticDelegation = stored.SemanticDelegation };
                    if (stored.SemanticDelegation is not null) Flower.HighHelper.SemanticDelegation.Validate(stored.SemanticDelegation, sid);
                    ValidateForUser(merged, sid);
                    if (commonSchema != 1) uacError = "user_policy_migration_required";
                    else if (stored.CommonRevision != RawRevision(common)) uacError = "uac_policy_common_changed";
                    else value = merged with { UacAllowlist = SafeRows(merged.UacAllowlist), AdminLaunchAllowlist = SafeRows(merged.AdminLaunchAllowlist) };
                }
            }
            catch (Boundary error) { uacError = error.Code; }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or ArgumentException
                or InvalidOperationException or System.Security.SecurityException) { uacError = "user_policy_invalid"; }
            if (commonSchema != 1) uacError = "user_policy_migration_required";
            bool stable = SameBytes(ReadStorageBytes(path, fixture), common);
            if (uac is not null || uacError is null) try { stable &= SameBytes(ReadStorageBytes(UacPath(path), fixture), uac); }
            catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { stable = false; }
            if (!stable)
            {
                if (attempt >= 2) throw new Boundary("user_policy_unavailable");
                return ReadStorageStable(path, sid, fixture, attempt + 1);
            }
            return new(value with { Revision = StorageRevision(common, uac, uac is null ? uacError : null), UacPolicyError = uacError },
                common, uac, commonSchema);
        }
        catch (Boundary) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException or ArgumentException
            or InvalidOperationException or System.Security.SecurityException) { throw new Boundary("user_policy_unavailable"); }
    }
    private static UserPermissionSettings ReadFrom(string path, string sid, bool fixture)
    {
        try
        {
            // File.Exists also returns false on access errors; only absence is a default.
            if (!fixture) CheckStorageParent(Path.GetDirectoryName(path)!);
            try {
                var attributes = File.GetAttributes(path);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                    throw new Boundary("user_policy_invalid");
            }
            catch (FileNotFoundException) { return Defaults(sid); }
            catch (DirectoryNotFoundException) { return Defaults(sid); }
            if (!fixture) CheckProtection(path);
            byte[] bytes;
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            {
                if (stream.Length > 128000) throw new Boundary("user_policy_invalid");
                bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes);
            }
            using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document);
            var value = Decode(document); ValidateForUser(value, sid);
            // Preserve old rows and the raw revision so the local user can
            // remove them. A known payload host never regains preauthorization
            // merely by reading an older policy; renamed hosts are also vetoed
            // against the actual pinned file at the matching boundary below.
            return value with { Revision = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant(),
                UacAllowlist = SafeRows(value.UacAllowlist), AdminLaunchAllowlist = SafeRows(value.AdminLaunchAllowlist) };
        }
        catch (Boundary) { throw; }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException
            or ArgumentException or InvalidOperationException or System.Security.SecurityException)
        { throw new Boundary("user_policy_unavailable"); }
    }
    private static UserPermissionSettings Defaults(string sid) => new() {
        Revision = "absent", UserSid = sid, AuthorityTier = 0, AdminWindows = false, AdminLaunchEnabled = false };
    internal static UserPermissionSettings Decode(JsonDocument document)
    {
        static void Keys(JsonElement element, string[] required, params string[] optional)
        {
            if (element.ValueKind != JsonValueKind.Object) throw new Boundary("user_policy_invalid");
            var actual = element.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal);
            if (!actual.IsSupersetOf(required) || !actual.IsSubsetOf(required.Concat(optional)))
                throw new Boundary("user_policy_invalid");
        }
        Protocol.CheckUnique(document);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("Schema", out var schema) || schema.ValueKind != JsonValueKind.Number
            || !schema.TryGetInt32(out var version) || version is not (1 or 2)) throw new Boundary("user_policy_invalid");
        string[] common = ["Schema", "Revision", "UserSid", "AdminWindows", "AdminScope", "JevEnabled",
                           "DeniedApplications", "AllowedAdminApplications", "Masks", "SmoothPointer", "HudCompact", "HudPosition"];
        if (version == 1)
        {
            Keys(root, [..common, "UacEnabled"]);
            if (root.GetProperty("UacEnabled").ValueKind != JsonValueKind.False) throw new Boundary("user_policy_invalid");
        }
        else Keys(root, [..common, "UacMode"], "UacAllowlist", "AdminLaunchEnabled", "UacCancellationScope", "AdminLaunchAllowlist",
            "AuthorityTier", "AdminLaunchMode", "DeniedAdminWindowApplications", "DeniedAdminLaunchApplications", "DeniedUacApplications");
        foreach (var name in new[] { "DeniedApplications", "AllowedAdminApplications" })
        {
            if (root.GetProperty(name).ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
            foreach (var row in root.GetProperty(name).EnumerateArray()) Keys(row, ["Path", "TitleContains", "Enabled"]);
        }
        if (root.GetProperty("Masks").ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
        foreach (var row in root.GetProperty("Masks").EnumerateArray()) Keys(row, ["Path", "Rect", "ClientSize", "Enabled"]);
        if (root.TryGetProperty("DeniedAdminWindowApplications", out var deniedWindows))
        {
            if (deniedWindows.ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
            foreach (var row in deniedWindows.EnumerateArray()) Keys(row, ["Path", "TitleContains", "Enabled"]);
        }
        foreach (var name in new[] { "DeniedAdminLaunchApplications", "DeniedUacApplications" })
        {
            if (!root.TryGetProperty(name, out var denied)) continue;
            if (denied.ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
            foreach (var row in denied.EnumerateArray())
                Keys(row, ["Path", "IdentityKind", "Identity", "DisplayName", "Enabled"], "Arguments");
        }
        if (version == 2)
        {
            foreach (var name in new[] { "UacAllowlist", "AdminLaunchAllowlist" })
            {
                if (!root.TryGetProperty(name, out var allowlist)) continue;
                if (allowlist.ValueKind != JsonValueKind.Array) throw new Boundary("user_policy_invalid");
                foreach (var row in allowlist.EnumerateArray()) Keys(row, ["Path", "IdentityKind", "Identity", "DisplayName", "Enabled"], "Arguments");
            }
            var decoded = Protocol.Decode<UserPermissionSettings>(document);
            // Full access was removed by the user. Reading an old policy does
            // not enable a replacement mode or rewrite unrelated preferences.
            return decoded.UacMode == "full" ? decoded with { UacMode = "off" } : decoded;
        }
        // Migrate only the known disabled legacy flag. All unrelated preferences
        // stay byte-for-byte values, and the read revision is still the raw hash.
        var migrated = root.EnumerateObject().Where(p => p.Name != "UacEnabled").ToDictionary(p => p.Name, p => p.Value);
        migrated["Schema"] = JsonSerializer.SerializeToElement(2);
        migrated["UacMode"] = JsonSerializer.SerializeToElement("off");
        using var current = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(migrated));
        return Protocol.Decode<UserPermissionSettings>(current);
    }
    internal static string UacArgumentsSha256(string arguments)
        => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(arguments))).ToLowerInvariant();
    internal static bool UacAllowlisted(UserPermissionSettings value, UacApplicationPermission actual)
        => UacAllowlisted(value, actual, actual.Arguments is null ? null : UacArgumentsSha256(actual.Arguments));
    internal static bool UacAllowlisted(UserPermissionSettings value, UacApplicationPermission actual, string? argumentsSha256) => Effective(value).UacMode == "allowlist"
        && ValidUacApplication(actual) && !UacPromptDenied(value, actual.Path) && argumentsSha256 is not null
        && System.Text.RegularExpressions.Regex.IsMatch(argumentsSha256, "\\A[a-f0-9]{64}\\z") && value.UacAllowlist.Any(row => row.Enabled
            && Path.GetFullPath(row.Path).TrimEnd('\\').Equals(Path.GetFullPath(actual.Path).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)
            && row.IdentityKind == actual.IdentityKind && row.Identity == actual.Identity
            && row.Arguments is not null && UacArgumentsSha256(row.Arguments) == argumentsSha256)
        && UacIdentity.AllowlistSupported(actual.Path);
    // A future elevated window's title is unknown. Use the same conservative
    // program-start denial for direct launch and UAC, including title rules.
    internal static bool ProgramStartDenied(UserPermissionSettings value, string image)
        => value.DeniedApplications.Any(row => row.Enabled
            && Path.GetFullPath(row.Path).TrimEnd('\\').Equals(Path.GetFullPath(image).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    private static bool PathDenied(IEnumerable<ApplicationPermission> rows, string image)
        => rows.Any(row => row.Enabled
            && Path.GetFullPath(row.Path).TrimEnd('\\').Equals(Path.GetFullPath(image).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    private static bool PathDenied(IEnumerable<UacApplicationPermission> rows, string image)
        => rows.Any(row => row.Enabled
            && Path.GetFullPath(row.Path).TrimEnd('\\').Equals(Path.GetFullPath(image).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    // Tiers inherit the lower tiers' denials: a program the user blocked for
    // ordinary windows cannot become launchable or UAC-confirmable.
    internal static bool AdminLaunchDenied(UserPermissionSettings value, string image)
        => ProgramStartDenied(value, image) || PathDenied(value.DeniedAdminLaunchApplications, image);
    internal static bool UacPromptDenied(UserPermissionSettings value, string image)
        => AdminLaunchDenied(value, image) || PathDenied(value.DeniedAdminWindowApplications, image)
        || PathDenied(value.DeniedUacApplications, image);
    internal static void RequireUacAllowlistPreauthorization(IEnumerable<UacApplicationPermission> rows)
    {
        foreach (var row in rows.Where(row => row.Enabled))
        {
            if (row.Arguments is null || !ValidUacArguments(row.Arguments)) throw new Boundary("uac_arguments_approval_required");
            UacIdentity.RequireAllowlistSupported(row.Path);
        }
    }
    internal static bool Matches(ApplicationPermission row, string image, string title) => row.Enabled
        && Path.GetFullPath(row.Path).TrimEnd('\\').Equals(Path.GetFullPath(image).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)
        && (row.TitleContains.Length == 0 || title.Contains(row.TitleContains, StringComparison.OrdinalIgnoreCase));
    internal static void Require(string image, int integrity, string title, UserPermissionSettings value)
    {
        if (TierOf(value) < 0) throw new Boundary("flower_fully_disabled");
        if (value.DeniedApplications.Any(r => Matches(r, image, title))) throw new Boundary("window_disabled_by_user");
        if (integrity > 8192 && value.DeniedAdminWindowApplications.Any(r => Matches(r, image, title)))
            throw new Boundary("window_disabled_by_user");
        if (integrity > 8192 && !value.AdminWindows)
            throw new Boundary("administrator_window_disabled");
    }
    internal static void RequireWindow(IntPtr hwnd, Peer peer, string image, UserPermissionSettings? permissions = null)
    {
        var value = permissions ?? Read();
        var title = new StringBuilder(32768);
        if (value.DeniedApplications.Any(r => r.TitleContains.Length > 0)
            || value.DeniedAdminWindowApplications.Any(r => r.TitleContains.Length > 0)
            || value.AllowedAdminApplications.Any(r => r.TitleContains.Length > 0)) GetWindowTextW(hwnd, title, title.Capacity);
        Require(image, peer.Integrity, title.ToString(), value);
        var owner = Native.GetWindow(hwnd, 4); var seen = new HashSet<IntPtr> { hwnd };
        for (var depth = 0; owner != IntPtr.Zero; depth++)
        {
            if (depth >= 16 || !seen.Add(owner)) throw new Boundary("window_policy_identity_unavailable");
            Native.GetWindowThreadProcessId(owner, out var pid); var process = Native.Process((int)pid, false);
            title.Clear(); GetWindowTextW(owner, title, title.Capacity);
            Require(process.Image, process.Identity.Integrity, title.ToString(), value);
            owner = Native.GetWindow(owner, 4);
        }
    }
    internal static PrivacyMask[] MasksFor(string image, UserPermissionSettings value) => value.Masks.Where(r => r.Enabled
        && Path.GetFullPath(r.Path).Equals(Path.GetFullPath(image), StringComparison.OrdinalIgnoreCase)).ToArray();
    internal static void RequireAppTarget(Target target)
    {
        var value = Read();
        if (value.Masks.Length == 0) return;
        var image = Native.Process(target.Pid, false).Image;
        if (MasksFor(image, value).Length != 0) throw new Boundary("privacy_text_mapping_unavailable");
    }
    internal static void RequireInput(Bound bound, Step[] steps, DesktopShape? desktop, PasswordMetadata.Info? password = null, bool deferKeyboard = true, bool sweepMotion = false, bool heldMouse = false,
        UserPermissionSettings? permissions = null)
    {
        RequirePasswordFocus(steps, password, deferKeyboard);
        var value = permissions ?? Read();
        var masks = MasksFor(Native.Process(bound.Pid, false).Image, value);
        if (masks.Length == 0 && (password is null || password.Rectangles.Length == 0)) return;
        var hwnd = new IntPtr(bound.Hwnd); var origin = new Native.Point();
        if (!GetClientRect(hwnd, out var client) || !ClientToScreen(hwnd, ref origin)) throw new Boundary("privacy_geometry_unavailable");
        if (masks.Any(r => r.ClientSize[0] != client.Right || r.ClientSize[1] != client.Bottom)) throw new Boundary("privacy_region_geometry_changed");
        var rectangles = masks.Select(r => new[] { r.Rect[0] + origin.X, r.Rect[1] + origin.Y, r.Rect[2] + origin.X, r.Rect[3] + origin.Y })
            .Concat(password?.Rectangles ?? []).ToArray();
        if (steps.Any(s => s.Raw.Type == 1) && !deferKeyboard)
        {
            var focus = password?.FocusRectangle;
            if (focus is null || password?.FocusPassword is true || rectangles.Any(r => focus[0] < r[2] && r[0] < focus[2] && focus[1] < r[3] && r[1] < focus[3]))
                throw new Boundary("privacy_keyboard_focus_unverified");
        }
        if (!GetCursorPos(out var previous)) throw new Boundary("privacy_geometry_unavailable");
        bool dragging = heldMouse;
        foreach (var step in steps.Where(s => s.Raw.Type == 0))
        {
            var mouse = step.Raw.Data.Mouse;
            if ((mouse.Flags & 1) != 0 && (mouse.Flags & 0x8000) == 0) throw new Boundary("privacy_relative_input_disabled");
            var point = previous;
            if ((mouse.Flags & 0x8000) != 0)
            {
                if (desktop is null) throw new Boundary("desktop_topology_required");
                point = InputContext.AbsolutePoint(mouse, desktop);
            }
            int left = dragging || sweepMotion ? Math.Min(previous.X, point.X) : point.X, top = dragging || sweepMotion ? Math.Min(previous.Y, point.Y) : point.Y;
            int right = dragging || sweepMotion ? Math.Max(previous.X, point.X) : point.X, bottom = dragging || sweepMotion ? Math.Max(previous.Y, point.Y) : point.Y;
            if (rectangles.Any(r => left < r[2] && r[0] <= right && top < r[3] && r[1] <= bottom))
                throw new Boundary("privacy_region_input_disabled");
            if ((mouse.Flags & 0x2a) != 0) dragging = true;
            if ((mouse.Flags & 0x54) != 0) dragging = false;
            previous = point;
        }
    }
    internal static void RequirePasswordFocus(Step[] steps, PasswordMetadata.Info? password, bool deferred)
    {
        if (!deferred && password?.FocusPassword is true && steps.Any(s => s.Raw.Type == 1))
            throw new Boundary("privacy_keyboard_focus_unverified");
    }
    internal static void CheckProtection(string path)
        => CheckProtectionCore(path, false);
    internal static void CheckSystemExecutableProtection(string path)
    {
        if (!Path.GetFullPath(path).Equals(Path.Combine(AppContext.BaseDirectory, "Flower.HighHelper.exe"), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_install_path_rejected");
        CheckProtectionCore(path, true);
    }
    internal static void RequireQualificationWitnessPath(string path)
    {
        var name = Path.GetFileName(path);
        if (!Path.IsPathFullyQualified(path)
            || !(name.Equals("uac-witness-baseline.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("uac-witness-moved.exe", StringComparison.OrdinalIgnoreCase)
                || name.Equals("uac-witness-decoy.exe", StringComparison.OrdinalIgnoreCase))
            || !Path.GetFullPath(path).Equals(Path.Combine(AppContext.BaseDirectory, name), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_qualification_witness_path_rejected");
    }
    internal static void CheckQualificationWitnessProtection(string path)
    {
        RequireQualificationWitnessPath(path);
        // Same owner/DACL/parent High label checks as the dual-role helper.
        // Only these three fixed fixture images may omit an executable label.
        CheckProtectionCore(path, true);
    }
    private static void CheckProtectionCore(string path, bool systemExecutable)
    {
        BrokerPolicy.RejectLinks(path);
        foreach (var item in Directory.Exists(path) ? new[] { path } : new[] { path, Path.GetDirectoryName(path)! })
        {
            var security = Directory.Exists(item)
                ? (FileSystemSecurity)new DirectoryInfo(item).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : new FileInfo(item).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
                throw new Boundary("user_policy_unprotected");
            if (security.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw new Boundary("user_policy_unprotected");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && ((int)rule.FileSystemRights & PolicyMutationRights) != 0
                    && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                    throw new Boundary("user_policy_unprotected");
            // The explicit High mandatory label is independently checked below.
            if (systemExecutable && item == path) SecurityLabel.RequireUnlabelledExecutable(SecurityLabel.Read(item));
            else SecurityLabel.RequireHigh(SecurityLabel.Read(item));
        }
    }
    internal static void CheckProtectionForDirectory(string path)
    {
        CheckProtection(path);
    }
    private static void CheckStorageParent(string parent)
    {
        var root = Path.GetDirectoryName(parent)!;
        BrokerPolicy.RejectLinks(root);
        var security = new DirectoryInfo(root).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
            throw new Boundary("user_policy_unprotected");
        if (security.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544"))
            throw new Boundary("user_policy_unprotected");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && ((int)rule.FileSystemRights & PolicyMutationRights) != 0
                && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw new Boundary("user_policy_unprotected");
        try { var attributes = File.GetAttributes(parent);
            if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
                throw new Boundary("user_policy_unprotected");
            CheckProtection(parent);
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
    }
    internal static string Save(UserPermissionSettings value)
    {
        if (FixturePath is not null) throw new Boundary("fixture_permission_write_rejected");
        if (WindowsIdentity.GetCurrent().IsSystem || Native.Process(Environment.ProcessId, false).Identity.Integrity != 12288)
            throw new Boundary("user_policy_high_required");
        Validate(value);
        // Semantic mode is a first-class choice now. The execution side still
        // requires a task-scoped grant; saving alone never grants a start.
        value = Effective(value);
        if (value.AdminLaunchEnabled) RequireUacAllowlistPreauthorization(value.AdminLaunchAllowlist);
        if (value.UacMode == "allowlist") RequireUacAllowlistPreauthorization(value.UacAllowlist);
        var expectedRevision = value.Revision;
        // Serialize writers before re-reading the real policy. The tolerant tray
        // Revision property must never turn an unreadable file into overwrite permission.
        return WithPolicyGate(value.UserSid, () => SaveLocked(value, expectedRevision));
    }
    private static string SaveLocked(UserPermissionSettings value, string expectedRevision)
        => SaveStorage(value, expectedRevision, FilePath, false, null);
    // Called only after the local settings window's explicit confirmation.
    // Neither an ordinary Save nor an MCP payload can supply this selection.
    internal static UserPermissionSettings ConfirmSemanticDelegation(string expectedRevision)
    {
        if (FixturePath is not null) throw new Boundary("fixture_permission_write_rejected");
        var own = Native.Process(Environment.ProcessId, false).Identity;
        if (WindowsIdentity.GetCurrent().IsSystem || own.Integrity != 12288)
            throw new Boundary("user_policy_high_required");
        return WithPolicyGate(own.User, () => ConfirmSemanticDelegationStorage(expectedRevision, own.User, FilePath, false));
    }
    private static UserPermissionSettings ConfirmSemanticDelegationStorage(string expectedRevision, string sid, string path, bool fixture)
    {
        var before = ReadStorage(path, sid, fixture).Settings;
        RequireCurrentRevision(expectedRevision, before.Revision);
        if (!Effective(before).AdminLaunchEnabled || before.AdminLaunchMode != "semantic")
            throw new Boundary("semantic_delegation_disabled");
        if (before.UacPolicyError is not null) throw new Boundary(before.UacPolicyError);
        if (Flower.HighHelper.SemanticDelegation.IncludesDsh(before.SemanticDelegation)) return before;
        return SaveStorageCore(before, expectedRevision, path, fixture, null, true);
    }
    internal static T WithCurrentPolicy<T>(string sid, string expectedRevision, Func<T> dispatch)
        => WithPolicyGate(sid, () => {
            var current = Read();
            if (current.UserSid != sid) throw new Boundary("user_policy_identity_mismatch");
            RequireCurrentRevision(expectedRevision, current.Revision);
            return dispatch();
        });
    private static T WithPolicyGate<T>(string sid, Func<T> operation)
    {
        // Same short gate as Save: acknowledged disable cannot precede an
        // older create that has only checked a now-stale policy snapshot.
        using var gate = new Mutex(false, "Local\\FlowerControl.UserPermissions." + sid);
        bool acquired;
        try { acquired = gate.WaitOne(5000); } catch (AbandonedMutexException) { acquired = true; }
        if (!acquired) throw new Boundary("user_policy_save_busy");
        try { return operation(); } finally { gate.ReleaseMutex(); }
    }
    private static byte[] CommonBytes(UserPermissionSettings value, string revision) => JsonSerializer.SerializeToUtf8Bytes(new {
        Schema = 1, Revision = revision, value.UserSid, value.AdminWindows, value.AdminScope, UacEnabled = false,
        value.JevEnabled, value.DeniedApplications, value.AllowedAdminApplications, value.Masks,
        value.SmoothPointer, value.HudCompact, value.HudPosition });
    private static byte[] UacBytes(UserPermissionSettings value, string revision, byte[]? common) => JsonSerializer.SerializeToUtf8Bytes(
        new UacStoredSettings(2, revision, value.UserSid, RawRevision(common), value.UacMode, value.UacAllowlist,
            value.AdminLaunchEnabled, value.UacCancellationScope, value.AdminLaunchAllowlist, value.AuthorityTier,
            value.AdminLaunchMode, value.DeniedAdminWindowApplications, value.DeniedAdminLaunchApplications,
            value.DeniedUacApplications, value.SemanticDelegation));
    private static bool SameBytes(byte[]? left, byte[]? right) => left is null ? right is null : right is not null && left.SequenceEqual(right);
    private static void ReplaceStorageFile(string path, byte[] bytes, byte[]? previous, string sid, bool fixture,
        List<string> recovery, ref bool committed)
    {
        var parent = Path.GetDirectoryName(path)!;
        var temporary = Path.Combine(parent, Guid.NewGuid().ToString("N") + ".tmp");
        var backup = Path.Combine(parent, Guid.NewGuid().ToString("N") + ".recovery");
        try
        {
            if (fixture) File.WriteAllBytes(temporary, bytes);
            else { SecurityLabel.Write(temporary, bytes, sid); CheckProtection(temporary); }
            if (!SameBytes(ReadStorageBytes(path, fixture), previous)) throw new Boundary("user_policy_changed_reopen_settings");
            // A replace exception cannot prove that the filesystem made no
            // change. From this point any failure has an uncertain outcome.
            committed = true;
            if (previous is null) File.Move(temporary, path);
            else { File.Replace(temporary, path, backup); recovery.Add(backup); }
            // Detect a noncooperating writer in the final replace interval. Do
            // not restore a previous file: it might revive revoked UAC settings.
            if (previous is not null && !SameBytes(ReadStorageBytes(backup, fixture), previous)
                || !SameBytes(ReadStorageBytes(path, fixture), bytes)) throw new Boundary("user_policy_save_outcome_unknown");
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { Console.Error.WriteLine("user_policy_temporary_cleanup_pending"); }
        }
    }
    private static string SaveStorage(UserPermissionSettings value, string expectedRevision, string path, bool fixture, Action<string>? checkpoint)
        => SaveStorageCore(value, expectedRevision, path, fixture, checkpoint, false).Revision;
    private static UserPermissionSettings SaveStorageCore(UserPermissionSettings value, string expectedRevision, string path, bool fixture, Action<string>? checkpoint, bool explicitSemanticSelection)
    {
        ValidateForUser(value, value.UserSid);
        value = Effective(value);
        var before = ReadStorage(path, value.UserSid, fixture);
        RequireCurrentRevision(expectedRevision, before.Settings.Revision);
        // Only this local High save path may mint metadata. Never accept a
        // marker copied into the submitted draft; off-first retains the mode.
        value = value with { SemanticDelegation = Flower.HighHelper.SemanticDelegation.ForLocalSave(before.Settings, value) };
        if (explicitSemanticSelection)
        {
            if (!value.AdminLaunchEnabled || value.AdminLaunchMode != "semantic" || Flower.HighHelper.SemanticDelegation.IncludesDsh(before.Settings.SemanticDelegation)
                || JsonSerializer.Serialize(before.Settings with { Revision = "" }) != JsonSerializer.Serialize(value with { Revision = "" }))
                throw new Boundary("semantic_delegation_disabled");
            value = value with { SemanticDelegation = Flower.HighHelper.SemanticDelegation.ForExplicitSelection(value.UserSid) };
        }
        if (before.CommonSchema != 1) throw new Boundary("user_policy_migration_required");
        if (before.Settings.UacPolicyError is not (null or "uac_policy_common_changed"))
            throw new Boundary(before.Settings.UacPolicyError);
        bool commonChanged = !CommonBytes(value, "compare").SequenceEqual(CommonBytes(before.Settings, "compare"));
        // The UI lifecycle already submits an off draft first, then explicitly
        // activates its returned revision. Never create a two-file enable commit.
        if (commonChanged && (value.UacMode != "off" || value.AdminLaunchEnabled)) throw new Boundary("uac_settings_require_off_first");
        bool uacChanged = !UacBytes(value, "compare", before.Common).SequenceEqual(UacBytes(before.Settings, "compare", before.Common));
        if (!commonChanged && !uacChanged && before.Settings.UacPolicyError is null) return value with { Revision = before.Settings.Revision };
        var common = commonChanged ? CommonBytes(value, Guid.NewGuid().ToString("N")) : before.Common;
        var uac = UacBytes(value, Guid.NewGuid().ToString("N"), common);
        var parent = Path.GetDirectoryName(path)!;
        if (!fixture) { CheckStorageParent(parent); SecurityLabel.CreateDirectory(parent, value.UserSid); }
        var recovery = new List<string>(); bool committed = false, succeeded = false;
        try
        {
            checkpoint?.Invoke("before_uac");
            RequireCurrentRevision(expectedRevision, ReadStorage(path, value.UserSid, fixture).Settings.Revision);
            // If common changes, the off sidecar is bound to its future bytes:
            // old-common/new-sidecar and new-common/new-sidecar both stay off.
            ReplaceStorageFile(UacPath(path), uac, before.Uac, value.UserSid, fixture, recovery, ref committed);
            checkpoint?.Invoke("after_uac");
            if (commonChanged)
            {
                if (!SameBytes(ReadStorageBytes(path, fixture), before.Common)
                    || !SameBytes(ReadStorageBytes(UacPath(path), fixture), uac)) throw new Boundary("user_policy_save_outcome_unknown");
                checkpoint?.Invoke("before_common");
                ReplaceStorageFile(path, common!, before.Common, value.UserSid, fixture, recovery, ref committed);
                checkpoint?.Invoke("after_common");
            }
            if (!SameBytes(ReadStorageBytes(path, fixture), common)
                || !SameBytes(ReadStorageBytes(UacPath(path), fixture), uac)) throw new Boundary("user_policy_save_outcome_unknown");
            succeeded = true;
            // Exact submitted bytes, never a fresh read that may lend the draft
            // another writer's revision after its own commit.
            return value with { Revision = StorageRevision(common, uac) };
        }
        catch (Exception original) when (committed)
        {
            // A failed enable must not leave our own just-written enable behind.
            // Only revoke bytes still belonging to this attempt; never overwrite
            // a newer writer and never restore an older permission file.
            Exception? revokeError = null;
            if (value.UacMode != "off" || value.AdminLaunchEnabled) try
            {
                if (SameBytes(ReadStorageBytes(UacPath(path), fixture), uac))
                    ReplaceStorageFile(UacPath(path), UacBytes(WithoutElevatedExecution(value), Guid.NewGuid().ToString("N"),
                        ReadStorageBytes(path, fixture)), uac, value.UserSid, fixture, recovery, ref committed);
            }
            catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or System.Security.SecurityException)
            { revokeError = error; Console.Error.WriteLine("user_policy_revoke_outcome_unknown"); }
            var uncertain = new Boundary("user_policy_save_outcome_unknown");
            // Computed from this attempt's submitted bytes, never a fresh
            // reader's revision. The lifecycle may CAS-revoke only this value.
            uncertain.Data["UserPermissionAttemptedRevision"] = StorageRevision(common, uac);
            uncertain.Data["OriginalError"] = original;
            uncertain.Data["OriginalErrorMessage"] = original.Message;
            if (revokeError is not null) uncertain.Data["RevocationError"] = revokeError;
            throw uncertain;
        }
        finally
        {
            // Partial results remain off and backups are retained for deliberate
            // recovery. A .recovery file is never consumed automatically.
            if (succeeded) foreach (var backup in recovery)
                try { File.Delete(backup); }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                { Console.Error.WriteLine("user_policy_saved_cleanup_pending"); }
        }
    }
    internal static void RequireCurrentRevision(string expected, string actual)
    {
        if (expected != actual) throw new Boundary("user_policy_changed_reopen_settings");
    }
}

internal static class SecurityLabel
{
    internal static void RequireUnlabelledExecutable(string sddl)
    {
        if (sddl.Length == 0) return;
        var acl = new RawSecurityDescriptor(sddl).SystemAcl;
        if (acl?.Cast<GenericAce>().Any(a => (byte)a.AceType == 17) == true)
            throw new Boundary("uac_image_label_would_demote_system");
    }
    internal static void RequireHigh(string sddl)
    {
        var acl = new RawSecurityDescriptor(sddl).SystemAcl;
        var labels = acl?.Cast<GenericAce>().Where(a => (byte)a.AceType == 17).ToArray() ?? [];
        if (labels.Length != 1 || (labels[0].AceFlags & AceFlags.InheritOnly) != 0)
            throw new Boundary("user_policy_unprotected");
        var bytes = new byte[labels[0].BinaryLength]; labels[0].GetBinaryForm(bytes, 0);
        if (bytes.Length < 20 || (BitConverter.ToInt32(bytes, 4) & 1) == 0
            || new SecurityIdentifier(bytes, 8).Value is not ("S-1-16-12288" or "S-1-16-16384"))
            throw new Boundary("user_policy_unprotected");
    }
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { public int Size; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern uint GetNamedSecurityInfoW(string path, uint kind, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr descriptor, uint revision, uint info, out IntPtr text, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateDirectoryW(string path, ref Attributes attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string path, uint access, uint sharing, ref Attributes attributes, uint disposition, uint flags, IntPtr template);
    private static IntPtr Descriptor(string sid) => ConvertStringSecurityDescriptorToSecurityDescriptorW(
        $"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;{sid})S:(ML;OICI;NW;;;HI)", 1, out var data, out _)
        ? data : throw new Boundary("permission_descriptor_failed", Marshal.GetLastWin32Error());
    internal static string Read(string path)
    {
        var status = GetNamedSecurityInfoW(path, 1, 0x10, out _, out _, out _, out _, out var descriptor);
        if (status != 0) throw new Boundary("user_policy_unprotected", (int)status);
        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 0x10, out var text, out _))
                throw new Boundary("user_policy_unprotected");
            try { return Marshal.PtrToStringUni(text)!; } finally { LocalFree(text); }
        }
        finally { LocalFree(descriptor); }
    }
    internal static void CreateDirectory(string path, string sid)
    {
        if (Directory.Exists(path)) { UserPermissions.CheckProtectionForDirectory(path); return; }
        var data = Descriptor(sid);
        try
        {
            var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = data };
            if (!CreateDirectoryW(path, ref attributes)) throw new Boundary("permission_directory_failed", Marshal.GetLastWin32Error());
        }
        finally { LocalFree(data); }
    }
    internal static void Write(string path, byte[] bytes, string sid)
    {
        var data = Descriptor(sid);
        try
        {
            var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = data };
            using var handle = CreateFileW(path, 0x40000000, 1, ref attributes, 1, 0x80000000, IntPtr.Zero);
            if (handle.IsInvalid) throw new Boundary("permission_write_failed", Marshal.GetLastWin32Error());
            using var stream = new FileStream(handle, FileAccess.Write); stream.Write(bytes); stream.Flush(true);
        }
        finally { LocalFree(data); }
    }
}
