using System.Reflection;
using System.Security.Principal;
using System.Text.Json;

var assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
var settingsType = assembly.GetType("Flower.HighHelper.UserPermissionSettings", true)!;
var portability = assembly.GetType("Flower.HighHelper.SettingsPortability", true)!;
object baseline = Activator.CreateInstance(settingsType)!;
void Set(string name, object value) => settingsType.GetProperty(name)!.SetValue(baseline, value);
Set("UserSid", WindowsIdentity.GetCurrent().User!.Value);
Set("Revision", "isolated-portability-fixture");
Set("AuthorityTier", 2); Set("AdminWindows", true); Set("AdminLaunchEnabled", true); Set("AdminLaunchMode", "semantic");
int checks = 0;
void Check(bool value) { if (!value) throw new Exception("settings_portability_check_failed"); checks++; }
var document = new Dictionary<string, object?> {
    ["schema"] = 1, ["kind"] = "flower-control-settings", ["created_utc"] = DateTime.UtcNow.ToString("O"),
    ["settings"] = new Dictionary<string, object?> {
        ["HudCompact"] = true, ["HudPosition"] = "bottom_right",
        ["AdminLaunchAllowlist"] = new[] { new { Path = @"C:\Windows\Admin.exe", IdentityKind = "sha256",
            Identity = new string('a',64), DisplayName = "Local program", Enabled = true, Arguments = "--password secret" } },
        ["DeniedApplications"] = new[] { new { Path = @"C:\Windows\Private.exe", TitleContains = "Private", Enabled = true } } },
    ["preferences"] = new { default_browser = "system", language = "en" },
    ["fixed_shortcuts"] = new { computer_stop = "Ctrl+Alt+9", global_stop = "Ctrl+Alt+Shift+9", save_settings = "Ctrl+S" },
    ["excluded"] = new[] { "credentials", "cookies", "profiles", "chat_content", "live_grants", "authority_tier", "semantic_delegation", "stop_state", "pending_requests", "unknown_results", "sensitive_words" } };
var decode = portability.GetMethod("Decode", BindingFlags.Static | BindingFlags.NonPublic)!;
using (var json = JsonSerializer.SerializeToDocument(document))
{
    object parsed = decode.Invoke(null, [json.RootElement, baseline])!;
    object imported = parsed.GetType().GetProperty("Settings")!.GetValue(parsed)!;
    object? Get(string name) => settingsType.GetProperty(name)!.GetValue(imported);
    Check((int)Get("AuthorityTier")! == 2);
    Check((bool)Get("AdminWindows")!);
    Check((bool)Get("AdminLaunchEnabled")!);
    Check((string)Get("AdminLaunchMode")! == "semantic");
    Check((bool)Get("HudCompact")!);
    Check((string)Get("HudPosition")! == "bottom_right");
    var allow = (Array)Get("AdminLaunchAllowlist")!;
    object row = allow.GetValue(0)!;
    Check(!(bool)row.GetType().GetProperty("Enabled")!.GetValue(row)!);
    Check((string)row.GetType().GetProperty("Arguments")!.GetValue(row)! == "");
    Check((string)parsed.GetType().GetProperty("Browser")!.GetValue(parsed)! == "system");
    Check((string)parsed.GetType().GetProperty("Language")!.GetValue(parsed)! == "en");
    Check(!(bool)settingsType.GetProperty("HudCompact")!.GetValue(baseline)!);
}
((Dictionary<string, object?>)document["settings"]!)["AuthorityTier"] = 3;
using (var json = JsonSerializer.SerializeToDocument(document))
{
    bool rejected = false;
    try { decode.Invoke(null, [json.RootElement, baseline]); }
    catch (TargetInvocationException error) { rejected = error.InnerException?.Message == "settings_portable_schema_invalid"; }
    Check(rejected);
}
// Exercise the real private storage reader with owned files. No protected
// production policy, registration, role switch or input entry is used.
var permissions = assembly.GetType("Flower.HighHelper.UserPermissions", true)!;
var readStorage = permissions.GetMethod("ReadStorage", BindingFlags.Static | BindingFlags.NonPublic)!;
var effective = permissions.GetMethod("Effective", BindingFlags.Static | BindingFlags.NonPublic)!;
string policySid = WindowsIdentity.GetCurrent().User!.Value;
string directory = Path.Combine(Path.GetTempPath(), "flower-native-policy-default-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
string commonPath = Path.Combine(directory, "policy.json"), sidecarPath = Path.Combine(directory, "policy.uac.json");
object ReadPolicy()
{
    object snapshot = readStorage.Invoke(null, [commonPath, policySid, true])!;
    object settings = snapshot.GetType().GetProperty("Settings")!.GetValue(snapshot)!;
    return effective.Invoke(null, [settings])!;
}
object? Field(object value, string name) => settingsType.GetProperty(name)!.GetValue(value);
void Tier(object value, int expected)
{
    Check((int)Field(value, "AuthorityTier")! == expected);
    Check((bool)Field(value, "AdminWindows")! == (expected >= 1));
    Check((bool)Field(value, "AdminLaunchEnabled")! == (expected >= 2));
}
byte[] WriteCommon(bool admin)
{
    byte[] raw = JsonSerializer.SerializeToUtf8Bytes(new { Schema = 1, Revision = "legacy", UserSid = policySid,
        AdminWindows = admin, AdminScope = "all", UacEnabled = false, JevEnabled = true,
        DeniedApplications = Array.Empty<object>(), AllowedAdminApplications = Array.Empty<object>(), Masks = Array.Empty<object>(),
        SmoothPointer = false, HudCompact = false, HudPosition = "auto" });
    File.WriteAllBytes(commonPath, raw); return raw;
}
byte[] WriteSidecar(string commonRevision, bool launch, int? explicitTier = null, string? overrideSid = null)
{
    var value = new Dictionary<string, object?> { ["Schema"] = 1, ["Revision"] = "legacy-sidecar", ["UserSid"] = overrideSid ?? policySid,
        ["CommonRevision"] = commonRevision, ["UacMode"] = "off", ["UacAllowlist"] = Array.Empty<object>(), ["AdminLaunchEnabled"] = launch };
    if (explicitTier is not null) value["AuthorityTier"] = explicitTier;
    byte[] raw = JsonSerializer.SerializeToUtf8Bytes(value); File.WriteAllBytes(sidecarPath, raw); return raw;
}
try
{
    Tier(ReadPolicy(), 0); Check(!File.Exists(commonPath) && !File.Exists(sidecarPath));
    byte[] common = WriteCommon(true); Tier(ReadPolicy(), 1); Check(File.ReadAllBytes(commonPath).SequenceEqual(common));
    string revision = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(common));
    byte[] sidecar = WriteSidecar(revision, true); Tier(ReadPolicy(), 2);
    Check(File.ReadAllBytes(commonPath).SequenceEqual(common)); Check(File.ReadAllBytes(sidecarPath).SequenceEqual(sidecar));
    File.Delete(commonPath);
    foreach (bool launch in new[] { false, true })
    {
        sidecar = WriteSidecar("absent", launch); Tier(ReadPolicy(), launch ? 2 : 1);
        Check(!File.Exists(commonPath)); Check(File.ReadAllBytes(sidecarPath).SequenceEqual(sidecar));
    }
    WriteSidecar("absent", true, explicitTier: 0); Tier(ReadPolicy(), 0);
    WriteSidecar("absent", true, overrideSid: policySid + "9"); Tier(ReadPolicy(), 0);
    WriteSidecar(new string('f', 64), true); Tier(ReadPolicy(), 0);
    File.WriteAllText(sidecarPath, "{"); Tier(ReadPolicy(), 0);
    common = WriteCommon(false);
    WriteSidecar(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(common)), true);
    Tier(ReadPolicy(), 0); Check(File.ReadAllBytes(commonPath).SequenceEqual(common));
}
finally { Directory.Delete(directory, recursive: true); }
Console.WriteLine($"settings_portability_and_default_policy_native_checks={checks}");
