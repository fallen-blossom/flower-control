using System.Reflection;
using System.Text;

namespace Flower.HighHelper;

internal static class SettingsUiPreferenceTests
{
    internal static int Run()
    {
        int assertions = 0;
        void Require(bool value) { assertions++; if (!value) throw new Boundary("settings_ui_preference_selftest_failed"); }
        string root = Path.Combine(Path.GetTempPath(), "flower-ui-preference-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        object Invoke(string name, params object?[] args)
        {
            try { return typeof(UserPermissions).GetMethod(name, BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, args)!; }
            catch (TargetInvocationException error) { throw error.InnerException!; }
        }
        const string sid = "S-1-5-21-111-222-333-1001";
        string path = Path.Combine(root, "fixture.settings-ui.json");
        SettingsUiPreference Read() => (SettingsUiPreference)Invoke("ReadUiPreferenceCore", path, sid, true);
        SettingsUiPreference Save(string revision, string mode, Action<string>? checkpoint = null)
            => (SettingsUiPreference)Invoke("SaveUiPreferenceCore", path, sid, revision, mode, true, checkpoint);
        void Reject(string code, Action action)
        {
            try { action(); }
            catch (Boundary error) { Require(error.Code == code); return; }
            throw new Boundary("settings_ui_preference_expected_rejection");
        }
        try
        {
            byte[] untouchedPolicy = "owned policy sentinel"u8.ToArray();
            string policy = Path.Combine(root, "policy.json"); File.WriteAllBytes(policy, untouchedPolicy);
            var missing = Read(); Require(missing == new SettingsUiPreference() && !File.Exists(path));
            var first = Save(missing.Revision, "semantic");
            Require(first.Error is null && first.UacSubmode == "semantic" && first.Revision != "absent");
            Require(Read() == first);
            Require(UserPermissions.PreferredUacSubmode("off", first) == "semantic");
            Require(UserPermissions.PreferredUacSubmode("allowlist", first) == "allowlist");
            Require(UserPermissions.PreferredUacSubmode("semantic", new()) == "semantic");
            Require(UserPermissions.PreferredUacSubmode("observe", first) == "semantic");
            var future = new SettingsUiPreference("allowlist", "opaque", "settings_ui_preferences_unsupported");
            Require(!UserPermissions.UiPreferenceNeedsSave("off", "off", "allowlist", "allowlist", future, false));
            Require(!UserPermissions.UiPreferenceNeedsSave("allowlist", "allowlist", "allowlist", "allowlist", future, false));
            Require(UserPermissions.UiPreferenceNeedsSave("semantic", "off", "semantic", "semantic", new(), false));
            Require(!UserPermissions.UiPreferenceNeedsSave("semantic", "off", "semantic", "semantic", first, false));
            Require(UserPermissions.UiPreferenceNeedsSave("allowlist", "off", "allowlist", "allowlist", new(), false));
            Require(UserPermissions.UiPreferenceNeedsSave("off", "off", "semantic", "semantic", first, true));
            Require(UserPermissions.UiPreferenceNeedsSave("off", "off", "semantic", "allowlist", new(), false));
            Require(!UserPermissions.UiPreferenceNeedsSave("observe", "off", "allowlist", "allowlist", future, false));
            byte[] firstBytes = File.ReadAllBytes(path);
            Require(Save(first.Revision, "semantic") == first && File.ReadAllBytes(path).SequenceEqual(firstBytes));
            Reject("settings_ui_preferences_changed", () => Save("absent", "allowlist"));
            Require(File.ReadAllBytes(path).SequenceEqual(firstBytes));
            Reject("settings_ui_preferences_invalid", () => Save(first.Revision, "off"));
            var second = Save(first.Revision, "allowlist");
            Require(second.Revision != first.Revision && Read().UacSubmode == "allowlist");
            Reject("settings_ui_preferences_changed", () => Save(first.Revision, "semantic"));

            Reject("settings_ui_preferences_save_outcome_unknown", () => Save(second.Revision, "semantic", phase => {
                if (phase == "after_write") throw new IOException("owned post-commit fault");
            }));
            var afterUnknown = Read(); Require(afterUnknown.UacSubmode == "semantic");
            Reject("settings_ui_preferences_changed", () => Save(second.Revision, "allowlist"));

            byte[] otherWriter = Encoding.UTF8.GetBytes("{\"Schema\":1,\"UserSid\":\"" + sid + "\",\"UacSubmode\":\"allowlist\"}");
            Reject("user_policy_changed_reopen_settings", () => Save(afterUnknown.Revision, "allowlist", phase => {
                if (phase == "before_write") File.WriteAllBytes(path, otherWriter);
            }));
            Require(File.ReadAllBytes(path).SequenceEqual(otherWriter));

            foreach (string bad in new[] {
                "{\"Schema\":2,\"UserSid\":\"" + sid + "\",\"UacSubmode\":\"semantic\"}",
                "{\"Schema\":1,\"UserSid\":\"" + sid + "\",\"UacSubmode\":\"semantic\",\"Future\":true}" })
            {
                File.WriteAllText(path, bad); var unsupported = Read();
                Require(unsupported.Error == "settings_ui_preferences_unsupported" && unsupported.Revision != "absent");
                Reject("settings_ui_preferences_unsupported", () => Save(unsupported.Revision, "allowlist"));
                Require(File.ReadAllText(path) == bad);
            }
            File.WriteAllText(path, "{\"Schema\":1,\"UserSid\":\"wrong-user\",\"UacSubmode\":\"semantic\"}");
            var wrongSid = Read(); Require(wrongSid.Error == "settings_ui_preferences_identity_mismatch");
            Reject("settings_ui_preferences_identity_mismatch", () => Save(wrongSid.Revision, "allowlist"));

            foreach (string broken in new[] { "{", "{\"Schema\":1,\"Schema\":1}",
                "{\"Schema\":1,\"UserSid\":\"" + sid + "\",\"UacSubmode\":true}" })
            {
                File.WriteAllText(path, broken); var invalid = Read();
                Require(invalid.Error == "settings_ui_preferences_invalid" && invalid.Revision != "absent");
                Require(invalid.UacSubmode == "allowlist" && File.ReadAllText(path) == broken);
                var repaired = Save(invalid.Revision, "allowlist"); Require(repaired.Error is null && Read() == repaired);
            }
            Require(File.ReadAllBytes(policy).SequenceEqual(untouchedPolicy));
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(path));
            Require(document.RootElement.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["Schema", "UserSid", "UacSubmode"]));
            return assertions;
        }
        finally { Directory.Delete(root, true); }
    }
}
