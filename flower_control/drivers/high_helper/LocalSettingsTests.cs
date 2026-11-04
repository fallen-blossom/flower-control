using System.Text.Json;
namespace Flower.HighHelper;

internal static class LocalSettingsTests
{
    internal static object Run()
    {
        int checks = 0;
        void Check(bool value, string name) { if (!value) throw new InvalidOperationException(name); checks++; }
        var custom = new CustomDecisionProvider("custom_" + new string('a', 32), "Compatible", "openai_chat", "https://provider.example/v1/chat/completions", "model-test");
        var value = new DecisionProviderPreferences([custom.Id, "jev", "host", "perplexity"], [custom.Id], Custom: [custom]);
        Check(DecisionProviderSettings.Parse(DecisionProviderSettings.Serialize(value)).Same(value), "schema2_roundtrip");
        Check(DecisionProviderSettings.Parse(DecisionProviderSettings.Serialize(DecisionProviderSettings.Legacy())).Same(DecisionProviderSettings.Legacy()), "schema1_legacy_roundtrip");
        Check(value.ActiveOrder().SequenceEqual([custom.Id]), "explicit_order_before_host");
        Check(DecisionCredential.Target(custom.Id, custom) != DecisionCredential.Target(custom.Id, custom with { Endpoint = "https://other.example/api" }), "changed_recipient_does_not_reuse_key");
        Check(DecisionCredential.Target(custom.Id, custom) == DecisionCredential.Target(custom.Id, custom with { Model = "other-model" }), "model_change_keeps_same_recipient_key");
        string root = Path.Combine(Path.GetTempPath(), "flower-local-settings-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var first = BrowserPreferences.Read(root);
            Check(first.Revision is null && first.Error is null && !File.Exists(Path.Combine(root, BrowserPreferences.FileName)), "first_use_missing_preference_is_valid_without_write");
            Check(BrowserPreferences.ProfileState("edge", "ai", root) == "missing", "missing_profile_is_create");
            string profile = Path.Combine(root, "profiles", "ai-edge-v1"); Directory.CreateDirectory(profile);
            Check(BrowserPreferences.ProfileState("edge", "ai", root) == "incomplete", "empty_profile_is_not_finished");
            Directory.CreateDirectory(Path.Combine(profile, "Default"));
            Check(BrowserPreferences.ProfileState("edge", "ai", root) == "exists", "existing_profile_is_open");
            Check(BrowserPreferences.ProfileState("chrome", "ai", root) == "missing", "same_kind_is_separate_per_browser");
            var saved = DecisionProviderSettings.Save(Path.Combine(root, "decision-providers.json"), null, value);
            Check(saved.Value!.Same(value) && saved.Revision is not null, "native_custom_save_and_readback");
            try { DecisionProviderSettings.Save(Path.Combine(root, "decision-providers.json"), null, value.Enable(custom.Id, false)); throw new InvalidOperationException("stale_save_allowed"); }
            catch (Boundary error) { Check(error.Code == "decision_settings_conflict", "conflict_keeps_current_config"); }
        }
        finally { Directory.Delete(root, true); } // Only this exact private test directory.
        return new { assertions = checks, scope = "private synthetic settings; no WinCred write, network, production policy, Stop, UI or input", credentialTarget = DecisionCredential.Target(custom.Id, custom) };
    }
}
