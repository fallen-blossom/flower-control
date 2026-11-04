using System.Text;

namespace Flower.HighHelper;

internal static class DisplayPreferenceTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Check(bool value, string name) { assertions++; if (!value) throw new InvalidOperationException("display_preferences_test_" + name); }
        string root = Path.Combine(Path.GetTempPath(), "flower-display-read-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string path = Path.Combine(root, DisplayPreferences.FileName);
        try
        {
            var absent = DisplayPreferences.Read(root);
            Check(absent.Language == "zh-CN" && absent.Revision is null && absent.Error is null && !File.Exists(path), "chinese_default_without_write");
            File.WriteAllText(path, "{\"schema\":1,\"language\":\"en\"}", new UTF8Encoding(false));
            var english = DisplayPreferences.Read(root);
            Check(english.Language == "en" && english.Revision?.Length == 64 && english.Error is null, "ordinary_file_read");
            UiText.LoadProduction(root);
            Check(UiText.English && UiText.Language == "en", "production_loader_uses_same_ordinary_preference");
            string privateValue = "决策 C:\\private\\用户文件.exe {0}";
            Check(UiText.Format("普通禁止 {0} 条 · {1} · {2}", 1, privateValue, "UAC").Contains(privateValue, StringComparison.Ordinal), "private_values_unchanged");
            var normal = new UserPermissionSettings { AuthorityTier = 0 };
            Check(!HostWindow.PrivilegeSummary(normal).Any(c => c is >= '\u3400' and <= '\u9fff'), "tray_privilege_summary_english");
            Check(UiText.BrokerSummary("全部写入已停止") == "All writes stopped", "tray_status_english");
            foreach (string bad in new[] { "{bad", "{\"schema\":true,\"language\":\"en\"}",
                "{\"schema\":1,\"schema\":1,\"language\":\"en\"}", "{\"schema\":2,\"language\":\"en\"}",
                "{\"schema\":1,\"language\":\"auto\"}", "{\"schema\":1,\"language\":\"en\",\"unknown\":true}" })
            {
                File.WriteAllText(path, bad, new UTF8Encoding(false)); var rejected = DisplayPreferences.Read(root);
                Check(rejected.Language == "zh-CN" && rejected.Error is not null && File.ReadAllText(path) == bad, "invalid_file_preserved");
            }
            UiText.LoadProduction(root);
            Check(!UiText.English && UiText.Language == "zh-CN", "unreadable_falls_back_without_overwrite");
            return new { passed = true, assertions, scope = "owned ordinary fixture reads and authored UI labels; no production preferences, permission/Stop writes, GUI or High" };
        }
        finally { UiText.SetLanguage("zh-CN"); Directory.Delete(root, true); }
    }
}
