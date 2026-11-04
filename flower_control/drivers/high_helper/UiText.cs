using System.Globalization;
using System.Text.Json;

namespace Flower.HighHelper;

// Only authored UI literals enter this catalog. User content, paths, provider
// names, protocol values and exception details are never passed for translation.
// Display language never participates in permission, Stop or provider settings.
internal static class UiText
{
    internal static bool English { get; private set; }
    internal static string Language => English ? "en" : "zh-CN";
    private static readonly Lazy<Dictionary<string, string>> Catalog = new(() =>
    {
        using var stream = typeof(UiText).Assembly.GetManifestResourceStream("Flower.Settings.English.json")
            ?? throw new Boundary("ui_translation_resource_missing");
        return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)
            ?? throw new Boundary("ui_translation_resource_invalid");
    });
    internal static void UseEnglishPreview() => English = true;
    internal static void SetLanguage(string language)
    {
        if (!DisplayPreferences.ValidLanguage(language)) throw new Boundary("invalid_display_language");
        English = language == "en";
    }
    internal static void LoadProduction(string root)
    {
        DisplayPreferences.BindProductionRoot(root);
        SetLanguage(DisplayPreferences.Read().Language);
    }
    internal static string BrokerSummary(string state) => state switch
    {
        "正在退出" => Get("正在退出"), "释放未确认，输入已停用" => Get("释放未确认，输入已停用"),
        "桌面锁定或不可用" => Get("桌面锁定或不可用"), "全部写入已停止" => Get("全部写入已停止"),
        "运行中；停止热键注册失败" => Get("运行中；停止热键注册失败"), "运行中" => Get("运行中"),
        _ => state
    };
    internal static string Get(string authored)
    {
        if (!English) return authored.Replace("决策", "decision", StringComparison.Ordinal);
        if (!Catalog.Value.TryGetValue(authored, out var result) || result.Length == 0)
            throw new Boundary("ui_translation_missing");
        return result;
    }
    internal static string Format(string authored, params object?[] values)
        => string.Format(CultureInfo.CurrentCulture, Get(authored), values);
    internal static int TranslationCount => Catalog.Value.Count;
    internal static object SelfTest()
    {
        int assertions = 0;
        void Check(bool value) { assertions++; if (!value) throw new Boundary("ui_localization_selftest_failed_" + assertions); }
        Check(!English && Get("决策服务") == "decision服务");
        var slots = new System.Text.RegularExpressions.Regex(@"\{[0-9]+(?:,[^}:]+)?(?::[^}]+)?\}");
        UseEnglishPreview();
        foreach (var pair in Catalog.Value)
        {
            Check(pair.Value.Length > 0 && !pair.Value.Any(c => c is >= '\u3400' and <= '\u9fff'));
            Check(slots.Matches(pair.Key).Select(x => x.Value).Order().SequenceEqual(slots.Matches(pair.Value).Select(x => x.Value).Order()));
        }
        Check(Get("决策服务").Contains("decision", StringComparison.Ordinal));
        string userText = "决策 C:\\私人路径\\item.exe {0} 中文程序名";
        string actual = Format("普通禁止 {0} 条 · {1} · {2}", 2, userText, "UAC");
        Check(actual.Contains(userText, StringComparison.Ordinal));
        Check(AuthorityPresentation.Label(2).StartsWith("04 ") && !AuthorityPresentation.Selectable(3));
        return new { passed = true, assertions, translations = TranslationCount,
            scope = "authored catalog, format placeholders and unchanged user values; no GUI or real settings" };
    }
}
