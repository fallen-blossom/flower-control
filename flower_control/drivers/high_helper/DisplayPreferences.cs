using System.Security.Cryptography;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record DisplayPreferenceSnapshot(string Language = "zh-CN", string? Revision = null, string? Error = null);

// This is ordinary user presentation data. The native UI only reads it;
// writes always use the verified Medium helper and its independent CAS.
internal static class DisplayPreferences
{
    internal const string FileName = "display-preferences.json";
    private static string? productionRoot;
    internal static bool HasProductionRoot => productionRoot is not null;
    internal static void BindProductionRoot(string root)
    {
        if (!Path.IsPathFullyQualified(root)) throw new Boundary("display_preferences_data_root_unavailable");
        productionRoot = root;
    }
    internal static bool ValidLanguage(string value) => value is "zh-CN" or "en";
    internal static DisplayPreferenceSnapshot Read(string? fixtureRoot = null)
    {
        try
        {
            string root = fixtureRoot ?? productionRoot ?? BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false).DataRoot;
            if (!Path.IsPathFullyQualified(root)) throw new Boundary("display_preferences_data_root_unavailable");
            if (fixtureRoot is null) productionRoot = root;
            string path = Path.Combine(root, FileName); BrowserPreferences.RejectOptionalPath(path);
            byte[] bytes;
            try
            {
                using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                if (input.Length > 4096) throw new Boundary("display_preferences_unverified");
                bytes = new byte[input.Length]; input.ReadExactly(bytes);
            }
            catch (FileNotFoundException) { return new(); }
            catch (DirectoryNotFoundException) { return new(); }
            string revision = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            ReadOnlyMemory<byte> json = bytes;
            if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) json = json[3..];
            using var document = JsonDocument.Parse(json); Protocol.CheckUnique(document);
            var value = document.RootElement;
            if (value.ValueKind != JsonValueKind.Object || !value.EnumerateObject().Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(["schema", "language"])
                || value.GetProperty("schema").ValueKind != JsonValueKind.Number || !value.GetProperty("schema").TryGetInt32(out int schema) || schema != 1
                || value.GetProperty("language").ValueKind != JsonValueKind.String || value.GetProperty("language").GetString() is not { } language || !ValidLanguage(language))
                throw new Boundary("display_preferences_unverified");
            return new(language, revision);
        }
        catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or System.Security.SecurityException)
        { return new(Error: "display_preferences_unverified"); }
    }
}
