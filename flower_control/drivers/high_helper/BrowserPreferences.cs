using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace Flower.HighHelper;

internal sealed record BrowserInstallation(string Browser, string Name, string Executable);
internal sealed record BrowserPreferenceSnapshot(BrowserInstallation[] Installed, BrowserInstallation? WindowsDefault,
    string WindowsDefaultName, string Preference, string? Revision, BrowserInstallation? Selected, string? Error = null);

// Installation/association metadata only. Saves run through the verified Medium
// helper so this ordinary preference never becomes a High-owned user file.
internal static class BrowserPreferences
{
    internal const string FileName = "browser-preferences.json";
    internal static readonly string[] Families = ["brave", "edge", "chrome"];
    internal static string Name(string family) => family switch { "brave" => "Brave", "edge" => "Microsoft Edge", "chrome" => "Google Chrome", _ => "未知" };
    private static string Image(string family) => family switch { "brave" => "brave.exe", "edge" => "msedge.exe", _ => "chrome.exe" };
    private static string? Family(string image) => Path.GetFileName(image).ToLowerInvariant() switch { "brave.exe" => "brave", "msedge.exe" => "edge", "chrome.exe" => "chrome", _ => null };

    internal static BrowserPreferenceSnapshot Synthetic() => new(
        Families.Select(f => new BrowserInstallation(f, Name(f), @"E:\Preview\" + Image(f))).ToArray(),
        new("brave", "Brave", @"E:\Preview\brave.exe"), "Brave", "system", null,
        new("brave", "Brave", @"E:\Preview\brave.exe"));

    internal static BrowserPreferenceSnapshot Read(string? fixtureRoot = null)
    {
        var installed = Discover(); var windows = SystemDefault();
        string choice = "system"; string? revision = null;
        try
        {
            var root = fixtureRoot ?? BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false).DataRoot;
            if (!Path.IsPathFullyQualified(root)) throw new Boundary("browser_preferences_data_root_unavailable");
            string path = Path.Combine(root, FileName); RejectOptionalPath(path);
            byte[]? bytes = null;
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                if (stream.Length > 4096) throw new Boundary("browser_preferences_unverified");
                bytes = new byte[stream.Length]; stream.ReadExactly(bytes);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            if (bytes is not null)
            {
                ReadOnlyMemory<byte> json = bytes;
                if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf })) json = json[3..];
                using var document = JsonDocument.Parse(json); Protocol.CheckUnique(document);
                var value = document.RootElement;
                if (value.ValueKind != JsonValueKind.Object || !value.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(["schema", "default_browser"])
                    || value.GetProperty("schema").ValueKind != JsonValueKind.Number || value.GetProperty("schema").GetInt32() != 1)
                    throw new Boundary("browser_preferences_unverified");
                choice = value.GetProperty("default_browser").GetString() ?? "";
                if (choice != "system" && !Families.Contains(choice)) throw new Boundary("browser_preferences_unverified");
                revision = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            }
            string? selected = choice == "system" ? windows.Family : choice;
            if (choice == "system" && revision is null && Environment.GetEnvironmentVariable("FLOWER_WEB_BROWSER") is { Length: > 0 } legacy)
            {
                selected = legacy.ToLowerInvariant() switch { "msedge" => "edge", "google-chrome" or "chrome-x86" => "chrome", "brave" or "edge" or "chrome" => legacy.ToLowerInvariant(), _ => Path.IsPathFullyQualified(legacy) ? Family(legacy) : null };
            }
            var actual = installed.FirstOrDefault(i => i.Browser == selected);
            if (actual is null && choice == "system") actual = installed.FirstOrDefault(i => i.Browser == "brave") ?? installed.FirstOrDefault();
            return new(installed, installed.FirstOrDefault(i => i.Browser == windows.Family), windows.Name, choice, revision, actual,
                actual is null ? "selected_browser_not_installed" : null);
        }
        catch (Exception error)
        {
            return new(installed, installed.FirstOrDefault(i => i.Browser == windows.Family), windows.Name, choice, revision, null,
                error is Boundary boundary ? boundary.Code : "browser_preferences_unverified");
        }
    }

    internal static void RejectOptionalPath(string path)
    {
        for (FileSystemInfo? entry = new FileInfo(path); entry is not null;
            entry = entry is FileInfo file ? file.Directory : ((DirectoryInfo)entry).Parent)
        {
            try { if ((File.GetAttributes(entry.FullName) & FileAttributes.ReparsePoint) != 0) throw new Boundary("browser_preferences_link_rejected"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    // Only our directory selection/marker, never account/cookie contents.
    internal static string ProfileState(string browser, string kind, string? fixtureRoot = null)
    {
        try
        {
            string root = fixtureRoot ?? BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false).DataRoot;
            string directory = Path.Combine(root, "profiles"), name = kind + (browser == "brave" ? "-v1" : "-" + browser + "-v1");
            if (browser == "brave")
            {
                string selection = Path.Combine(directory, "active.json"); RejectOptionalPath(selection);
                if (File.Exists(selection))
                {
                    if (new FileInfo(selection).Length > 8192) return "unavailable";
                    using var doc = JsonDocument.Parse(File.ReadAllBytes(selection)); Protocol.CheckUnique(doc);
                    name = doc.RootElement.GetProperty("profiles").GetProperty(kind).GetString() ?? "";
                    if (name.Length == 0 || Path.GetFileName(name) != name || name is "." or "..") return "unavailable";
                }
            }
            string path = Path.Combine(directory, name); RejectOptionalPath(path);
            if (!Directory.Exists(path)) return "missing";
            // An empty directory is not an existing usable login profile.
            return File.Exists(Path.Combine(path, "Local State")) || Directory.Exists(Path.Combine(path, "Default")) ? "exists" : "incomplete";
        }
        catch { return "unavailable"; }
    }

    internal static BrowserInstallation[] Discover()
    {
        string[] roots = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) }
            .Where(p => Path.IsPathFullyQualified(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        List<BrowserInstallation> output = [];
        foreach (string family in Families)
        {
            string relative = family switch { "brave" => @"BraveSoftware\Brave-Browser\Application\brave.exe", "edge" => @"Microsoft\Edge\Application\msedge.exe", _ => @"Google\Chrome\Application\chrome.exe" };
            var candidates = roots.Select(root => Path.Combine(root, relative)).ToList();
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
                foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                    try
                    {
                        using var registry = RegistryKey.OpenBaseKey(hive, view);
                        using var key = registry.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\App Paths\" + Image(family));
                        if (key?.GetValue(null) is string value) candidates.Add(Environment.ExpandEnvironmentVariables(value.Trim().Trim('"')));
                    }
                    catch (System.Security.SecurityException) { }
                    catch (UnauthorizedAccessException) { }
            string? found = candidates.FirstOrDefault(path => Trusted(path, family, roots));
            if (found is not null) output.Add(new(family, Name(family), found));
        }
        return output.ToArray();
    }

    private static bool Trusted(string path, string family, string[] roots)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\") || Family(path) != family || !File.Exists(path)) return false;
            string full = Path.GetFullPath(path);
            if (!roots.Any(root => full.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) return false;
            BrokerPolicy.RejectLinks(full); return true;
        }
        catch (Exception) { return false; }
    }

    private static (string? Family, string Name) SystemDefault()
    {
        try
        {
            uint size = 32768; var value = new StringBuilder((int)size);
            if (AssocQueryStringW(0, 2, "https", null, value, ref size) != 0) return (null, "未知");
            string? family = Family(value.ToString());
            return (family, family is not null ? Name(family) : Path.GetFileName(value.ToString()).Equals("firefox.exe", StringComparison.OrdinalIgnoreCase) ? "Mozilla Firefox（暂不支持）" : "不支持的浏览器");
        }
        catch (Exception) { return (null, "未知"); }
    }
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)] private static extern int AssocQueryStringW(uint flags, int text, string association, string? extra, StringBuilder output, ref uint size);
}
