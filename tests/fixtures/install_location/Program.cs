using System.Reflection;
using System.Security.AccessControl;
using Flower.HighHelper;

int checks = 0;
void Check(bool value) { if (!value) throw new Exception("installation_location_check_failed"); checks++; }
var layout = InstallationLocation.Prepare(@"D:\FlowerControl", "S-1-5-21-1-2-3-1001");
Check(layout.ProgramRoot == @"D:\FlowerControl\Program");
Check(layout.DataRoot == @"D:\FlowerControl\Data");
Check(layout.CacheRoot == @"D:\FlowerControl\Cache");
Check(layout.PackagesRoot == @"D:\FlowerControl\Packages");
foreach (string path in new[] { "relative", @"D:\", @"D:\root\..\code", @"D:\root.\code", @"D:\root \code",
    @"D:\root:stream", @"\\server\share\code", @"\\?\D:\code", @"D:\r?ot" })
{
    bool rejected = false;
    try { InstallationLocation.Prepare(path); } catch (Boundary) { rejected = true; }
    Check(rejected);
}
var legacy = typeof(InstallationLocation).GetMethod("LegacyLocation", BindingFlags.Static | BindingFlags.NonPublic)!;
string? previous = Environment.GetEnvironmentVariable("ProgramFiles");
try
{
    Environment.SetEnvironmentVariable("ProgramFiles", @"D:\forged");
    var actual = (InstallationLocation)legacy.Invoke(null, ["S-1-5-21-1-2-3-1001"])!;
    Check(actual.Legacy);
    Check(actual.ProgramRoot == Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper"));
    Check(!actual.ProgramRoot.StartsWith(@"D:\forged", StringComparison.OrdinalIgnoreCase));
}
finally { Environment.SetEnvironmentVariable("ProgramFiles", previous); }
string temporary = Path.Combine(Path.GetTempPath(), "flower-location-native-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temporary);
try
{
    bool rejected = false;
    try { InstallationLocation.RequireProtectedPath(temporary); }
    catch (Boundary error) { rejected = error.Code == "installation_unprotected"; }
    Check(rejected);
}
finally { Directory.Delete(temporary); }
// This fixture is launched from an owned Program/versions/<version> directory.
var versionDirectory = new DirectoryInfo(AppContext.BaseDirectory);
if (versionDirectory.Parent?.Name == "versions")
{
    string version = versionDirectory.Name;
    var original = InstallationLocation.Prepare(versionDirectory.Parent.Parent!.Parent!.FullName, "S-1-5-21-1-2-3-1001");
    InstallationLocation.Bind(original, original.UserSid, versionDirectory.FullName, version);
    Check(InstallationLocation.Current() == original);
    Check(InstallationLocation.Discover().ProgramRoot != original.ProgramRoot);
    Check(InstallationLocation.Current() == original);
    bool rejected = false;
    try { InstallationLocation.Bind(original with { Root = @"D:\moved", ProgramRoot = @"D:\moved\Program" }, original.UserSid, versionDirectory.FullName, version); }
    catch (Boundary) { rejected = true; }
    Check(rejected);
    rejected = false;
    try { InstallationLocation.Current("S-1-5-21-111-222-333-1001"); } catch (Boundary) { rejected = true; }
    Check(rejected);
}
Console.WriteLine($"installation_location_native_checks={checks}");

namespace Flower.HighHelper
{
    internal sealed class Boundary : Exception
    {
        internal string Code { get; }
        internal Boundary(string code) : base(code) { Code = code; }
    }
    internal static class BrokerPolicy
    {
        internal static void RejectLinks(string path)
        {
            for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new Boundary("installation_link_rejected");
        }
    }
}
