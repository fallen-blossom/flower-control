using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

// Read only: call the exact installed host predicate without constructing a
// broker, a SharedWriteGate, a policy writer or any source/authority record.
if (args.Length != 5 || !int.TryParse(args[3], out var pid) || pid <= 0
    || !long.TryParse(args[4], NumberStyles.None, CultureInfo.InvariantCulture, out var created) || created <= 0
    || !Regex.IsMatch(args[1], "\\A[a-f0-9]{64}\\z")) return 2;
var library = Path.GetFullPath(args[0]);
var versions = Path.Combine(Flower.HighHelper.InstallationLocation.Discover().ProgramRoot, "versions");
if (Path.GetFileName(library) != "Flower.HighHelper.dll"
    || !Regex.IsMatch(Path.GetFileName(Path.GetDirectoryName(library)!), "\\A[a-f0-9]{32}\\z")
    || !library.StartsWith(versions + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return 2;
for (FileSystemInfo? item = new FileInfo(library); item is not null;
     item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
    if ((File.GetAttributes(item.FullName) & FileAttributes.ReparsePoint) != 0) return 2;
using var pinned = new FileStream(library, FileMode.Open, FileAccess.Read, FileShare.Read);
if (Convert.ToHexString(SHA256.HashData(pinned)).ToLowerInvariant() != args[1]) return 3;
var assembly = Assembly.LoadFrom(library);
var type = assembly.GetType("Flower.HighHelper.CodexHostIdentity", throwOnError: true)!;
var check = type.GetMethod("IsOfficialCodexImage", BindingFlags.NonPublic | BindingFlags.Static)!;
var accepted = (bool)check.Invoke(null, [args[2], pid, (long?)created])!;
Console.WriteLine(JsonSerializer.Serialize(new {
    Accepted = accepted, Pid = pid, Created = created.ToString(CultureInfo.InvariantCulture),
    NativeSha256 = args[1], ReadOnly = true, AuthorityGranted = false, InputDispatched = false
}));
return accepted ? 0 : 1;
