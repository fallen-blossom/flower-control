using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// An explicit, read-only health check. A successful hash comparison grants no
// authority and never starts, reinstalls, resumes or replays an executor.
internal static class InstallationHealth
{
    private const int ManifestLimit = 4_000_000;
    internal static JsonDocument ReadManifest(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > ManifestLimit) throw new Boundary("installation_manifest_too_large");
        var document = JsonDocument.Parse(stream);
        try { Protocol.CheckUnique(document); return document; }
        catch { document.Dispose(); throw; }
    }
    internal static string RelativeFile(string directory, string relative, bool nested)
    {
        if (relative.Length is < 1 or > 512 || relative.Contains('\\') || relative.Contains(':')
            || relative.Split('/').Any(part => part is "" or "." or ".." || part.EndsWith(' ') || part.EndsWith('.'))
            || (!nested && relative.Contains('/')) || nested && !relative.StartsWith("runtime/", StringComparison.Ordinal)
                && !relative.StartsWith("python-source/", StringComparison.Ordinal))
            throw new Boundary("installation_inventory_rejected");
        string root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new Boundary("installation_inventory_rejected");
        return path;
    }
    internal static int VerifyHashes(string directory, JsonElement hashes, bool nested, CancellationToken cancellation,
        bool fixture = false)
    {
        if (hashes.ValueKind != JsonValueKind.Object) throw new Boundary("installation_inventory_rejected");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase); int count = 0;
        foreach (var item in hashes.EnumerateObject())
        {
            cancellation.ThrowIfCancellationRequested();
            if (++count > 20000 || !names.Add(item.Name) || item.Value.ValueKind != JsonValueKind.String
                || !Regex.IsMatch(item.Value.GetString() ?? "", "^[a-f0-9]{64}$"))
                throw new Boundary("installation_inventory_rejected");
            string path = RelativeFile(directory, item.Name, nested);
            BrokerPolicy.RejectLinks(path);
            if (!fixture) UserPermissions.CheckProtection(path);
            if (Native.Digest(path) != item.Value.GetString()) throw new Boundary("installation_file_changed");
        }
        if (count == 0) throw new Boundary("installation_inventory_rejected");
        return count;
    }
    internal static int Verify(BrokerPolicy policy, CancellationToken cancellation)
    {
        string programRoot = InstallationLocation.Discover(policy.UserSid).ProgramRoot;
        string activePath = Path.Combine(programRoot, "active.json");
        BrokerPolicy.RejectLinks(activePath); UserPermissions.CheckProtection(activePath);
        string activeDigest = Native.Digest(activePath);
        using var active = ReadManifest(activePath);
        if (active.RootElement.GetProperty("version").GetString() != policy.Version)
            throw new Boundary("installation_version_mismatch");
        cancellation.ThrowIfCancellationRequested();
        policy.VerifySource("flower-app"); // VerifySource hashes the common three-channel source set.
        int count = VerifyHashes(policy.Directory, active.RootElement.GetProperty("hashes"), false, cancellation);
        foreach (var (name, digest) in policy.AppWorkerHashes)
        {
            cancellation.ThrowIfCancellationRequested();
            if (Path.GetFileName(name) != name || name.Contains(':') || name.Contains('\\') || name.Contains('/'))
                throw new Boundary("installation_inventory_rejected");
            string path = Path.Combine(policy.Directory, "app", name);
            BrokerPolicy.RejectLinks(path); UserPermissions.CheckProtection(path);
            if (Native.Digest(path) != digest) throw new Boundary("app_worker_changed");
            ++count;
        }
        if (active.RootElement.TryGetProperty("runtime_hashes", out var nested))
        {
            using var inventory = ReadManifest(Path.Combine(policy.Directory, "runtime-inventory.json"));
            var listed = inventory.RootElement.GetProperty("files").EnumerateObject().ToDictionary(x => x.Name, x => x.Value.GetString(), StringComparer.Ordinal);
            var installed = nested.EnumerateObject().ToDictionary(x => x.Name, x => x.Value.GetString(), StringComparer.Ordinal);
            if (listed.Count != installed.Count || listed.Any(item => !installed.TryGetValue(item.Key, out var value) || value != item.Value))
                throw new Boundary("installation_inventory_changed");
            count += VerifyHashes(policy.Directory, nested, true, cancellation);
        }
        // The result describes one fixed manifest, even if an update arrived
        // during the check. A changed active record is never a green result.
        if (Native.Digest(activePath) != activeDigest) throw new Boundary("installation_changed_during_check");
        return count;
    }
    internal static int SelfTest()
    {
        int checks = 0;
        void Check(bool value) { ++checks; if (!value) throw new Boundary("installation_health_selftest_failed_" + checks); }
        string root = Path.Combine(Path.GetTempPath(), "flower-health-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string path = Path.Combine(root, "owned.txt"); File.WriteAllText(path, "fixture");
        string digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
        using var manifest = JsonDocument.Parse(JsonSerializer.Serialize(new Dictionary<string, string> { ["owned.txt"] = digest }));
        Check(VerifyHashes(root, manifest.RootElement, false, CancellationToken.None, fixture: true) == 1);
        File.WriteAllText(path, "changed");
        try { VerifyHashes(root, manifest.RootElement, false, CancellationToken.None, fixture: true); Check(false); }
        catch (Boundary error) { Check(error.Code == "installation_file_changed"); }
        foreach (string name in new[] { "../escape", "/absolute", "C:/escape", "runtime/../escape", "runtime/name. ", "runtime\\escape" })
            try { RelativeFile(root, name, true); Check(false); }
            catch (Boundary error) { Check(error.Code == "installation_inventory_rejected"); }
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        try { VerifyHashes(root, manifest.RootElement, false, cancellation.Token, fixture: true); Check(false); }
        catch (OperationCanceledException) { Check(true); }
        // The fixture stays in OS TEMP; no production/user path is touched.
        return checks;
    }
}
