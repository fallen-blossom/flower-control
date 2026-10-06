using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal record ImageRule(string Path, string Sha256);
internal record NativeHostRule(string Kind, string Path, string Sha256);
internal record FixturePeer(int Pid, long Created, string ImageDigest);
internal sealed record BrokerPolicy
{
    public int Schema { get; init; } = 1;
    public string Version { get; init; } = "";
    public string UserSid { get; init; } = "";
    public string Mode { get; init; } = "high";
    public string FixturePipe { get; init; } = "";
    public ImageRule Python { get; init; } = new("", "");
    public string[] CodexPackageFamilies { get; init; } = [];
    public string[] CodexImageRoots { get; init; } = [];
    public string[] AdditionalAgents { get; init; } = [];
    public NativeHostRule[] NativeHosts { get; init; } = [];
    public string Repository { get; init; } = "";
    public Dictionary<string, string> SourceHashes { get; init; } = [];
    public FixturePeer[] FixturePeers { get; init; } = [];
    public Dictionary<string, string> AppWorkerHashes { get; init; } = [];
    internal bool Fixture => Mode == "medium-isolated-fixture";
    internal string Directory { get; private set; } = "";
    internal static BrokerPolicy Load(string path, bool fixture)
    {
        path = Path.GetFullPath(path);
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length > 256000) throw new Boundary("policy_rejected");
        using var document = JsonDocument.Parse(bytes);
        Protocol.CheckUnique(document);
        var value = Protocol.Decode<BrokerPolicy>(document);
        if (value.Schema != 1 || !Regex.IsMatch(value.Version, "^[a-f0-9]{16,64}$")
            || !Regex.IsMatch(value.UserSid, "^S-1-5-21-[0-9-]+$")
            || value.AdditionalAgents.Length != 0 || value.Fixture != fixture
            || (fixture ? value.FixturePeers.Length is < 1 or > 16
                 || !Regex.IsMatch(value.FixturePipe, @"^Flower\.HighBroker\.Fixture\.[a-f0-9]{32}$")
                 : value.Mode != "high" || value.CodexPackageFamilies.Length + value.CodexImageRoots.Length + value.NativeHosts.Length is < 1 or > 16)
            || value.NativeHosts.Length > 16 || fixture && value.NativeHosts.Length != 0)
            throw new Boundary("policy_rejected");
        value.Directory = Path.GetDirectoryName(path)!;
        if (!fixture)
        {
            var expected = Path.Combine(AppContext.BaseDirectory, "broker.json");
            var production = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper", "versions");
            if (!path.Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase)
                || !path.StartsWith(production + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new Boundary("production_path_rejected");
            RejectLinks(path);
            if (!Path.IsPathFullyQualified(value.Python.Path) || !Regex.IsMatch(value.Python.Sha256, "^[a-f0-9]{64}$")
                || !Path.GetDirectoryName(value.Python.Path)!.Equals(value.Directory, StringComparison.OrdinalIgnoreCase)
                || Path.GetFileName(value.Python.Path) != "flower-python.exe"
                || value.CodexPackageFamilies.Any(f => !Regex.IsMatch(f, "^OpenAI\\.Codex_[a-z0-9]{13}$"))
                || value.CodexImageRoots.Any(p => !Path.IsPathFullyQualified(p) || p.Contains('*') || p.Contains('?') || p.TrimEnd('\\').Length < 16))
                throw new Boundary("policy_rejected");
            foreach (var host in value.NativeHosts)
            {
                var expectedName = host.Kind switch { "claude-code" => "claude.exe", "antigravity" => "Antigravity.exe",
                    "local-mcp" => Path.GetFileName(host.Path), _ => "" };
                if (expectedName == "" || !Path.IsPathFullyQualified(host.Path)
                    || !Path.GetFileName(host.Path).Equals(expectedName, StringComparison.OrdinalIgnoreCase)
                    || host.Path.Contains('*') || host.Path.Contains('?')
                    || host.Kind == "local-mcp" && !ConnectionHostImageAllowed(expectedName)
                    || !Regex.IsMatch(host.Sha256, "^[a-f0-9]{64}$"))
                    throw new Boundary("policy_rejected");
                RejectLinks(host.Path);
            }
            if (!Path.IsPathFullyQualified(value.Repository) || value.SourceHashes.Count is < 3 or > 1024)
                throw new Boundary("policy_rejected");
            var bootstrap = Path.Combine(value.Directory, "flower_bootstrap.py");
            if (!value.SourceHashes.TryGetValue("@bootstrap", out var digest) || Native.Digest(bootstrap) != digest)
                throw new Boundary("bootstrap_changed");
        }
        return value;
    }
    // Pin an actual native client, never a general-purpose interpreter/shell.
    internal static bool ConnectionHostImageAllowed(string name) =>
        new[] { "Cursor.exe", "Code.exe", "Code - Insiders.exe", "opencode.exe", "Antigravity.exe", "claude.exe" }
            .Contains(name, StringComparer.OrdinalIgnoreCase);
    internal static void RejectLinks(string path)
    {
        var item = new FileInfo(path);
        for (FileSystemInfo? current = item; current is not null;
             current = current is FileInfo file ? file.Directory : ((DirectoryInfo)current).Parent)
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new Boundary("installation_link_rejected");
    }
    internal void VerifySource(string channel)
    {
        if (channel is not ("flower-web" or "flower-app" or "flower-computer")) throw new Boundary("channel_rejected");
        if (Native.Digest(Python.Path) != Python.Sha256) throw new Boundary("python_image_changed");
        foreach (var (relative, expected) in SourceHashes)
        {
            if (relative == "@bootstrap") continue;
            if (relative.Contains("..") || Path.IsPathFullyQualified(relative)) throw new Boundary("policy_rejected");
            var path = Path.GetFullPath(Path.Combine(Repository, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!path.StartsWith(Repository.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || Native.Digest(path) != expected) throw new Boundary("flower_source_changed");
        }
    }
}

internal record PeerEvidence(int Pid, long Created, int Session, string Source, string? Channel,
    bool ProductionAdmitted, int? LauncherPid, long? LauncherCreated, int? CodexPid,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? HostPid = null)
{
    [JsonIgnore] public int SourcePid => CodexPid ?? HostPid ?? throw new Boundary("host_source_missing");
}
internal record Admission(Peer Peer, PeerEvidence Evidence, bool Admin);

internal static class ClientAdmission
{
    internal static bool ImageMatches(ImageRule rule, Peer peer, string path) =>
        path.Equals(rule.Path, StringComparison.OrdinalIgnoreCase) && peer.ImageDigest == rule.Sha256;
    internal static Admission Verify(int pid, BrokerPolicy policy)
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        var (client, image) = Native.Process(pid);
        if (client.User != own.User || client.Session != own.Session || client.Integrity is not (8192 or 12288))
            throw new Boundary("client_user_session_rejected");
        if (policy.Fixture)
        {
            if (own.Integrity != 8192 || !policy.FixturePeers.Any(p => p.Pid == pid && p.Created == client.Created && p.ImageDigest == client.ImageDigest))
                throw new Boundary("fixture_peer_rejected");
            return new Admission(client, new(pid, client.Created, client.Session, "medium-isolated-fixture", null, false, null, null, null), true);
        }
        var executable = Environment.ProcessPath!;
        bool admin = image.Equals(executable, StringComparison.OrdinalIgnoreCase) && client.ImageDigest == own.ImageDigest;
        var launcherPid = admin ? pid : Native.ParentPid(pid);
        var (launcher, launcherImage) = Native.Process(launcherPid);
        if (!admin && (!ImageMatches(policy.Python, client, image)
            || !launcherImage.Equals(executable, StringComparison.OrdinalIgnoreCase)
            || launcher.ImageDigest != own.ImageDigest || launcher.Created > client.Created
            || launcher.User != own.User || launcher.Session != own.Session))
            throw new Boundary("flower_entry_rejected");
        var seen = new HashSet<int> { pid };
        var cursor = admin ? Native.ParentPid(pid) : Native.ParentPid(launcherPid);
        var childCreated = launcher.Created;
        for (var depth = 0; depth < 12 && cursor > 0 && seen.Add(cursor); ++depth)
        {
            var (ancestor, path) = Native.Process(cursor, digestImage: false);
            if (ancestor.Created > childCreated || ancestor.User != own.User || ancestor.Session != own.Session)
                throw new Boundary("codex_launch_chain_unverified");
            if (policy.CodexPackageFamilies.Contains(Native.PackageFamily(cursor), StringComparer.Ordinal)
                || Path.GetFileName(path).Equals("codex.exe", StringComparison.OrdinalIgnoreCase)
                && policy.CodexImageRoots.Any(root => path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)))
                return new Admission(client, new(pid, client.Created, client.Session, "codex-flower", null, true,
                    launcherPid, launcher.Created, cursor), admin);
            foreach (var host in policy.NativeHosts)
            {
                if (!path.Equals(host.Path, StringComparison.OrdinalIgnoreCase)) continue;
                BrokerPolicy.RejectLinks(path);
                var (pinned, pinnedPath) = Native.Process(cursor);
                if (pinned.Created != ancestor.Created || pinned.User != own.User || pinned.Session != own.Session
                    || !pinnedPath.Equals(host.Path, StringComparison.OrdinalIgnoreCase)
                    || pinned.ImageDigest != host.Sha256)
                    throw new Boundary("native_host_image_changed");
                return new Admission(client, new(pid, client.Created, client.Session, host.Kind + "-flower", null, true,
                    launcherPid, launcher.Created, null, cursor), admin);
            }
            childCreated = ancestor.Created;
            cursor = Native.ParentPid(cursor);
        }
        throw new Boundary("codex_launch_chain_unverified");
    }
    internal static int LaunchFlower(BrokerPolicy policy, string channel, bool probe = false, bool connection = false)
    {
        if (policy.Fixture) throw new Boundary("fixture_launcher_rejected");
        // No script/argv surface: this one protected bootstrap selects one fixed module.
        var admission = Verify(Environment.ProcessId, policy);
        policy.VerifySource(channel);
        var info = new ProcessStartInfo(policy.Python.Path) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = policy.Repository };
        // Display metadata only. Never use this environment field for admission.
        info.Environment["FLOWER_OPERATOR_HOST"] = admission.Evidence.Source switch
        { "claude-code-flower" => "claude-code", "antigravity-flower" => "antigravity", "local-mcp-flower" => "local-mcp", _ => "codex" };
        // Select explicitly; an absent/failed Hook must never downgrade itself.
        info.Environment["FLOWER_ORIGIN_MODE"] = connection || admission.Evidence.Source is "antigravity-flower" or "local-mcp-flower"
            ? "connection" : "hook";
        info.ArgumentList.Add("-I");
        info.ArgumentList.Add(Path.Combine(policy.Directory, "flower_bootstrap.py"));
        info.ArgumentList.Add(channel);
        if (probe) info.ArgumentList.Add("probe");
        return SuperviseMcp(info);
    }
    internal static int SuperviseMcp(ProcessStartInfo info)
    {
        // With CREATE_NO_WINDOW, .NET only sets STARTF_USESTDHANDLES when at
        // least one stream is explicitly redirected. Redirect diagnostics so
        // stdin/stdout are explicitly inherited without buffering protocol IO.
        // EOF retires this MCP; supervisor exit reclaims only its owned Python.
        info.RedirectStandardError = true;
        using var owned = new OwnedChild(info, allowDescendantBreakaway: true);
        var diagnostics = Task.Run(() => owned.Process.StandardError.BaseStream.CopyToAsync(Console.OpenStandardError()));
        owned.Process.WaitForExit();
        diagnostics.GetAwaiter().GetResult();
        return owned.Process.ExitCode;
    }
}
