using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record CustomDecisionProvider(string Id, string Name, string Protocol, string Endpoint, string Model, string PrivacyUrl = "");

// Provider preferences only. Keys stay in Windows Credential Manager, and the
// protected JevEnabled permission remains the independent external-API master.
internal sealed record DecisionProviderPreferences(string[] Order, string[] Enabled,
    string PerplexityModel = "pplx-decider-v1.2", string JevModel = "jev-1.14.0", CustomDecisionProvider[]? Custom = null)
{
    internal CustomDecisionProvider[] Providers => Custom ?? [];
    internal DecisionProviderPreferences Copy() => this with { Order = [.. Order], Enabled = [.. Enabled], Custom = [.. Providers] };
    internal bool Same(DecisionProviderPreferences other) => Order.SequenceEqual(other.Order)
        && Enabled.ToHashSet(StringComparer.Ordinal).SetEquals(other.Enabled)
        && PerplexityModel == other.PerplexityModel && JevModel == other.JevModel && Providers.SequenceEqual(other.Providers);
    internal string[] ActiveOrder() => Order.TakeWhile(x => x != "host").Where(Enabled.Contains).ToArray();
    internal DecisionProviderPreferences Move(int index, int delta)
    {
        int destination = index + delta;
        if (index < 0 || index >= Order.Length || destination < 0 || destination >= Order.Length) return Copy();
        var result = (string[])Order.Clone(); (result[index], result[destination]) = (result[destination], result[index]);
        return this with { Order = result };
    }
    internal DecisionProviderPreferences Enable(string provider, bool enabled)
    {
        if (provider is not ("perplexity" or "jev") && !Providers.Any(p => p.Id == provider)) throw new Boundary("invalid_decision_settings");
        return this with { Enabled = Order.Where(x => x != "host" && (x == provider ? enabled : Enabled.Contains(x))).ToArray() };
    }
}

internal sealed record DecisionProviderSnapshot(DecisionProviderPreferences? Value, string? Revision = null,
    string? Error = null, bool Legacy = false);

internal static class DecisionProviderSettings
{
    internal const string FileName = "decision-providers.json";
    internal static DecisionProviderPreferences Legacy(bool jevEnabled = false)
        => new(["jev", "host", "perplexity"], jevEnabled ? ["jev"] : []);

    internal static string LivePath()
    {
        // Use the same pinned physical DataRoot as the installed Python hosts.
        // An absent installation must not silently create an alternate ledger.
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        if (policy.DataRoot.Length == 0) throw new Boundary("decision_settings_data_root_unavailable");
        return LocalPath(Path.Combine(policy.DataRoot, "state-v1", FileName));
    }

    internal static string MutexName(string path) => "Local\\FlowerControl.DecisionProviders."
        + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(LocalPath(path).Replace('\\', '/').ToLowerInvariant()))).ToLowerInvariant();

    private static string LocalPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
            throw new Boundary("decision_settings_local_path_required");
        return Path.GetFullPath(path);
    }
    private static void RejectLinks(string path)
    {
        for (FileSystemInfo? item = new FileInfo(LocalPath(path)); item is not null;
            item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
        {
            try { if ((File.GetAttributes(item.FullName) & FileAttributes.ReparsePoint) != 0) throw new Boundary("decision_settings_link_rejected"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }
    private static byte[]? Raw(string path)
    {
        RejectLinks(path);
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length > 65536) throw new Boundary("invalid_decision_settings");
            var bytes = new byte[stream.Length]; stream.ReadExactly(bytes); return bytes;
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }
    private static string? Revision(byte[]? bytes) => bytes is null ? null : Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static bool Exact(JsonElement value, params string[] names) => value.ValueKind == JsonValueKind.Object
        && value.EnumerateObject().Count() == names.Length
        && value.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(names);
    private static string[] Strings(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.String))
            throw new Boundary("invalid_decision_settings");
        return value.EnumerateArray().Select(x => x.GetString()!).ToArray();
    }
    internal static DecisionProviderPreferences Parse(byte[] bytes)
    {
        using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document);
        var value = document.RootElement;
        if (!value.TryGetProperty("schema", out var version) || !version.TryGetInt32(out int schema) || schema is not (1 or 2)
            || !Exact(value, schema == 1 ? ["schema", "order", "enabled", "models"] : ["schema", "order", "enabled", "models", "custom"]))
            throw new Boundary("invalid_decision_settings");
        List<CustomDecisionProvider> custom = [];
        if (schema == 2)
        {
            var entries = value.GetProperty("custom");
            if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() > 16) throw new Boundary("invalid_decision_provider");
            foreach (var entry in entries.EnumerateArray())
            {
                if (!Exact(entry, "id", "name", "protocol", "endpoint", "model", "privacy_url")
                    || entry.EnumerateObject().Any(p => p.Value.ValueKind != JsonValueKind.String)) throw new Boundary("invalid_decision_provider");
                string S(string key) => entry.GetProperty(key).GetString()!;
                var provider = new CustomDecisionProvider(S("id"), S("name"), S("protocol"), S("endpoint"), S("model"), S("privacy_url"));
                ValidateProvider(provider); custom.Add(provider);
            }
            if (custom.Select(p => p.Id).Distinct().Count() != custom.Count) throw new Boundary("invalid_decision_provider");
        }
        var order = Strings(value.GetProperty("order")); var enabled = Strings(value.GetProperty("enabled"));
        var models = value.GetProperty("models");
        var providers = new[] { "perplexity", "jev" }.Concat(custom.Select(p => p.Id)).ToHashSet(StringComparer.Ordinal);
        if (order.Length != providers.Count + 1 || !order.ToHashSet(StringComparer.Ordinal).SetEquals(providers.Append("host"))
            || enabled.Length != enabled.Distinct(StringComparer.Ordinal).Count() || enabled.Any(x => !providers.Contains(x))
            || !Exact(models, "perplexity", "jev") || models.GetProperty("perplexity").ValueKind != JsonValueKind.String
            || models.GetProperty("jev").ValueKind != JsonValueKind.String)
            throw new Boundary("invalid_decision_settings");
        string perplexity = models.GetProperty("perplexity").GetString()!, jev = models.GetProperty("jev").GetString()!;
        if (perplexity is not ("pplx-decider-v1.2" or "pplx-decider-flash-v1.2") || jev is not ("jev-1.13.0" or "jev-1.14.0"))
            throw new Boundary("invalid_decision_settings");
        return new(order, enabled, perplexity, jev, custom.ToArray());
    }

    internal static void ValidateProvider(CustomDecisionProvider provider)
    {
        if (provider.Id.Any(char.IsControl) || provider.Model.Any(char.IsControl) || !System.Text.RegularExpressions.Regex.IsMatch(provider.Id, "^custom_[a-f0-9]{32}$")
            || provider.Name.Trim().Length is < 1 or > 64 || provider.Name.Any(char.IsControl)
            || provider.Protocol is not ("openai_chat" or "decisions")
            || !System.Text.RegularExpressions.Regex.IsMatch(provider.Model, "^[A-Za-z0-9][A-Za-z0-9_./:@+\\-]{0,127}$")) throw new Boundary("invalid_decision_provider");
        ValidateUrl(provider.Endpoint); if (provider.PrivacyUrl != "") ValidateUrl(provider.PrivacyUrl);
    }
    internal static void ValidateUrl(string value)
    {
        if (value.Length > 1024 || value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) || value.Contains('\\')
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host.Length == 0
            || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "" || !uri.IsDefaultPort) throw new Boundary("invalid_decision_service_url");
    }
    internal static byte[] Serialize(DecisionProviderPreferences value)
    {
        var payload = new Dictionary<string, object> { ["schema"] = value.Providers.Length == 0 ? 1 : 2,
            ["order"] = value.Order, ["enabled"] = value.Enabled,
            ["models"] = new { perplexity = value.PerplexityModel, jev = value.JevModel } };
        if (value.Providers.Length > 0) payload["custom"] = value.Providers.Select(p => new { id = p.Id, name = p.Name,
            protocol = p.Protocol, endpoint = p.Endpoint, model = p.Model, privacy_url = p.PrivacyUrl }).ToArray();
        return JsonSerializer.SerializeToUtf8Bytes(payload);
    }
    private static bool LegacyEnabled(string path)
    {
        try
        {
            var bytes = Raw(Path.Combine(Path.GetDirectoryName(path)!, "jev.json")); if (bytes is null) return false;
            using var document = JsonDocument.Parse(bytes); Protocol.CheckUnique(document); var value = document.RootElement;
            return Exact(value, "schema", "enabled") && value.GetProperty("schema").TryGetInt32(out int version) && version == 1
                && value.GetProperty("enabled").ValueKind == JsonValueKind.True;
        }
        catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or JsonException or InvalidOperationException) { return false; }
    }
    internal static DecisionProviderSnapshot Read(string path)
    {
        byte[]? bytes = null;
        try
        {
            bytes = Raw(path);
            return bytes is null ? new(Legacy(LegacyEnabled(path)), Legacy: true) : new(Parse(bytes), Revision(bytes));
        }
        catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
        {
            string code = error is Boundary boundary ? boundary.Code : error is JsonException or InvalidOperationException
                ? "invalid_decision_settings" : "decision_settings_unreadable";
            return new(null, Revision(bytes), code);
        }
    }
    internal static DecisionProviderSnapshot Save(string path, string? expectedRevision, DecisionProviderPreferences value,
        CancellationToken cancellation = default, Action? beforeReplace = null)
    {
        path = LocalPath(path);
        var bytes = Serialize(value);
        _ = Parse(bytes);
        cancellation.ThrowIfCancellationRequested(); RejectLinks(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!); RejectLinks(path);
        using var gate = new Mutex(false, MutexName(path)); bool held;
        try { held = gate.WaitOne(5000); } catch (AbandonedMutexException) { held = true; }
        if (!held) throw new Boundary("decision_settings_busy");
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp"; bool committed = false;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            var before = Read(path);
            if (before.Revision != expectedRevision) throw new Boundary("decision_settings_conflict");
            if (before.Error is not null) throw new Boundary(before.Error);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            { stream.Write(bytes); stream.Flush(true); }
            beforeReplace?.Invoke(); cancellation.ThrowIfCancellationRequested(); RejectLinks(path);
            if (Revision(Raw(path)) != expectedRevision) throw new Boundary("decision_settings_conflict");
            File.Move(temporary, path, true); committed = true;
            return new(value.Copy(), Revision(bytes));
        }
        catch (Exception error) when (committed)
        { throw new Boundary("decision_settings_save_outcome_unknown") { Data = { ["OriginalError"] = error } }; }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); } finally { gate.ReleaseMutex(); }
        }
    }
}
