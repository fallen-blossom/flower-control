using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Text;

namespace Flower.HighHelper;

// The machine record and protected manifest jointly identify an installation.
// No environment value, arbitrary JSON path or command argument selects code.
internal sealed record InstallationLocation(string Root, string ProgramRoot, string DataRoot,
    string CacheRoot, string PackagesRoot, bool Legacy, string UserSid, string InstallationId)
{
    internal const string RegistrationBase = @"SOFTWARE\FlowerControl\Installations";
    internal const string ManifestName = "installation-location.json";
    private static readonly string[] Trusted = ["S-1-5-18", "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];
    private const int Mutation = 0x500D0156;
    // A volume root cannot be deleted/renamed. Ordinary create-folder rights
    // there do not permit replacing the protected installation child.
    private const int VolumeMutation = 0x100C0040;
    private static readonly object RuntimeGate = new();
    private static InstallationLocation? runtimeLocation;

    internal static InstallationLocation Current(string? userSid = null)
    {
        var value = Volatile.Read(ref runtimeLocation);
        if (value is null) return Discover(userSid);
        if (userSid is not null && value.UserSid != userSid) throw new Boundary("installation_runtime_user_changed");
        return value;
    }

    // Called only after BrokerPolicy.Load has checked the real apphost path,
    // manifest, registration, immutable bytes and user identity. A running
    // process keeps its original root even if another installation is added.
    internal static void Bind(InstallationLocation value, string userSid, string directory, string version)
    {
        directory = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
        if (value.UserSid != userSid || !Regex.IsMatch(version, "^[a-f0-9]{16,64}$")
            || !directory.Equals(Path.Combine(value.ProgramRoot, "versions", version), StringComparison.OrdinalIgnoreCase)
            || !directory.Equals(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("installation_runtime_binding_rejected");
        lock (RuntimeGate)
        {
            if (runtimeLocation is not null && runtimeLocation != value) throw new Boundary("installation_running_root_changed");
            runtimeLocation ??= value;
        }
    }

    internal static InstallationLocation Prepare(string root, string userSid = "")
    {
        root = LocalPath(root);
        if (userSid.Length > 0 && !ValidSid(userSid)) throw new Boundary("installation_user_rejected");
        return new(root, Path.Combine(root, "Program"), Path.Combine(root, "Data"),
            Path.Combine(root, "Cache"), Path.Combine(root, "Packages"), false, userSid, "");
    }

    internal static InstallationLocation Discover(string? userSid = null)
    {
        string sid = userSid ?? WindowsIdentity.GetCurrent().User!.Value;
        // Frozen legacy SYSTEM roles retain their old root. A registered
        // SYSTEM companion must match its own protected Program manifest and
        // that user's HKLM record; a caller cannot supply another root.
        if (sid == "S-1-5-18")
        {
            string? program = Directory.GetParent(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))?.Parent?.FullName;
            string? manifestPath = program is null ? null : Path.Combine(program, ManifestName);
            if (manifestPath is not null && File.Exists(manifestPath))
            {
                RequireProtectedPath(manifestPath);
                using var ownManifest = Parse(File.ReadAllBytes(manifestPath));
                sid = Text(ownManifest.RootElement, "user_sid");
            }
            else return LegacyLocation(sid);
        }
        if (!ValidSid(sid)) throw new Boundary("installation_user_rejected");
        string? recordText = ReadRegistration(sid);
        if (recordText is null) return RequireRunningRoot(LegacyLocation(sid));
        try
        {
            using var recordDocument = Parse(System.Text.Encoding.UTF8.GetBytes(recordText));
            var record = recordDocument.RootElement;
            RequireFields(record, ["schema", "installation_id", "user_sid", "root", "manifest_sha256"]);
            string id = Text(record, "installation_id"), digest = Text(record, "manifest_sha256");
            if (record.GetProperty("schema").GetInt32() != 1 || Text(record, "user_sid") != sid
                || !Regex.IsMatch(id, "^[a-f0-9]{32}$") || !Regex.IsMatch(digest, "^[a-f0-9]{64}$"))
                throw new Boundary("installation_registration_rejected");
            var location = Prepare(Text(record, "root"), sid);
            string path = Path.Combine(location.ProgramRoot, ManifestName);
            RequireProtectedPath(path);
            if (new FileInfo(path).Length > 131072) throw new Boundary("installation_manifest_rejected");
            var raw = File.ReadAllBytes(path);
            if (Convert.ToHexStringLower(SHA256.HashData(raw)) != digest) throw new Boundary("installation_manifest_changed");
            using var manifestDocument = Parse(raw);
            var manifest = manifestDocument.RootElement;
            RequireFields(manifest, ["schema", "installation_id", "user_sid", "root", "program_root",
                "data_root", "cache_root", "packages_root", "host_bindings"]);
            var bindings = manifest.GetProperty("host_bindings");
            if (manifest.GetProperty("schema").GetInt32() != 1 || Text(manifest, "installation_id") != id
                || Text(manifest, "user_sid") != sid || bindings.ValueKind != JsonValueKind.Array
                || bindings.GetArrayLength() > 32 || bindings.EnumerateArray().Any(row => row.ValueKind != JsonValueKind.Object))
                throw new Boundary("installation_manifest_rejected");
            foreach (var (field, expected) in new[] { ("root", location.Root), ("program_root", location.ProgramRoot),
                ("data_root", location.DataRoot), ("cache_root", location.CacheRoot), ("packages_root", location.PackagesRoot) })
                if (!LocalPath(Text(manifest, field)).Equals(expected, StringComparison.OrdinalIgnoreCase))
                    throw new Boundary("installation_layout_mismatch");
            return RequireRunningRoot(location with { InstallationId = id });
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw new Boundary("installation_schema_rejected"); }
    }

    private static InstallationLocation RequireRunningRoot(InstallationLocation value)
    {
        var own = new DirectoryInfo(AppContext.BaseDirectory);
        if (own.Parent?.Name.Equals("versions", StringComparison.OrdinalIgnoreCase) == true
            && string.Equals(Path.GetFileName(Environment.ProcessPath), "Flower.HighHelper.exe", StringComparison.OrdinalIgnoreCase)
            && !own.Parent.Parent!.FullName.Equals(value.ProgramRoot, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("installation_running_root_changed");
        return value;
    }

    private static InstallationLocation LegacyLocation(string sid)
    {
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl");
        string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FlowerControl");
        return new(root, Path.Combine(root, "HighHelper"), data, Path.Combine(data, "cache"), Path.Combine(root, "Packages"), true, sid, "");
    }

    private static string? ReadRegistration(string sid)
    {
        string path = RegistrationBase + "\\" + sid;
        string[] parts = path.Split('\\');
        for (int index = 1; index <= parts.Length; index++)
        {
            int result = RegOpenKeyExW(new IntPtr(unchecked((int)0x80000002)), string.Join('\\', parts.Take(index)), 8, 0x20119, out var handle);
            if (result is 2 or 3) { handle.Dispose(); return null; }
            if (result != 0) { handle.Dispose(); throw new Boundary("installation_registration_unavailable"); }
            using var parent = RegistryKey.FromHandle(handle, RegistryView.Registry64);
            var security = parent.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            RequireOwnerAndDacl(security);
            foreach (RegistryAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0
                    && ((int)rule.RegistryRights & 0x500D0026) != 0 && !Trusted.Contains(rule.IdentityReference.Value)
                    && rule.IdentityReference.Value != "S-1-3-0")
                    throw new Boundary("installation_unprotected");
            if (parent.GetValueNames().Contains("SymbolicLinkValue", StringComparer.OrdinalIgnoreCase))
                throw new Boundary("installation_registry_link_rejected");
            if (index == parts.Length)
            {
                if (parent.GetValueKind("Record") != RegistryValueKind.String
                    || parent.GetValue("Record", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string text
                    || text.Length > 32768) throw new Boundary("installation_registration_rejected");
                return text;
            }
        }
        throw new Boundary("installation_registration_rejected");
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyExW(IntPtr key, string subkey, uint options, uint access, out SafeRegistryHandle result);

    internal static void RequireProtectedPath(string path)
    {
        path = LocalPath(path);
        var chain = new List<string> { path };
        for (string? current = Path.GetDirectoryName(path); current is not null; current = Path.GetDirectoryName(current)) chain.Add(current);
        var held = new List<SafeFileHandle>();
        try
        {
        foreach (string current in chain.AsEnumerable().Reverse())
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new Boundary("installation_link_rejected");
            var handle = CreateFileW(current, 0x20000, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new Boundary("installation_path_identity_unavailable"); }
            held.Add(handle);
            var final = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
            string actual = final.ToString();
            if (length == 0 || length >= final.Capacity || !actual.StartsWith(@"\\?\", StringComparison.Ordinal)
                || !actual[4..].TrimEnd('\\').Equals(current.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new Boundary("installation_path_identity_changed");
            bool directory = Directory.Exists(current);
            FileSystemSecurity security = directory
                ? new DirectoryInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
                : new FileInfo(current).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            RequireOwnerAndDacl(security);
            int mutation = Path.GetPathRoot(current)!.Equals(current, StringComparison.OrdinalIgnoreCase) ? VolumeMutation : Mutation;
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && (rule.PropagationFlags & PropagationFlags.InheritOnly) == 0
                    && ((int)rule.FileSystemRights & mutation) != 0 && !Trusted.Contains(rule.IdentityReference.Value)
                    && rule.IdentityReference.Value != "S-1-3-0")
                    throw new Boundary("installation_unprotected");
        }
        }
        finally { foreach (var handle in held) handle.Dispose(); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);

    private static void RequireOwnerAndDacl(ObjectSecurity security)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !Trusted.Contains(owner.Value)
            || new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0).DiscretionaryAcl is null)
            throw new Boundary("installation_unprotected");
    }

    private static bool ValidSid(string sid) => Regex.IsMatch(sid, "^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$");
    private static string LocalPath(string text)
    {
        if (!Path.IsPathFullyQualified(text) || text.StartsWith(@"\\", StringComparison.Ordinal)
            || text.IndexOfAny(['*', '?', '\0']) >= 0 || text.Length < 4 || text[2..].Contains(':')
            || text.Replace('\\', '/').Split('/').Skip(1).Any(p => p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.')))
            throw new Boundary("installation_path_rejected");
        string path = Path.GetFullPath(text).TrimEnd(Path.DirectorySeparatorChar);
        if (path.Length < 4) throw new Boundary("installation_path_rejected");
        return path;
    }
    private static string Text(JsonElement element, string name) => element.GetProperty(name).GetString()
        ?? throw new Boundary("installation_schema_rejected");
    private static void RequireFields(JsonElement element, string[] names)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(names))
            throw new Boundary("installation_schema_rejected");
    }
    private static JsonDocument Parse(byte[] raw)
    {
        var document = JsonDocument.Parse(raw);
        try { Unique(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }
    private static void Unique(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new Boundary("installation_schema_rejected");
                Unique(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var row in element.EnumerateArray()) Unique(row);
    }
}
