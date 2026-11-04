using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

// Called only by explicit local editor Save. No credential is ever read back,
// sent as argv, logged, or used to enable a service.
internal static class DecisionCredential
{
    internal static string Target(string provider, CustomDecisionProvider? custom = null) => provider switch
    {
        "jev" => "FlowerControl/JevApiKey/v1", "perplexity" => "FlowerControl/PerplexityApiKey/v1",
        _ when custom is not null && custom.Id == provider => "FlowerControl/Decision/" + provider + "/"
            + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(custom.Protocol + "\n" + custom.Endpoint))).ToLowerInvariant(),
        _ => throw new Boundary("unknown_decision_provider")
    };
    internal static void Store(string settingsPath, string provider, CustomDecisionProvider? custom, string key)
    {
        if (key.Length == 0 || key != key.Trim() || key.Any(char.IsControl) || Encoding.Unicode.GetByteCount(key) > 2560)
            throw new Boundary("invalid_decision_key");
        if (custom is not null) DecisionProviderSettings.ValidateProvider(custom);
        string target = Target(provider, custom), directory = Path.GetDirectoryName(settingsPath)!;
        string marker = Path.Combine(directory, "decision-credential-revision.json");
        BrowserPreferences.RejectOptionalPath(marker);
        Directory.CreateDirectory(directory); BrowserPreferences.RejectOptionalPath(marker);
        using var gate = new Mutex(false, DecisionProviderSettings.MutexName(settingsPath));
        bool held; try { held = gate.WaitOne(0); } catch (AbandonedMutexException) { held = true; }
        if (!held) throw new Boundary("decision_settings_busy");
        string revision = Guid.NewGuid().ToString("N"), temporary = marker + "." + revision + ".tmp";
        byte[] bytes = Encoding.Unicode.GetBytes(key); IntPtr blob = IntPtr.Zero;
        try
        {
            void Publish(string state)
            {
                BrowserPreferences.RejectOptionalPath(marker);
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { stream.Write(JsonSerializer.SerializeToUtf8Bytes(new { schema = 1, revision, state })); stream.Flush(true); }
                File.Move(temporary, marker, true);
            }
            Publish("updating");
            blob = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, blob, bytes.Length);
            var credential = new Credential { Type = 1, TargetName = target, BlobSize = (uint)bytes.Length,
                Blob = blob, Persist = 2, UserName = "FlowerControl" };
            if (!CredWriteW(ref credential, 0)) throw new Boundary("decision_key_save_unconfirmed");
            Publish("ready");
        }
        finally
        {
            if (blob != IntPtr.Zero) { Marshal.Copy(new byte[bytes.Length], 0, blob, bytes.Length); Marshal.FreeHGlobal(blob); }
            CryptographicOperations.ZeroMemory(bytes);
            try { if (File.Exists(temporary)) File.Delete(temporary); } finally { gate.ReleaseMutex(); }
        }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags, Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint BlobSize;
        public IntPtr Blob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes, TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWriteW(ref Credential credential, uint flags);
}
