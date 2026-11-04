using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// Codex is identified by its live official Authenticode signature, not by a
// versioned cache directory or an installer-specific path. It also binds the
// queried process path/creation time and a stable read-only file handle to the
// signature. ClientAdmission retains the user/session/process-chain checks.
internal static class CodexHostIdentity
{
    private const string OfficialPublisher = "OpenAI OpCo, LLC";
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 1;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeWholeChain = 1;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;
    private const uint WtdRevocationCheckChainExcludeRoot = 0x80;
    private const uint WtdDisableMd2Md4 = 0x2000;
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        internal uint Size;
        internal IntPtr FilePath;
        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        internal uint Size;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr File;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
        internal IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        internal uint FileAttributes;
        internal long CreationTime;
        internal long LastAccessTime;
        internal long LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProviderCertificate
    {
        internal uint Size;
        internal IntPtr Certificate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertificateContext
    {
        internal uint Encoding;
        internal IntPtr Encoded;
        internal uint EncodedSize;
        internal IntPtr Information;
        internal IntPtr Store;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WinTrustData data);
    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signer, bool counterSigner, uint counterIndex);
    [DllImport("wintrust.dll")]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certificate);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation information);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited,
        out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string root);

    internal static bool IsOfficialCodexImage(string path, int processId = 0, long? created = null)
        => IsPublisherImage(path, "codex.exe", OfficialPublisher, processId, created);

    // Publisher identity survives normal certificate renewal. This verifies
    // identity only; it neither registers a message nor grants work authority.
    internal static bool IsPublisherImage(string path, string executableName, string publisher,
        int processId = 0, long? created = null)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)
            || !Path.GetFileName(path).Equals(executableName, StringComparison.OrdinalIgnoreCase)
            || path.Any(char.IsControl) || path.Contains('*') || path.Contains('?')) return false;
        var root = Path.GetPathRoot(path);
        if (string.IsNullOrEmpty(root) || root.StartsWith("\\\\", StringComparison.Ordinal)
            || GetDriveTypeW(root) != 3) return false;
        try
        {
            BrokerPolicy.RejectLinks(path);
            var fullPath = Path.GetFullPath(path);
            if (processId > 0 && !ProcessMatches(processId, created, fullPath)) return false;
            using var file = CreateFileW(fullPath, GenericRead, FileShareRead, IntPtr.Zero, OpenExisting,
                FileFlagOpenReparsePoint, IntPtr.Zero);
            if (file.IsInvalid || !GetFileInformationByHandle(file, out var information)
                || (information.FileAttributes & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0
                || information.FileSizeLow == 0 && information.FileSizeHigh == 0
                || !FinalPath(fullPath, file, out var finalPath)
                || !AuthenticatedPublisherKey(fullPath, file, publisher, out _)) return false;
            return processId <= 0 || ProcessMatches(processId, created, fullPath);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
            or NotSupportedException or Win32Exception or BadImageFormatException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool ProcessMatches(int pid, long? expectedCreated, string expectedPath)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process.IsInvalid || !GetProcessTimes(process, out var created, out var exited, out _, out _)
            || exited != 0 || expectedCreated is { } expected && created != expected) return false;
        var image = new StringBuilder(32768);
        uint size = (uint)image.Capacity;
        return QueryFullProcessImageNameW(process, 0, image, ref size)
            && Path.GetFullPath(image.ToString()).Equals(expectedPath, StringComparison.OrdinalIgnoreCase);
    }

    private static bool FinalPath(string expected, SafeFileHandle file, out string path)
    {
        var buffer = new StringBuilder(32768);
        uint size = GetFinalPathNameByHandleW(file, buffer, (uint)buffer.Capacity, 0);
        path = "";
        if (size == 0 || size >= buffer.Capacity) return false;
        var value = buffer.ToString();
        if (value.StartsWith("\\\\?\\", StringComparison.Ordinal)) value = value[4..];
        else if (value.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase)) return false;
        path = Path.GetFullPath(value);
        return path.Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase);
    }

    private static bool AuthenticatedSignerKey(string path, SafeFileHandle file, out string key)
        => AuthenticatedPublisherKey(path, file, OfficialPublisher, out key);

    private static bool AuthenticatedPublisherKey(string path, SafeFileHandle file, string publisher, out string key)
    {
        key = "";
        var filePath = Marshal.StringToCoTaskMemUni(path);
        var winTrustFile = new WinTrustFileInfo {
            Size = (uint)Marshal.SizeOf<WinTrustFileInfo>(), FilePath = filePath,
            FileHandle = file.DangerousGetHandle(), KnownSubject = IntPtr.Zero
        };
        var filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(winTrustFile, filePointer, false);
            var data = new WinTrustData {
                Size = (uint)Marshal.SizeOf<WinTrustData>(), UiChoice = WtdUiNone, RevocationChecks = WtdRevokeWholeChain,
                UnionChoice = WtdChoiceFile, File = filePointer, StateAction = WtdStateActionVerify,
                ProviderFlags = WtdCacheOnlyUrlRetrieval | WtdRevocationCheckChainExcludeRoot | WtdDisableMd2Md4
            };
            var action = GenericVerifyV2;
            var result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            try
            {
                if (result != 0 || data.StateData == IntPtr.Zero) return false;
                var provider = WTHelperProvDataFromStateData(data.StateData);
                var signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
                var certificate = WTHelperGetProvCertFromChain(signer, 0);
                if (certificate == IntPtr.Zero) return false;
                var providerCertificate = Marshal.PtrToStructure<ProviderCertificate>(certificate);
                if (providerCertificate.Certificate == IntPtr.Zero) return false;
                var context = Marshal.PtrToStructure<CertificateContext>(providerCertificate.Certificate);
                if (context.Encoded == IntPtr.Zero || context.EncodedSize is 0 or > 1024 * 1024) return false;
                var encoded = new byte[checked((int)context.EncodedSize)];
                Marshal.Copy(context.Encoded, encoded, 0, encoded.Length);
                using var signerCertificate = X509CertificateLoader.LoadCertificate(encoded);
                if (!signerCertificate.GetNameInfo(X509NameType.SimpleName, false).Equals(publisher, StringComparison.Ordinal))
                    return false;
                key = Convert.ToHexString(SHA256.HashData(signerCertificate.GetPublicKey())).ToLowerInvariant();
                return true;
            }
            finally
            {
                data.StateAction = WtdStateActionClose;
                _ = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(filePointer);
            Marshal.FreeCoTaskMem(filePath);
        }
    }
}
