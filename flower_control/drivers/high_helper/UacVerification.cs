using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed record UacVerificationBinding(string Version, string NativeSha256, string HelperSha256,
    string ManagedHelperSha256, string ConsentSha256, string WindowsBuild, string UserSid, int Session);

// Fixed local evidence registration. This never changes settings, clears Stop,
// starts a process, accepts a supplied path, or treats an offline assertion as
// real input evidence. The source test and worker receipts remain immutable.
internal static class UacVerification
{
    private sealed record Index(int Schema, string Command, string TestNonce, string WorkerNonce,
        string TestSha256, string WorkerSha256, UacVerificationBinding Binding);
    internal static UacVerificationBinding Binding(BrokerPolicy policy, int session) => new(policy.Version,
        Native.Digest(Path.Combine(policy.Directory, "Flower.UacNative.dll")),
        Native.Digest(Path.Combine(policy.Directory, "Flower.HighHelper.exe")),
        Native.Digest(Path.Combine(policy.Directory, "Flower.HighHelper.dll")),
        Native.Digest(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "consent.exe")),
        UacRuntime.WindowsBuild(), policy.UserSid, session);
    internal static UacVerificationBinding? ReceiptBinding(BrokerPolicy policy, int session)
    { try { return Binding(policy, session); } catch { return null; } }
    private static (BrokerPolicy Policy, Peer Own) Context()
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        if (own.Integrity != 12288 || own.User == "S-1-5-18" || Native.UiAccess(own.Pid))
            throw new Boundary("uac_verification_local_high_required");
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        if (policy.Fixture || own.User != policy.UserSid || own.Session <= 0
            || own.ImageDigest != Native.Digest(Path.Combine(policy.Directory, "Flower.HighHelper.exe")))
            throw new Boundary("uac_verification_context_rejected");
        _ = new UacClaimJournal(policy, own.Session); // Enforce the sealed installed version location and role.
        UserPermissions.CheckProtectionForDirectory(policy.Directory);
        return (policy, own);
    }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static bool Nonce(string? value) => value is not null && Regex.IsMatch(value, "\\A[a-f0-9]{32}\\z");
    private static byte[] Read(string path)
    {
        BrokerPolicy.RejectLinks(path); UserPermissions.CheckProtection(path);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 131072) throw new Boundary("uac_verification_evidence_size");
        var raw = new byte[checked((int)file.Length)]; file.ReadExactly(raw); return raw;
    }
    private static JsonDocument Parse(byte[] bytes)
    { var document = JsonDocument.Parse(bytes); try { Protocol.CheckUnique(document); return document; } catch { document.Dispose(); throw; } }
    private static string ReceiptPath(BrokerPolicy policy, int session, string category, string nonce)
    {
        if (category is not ("tests" or "workers") || !Nonce(nonce)) throw new Boundary("uac_verification_receipt_rejected");
        string key = Hash(Encoding.UTF8.GetBytes(policy.UserSid + "|" + session.ToString(CultureInfo.InvariantCulture)));
        string directory = Path.GetFullPath(Path.Combine(policy.Directory, "..", "..", "recovery", "uac", key + "." + category));
        BrokerPolicy.RejectLinks(directory); UserPermissions.CheckProtectionForDirectory(directory);
        return Path.Combine(directory, nonce + ".json");
    }
    private static string IndexPath(BrokerPolicy policy, int session, string command)
    {
        if (command is not ("cancel" or "accept" or "stop")) throw new Boundary("uac_verification_action_rejected");
        return Path.Combine(UacStateStorage.Directory(policy, true), "uac-verification-evidence." + session.ToString(CultureInfo.InvariantCulture) + "." + command + ".json");
    }
    // FileInfo.Attributes is -1 for a missing leaf (and thus appears to have
    // ReparsePoint set). Missing is permitted only at this exact new leaf;
    // all parents must already exist and pass the normal link checks.
    internal static bool ExistingWriteTarget(string directory, string path)
    {
        if (!Path.GetFullPath(Path.GetDirectoryName(path)!).Equals(Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_verification_destination_rejected");
        BrokerPolicy.RejectLinks(directory);
        FileAttributes attributes;
        try { attributes = File.GetAttributes(path); }
        catch (FileNotFoundException) { return false; }
        if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
            throw new Boundary("installation_link_rejected");
        BrokerPolicy.RejectLinks(path); return true;
    }
    internal static void CommitPrepared(string directory, string temporary, string path, bool existed)
    {
        if (!ExistingWriteTarget(directory, temporary) || ExistingWriteTarget(directory, path) != existed)
            throw new Boundary("uac_verification_destination_changed");
        if (existed) File.Replace(temporary, path, path + "." + Guid.NewGuid().ToString("N") + ".previous");
        else File.Move(temporary, path); // No overwrite if a destination appeared.
    }
    private static void Write(BrokerPolicy policy, string path, object value)
    {
        var directory = UacStateStorage.Directory(policy, true);
        UserPermissions.CheckProtectionForDirectory(directory);
        bool existed = ExistingWriteTarget(directory, path);
        if (existed) UserPermissions.CheckProtection(path);
        var temporary = Path.Combine(directory, "uac-verification." + Guid.NewGuid().ToString("N") + ".tmp");
        SecurityLabel.Write(temporary, JsonSerializer.SerializeToUtf8Bytes(value), policy.UserSid);
        UserPermissions.CheckProtection(temporary);
        UserPermissions.CheckProtectionForDirectory(directory);
        if (existed) UserPermissions.CheckProtection(path);
        CommitPrepared(directory, temporary, path, existed);
        UserPermissions.CheckProtection(path);
    }
    internal static bool StopConsistent(object? receipt, UacTestResult? business)
    {
        if (receipt is null || business is null || business.Status != "business_cancelled" || business.Win32Error != 1223
            || business.Target is not null) return false;
        using var document = JsonSerializer.SerializeToDocument(receipt); var report = document.RootElement;
        if (!UacOutcomeEvidence.True(report, "PhysicalStopObserved") || !UacOutcomeEvidence.True(report, "WorkerNoNativeDispatch")
            || UacOutcomeEvidence.Text(report, "Action") != "none" || !UacOutcomeEvidence.CleanupComplete(report)
            || !report.TryGetProperty("PromptBefore", out var prompt) || UacOutcomeEvidence.Text(prompt, "desktop") != "Winlogon"
            || !report.TryGetProperty("StopState", out var state) || !UacOutcomeEvidence.True(state, "Stopped")
            || state.GetProperty("Epoch").GetInt64() <= report.GetProperty("InitialStopEpoch").GetInt64()
            || !report.TryGetProperty("NativeResult", out var native) || !UacOutcomeEvidence.False(native, "input_dispatched")
            || !report.TryGetProperty("StopMonitorEnd", out var monitor)) return false;
        // Signal success is emitted only on an actual hotkey or physical key
        // polling branch, not when somebody merely sets the event externally.
        return UacOutcomeEvidence.True(monitor, "secure_stop_signal_succeeded")
            && UacOutcomeEvidence.True(monitor, "secure_stop_cancel_signal_succeeded")
            && (UacOutcomeEvidence.True(monitor, "secure_stop_hotkey_received")
                || UacOutcomeEvidence.True(monitor, "secure_stop_key_polling"));
    }
    internal static bool Matches(string command, JsonElement test, JsonElement worker, UacVerificationBinding current)
    {
        try
        {
            var binding = worker.GetProperty("VerificationBinding").Deserialize<UacVerificationBinding>();
            var nonce = UacOutcomeEvidence.Text(test, "Nonce");
            if (binding != current || test.GetProperty("Schema").GetInt32() != 1
                || UacOutcomeEvidence.Text(test, "Phase") != "uac_test" || UacOutcomeEvidence.Text(worker, "Phase") != "uac"
                || !UacOutcomeEvidence.False(test, "InputReplay") || !UacOutcomeEvidence.False(worker, "InputReplay")
                || UacOutcomeEvidence.Text(worker, "ManagedHelperSha256") != current.ManagedHelperSha256
                || UacOutcomeEvidence.Text(worker, "BusinessResult") != "unverified" || !Nonce(nonce) || !Nonce(UacOutcomeEvidence.Text(worker, "RequestNonce"))
                || !UacOutcomeEvidence.True(worker, "ControlledExperiment") || UacOutcomeEvidence.Text(worker, "TestCommand") != command
                || UacOutcomeEvidence.Text(worker, "TestNonce") != nonce
                || UacOutcomeEvidence.Text(worker, "TaskId") != "uac_test_" + command + "_" + nonce
                || UacOutcomeEvidence.Text(worker, "Version") != current.Version
                || UacOutcomeEvidence.Text(test, "ControllerError") is not null) return false;
            var executor = worker.GetProperty("Worker").Deserialize<Peer>();
            var source = worker.GetProperty("Source").Deserialize<Peer>();
            if (executor is null || source is null || executor.Pid <= 0 || executor.Created <= 0 || source.Pid <= 0 || source.Created <= 0 || executor.User != "S-1-5-18" || executor.Integrity != 16384
                || executor.Session != current.Session || executor.ImageDigest != current.HelperSha256
                || source.User != current.UserSid || source.Session != current.Session || source.Integrity != 12288
                || source.ImageDigest != current.HelperSha256) return false;
            var receipt = test.GetProperty("Receipt");
            foreach (var field in worker.EnumerateObject())
            {
                // High replaces only the SYSTEM placeholder with the oracle's
                // result. All other original executor fields must remain exact.
                if (field.Name == "BusinessResult") continue;
                if (!receipt.TryGetProperty(field.Name, out var copied) || !JsonElement.DeepEquals(field.Value, copied)) return false;
            }
            if (UacOutcomeEvidence.Text(receipt, "WorkerEvidenceSaveError") is not null
                || !UacOutcomeEvidence.True(receipt, "InputFree") || !UacOutcomeEvidence.True(receipt, "ControlComplete")) return false;
            if (!receipt.TryGetProperty("BusinessResult", out var receivedBusiness)
                || !JsonElement.DeepEquals(test.GetProperty("Business"), receivedBusiness)
                || !UacOutcomeEvidence.True(receipt, "TestLauncherStarted")
                || !UacOutcomeEvidence.True(receipt, "BusinessLaunchAttempted")) return false;
            var business = test.GetProperty("Business").Deserialize<UacTestResult>();
            if (business is null || business.Launcher.Pid <= 0 || business.Launcher.Created <= 0 || business.Nonce != nonce || business.Launcher.Session != current.Session
                || business.Launcher.User != current.UserSid || business.Launcher.Integrity != 8192
                || business.Launcher.ImageDigest != current.HelperSha256) return false;
            if (business.Target is not null && (business.Target.Pid <= 0 || business.Target.Created <= 0 || business.Target.Session != current.Session || business.Target.User != current.UserSid
                || business.Target.Integrity != 12288 || business.Target.ImageDigest != current.HelperSha256)) return false;
            return command switch {
                "cancel" => UacRuntime.CancelExperimentConsistent(receipt, business),
                "accept" => UacRuntime.AcceptExperimentConsistent(receipt, business),
                "stop" => StopConsistent(receipt, business), _ => false };
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException) { return false; }
    }
    internal static void Record(BrokerPolicy policy, Peer own, string command, string nonce)
    {
        if (command is not ("cancel" or "accept" or "stop")) return;
        var current = Binding(policy, own.Session);
        var testBytes = Read(ReceiptPath(policy, own.Session, "tests", nonce)); using var test = Parse(testBytes);
        var workerNonce = test.RootElement.GetProperty("Receipt").GetProperty("RequestNonce").GetString()!;
        var workerBytes = Read(ReceiptPath(policy, own.Session, "workers", workerNonce)); using var worker = Parse(workerBytes);
        if (!Matches(command, test.RootElement, worker.RootElement, current)) return;
        Write(policy, IndexPath(policy, own.Session, command), new Index(1, command, nonce, workerNonce,
            Hash(testBytes), Hash(workerBytes), current));
    }
    private static bool Verified(BrokerPolicy policy, int session, string command, UacVerificationBinding current)
    {
        var path = IndexPath(policy, session, command);
        if (!ExistingWriteTarget(UacStateStorage.Directory(policy), path)) return false;
        using var indexDoc = Parse(Read(path)); var index = indexDoc.RootElement.Deserialize<Index>()
            ?? throw new Boundary("uac_verification_index_rejected");
        if (index.Schema != 1 || index.Command != command || index.Binding != current) return false;
        var testBytes = Read(ReceiptPath(policy, session, "tests", index.TestNonce));
        var workerBytes = Read(ReceiptPath(policy, session, "workers", index.WorkerNonce));
        if (Hash(testBytes) != index.TestSha256 || Hash(workerBytes) != index.WorkerSha256)
            throw new Boundary("uac_verification_evidence_changed");
        using var test = Parse(testBytes); using var worker = Parse(workerBytes);
        return Matches(command, test.RootElement, worker.RootElement, current);
    }
    internal static object Register()
    {
        var (policy, own) = Context(); var current = Binding(policy, own.Session);
        bool cancel = Verified(policy, own.Session, "cancel", current), accept = Verified(policy, own.Session, "accept", current),
            stop = Verified(policy, own.Session, "stop", current);
        // Profile readiness verifies native-generated three-witness evidence;
        // this does not claim semantic Hook acceptance or change any mode.
        bool program = UacProgramBinding.Readiness().Available;
        var proof = new { Schema = 3, current.Version, current.NativeSha256, current.HelperSha256, current.ManagedHelperSha256,
            current.ConsentSha256, current.WindowsBuild, CancelRoute = "window_message", AcceptRoute = "uia_invoke",
            SystemSessionVerified = cancel || accept || stop, SecureStopReachabilityVerified = stop,
            CancelRouteVerified = cancel, AcceptRouteVerified = accept, ProgramBindingVerified = program,
            SemanticAuthorityVerified = false };
        if (Binding(policy, own.Session) != current) throw new Boundary("uac_verification_components_changed");
        Write(policy, Path.Combine(UacStateStorage.Directory(policy, true), "uac-verification.json"), proof);
        return new { State = "recorded", EvidenceRegistered = true, Proof = proof, ModeChanged = false, StopCleared = false,
            SemanticRuntimeVerified = false, SavedMode = UserPermissions.Read().UacMode, InputDispatched = false };
    }
}
