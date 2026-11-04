using System.Security.Cryptography;
using System.Text.Json;

namespace Flower.HighHelper;

// Compatibility for ONE fixed harmless b15 experiment. This never resolves its
// business result and is deliberately not a general unknown-claim recovery API.
internal static class UacLegacyControlRecovery
{
    internal const string ClaimDigest = "1fa482634fe20fab34fadcab6208494ea2bfe2ebb1fabbe94fa816b64f5f4d9a";
    internal const string TestDigest = "f3a7cdfc6fb8370440a3d7b21198a89924b99feabe735c1bac20a29121e7dc10";
    internal const string Version = "531984103c8740c7b42a605876d7e7ed";
    internal const string Task = "uac_test_cancel_46e26da8d35e387ecb723dee5836d0c0";
    internal const string Nonce = "5099a0d0bfdb41c9a4a2cc0736f29cdc";
    internal static bool IsOriginal(byte[] bytes, UacClaimEntry entry) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() == ClaimDigest
        && entry.Nonce == Nonce && entry.TaskId == Task && entry.State == "unknown" && !entry.InputFree;
    internal static bool FreshControlled(UacClaimEntry entry) => entry.State == "reserved" && entry.InputFree
        && entry.Nonce != Nonce && entry.TaskId != Task
        && (entry.TaskId.StartsWith("uac_test_cancel_", StringComparison.Ordinal)
            || entry.TaskId.StartsWith("uac_test_accept_", StringComparison.Ordinal));
    internal static bool Matches(JsonElement value, string version, string sid, int session)
    {
        static bool Text(JsonElement value, string key, string expected) => UacOutcomeEvidence.Text(value, key) == expected;
        return value.ValueKind == JsonValueKind.Object
            && value.TryGetProperty("Schema", out var schema) && schema.TryGetInt32(out int number) && number == 1
            && value.TryGetProperty("Session", out var ownSession) && ownSession.TryGetInt32(out int actual) && actual == session
            && Text(value, "ClaimSha256", ClaimDigest) && Text(value, "TestReceiptSha256", TestDigest)
            && Text(value, "PreviousVersion", Version) && Text(value, "RecoveryVersion", version)
            && Text(value, "UserSid", sid) && Text(value, "Scope", "fixed_harmless_test_only")
            && Text(value, "BusinessOutcome", "unknown") && UacOutcomeEvidence.True(value, "InputFree")
            && UacOutcomeEvidence.True(value, "OldExecutorsAbsent") && UacOutcomeEvidence.True(value, "OriginalPromptGone")
            && UacOutcomeEvidence.True(value, "TasksDisabledDuringProof") && UacOutcomeEvidence.False(value, "InputReplay");
    }
}
