using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Decode the real recovery schema without constructing a broker or changing
// acknowledgements. A released historical result may remain business-unknown.
internal static class OfflineRecovery
{
    internal static int Validate(byte[] bytes)
    {
        if (bytes.Length is < 1 or > 16 * 1024 * 1024) throw new Boundary("offline_journal_rejected");
        using var document = JsonDocument.Parse(bytes);
        Protocol.CheckUnique(document);
        var snapshot = Protocol.Decode<BrokerState.RecoverySnapshot>(document);
        if (snapshot.Schema != 1 || snapshot.Pending is null || snapshot.Pending.Length > 4128)
            throw new Boundary("offline_journal_rejected");
        var pending = document.RootElement.GetProperty("Pending");
        if (pending.ValueKind != JsonValueKind.Array) throw new Boundary("offline_journal_rejected");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int index = 0;
        foreach (var item in pending.EnumerateArray())
        {
            var entry = snapshot.Pending[index++];
            if (entry is null || entry.Owner is null || entry.Source is null || entry.Helper is null
                || entry.LedgerIdentity is null || !Regex.IsMatch(entry.LedgerIdentity, "^[a-f0-9]{64}$")
                || !seen.Add(entry.LedgerIdentity) || entry.TaskId is null || !Regex.IsMatch(entry.TaskId, "^[a-zA-Z0-9_-]{1,128}$")
                || entry.ActionId is null || entry.ActionId.Length > 512 || entry.ActionId.Any(char.IsControl))
                throw new Boundary("offline_journal_rejected");
            if (item.GetProperty("InputRelease").ValueKind != JsonValueKind.String || entry.InputRelease != "released"
                || item.GetProperty("MutexReleased").ValueKind != JsonValueKind.True
                || item.GetProperty("NativeCountKnown").ValueKind != JsonValueKind.True
                || item.GetProperty("Acknowledged").ValueKind != JsonValueKind.False
                || item.GetProperty("SemanticExecutorExited").ValueKind is not (JsonValueKind.Null or JsonValueKind.True or JsonValueKind.False)
                || item.GetProperty("PhysicalInputFree").ValueKind is not (JsonValueKind.True or JsonValueKind.False)
                || entry.SemanticExecutorExited == false && !entry.PhysicalInputFree)
                throw new Boundary("offline_input_release_unconfirmed");
        }
        return snapshot.Pending.Length;
    }
}
