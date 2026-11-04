using System.Text.Json;

namespace Flower.HighHelper;

// Called only after the original pipe-server PID/image identity verification.
// An error remains a rejection; retain its bounded code for local diagnosis.
internal static class AdminHandshake
{
    internal static void RequireHello(JsonDocument? document)
    {
        if (document is not null && document.RootElement.ValueKind == JsonValueKind.Object
            && document.RootElement.TryGetProperty("Phase", out var phase)
            && phase.ValueKind == JsonValueKind.String)
        {
            if (phase.GetString() == "hello") return;
            if (phase.GetString() == "error"
                && document.RootElement.TryGetProperty("Reason", out var reason)
                && reason.ValueKind == JsonValueKind.String
                && reason.GetString() is { Length: > 0 and <= 96 } code
                && code[0] is >= 'a' and <= 'z'
                && code.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_'))
                throw new Boundary(code);
        }
        throw new Boundary("hello_rejected");
    }
}
