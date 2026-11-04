internal static class TextValueComparison
{
    private static string Lines(string value) => value.Replace("\r\n", "\n").Replace('\r', '\n');
    internal static bool Matches(string expected, string actual) => Lines(expected) == Lines(actual);
    internal static string Verification(string expected, string? actual, bool matched) =>
        matched && actual != expected ? "control_value_line_endings_normalized_readback" : "exact_control_value_readback";
}
