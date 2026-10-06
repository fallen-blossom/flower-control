using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

internal static class TextPages
{
    internal const int DocumentLimit = 1_048_576;

    internal static Dictionary<string, object?> Read(string text, JsonElement options)
    {
        var result = new Dictionary<string, object?> { ["dispatched"] = false };
        if (text.Length > DocumentLimit)
        {
            result["state"] = "not_verified";
            result["reason"] = "text_document_limit_exceeded";
            result["truncated"] = true;
            result["document_complete"] = false;
            result["document_limit_utf16"] = DocumentLimit;
            return result;
        }
        var version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
        var expected = options.GetProperty("version").GetString();
        if (expected is not null && version != expected)
        {
            result["state"] = "rejected";
            result["reason"] = "text_version_changed";
            result["requires_new_observation"] = true;
            return result;
        }
        int offset = options.GetProperty("offset").GetInt32(), size = options.GetProperty("max_chars").GetInt32();
        var runes = text.EnumerateRunes().ToArray();
        if (offset < 0 || offset > runes.Length || size is < 1 or > 4096)
            throw new ArgumentException();
        int end = Math.Min(runes.Length, offset + size);
        var page = new StringBuilder();
        for (int index = offset; index < end; index++)
            page.Append(runes[index]);
        result["state"] = "observed";
        result["text"] = page.ToString();
        result["text_version"] = version;
        result["offset"] = offset;
        result["next_offset"] = end;
        result["total_chars"] = runes.Length;
        result["offset_unit"] = "unicode_scalar";
        result["truncated"] = end < runes.Length;
        result["document_complete"] = end == runes.Length;
        result["document_limit_utf16"] = DocumentLimit;
        return result;
    }
}
