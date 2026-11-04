using System.Security.Principal;
using System.Text;

namespace Flower.HighHelper;

internal sealed record SettingsWordSnapshot(string Text, string Revision, string? Error = null);

internal static partial class UserPermissions
{
    // This is the already-consumed protected word list, not an arbitrary path
    // supplied by an RPC. The user's separate LocalAppData appendix is retained.
    private static string SettingsWordsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper", "privacy", "sensitive-words.txt");
    internal static SettingsWordSnapshot ReadSettingsWords()
    {
        try { return ReadSettingsWordsAt(SettingsWordsPath, false); }
        catch (Exception error) { return new("", "unreadable", Program.Code(error)); }
    }
    private static SettingsWordSnapshot ReadSettingsWordsAt(string path, bool fixture)
    {
        var bytes = ReadStorageBytes(path, fixture);
        if (bytes is { Length: > 262144 }) throw new Boundary("privacy_words_too_large");
        return new(bytes is null ? "" : new UTF8Encoding(false, true).GetString(bytes).TrimStart('\uFEFF'), RawRevision(bytes));
    }
    internal static void ValidateSettingsWords(string text)
    {
        var words = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim()).Where(x => x.Length > 0 && !x.StartsWith('#')).ToArray();
        if (Encoding.UTF8.GetByteCount(text) > 262144 || words.Length > 2000
            || words.Any(x => x.Length > 200 || x.Any(char.IsControl))) throw new Boundary("privacy_words_invalid");
    }
    internal static SettingsWordSnapshot SaveSettingsWords(string text, string revision, string policyRevision,
        CancellationToken cancellation)
    {
        if (FixturePath is not null || WindowsIdentity.GetCurrent().IsSystem
            || Native.Process(Environment.ProcessId, false).Identity.Integrity != 12288)
            throw new Boundary("user_policy_high_required");
        ValidateSettingsWords(text);
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        using var gate = new Mutex(false, "Local\\FlowerControl.UserPermissions." + sid);
        bool held; try { held = gate.WaitOne(5000); } catch (AbandonedMutexException) { held = true; }
        if (!held) throw new Boundary("user_policy_save_busy");
        try
        {
            cancellation.ThrowIfCancellationRequested();
            RequireCurrentRevision(policyRevision, Read().Revision);
            string parent = Path.GetDirectoryName(SettingsWordsPath)!;
            CheckStorageParent(parent); SecurityLabel.CreateDirectory(parent, sid);
            return SaveSettingsWordsAt(SettingsWordsPath, text, revision, sid, false);
        }
        finally { gate.ReleaseMutex(); }
    }
    private static SettingsWordSnapshot SaveSettingsWordsAt(string path, string text, string revision, string sid, bool fixture)
    {
        ValidateSettingsWords(text);
        var before = ReadStorageBytes(path, fixture);
        if (RawRevision(before) != revision) throw new Boundary("privacy_words_changed");
        var bytes = new UTF8Encoding(false).GetBytes(text);
        bool committed = false;
        try { ReplaceStorageFile(path, bytes, before, sid, fixture, [], ref committed); }
        catch (Exception error) when (committed)
        { var unknown = new Boundary("privacy_words_save_outcome_unknown"); unknown.Data["OriginalError"] = error; throw unknown; }
        return new(text, RawRevision(bytes));
    }
}
