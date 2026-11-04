using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Mutable qualification and launch records never belong to the sealed binary
// inventory. Old version records remain in place; no implicit migration occurs.
internal static class UacStateStorage
{
    internal static string Directory(BrokerPolicy policy, bool create = false)
    {
        var root = InstallationLocation.Current().ProgramRoot;
        if (policy.Fixture || !Regex.IsMatch(policy.Version, "\\A[a-f0-9]{16,64}\\z")
            || !Path.GetFullPath(policy.Directory).TrimEnd('\\').Equals(Path.Combine(root, "versions", policy.Version), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_state_installation_rejected");
        if (create)
        {
            var own = Native.Process(Environment.ProcessId).Identity;
            if (own.Integrity is not (12288 or 16384) || own.User != policy.UserSid && own.User != "S-1-5-18"
                || Native.UiAccess(own.Pid)) throw new Boundary("uac_state_writer_rejected");
        }
        UacClaimJournal.CheckParent(Path.GetDirectoryName(root)!, false);
        UacClaimJournal.CheckParent(root, false);
        var recovery = Path.Combine(root, "recovery");
        try { UacClaimJournal.CheckParent(recovery, false); }
        catch (Exception error) when (create && error is FileNotFoundException or DirectoryNotFoundException)
        { SecurityLabel.CreateDirectory(recovery, policy.UserSid); UacClaimJournal.CheckParent(recovery, true); }
        var current = recovery;
        foreach (var part in new[] { "uac", "versions", policy.Version })
        {
            current = Path.Combine(current, part);
            try { UacClaimJournal.CheckParent(current, true); }
            catch (Exception error) when (create && error is FileNotFoundException or DirectoryNotFoundException)
            { SecurityLabel.CreateDirectory(current, policy.UserSid); UacClaimJournal.CheckParent(current, true); }
        }
        return current;
    }
}
