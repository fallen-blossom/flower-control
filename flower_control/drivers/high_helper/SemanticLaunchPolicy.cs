using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Tier 03/04 semantic mode. The user granted "administrator execution" as a
// tier rather than enumerating programs, because they cannot know which
// scripts or hosts a development task will need. This applies explicit target
// vetoes plus the independent work and execution bindings:
//   - the file must be an ordinary local image, never a link or a device
//   - explicit per-tier blacklists still win
//   - obvious direct security/UAC/cross-user entry points are refused
// These name/argument vetoes cannot prove arbitrary scripts avoid those effects.
// Every accepted launch is journaled with its computed identity so the user
// can audit what ran while they were away.
internal static class SemanticLaunchPolicy
{
    private static readonly string[] SecuritySoftware =
    [
        "\\windows defender\\", "\\microsoft security client\\", "\\huorong\\",
        "\\360safe\\", "\\360 total security\\", "\\kingsoft\\", "\\avast\\",
        "\\avira\\", "\\kaspersky", "\\mcafee\\", "\\symantec\\", "\\eset\\",
        "\\bitdefender\\", "\\trend micro\\", "\\sophos\\", "\\恶意软件"
    ];
    private static readonly HashSet<string> CrossUserHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "runas.exe", "psexec.exe", "psexec64.exe", "paexec.exe", "remoteexec.exe"
    };
    private static readonly HashSet<string> CredentialTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "mimikatz.exe", "lazagne.exe", "pwdump.exe", "gsecdump.exe"
    };
    private static readonly string[] UacPolicyArguments =
    [
        "consentpromptbehavior", "enablelua", "filteradministratortoken",
        "promptonsecuredesktop", "validateadmincodesignatures"
    ];

    internal static bool ValidPath(string? value) => value is not null
        && Path.IsPathFullyQualified(value) && !value.StartsWith("\\\\", StringComparison.Ordinal)
        && !value.Contains('*') && !value.Contains('?') && !value.Skip(2).Contains(':')
        && !value.Any(char.IsControl) && value.Length <= 1024;

    // Arguments travel inside a quoted argv[1], never through a shell, so the
    // only hard limits are the protocol's existing character rules.
    internal static bool ValidArguments(string? value) => value is not null
        && value.Length <= 4096 && !value.Any(char.IsControl) && !value.Contains('*') && !value.Contains('?');

    internal static void RequireAllowed(UserPermissionSettings settings, string image, string arguments, bool structured = false)
    {
        if (!ValidPath(image)) throw new Boundary("program_launch_semantic_path_rejected");
        if (structured ? arguments.Length > 24576 || arguments.Contains('\0') : !ValidArguments(arguments))
            throw new Boundary("program_launch_semantic_arguments_rejected");
        if (UserPermissions.AdminLaunchDenied(settings, image))
            throw new Boundary("window_disabled_by_user");
        string full = Path.GetFullPath(image);
        string name = Path.GetFileName(full);
        string lower = full.ToLowerInvariant();
        if (SecuritySoftware.Any(fragment => lower.Contains(fragment, StringComparison.Ordinal)))
            throw new Boundary("program_launch_security_software_blocked");
        if (CrossUserHosts.Contains(name)) throw new Boundary("program_launch_cross_user_blocked");
        if (CredentialTools.Contains(name)) throw new Boundary("program_launch_credential_tool_blocked");
        if (name is "reg.exe" or "regedit.exe" && UacPolicyArguments.Any(fragment =>
                arguments.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
            throw new Boundary("program_launch_uac_policy_change_blocked");
        // Tier 01/02 may not reach this path at all; the caller already checked
        // RequireMode, but re-check the ladder so a stale draft cannot exceed it.
        if (UserPermissions.TierOf(settings) < 2) throw new Boundary("program_launch_disabled");
    }
}
