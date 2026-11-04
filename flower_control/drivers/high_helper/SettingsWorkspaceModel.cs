using System.Text.Json;

namespace Flower.HighHelper;

// Drafts never mutate the effective snapshot. Every array change replaces the
// record, and lowering the tier preserves all independent lists and preferences.
internal sealed class SettingsWorkspaceModel
{
    internal UserPermissionSettings Saved { get; private set; }
    internal UserPermissionSettings Draft { get; private set; }
    internal int EffectiveTier => UserPermissions.TierOf(Saved);
    internal int DraftTier => UserPermissions.TierOf(Draft);
    internal bool Conflict { get; set; }
    internal bool Dirty => !Same(Saved, Draft);
    internal SettingsWorkspaceModel(UserPermissionSettings value) { Saved = Draft = value; }
    internal static bool Same(UserPermissionSettings a, UserPermissionSettings b)
        => JsonSerializer.Serialize(a with { Revision = "" }) == JsonSerializer.Serialize(b with { Revision = "" });
    internal void Edit(Func<UserPermissionSettings, UserPermissionSettings> change) => Draft = change(Draft);
    internal void SelectTier(int tier)
    {
        if (!AuthorityPresentation.Selectable(tier)) throw new Boundary("user_policy_invalid");
        Draft = UserPermissions.Effective(Draft with { AuthorityTier = tier });
    }
    internal void Commit(UserPermissionSettings submitted, UserPermissionSettings committed)
    {
        // A save completion may arrive after the user edited a different page.
        // Keep those later edits and only advance their CAS baseline.
        Saved = committed;
        Draft = Same(Draft, submitted) ? committed : Draft with { Revision = committed.Revision };
    }
    internal void Reload(UserPermissionSettings loaded) { Saved = Draft = loaded; Conflict = false; }
    internal void ReconcileTier(UserPermissionSettings prior, UserPermissionSettings committed)
    {
        if (Saved.Revision != prior.Revision) { Conflict = true; return; }
        Saved = committed;
        Draft = UserPermissions.Effective(Draft with { Revision = committed.Revision, AuthorityTier = committed.AuthorityTier,
            AdminWindows = committed.AdminWindows, AdminLaunchEnabled = committed.AdminLaunchEnabled,
            UacMode = committed.UacMode, SemanticDelegation = committed.SemanticDelegation });
    }
    internal void RetainRoleDraft(UserPermissionSettings baseline, UserPermissionSettings retained)
    {
        UserPermissionSettings WithoutRole(UserPermissionSettings value) => value with { AuthorityTier = 0,
            AdminWindows = false, AdminLaunchEnabled = false, UacMode = "off", SemanticDelegation = null };
        bool conflict = baseline.UserSid != Saved.UserSid || retained.UserSid != Saved.UserSid
            || baseline.UacPolicyError != Saved.UacPolicyError
            || !Same(WithoutRole(baseline), WithoutRole(Saved));
        // A role-only commit may advance this CAS baseline. An unrelated
        // concurrent policy edit must stay a conflict, never be overwritten
        // by silently rebasing old lists onto its new revision.
        Draft = retained with { Revision = conflict ? baseline.Revision : Saved.Revision,
            AuthorityTier = Saved.AuthorityTier, AdminWindows = Saved.AdminWindows,
            AdminLaunchEnabled = Saved.AdminLaunchEnabled, UacMode = Saved.UacMode,
            SemanticDelegation = Saved.SemanticDelegation };
        Conflict = conflict;
    }
    internal bool ReconcileSemanticDelegation(UserPermissionSettings baseline, UserPermissionSettings committed)
    {
        if (Conflict || Saved.Revision != baseline.Revision || !SameRevokeSnapshot(Saved, baseline)
            || !Same(baseline, committed) || baseline.UacPolicyError != committed.UacPolicyError
            || committed.SemanticDelegation is null)
        { Conflict = true; return false; }
        SemanticDelegation.Validate(committed.SemanticDelegation, baseline.UserSid);
        Saved = committed;
        Draft = Draft with { Revision = committed.Revision, SemanticDelegation = committed.SemanticDelegation };
        return true;
    }
    private static bool SameRevokeSnapshot(UserPermissionSettings a, UserPermissionSettings b)
        => Same(a, b) && a.UacPolicyError == b.UacPolicyError
            && Equals(a.SemanticDelegation, b.SemanticDelegation);
    internal bool ReconcileImmediateRevoke(UserPermissionSettings current, UserPermissionSettings? expectedBaseline = null)
    {
        var baseline = expectedBaseline ?? Saved;
        var expectedOff = UserPermissions.Effective(UserPermissions.WithoutUac(baseline));
        int lowered = Math.Min(DraftTier, Math.Min(2, UserPermissions.TierOf(current)));
        // Revoke only the authority draft even on conflict. A newly observed
        // revision cannot authorize saving unrelated stale lists/preferences.
        Draft = UserPermissions.Effective(Draft with { AuthorityTier = lowered });
        if (Conflict || Saved.Revision != baseline.Revision || !SameRevokeSnapshot(Saved, baseline)
            || current.UacMode != "off" || !SameRevokeSnapshot(expectedOff, UserPermissions.Effective(current)))
        {
            Conflict = true;
            return false;
        }
        Draft = Draft with { Revision = current.Revision };
        Saved = current;
        return true;
    }
    internal void AddWindowRule(int layer, string path)
    {
        var rows = WindowRules(layer);
        if (rows.Any(x => x.Path.Equals(path, StringComparison.OrdinalIgnoreCase) && x.TitleContains.Length == 0 && x.Enabled)) return;
        WindowRules(layer, rows.Append(new ApplicationPermission(path)).ToArray());
    }
    internal ApplicationPermission[] WindowRules(int layer) => layer == 0 ? Draft.DeniedApplications : Draft.DeniedAdminWindowApplications;
    internal void WindowRules(int layer, ApplicationPermission[] rows)
    {
        if (rows.Length > 128) throw new Boundary("user_policy_invalid");
        Draft = layer == 0 ? Draft with { DeniedApplications = rows } : Draft with { DeniedAdminWindowApplications = rows };
    }
    internal UacApplicationPermission[] Programs(int layer, bool denied) => layer == 2
        ? denied ? Draft.DeniedAdminLaunchApplications : Draft.AdminLaunchAllowlist
        : denied ? Draft.DeniedUacApplications : Draft.UacAllowlist;
    internal void Programs(int layer, bool denied, UacApplicationPermission[] rows)
    {
        if (rows.Length > 128) throw new Boundary("user_policy_invalid");
        Draft = (layer, denied) switch
        {
            (2, false) => Draft with { AdminLaunchAllowlist = rows },
            (2, true) => Draft with { DeniedAdminLaunchApplications = rows },
            (3, false) => Draft with { UacAllowlist = rows },
            (3, true) => Draft with { DeniedUacApplications = rows },
            _ => throw new Boundary("user_policy_invalid")
        };
    }
    internal bool ProgramOnOppositeSide(int layer, bool denied, string path)
        => Programs(layer, !denied).Any(old => old.Path.Equals(path, StringComparison.OrdinalIgnoreCase));
    internal bool ProgramsOverlap(int layer)
        => Programs(layer, false).Any(row => ProgramOnOppositeSide(layer, false, row.Path));
    internal void AddProgram(int layer, bool denied, UacApplicationPermission row, bool moveOpposite = false)
    {
        var rows = Programs(layer, denied).ToList();
        int index = rows.FindIndex(old => old.Path.Equals(row.Path, StringComparison.OrdinalIgnoreCase) && old.Arguments == "" && row.Arguments == "");
        if (index < 0) rows.Add(row); else rows[index] = row;
        if (rows.Count > 128) throw new Boundary("user_policy_invalid");
        if (moveOpposite)
        {
            var opposite = Programs(layer, !denied).Where(old => !old.Path.Equals(row.Path, StringComparison.OrdinalIgnoreCase)).ToArray();
            Programs(layer, !denied, opposite);
        }
        Programs(layer, denied, rows.ToArray());
    }
}
