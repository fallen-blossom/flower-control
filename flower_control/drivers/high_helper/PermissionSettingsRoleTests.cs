using System.Security.Principal;

namespace Flower.HighHelper;

// State/descriptor tests only. The existing UserPermissions.Validate contract
// reads the current user SID; no protected policy, Stop, pipe, window or UAC is
// read or executed. No window-class initialization or preview is invoked.
internal static class PermissionSettingsRoleTests
{
    internal static object Run()
    {
        int checks = 0;
        void Check(bool value) { ++checks; if (!value) throw new Boundary("permission_role_selftest_failed"); }
        void Reject(Action action, string code)
        {
            try { action(); }
            catch (Boundary error) { Check(error.Code == code); return; }
            throw new Boundary("permission_role_selftest_missing_rejection");
        }
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        var original = UserPermissions.Effective(new UserPermissionSettings { UserSid = sid, Revision = "baseline", AuthorityTier = 0,
            JevEnabled = false, HudCompact = false, HudPosition = "auto" });
        var retained = original with { HudCompact = true, HudPosition = "bottom_right", JevEnabled = true,
            DeniedApplications = [new(@"C:\Fixture\private.exe", "private")],
            DeniedAdminWindowApplications = [new(@"C:\Fixture\admin.exe")],
            AdminLaunchAllowlist = [new(@"C:\Fixture\editor.exe", "sha256", new string('a', 64), "fixture", false, "")],
            DeniedAdminLaunchApplications = [new(@"C:\Fixture\blocked.exe", "sha256", new string('b', 64), "blocked", true, "")],
            Masks = [new(@"C:\Fixture\editor.exe", [1, 2, 20, 30], [100, 100])] };
        foreach (int tier in new[] { -1, 0, 1, 2, 3 })
        {
            var saved = UserPermissions.Effective(original with { AuthorityTier = tier });
            var attemptedRole = retained with { AuthorityTier = tier == 3 ? 0 : 3, AdminWindows = !saved.AdminWindows,
                AdminLaunchEnabled = !saved.AdminLaunchEnabled, UacMode = "off", Revision = "untrusted-draft-revision" };
            var submitted = PermissionSettingsWindow.SameRoleSubmission(attemptedRole, saved);
            Check(submitted.AuthorityTier == saved.AuthorityTier && UserPermissions.TierOf(submitted) == tier);
            Check(submitted.AdminWindows == saved.AdminWindows && submitted.AdminLaunchEnabled == saved.AdminLaunchEnabled);
            Check(submitted.UacMode == saved.UacMode && submitted.Revision == saved.Revision);
            Check(submitted.HudCompact && submitted.HudPosition == "bottom_right" && submitted.JevEnabled);
            Check(ReferenceEquals(submitted.DeniedApplications, retained.DeniedApplications)
                && ReferenceEquals(submitted.Masks, retained.Masks) && submitted.AdminLaunchAllowlist.Length == 1);
        }
        var legacy = original with { AuthorityTier = int.MinValue, AdminWindows = false };
        Check(PermissionSettingsWindow.SameRoleSubmission(retained, legacy).AuthorityTier == int.MinValue);
        Reject(() => PermissionSettingsWindow.SameRoleSubmission(retained with { UserSid = "S-1-5-18" }, original), "user_policy_invalid");
        var observe = UserPermissions.Effective(original with { AuthorityTier = 3, UacMode = "observe" });
        Check(PermissionSettingsWindow.SameRoleSubmission(retained with { UacMode = "cancel" }, observe).UacMode == "cancel");
        Check(PermissionSettingsWindow.ChosenExecutionTier(0, 3, false) == 0);
        Check(PermissionSettingsWindow.ChosenExecutionTier(1, 0, true) == 1);
        Check(PermissionSettingsWindow.ChosenExecutionTier(3, 0, true) == 3);
        Check(PermissionSettingsWindow.ChosenExecutionTier(2, 2, false) == -1);
        Check(PermissionSettingsWindow.ChosenExecutionTier(0, 0, true) == -1);
        Check(PermissionSettingsWindow.ChosenExecutionTier(2, 2, true) == 2); // Policy/actual-role mismatch must repair the role.
        Check(PermissionSettingsWindow.ChosenExecutionTier(0, 0, false) == 0);
        Check(PermissionSettingsWindow.ChosenExecutionTier(0, 0, true, toggle: false) == 0);
        Reject(() => PermissionSettingsWindow.ChosenExecutionTier(4, 0, true), "user_policy_invalid");
        Reject(() => PermissionSettingsWindow.RequireResidentTierChange(true), "settings_live_broker_required");
        PermissionSettingsWindow.RequireResidentTierChange(false); Check(true);
        Reject(() => PermissionSettingsWindow.RequireDiagnosticRole(true), "uac_diagnostic_requires_admin_tier");
        PermissionSettingsWindow.RequireDiagnosticRole(false); Check(true);

        var words = new SettingsWordSnapshot("fixture-sensitive-word", "words-revision");
        var preference = new SettingsUiPreference("allowlist", "ui-revision");
        var snapshot = PermissionSettingsWindow.CreateRoleHandoff(retained, original, words, preference,
            "semantic", "allowlist", true, 6);
        Check(snapshot.Legacy && snapshot.Page == 6 && snapshot.Baseline == original);
        Check(snapshot.Words == words && snapshot.WordDraft == words.Text && snapshot.PreferredMode == "semantic"
            && snapshot.ModeBaseline == "allowlist" && snapshot.PreferencePending);
        foreach (int page in Enumerable.Range(0, 7))
        { PermissionSettingsWindow.ValidateRoleHandoff(snapshot with { Page = page }, sid); Check(true); }
        foreach (var invalid in new[] { snapshot with { Legacy = false }, snapshot with { Page = 7 }, snapshot with { Page = -1 },
            snapshot with { PreferredMode = "invalid" }, snapshot with { ModeBaseline = "off" }, snapshot with { RuleLayer = 1 },
            snapshot with { ManagedBrowser = "brave" }, snapshot with { DecisionSelection = 1 }, snapshot with { PrivacyTab = 1 },
            snapshot with { Preference = preference with { UacSubmode = "invalid" } }, snapshot with { WordDraft = null! },
            snapshot with { Draft = retained with { UserSid = "S-1-5-18" } }, snapshot with { WordDraft = "silently-changed" } })
            Reject(() => PermissionSettingsWindow.ValidateRoleHandoff(invalid, sid), "settings_handoff_invalid");

        var committed = UserPermissions.Effective(original with { Revision = "role-commit", AuthorityTier = 2 });
        var recovered = PermissionSettingsWindow.RetainRoleSurface(committed, snapshot);
        Check(!recovered.Conflict && recovered.Saved == committed && recovered.Draft.Revision == committed.Revision);
        Check(recovered.Draft.AuthorityTier == 2 && recovered.Draft.AdminWindows && recovered.Draft.AdminLaunchEnabled
            && recovered.Draft.UacMode == "off");
        Check(recovered.Draft.HudCompact && recovered.Draft.HudPosition == "bottom_right" && recovered.Draft.JevEnabled);
        Check(recovered.Draft.DeniedApplications.Length == 1 && recovered.Draft.DeniedAdminWindowApplications.Length == 1
            && recovered.Draft.DeniedAdminLaunchApplications.Length == 1 && recovered.Draft.Masks.Length == 1);
        Check(recovered.Dirty); // Selecting a tier saved no unrelated draft fields.
        var cancelled = PermissionSettingsWindow.RetainRoleSurface(original, snapshot);
        Check(!cancelled.Conflict && cancelled.Draft.AuthorityTier == 0 && cancelled.Draft.HudCompact && cancelled.Dirty);
        foreach (var concurrent in new[] { committed with { JevEnabled = true }, committed with { HudCompact = true },
            committed with { HudPosition = "top_left" }, committed with { AdminLaunchMode = "semantic" },
            committed with { DeniedApplications = [new(@"C:\Fixture\other.exe")] },
            committed with { UacPolicyError = "fixture-unreadable" } })
        {
            var conflict = PermissionSettingsWindow.RetainRoleSurface(concurrent, snapshot);
            Check(conflict.Conflict && conflict.Saved == concurrent && conflict.Draft.Revision == original.Revision);
            Check(conflict.Draft.HudCompact && conflict.Draft.DeniedApplications[0].Path == retained.DeniedApplications[0].Path);
        }
        var operation = PermissionSettingsWindow.SameRoleSaveOperation(retained with { AuthorityTier = 3 }, original,
            true, "semantic", preference, true);
        Check(operation.Kind == "save" && operation.Revision == original.Revision && operation.Submitted!.AuthorityTier == 0);
        Check(operation.Mode == "semantic" && operation.ModeRevision == preference.Revision && operation.PolicyChanged);
        Check(operation.Submitted!.HudCompact && operation.Submitted.DeniedApplications.Length == 1 && operation.Tier is null);
        var preferenceOnly = PermissionSettingsWindow.SameRoleSaveOperation(original, original, false, "semantic", preference, true);
        Check(!preferenceOnly.PolicyChanged && preferenceOnly.Mode == "semantic");
        var noPreference = PermissionSettingsWindow.SameRoleSaveOperation(retained, original, true, "semantic", preference, false);
        Check(noPreference.Mode is null && noPreference.ModeRevision is null);
        var partial = PermissionSettingsWindow.RolePreferenceResult(new(committed, PreferenceError: "settings_ui_preferences_changed"), "semantic", true, true);
        Check(partial.PolicyWritten && partial.PreferenceRequested && partial.Error == "settings_ui_preferences_changed" && partial.Saved is null);
        Check(PermissionSettingsWindow.PreferenceSaveConflicts(partial.Error));
        Check(PermissionSettingsWindow.PreferenceSaveConflicts("settings_ui_preferences_save_outcome_unknown"));
        Check(!PermissionSettingsWindow.PreferenceSaveConflicts("deadline_expired"));
        var noChange = PermissionSettingsWindow.RolePreferenceResult(new(original), "allowlist", false, false);
        Check(!noChange.PolicyWritten && !noChange.PreferenceRequested && noChange.Error is null);
        Check(!PermissionSettingsWindow.ProtectedWorkFailureConflicts("local_writer_user_cancelled", original.Revision, original.Revision));
        Check(PermissionSettingsWindow.ProtectedWorkFailureConflicts("local_writer_outcome_unknown", original.Revision, original.Revision));
        Check(PermissionSettingsWindow.ProtectedWorkFailureConflicts("local_writer_user_cancelled", "external-change", original.Revision));
        Check(PermissionSettingsWindow.KeepRoleReplyForTimer("tier", 7, 7, true));
        Check(!PermissionSettingsWindow.KeepRoleReplyForTimer("tier", 7, 8, true));
        Check(!PermissionSettingsWindow.KeepRoleReplyForTimer("tier", 7, 7, false));
        Check(!PermissionSettingsWindow.KeepRoleReplyForTimer("save", 7, 7, true));
        return new { passed = true, assertions = checks, currentUserIdentityRead = true, productionPolicyRead = false,
            productionStopTouched = false, guiStarted = false, elevated = false, inputDispatched = false,
            evidence = "state-and-native-descriptor-only" };
    }
}
