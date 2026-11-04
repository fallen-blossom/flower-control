namespace Flower.HighHelper;

internal sealed record SettingsSurfaceHandoff(UserPermissionSettings Draft, UserPermissionSettings Baseline, string WordDraft,
    SettingsWordSnapshot Words, SettingsUiPreference Preference, string PreferredMode, string ModeBaseline,
    bool PreferencePending, DecisionProviderSnapshot? DecisionSnapshot, DecisionProviderPreferences? DecisionDraft,
    int DecisionSelection, int Page, int RuleLayer, bool Denied, int PrivacyTab, int GeneralSection, string? ManagedBrowser, bool Legacy = false);

internal static class SettingsSurfaceHandoffValidator
{
    internal static void Validate(SettingsSurfaceHandoff snapshot, string sid)
    {
        if (snapshot.Draft is null || snapshot.Baseline is null || snapshot.Words is null || snapshot.Preference is null
            || snapshot.WordDraft is null || snapshot.Words.Text is null || snapshot.Draft.UserSid != sid || snapshot.Baseline.UserSid != sid
            || snapshot.Page < 0 || snapshot.Page > (snapshot.Legacy ? 6 : 4) || snapshot.RuleLayer is < 0 or > 3
            || snapshot.PrivacyTab is < 0 or > 2 || snapshot.GeneralSection is < 0 or > 2 || snapshot.DecisionSelection < 0 || snapshot.DecisionSelection > 18
            || snapshot.ManagedBrowser is not (null or "brave" or "edge" or "chrome") || snapshot.PreferredMode is not ("allowlist" or "semantic")
            || snapshot.ModeBaseline is not ("allowlist" or "semantic") || snapshot.Preference.UacSubmode is not ("allowlist" or "semantic"))
            throw new Boundary("settings_handoff_invalid");
        UserPermissions.Validate(snapshot.Draft); UserPermissions.Validate(snapshot.Baseline);
        UserPermissions.ValidateSettingsWords(snapshot.WordDraft); UserPermissions.ValidateSettingsWords(snapshot.Words.Text);
        void Decision(DecisionProviderPreferences? value)
        {
            if (value is null) return;
            _ = DecisionProviderSettings.Parse(DecisionProviderSettings.Serialize(value));
        }
        Decision(snapshot.DecisionSnapshot?.Value); Decision(snapshot.DecisionDraft);
    }
}

internal static partial class SettingsWorkspace
{
    private static SettingsSurfaceHandoff? incomingHandoff;
    private static bool roleWork;
    internal static bool HasIncomingHandoff => incomingHandoff is not null;
    internal static bool IncomingLegacy => incomingHandoff?.Legacy == true;
    internal static SettingsSurfaceHandoff TakeIncomingHandoff()
    {
        var snapshot = incomingHandoff ?? throw new Boundary("settings_handoff_missing");
        incomingHandoff = null;
        return snapshot;
    }
    internal static void QueueHandoff(SettingsSurfaceHandoff snapshot) => incomingHandoff = snapshot;
    private static SettingsSurfaceHandoff CaptureHandoff() => new(draft, saved, wordDraft, words, preference,
        preferredMode, modeBaseline, preferencePending, decisionSnapshot, decisionDraft?.Copy(), decisionSelection,
        page, ruleLayer, denied, privacyTab, generalSection, managedBrowser);
    // Pure preparation is shared by the actual importer and its conflict
    // regression; it cannot accept/delete recovery files or write policy.
    private static (SettingsSurfaceHandoff Surface, SettingsWorkspaceModel Model) PrepareSurfaceImport(
        UserPermissionSettings current, SettingsSurfaceHandoff snapshot)
    {
        SettingsSurfaceHandoffValidator.Validate(snapshot, current.UserSid);
        SettingsWorkspaceModel retained;
        if (snapshot.Legacy)
        {
            retained = PermissionSettingsWindow.RetainRoleSurface(current, snapshot);
            snapshot = snapshot with {
                Page = snapshot.Page switch { 0 => 3, 1 or 2 => 1, 3 or 5 => 4, 4 => 2, _ => 0 },
                RuleLayer = snapshot.Page == 2 ? 2 : Math.Clamp(retained.EffectiveTier, 0, 2), Legacy = false
            };
        }
        else
        {
            retained = new(current);
            retained.RetainRoleDraft(snapshot.Baseline, snapshot.Draft);
        }
        SettingsSurfaceHandoffValidator.Validate(snapshot, current.UserSid);
        return (snapshot, retained);
    }
    private static void ImportHandoff()
    {
        var snapshot = incomingHandoff; incomingHandoff = null;
        if (snapshot is null) return;
        var prepared = PrepareSurfaceImport(saved, snapshot);
        snapshot = prepared.Surface;
        // The protected read remains the authority. Only unsaved UI fields are
        // imported; neither an old tier nor old delegation can be resurrected.
        model = prepared.Model;
        wordDraft = snapshot.WordDraft; words = snapshot.Words; preference = snapshot.Preference;
        preferredMode = snapshot.PreferredMode; modeBaseline = snapshot.ModeBaseline; preferencePending = snapshot.PreferencePending;
        decisionSnapshot = snapshot.DecisionSnapshot; decisionDraft = snapshot.DecisionDraft?.Copy(); decisionSelection = snapshot.DecisionSelection;
        if (decisionSnapshot is not null) decisionPath = DecisionProviderSettings.LivePath();
        page = snapshot.Page; ruleLayer = Math.Min(2, snapshot.RuleLayer); denied = snapshot.Denied; privacyTab = snapshot.PrivacyTab;
        generalSection = snapshot.GeneralSection; managedBrowser = snapshot.ManagedBrowser;
        notice = model.Conflict ? UiText.Get("设置在交接时已被更改；原草稿已保留，保存前需重新核对。") : UiText.Get("执行权限已切换；其他未保存更改已保留。");
        RoleDraftRecovery.AcceptImported();
    }
}
