namespace Flower.HighHelper;

internal static partial class PermissionSettingsWindow
{
    private static bool changingExecutionRole;
    private static readonly UIntPtr ExecutionRoleReplyTimer = new(85);

    internal static UserPermissionSettings SameRoleSubmission(UserPermissionSettings edited, UserPermissionSettings saved)
    {
        if (edited.UserSid != saved.UserSid || UserPermissions.TierOf(saved) is < -1 or > 3) throw new Boundary("user_policy_invalid");
        var actual = UserPermissions.Effective(saved);
        return edited with { Revision = saved.Revision, AuthorityTier = saved.AuthorityTier,
            AdminWindows = actual.AdminWindows, AdminLaunchEnabled = actual.AdminLaunchEnabled,
            UacMode = UserPermissions.TierOf(saved) < 3 ? "off" : edited.UacMode == "off" ? actual.UacMode : edited.UacMode,
            SemanticDelegation = saved.SemanticDelegation };
    }

    internal static int ChosenExecutionTier(int target, int savedTier, bool ordinaryResident, bool toggle = true)
    {
        if (target is < -1 or > 3 || savedTier is < -1 or > 3) throw new Boundary("user_policy_invalid");
        bool roleMatches = ordinaryResident == (savedTier <= 0);
        return toggle && savedTier == target && roleMatches ? -1 : target;
    }

    internal static LocalUiOperation SameRoleSaveOperation(UserPermissionSettings edited, UserPermissionSettings saved,
        bool policyChanged, string mode, SettingsUiPreference preference, bool preferenceRequested)
        => new("save", saved.Revision, Submitted: SameRoleSubmission(edited, saved), PolicyChanged: policyChanged,
            Mode: preferenceRequested ? mode : null, ModeRevision: preferenceRequested ? preference.Revision : null);

    internal static SettingsUiSave RolePreferenceResult(LocalUiResult outcome, string mode, bool policyChanged, bool preferenceRequested)
        => new(mode, outcome.Preference, outcome.PreferenceError, PolicyWritten: policyChanged, PreferenceRequested: preferenceRequested);

    internal static bool ProtectedWorkFailureConflicts(string error, string currentRevision, string savedRevision)
        => currentRevision != savedRevision || error.Contains("outcome_unknown", StringComparison.Ordinal);

    internal static bool KeepRoleReplyForTimer(string kind, long replyGeneration, long currentGeneration, bool windowExists)
        => kind == "tier" && replyGeneration == currentGeneration && windowExists;

    private static void DrainExecutionRoleReply()
    {
        foreach (var entry in uacReplies.Where(entry => entry.Value.Kind == "tier" && entry.Value.WindowGeneration == windowGeneration).ToArray())
            WindowMessageCore(window, UacWorkFinished, new UIntPtr((ulong)entry.Key), IntPtr.Zero);
    }

    internal static SettingsSurfaceHandoff CreateRoleHandoff(UserPermissionSettings retained, UserPermissionSettings baseline,
        SettingsWordSnapshot words, SettingsUiPreference preference, string preferredMode, string modeBaseline,
        bool preferencePending, int selectedPage)
    {
        var snapshot = new SettingsSurfaceHandoff(SameRoleSubmission(retained, baseline), baseline, words.Text, words,
            preference, preferredMode, modeBaseline, preferencePending, null, null, 0, selectedPage, 0, false, 0, 0, null, Legacy: true);
        ValidateRoleHandoff(snapshot, baseline.UserSid); return snapshot;
    }

    private static SettingsSurfaceHandoff CaptureRoleHandoff()
    {
        if (original is null) throw new Boundary("settings_handoff_invalid");
        var words = preview ? new SettingsWordSnapshot("", "preview") : UserPermissions.ReadSettingsWords();
        return CreateRoleHandoff(EditedSettings(), original, words, uiPreference, uacSubmode, uiBaselineSubmode,
            uiPreferencePending, (int)page);
    }

    internal static void ValidateRoleHandoff(SettingsSurfaceHandoff snapshot, string sid)
    {
        if (!snapshot.Legacy || snapshot.Draft is null || snapshot.Baseline is null || snapshot.Words is null || snapshot.Preference is null
            || snapshot.WordDraft is null || snapshot.Words.Text is null || snapshot.Preference.UacSubmode is not ("allowlist" or "semantic")
            || snapshot.Draft.UserSid != sid || snapshot.Baseline.UserSid != sid || snapshot.Page is < 0 or > 6
            || snapshot.PreferredMode is not ("allowlist" or "semantic") || snapshot.ModeBaseline is not ("allowlist" or "semantic")
            || snapshot.DecisionSnapshot is not null || snapshot.DecisionDraft is not null || snapshot.DecisionSelection != 0
            || snapshot.RuleLayer != 0 || snapshot.Denied || snapshot.PrivacyTab != 0 || snapshot.GeneralSection != 0
            || snapshot.ManagedBrowser is not null || snapshot.WordDraft != snapshot.Words.Text)
            throw new Boundary("settings_handoff_invalid");
        UserPermissions.Validate(snapshot.Draft); UserPermissions.Validate(snapshot.Baseline);
        UserPermissions.ValidateSettingsWords(snapshot.WordDraft);
    }

    internal static SettingsWorkspaceModel RetainRoleSurface(UserPermissionSettings current, SettingsSurfaceHandoff snapshot)
    {
        ValidateRoleHandoff(snapshot, current.UserSid);
        var retained = new SettingsWorkspaceModel(current);
        retained.RetainRoleDraft(snapshot.Baseline, snapshot.Draft);
        if (snapshot.Baseline.UacPolicyError != current.UacPolicyError)
        {
            retained.Conflict = true;
            retained.Edit(value => value with { Revision = snapshot.Baseline.Revision });
        }
        return retained;
    }

    internal static bool PreferenceSaveConflicts(string? error) => error is "user_policy_changed_reopen_settings"
        or "settings_ui_preferences_changed" or "settings_ui_preferences_save_outcome_unknown";

    internal static void RequireResidentTierChange(bool standalone)
    {
        if (standalone) throw new Boundary("settings_live_broker_required");
    }

    internal static void RequireDiagnosticRole(bool ordinary)
    {
        if (ordinary) throw new Boundary("uac_diagnostic_requires_admin_tier");
    }

    internal static void ShowHandoff(IntPtr owner, BrokerState core, SettingsSurfaceHandoff snapshot)
    {
        if (Native.IsWindow(window)) throw new Boundary("settings_handoff_surface_busy");
        var current = UserPermissions.Read();
        ValidateRoleHandoff(snapshot, current.UserSid);
        try { Create(owner, core, current, true, snapshot); RoleDraftRecovery.AcceptImported(); }
        catch { CloseAfterFailure(); throw; }
    }

    private static void ApplyRoleSurface(SettingsSurfaceHandoff snapshot, UserPermissionSettings current)
    {
        var retained = RetainRoleSurface(current, snapshot); var value = retained.Draft;
        bool hadConflict = conflict;
        original = current; controlBaseline = UserPermissions.Effective(current);
        policyValid = !current.Revision.StartsWith("invalid:", StringComparison.Ordinal);
        fullyDisabled = UserPermissions.TierOf(current) < 0;
        var effective = UserPermissions.Effective(value);
        Check(1, effective.AdminWindows); Check(78, effective.AdminLaunchEnabled); Check(79, effective.UacMode != "off");
        launchMode = value.AdminLaunchMode; uacMode = effective.UacMode; uacCancellationScope = value.UacCancellationScope;
        Check(4, value.JevEnabled); Check(6, value.HudCompact);
        SendMessageW(controls[7], 0x14e, new IntPtr(Array.IndexOf(new[] { "auto", "top_left", "top_right", "bottom_left", "bottom_right" }, value.HudPosition)), IntPtr.Zero);
        SetWindowTextW(controls[11], Lines(value.DeniedApplications)); SetWindowTextW(controls[3402], Lines(value.DeniedAdminWindowApplications));
        deniedLaunchPrograms.Clear(); deniedLaunchPrograms.AddRange(value.DeniedAdminLaunchApplications);
        deniedUacPrograms.Clear(); deniedUacPrograms.AddRange(value.DeniedUacApplications);
        adminLaunchAllowlist.Clear(); adminLaunchAllowlist.AddRange(value.AdminLaunchAllowlist);
        uacAllowlist.Clear(); uacAllowlist.AddRange(value.UacAllowlist);
        masks.Clear(); masks.AddRange(value.Masks);
        uiPreference = snapshot.Preference; uacSubmode = snapshot.PreferredMode; uiBaselineSubmode = snapshot.ModeBaseline;
        uiPreferencePending = snapshot.PreferencePending;
        conflict = hadConflict || retained.Conflict;
        RefreshBlockedPrograms(ProgramListKind.Launch); RefreshBlockedPrograms(ProgramListKind.Uac);
        RefreshUacAllowlist(kind: ProgramListKind.Launch); RefreshUacAllowlist(); RefreshMasks();
        ShowPage((SettingsPage)snapshot.Page); UpdateUacControls(); PositionControls(); UpdateScroll();
        SetNotice(conflict ? "设置在交接时已被更改；原草稿保留，保存前请重新载入核对。"
            : "执行档位已切换；其它未保存更改已保留。");
    }

    private static void RequestExecutionTier(int target, bool toggle = true)
    {
        if (preview || broker is null)
        {
            if (target == 3) { RequestSystemTier(); return; }
            SetTier(toggle && CurrentTier() == target ? -1 : target); return;
        }
        RequireResidentTierChange(localSettings);
        if (!policyValid || surfaceFault || conflict || UacBusy) throw new Boundary("uac_settings_work_busy");
        EndUacWindowPick();
        var source = broker; var prior = original!; var surface = CaptureRoleHandoff();
        // Retired controls may still receive a native command. Cancellation
        // must keep their indicators on the actual role, not a draft role.
        var actual = UserPermissions.Effective(prior);
        fullyDisabled = UserPermissions.TierOf(prior) < 0;
        Check(1, actual.AdminWindows); Check(78, actual.AdminLaunchEnabled); Check(79, actual.UacMode != "off");
        uacMode = actual.UacMode;
        int chosen = ChosenExecutionTier(target, UserPermissions.TierOf(prior), source.OrdinaryResident, toggle);
        UserPermissionSettings? committed = null;
        try
        {
            if (SetTimer(window, ExecutionRoleReplyTimer, 100, IntPtr.Zero) == UIntPtr.Zero)
                throw new Boundary("permission_role_reply_unavailable");
            changingExecutionRole = true;
            BeginUacWork("tier", token =>
            {
                if (source.OrdinaryResident)
                {
                    committed = LocalUiWriter.Execute(source, new("tier", prior.Revision, Tier: chosen), surface, token).Current;
                    return;
                }
                source.BeginLocalTransition(token); bool switched = false;
                try
                {
                    token.ThrowIfCancellationRequested();
                    UserPermissions.RequireCurrentRevision(prior.Revision, UserPermissions.Read().Revision);
                    if (chosen == 3)
                    {
                        UacInstallation.PrepareForTierSelection(token);
                        if (!UacRuntime.Capabilities().AllowlistAvailable) throw new Boundary("uac_component_unavailable");
                    }
                    committed = UacInstallation.SaveSettings(UserPermissions.Effective(prior with { AuthorityTier = chosen }), source, token);
                    if (chosen <= 0) { RoleHandoff.ToOrdinary(source, surface, token); switched = true; }
                }
                finally { if (!switched) source.EndLocalTransition(); }
            }, () => committed, roleSurface: surface);
            EnableWindow(window, false);
            SetNotice(chosen <= 0 ? "正在保存普通权限并释放管理员执行器；其它草稿保留。"
                : source.OrdinaryResident ? "正在请求 Windows 管理员确认；取消会保留普通执行器和草稿。"
                : "正在切换管理员档位；其它草稿保留。");
        }
        catch { changingExecutionRole = false; if (window != IntPtr.Zero) { KillTimer(window, ExecutionRoleReplyTimer); EnableWindow(window, true); } throw; }
    }

    private static void CompleteExecutionTier(WorkReply reply)
    {
        changingExecutionRole = false;
        if (window != IntPtr.Zero) { KillTimer(window, ExecutionRoleReplyTimer); EnableWindow(window, true); }
        if (reply.Error is not null) return;
        if (reply.Saved is null || reply.RoleSurface is null) throw new Boundary("settings_handoff_invalid");
        var actual = UserPermissions.Read();
        ApplyRoleSurface(reply.RoleSurface, actual);
        if (actual.Revision != reply.Saved.Revision) { conflict = true; SetNotice("切换后设置又有变化；草稿保留，请重新载入核对。"); UpdateUacControls(); }
    }

    private static void PrepareRoleSource(BrokerState source, string revision, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (source.OrdinaryResident) LocalUiWriter.Execute(source, new("prepare", revision), null, cancellation);
        else UacInstallation.PrepareForTierSelection(cancellation);
    }

    private static void DisableRoleSource(BrokerState source, string revision, CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        if (source.OrdinaryResident) LocalUiWriter.Execute(source, new("disable", revision), null, cancellation);
        else { UacInstallation.Disable(); source.RefreshPermissions(); }
    }
}
