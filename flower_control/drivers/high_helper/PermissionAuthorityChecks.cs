namespace Flower.HighHelper;

internal static partial class PermissionSettingsWindow
{
    // Hidden synthetic settings; never read/write the installed policy or
    // dispatch real input, register tasks, invoke SYSTEM, or change focus.
    internal static object NativeAuthorityProbe()
    {
        int assertions = 0;
        void Require(bool value, [System.Runtime.CompilerServices.CallerArgumentExpression("value")] string assertion = "")
        {
            assertions++;
            if (!value)
            {
                Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { fixture = "settings-authority", assertions, assertion }));
                throw new Boundary("permission_authority_probe_failed");
            }
        }
        bool previousPreview = preview;
        var saved = new UserPermissionSettings {
            UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            AuthorityTier = 3, AdminWindows = true, AdminLaunchEnabled = true,
            AdminLaunchMode = "semantic", UacMode = "allowlist",
            DeniedAdminWindowApplications = [new(@"C:\Fixture\admin-window.exe", "private", false)],
            DeniedAdminLaunchApplications = [new(@"C:\Fixture\blocked-launch.exe", "sha256", new string('a', 64), "blocked launch")],
            DeniedUacApplications = [new(@"C:\Fixture\blocked-uac.exe", "sha256", new string('b', 64), "blocked uac")]
        };
        try
        {
            preview = true;
            Create(IntPtr.Zero, null, saved, false);
            Require(!IsWindowVisible(window));
            Require(CurrentTier() == 3);
            Require(EditedSettings().AdminLaunchMode == "semantic" && EditedSettings().UacMode == "allowlist");
            ShowPage(SettingsPage.Admin);
            Require(new[] { 3301, 3302, 3303, 3304 }.All(activeLayout!.Controls.ContainsKey));
            Require(new[] { 1, 78, 79 }.All(id => !activeLayout!.Controls.ContainsKey(id)));
            Require(activeLayout!.Controls.ContainsKey(3402));
            Require(EditedSettings().DeniedAdminWindowApplications.SequenceEqual(saved.DeniedAdminWindowApplications));
            SetWindowTextW(controls[3402], @"C:\Fixture\new-admin.exe | blocked");
            Require(EditedSettings().DeniedAdminWindowApplications is [{ TitleContains: "blocked", Enabled: true }]);
            Require(EditedSettings().DeniedApplications.Length == 0);
            ShowPage(SettingsPage.Launch);
            Require(new[] { 3311, 3312 }.All(activeLayout!.Controls.ContainsKey));
            // Exercise the production enablement branch against the owned
            // hidden controls; do not read/write the installed policy.
            original = saved with { AdminLaunchMode = "allowlist" };
            preview = false;
            Check(79, false); // Native 03, without enabling the SYSTEM tier.
            Require(CurrentTier() == 2);
            UpdateTierControls(true);
            Require((GetWindowLongW(controls[3312], -16) & 0x08000000) == 0);
            UpdateTierControls(false);
            Require((GetWindowLongW(controls[3312], -16) & 0x08000000) != 0);
            original = saved; preview = true; Check(79, true); UpdateTierControls(true);
            Require(activeLayout!.Controls.ContainsKey(3412));
            ShowPage(SettingsPage.Uac);
            Require(new[] { 3321, 3322 }.All(activeLayout!.Controls.ContainsKey));
            Require(activeLayout!.Controls.ContainsKey(3422));
            Require(EditedSettings().DeniedAdminLaunchApplications.SequenceEqual(saved.DeniedAdminLaunchApplications));
            Require(EditedSettings().DeniedUacApplications.SequenceEqual(saved.DeniedUacApplications));
            RefreshBlockedPrograms(ProgramListKind.Launch, 0);
            // Real LISTBOX selection is LBN_SELCHANGE (high word 1), not a
            // button notification. Exercise the actual WM_COMMAND route.
            RefreshBlockedPrograms(ProgramListKind.Launch);
            UpdateBlockedProgramControls(true);
            Require((GetWindowLongW(controls[3414], -16) & 0x08000000) != 0);
            SendMessageW(controls[3412], 0x186, IntPtr.Zero, IntPtr.Zero);
            HandleMessage(window, 0x111, new UIntPtr((1u << 16) | 3412u), controls[3412]);
            Require((GetWindowLongW(controls[3414], -16) & 0x08000000) == 0);
            EditBlockedProgram(ProgramListKind.Launch, remove: false);
            Require(!EditedSettings().DeniedAdminLaunchApplications[0].Enabled);
            Require(EditedSettings().DeniedUacApplications[0].Enabled);
            RefreshBlockedPrograms(ProgramListKind.Uac, 0);
            EditBlockedProgram(ProgramListKind.Uac, remove: true);
            Require(EditedSettings().DeniedUacApplications.Length == 0);
            Require(saved.DeniedUacApplications.Length == 1 && saved.DeniedAdminLaunchApplications[0].Enabled);
            HandleMessage(window, 0x111, new UIntPtr(3322), controls[3322]);
            Require(EditedSettings().UacMode == "semantic");
            HandleMessage(window, 0x111, new UIntPtr(3311), controls[3311]);
            Require(EditedSettings().AdminLaunchMode == "allowlist" && EditedSettings().UacMode == "semantic");
            SetTier(2);
            Require(EditedSettings().UacMode == "off");
            SetTier(3);
            Require(EditedSettings().UacMode == "semantic" && EditedSettings().AdminLaunchMode == "allowlist");
            ReloadSaved();
            Require(EditedSettings().AdminLaunchMode == "semantic" && EditedSettings().UacMode == "allowlist");
            Require(!Dirty);
            Require(EditedSettings().DeniedAdminWindowApplications.SequenceEqual(saved.DeniedAdminWindowApplications));
            Require(EditedSettings().DeniedAdminLaunchApplications.SequenceEqual(saved.DeniedAdminLaunchApplications));
            Require(EditedSettings().DeniedUacApplications.SequenceEqual(saved.DeniedUacApplications));
            Require(UserPermissions.AdminLaunchDenied(EditedSettings(), @"C:\Fixture\blocked-launch.exe"));
            Require(!UserPermissions.AdminLaunchDenied(EditedSettings(), @"C:\Fixture\blocked-uac.exe"));
            Require(UserPermissions.UacPromptDenied(EditedSettings(), @"C:\Fixture\blocked-uac.exe"));
            var revoked = UserPermissions.Effective(UacInstallation.SettingsTransition(saved, "off", false, "revoked"));
            Require(revoked.AuthorityTier == 1 && revoked.AdminWindows && !revoked.AdminLaunchEnabled && revoked.UacMode == "off");
            var final = UserPermissions.Effective(UacInstallation.SettingsTransition(saved, "allowlist", true, "enabled"));
            Require(final.AuthorityTier == 3 && final.AdminLaunchEnabled && final.UacMode == "allowlist");
            var noUac = UserPermissions.Effective(UserPermissions.WithoutUac(saved));
            Require(noUac.AuthorityTier == 2 && noUac.AdminWindows && noUac.AdminLaunchEnabled && noUac.UacMode == "off");
            Require(OnlyUacDisabled(saved, noUac));
            Require(UserPermissions.Effective(UacInstallation.SettingsTransition(saved with { AuthorityTier = -1 }, "off", false, "disabled")).AuthorityTier == -1);
            SetTier(-1);
            Require(EditedSettings().AuthorityTier == -1);
            ReloadSaved();
            Require(CurrentTier() == 3 && !Dirty);
            Require(original == saved);
            SetTier(1);
            Require(!CompleteSystemTierPreparation(saved, saved, new(false, false, false, false, "unverified")));
            Require(CurrentTier() == 1 && !conflict);
            Require(!CompleteSystemTierPreparation(saved, saved with { Revision = "other-writer" }, new(true, true, false, true, "verified")));
            Require(CurrentTier() == 1 && conflict);
            ReloadSaved(); SetTier(1);
            Require(CompleteSystemTierPreparation(saved, saved, new(true, true, false, true, "verified")));
            Require(CurrentTier() == 3 && original == saved);
            SetTier(1);
            EnableWindow(controls[30], false); EnableWindow(controls[3301], false);
            long preparationToken = ++workGeneration;
            uacReplies[preparationToken] = new(windowGeneration, "prepare_tier", null, saved);
            WindowProc(window, UacWorkFinished, new UIntPtr((ulong)preparationToken), IntPtr.Zero);
            Require(CurrentTier() == 1);
            Require((GetWindowLongW(controls[30], -16) & 0x08000000) == 0);
            Require((GetWindowLongW(controls[3301], -16) & 0x08000000) == 0);
            assertions += AuthorityStorageChecks.Run();
            return new { fixture = "settings-authority", assertions, hiddenWindow = true,
                productionPolicyReadOrWritten = false, temporaryPolicyStorageChecked = true,
                nativeInputDispatched = false, systemTaskPrepared = false };
        }
        finally { CloseAfterFailure(); preview = previousPreview; }
    }
}
