using System.Reflection;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class AuthorityStorageChecks
{
    internal static int Run()
    {
        int assertions = 0;
        void Require(bool value)
        { assertions++; if (!value) throw new Boundary("authority_storage_probe_failed"); }
        object Invoke(string name, params object?[] args)
        {
            try { return typeof(UserPermissions).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, args)!; }
            catch (TargetInvocationException error) { throw error.InnerException!; }
        }
        string directory = Path.Combine(Path.GetTempPath(), "flower-authority-storage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "policy.json");
            string sid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
            var baseline = new UserPermissionSettings { UserSid = sid, AuthorityTier = 1 };
            File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(new {
                Schema = 1, Revision = "authority-fixture", UserSid = sid, AdminWindows = true, AdminScope = "all",
                UacEnabled = false, JevEnabled = false, baseline.DeniedApplications, baseline.AllowedAdminApplications,
                baseline.Masks, SmoothPointer = false, HudCompact = false, HudPosition = "auto"
            }));
            UserPermissionSettings Read()
            {
                object snapshot = Invoke("ReadStorage", path, sid, true);
                return UserPermissions.Effective((UserPermissionSettings)snapshot.GetType().GetProperty("Settings")!.GetValue(snapshot)!);
            }
            foreach (int tier in new[] { 2, 3 })
            {
                var before = Read();
                var enable = before with { AuthorityTier = tier, AdminLaunchEnabled = true, UacMode = tier == 3 ? "allowlist" : "off" };
                bool faultSeen = false;
                try
                {
                    Invoke("SaveStorage", enable, before.Revision, path, true, (Action<string>)(phase => {
                        if (phase == "after_uac") throw new IOException("synthetic committed-write failure");
                    }));
                }
                catch (Boundary error) when (error.Code == "user_policy_save_outcome_unknown") { faultSeen = true; }
                Require(faultSeen);
                var after = Read();
                Require(after.AdminWindows && !after.AdminLaunchEnabled && after.UacMode == "off" && after.AuthorityTier == 1);
            }
            return assertions;
        }
        finally { Directory.Delete(directory, true); }
    }
}
