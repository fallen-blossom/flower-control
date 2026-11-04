using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using System.Diagnostics;
using System.Security.AccessControl;

namespace Flower.HighHelper;

// Invoked only by the local settings window running in the verified user High
// broker. No MCP command may prepare, replace or disable this SYSTEM entry.
internal static class UacInstallation
{
    private sealed class LifecycleLock : IDisposable
    {
        private readonly Mutex mutex;
        internal LifecycleLock(string sid)
        {
            mutex = new Mutex(false, "Local\\FlowerControl.UacLifecycle." + sid);
            bool held; try { held = mutex.WaitOne(2000); } catch (AbandonedMutexException) { held = true; }
            if (!held) { mutex.Dispose(); throw new Boundary("uac_lifecycle_busy"); }
        }
        public void Dispose() { mutex.ReleaseMutex(); mutex.Dispose(); }
    }
    internal static IDisposable LockLifecycle(BrokerPolicy policy) => new LifecycleLock(policy.UserSid);
    internal static string TaskSecurity(string sid, bool experiment = false) => "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        + (experiment ? "(A;;GRGX;;;" + sid + ")" : "");
    internal static void RequireTaskSecurity(string descriptor, string sid)
    {
        var security = new RawSecurityDescriptor(descriptor);
        if (security.Owner?.Value is not ("S-1-5-18" or "S-1-5-32-544") || security.DiscretionaryAcl is null)
            throw new Boundary("uac_task_security_rejected");
        foreach (GenericAce ace in security.DiscretionaryAcl)
        {
            if (ace is not CommonAce common || common.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))
                throw new Boundary("uac_task_security_rejected");
            if (common.AceQualifier == AceQualifier.AccessAllowed && common.SecurityIdentifier.Value is not ("S-1-5-18" or "S-1-5-32-544")
                && (common.SecurityIdentifier.Value != sid || (common.AccessMask & UserPermissions.PolicyMutationRights) != 0))
                throw new Boundary("uac_task_security_rejected");
        }
    }
    internal static bool MissingTask(Exception error) => unchecked((uint)error.HResult) == 0x80070002;
    internal static string RenderTask(string application)
    {
        if (!Path.IsPathFullyQualified(application) || application.Contains('"')) throw new Boundary("uac_install_path_rejected");
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        XElement Node(string name, object value) => new(ns + name, value);
        return new XDocument(new XElement(ns + "Task", new XAttribute("version", "1.4"),
            Node("RegistrationInfo", Node("Description", "Flower Control UAC：按需短进程，无登录或定时触发。")),
            new XElement(ns + "Triggers"),
            Node("Principals", new XElement(ns + "Principal", new XAttribute("id", "System"),
                Node("UserId", "S-1-5-18"), Node("RunLevel", "HighestAvailable"))),
            Node("Settings", new object[] { Node("MultipleInstancesPolicy", "IgnoreNew"),
                Node("DisallowStartIfOnBatteries", false), Node("StopIfGoingOnBatteries", false),
                Node("AllowHardTerminate", true), Node("StartWhenAvailable", false),
                Node("RunOnlyIfNetworkAvailable", false), Node("Enabled", false), Node("Hidden", false),
                Node("ExecutionTimeLimit", "PT1M"), Node("Priority", 7) }),
            new XElement(ns + "Actions", new XAttribute("Context", "System"), Node("Exec", new object[] {
                Node("Command", application), Node("Arguments", "--uac-bootstrap"), Node("WorkingDirectory", Path.GetDirectoryName(application)!) })))).ToString();
    }
    internal static void RequireTask(string xml, string application)
    {
        var document = XDocument.Parse(xml);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var actions = document.Descendants(ns + "Actions").Elements().ToArray();
        if (actions.Length != 1 || actions[0].Name != ns + "Exec"
            || actions[0].Element(ns + "Command")?.Value != application
            || actions[0].Element(ns + "Arguments")?.Value != "--uac-bootstrap"
            || actions[0].Element(ns + "WorkingDirectory")?.Value != Path.GetDirectoryName(application)
            || document.Descendants(ns + "UserId").SingleOrDefault()?.Value != "S-1-5-18"
            || document.Descendants(ns + "Triggers").Any(row => row.HasElements)
            || document.Descendants(ns + "ExecutionTimeLimit").SingleOrDefault()?.Value != "PT1M")
            throw new Boundary("uac_registered_action_mismatch");
    }
    private static BrokerPolicy Context()
    {
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        var own = Native.Process(Environment.ProcessId).Identity;
        if (policy.Fixture || own.User != policy.UserSid || own.Integrity != 12288 || Native.UiAccess(own.Pid)
            || own.ImageDigest != Native.Digest(Path.Combine(policy.Directory, "Flower.HighHelper.exe")))
            throw new Boundary("uac_install_local_high_required");
        return policy;
    }
    internal static void Prepare()
    {
        var policy = Context();
        using var lifecycle = new LifecycleLock(policy.UserSid);
        UacStateStorage.Directory(policy, true);
        UserPermissions.CheckSystemExecutableProtection(Path.Combine(policy.Directory, "Flower.HighHelper.exe"));
        // Loading and verifying the sealed DLL is part of preparation, never
        // evidence of safe-desktop input or semantic permission readiness.
        _ = UacNativeBridge.PublisherIdentity(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "consent.exe"));
        var application = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        var xml = RenderTask(application); RequireTask(xml, application);
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new Boundary("uac_task_scheduler_unavailable");
        dynamic scheduler = Activator.CreateInstance(type)!;
        try
        {
            scheduler.Connect(); dynamic folder = scheduler.GetFolder("\\");
            try
            {
                // TASK_CREATE never silently rewrites a different existing entry.
                // A matching existing entry is idempotent; an upgrade has to use
                // the normal versioned update path rather than overwrite it here.
                dynamic? existing = null;
                try { existing = folder.GetTask(UacRuntime.TaskName(policy.UserSid)); }
                catch (Exception error) when (MissingTask(error)) { }
                if (existing is not null)
                { try { RequireTask((string)existing.Xml, application); existing.Enabled = false;
                    existing.SetSecurityDescriptor(TaskSecurity(policy.UserSid), 0x10); RequireTaskSecurity((string)existing.GetSecurityDescriptor(7), policy.UserSid); return;
                    } finally { Marshal.ReleaseComObject(existing); } }
                var security = TaskSecurity(policy.UserSid);
                dynamic task = folder.RegisterTask(UacRuntime.TaskName(policy.UserSid), xml, 2,
                    "S-1-5-18", null, 5, security);
                try { RequireTask((string)task.Xml, application); task.SetSecurityDescriptor(security, 0x10); RequireTaskSecurity((string)task.GetSecurityDescriptor(7), policy.UserSid); }
                finally { Marshal.ReleaseComObject(task); }
            }
            finally { Marshal.ReleaseComObject(folder); }
        }
        finally { Marshal.ReleaseComObject(scheduler); }
    }
    internal static void Disable()
    {
        var policy = Context();
        using var lifecycle = new LifecycleLock(policy.UserSid);
        try { var settings = UserPermissions.Read(); if (settings.UacMode != "off") UserPermissions.Save(UserPermissions.WithoutUac(settings)); }
        finally { SetEnabled(false); }
    }
    internal static void PrepareForTierSelection(CancellationToken cancellation)
    {
        cancellation.ThrowIfCancellationRequested();
        throw new Boundary("host_uac_feature_retired");
    }
    internal static UserPermissionSettings SaveSettings(UserPermissionSettings value, BrokerState core, CancellationToken cancellation = default)
    {
        UserPermissions.Validate(value);
        if (value.UacMode == "semantic") throw new Boundary("semantic_privilege_authorization_removed");
        value = UserPermissions.Effective(value);
        var policy = Context(); using var lifecycle = new LifecycleLock(policy.UserSid);
        bool preparedSystemEntry = false;
        string savedRevision = SaveSettingsCore(value, cancellation, () => UserPermissions.Read().Revision,
            (mode, launchEnabled, revision) => UserPermissions.Save(SettingsTransition(value, mode, launchEnabled, revision)),
            () => preparedSystemEntry = HasPreparedSystemEntry(policy),
            (enabled, revision) => { if (!enabled) SetEnabled(false, revision); },
            core.RefreshPermissions, () => CancelSettingsRequests(core));
        // A normal mode selection may have minted local-only metadata. Return
        // that exact commit rather than the old draft's ignored/null marker.
        return UserPermissions.WithCurrentPolicy(value.UserSid, savedRevision, () => {
            var committed = UserPermissions.Read();
            UserPermissions.RequireCurrentRevision(savedRevision, committed.Revision);
            return committed;
        });
    }
    internal static UserPermissionSettings ConfirmSemanticDelegation(string expectedRevision, BrokerState core, CancellationToken cancellation)
    {
        var policy = Context(); using var lifecycle = new LifecycleLock(policy.UserSid);
        cancellation.ThrowIfCancellationRequested();
        var committed = UserPermissions.ConfirmSemanticDelegation(expectedRevision);
        core.RefreshPermissions();
        return committed;
    }
    internal static UserPermissionSettings SettingsTransition(UserPermissionSettings value, string mode, bool launchEnabled, string revision)
        => (mode == "off" && !launchEnabled ? UserPermissions.WithoutElevatedExecution(value) : value) with {
            UacMode = mode, AdminLaunchEnabled = launchEnabled, Revision = revision
            // The ladder is authoritative. Revoking legacy booleans alone is
            // undone by Effective(); lower the ladder for the off-first write
            // and its compensating revoke while preserving ordinary/High windows.
        };
    private static void CancelSettingsRequests(BrokerState core)
    {
        core.CancelUacRequests("privilege_settings_changed");
        core.CancelAdminLaunchRequests("privilege_settings_changed");
    }
    // The UAC setting alone may re-enable an already prepared exact-version
    // SYSTEM entry. High's independent launch setting never prepares/enables it.
    private static bool HasPreparedSystemEntry(BrokerPolicy policy)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new Boundary("uac_task_scheduler_unavailable");
        dynamic scheduler = Activator.CreateInstance(type)!;
        try
        {
            scheduler.Connect(); dynamic folder = scheduler.GetFolder("\\");
            try
            {
                dynamic task;
                try { task = folder.GetTask(UacRuntime.TaskName(policy.UserSid)); }
                catch (Exception error) when (MissingTask(error)) { return false; }
                try
                {
                    RequireTaskSecurity((string)task.GetSecurityDescriptor(7), policy.UserSid);
                    try { RequireTask((string)task.Xml, Path.Combine(policy.Directory, "Flower.HighHelper.exe")); }
                    catch (Boundary error) when (error.Code == "uac_registered_action_mismatch") { return false; }
                    return true;
                }
                finally { Marshal.ReleaseComObject(task); }
            }
            finally { Marshal.ReleaseComObject(folder); }
        }
        finally { Marshal.ReleaseComObject(scheduler); }
    }
    // A narrow seam for the existing settings lifecycle. Production supplies only
    // the fixed local operations above; tests supply owned storage and fake tasks.
    private static string SaveSettingsCore(UserPermissionSettings value, CancellationToken cancellation,
        Func<string> readRevision, Func<string, bool, string, string> savePermissions, Action prepare,
        Action<bool, string?> setEntry, Action refreshPermissions, Action cancelRequests)
    {
        UserPermissions.Validate(value);
        if (value.UacMode == "semantic") throw new Boundary("semantic_privilege_authorization_removed");
        value = UserPermissions.Effective(value);
        UserPermissions.RequireCurrentRevision(value.Revision, readRevision());
        // Revoke before waiting for existing executors, including when changing
        // between enabled modes. Failed activation leaves both new privileges off.
        string? knownOffRevision = null, ownedEnabledRevision = null;
        bool enableSaveStarted = false;
        try
        {
            knownOffRevision = savePermissions("off", false, value.Revision);
            cancelRequests(); refreshPermissions(); setEntry(false, null);
            if (value.UacMode == "off" && !value.AdminLaunchEnabled) return knownOffRevision;
            cancellation.ThrowIfCancellationRequested();
            if (value.UacMode != "off") prepare();
            cancellation.ThrowIfCancellationRequested();
            enableSaveStarted = true;
            ownedEnabledRevision = savePermissions(value.UacMode, value.AdminLaunchEnabled, knownOffRevision);
            knownOffRevision = null;
            refreshPermissions();
            cancellation.ThrowIfCancellationRequested();
            if (value.UacMode != "off") setEntry(true, ownedEnabledRevision);
            UserPermissions.RequireCurrentRevision(ownedEnabledRevision, readRevision());
            return ownedEnabledRevision;
        }
        catch (Exception original)
        {
            var recoveryErrors = new List<Exception>();
            void Recover(string stage, Action action)
            {
                try { action(); }
                catch (Exception error) { error.Data["UacSettingsRecoveryStage"] = stage; recoveryErrors.Add(error); }
            }
            if (ownedEnabledRevision is null && enableSaveStarted
                && original is Boundary { Code: "user_policy_save_outcome_unknown" }
                && original.Data["UserPermissionAttemptedRevision"] is string attempted
                && System.Text.RegularExpressions.Regex.IsMatch(attempted, "\\A[a-f0-9]{64}\\z"))
                ownedEnabledRevision = attempted;
            if (ownedEnabledRevision is not null)
            {
                // CAS only this attempt's exact commit. A fresh reader must not
                // lend us another writer's revision for the compensating off.
                knownOffRevision = null;
                Recover("revoke_owned_enabled_revision", () => knownOffRevision = savePermissions("off", false, ownedEnabledRevision));
            }
            else if (enableSaveStarted)
            {
                // Save may have committed before reporting unknown. Its missing
                // return value is never evidence that the earlier off survived.
                knownOffRevision = null;
            }
            // Every cleanup is attempted independently, even if revocation,
            // refresh or cancellation fails. Task disable includes its readback.
            Recover("cancel_requests", cancelRequests);
            Recover("refresh_permissions", refreshPermissions);
            Recover("disable_entry", () => setEntry(false, null));
            var expectedOffRevision = knownOffRevision;
            if (expectedOffRevision is not null)
                Recover("verify_owned_off_revision", () => UserPermissions.RequireCurrentRevision(expectedOffRevision, readRevision()));
            if (knownOffRevision is not null && recoveryErrors.Count == 0) throw;
            var uncertain = new Boundary("user_policy_save_outcome_unknown");
            uncertain.Data["OriginalError"] = original;
            uncertain.Data["OriginalErrorMessage"] = original.Message;
            uncertain.Data["OwnedEnabledRevision"] = ownedEnabledRevision ?? "not_returned";
            if (original.Data["UserPermissionAttemptedRevision"] is string attemptedRevision)
                uncertain.Data["UserPermissionAttemptedRevision"] = attemptedRevision;
            uncertain.Data["RecoveryErrors"] = recoveryErrors.ToArray();
            Console.Error.WriteLine("user_policy_save_outcome_unknown: original=" + original.Message
                + "; recovery=" + string.Join(",", recoveryErrors.Select(error => error.Data["UacSettingsRecoveryStage"] + ":" + error.Message)));
            throw uncertain;
        }
    }
    internal static void ReconcileOff(BrokerPolicy policy, BrokerState core)
    {
        using var lifecycle = new LifecycleLock(policy.UserSid);
        if (!policy.Fixture && UserPermissions.Read().UacMode == "off")
        { core.CancelUacRequests("uac_disabled"); SetEnabled(false); }
    }
    internal static void ActivatePrepared()
    { var policy = Context(); using var lifecycle = new LifecycleLock(policy.UserSid);
        var settings = UserPermissions.Read(); if (settings.UacMode == "off") throw new Boundary("uac_disabled"); SetEnabled(true, settings.Revision); }
    private sealed record LegacyDiagnostic(string Suffix, string Command, string ArgumentsSha256);
    // Exact actions recorded by the local read-only inventory on 2026-10-15.
    // These entries may only be revoked; their scripts are never opened or run.
    private static LegacyDiagnostic[] LegacyDiagnostics() => [
        new(".LabelDiagnostic.20261014", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe"),
            "928dbce5e38f727a1d0c211801f76f4ea28ff40f0b6cb55f56e5296261afcaf9"),
        new(".LabelRepair.20261014", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"),
            "c615d04959761a5e9016690cb63c1b691b4375c7aeee00fd1108a9618c7b2e2f")];
    internal static string[] ControlledTaskNames(string sid, bool enabled) => enabled
        ? [UacRuntime.TaskName(sid), ExperimentTaskName(sid)]
        : [UacRuntime.TaskName(sid), ExperimentTaskName(sid), ..LegacyDiagnostics().Select(row => UacRuntime.TaskName(sid) + row.Suffix)];
    internal static void RequireLegacyDiagnosticIdentity(string name, string command, string argumentsSha256, string sid)
    {
        var identity = LegacyDiagnostics().SingleOrDefault(row => name == UacRuntime.TaskName(sid) + row.Suffix);
        if (identity is null || !command.Equals(identity.Command, StringComparison.OrdinalIgnoreCase)
            || argumentsSha256 != identity.ArgumentsSha256) throw new Boundary("uac_legacy_diagnostic_task_mismatch");
    }
    internal static void RequireLegacyDiagnosticTask(string xml, string name, string sid)
    {
        var document = XDocument.Parse(xml); XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var actions = document.Descendants(ns + "Actions").Elements().ToArray();
        if (document.Root?.Name != ns + "Task" || actions.Length != 1 || actions[0].Name != ns + "Exec"
            || document.Descendants(ns + "Principal").Count() != 1
            || document.Descendants(ns + "UserId").SingleOrDefault()?.Value != "S-1-5-18"
            || document.Descendants(ns + "RunLevel").SingleOrDefault()?.Value != "HighestAvailable"
            || document.Descendants(ns + "Triggers").Any(row => row.HasElements))
            throw new Boundary("uac_legacy_diagnostic_task_mismatch");
        var command = actions[0].Elements(ns + "Command").SingleOrDefault()?.Value;
        var arguments = actions[0].Elements(ns + "Arguments").SingleOrDefault()?.Value;
        if (command is null || arguments is null) throw new Boundary("uac_legacy_diagnostic_task_mismatch");
        RequireLegacyDiagnosticIdentity(name, command, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(arguments))).ToLowerInvariant(), sid);
    }
    internal static void SetVerifiedTaskState(bool enabled, Action validate, Action<bool> setEnabled, Func<bool> readEnabled,
        Func<int> runningCount, Func<long> tick, Action wait)
    {
        validate();
        setEnabled(enabled);
        if (readEnabled() != enabled) throw new Boundary("uac_entry_state_unverified");
        if (enabled) return;
        long deadline = tick() + 12000;
        while (runningCount() != 0)
        {
            if (tick() >= deadline) throw new Boundary("uac_disable_executors_pending");
            wait();
        }
    }
    private static void SetEnabled(bool enabled, string? expectedRevision = null)
    {
        if (enabled) throw new Boundary("host_uac_feature_retired");
        var policy = Context();
        var ownedImages = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Path.Combine(policy.Directory, "Flower.HighHelper.exe") };
        var failures = new List<string>();
        if (enabled && UserPermissions.Read().UacMode == "off") throw new Boundary("uac_disabled");
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new Boundary("uac_task_scheduler_unavailable");
        dynamic scheduler = Activator.CreateInstance(type)!;
        try
        {
            scheduler.Connect(); dynamic folder = scheduler.GetFolder("\\");
            try
            {
                foreach (var name in ControlledTaskNames(policy.UserSid, enabled))
                {
                    dynamic? task = null;
                    try
                    {
                        try { task = folder.GetTask(name); }
                        catch (Exception error) when (MissingTask(error)) { if (enabled && name == UacRuntime.TaskName(policy.UserSid)) throw; else continue; }
                        void ValidateEntry()
                        {
                            // Check existing ownership before changing anything. Revocation
                            // must never repair an untrusted ACL and then claim ownership.
                            RequireTaskSecurity((string)task.GetSecurityDescriptor(7), policy.UserSid);
                            bool legacy = name != UacRuntime.TaskName(policy.UserSid) && name != ExperimentTaskName(policy.UserSid);
                            if (legacy) RequireLegacyDiagnosticTask((string)task.Xml, name, policy.UserSid);
                            // Accept an older sealed version only for revocation.
                            // Enabling is always the exact current installed image.
                            var application = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
                            if (!enabled && !legacy)
                            {
                                XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
                                var action = XDocument.Parse((string)task.Xml).Descendants(ns + "Command").SingleOrDefault()?.Value;
                                var versions = Path.Combine(InstallationLocation.Current().ProgramRoot, "versions");
                                var version = Path.GetFileName(Path.GetDirectoryName(action ?? ""));
                                if (action is null || !System.Text.RegularExpressions.Regex.IsMatch(version ?? "", "\\A[a-f0-9]{16,64}\\z")
                                    || !action.Equals(Path.Combine(versions, version!, "Flower.HighHelper.exe"), StringComparison.OrdinalIgnoreCase))
                                    throw new Boundary("uac_registered_action_mismatch");
                                application = action;
                            }
                            if (!legacy)
                            {
                                if (name == ExperimentTaskName(policy.UserSid)) RequireExperimentTask((string)task.Xml, application, policy.UserSid);
                                else RequireTask((string)task.Xml, application);
                                ownedImages.Add(application);
                            }
                            if (enabled)
                            {
                                task.SetSecurityDescriptor(TaskSecurity(policy.UserSid, name == ExperimentTaskName(policy.UserSid)), 0x10);
                                RequireTaskSecurity((string)task.GetSecurityDescriptor(7), policy.UserSid);
                            }
                            if (enabled) UserPermissions.RequireCurrentRevision(expectedRevision!, UserPermissions.Read().Revision);
                        }
                        int RunningCount()
                        {
                            dynamic running = task.GetInstances(0);
                            try { return (int)running.Count; } finally { Marshal.ReleaseComObject(running); }
                        }
                        SetVerifiedTaskState(enabled, ValidateEntry, value => task.Enabled = value,
                            () => (bool)task.Enabled, RunningCount, () => Environment.TickCount64, () => Thread.Sleep(25));
                    }
                    catch (Exception error) when (!enabled)
                    { failures.Add(name + ":" + Program.Code(error)); }
                    finally { if (task is not null) Marshal.ReleaseComObject(task); }
                }
            }
            finally { Marshal.ReleaseComObject(folder); }
        }
        finally { Marshal.ReleaseComObject(scheduler); }
        if (!enabled)
        {
            var deadline = Environment.TickCount64 + 12000;
            while (true)
            {
                bool live = false;
                foreach (var process in Process.GetProcessesByName("Flower.HighHelper"))
                using (process)
                {
                    try
                    {
                        var peer = Native.Process(process.Id, digestImage: false);
                        if (peer.Identity.User != "S-1-5-18") continue;
                        if (ownedImages.Contains(peer.Image)) { live = true; continue; }
                        // A prior version's task may already have been replaced
                        // while its separate worker still exists. Inventory the
                        // protected installation rather than trusting task paths.
                        var versions = Path.Combine(InstallationLocation.Current().ProgramRoot, "versions");
                        if (!peer.Image.StartsWith(versions + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;
                        BrokerPolicy.RejectLinks(peer.Image);
                        var oldDirectory = Path.GetDirectoryName(peer.Image)!;
                        var oldVersion = Path.GetFileName(oldDirectory);
                        if (!System.Text.RegularExpressions.Regex.IsMatch(oldVersion, "\\A[a-f0-9]{16,64}\\z")
                            || !peer.Image.Equals(Path.Combine(versions, oldVersion, "Flower.HighHelper.exe"), StringComparison.OrdinalIgnoreCase))
                            throw new Boundary("uac_disable_executor_unverified");
                        var oldPolicyPath = Path.Combine(oldDirectory, "broker.json");
                        UserPermissions.CheckProtection(oldPolicyPath);
                        using var oldPolicy = JsonDocument.Parse(File.ReadAllBytes(oldPolicyPath)); Protocol.CheckUnique(oldPolicy);
                        if (oldPolicy.RootElement.GetProperty("Version").GetString() != oldVersion) throw new Boundary("uac_disable_executor_unverified");
                        if (oldPolicy.RootElement.GetProperty("UserSid").GetString() == policy.UserSid) live = true;
                    }
                    catch { if (!process.HasExited) throw new Boundary("uac_disable_executor_unverified"); }
                }
                if (!live) break;
                if (Environment.TickCount64 >= deadline) throw new Boundary("uac_disable_executors_pending");
                Thread.Sleep(25);
            }
        }
        if (failures.Count != 0)
        {
            var error = new Boundary("uac_disable_entries_unverified");
            error.Data["UacDisableEntries"] = failures.ToArray();
            throw error;
        }
    }
    internal static string ExperimentTaskName(string sid) => UacRuntime.TaskName(sid) + ".Experiment";
    internal static void RequireExperimentQuiescent()
    {
        var policy = Context();
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new Boundary("uac_task_scheduler_unavailable");
        dynamic scheduler = Activator.CreateInstance(type)!;
        try
        {
            scheduler.Connect(); dynamic folder = scheduler.GetFolder("\\");
            try
            {
                dynamic task;
                try { task = folder.GetTask(ExperimentTaskName(policy.UserSid)); }
                catch (Exception error) when (MissingTask(error)) { return; }
                try
                {
                    RequireExperimentTask((string)task.Xml, Path.Combine(policy.Directory, "Flower.HighHelper.exe"), policy.UserSid);
                    RequireTaskSecurity((string)task.GetSecurityDescriptor(7), policy.UserSid);
                    dynamic instances = task.GetInstances(0);
                    try { if ((int)instances.Count != 0) throw new Boundary("uac_original_work_still_running"); }
                    finally { Marshal.ReleaseComObject(instances); }
                }
                finally { Marshal.ReleaseComObject(task); }
            }
            finally { Marshal.ReleaseComObject(folder); }
        }
        finally { Marshal.ReleaseComObject(scheduler); }
    }
    internal static void RequireExperimentTask(string xml, string application, string sid)
    {
        var document = XDocument.Parse(xml); XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var actions = document.Descendants(ns + "Actions").Elements().ToArray();
        if (actions.Length != 1 || actions[0].Name != ns + "Exec"
            || actions[0].Element(ns + "Command")?.Value != application
            || actions[0].Element(ns + "Arguments")?.Value != "--uac-local-experiment $(Arg0)"
            || actions[0].Element(ns + "WorkingDirectory")?.Value != Path.GetDirectoryName(application)
            || document.Descendants(ns + "UserId").SingleOrDefault()?.Value != sid
            || document.Descendants(ns + "LogonType").SingleOrDefault()?.Value != "InteractiveToken"
            || document.Descendants(ns + "RunLevel").SingleOrDefault()?.Value != "HighestAvailable"
            || document.Descendants(ns + "Triggers").Any(row => row.HasElements)
            || document.Descendants(ns + "ExecutionTimeLimit").SingleOrDefault()?.Value != "PT2M")
            throw new Boundary("uac_experiment_registered_action_mismatch");
    }
    internal static void PrepareExperiments()
    {
        var policy = Context(); using var lifecycle = new LifecycleLock(policy.UserSid);
        // Coexisting preparation must leave every known entry disabled, including
        // old fixed diagnostics that do not read the current production policy.
        // A drifted task or unconfirmed executor prevents preparation, not grants.
        SetEnabled(false);
        Prepare();
        var application = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var document = XDocument.Parse(RenderTask(application));
        document.Descendants(ns + "Description").Single().Value = "Flower Control 本批无害 UAC 实验；按需退出，不修改生产模式。";
        var principal = document.Descendants(ns + "Principal").Single();
        principal.Element(ns + "UserId")!.Value = policy.UserSid;
        principal.Add(new XElement(ns + "LogonType", "InteractiveToken"));
        document.Descendants(ns + "Arguments").Single().Value = "--uac-local-experiment $(Arg0)";
        document.Descendants(ns + "ExecutionTimeLimit").Single().Value = "PT2M";
        var xml = document.ToString(); RequireExperimentTask(xml, application, policy.UserSid);
        var type = Type.GetTypeFromProgID("Schedule.Service") ?? throw new Boundary("uac_task_scheduler_unavailable");
        dynamic scheduler = Activator.CreateInstance(type)!;
        try
        {
            scheduler.Connect(); dynamic folder = scheduler.GetFolder("\\");
            try
            {
                dynamic? existing = null;
                try { existing = folder.GetTask(ExperimentTaskName(policy.UserSid)); }
                catch (Exception error) when (MissingTask(error)) { }
                if (existing is not null)
                { try { RequireExperimentTask((string)existing.Xml, application, policy.UserSid); existing.Enabled = false;
                    existing.SetSecurityDescriptor(TaskSecurity(policy.UserSid, true), 0x10); RequireTaskSecurity((string)existing.GetSecurityDescriptor(7), policy.UserSid); return;
                    } finally { Marshal.ReleaseComObject(existing); } }
                var security = TaskSecurity(policy.UserSid, true);
                dynamic task = folder.RegisterTask(ExperimentTaskName(policy.UserSid), xml, 2, policy.UserSid, null, 3, security);
                try { RequireExperimentTask((string)task.Xml, application, policy.UserSid); task.SetSecurityDescriptor(security, 0x10);
                    RequireTaskSecurity((string)task.GetSecurityDescriptor(7), policy.UserSid); task.Enabled = false; }
                finally { Marshal.ReleaseComObject(task); }
            }
            finally { Marshal.ReleaseComObject(folder); }
        }
        finally { Marshal.ReleaseComObject(scheduler); }
    }
}
