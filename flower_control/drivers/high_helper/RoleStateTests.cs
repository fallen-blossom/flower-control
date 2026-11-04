using System.Diagnostics;
using System.Security.Principal;

namespace Flower.HighHelper;

// No production path, policy, Stop record, input or elevation is used. The
// shared objects below all have unique owned test namespaces.
internal static class RoleStateTests
{
    private sealed class AppendOnLength(string path, Action append) : FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)
    {
        private bool appended;
        public override long Length
        {
            get { long prior = base.Length; if (!appended) { appended = true; append(); } return prior; }
        }
    }
    internal static object Run()
    {
        int checks = 0;
        void Check(bool value) { ++checks; if (!value) throw new Boundary("role_state_selftest_failed"); }
        void Reject(Action action, string code)
        {
            try { action(); throw new Boundary("role_state_selftest_missing_rejection"); }
            catch (Boundary error) { Check(error.Code == code); }
        }
        string sid = WindowsIdentity.GetCurrent().User!.Value;
        var timers = new[] { "PickTimer", "OverviewTimer", "WorkCompletionTimer" }.Select(name =>
            (uint)typeof(SettingsWorkspace).GetField(name, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.GetRawConstantValue()!).ToArray();
        Check(timers.Distinct().Count() == timers.Length);
        var initial = new RoleStopSnapshot(new(false, 7, 3), new(1, sid, 1, false, 9), new(1, sid, 1, false, 5), new(2, 2), new(1, 1));
        Check(RoleHandoff.ConservativeStopAdvance(initial, initial));
        Check(RoleHandoff.ConservativeStopAdvance(initial, initial with { Shared = new(true, 8, 3), Protected = initial.Protected with { Stopped = true, Epoch = 10 } }));
        Check(RoleHandoff.ConservativeStopAdvance(initial, initial with { Ordinary = new(3, 2), OrdinaryComputer = new(2, 1) }));
        Check(RoleHandoff.ConservativeStopAdvance(initial, initial with { Computer = initial.Computer with { Stopped = true, Epoch = 6 } }));
        Check(!RoleHandoff.ConservativeStopAdvance(initial, initial with { Shared = new(false, 8, 8) }));
        Check(!RoleHandoff.ConservativeStopAdvance(initial, initial with { Protected = initial.Protected with { Epoch = 10 } }));
        Check(!RoleHandoff.ConservativeStopAdvance(initial, initial with { Protected = initial.Protected with { Stopped = true } }));
        Check(!RoleHandoff.ConservativeStopAdvance(initial, initial with { Protected = initial.Protected with { UserSid = "S-1-5-18", Stopped = true, Epoch = 10 } }));
        Check(!RoleHandoff.ConservativeStopAdvance(initial, initial with { Ordinary = new(3, 3) }));
        Check(!RoleHandoff.ConservativeStopAdvance(initial, initial with { OrdinaryComputer = new(0, 0) }));
        var stopped = initial with { Shared = new(true, 8, 3), Protected = initial.Protected with { Stopped = true, Epoch = 10 }, Ordinary = new(3, 2) };
        Check(!RoleHandoff.ConservativeStopAdvance(stopped, stopped with { Protected = stopped.Protected with { Stopped = false, Epoch = 11 } }));
        var resumed = stopped with { Shared = new(false, 8, 8), Protected = stopped.Protected with { Stopped = false, Epoch = 11 }, Ordinary = new(3, 3) };
        Check(BrokerState.IsBoundGlobalResume(stopped, resumed));
        Check(!BrokerState.IsBoundGlobalResume(stopped, resumed with { Ordinary = new(4, 4) }));
        Check(!BrokerState.IsBoundGlobalResume(stopped, resumed with { Protected = resumed.Protected with { Epoch = 12 } }));
        Check(!BrokerState.IsBoundGlobalResume(stopped, resumed with { Shared = new(false, 9, 9) }));
        var restarted = stopped with { Shared = new(false, 8, 3) };
        Check(BrokerState.IsBoundGlobalResume(restarted, resumed with { Shared = new(false, 9, 9) }));
        using (var shared = new SharedWriteGate(Guid.NewGuid().ToString("N")))
        {
            var source = new BrokerState(writeGate: shared) { OrdinaryResident = true };
            source.Pause(true); long generation = source.LocalStopGeneration;
            var before = stopped with { Shared = shared.Snapshot() };
            shared.Resume(before.Shared.Epoch); // Owned stand-in for a completed High writer.
            Check(source.IsPaused && !shared.Snapshot().Stopped);
            var after = resumed with { Shared = shared.Snapshot() };
            source.ConfirmBoundLocalResumeState(before, after, generation);
            Check(!source.IsPaused);
            source.Pause(true);
            Reject(() => source.ConfirmBoundLocalResumeState(before, after, generation), "resume_state_changed");
            Check(source.IsPaused && shared.Snapshot().Stopped);
        }
        var baseline = UserPermissions.Effective(new() { UserSid = sid, AuthorityTier = 0 });
        var draft = baseline with { HudCompact = true, DeniedApplications = [new(@"E:\fixture\blocked.exe")] };
        var tierCommit = UserPermissions.Effective(baseline with { AuthorityTier = 1, Revision = Guid.NewGuid().ToString("N") });
        var model = new SettingsWorkspaceModel(tierCommit);
        model.RetainRoleDraft(baseline, draft);
        Check(!model.Conflict && model.Draft.Revision == tierCommit.Revision && model.Draft.HudCompact && model.Draft.DeniedApplications.Length == 1);
        Check(model.Draft.AuthorityTier == 1 && model.Draft.AdminWindows);
        var concurrent = tierCommit with { JevEnabled = !baseline.JevEnabled };
        var conflict = new SettingsWorkspaceModel(concurrent);
        conflict.RetainRoleDraft(baseline, draft);
        Check(conflict.Conflict && conflict.Draft.Revision == baseline.Revision && conflict.Saved.Revision == concurrent.Revision);
        Check(conflict.Draft.HudCompact && conflict.Draft.DeniedApplications.Length == 1);
        var surface = new SettingsSurfaceHandoff(draft, baseline, "local-draft", new("", "absent"), new(),
            "allowlist", "allowlist", false, null, null, 2, 4, 0, false, 2, 2, "chrome");
        SettingsSurfaceHandoffValidator.Validate(surface, sid); Check(true);
        SettingsSurfaceHandoffValidator.Validate(surface with { Legacy = true, Page = 6 }, sid); Check(true);
        Reject(() => SettingsSurfaceHandoffValidator.Validate(surface with { Page = 6 }, sid), "settings_handoff_invalid");
        Reject(() => SettingsSurfaceHandoffValidator.Validate(surface with { GeneralSection = 3 }, sid), "settings_handoff_invalid");
        Reject(() => SettingsSurfaceHandoffValidator.Validate(surface with { Baseline = baseline with { UserSid = "S-1-5-18" } }, sid), "settings_handoff_invalid");
        var plain = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(surface);
        var encrypted = RoleDraftRecovery.Crypt(plain, true);
        Check(!plain.SequenceEqual(encrypted) && RoleDraftRecovery.Crypt(encrypted, false).SequenceEqual(plain));
        Reject(() => RoleDraftRecovery.Crypt(encrypted[..32], false), "settings_draft_recovery_crypto_failed");
        string recoveryRoot = Path.Combine(Path.GetTempPath(), "flower-role-draft-" + Guid.NewGuid().ToString("N"));
        var fixturePolicy = new BrokerPolicy { UserSid = sid, Version = new string('a', 32), DataRoot = recoveryRoot };
        var process = Native.Process(Environment.ProcessId).Identity;
        RoleDraftRecovery.Preserve(fixturePolicy, process, surface);
        RoleDraftRecovery.Restore(fixturePolicy, process);
        Check(System.Text.Json.JsonSerializer.Serialize(SettingsWorkspace.TakeIncomingHandoff()) == System.Text.Json.JsonSerializer.Serialize(surface));
        RoleDraftRecovery.AcceptImported();
        Check(!File.Exists(Path.Combine(recoveryRoot, "control", "role-draft-" + process.Session + ".bin")));
        Directory.Delete(recoveryRoot, true);
        string path = Path.Combine(Path.GetTempPath(), "flower-role-tail-" + Guid.NewGuid().ToString("N") + ".bin");
        using var writer = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.DeleteOnClose);
        writer.WriteByte(0xa5); writer.Flush(true);
        using var reader = new AppendOnLength(path, () => { writer.Position = writer.Length; writer.WriteByte(0xa5); writer.Flush(true); });
        long count = OrdinaryStopJournal.ReadValidatedTail(reader, 0);
        Check(count == 2); // Original length was 1; validation saw a later append.
        writer.Position = writer.Length; writer.WriteByte(0xa5); writer.Flush(true);
        count = OrdinaryStopJournal.ReadValidatedTail(reader, count); Check(count == 3);
        var clock = Stopwatch.StartNew();
        bool stable = true;
        for (int i = 0; i < 10000; i++) stable &= OrdinaryStopJournal.ReadValidatedTail(reader, count) == count;
        clock.Stop();
        Check(stable);
        writer.Position = writer.Length; writer.WriteByte(0); writer.Flush(true);
        Reject(() => OrdinaryStopJournal.ReadValidatedTail(reader, count), "ordinary_stop_corrupt");
        writer.SetLength(1); writer.Flush(true);
        Reject(() => OrdinaryStopJournal.ReadValidatedTail(reader, count), "ordinary_stop_truncated");
        writer.SetLength(1024 * 1024 + 1); writer.Flush(true);
        Reject(() => OrdinaryStopJournal.ReadValidatedTail(reader, 0), "ordinary_stop_capacity");
        return new { passed = true, assertions = checks, pinnedTailReads = 10000, pinnedTail10000Milliseconds = clock.Elapsed.TotalMilliseconds,
            productionStopTouched = false, elevated = false, inputDispatched = false, evidence = "pure-state-and-owned-file-shared-object-only" };
    }
}
