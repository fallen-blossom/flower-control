using System.Text;
using System.Text.Json;

namespace Flower.HighHelper;

// Test seam cannot be selected by a request or production constructor. Only
// caller-owned TEMP files and synthetic identities/context are used here.
internal sealed partial class UacQualificationLeaseStore
{
    private static readonly string TestSid = "S-1-5-21-1-2-3-1001";
    private static readonly string TestVersion = new('a', 32);
    private static Peer TestOwner => new(123, 456, 7, TestSid, new string('b', 64), 12288);
    private static UacQualificationContext TestContext => new("absent", new string('c', 32), 11, 17, 1000);
    private static UacQualificationLeaseStore Fixture(string root, Func<bool, Peer>? role = null,
        Func<UacQualificationContext>? context = null, Func<Peer, bool>? live = null, Action<string>? checkpoint = null)
        => new(root, TestSid, 7, TestVersion, true, role ?? (_ => TestOwner), context ?? (() => TestContext),
            live ?? (peer => peer == TestOwner), checkpoint);

    internal static int RunFixtureTests()
    {
        int assertions = 0;
        void Check(bool value) { ++assertions; if (!value) throw new Boundary("uac_qualification_lease_test_failed_" + assertions); }
        void Reject(Action action, string? code = null)
        {
            Exception? caught = null;
            try { action(); } catch (Exception error) { caught = error; }
            Check(caught is not null && (code is null ? caught is Boundary or IOException or UnauthorizedAccessException or OverflowException
                : caught is Boundary boundary && boundary.Code == code));
        }
        string temporary = Path.Combine(Path.GetTempPath(), "flower-qualification-lease-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        try
        {
            Check(SharedSid(TestOwner, TestSid, 7) is null);
            Check(SharedSid(TestOwner with { User = "S-1-5-18", Integrity = 16384 }, TestSid, 7) == TestSid);
            Reject(() => SharedSid(TestOwner with { User = "S-1-5-18", Integrity = 16384, Session = 0 }, TestSid, 7),
                "uac_qualification_interactive_session_required");
            Reject(() => SharedSid(TestOwner with { Integrity = 8192 }, TestSid, 7), "uac_qualification_role_rejected");
            Reject(() => SharedSid(TestOwner with { User = "S-1-5-21-1-2-3-1002" }, TestSid, 7), "uac_qualification_role_rejected");
            string root = Path.Combine(temporary, "records");
            var first = Fixture(root); var second = Fixture(root);
            var absent = first.Read(); Check(absent.Revision == "absent" && absent.Record.Epoch == 0);
            Check(!Directory.Exists(root));
            var issued = first.Issue(absent); var active = issued.Record.Active!;
            Check(issued.Record.Epoch == 1 && active.Owner == TestOwner && active.Version == TestVersion);
            Check(active.ExpiresTick - active.IssuedTick == LifetimeMilliseconds);
            first.RequireCurrent(issued); second.RequireCurrent(issued); Check(true);
            Reject(() => second.Issue(absent), "uac_qualification_changed");
            Reject(() => first.Issue(issued), "uac_qualification_cleanup_required");
            Reject(() => Fixture(root, context: () => TestContext with { Tick = active.ExpiresTick }).Issue(issued),
                "uac_qualification_cleanup_required");
            foreach (var now in new[] { TestContext with { Tick = active.IssuedTick - 1 },
                TestContext with { Tick = active.ExpiresTick }, TestContext with { Tick = active.ExpiresTick + 1 },
                TestContext with { PolicyRevision = new string('d', 64) }, TestContext with { BootId = new string('d', 32) },
                TestContext with { SharedStopEpoch = 12 }, TestContext with { ProtectedStopEpoch = 18 } })
                Reject(() => Fixture(root, context: () => now).RequireCurrent(issued), "uac_qualification_not_current");
            Fixture(root, context: () => TestContext with { Tick = active.ExpiresTick - 1 }).RequireCurrent(issued); Check(true);
            Reject(() => Fixture(root, live: _ => false).RequireCurrent(issued), "uac_qualification_not_current");
            Reject(() => Fixture(root, role: _ => TestOwner with { Created = 457 }).CloseOwned(issued), "uac_qualification_owner_changed");
            Reject(() => first.CloseOwned(issued with { Record = issued.Record with { Epoch = 5 } }), "uac_qualification_owner_changed");
            Reject(() => first.CloseOwned(issued with { Record = issued.Record with { Active = active with { LeaseId = new string('e', 32) } } }),
                "uac_qualification_owner_changed");
            var revoked = second.Revoke(issued); Check(revoked.Record.Epoch == 2 && revoked.Record.Active is null);
            Reject(() => first.RequireCurrent(issued), "uac_qualification_changed");
            Reject(() => first.CloseOwned(issued), "uac_qualification_changed");
            var again = second.Revoke(revoked); Check(again.Record.Epoch == 3 && again.Record.Active is null);
            var newer = second.Issue(again); Check(newer.Record.Epoch == 4 && newer.Record.Active!.LeaseId != active.LeaseId);
            Reject(() => first.CloseOwned(issued), "uac_qualification_changed");
            Check(second.Read() == newer);
            var closed = second.CloseOwned(newer); Check(closed.Record.Epoch == 5 && closed.Record.Active is null);
            // A bootstrapping SYSTEM role may revoke, but never issue or close as a High owner.
            var system = Fixture(root, role: issue => issue ? throw new Boundary("synthetic_system_issue_rejected")
                : TestOwner with { User = "S-1-5-18", Integrity = 16384, Session = 0 });
            Reject(() => system.Issue(closed), "synthetic_system_issue_rejected");
            Check(system.Revoke(closed).Record.Epoch == 6);

            byte[] baseline = File.ReadAllBytes(first.PathName);
            foreach (string phase in new[] { "before_write", "before_replace" })
            {
                var fault = Fixture(root, checkpoint: actual => { if (actual == phase) throw new IOException("synthetic fault"); });
                Reject(() => fault.Issue(fault.Read())); Check(File.ReadAllBytes(first.PathName).SequenceEqual(baseline));
            }
            var unknown = Fixture(root, checkpoint: phase => { if (phase == "after_replace") throw new IOException("lost receipt"); });
            var beforeUnknown = first.Read();
            Reject(() => unknown.Issue(beforeUnknown), "uac_qualification_outcome_unknown");
            var survived = first.Read(); Check(survived.Record.Active is not null && survived.Record.Epoch == 7);
            Reject(() => first.Issue(beforeUnknown), "uac_qualification_changed");
            Reject(() => first.Issue(survived), "uac_qualification_cleanup_required");
            Reject(() => unknown.Revoke(survived), "uac_qualification_outcome_unknown");
            Check(first.Read().Record.Active is null && first.Read().Record.Epoch == 8);
            Reject(() => first.CloseOwned(survived), "uac_qualification_changed");

            // Raw CAS detects replacement between staging and committing too.
            var old = first.Read();
            var drift = Fixture(root, checkpoint: phase => { if (phase == "before_replace")
                File.WriteAllBytes(first.PathName, JsonSerializer.SerializeToUtf8Bytes(old.Record with { Epoch = 99 })); });
            Reject(() => drift.Issue(old), "uac_qualification_changed");
            Check(first.Read().Record.Epoch == 99 && first.Read().Record.Active is null);

            var json = Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(issued.Record));
            var malformed = new[] { "", "{", "null", json.Replace("\"Schema\":1", "\"Schema\":2"),
                json.Replace("\"Schema\":1", "\"Schema\":1,\"Schema\":1"),
                json.Replace("\"Schema\":1,", ""), json.Replace("\"Schema\":1", "\"Schema\":1,\"Extra\":0"),
                json.Replace("\"Pid\":123", "\"Pid\":null"), json.Replace("\"Pid\":123", "\"Pid\":\"123\""),
                json.Replace("\"Pid\":123", "\"Pid\":123,\"Unknown\":true"), json.Replace(TestSid, "S-1-5-18"),
                json.Replace("\"Session\":7", "\"Session\":8"), json.Replace("\"Epoch\":1", "\"Epoch\":-1"),
                json.Replace("\"Active\":", "\"Missing\":"), json.Replace("\"Integrity\":12288", "\"Integrity\":8192"),
                json.Replace("\"IssuedTick\":1000", "\"IssuedTick\":-1"),
                json.Replace("\"ExpiresTick\":301000", "\"ExpiresTick\":301001"),
                json.Replace(new string('c', 32), new string('0', 32)), new string(' ', 8193) };
            foreach (string bad in malformed)
            {
                File.WriteAllText(first.PathName, bad);
                Reject(() => first.Read(), "uac_qualification_record_invalid");
                byte[] unchanged = File.ReadAllBytes(first.PathName);
                Reject(() => first.Revoke(absent), "uac_qualification_record_invalid");
                Check(File.ReadAllBytes(first.PathName).SequenceEqual(unchanged));
            }
            File.WriteAllBytes(first.PathName, JsonSerializer.SerializeToUtf8Bytes(closed.Record with { Epoch = long.MaxValue }));
            var maximum = first.Read(); Reject(() => first.Revoke(maximum)); Reject(() => first.Issue(maximum));
            Check(first.Read() == maximum);

            File.WriteAllBytes(first.PathName, JsonSerializer.SerializeToUtf8Bytes(closed.Record));
            var clean = first.Read(); byte[] cleanBytes = File.ReadAllBytes(first.PathName);
            foreach (var invalid in new[] { TestContext with { PolicyRevision = "invalid:error" },
                TestContext with { BootId = "not-a-boot-id" }, TestContext with { SharedStopEpoch = -1 },
                TestContext with { ProtectedStopEpoch = -1 }, TestContext with { Tick = -1 } })
            { Reject(() => Fixture(root, context: () => invalid).Issue(clean));
                Check(File.ReadAllBytes(first.PathName).SequenceEqual(cleanBytes)); }
            Reject(() => Fixture(root, context: () => TestContext with { Tick = long.MaxValue }).Issue(clean));
            Check(File.ReadAllBytes(first.PathName).SequenceEqual(cleanBytes));
            foreach (var invalid in new[] { TestOwner with { Created = 0 }, TestOwner with { Integrity = 8192 },
                TestOwner with { User = "S-1-5-18" }, TestOwner with { Session = 0 }, TestOwner with { ImageDigest = "bad" } })
            { Reject(() => Fixture(root, role: _ => invalid).Issue(clean));
                Check(File.ReadAllBytes(first.PathName).SequenceEqual(cleanBytes)); }

            string directoryFileRoot = Path.Combine(temporary, "record-directory"); Directory.CreateDirectory(directoryFileRoot);
            Directory.CreateDirectory(Path.Combine(directoryFileRoot, "lease.json"));
            Reject(() => Fixture(directoryFileRoot).Read(), "uac_qualification_storage_unprotected");
            string fileRoot = Path.Combine(temporary, "file-root"); File.WriteAllText(fileRoot, "not a directory");
            Reject(() => Fixture(fileRoot).Read(), "uac_qualification_storage_unprotected");

            // A held physical lock blocks a second store, then releasing it permits progress.
            using (var held = new FileStream(first.LockName, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                Reject(() => first.Revoke(clean), "uac_qualification_busy");
            File.WriteAllBytes(first.PathName, JsonSerializer.SerializeToUtf8Bytes(closed.Record));
            var raceStart = first.Read(); int won = 0, lost = 0;
            Parallel.Invoke(() => Race(first), () => Race(second));
            void Race(UacQualificationLeaseStore store)
            {
                try { store.Issue(raceStart); Interlocked.Increment(ref won); }
                catch (Boundary error) when (error.Code == "uac_qualification_changed") { Interlocked.Increment(ref lost); }
            }
            Check(won == 1 && lost == 1);
            Check(first.Read().Record.Epoch == closed.Record.Epoch + 1);
            Check(!Directory.EnumerateFiles(root).Any(path => path.EndsWith(".pending", StringComparison.Ordinal)));
            // The fixture is never a public production context.
            Reject(() => Open(new BrokerPolicy { Mode = "medium-isolated-fixture", UserSid = TestSid, Version = TestVersion }, 7),
                "uac_qualification_context_rejected");
            return assertions;
        }
        finally { Directory.Delete(temporary, true); }
    }

    // Reflection-only external test driver: multiple OS processes exercise the
    // same TEMP physical lock. This is not exposed by Program or any protocol.
    internal static long RunFixtureRevocations(string root, int count, bool synchronize)
    {
        string absolute = Path.GetFullPath(root);
        if (!absolute.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)
            || count is < 1 or > 100) throw new Boundary("uac_qualification_fixture_rejected");
        var store = Fixture(absolute);
        UacQualificationSnapshot? initial = null;
        if (synchronize)
        {
            Directory.CreateDirectory(absolute); initial = store.Read();
            File.WriteAllText(Path.Combine(absolute, "ready." + Environment.ProcessId), initial.Revision);
            long deadline = Environment.TickCount64 + 5000;
            while (Directory.GetFiles(absolute, "ready.*").Length < 2)
            {
                if (Environment.TickCount64 >= deadline) throw new Boundary("uac_qualification_fixture_peer_timeout");
                Thread.Sleep(10);
            }
        }
        for (int i = 0; i < count;)
        {
            var snapshot = initial ?? store.Read(); initial = null;
            try { store.Revoke(snapshot); ++i; }
            catch (Boundary error) when (error.Code == "uac_qualification_changed") { }
        }
        return store.Read().Record.Epoch;
    }
}
