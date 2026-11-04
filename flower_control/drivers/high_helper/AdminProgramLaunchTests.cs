using System.Text.Json;

namespace Flower.HighHelper;

// No launch callback, fixture executable, UI, High or SYSTEM entry is used.
internal static class AdminProgramLaunchTests
{
    private sealed class UnreadableDiagnosticException : Exception
    {
        public override System.Collections.IDictionary Data => throw new InvalidOperationException("private diagnostic failure");
    }
    internal static object Run()
    {
        void Trace(string stage) { if (Environment.GetEnvironmentVariable("FLOWER_ADMIN_SELFTEST_TRACE") == "1") Console.Error.WriteLine("admin_selftest:" + stage); }
        Trace("start");
        if (Native.Process(Environment.ProcessId, false).Identity.Integrity != 8192)
            throw new Boundary("program_launch_tests_medium_required");
        Trace("medium_identity");
        int assertions = 0;
        void Check(bool condition, string name)
        { assertions++; if (!condition) throw new Boundary("program_launch_test_" + name); }
        var sharing = new IOException("private-path-and-argv-must-not-leak", unchecked((int)0x80070020));
        sharing.Data["AdminLaunchStage"] = "payload_pin"; sharing.Data["AdminLaunchPayloadIndex"] = 1;
        var failure = AdminLaunchFailure.Describe(sharing, "execution_binding");
        Check(failure.Stage == "payload_pin" && failure.Winerror == 32 && failure.PayloadIndex == 1, "io_diagnostic_preserves_native_code");
        Check(!JsonSerializer.Serialize(failure).Contains("private-path-and-argv"), "diagnostic_excludes_exception_content");
        Check(AdminLaunchFailure.Describe(new IOException("private"), "audit_request").Winerror is null, "generic_io_has_no_invented_winerror");
        var publication = new IOException("execution_audit_create_failed", unchecked((int)0x80070003));
        var publicationFailure = AdminLaunchFailure.Describe(publication, "archive_closed_execution");
        Check(publicationFailure.Stage == "archive_closed_execution" && publicationFailure.Winerror == 3,
            "archive_publication_failure_keeps_stage_and_native_error");
        Check(Program.Code(publication) == "execution_audit_create_failed", "file_creation_failure_is_not_a_pipe_failure");
        Check(AdminLaunchFailure.Describe(new System.ComponentModel.Win32Exception(5, "private"), "executable_pin").Winerror == 5, "native_error_code_is_preserved");
        Check(AdminLaunchFailure.Describe(new Boundary("program_launch_directory_pin_failed", 5), "executable_pin").Winerror == 5, "boundary_keeps_original_native_code");
        Check(AdminLaunchFailure.Describe(new Exception("private"), "private-path").Stage == "unknown", "diagnostic_stage_is_closed");
        sharing.Data["AdminLaunchPayloadIndex"] = 32;
        Check(AdminLaunchFailure.Describe(sharing, "execution_binding").PayloadIndex is null, "diagnostic_index_is_bounded");
        var watched = new BrokerRequest(); watched.CaptureAdminLaunchFailure(sharing, "caller_watch");
        var originalFailure = watched.AdminLaunchFailure;
        watched.CaptureAdminLaunchFailure(new Boundary("pipe_disconnected"), "policy_check");
        Check(ReferenceEquals(originalFailure, watched.AdminLaunchFailure) && !watched.Stop.IsCancellationRequested, "first_failure_kept_without_changing_stop");
        watched.Stop.Dispose();
        var unreadable = new UnreadableDiagnosticException();
        var cancelStillRuns = new BrokerRequest();
        cancelStillRuns.CaptureAdminLaunchFailure(unreadable, "caller_watch");
        cancelStillRuns.Cancel("pipe_disconnected");
        Check(cancelStillRuns.Stop.IsCancellationRequested && cancelStillRuns.AdminLaunchFailure is null, "diagnostic_failure_cannot_prevent_cancel");
        cancelStillRuns.Stop.Dispose();
        AdminLaunchFailure.TagPin(unreadable, "payload_pin", 0); // Must not throw before mandatory Close().
        var closing = AdminLaunchFailure.Describe(new IOException("private", unchecked((int)0x8007006d)), "caller_watch", true);
        var beforeClosing = new { State = "rejected", Dispatched = false, Created = 134374133862343831L, Failure = (AdminLaunchFailure?)null };
        var afterClosing = JsonSerializer.SerializeToElement(AdminProgramLaunch.CompleteReport(beforeClosing, closing));
        Check(afterClosing.GetProperty("Failure").GetProperty("Finishing").GetBoolean(), "closing_failure_is_attached_after_watch_ends");
        Check(afterClosing.GetProperty("State").GetString() == "rejected" && !afterClosing.GetProperty("Dispatched").GetBoolean()
            && afterClosing.GetProperty("Created").GetInt64() == 134374133862343831L, "closing_diagnostic_preserves_original_outcome_and_int64");
        // Real Medium process identity, including the executable digest. No
        // authorization store, confirmation window or process launch is used.
        var admitted = Native.Process(Environment.ProcessId).Identity;
        Trace("image_identity");
        Check(admitted.ImageDigest.Length == 64 && WorkAuthority.SourceIdentityCurrent(admitted), "work_caller_full_identity_current");
        foreach (var changed in new[] { admitted with { Pid = int.MaxValue }, admitted with { Created = admitted.Created + 1 },
            admitted with { Session = admitted.Session + 1 }, admitted with { User = admitted.User + "-changed" },
            admitted with { Integrity = admitted.Integrity + 1 }, admitted with { ImageDigest = new string('0', 64) },
            admitted with { ImageDigest = "" } })
        { Trace("changed_identity"); Check(!WorkAuthority.SourceIdentityCurrent(changed), "work_caller_identity_change_rejected"); }
        Trace("identity_checks_complete");
        var self = Native.Process(Environment.ProcessId, false).Identity;
        Check(AdminProgramLaunch.ProbeRootExitState(self.Pid, self.Created) == "running", "detached_live_root_running");
        Check(AdminProgramLaunch.ProbeRootExitState(self.Pid, self.Created + 1) == "root_exited", "detached_reused_pid_root_exited");
        Check(AdminProgramLaunch.ProbeRootExitState(int.MaxValue, 1) == "root_exited", "detached_missing_pid_root_exited");
        Trace("detached_root_probe_complete");
        void Reject(Action action, string code, string name)
        {
            bool rejected = false;
            try { action(); } catch (Boundary error) { rejected = error.Code == code; }
            Check(rejected, name);
        }
        string digest = new('a', 64);
        var row = new UacApplicationPermission(@"C:\Approved\Game.exe", "sha256", digest, "Game", Arguments: "");
        var settings = new UserPermissionSettings { AdminLaunchEnabled = true, UacMode = "off", AdminLaunchAllowlist = [row] };
        Check(AdminProgramLaunch.Eligible(row), "empty_rule");
        Check(!AdminProgramLaunch.Eligible(row with { Arguments = null }), "legacy_rule");
        Check(!AdminProgramLaunch.Eligible(row with { Arguments = "--launch" }), "arguments_rule");
        Check(!AdminProgramLaunch.Eligible(row with { Enabled = false }), "disabled_rule");
        Check(!AdminProgramLaunch.Eligible(row with { Path = @"C:\Approved\cmd.exe" }), "shell_rule");
        Check(AdminProgramLaunch.ProgramRef(row) == AdminProgramLaunch.ProgramRef(row with { DisplayName = "Renamed", Path = @"c:\approved\GAME.exe" }), "stable_reference");
        Check(AdminProgramLaunch.ProgramRef(row) != AdminProgramLaunch.ProgramRef(row with { Identity = new('b', 64) }), "identity_reference");
        Check(AdminProgramLaunch.ProgramRef(row) != AdminProgramLaunch.ProgramRef(row with { IdentityKind = "signed" }), "kind_reference");
        Trace("reference_checks_complete");
        Check(!new UserPermissionSettings().AdminLaunchEnabled, "launch_default_off");
        foreach (var mode in new[] { "off", "cancel", "allowlist", "semantic", "full", "unknown" })
        {
            Reject(() => AdminProgramLaunch.RequireMode(settings with { AdminLaunchEnabled = false, UacMode = mode }),
                "program_launch_disabled", "disabled_independent_of_" + mode);
            AdminProgramLaunch.RequireMode(settings with { UacMode = mode }); Check(true, "enabled_independent_of_" + mode);
        }
        Reject(() => AdminProgramLaunch.RequirePreferences(settings with { AdminWindows = false }, row.Path),
            "administrator_window_disabled", "admin_off");
        Reject(() => AdminProgramLaunch.RequirePreferences(settings with { DeniedApplications = [new(row.Path, "future title")] }, row.Path),
            "window_disabled_by_user", "future_title_denial");
        AdminProgramLaunch.RequirePreferences(settings with { AdminScope = "allowlist", AllowedAdminApplications = [new(row.Path, "future title")] }, row.Path);
        Check(true, "legacy_window_allowlist_does_not_limit_master_enabled_control");
        AdminProgramLaunch.RequirePreferences(settings with { AdminScope = "allowlist", AllowedAdminApplications = [new(row.Path)] }, row.Path);
        Check(true, "exact_admin_grant");
        var entry = new AdminLaunchEntry("task", "request", AdminProgramLaunch.ProgramRef(row), AdminProgramLaunch.Target(row.Path),
            "fixture", 1, "unknown", "crash_after_intent");
        Check(AdminProgramLaunch.BlocksTarget(entry, "exited"), "unknown_never_unblocks");
        Trace("preferences_complete");
        Check(AdminProgramLaunch.BlocksTarget(entry with { State = "created" }, "running"), "running_blocks");
        Check(AdminProgramLaunch.BlocksTarget(entry with { State = "created" }, "unknown"), "unknown_process_blocks");
        Check(AdminProgramLaunch.BlocksTarget(entry with { State = "created" }, "exited"), "exit_without_workload_evidence_blocks");
        Check(!AdminProgramLaunch.BlocksTarget(entry with { State = "rejected" }, "unknown"), "rejected_no_launch");
        var nextQuery = new ProgramLaunchQuery("program_launch", "launch", "current-task", "connection",
            entry.ProgramRef, "fresh-request");
        var completed = entry with { State = "handoff_unknown", Dispatched = true, WorkloadState = "exited", ExitCode = 0,
            Process = new(123, 456, row.Path, 12288, "fixture", 1), NativePid = 123, NativeCreated = 456,
            EnvironmentPolicy = "ordinary-app-allowlist-v1" };
        string? Proof(params AdminLaunchEntry[] rows) => AdminProgramLaunch.AllowlistExitReference(rows, nextQuery,
            completed.Target, "fixture", 1, "policy-and-executable-version");
        var exitProof = Proof(completed);
        Check(exitProof is not null && AdminProgramLaunch.Digest(exitProof), "allowlist_exact_tree_exit_offers_new_run");
        Check(Proof(completed with { State = "unknown" }) is null, "allowlist_uncertain_creation_blocks_new_run");
        Check(Proof(completed with { WorkloadState = "running" }) is null, "allowlist_running_tree_blocks_new_run");
        Check(Proof(completed with { WorkloadState = "legacy" }) is null, "allowlist_legacy_exit_blocks_new_run");
        Check(Proof(completed with { NativeCreated = 457 }) is null, "allowlist_pid_reuse_blocks_new_run");
        Check(Proof(completed with { ExitCode = null }) is null, "allowlist_missing_exit_blocks_new_run");
        Check(Proof(completed, entry) is null, "allowlist_all_pending_records_require_exit");
        Check(Proof(completed with { RequestId = nextQuery.RequestId }) is null, "allowlist_original_id_never_replays");
        Check(Proof(completed with { RequestId = "newer-completed" }) != exitProof, "allowlist_newer_record_invalidates_proof");
        Check(AdminProgramLaunch.AllowlistExitReference([completed], nextQuery with { TaskId = "another-task" },
            completed.Target, "fixture", 1, "policy-and-executable-version") != exitProof, "allowlist_proof_task_bound");
        Check(AdminProgramLaunch.AllowlistExitReference([completed], nextQuery, completed.Target, "fixture", 1,
            "changed-policy") != exitProof, "allowlist_proof_policy_and_executable_bound");
        var detached = completed with { State = "created", ExitCode = null, WorkloadState = "unknown",
            EnvironmentPolicy = "ordinary-app-allowlist-v1" };
        string? RootProof(IEnumerable<AdminLaunchEntry> rows, bool tracked = false, string? rootState = null) =>
            AdminProgramLaunch.AllowlistRootExitReference(rows, nextQuery, completed.Target, "fixture", 1,
                "policy-and-executable-version", entry => rootState ?? (entry.ExitCode is null ? "root_exited" : "exited"),
                _ => tracked);
        var rootProof = RootProof([detached]);
        Check(rootProof is not null && AdminProgramLaunch.Digest(rootProof), "root_exit_tracking_lost_offers_new_run");
        Check(RootProof([detached], tracked: true) is null, "tracked_workload_never_uses_lost_tracking_proof");
        Check(RootProof([detached], rootState: "running") is null, "live_root_blocks_tracking_lost_proof");
        Check(RootProof([detached], rootState: "unknown") is null, "unverified_root_blocks_tracking_lost_proof");
        Check(RootProof([detached with { WorkloadState = "running" }]) is null, "running_workload_blocks_tracking_lost_proof");
        Check(RootProof([detached with { WorkloadState = "legacy" }]) is null, "legacy_tracking_blocks_tracking_lost_proof");
        Check(RootProof([detached with { EnvironmentPolicy = "inherited-legacy" }]) is null, "legacy_policy_blocks_tracking_lost_proof");
        Check(RootProof([detached with { Dispatched = false }]) is null, "undispatched_record_blocks_tracking_lost_proof");
        Check(RootProof([detached with { Process = null }]) is null, "missing_process_identity_blocks_tracking_lost_proof");
        Check(RootProof([detached], rootState: "exited") is null, "exit_without_code_blocks_tracking_lost_proof");
        Check(RootProof([detached with { ExitCode = 0 }], rootState: "root_exited") is null, "root_exit_without_code_cannot_claim_code");
        Check(RootProof([completed]) is null, "tracked_tree_exit_does_not_use_weaker_proof");
        var mixedProof = RootProof([completed, detached]);
        Check(mixedProof is not null && mixedProof != rootProof, "mixed_tree_and_lost_tracking_uses_all_roots");
        Check(AdminProgramLaunch.AllowlistRootExitReference([detached], nextQuery with { TaskId = "another-task" },
            completed.Target, "fixture", 1, "policy-and-executable-version", _ => "root_exited", _ => false) != rootProof,
            "root_exit_proof_task_bound");
        Check(RootProof([detached with { State = "unknown" }]) != rootProof, "root_exit_proof_state_bound");
        Trace("exit_proof_complete");
        Check(AdminProgramLaunch.Id("launch-001_test") && !AdminProgramLaunch.Id("") && !AdminProgramLaunch.Id("../other"), "request_ids");
        Check(AdminProgramLaunch.Digest(entry.ProgramRef) && !AdminProgramLaunch.Digest(entry.ProgramRef.ToUpperInvariant()), "reference_format");
        using (var bad = JsonDocument.Parse("{\"Phase\":\"program_launch\",\"Command\":\"launch\",\"TaskId\":\"task\",\"ConnectionId\":\"connection\",\"Path\":\"C:\\\\arbitrary.exe\"}"))
        {
            Check(BrokerHost.StructuredPhase(bad, "program_launch"), "structured_launch_routes_before_schema_check");
            bool rejected = false;
            try { Protocol.Decode<ProgramLaunchQuery>(bad); } catch (JsonException) { rejected = true; }
            Check(rejected, "caller_path_rejected");
        }
        foreach (var command in new[] { "list", "launch", "status", "cancel" })
        {
            var payload = new ProgramLaunchQuery("program_launch", command, "task", "connection",
                command == "list" ? "" : entry.ProgramRef, command == "list" ? "" : "request");
            using var message = JsonDocument.Parse(JsonSerializer.Serialize(payload));
            Protocol.CheckUnique(message);
            Check(!Protocol.Phase(message, "program_launch") && BrokerHost.StructuredPhase(message, "program_launch")
                && Protocol.Decode<ProgramLaunchQuery>(message) == payload, "full_launch_route_" + command);
        }
        var permissionPayload = new UacPermissionQuery("uac_permission", "task", "connection", digest, "turn", "review");
        using (var message = JsonDocument.Parse(JsonSerializer.Serialize(permissionPayload)))
        {
            Protocol.CheckUnique(message);
            Check(!Protocol.Phase(message, "uac_permission") && BrokerHost.StructuredPhase(message, "uac_permission")
                && Protocol.Decode<UacPermissionQuery>(message) == permissionPayload, "full_permission_route");
            Check(!BrokerHost.StructuredPhase(message, "program_launch"), "permission_does_not_route_launch");
        }
        using (var bad = JsonDocument.Parse("{\"Phase\":\"uac_permission\",\"TaskId\":\"task\",\"ConnectionId\":\"connection\",\"SessionHash\":\"hash\",\"TurnId\":\"turn\",\"Decision\":\"review\",\"Path\":\"arbitrary\"}"))
        {
            Check(BrokerHost.StructuredPhase(bad, "uac_permission"), "structured_permission_routes_before_schema_check");
            bool rejected = false;
            try { Protocol.Decode<UacPermissionQuery>(bad); } catch (JsonException) { rejected = true; }
            Check(rejected, "permission_extra_field_rejected");
        }
        foreach (var payload in new[] { "[]", "null", "{\"Phase\":3}", "{\"Phase\":null}", "{\"Phase\":\"other\"}" })
        {
            using var message = JsonDocument.Parse(payload);
            Check(!BrokerHost.StructuredPhase(message, "program_launch") && !BrokerHost.StructuredPhase(message, "uac_permission"),
                "invalid_structured_route");
        }
        using (var duplicate = JsonDocument.Parse("{\"Phase\":\"program_launch\",\"Phase\":\"uac_permission\"}"))
            Reject(() => Protocol.CheckUnique(duplicate), "schema_rejected", "duplicate_phase_rejected");
        using (var status = JsonDocument.Parse("{\"Phase\":\"status\"}"))
            Check(Protocol.Phase(status, "status"), "generic_single_field_status_preserved");
        using (var status = JsonDocument.Parse("{\"Phase\":\"status\",\"Command\":\"unexpected\"}"))
            Check(!Protocol.Phase(status, "status"), "generic_status_stays_strict");
        var preflightOrder = new List<string>();
        AdminProgramLaunch.FinalCallerPreflight(() => preflightOrder.Add("caller"), () => preflightOrder.Add("check"));
        Check(preflightOrder.SequenceEqual(new[] { "check", "caller", "check" }), "final_caller_preflight_rechecks_before_and_after");
        bool stopped = false;
        Reject(() => AdminProgramLaunch.FinalCallerPreflight(() => stopped = true,
            () => { if (stopped) throw new Boundary("fixture_stopped"); }), "fixture_stopped", "stop_during_caller_preflight_blocks_creation_stage");
        bool callerReached = false;
        Reject(() => AdminProgramLaunch.FinalCallerPreflight(() => callerReached = true,
            () => throw new Boundary("fixture_stopped")), "fixture_stopped", "stop_before_caller_preflight");
        Check(!callerReached, "stopped_final_stage_does_not_recheck_caller");
        var directory = Path.Combine(Path.GetTempPath(), "flower-admin-launch-policy-" + Guid.NewGuid().ToString("N"));
        Trace("journal_start");
        Directory.CreateDirectory(directory);
        Trace("journal_directory_created");
        var path = Path.Combine(directory, "launches.json");
        var journal = AdminLaunchJournal.TestStorage(path);
        Trace("journal_fixture_created");
        Check(journal.Read().Count == 0, "absent_journal");
        Trace("journal_empty_read");
        journal.Write([entry]);
        Trace("journal_first_write");
        var reopened = AdminLaunchJournal.TestStorage(path);
        Check(reopened.Read().Single() == entry, "crash_intent_survives_reopen");
        Check(AdminProgramLaunch.BlocksTarget(reopened.Read().Single(), "unknown"), "new_id_cannot_bypass");
        // A crashed temporary write cannot replace the original durable intent.
        File.WriteAllText(path + ".new", "{broken");
        Check(reopened.Read().Single() == entry, "temporary_not_authoritative");
        var process = new AdminLaunchedProcess(1234, 1234567, row.Path, 12288, "fixture", 1);
        Check(AdminProgramLaunch.SameProcess(process, process with { Image = @"c:\approved\GAME.exe" }), "window_case_alias");
        foreach (var unrelated in new[] { process with { Pid = 1235 }, process with { Created = 1234568 },
            process with { User = "other" }, process with { Session = 2 }, process with { Integrity = 8192 },
            process with { Image = @"C:\Other\Game.exe" } })
            Check(!AdminProgramLaunch.SameProcess(process, unrelated), "window_identity_mismatch");
        var created = entry with { State = "created", Process = process, Reason = null };
        reopened.Write([created]);
        Check(AdminLaunchJournal.TestStorage(path).Read().Single() == created, "original_process_survives_reopen");
        File.WriteAllText(path, JsonSerializer.Serialize(new { Schema = 1, Entries = new[] { entry, entry } }));
        Reject(() => reopened.Read(), "program_launch_journal_rejected", "duplicate_request_rejected");
        File.WriteAllText(path, JsonSerializer.Serialize(new { Schema = 1, Entries = new[] { created with { Process = process with { Integrity = 8192 } } } }));
        Reject(() => reopened.Read(), "program_launch_journal_rejected", "medium_result_rejected");
        File.WriteAllText(path, JsonSerializer.Serialize(new { Schema = 1, Entries = new[] { created with { Process = process with { Created = 0 } } } }));
        Reject(() => reopened.Read(), "program_launch_journal_rejected", "missing_creation_time_rejected");
        File.WriteAllText(path, JsonSerializer.Serialize(new { Schema = 1, Entries = new[] { created with { Process = process with { Image = @"C:\Other\Game.exe" } } } }));
        Reject(() => reopened.Read(), "program_launch_journal_rejected", "foreign_image_rejected");
        var caller = new Peer(7, 42, 1, "fixture", "", 8192);
        var bound = entry with { Caller = caller };
        var query = new ProgramLaunchQuery("program_launch", "status", "task", "connection", entry.ProgramRef, "request");
        foreach (var command in new[] { "status", "launch", "cancel" })
            Check(!AdminProgramLaunch.RequireOriginal(bound, query with { Command = command }, caller), "same_original_caller_" + command);
        reopened.Write([bound]);
        var beforeRecovery = File.ReadAllBytes(path);
        foreach (var reconnected in new[] { caller with { Pid = 8 }, caller with { Created = 43 }, caller with { Pid = 8, Created = 43 } })
        {
            var recovered = AdminLaunchJournal.TestStorage(path).FindOriginal(query.RequestId)!;
            Check(AdminProgramLaunch.RequireOriginal(recovered, query, reconnected), "new_source_process_can_read_status");
            Check(recovered == bound && recovered.State == "unknown" && recovered.Caller == caller
                && AdminProgramLaunch.BlocksTarget(recovered, "unknown"), "reconnected_status_keeps_original_unknown_and_caller");
            Check(File.ReadAllBytes(path).SequenceEqual(beforeRecovery), "status_binding_recovery_does_not_change_journal_facts");
            foreach (var command in new[] { "launch", "cancel" })
                Reject(() => AdminProgramLaunch.RequireOriginal(recovered, query with { Command = command }, reconnected),
                    "program_launch_original_binding_rejected", "reconnected_source_cannot_" + command);
            // The persistence helper is an action even if an internal caller
            // accidentally passes a status-shaped query.
            Reject(() => AdminProgramLaunch.PersistWithdrawal(reopened, query, reconnected, true),
                "program_launch_original_binding_rejected", "status_reconnection_cannot_persist_withdrawal");
        }
        var newSource = caller with { Pid = 8, Created = 43 };
        foreach (var command in new[] { "status", "launch", "cancel" })
        {
            foreach (var other in new[] { newSource with { User = "other-user" }, newSource with { Session = 2 } })
                Reject(() => AdminProgramLaunch.RequireOriginal(bound, query with { Command = command }, other),
                    "program_launch_original_binding_rejected", "recovery_never_crosses_user_or_session_" + command);
            foreach (var otherQuery in new[] { query with { TaskId = "other" }, query with { ProgramRef = new('b', 64) },
                query with { RequestId = "other-request" } })
                Reject(() => AdminProgramLaunch.RequireOriginal(bound, otherQuery with { Command = command }, newSource),
                    "program_launch_original_binding_rejected", "recovery_requires_exact_task_ref_request_" + command);
        }
        Check(!AdminProgramLaunch.RequireOriginal(entry, query, newSource), "legacy_status_without_original_peer_has_no_reconnect_claim");
        foreach (var command in new[] { "launch", "cancel" })
            Reject(() => AdminProgramLaunch.RequireOriginal(entry, query with { Command = command }, caller),
                "program_launch_original_binding_rejected", "missing_original_peer_never_grants_action_" + command);
        var console = created with { LaunchKind = "console", Dispatched = true, Caller = caller };
        var exited = AdminProgramLaunch.RecordExit(console, 259); // 259 is a valid *confirmed* exit code.
        Check(exited.State == "handoff_unknown" && exited.ExitCode == 259 && AdminProgramLaunch.BlocksTarget(exited, "exited"), "console_exit_not_workload_completion");
        var handoff = AdminProgramLaunch.RecordExit(created with { LaunchKind = "gui", Dispatched = true }, 0);
        Check(handoff.State == "handoff_unknown" && handoff.ExitCode == 0 && AdminProgramLaunch.BlocksTarget(handoff, "exited"), "gui_exit_not_workload_completion");
        var unknownExit = AdminProgramLaunch.RecordExit(bound with { LaunchKind = "console" }, 0);
        Check(unknownExit.State == "unknown" && unknownExit.ExitCode == 0 && AdminProgramLaunch.BlocksTarget(unknownExit, "exited"), "exit_does_not_clear_unknown");
        reopened.Write([console, bound with { RequestId = "unknown-original" }]);
        reopened.Replace(exited);
        Check(reopened.Read().Single(value => value.RequestId == "request") == exited, "console_handoff_remains_active");
        Check(reopened.FindReceipt("request") is null && reopened.FindOriginal("request") == exited, "console_handoff_not_archived");
        Reject(() => reopened.Archive(exited), "program_launch_terminal_required", "console_cannot_archive");
        Reject(() => reopened.Archive(unknownExit), "program_launch_terminal_required", "unknown_cannot_archive");
        Reject(() => reopened.Archive(handoff), "program_launch_terminal_required", "handoff_cannot_archive");
        var rejectedIntent = bound with { RequestId = "definite-rejection" };
        var rejectedResult = rejectedIntent with { State = "rejected", Reason = "program_launch_create_failed:2", Dispatched = false };
        reopened.Write([rejectedIntent, bound with { RequestId = "unknown-original" }]);
        reopened.Replace(rejectedResult);
        Check(reopened.Read().Single().RequestId == "unknown-original", "definite_rejection_frees_active_slot");
        Check(reopened.FindOriginal("definite-rejection") == rejectedResult, "rejected_original_receipt_survives_reopen");
        reopened.Archive(rejectedResult); Check(true, "archive_idempotent");
        Reject(() => reopened.Archive(rejectedResult with { Reason = "different" }), "program_launch_receipt_conflict", "terminal_cannot_change");
        // Exact crash boundary: the terminal receipt was flushed, but the
        // original active intent survived because its replacement did not run.
        var crashIntent = bound with { RequestId = "archive-before-active-write" };
        var crashResult = crashIntent with { State = "rejected", Reason = "program_launch_create_failed:5", Dispatched = false };
        reopened.Write([crashIntent, bound with { RequestId = "unknown-original" }]);
        reopened.Archive(crashResult);
        var crashReopened = AdminLaunchJournal.TestStorage(path);
        Check(crashReopened.Read().Any(value => value == crashIntent) && crashReopened.FindReceipt(crashIntent.RequestId) == crashResult,
            "archive_crash_has_both_copies");
        Check(crashReopened.FindOriginal(crashIntent.RequestId) == crashResult, "archive_crash_original_lookup_recovers_terminal");
        Check(crashReopened.Read().Single().RequestId == "unknown-original", "archive_crash_recovery_removes_only_original_active");
        crashReopened.Replace(crashResult);
        Check(crashReopened.Read().Single().State == "unknown", "archive_crash_recovery_idempotent");
        crashReopened.Write([crashIntent with { TaskId = "different-task" }, bound with { RequestId = "unknown-original" }]);
        Reject(() => crashReopened.FindOriginal(crashIntent.RequestId), "program_launch_receipt_conflict", "archive_cannot_remove_other_binding");
        Check(crashReopened.Read().Any(value => value.TaskId == "different-task"), "archive_binding_conflict_preserves_active");
        reopened.Write([bound with { RequestId = "unknown-original" }]);
        // A normal lifetime exceeding the old ledger limit must preserve both
        // historical request IDs and the one unresolved target blocker.
        Trace("terminal_churn_4097_start");
        for (int index = 0; index < 4097; index++)
            reopened.Archive(entry with { RequestId = "terminal-" + index, State = "rejected", Dispatched = false });
        Trace("terminal_churn_4097_complete");
        Check(reopened.Read().Single().State == "unknown", "terminal_churn_keeps_unknown");
        Check(reopened.FindReceipt("terminal-0")?.Dispatched == false
            && reopened.FindReceipt("terminal-4096")?.State == "rejected", "beyond_4096_receipts_reachable");
        var environment = AdminProgramLaunch.OrdinaryEnvironment(new Dictionary<string, string> {
            ["SystemRoot"] = @"C:\Windows", ["PATH"] = @"C:\Windows\System32", ["TEMP"] = directory,
            ["OPENAI_API_KEY"] = "fixture-secret", ["DOTNET_STARTUP_HOOKS"] = "fixture-hook", ["PYTHONPATH"] = "fixture-provider" });
        Check(environment.Count == 3 && environment.ContainsKey("TEMP") && !environment.ContainsKey("OPENAI_API_KEY")
            && !environment.ContainsKey("DOTNET_STARTUP_HOOKS") && !environment.ContainsKey("PYTHONPATH"), "ordinary_environment_filters_provider_secrets");
        Reject(() => AdminProgramLaunch.OrdinaryEnvironment([]), "windows_system_root_missing", "environment_requires_windows_root");
        var core = new BrokerState();
        var uacRequest = new BrokerRequest { Uac = true };
        var launchRequest = new BrokerRequest { AdminLaunch = true };
        var ordinaryRequest = new BrokerRequest();
        core.Requests["uac"] = uacRequest; core.Requests["launch"] = launchRequest; core.Requests["ordinary"] = ordinaryRequest;
        core.CancelUacRequests("fixture_uac_off");
        Check(uacRequest.Stop.IsCancellationRequested && !launchRequest.Stop.IsCancellationRequested && !ordinaryRequest.Stop.IsCancellationRequested,
            "uac_revocation_does_not_cancel_high_launch");
        core.CancelAdminLaunchRequests("fixture_launch_off");
        Check(launchRequest.Stop.IsCancellationRequested && !ordinaryRequest.Stop.IsCancellationRequested, "launch_revocation_is_separate");
        uacRequest.Stop.Dispose(); launchRequest.Stop.Dispose(); ordinaryRequest.Stop.Dispose();
        core.Requests.Clear();
        BrokerRequest Pending(string id) => new() { AdminLaunch = true, TaskId = "task", AdminLaunchCaller = caller,
            AdminLaunchProgramRef = entry.ProgramRef, AdminLaunchRequestId = id };
        var exact = Pending("exact-withdrawal");
        core.Requests["exact-owner"] = exact;
        foreach (var other in new[] {
            (Caller: caller with { Pid = 8 }, Task: "task", Reference: entry.ProgramRef, Request: "exact-withdrawal"),
            (Caller: caller with { Created = 43 }, Task: "task", Reference: entry.ProgramRef, Request: "exact-withdrawal"),
            (Caller: caller with { Session = 2 }, Task: "task", Reference: entry.ProgramRef, Request: "exact-withdrawal"),
            (Caller: caller with { User = "other" }, Task: "task", Reference: entry.ProgramRef, Request: "exact-withdrawal"),
            (Caller: caller, Task: "other-task", Reference: entry.ProgramRef, Request: "exact-withdrawal"),
            (Caller: caller, Task: "task", Reference: new string('b', 64), Request: "exact-withdrawal"),
            (Caller: caller, Task: "task", Reference: entry.ProgramRef, Request: "other-request") })
        {
            var refused = core.WithdrawAdminLaunch(other.Caller, other.Task, other.Reference, other.Request);
            Check(!refused.Found && !refused.Withdrawn && !exact.Stop.IsCancellationRequested, "withdrawal_requires_exact_owner_binding");
        }
        core.Requests.Clear(); exact.Stop.Dispose();
        void WithdrawalBeforeSubmission(string stage, bool duringPreflight)
        {
            string id = "withdraw-" + stage;
            var pending = Pending(id);
            core.Requests[stage] = pending;
            using var paused = new ManualResetEventSlim();
            using var continueOriginal = new ManualResetEventSlim();
            int callbacks = 0;
            void PauseOriginal()
            {
                paused.Set();
                if (!continueOriginal.Wait(3000)) throw new Boundary("withdrawal_test_pause_timeout");
            }
            var worker = Task.Run(() => {
                try
                {
                    if (duringPreflight)
                        AdminProgramLaunch.FinalCallerPreflight(PauseOriginal,
                            () => { if (pending.Stop.IsCancellationRequested) throw new Boundary(pending.Reason!); });
                    else PauseOriginal();
                    pending.SubmitAdminLaunch(() => Interlocked.Increment(ref callbacks));
                    return true;
                }
                catch (Boundary error) when (error.Code == "program_launch_task_cancelled") { return false; }
            });
            try
            {
                Check(paused.Wait(3000), "original_paused_" + stage);
                var withdrawn = core.WithdrawAdminLaunch(caller, "task", entry.ProgramRef, id);
                Check(withdrawn.Found && withdrawn.Withdrawn, "exact_withdrawal_wins_" + stage);
                var cancelledQuery = query with { Command = "cancel", RequestId = id };
                var cancelled = AdminProgramLaunch.PersistWithdrawal(reopened, cancelledQuery, caller, false);
                Check(cancelled.State == "cancelled" && cancelled.Dispatched == false && cancelled.Target == "",
                    "withdrawal_durable_before_original_resumes_" + stage);
                continueOriginal.Set();
                Check(!worker.GetAwaiter().GetResult() && callbacks == 0, "withdrawn_original_never_calls_create_" + stage);
                Check(AdminLaunchJournal.TestStorage(path).FindOriginal(id) == cancelled,
                    "withdrawal_survives_reopen_and_same_id_" + stage);
                Check(AdminProgramLaunch.PersistWithdrawal(reopened, cancelledQuery, caller, false) == cancelled,
                    "withdrawal_receipt_idempotent_" + stage);
            }
            finally
            {
                continueOriginal.Set(); worker.GetAwaiter().GetResult();
                core.Requests.TryRemove(stage, out _); pending.Stop.Dispose();
            }
        }
        WithdrawalBeforeSubmission("resource", false);
        WithdrawalBeforeSubmission("preflight", true);
        var ownedIntent = bound with { RequestId = "withdraw-owned-intent" };
        reopened.Write([ownedIntent, bound with { RequestId = "unknown-original" }]);
        var owned = Pending(ownedIntent.RequestId); owned.AdminLaunchOwnsIntent = true;
        core.Requests["owned-intent"] = owned;
        var ownedWithdrawal = core.WithdrawAdminLaunch(caller, "task", entry.ProgramRef, ownedIntent.RequestId);
        Check(ownedWithdrawal.Withdrawn, "unsubmitted_owned_intent_withdraws");
        var ownedCancelled = AdminProgramLaunch.PersistWithdrawal(reopened, query with { RequestId = ownedIntent.RequestId }, caller, true);
        Check(ownedCancelled.State == "cancelled" && ownedCancelled.Target == ownedIntent.Target
            && reopened.Read().Single().RequestId == "unknown-original", "owned_intent_retires_only_after_durable_cancellation");
        var oldUnknown = reopened.Read().Single();
        var collision = Pending(oldUnknown.RequestId); core.Requests["old-collision"] = collision;
        Check(core.WithdrawAdminLaunch(caller, "task", entry.ProgramRef, oldUnknown.RequestId).Withdrawn, "colliding_new_executor_stops");
        Check(AdminProgramLaunch.PersistWithdrawal(reopened, query with { RequestId = oldUnknown.RequestId }, caller, false) == oldUnknown
            && AdminProgramLaunch.BlocksTarget(reopened.Read().Single(), "unknown"), "withdrawal_never_clears_historical_unknown");
        core.Requests.Clear(); owned.Stop.Dispose(); collision.Stop.Dispose();
        var submitted = Pending("already-submitted");
        core.Requests["submitted"] = submitted;
        using (var enteredCreate = new ManualResetEventSlim())
        using (var finishCreate = new ManualResetEventSlim())
        {
            int callbacks = 0;
            var worker = Task.Run(() => submitted.SubmitAdminLaunch(() => {
                Interlocked.Increment(ref callbacks); enteredCreate.Set();
                if (!finishCreate.Wait(3000)) throw new Boundary("withdrawal_test_create_timeout");
                return 17;
            }));
            try
            {
                Check(enteredCreate.Wait(3000), "creation_callback_has_crossed_submission_point");
                var tooLate = core.WithdrawAdminLaunch(caller, "task", entry.ProgramRef, "already-submitted");
                Check(tooLate.Found && !tooLate.Withdrawn && !submitted.Stop.IsCancellationRequested,
                    "late_cancel_cannot_claim_withdrawal_or_kill_created_result");
                finishCreate.Set();
                Check(worker.GetAwaiter().GetResult() == 17 && callbacks == 1, "submitted_callback_finishes_once");
                Reject(() => submitted.SubmitAdminLaunch(() => Interlocked.Increment(ref callbacks)),
                    "program_launch_original_status_required", "same_owner_cannot_submit_twice");
                Check(callbacks == 1, "duplicate_submission_never_calls_create_again");
            }
            finally { finishCreate.Set(); worker.GetAwaiter().GetResult(); }
        }
        core.Requests.Clear(); submitted.Stop.Dispose();
        return new { assertions, processLaunchExecuted = false, highExecuted = false, systemExecuted = false,
            inputExecuted = false, storageDirectory = directory, runtimeAcceptance = "not_run" };
    }
}
