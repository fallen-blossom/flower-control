using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed record ProgramLaunchQuery(string Phase, string Command, string TaskId, string ConnectionId,
    string ProgramRef = "", string RequestId = "", string ProgramPath = "", string Arguments = "", AuditThread? Thread = null, string WorkId = "",
    SemanticExecutionSpec? Execution = null, DshCallSourceGuard? DshSource = null, IndependentNewRun? NewRun = null);
internal sealed record AdminLaunchedProcess(int Pid, long Created, string Image, int Integrity, string User, int Session);
internal sealed record AdminLaunchWindow(long Hwnd, AdminLaunchedProcess Process);
internal sealed record AdminLaunchEntry(string TaskId, string RequestId, string ProgramRef, string Target,
    string User, int Session, string State, string? Reason = null, AdminLaunchedProcess? Process = null, int? NativePid = null,
    Peer? Caller = null, bool? Dispatched = null, long? NativeCreated = null, string LaunchKind = "unknown", uint? ExitCode = null,
    string EnvironmentPolicy = "inherited-legacy", string WorkloadState = "legacy");

// List mode consumes protected empty-argument rules. Semantic execution also
// requires an active work grant and a separately bound immutable execution.
internal static class AdminProgramLaunch
{
    private readonly record struct DetachedRootProbe(string State, AdminLaunchedProcess? Process = null, uint? ExitCode = null);
    internal static object CompleteReport(object report, AdminLaunchFailure? failure)
    {
        if (failure is null) return report;
        try
        {
            var fields = JsonSerializer.SerializeToElement(report).EnumerateObject()
                .ToDictionary(value => value.Name, value => value.Value.Clone(), StringComparer.Ordinal);
            if (!fields.TryGetValue("Failure", out var original) || original.ValueKind == JsonValueKind.Null)
                fields["Failure"] = JsonSerializer.SerializeToElement(failure);
            return fields;
        }
        catch { return report; } // Keep the original outcome if diagnostics fail.
    }
    private static readonly object Gate = new();
    private static readonly ConcurrentDictionary<string, SafeProcessHandle> Processes = new();
    private static readonly ConcurrentDictionary<string, byte> Creating = new();
    private static readonly ConcurrentDictionary<string, AdminLaunchWorkload> Workloads = new();
    private static readonly ConcurrentDictionary<string, Action> PayloadReleases = new();
    internal static void RetainPayloads(string requestId, Action release)
    {
        if (!Workloads.ContainsKey(requestId) || !PayloadReleases.TryAdd(requestId, release))
            throw new Boundary("program_launch_payload_lifetime_unconfirmed");
    }
    internal static bool Id(string? value) => value is not null && Regex.IsMatch(value, "\\A[a-zA-Z0-9_-]{1,128}\\z");
    internal static bool Digest(string? value) => value is not null && Regex.IsMatch(value, "\\A[a-f0-9]{64}\\z");
    internal static string Target(string path) => Path.GetFullPath(path).TrimEnd('\\').ToUpperInvariant();
    internal static string ProgramRef(UacApplicationPermission row) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes("flower-admin-launch-v1\n" + Target(row.Path) + "\n" + row.IdentityKind + "\n" + row.Identity + "\n"))).ToLowerInvariant();
    internal static bool Eligible(UacApplicationPermission row) => row.Enabled && row.Arguments == ""
        && row.IdentityKind is "signed" or "sha256" && Digest(row.Identity)
        && Path.IsPathFullyQualified(row.Path) && !UacIdentity.AllowlistExecutionHostName(row.Path);
    internal static void RequireMode(UserPermissionSettings settings)
    {
        if (!UserPermissions.Effective(settings).AdminLaunchEnabled) throw new Boundary("program_launch_disabled");
    }
    internal static void RequirePreferences(UserPermissionSettings settings, string image)
    {
        // A future window title is unknown. A matching title-specific denial
        // must fail closed; title-only admin grants cannot authorize a launch.
        if (UserPermissions.AdminLaunchDenied(settings, image))
            throw new Boundary("window_disabled_by_user");
        UserPermissions.Require(image, 12288, "", settings);
    }
    private static object Report(ProgramLaunchQuery query, AdminLaunchEntry? entry, string state, string? reason = null,
        string processState = "unknown", AdminLaunchWindow? window = null, bool sourceReconnected = false, string? auditWarning = null,
        AdminLaunchFailure? failure = null, object? independentNewRunReview = null)
    {
        var workload = entry is null ? null : WorkloadSnapshot(entry);
        return new { Phase = "program_launch", query.Command, query.TaskId, query.ConnectionId,
        query.ProgramRef, query.RequestId, query.ProgramPath, query.Arguments, State = state, Reason = reason ?? entry?.Reason,
        Dispatched = entry?.Dispatched ?? (entry?.Process is not null ? true : state is "rejected" or "listed" or "cancelled" ? (bool?)false : null),
        Process = entry?.Process, ProcessState = processState, entry?.ExitCode, entry?.LaunchKind, Window = window,
        WorkloadState = workload?.State ?? entry?.WorkloadState ?? "unknown",
        Workload = workload,
        WindowReady = window is not null, HandoffUnknown = state == "handoff_unknown", BusinessVerified = false,
        ContinuationReview = query.Execution?.Continuation is not { } review ? null : new {
            review.PreviousRequestId, review.Outcome, Kind = "host_agent_attestation", NativeBusinessVerified = false },
        IndependentNewRunReview = independentNewRunReview,
        EnvironmentPolicy = entry?.EnvironmentPolicy ?? "ordinary-app-allowlist-v1", DependencyIsolation = false,
        SourceReconnected = sourceReconnected,
        Failure = failure,
        AuditWarning = auditWarning,
        CancellationApplied = query.Command == "cancel" ? state == "cancelled" ? true : state == "unknown" ? null : (bool?)false : null,
        NotQueued = reason == "program_launch_resource_busy", RetrySameRequestId = entry is null && state == "rejected"
            && reason != "program_launch_task_cancelled",
        PhysicalInputFree = true };
    }

    internal static object Handle(BrokerPolicy policy, Peer own, Peer source, ProgramLaunchQuery query,
        string connectionId, BrokerState core, BrokerRequest request)
    {
        if (policy.Fixture || own.Integrity != 12288 || own.User != policy.UserSid || Native.UiAccess(own.Pid))
            throw new Boundary("program_launch_high_role_required");
        if (query.Phase != "program_launch" || query.ConnectionId != connectionId || !Id(query.TaskId)
            || query.Command is not ("list" or "launch" or "status" or "cancel")
            || (query.Command == "list" ? query.ProgramRef != "" || query.RequestId != "" : !Digest(query.ProgramRef) || !Id(query.RequestId)))
            throw new Boundary("program_launch_binding_rejected");
        bool recoveryRead = false;
        string stage = "journal_read";
        ExecutionAudit? audit = null;
        WorkAuthorityRecord? workGrant = null;
        object? independentNewRunReview = null;
        string? backgroundAuditWarning = null;
        void RecordObserved(AdminLaunchEntry observed, string processState)
        {
            try
            {
                audit ??= ExecutionAudit.Open(policy, own);
                audit.Append(new AuditEvent("admin_launch_observed", observed.TaskId, observed.RequestId, observed.State,
                    observed.Target, Thread: observed.TaskId == query.TaskId ? query.Thread : null,
                    Evidence: new { observed.Process, observed.NativePid, observed.NativeCreated, observed.ExitCode,
                        ProcessState = processState, observed.Caller, Helper = own, Version = policy.Version }));
            }
            catch (Exception error) { backgroundAuditWarning = Program.Code(error); }
        }
        AuditStamp Record(string kind, string state, string? target = null, string? reason = null, object? evidence = null, object? details = null)
        {
            audit ??= ExecutionAudit.Open(policy, own);
            return audit.Append(new AuditEvent(kind, query.TaskId, query.RequestId, state, target, reason, query.Thread,
                new { Source = source, Helper = own, Version = policy.Version, query.WorkId, GrantRevision = workGrant?.Revision, Evidence = evidence }), details);
        }
        object WithdrawalReport(AdminLaunchEntry withdrawn)
        {
            string? warning = null;
            try { Record("admin_launch_withdrawal", withdrawn.State, withdrawn.Target, withdrawn.Reason,
                new { withdrawn.Dispatched, withdrawn.Process, withdrawn.NativePid }); }
            catch (Exception error) { warning = Program.Code(error); }
            return Report(query, withdrawn, withdrawn.State,
                processState: withdrawn.State == "cancelled" ? "not_created" : "unknown", auditWarning: warning);
        }
        try
        {
            // Stop the exact in-flight owner before any recovery storage read.
            // A damaged journal/sidecar must not delay a real cancellation.
            var cancellation = query.Command == "cancel"
                ? core.WithdrawAdminLaunch(source, query.TaskId, query.ProgramRef, query.RequestId) : default;
            var journal = AdminLaunchJournal.Open(policy, own);
            if (cancellation.Withdrawn)
            {
                var cancelled = PersistWithdrawal(journal, query, source, cancellation.Owners.Any(owner => owner.AdminLaunchOwnsIntent));
                return WithdrawalReport(cancelled);
            }
            AdminLaunchEntry? closed = null;
            if (query.Command != "list")
            {
                lock (Gate)
                    if (journal.FindOriginal(query.RequestId) is null) closed = SemanticExecution.FindClosed(policy, own, query.RequestId);
            }
            if (closed is not null)
            {
                bool reconnected = RequireOriginal(closed, query, source);
                return Report(query, closed, closed.State,
                    query.Command == "cancel" ? "program_launch_already_submitted_not_terminated" : null,
                    processState: "exited", sourceReconnected: reconnected);
            }
            ReapExited(journal, RecordObserved);
            if (query.Command == "list")
            {
                var settings = UserPermissions.Read();
                var programs = new List<object>();
                foreach (var listed in settings.AdminLaunchAllowlist.Where(Eligible).DistinctBy(ProgramRef))
                {
                    try
                    {
                        RequirePreferences(settings, listed.Path);
                        var actual = UacIdentity.InspectForAllowlist(listed.Path);
                        if (!Matches(listed, actual)) continue;
                        programs.Add(new { ProgramRef = ProgramRef(listed), listed.DisplayName, Path = actual.Path,
                            listed.IdentityKind, Arguments = "" });
                    }
                    catch (Exception error) when (error is Boundary or IOException or UnauthorizedAccessException) { }
                }
                return new { Phase = "program_launch", query.Command, query.TaskId, query.ConnectionId,
                    query.ProgramRef, query.RequestId, query.ProgramPath, query.Arguments, State = "listed", Reason = (string?)null, Dispatched = false,
                    LaunchMode = settings.AdminLaunchMode,
                    AdminLaunchEnabled = settings.AdminLaunchEnabled, LaunchAvailable = settings.AdminLaunchEnabled
                        && settings.AdminWindows && !core.IsPaused && !core.IsFault,
                    Programs = programs, PhysicalInputFree = true, WindowReady = false, BusinessVerified = false };
            }
            AdminLaunchEntry? prior;
            lock (Gate)
            {
                prior = journal.FindOriginal(query.RequestId);
                recoveryRead = true;
            }
            if (prior is not null)
            {
                var sourceReconnected = RequireOriginal(prior, query, source);
                // Read-only recovery remains reachable after Stop or permission
                // revocation. It cannot clear unknown, dispatch or kill.
                var observed = Observe(prior);
                string? auditWarning = backgroundAuditWarning;
                try
                {
                    observed = PersistObservation(journal, observed);
                    ReleaseExited(observed.Entry);
                    if (observed.Entry != prior)
                    {
                        try { Record("admin_launch_observed", observed.Entry.State, observed.Entry.Target, evidence: new { observed.Entry.Process, observed.Entry.ExitCode, observed.ProcessState }); }
                        catch (Exception auditError) { auditWarning = Program.Code(auditError); }
                    }
                }
                catch (Exception error)
                {
                    return Report(query, observed.Entry, observed.Entry.State, "program_launch_status_persistence_unconfirmed:" + Program.Code(error),
                        observed.ProcessState, observed.Window, sourceReconnected);
                }
                return Report(query, observed.Entry, observed.Entry.State,
                    query.Command == "cancel" && observed.Entry.State != "cancelled" ? "program_launch_already_submitted_not_terminated" : null,
                    observed.ProcessState, observed.Window, sourceReconnected, auditWarning);
            }
            if (query.Command is "status" or "cancel")
                return Report(query, null, "unknown", "program_launch_request_unknown");
            // Only a new launch compacts exact script exits. Recovery reads do
            // not depend on creating or writing the new sidecar namespace.
            stage = "archive_closed_execution";
            foreach (var exited in journal.Read().Where(r => SemanticExecution.CanContinueAfterExit(policy, own, r)))
            {
                lock (Gate)
                {
                    SemanticExecution.ArchiveClosed(policy, own, exited);
                    journal.RemoveClosedExecution(exited);
                }
            }
            stage = "audit_request";
            Record("admin_launch_requested", "requested", query.ProgramPath == "" ? null : query.ProgramPath,
                evidence: new { query.ProgramRef, ArgumentsDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(query.Arguments))).ToLowerInvariant() },
                details: new { query.ProgramPath, query.Arguments, query.Execution });
            stage = "policy_check";
            core.RefreshPermissions();
            long revision = core.Revision;
            long? stopEpoch = core.WriteGate?.Snapshot().Epoch;
            Check(core, request, revision);
            var currentSettings = UserPermissions.Read(); RequireMode(currentSettings);
            bool semantic = currentSettings.AdminLaunchMode == "semantic";
            if (query.NewRun is { } next && (semantic || query.Command != "launch" || !Digest(next.ExitReference)
                || string.IsNullOrWhiteSpace(next.Evidence) || next.Evidence.Length > 2048
                || next.Evidence.Any(c => char.IsControl(c))))
                throw new Boundary("program_launch_new_run_invalid");
            if (semantic) workGrant = WorkAuthority.Require(policy, own, query.Thread, query.WorkId);
            // Semantic tiers grant administrator execution as a whole, because
            // the user cannot enumerate the hosts a development task will need.
            // The target is still resolved and re-identified locally, and the
            // tier blacklists plus the effect rules in SemanticLaunchPolicy win.
            stage = "semantic_row_identity";
            var row = semantic
                ? SemanticRow(currentSettings, query)
                : currentSettings.AdminLaunchAllowlist.Where(Eligible).FirstOrDefault(r => ProgramRef(r) == query.ProgramRef)
                    ?? throw new Boundary("program_launch_allowlist_miss");
            RequirePreferences(currentSettings, row.Path);
            stage = "executable_pin";
            using var pinned = new PinnedProgram(row, semantic);
            stage = "execution_binding";
            using var execution = semantic ? new SemanticExecution(query, pinned.ExecutableSha256, () => Check(core, request, revision), pinned.CanonicalPath) : null;
                // ProgramIdentity returns native GetFinalPathNameByHandleW's
                // normalized DOS path, rather than an unverified 8.3 alias.
            var target = Target(pinned.CanonicalPath);
            stage = "target_refresh";
            if (execution is not null)
            {
                independentNewRunReview = execution.IndependentNewRunReview(policy, own, target, workGrant!);
                // Semantic new-run is nested in execution; defer its freshness
                // check until the persisted blockers can supply a root proof.
                if (!execution.HasNewRun) execution.RequireFreshExecution(policy, own, target, workGrant);
            }
            RefreshTarget(journal, target, RecordObserved);
                // Source preflight is requested only after resolving a current
                // protected rule; source admission itself grants no exception.
            var callerPreflight = request.AdminLaunchLastPreflight ?? throw new Boundary("program_launch_caller_preflight_unconfirmed");
            stage = "caller_preflight";
            callerPreflight();
            // Wait on this original executor, without holding the journal gate.
            // The wait is bounded and Stop/deadline/policy changes cancel it.
            stage = "creation_resource";
            using var resources = WaitForCreationResource(() => Check(core, request, revision));
            FinalCallerPreflight(callerPreflight, () => Check(core, request, revision));
            Native.VerifyPeer(request.Owner ?? throw new Boundary("program_launch_caller_unavailable"));
            if (Native.Process(source.Pid, false).Identity != source) throw new Boundary("program_launch_caller_changed");
            Check(core, request, revision); currentSettings = UserPermissions.Read(); RequireMode(currentSettings);
            RequirePreferences(currentSettings, row.Path);
            if (semantic)
            {
                SemanticLaunchPolicy.RequireAllowed(currentSettings, query.ProgramPath,
                    string.Join(' ', query.Execution!.Argv), structured: true);
                if (!currentSettings.AdminLaunchMode.Equals("semantic", StringComparison.Ordinal))
                    throw new Boundary("program_launch_mode_changed");
            }
            else if (!currentSettings.AdminLaunchAllowlist.Any(r => Eligible(r) && ProgramRef(r) == query.ProgramRef))
                    throw new Boundary("program_launch_allowlist_changed");
            pinned.Recheck(); Check(core, request, revision);
            var entry = new AdminLaunchEntry(query.TaskId, query.RequestId, query.ProgramRef, target,
                source.User, source.Session, "unknown", "program_launch_creation_unconfirmed", Caller: source,
                LaunchKind: pinned.LaunchKind, EnvironmentPolicy: "ordinary-app-allowlist-v1", WorkloadState: "unknown");
            stage = "intent_journal_write";
            lock (Gate)
            {
                if (execution is not null && !execution.HasNewRun)
                    execution.RequireFreshExecution(policy, own, target, workGrant);
                var entries = journal.Read();
                if (entries.Any(r => r.RequestId == query.RequestId) || journal.FindReceipt(query.RequestId) is not null
                    || SemanticExecution.FindClosed(policy, own, query.RequestId) is not null)
                    throw new Boundary("program_launch_original_status_required");
                // Terminal receipts do not consume the active 4096-slot ledger.
                // New terminal results have already been archived by Replace;
                // old terminal rows are compacted incrementally before admission.
                var blockers = entries.Where(r => r.Target == target && BlocksTarget(r, ProcessState(r))).ToArray();
                if (!semantic)
                {
                    var version = $"{policy.Version}\n{own.Pid}\n{own.Created}\n{currentSettings.Revision}\n{pinned.ExecutableSha256}";
                    var treeProof = AllowlistExitReference(blockers, query, target, own.User, own.Session,
                        version);
                    var rootProof = treeProof is null ? AllowlistRootExitReference(blockers, query, target, own.User, own.Session,
                        version, ProcessState, requestId => Workloads.ContainsKey(requestId)) : null;
                    var proof = treeProof ?? rootProof;
                    if (treeProof is not null) independentNewRunReview = new { Eligible = true, ExitReference = treeProof,
                        PreviousTreeExited = true, PreviousBusinessState = "unknown", AuthorityTransferred = false };
                    else if (rootProof is not null) independentNewRunReview = new { Eligible = true, ExitReference = rootProof,
                        RootProcessExited = true, PreviousTreeExited = false, ProofKind = "root_exit_tracking_lost",
                        TreeEvidence = "helper_restart_workload_tracking_unavailable",
                        PreviousBusinessState = "unknown", AuthorityTransferred = false };
                    if (query.NewRun is { } newRun && (proof is null || newRun.ExitReference != proof))
                        throw new Boundary("program_launch_new_run_exit_reference_changed");
                    if (blockers.Length > 0 && query.NewRun is null)
                        throw new Boundary(treeProof is not null ? "program_launch_target_pending"
                            : rootProof is not null ? "program_launch_root_exited_workload_unknown" : "program_launch_target_pending");
                }
                else
                {
                    string? rootExitReference = null;
                    if (blockers.Length > 0)
                    {
                        var rootReview = execution!.IndependentRootExitReview(policy, own, target, workGrant!, blockers, ProcessState,
                            requestId => Workloads.ContainsKey(requestId), out var rootReference);
                        rootExitReference = rootReference;
                        if (rootExitReference is not null) independentNewRunReview = rootReview;
                    }
                    if (execution!.HasNewRun)
                        execution!.RequireFreshExecution(policy, own, target, workGrant, rootExitReference);
                    else if (blockers.Length > 0)
                        throw new Boundary(rootExitReference is not null ? "program_launch_root_exited_workload_unknown"
                            : "program_launch_target_pending");
                }
                if (entries.Count >= 4096) throw new Boundary("program_launch_recovery_capacity");
                // This durable intent precedes the sole CreateProcess call. A
                // crash anywhere afterward cannot authorize a second call.
                entries.Add(entry); journal.Write(entries);
                request.AdminLaunchOwnsIntent = true;
                Creating[query.RequestId] = 0;
            }
            bool attempted = false;
            try
            {
                void VerifySuspended(SafeProcessHandle handle, int pid)
                {
                    var actual = ReadProcess(handle, pid);
                    if (actual.User != own.User || actual.Session != own.Session || actual.Integrity != 12288
                        || TokenUiAccess(handle))
                        throw new Boundary("program_launch_created_identity_unverified");
                    if (Target(actual.Image) != target)
                        throw new Boundary("program_launch_image_redirected_bind_actual_executable");
                }
                stage = "audit_intent";
                var stamp = Record("admin_launch_dispatch_intent", "not_yet_dispatched", target,
                    evidence: new { row.IdentityKind, row.Identity, pinned.ExecutableSha256, query.ProgramRef, entry.LaunchKind, entry.EnvironmentPolicy,
                        Execution = execution?.Evidence, IndependentNewRun = query.NewRun?.ExitReference },
                    details: new { Executable = pinned.CanonicalPath, Arguments = execution?.Arguments ?? "", Execution = execution?.Details, query.NewRun });
                stage = "execution_seal";
                execution?.SealIntent(policy, own, query, workGrant!, target, stamp);
                Check(core, request, revision); pinned.Recheck(); Check(core, request, revision);
                if (stopEpoch is { } epoch) core.WriteGate!.Admit(epoch);
                stage = "dispatch_preflight";
                var started = request.SubmitAdminLaunch(() => UserPermissions.WithCurrentPolicy(own.User, currentSettings.Revision, () => {
                    if (semantic)
                        return WorkAuthority.Dispatch(policy, own, query.Thread, query.WorkId, workGrant!.Revision, () => {
                            Check(core, request, revision); pinned.Recheck(); execution!.Recheck(); Check(core, request, revision);
                            stage = "create_process"; attempted = true;
                            var created = Create(query.RequestId, pinned.CanonicalPath, execution.Arguments, execution.WorkingDirectory, execution.Environment, VerifySuspended);
                            if (created.Handle is not null) execution.OwnCreated();
                            return created;
                        });
                    return DshCallSource.Dispatch(() => {
                        Check(core, request, revision); pinned.Recheck(); Check(core, request, revision);
                        stage = "create_process"; attempted = true;
                        return Create(query.RequestId, pinned.CanonicalPath, row.Arguments ?? "", verifySuspended: VerifySuspended);
                    });
                }));
                // Creation is the only foreground-sensitive short stage. No
                // window/status wait keeps the global desktop resource.
                if (started.Handle is not null)
                {
                    Processes[query.RequestId] = started.Handle;
                    GetProcessTimes(started.Handle, out var nativeCreated, out _, out _, out _);
                    entry = entry with { NativePid = started.Pid, NativeCreated = nativeCreated > 0 ? nativeCreated : null, Dispatched = true, WorkloadState = "running" };
                }
                resources.Dispose();
                if (started.Handle is not null && started.Error != 0)
                    throw new Boundary("program_launch_suspended_cleanup_unconfirmed", started.Error);
                if (started.Handle is null)
                {
                    entry = entry with { State = "rejected", Dispatched = false, Reason = started.Reason ?? "program_launch_create_failed:" + started.Error };
                    stage = "result_journal_write";
                    lock (Gate) { journal.Replace(entry); }
                    try { Record("admin_launch_result", entry.State, target, entry.Reason, new { entry.Dispatched }); }
                    catch (Exception auditError) { return Report(query, entry, entry.State, auditWarning: Program.Code(auditError)); }
                    return Report(query, entry, entry.State);
                }
                    try { execution?.RetainUntilWorkloadExit(query.RequestId); }
                    catch (Exception error) { backgroundAuditWarning = Program.Code(error); } // Pins remain owned for the helper lifetime.
                    // Keep the original process object for subsequent status.
                    // Neither Stop nor a caller disconnect terminates it.
                    lock (Gate) { journal.Replace(entry); }
                    stage = "created_identity";
                    var process = ReadProcess(started.Handle, started.Pid);
                    if (process.User != own.User || process.Session != own.Session || process.Integrity != 12288
                        || Target(process.Image) != target || TokenUiAccess(started.Handle))
                        throw new Boundary("program_launch_created_identity_unverified");
                    entry = entry with { State = "created", Reason = null, Process = process };
                    stage = "result_journal_write";
                    lock (Gate) { journal.Replace(entry); }
                    try { Record("admin_launch_result", "created", target, evidence: new { entry.Process, entry.Dispatched, entry.LaunchKind }); }
                    catch (Exception auditError) { return Report(query, entry, "created", processState: ProcessState(entry), auditWarning: Program.Code(auditError)); }
                    return Report(query, entry, "created", processState: ProcessState(entry), auditWarning: backgroundAuditWarning);
            }
            catch (Exception error)
            {
                    request.CaptureAdminLaunchFailure(error, stage);
                    if (!attempted && request.AdminLaunchWasWithdrawn)
                    {
                        try
                        {
                            var cancelled = PersistWithdrawal(journal, query, source, request.AdminLaunchOwnsIntent);
                            return WithdrawalReport(cancelled);
                        }
                        catch (Exception persistenceError)
                        { return Report(query, null, "unknown", "program_launch_cancellation_receipt_unconfirmed:" + Program.Code(persistenceError)); }
                    }
                    // Any failure after invoking creation is uncertain, even
                    // if its result or durable receipt could not be inspected.
                    entry = entry with { State = attempted ? "unknown" : "rejected", Reason = Program.Code(error),
                        Dispatched = attempted ? entry.Dispatched : false };
                    try { lock (Gate) { journal.Replace(entry); } } catch (Exception) { /* Original durable unknown remains. */ }
                    try { Record("admin_launch_result", entry.State, target, entry.Reason, new { entry.Process, entry.NativePid, entry.NativeCreated, entry.Dispatched }); }
                    catch (Exception auditError) { return Report(query, entry, entry.State, auditWarning: Program.Code(auditError), failure: request.AdminLaunchFailure); }
                    return Report(query, entry, entry.State, failure: request.AdminLaunchFailure);
            }
            finally { Creating.TryRemove(query.RequestId, out _); }
        }
        catch (Exception error)
        {
            request.CaptureAdminLaunchFailure(error, stage);
            string? auditWarning = null;
            if (query.Command == "launch")
            {
                try { Record("admin_launch_denied", "not_dispatched_by_this_call", reason: Program.Code(error), evidence: new { Failure = request.AdminLaunchFailure }); }
                catch (Exception auditError) { auditWarning = Program.Code(auditError); }
            }
            if (query.Command == "launch" && request.AdminLaunchWasWithdrawn)
            {
                try
                {
                    var cancelled = PersistWithdrawal(AdminLaunchJournal.Open(policy, own), query, source, request.AdminLaunchOwnsIntent);
                    return WithdrawalReport(cancelled);
                }
                catch (Exception persistenceError)
                { return Report(query, null, "unknown", "program_launch_cancellation_receipt_unconfirmed:" + Program.Code(persistenceError)); }
            }
            // A missing/unreadable original ledger cannot prove that this ID
            // has never created a process in an earlier connection.
            return Report(query, null, query.Command is "status" or "cancel" || query.Command == "launch" && !recoveryRead
                || error is Boundary { Code: "program_launch_original_binding_rejected" }
                ? "unknown" : "rejected", Program.Code(error), auditWarning: auditWarning, failure: request.AdminLaunchFailure,
                independentNewRunReview: independentNewRunReview);
        }
    }

    private static bool Matches(UacApplicationPermission expected, UacApplicationPermission actual)
        => Target(expected.Path) == Target(actual.Path) && expected.IdentityKind == actual.IdentityKind
            && expected.Identity == actual.Identity && actual.Arguments == "";
    internal static AdminLaunchEntry PersistWithdrawal(AdminLaunchJournal journal, ProgramLaunchQuery query, Peer source, bool ownsIntent)
    {
        lock (Gate)
        {
            var prior = journal.FindOriginal(query.RequestId);
            if (prior is not null)
            {
                // Withdrawal always requires action authority. A status-shaped
                // internal binding must not inherit read-only reconnection.
                RequireOriginal(prior, query with { Command = "cancel" }, source);
                // A fresh colliding caller must never clear an older unknown.
                // Only the current unsubmitted owner may retire its own intent.
                if (prior.State != "unknown" || !ownsIntent) return prior;
                if (prior.Dispatched == true || prior.Process is not null || prior.NativePid is not null)
                    throw new Boundary("program_launch_withdrawal_submission_unconfirmed");
            }
            var cancelled = prior is null
                ? new AdminLaunchEntry(query.TaskId, query.RequestId, query.ProgramRef, "", source.User, source.Session,
                    "cancelled", "program_launch_task_cancelled", Caller: source, Dispatched: false)
                : prior with { State = "cancelled", Reason = "program_launch_task_cancelled", Dispatched = false };
            if (prior is null) journal.Archive(cancelled);
            else journal.Replace(cancelled);
            if (journal.FindOriginal(query.RequestId) != cancelled) throw new Boundary("program_launch_journal_write_unconfirmed");
            return cancelled;
        }
    }
    internal static bool BlocksTarget(AdminLaunchEntry entry, string state)
        => entry.State is "unknown" or "handoff_unknown" || entry.State == "created";
    internal static string? AllowlistExitReference(IEnumerable<AdminLaunchEntry> entries, ProgramLaunchQuery query,
        string target, string user, int session, string version)
    {
        var blockers = entries.OrderBy(r => r.RequestId, StringComparer.Ordinal).ToArray();
        if (blockers.Length == 0 || blockers.Any(r => r.Target != target || r.User != user || r.Session != session
            || r.RequestId == query.RequestId || r.State != "handoff_unknown" || r.Dispatched != true
            || r.WorkloadState != "exited" || r.ExitCode is null || r.Process is not { } process
            || process.User != user || process.Session != session || process.Integrity != 12288 || Target(process.Image) != target
            || r.NativePid != process.Pid || r.NativeCreated != process.Created)) return null;
        // Bind every unresolved record, the current protected rule and current
        // caller task. This is an opaque exit proof, never transferred authority
        // or a successful business result. Adding another launch changes it.
        var binding = JsonSerializer.Serialize(new { Kind = "flower-allowlist-new-run-v1", query.TaskId,
            query.ProgramRef, Target = target, User = user, Session = session, Version = version, Entries = blockers });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(binding))).ToLowerInvariant();
    }
    internal static string? AllowlistRootExitReference(IEnumerable<AdminLaunchEntry> entries, ProgramLaunchQuery query,
        string target, string user, int session, string version, Func<AdminLaunchEntry, string> processState,
        Func<string, bool> workloadTracked)
    {
        var blockers = entries.OrderBy(r => r.RequestId, StringComparer.Ordinal).ToArray();
        if (blockers.Length == 0 || !blockers.Any(r => r.WorkloadState == "unknown")
            || blockers.Any(r => r.Target != target || r.User != user || r.Session != session
                || r.RequestId == query.RequestId || r.State is not ("created" or "unknown" or "handoff_unknown")
                || r.Dispatched != true || r.WorkloadState is not ("unknown" or "exited")
                || r.EnvironmentPolicy != "ordinary-app-allowlist-v1"
                || r.WorkloadState == "unknown" && workloadTracked(r.RequestId)
                || r.Process is not { } process || r.NativePid != process.Pid || r.NativeCreated != process.Created
                || process.User != user || process.Session != session || process.Integrity != 12288
                || Target(process.Image) != target)) return null;
        var observed = blockers.Select(entry => new { Entry = entry, RootProcessState = processState(entry) }).ToArray();
        if (observed.Any(value => value.RootProcessState is not ("exited" or "root_exited")
            || value.RootProcessState == "exited" && value.Entry.ExitCode is null
            || value.RootProcessState == "root_exited" && value.Entry.ExitCode is not null)) return null;
        // This is deliberately weaker than a tracked-tree exit. It proves only
        // that each recorded root process is gone after the helper lost its
        // anonymous job handles; the new-run evidence must state that limit.
        var binding = JsonSerializer.Serialize(new { Kind = "flower-allowlist-root-exit-tracking-lost-v1", query.TaskId,
            query.ProgramRef, Target = target, User = user, Session = session, Version = version,
            Entries = observed.Select(value => new { value.Entry.RequestId, value.Entry.State, value.Entry.WorkloadState,
                value.Entry.Process, value.Entry.NativePid, value.Entry.NativeCreated, value.Entry.ExitCode,
                value.RootProcessState }) });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(binding))).ToLowerInvariant();
    }
    internal static bool RequireOriginal(AdminLaunchEntry prior, ProgramLaunchQuery query, Peer source)
    {
        if (prior.TaskId != query.TaskId || prior.RequestId != query.RequestId || prior.ProgramRef != query.ProgramRef
            || prior.User != source.User || prior.Session != source.Session
            || query.Command != "status" && prior.Caller != source)
            throw new Boundary("program_launch_original_binding_rejected");
        // BrokerHost already admitted the current host. This only permits
        // reading the same immutable request after its source process changes;
        // it neither authenticates a human nor transfers creation/withdrawal.
        return query.Command == "status" && prior.Caller is not null && prior.Caller != source;
    }
    private static void Check(BrokerState core, BrokerRequest request, long revision)
    {
        core.Check(revision);
        if (request.Stop.IsCancellationRequested) throw new Boundary(request.Reason ?? "program_launch_cancelled");
        Native.Desktop();
    }
    private static ResourceLocks WaitForCreationResource(Action check)
    {
        var deadline = Stopwatch.StartNew();
        while (true)
        {
            check();
            try { return new ResourceLocks(["desktop-foreground-input-v1"]); }
            catch (Boundary error) when (error.Code == "resource_busy")
            {
                if (deadline.ElapsedMilliseconds >= 5000) throw new Boundary("program_launch_resource_busy");
                Thread.Sleep(25);
            }
        }
    }
    internal static void FinalCallerPreflight(Action preflight, Action check)
    {
        // This runs after resource acquisition, outside the journal gate. The
        // original owner must recheck Medium input debt immediately before the
        // fixed launch, even if it changed while this executor was waiting.
        check(); preflight(); check();
    }
    private static string ProcessState(AdminLaunchEntry entry)
    {
        if (entry.Process is not { } original) return "unknown";
        try
        {
            if (Processes.TryGetValue(entry.RequestId, out var retained))
            {
                uint wait = WaitForSingleObject(retained, 0);
                return wait == 0 ? entry.ExitCode is null ? "root_exited" : "exited"
                    : wait == 258 ? "running" : "unknown";
            }
            // Restart recovery never launches or kills. Creation time prevents
            // a reused PID from being treated as the original program.
            var probe = ProbeDetachedRoot(original.Pid, original.Created);
            if (probe.State == "running")
                return probe.Process is { } actual && SameProcess(original, actual) ? "running" : "unknown";
            if (probe.State == "exited") return "exited";
            if (probe.State == "root_exited") return entry.ExitCode is null ? "root_exited" : "exited";
            return "unknown";
        }
        catch (Exception) { return "unknown"; }
    }

    private static DetachedRootProbe ProbeDetachedRoot(int pid, long expectedCreated)
    {
        try
        {
            using var handle = OpenProcess(0x1000 | 0x100000, false, pid);
            if (handle.IsInvalid)
                return new(Marshal.GetLastWin32Error() == 87 ? "root_exited" : "unknown");
            if (!GetProcessTimes(handle, out var created, out _, out _, out _)) return new("unknown");
            if (created != expectedCreated) return new("root_exited");
            uint wait = WaitForSingleObject(handle, 0);
            if (wait == 0)
                return GetExitCodeProcess(handle, out var exitCode)
                    ? new("exited", ExitCode: exitCode) : new("root_exited");
            if (wait != 258) return new("unknown");
            try { return new("running", ReadProcess(handle, pid)); }
            catch (Exception) { return new("unknown"); }
        }
        catch (Exception) { return new("unknown"); }
    }

    internal static string ProbeRootExitState(int pid, long expectedCreated)
        => ProbeDetachedRoot(pid, expectedCreated).State;

    internal static AdminLaunchEntry RecordExit(AdminLaunchEntry entry, uint exitCode)
        => entry with { ExitCode = exitCode, State = entry.State == "unknown" ? "unknown"
            : "handoff_unknown", Reason = entry.State == "unknown" ? entry.Reason : "program_launch_handoff_unverified" };

    private static AdminLaunchWorkloadSnapshot? WorkloadSnapshot(AdminLaunchEntry entry)
    {
        if (entry.WorkloadState == "legacy") return null;
        if (entry.WorkloadState == "exited") return new("exited", []);
        if (!Workloads.TryGetValue(entry.RequestId, out var workload))
            return new("unknown", [], "program_launch_workload_tracking_unavailable");
        return workload.Observe((handle, pid) => {
            var process = ReadProcess(handle, pid);
            if (process.User != entry.User || process.Session != entry.Session || TokenUiAccess(handle))
                throw new Boundary("program_launch_workload_identity_unverified");
            return process;
        });
    }
    internal static AdminLaunchEntry WithWorkloadObservation(AdminLaunchEntry entry, string state)
    {
        if (state is not ("running" or "exited" or "unknown")) throw new Boundary("program_launch_workload_state_invalid");
        // A durable completed tree cannot acquire new members. An uncertain
        // creation remains uncertain even when this observer sees no members.
        return entry.WorkloadState == "legacy" || entry.WorkloadState == "exited" ? entry : entry with { WorkloadState = state };
    }
    internal static AdminLaunchEntry MergeObservation(AdminLaunchEntry current, AdminLaunchEntry incoming)
    {
        if (current.TaskId != incoming.TaskId || current.RequestId != incoming.RequestId || current.ProgramRef != incoming.ProgramRef
            || current.Target != incoming.Target || current.User != incoming.User || current.Session != incoming.Session
            || current.Caller != incoming.Caller)
            throw new Boundary("program_launch_observation_binding_changed");
        // Observers do native reads outside Gate. A delayed running/creating
        // snapshot must not overwrite an already persisted identity or exit,
        // especially after the corresponding handles have been retired.
        var merged = incoming with {
            Process = current.Process ?? incoming.Process,
            NativePid = current.NativePid ?? incoming.NativePid,
            NativeCreated = current.NativeCreated ?? incoming.NativeCreated,
            Dispatched = current.Dispatched == true ? true : incoming.Dispatched,
            WorkloadState = current.WorkloadState == "exited" || incoming.WorkloadState == "legacy"
                ? current.WorkloadState : incoming.WorkloadState
        };
        if (current.Process is not null && incoming.Process is null
            || current.NativePid is not null && incoming.NativePid is null
            || current.ExitCode is not null && incoming.ExitCode is null)
            merged = merged with { State = current.State, Reason = current.Reason };
        if (current.ExitCode is not null) merged = merged with { ExitCode = current.ExitCode };
        return merged;
    }
    private static (AdminLaunchEntry Entry, string ProcessState, AdminLaunchWindow? Window) Observe(AdminLaunchEntry entry)
    {
        var original = ObserveProcess(entry);
        if (entry.WorkloadState == "legacy" || entry.State is "rejected" or "cancelled"
            || Creating.ContainsKey(entry.RequestId)) return original;
        var snapshot = WorkloadSnapshot(original.Entry)!;
        var current = WithWorkloadObservation(original.Entry, snapshot.State);
        AdminLaunchWindow? window = original.Window;
        foreach (var process in snapshot.Processes.Where(p => p.Integrity == 12288))
        {
            if (window is not null) break;
            try
            {
                RequirePreferences(UserPermissions.Read(), process.Image);
                window = FindWindow(process);
            }
            catch (Exception) { /* A denied/unreadable child is not a ready target. */ }
        }
        return (current, original.ProcessState, window);
    }
    private static (AdminLaunchEntry Entry, string ProcessState, AdminLaunchWindow? Window) PersistObservation(AdminLaunchJournal journal,
        (AdminLaunchEntry Entry, string ProcessState, AdminLaunchWindow? Window) observed)
    {
        lock (Gate)
        {
            journal.Replace(observed.Entry);
            var current = journal.FindOriginal(observed.Entry.RequestId)
                ?? throw new Boundary("program_launch_original_request_missing");
            return (current, current.ExitCode is not null ? "exited" : observed.ProcessState,
                current.WorkloadState == "exited" ? null : observed.Window);
        }
    }
    private static (AdminLaunchEntry Entry, string ProcessState, AdminLaunchWindow? Window) ObserveProcess(AdminLaunchEntry entry)
    {
        if (entry.State is "rejected" or "cancelled") return (entry, "not_created", null);
        if (Creating.ContainsKey(entry.RequestId)) return (entry, "creation_in_progress", null);
        if (entry.ExitCode is not null) return (entry, "exited", null);
        try
        {
            if (!Processes.TryGetValue(entry.RequestId, out var handle))
            {
                var pid = entry.Process?.Pid ?? entry.NativePid;
                var created = entry.Process?.Created ?? entry.NativeCreated;
                if (pid is null || created is null) return (entry, "unknown", null);
                var probe = ProbeDetachedRoot(pid.Value, created.Value);
                if (probe.State == "exited" && probe.ExitCode is { } exitCode)
                    return (RecordExit(entry, exitCode), "exited", null);
                if (probe.State == "root_exited") return (entry, "root_exited", null);
                if (probe.State != "running" || probe.Process is not { } actual)
                    return (entry, "unknown", null);
                if (actual.User != entry.User || actual.Session != entry.Session || actual.Integrity != 12288
                    || Target(actual.Image) != entry.Target
                    || entry.Process is not null && actual != entry.Process
                    || entry.NativeCreated is { } expected && expected != actual.Created)
                    return (entry, "running_identity_unknown", null);
                entry = entry with { Process = actual, NativePid = actual.Pid, NativeCreated = actual.Created, Dispatched = true };
                return (entry, "running", FindWindow(actual));
            }
            lock (handle)
            {
                uint wait = WaitForSingleObject(handle, 0);
                if (wait == 0)
                {
                    if (!GetExitCodeProcess(handle, out var exitCode)) return (entry, "root_exited", null);
                    // Never reinterpret unknown as a safe-to-retry terminal.
                    var result = RecordExit(entry, exitCode);
                    return (result, "exited", null);
                }
                if (wait != 258) return (entry, "unknown", null);
                var pid = entry.Process?.Pid ?? entry.NativePid ?? (int)GetProcessId(handle);
                if (pid <= 0) return (entry, "running_identity_unknown", null);
                var actual = ReadProcess(handle, pid);
                if (actual.User != entry.User || actual.Session != entry.Session || actual.Integrity != 12288
                    || Target(actual.Image) != entry.Target || TokenUiAccess(handle)
                    || entry.Process is not null && actual != entry.Process
                    || entry.NativeCreated is { } expected && expected != actual.Created)
                    return (entry, "running_identity_unknown", null);
                entry = entry with { Process = actual, NativePid = actual.Pid, NativeCreated = actual.Created, Dispatched = true };
                return (entry, "running", FindWindow(actual));
            }
        }
        catch (Exception) { return (entry, "unknown", null); }
    }
    private static void RefreshTarget(AdminLaunchJournal journal, string target, Action<AdminLaunchEntry, string>? record = null)
    {
        List<AdminLaunchEntry> entries;
        lock (Gate) { entries = journal.Read().Where(entry => entry.Target == target).ToList(); }
        foreach (var entry in entries)
        {
            AdminLaunchEntry current;
            lock (Gate) { current = journal.FindOriginal(entry.RequestId) ?? throw new Boundary("program_launch_original_request_missing"); }
            var observed = Observe(current);
            observed = PersistObservation(journal, observed);
            if (observed.Entry != current) record?.Invoke(observed.Entry, observed.ProcessState);
            ReleaseExited(observed.Entry);
        }
    }
    private static void ReleaseExited(AdminLaunchEntry entry)
    {
        if (entry.WorkloadState == "exited")
        {
            if (PayloadReleases.TryRemove(entry.RequestId, out var release)) release();
            if (Workloads.TryRemove(entry.RequestId, out var workload)) workload.Dispose();
        }
        if (entry.ExitCode is null || !Processes.TryGetValue(entry.RequestId, out var handle)) return;
        lock (handle)
        {
            if (WaitForSingleObject(handle, 0) == 0 && Processes.TryRemove(entry.RequestId, out var retired)) retired.Dispose();
        }
    }
    private static void ReapExited(AdminLaunchJournal journal, Action<AdminLaunchEntry, string>? record = null)
    {
        // Opportunistic retirement on the next tool request, with no permanent
        // monitor. Journal I/O and process inspection never share a long lock.
        List<AdminLaunchEntry> entries;
        lock (Gate) { entries = journal.Read(); }
        foreach (var old in entries.Take(64))
        {
            lock (Gate)
            {
                var archived = journal.FindReceipt(old.RequestId);
                if (archived is not null) journal.Replace(archived);
                else if (AdminLaunchJournal.Terminal(old)) journal.Replace(old);
            }
        }
        if (Processes.IsEmpty && Workloads.IsEmpty) return;
        foreach (var entry in entries)
        {
            try
            {
                if (!Workloads.ContainsKey(entry.RequestId)
                    && (!Processes.TryGetValue(entry.RequestId, out var handle) || WaitForSingleObject(handle, 0) != 0)) continue;
                var observed = Observe(entry);
                observed = PersistObservation(journal, observed);
                if (observed.Entry != entry) record?.Invoke(observed.Entry, observed.ProcessState);
                ReleaseExited(observed.Entry);
            }
            catch (Exception) { /* Keep original handle and durable intent for status. */ }
        }
    }
    private delegate bool EnumWindowCallback(IntPtr hwnd, IntPtr parameter);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool EnumWindows(EnumWindowCallback callback, IntPtr parameter);
    [DllImport("user32.dll")] private static extern bool IsHungAppWindow(IntPtr hwnd);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr hwnd, uint attribute, out uint value, uint size);
    internal static bool SameProcess(AdminLaunchedProcess expected, AdminLaunchedProcess actual)
        => expected.Pid == actual.Pid && expected.Created == actual.Created && expected.Session == actual.Session
            && expected.User == actual.User && expected.Integrity == actual.Integrity && Target(expected.Image) == Target(actual.Image);
    private static AdminLaunchWindow? FindWindow(AdminLaunchedProcess expected)
    {
        AdminLaunchWindow? found = null;
        // A bounded current snapshot; no activation, messages, title/content
        // observation or background polling. A title is never an identity.
        EnumWindows((hwnd, _) => {
            try
            {
                uint thread = Native.GetWindowThreadProcessId(hwnd, out var pid);
                if (pid != expected.Pid || thread == 0 || !Native.IsWindowVisible(hwnd)
                    || Native.GetAncestor(hwnd, 2) != hwnd || IsHungAppWindow(hwnd)
                    || DwmGetWindowAttribute(hwnd, 14, out var cloaked, 4) != 0 || cloaked != 0) return true;
                Native.Desktop(thread);
                var current = Native.Process((int)pid, false);
                var p = current.Identity;
                if (!SameProcess(expected, new((int)pid, p.Created, current.Image, p.Integrity, p.User, p.Session))) return true;
                var bounds = Native.Bounds(hwnd.ToInt64());
                if (bounds[2] <= bounds[0] || bounds[3] <= bounds[1] || !Native.IsWindow(hwnd)
                    || Native.GetWindowThreadProcessId(hwnd, out var again) == 0 || again != pid
                    || Native.Process((int)pid, false).Identity != p) return true;
                found = new(hwnd.ToInt64(), expected); return false;
            }
            catch (Exception) { return true; }
        }, IntPtr.Zero);
        return found;
    }

    internal static Dictionary<string, string> OrdinaryEnvironment(IEnumerable<KeyValuePair<string, string>> environment)
    {
        // Same allowlist as drivers/app_lifecycle.py. This removes inherited
        // provider credentials; it does not isolate plugins, DLLs or settings.
        var allowed = new HashSet<string>(["SystemRoot", "SystemDrive", "WINDIR", "COMSPEC", "PATH", "PATHEXT",
            "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
            "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "HOMEDRIVE", "HOMEPATH", "PUBLIC", "LANG", "LC_ALL"], StringComparer.OrdinalIgnoreCase);
        var result = environment.Where(pair => allowed.Contains(pair.Key)).ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        if (!result.ContainsKey("SystemRoot") && !result.ContainsKey("WINDIR")) throw new Boundary("windows_system_root_missing");
        return result;
    }

    private sealed class PinnedProgram : IDisposable
    {
        private readonly UacApplicationPermission row;
        private readonly bool semantic;
        private readonly List<SafeFileHandle> parents = [];
        private FileStream? file;
        private UacProgramFileIdentity? identity;
        internal string CanonicalPath => identity?.Path ?? throw new Boundary("program_launch_file_unavailable");
        internal string ExecutableSha256 => identity?.Sha256 ?? throw new Boundary("program_launch_file_unavailable");
        internal string LaunchKind
        {
            get
            {
                var stream = file ?? throw new Boundary("program_launch_file_unavailable");
                stream.Position = 0;
                using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
                if (reader.ReadUInt16() != 0x5a4d) return "unknown";
                stream.Position = 0x3c; int header = reader.ReadInt32();
                if (header < 0x40 || header > stream.Length - 94) return "unknown";
                stream.Position = header;
                if (reader.ReadUInt32() != 0x00004550) return "unknown";
                stream.Position = header + 24;
                if (reader.ReadUInt16() is not (0x10b or 0x20b)) return "unknown";
                stream.Position = header + 24 + 68;
                return reader.ReadUInt16() switch { 3 => "console", 2 => "gui", _ => "unknown" };
            }
        }
        internal PinnedProgram(UacApplicationPermission row, bool semantic = false)
        {
            this.row = row; this.semantic = semantic;
            try
            {
                var ancestors = new Stack<string>();
                for (var parent = Path.GetDirectoryName(Path.GetFullPath(row.Path)); parent is not null; parent = Path.GetDirectoryName(parent))
                    ancestors.Push(parent);
                while (ancestors.TryPop(out var parent))
                {
                    BrokerPolicy.RejectLinks(parent);
                    var handle = CreateFileW(parent, 0x20080, 1, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
                    if (handle.IsInvalid) { handle.Dispose(); throw new Boundary("program_launch_directory_pin_failed", Marshal.GetLastWin32Error()); }
                    parents.Add(handle);
                }
                BrokerPolicy.RejectLinks(row.Path);
                file = new FileStream(row.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                Recheck();
            }
            catch { Dispose(); throw; }
        }
        internal void Recheck()
        {
            using var document = UacNativeBridge.ProgramIdentity(row.Path);
            var actual = UacProgramBinding.DecodeIdentity(document.RootElement);
            if (!semantic && !actual.AllowlistProtected || !Matches(row, actual.Permission with { Arguments = "" })
                || identity is not null && actual != identity)
                throw new Boundary("program_launch_file_changed");
            if (!semantic) UacIdentity.RequireAllowlistSupported(row.Path);
            // Native inspection verifies ACL/signature/hash and all ancestors.
            // Our handles preserve those same objects through creation.
            identity = actual;
        }
        public void Dispose()
        { file?.Dispose(); file = null; foreach (var parent in parents) parent.Dispose(); parents.Clear(); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Startup
    {
        internal uint Size; internal string? Reserved, Desktop, Title;
        internal uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        internal ushort Show, ReservedSize; internal IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation
    { internal IntPtr Process, Thread; internal int Pid, Tid; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref Startup startup, out ProcessInformation information);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(SafeProcessHandle handle, out uint code);
    [DllImport("kernel32.dll")] private static extern uint GetProcessId(SafeProcessHandle handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder image, ref uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int kind, IntPtr buffer, int size, out int needed);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    // Resolves one semantic launch into a verified permission row. Identity is
    // computed from the real file, never from the request, so a caller cannot
    // claim a hash it did not read.
    private static UacApplicationPermission SemanticRow(UserPermissionSettings settings, ProgramLaunchQuery query)
    {
        SemanticExecution.Validate(query);
        SemanticLaunchPolicy.RequireAllowed(settings, query.ProgramPath, string.Join(' ', query.Execution!.Argv), structured: true);
        var inspected = UacIdentity.Inspect(query.ProgramPath);
        return inspected with { Arguments = "", Enabled = true };
    }
    private static (SafeProcessHandle? Handle, int Pid, int Error, string? Reason) Create(string requestId, string path, string arguments,
        string? workingDirectory = null, IReadOnlyDictionary<string, string>? boundEnvironment = null,
        Action<SafeProcessHandle, int>? verifySuspended = null)
    {
        var startup = new Startup { Size = (uint)Marshal.SizeOf<Startup>(), Desktop = "winsta0\\default" };
        // Explicit application + quoted argv[0]. Arguments are appended to the
        // command line verbatim; there is no shell, so nothing is re-expanded.
        // Windows applies the existing High broker token; no ShellExecute/runas.
        var values = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .Select(pair => new KeyValuePair<string, string>((string)pair.Key, (string)pair.Value!));
        var environment = boundEnvironment ?? OrdinaryEnvironment(values);
        var block = string.Join('\0', environment.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
        var pointer = Marshal.StringToHGlobalUni(block);
        AdminLaunchWorkload? workload = null;
        bool transferred = false;
        try
        {
            try { workload = AdminLaunchWorkload.Create(); }
            catch (Exception error)
            {
                // No CreateProcess call has occurred. A job allocation failure
                // is a known rejection, not a durable uncertain launch.
                return (null, 0, error is System.ComponentModel.Win32Exception win32 ? win32.NativeErrorCode : 1, null);
            }
            var commandLine = arguments.Length == 0 ? "\"" + path + "\"" : "\"" + path + "\" " + arguments;
            // Establish tree membership before any application instruction can
            // run. Neither closing the job nor Stop terminates submitted work.
            if (!CreateProcessW(path, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, false, 0x400 | 0x4,
                    pointer, workingDirectory ?? Path.GetDirectoryName(path)!, ref startup, out var result))
                return (null, 0, Marshal.GetLastWin32Error(), null);
            var process = new SafeProcessHandle(result.Process, true);
            try
            {
                workload.Assign(process);
                // Windows may redirect an executable to an AppX alias. Check
                // the actual image and token while no app instruction has run.
                // The caller must bind the real executable for a fresh request.
                (verifySuspended ?? throw new Boundary("program_launch_verifier_missing"))(process, result.Pid);
                if (!Workloads.TryAdd(requestId, workload)) throw new Boundary("program_launch_workload_binding_conflict");
                transferred = true;
                if (ResumeThread(result.Thread) == uint.MaxValue)
                    throw new Boundary("program_launch_resume_failed", Marshal.GetLastWin32Error());
                return (process, result.Pid, 0, null);
            }
            catch (Exception error)
            {
                // Only this still-suspended, never-executed process may be
                // terminated during setup. Do not terminate a resumed result.
                if (TerminateProcess(process, 1) && WaitForSingleObject(process, 1000) == 0)
                {
                    process.Dispose();
                    if (transferred && Workloads.TryRemove(requestId, out var failed)) failed.Dispose();
                    return (null, 0, error is Boundary b && b.NativeCode is { } code ? code : 1,
                        error is Boundary boundary ? boundary.Message : null);
                }
                // Preserve the handle and durable unknown instead of claiming
                // a safe rejection or ever dispatching the same intent again.
                return (process, result.Pid, Marshal.GetLastWin32Error() is var native && native != 0 ? native : 1, null);
            }
            finally { CloseHandle(result.Thread); }
        }
        finally { Marshal.FreeHGlobal(pointer); if (!transferred) workload?.Dispose(); }
    }
    private static bool TokenUiAccess(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, 8, out var token)) throw new Boundary("program_launch_token_unavailable", Marshal.GetLastWin32Error());
        using (token)
        {
            var data = Marshal.AllocHGlobal(4);
            try
            {
                if (!GetTokenInformation(token, 26, data, 4, out _)) throw new Boundary("program_launch_token_unavailable");
                return Marshal.ReadInt32(data) != 0;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
    }
    private static AdminLaunchedProcess ReadProcess(SafeProcessHandle process, int pid)
    {
        if (!GetProcessTimes(process, out var created, out _, out _, out _)) throw new Boundary("program_launch_process_unavailable");
        var path = new StringBuilder(32768); uint size = 32768;
        if (!QueryFullProcessImageNameW(process, 0, path, ref size)) throw new Boundary("program_launch_image_unavailable");
        if (!OpenProcessToken(process, 8, out var token)) throw new Boundary("program_launch_token_unavailable");
        using (token)
        {
            GetTokenInformation(token, 25, IntPtr.Zero, 0, out var needed);
            if (needed is < 1 or > 4096) throw new Boundary("program_launch_token_unavailable");
            var data = Marshal.AllocHGlobal(needed);
            try
            {
                if (!GetTokenInformation(token, 25, data, needed, out _)) throw new Boundary("program_launch_token_unavailable");
                var sid = Marshal.ReadIntPtr(data); var count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                if (count == 0) throw new Boundary("program_launch_token_unavailable");
                int integrity = Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
                using var identity = new WindowsIdentity(token.DangerousGetHandle());
                var user = identity.User?.Value ?? throw new Boundary("program_launch_token_unavailable");
                var session = Marshal.AllocHGlobal(4);
                try
                {
                    if (!GetTokenInformation(token, 12, session, 4, out _)) throw new Boundary("program_launch_token_unavailable");
                    return new(pid, created, path.ToString(), integrity, user, Marshal.ReadInt32(session));
                }
                finally { Marshal.FreeHGlobal(session); }
            }
            finally { Marshal.FreeHGlobal(data); }
        }
    }
}

internal sealed class AdminLaunchJournal
{
    private sealed record Snapshot(int Schema, AdminLaunchEntry[] Entries);
    private readonly string path, sid;
    private readonly bool fixture;
    private AdminLaunchJournal(string path, string sid, bool fixture)
    { this.path = path; this.sid = sid; this.fixture = fixture; }
    internal static AdminLaunchJournal Open(BrokerPolicy policy, Peer own)
    {
        var root = InstallationLocation.Current().ProgramRoot;
        if (policy.Fixture || policy.Mode != "high" || own.Integrity != 12288 || own.User != policy.UserSid
            || !Path.GetFullPath(policy.Directory).TrimEnd('\\').Equals(Path.Combine(root, "versions", policy.Version), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("program_launch_storage_role_rejected");
        UacClaimJournal.CheckParent(Path.GetDirectoryName(root)!, false); UacClaimJournal.CheckParent(root, false);
        foreach (var part in new[] { "recovery", "program-launch" })
        {
            root = Path.Combine(root, part);
            try { UacClaimJournal.CheckParent(root, part == "program-launch"); }
            catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
            { SecurityLabel.CreateDirectory(root, policy.UserSid); UacClaimJournal.CheckParent(root, true); }
        }
        // Deliberately outside version directories: upgrading the broker must
        // not make an unresolved launch disappear or permit a new request ID.
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(own.User + ":" + own.Session))).ToLowerInvariant();
        return new(Path.Combine(root, key + ".json"), own.User, false);
    }
    // Only used by a Medium pure-storage selftest; never accepted by Handle.
    internal static AdminLaunchJournal TestStorage(string path)
    {
        if (Native.Process(Environment.ProcessId, false).Identity.Integrity != 8192
            || !Path.GetFullPath(path).StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase))
            throw new Boundary("program_launch_test_storage_rejected");
        return new(path, "fixture", true);
    }
    internal List<AdminLaunchEntry> Read()
    {
        BrokerPolicy.RejectLinks(Path.GetDirectoryName(path)!);
        if (!File.Exists(path)) return [];
        BrokerPolicy.RejectLinks(path); if (!fixture) UserPermissions.CheckProtection(path);
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is < 1 or > 4 * 1024 * 1024) throw new Boundary("program_launch_journal_rejected");
        using var document = JsonDocument.Parse(input); Protocol.CheckUnique(document);
        var value = Protocol.Decode<Snapshot>(document);
        if (value.Schema != 1 || value.Entries is null || value.Entries.Length > 4096
            || value.Entries.Any(r => !Valid(r))
            || value.Entries.Select(r => r.RequestId).Distinct().Count() != value.Entries.Length)
            throw new Boundary("program_launch_journal_rejected");
        return value.Entries.ToList();
    }
    private bool Valid(AdminLaunchEntry r)
        => AdminProgramLaunch.Id(r.TaskId) && AdminProgramLaunch.Id(r.RequestId)
            && AdminProgramLaunch.Digest(r.ProgramRef) && r.State is "unknown" or "created" or "rejected" or "cancelled" or "handoff_unknown"
            && (r.State == "cancelled" && r.Target == "" || r.Target == AdminProgramLaunch.Target(r.Target)) && (fixture || r.User == sid) && r.Session > 0
            && (r.NativePid is null || r.NativePid > 0) && (r.NativeCreated is null || r.NativeCreated > 0)
            && r.LaunchKind is "unknown" or "console" or "gui"
            && r.EnvironmentPolicy is "inherited-legacy" or "ordinary-app-allowlist-v1"
            && r.WorkloadState is "legacy" or "running" or "exited" or "unknown"
            && (r.State != "created" || r.Process is not null)
            && (r.State != "cancelled" || r.Dispatched == false && r.Process is null && r.NativePid is null && r.NativeCreated is null && r.ExitCode is null)
            && (r.State != "handoff_unknown" || r.Process is not null && r.ExitCode is not null)
            && (r.Caller is null || r.Caller.Pid > 0 && r.Caller.Created > 0 && r.Caller.Session == r.Session && r.Caller.User == r.User)
            && (r.Process is not { } p || p.Pid > 0 && p.Created > 0 && p.Integrity == 12288 && p.User == r.User
                && (r.NativePid is null || p.Pid == r.NativePid) && (r.NativeCreated is null || p.Created == r.NativeCreated)
                && p.Session == r.Session && AdminProgramLaunch.Target(p.Image) == r.Target);
    internal static bool Terminal(AdminLaunchEntry entry) => entry.State is "rejected" or "cancelled";
    private string ReceiptPath(string requestId)
    {
        if (!AdminProgramLaunch.Id(requestId)) throw new Boundary("program_launch_binding_rejected");
        var root = path + ".receipts";
        if (!Directory.Exists(root))
        {
            if (fixture) Directory.CreateDirectory(root); else SecurityLabel.CreateDirectory(root, sid);
        }
        BrokerPolicy.RejectLinks(root);
        if (!fixture) UacClaimJournal.CheckParent(root, true);
        return Path.Combine(root, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(requestId))).ToLowerInvariant() + ".json");
    }
    internal AdminLaunchEntry? FindReceipt(string requestId)
    {
        var receipt = ReceiptPath(requestId);
        if (!File.Exists(receipt)) return null;
        BrokerPolicy.RejectLinks(receipt); if (!fixture) UserPermissions.CheckProtection(receipt);
        using var input = new FileStream(receipt, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is < 1 or > 512 * 1024) throw new Boundary("program_launch_receipt_rejected");
        using var document = JsonDocument.Parse(input); Protocol.CheckUnique(document);
        var entry = Protocol.Decode<AdminLaunchEntry>(document);
        if (!Valid(entry) || !Terminal(entry) || entry.RequestId != requestId) throw new Boundary("program_launch_receipt_rejected");
        return entry;
    }
    internal AdminLaunchEntry? FindOriginal(string requestId)
    {
        var archived = FindReceipt(requestId);
        if (archived is not null)
        {
            // A prior crash may have preserved both an original intent and its
            // already-durable rejected receipt. Finish that exact transition.
            Replace(archived); return archived;
        }
        return Read().SingleOrDefault(entry => entry.RequestId == requestId);
    }
    internal void Archive(AdminLaunchEntry entry)
    {
        if (!Valid(entry) || !Terminal(entry)) throw new Boundary("program_launch_terminal_required");
        var prior = FindReceipt(entry.RequestId);
        if (prior is not null)
        { if (prior != entry) throw new Boundary("program_launch_receipt_conflict"); return; }
        var receipt = ReceiptPath(entry.RequestId);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(entry);
        var temporary = receipt + "." + Guid.NewGuid().ToString("N") + ".tmp";
        if (fixture) File.WriteAllBytes(temporary, bytes); else SecurityLabel.Write(temporary, bytes, sid);
        using (var output = new FileStream(temporary, FileMode.Open, FileAccess.Write, FileShare.None)) output.Flush(true);
        if (!fixture) UserPermissions.CheckProtection(temporary);
        File.Move(temporary, receipt, false);
        if (FindReceipt(entry.RequestId) != entry) throw new Boundary("program_launch_journal_write_unconfirmed");
    }
    // Called under the broker's short journal gate. Archive first, remove from
    // active ledger second: a crash can duplicate a receipt but cannot lose it.
    internal void Replace(AdminLaunchEntry entry)
    {
        var entries = Read();
        int index = entries.FindIndex(r => r.RequestId == entry.RequestId);
        var archived = FindReceipt(entry.RequestId);
        if (archived is not null)
        {
            if (archived != entry) throw new Boundary("program_launch_receipt_conflict");
            if (index >= 0)
            {
                var original = entries[index];
                if (original.TaskId != archived.TaskId || original.ProgramRef != archived.ProgramRef
                    || original.Target != archived.Target || original.User != archived.User || original.Session != archived.Session
                    || original.Caller != archived.Caller || original.Dispatched == true && archived.Dispatched == false)
                    throw new Boundary("program_launch_receipt_conflict");
                entries.RemoveAt(index); Write(entries);
            }
            return;
        }
        if (index < 0) throw new Boundary("program_launch_original_request_missing");
        if (Terminal(entry)) { Archive(entry); entries.RemoveAt(index); }
        else entries[index] = AdminProgramLaunch.MergeObservation(entries[index], entry);
        Write(entries);
    }
    internal void Write(List<AdminLaunchEntry> entries)
    {
        if (entries.Count > 4096 || entries.Any(r => !Valid(r)) || entries.Select(r => r.RequestId).Distinct().Count() != entries.Count)
            throw new Boundary("program_launch_journal_rejected");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        BrokerPolicy.RejectLinks(Path.GetDirectoryName(path)!);
        if (File.Exists(path)) { BrokerPolicy.RejectLinks(path); if (!fixture) UserPermissions.CheckProtection(path); }
        if (File.Exists(temporary)) { BrokerPolicy.RejectLinks(temporary); if (!fixture) UserPermissions.CheckProtection(temporary); }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new Snapshot(1, entries.ToArray()));
        if (bytes.Length > 4 * 1024 * 1024) throw new Boundary("program_launch_recovery_capacity");
        if (fixture) File.WriteAllBytes(temporary, bytes);
        else SecurityLabel.Write(temporary, bytes, sid);
        using (var output = new FileStream(temporary, FileMode.Open, FileAccess.Write, FileShare.None)) output.Flush(true);
        if (!fixture) UserPermissions.CheckProtection(temporary);
        File.Move(temporary, path, true);
        if (!fixture) UserPermissions.CheckProtection(path);
        using var verified = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (verified.Length != bytes.Length) throw new Boundary("program_launch_journal_write_unconfirmed");
        var current = new byte[bytes.Length]; verified.ReadExactly(current);
        if (!current.SequenceEqual(bytes)) throw new Boundary("program_launch_journal_write_unconfirmed");
    }
    internal void RemoveClosedExecution(AdminLaunchEntry closed)
    {
        var entries = Read();
        int index = entries.FindIndex(row => row.RequestId == closed.RequestId);
        if (index < 0) return;
        if (entries[index] != closed || closed.State != "handoff_unknown" || closed.Dispatched != true
            || closed.Process is null || closed.ExitCode is null) throw new Boundary("program_launch_closed_receipt_conflict");
        entries.RemoveAt(index); Write(entries);
    }
}
