using System.Diagnostics;
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed record UacCapabilities(bool CancelAvailable, bool AcceptAvailable,
    bool SemanticAuthorityAvailable, bool AllowlistAvailable, string Reason, bool ProgramBindingAvailable = false)
{
    // Finite genuine-prompt metadata only. This does not authorize expanding
    // details, cancelling, accepting, credential entry or arbitrary SYSTEM UI.
    public bool ObserveAvailable { get; init; }
    // This describes implementation support, not route readiness or a grant.
    // Only the protected saved setting enables the selected-prompt scope.
    public bool CancellationScopeAvailable { get; init; } = true;
    public bool SemanticExpansionRemoved => true;
    public string SemanticAuthorityReason => "uac_semantic_expansion_removed";
}
internal sealed record UacQuery(string Phase, string TaskId, string Command, string ConnectionId, string? PromptRef = null,
    string? SessionHash = null, string? TurnId = null, AuditThread? Thread = null);
internal sealed record UacPermissionQuery(string Phase, string TaskId, string ConnectionId, string SessionHash,
    string TurnId, string Decision, string? MessageRef = null, string? ScopeKind = null, string[]? ProgramPaths = null);
internal sealed record UacBridgeRequest(string Nonce, int Session, Peer Parent, Peer Source, string TaskId,
    string Command, string PolicyRevision, long StopEpoch, bool ControlledExperiment = false, UacPromptIdentity? ExpectedPrompt = null,
    string? TestNonce = null, long DeadlineTick = 0, UacChatAuthorizationSnapshot? ChatAuthorization = null,
    int? QualificationIndex = null)
{
    public long SelectionExpiresTick { get; init; }
    public bool SemanticSourceVerified { get; init; }
}
internal sealed record UacReady(string Phase, string Nonce, string TaskId, UacPromptIdentity Prompt, string ObservationId);
internal sealed record UacGo(string Phase, string Nonce, string TaskId, UacPromptIdentity Prompt, string ObservationId);
internal sealed record UacObservedPrompt(UacPromptIdentity Prompt, Peer Source, string TaskId, long Tick);
internal sealed record UacPromptSelection(UacPromptIdentity Prompt, long ExpiresTick);

internal static class UacRuntime
{
    private static readonly ConcurrentDictionary<string, UacObservedPrompt> observedPrompts = new(StringComparer.Ordinal);
    // Bind the prompt to the claim that will actually be written. A completed
    // request keeps its historical prompt, which must not leak into its successor.
    internal static (UacClaimEntry Entry, UacPromptIdentity? ExpectedPrompt, bool NewClaim) BindRequestClaim(
        UacClaimEntry? previous, string taskId, string sourceDigest, UacPromptIdentity? selectedPrompt, bool recoveredLegacy)
    {
        bool replace = previous is null || previous.State == "released" || recoveredLegacy;
        var current = replace ? new UacClaimEntry(1, Guid.NewGuid().ToString("N"), taskId, sourceDigest,
            "reserved", InputFree: true) : previous!;
        return (current, selectedPrompt ?? current.Prompt, replace);
    }
    internal static void RequireResumeClaimQuiescent(UacClaimEntry? entry)
    {
        if (entry is not null && (!entry.InputFree || entry.State is "reserved" or "observed" or "dispatching"))
            throw new Boundary("uac_original_work_still_running");
    }
    internal static void ResumeLocalControl(BrokerState core)
    {
        var own = Native.Process(Environment.ProcessId).Identity;
        if (own.Integrity != 12288 || Native.UiAccess(own.Pid)) throw new Boundary("protected_stop_local_resume_required");
        var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
        if (own.User != policy.UserSid || policy.Fixture) throw new Boundary("protected_stop_local_resume_required");
        using var claim = new Mutex(false, "Local\\FlowerControl.UacClaim." + own.User + "." + own.Session);
        bool held = false;
        try
        {
            try { held = claim.WaitOne(0); }
            catch (AbandonedMutexException) { held = true; throw new Boundary("uac_previous_owner_result_unknown"); }
            if (!held || core.Requests.Values.Any(request => !request.ReadOnly))
                throw new Boundary("uac_original_work_still_running");
            RequireResumeClaimQuiescent(new UacClaimJournal(policy, own.Session).Read());
            UacInstallation.RequireExperimentQuiescent();
            var shared = core.WriteGate?.Snapshot() ?? throw new Boundary("shared_stop_state_unavailable");
            long protectedEpoch = core.ProtectedStopEpoch ?? throw new Boundary("protected_stop_state_unavailable");
            core.Pause(false, shared.Epoch, protectedEpoch);
            if (core.IsPaused) throw new Boundary("resume_state_changed");
        }
        finally { if (held) claim.ReleaseMutex(); }
    }
    internal static void RequireFreshObservation(UacObservedPrompt value, Peer source, string taskId, int session, long now)
    {
        if (value.Source != source || value.TaskId != taskId || value.Prompt.Session != session)
            throw new Boundary("uac_prompt_reference_foreign");
        if (value.Tick < 0 || value.Tick > now || now - value.Tick >= 10000)
            throw new Boundary("uac_prompt_reference_stale");
    }
    private static UacPromptSelection ConsumeSelection(UacQuery query, Peer source, int session)
    {
        if (query.PromptRef is null) throw new Boundary("uac_fresh_prompt_reference_required");
        if (!observedPrompts.TryGetValue(query.PromptRef, out var observation)) throw new Boundary("uac_prompt_reference_stale");
        RequireFreshObservation(observation, source, query.TaskId, session, Environment.TickCount64);
        if (!observedPrompts.TryRemove(new KeyValuePair<string, UacObservedPrompt>(query.PromptRef, observation)))
            throw new Boundary("uac_prompt_reference_stale");
        return new(observation.Prompt, checked(observation.Tick + 10000));
    }
    private static void RememberObservation(string reference, UacPromptIdentity prompt, Peer source, string taskId)
    {
        long now = Environment.TickCount64;
        foreach (var pair in observedPrompts)
            if (pair.Value.Tick > now || now - pair.Value.Tick >= 10000) observedPrompts.TryRemove(pair);
        if (observedPrompts.Count >= 256) throw new Boundary("uac_observation_capacity_reached");
        observedPrompts[reference] = new(prompt, source, taskId, now);
    }
    // A selected consent instance is deliberately broader than task ownership.
    // Reserve/claim and the elevation allowlist never satisfy this authority.
    internal static void RequireSelectedCancellation(UserPermissionSettings settings, UacBridgeRequest request,
        UacPromptIdentity actual, long now, bool stopped)
    {
        settings = UserPermissions.Effective(settings);
        if (stopped) throw new Boundary("global_write_stopped");
        if (settings.UacMode == "off") throw new Boundary("uac_disabled");
        if (settings.UacMode == "observe") throw new Boundary("uac_observation_only");
        if (settings.UacMode is not ("cancel" or "allowlist" or "semantic")) throw new Boundary("uac_mode_invalid");
        if (settings.Revision != request.PolicyRevision) throw new Boundary("uac_user_policy_changed");
        if (settings.UacCancellationScope != "selected_prompt_in_session") throw new Boundary("uac_prompt_attribution_unknown");
        if (request.Command is not ("cancel" or "auto") || request.ExpectedPrompt is null)
            throw new Boundary("uac_fresh_prompt_reference_required");
        if (request.Session <= 0 || actual.Session != request.Session || request.ExpectedPrompt != actual
            || actual.Pid <= 0 || actual.Created <= 0 || actual.Hwnd == 0)
            throw new Boundary("uac_prompt_changed_requires_new_observation");
        if (now < 0 || request.SelectionExpiresTick <= now || request.SelectionExpiresTick - now > 10000)
            throw new Boundary("uac_prompt_reference_stale");
    }
    internal static UacChoice AuthorizeProductionCancellation(UserPermissionSettings settings, UacBridgeRequest request,
        UacPromptIdentity actual, UacChoice decision, long now, bool stopped)
    {
        if (decision.Action != "esc") return decision;
        RequireSelectedCancellation(settings, request, actual, now, stopped);
        return decision with { Authority = "local_selected_prompt_in_session" };
    }
    internal static UacChatAuthorizationSnapshot ReadRestrictionContext(Func<UacChatAuthorizationSnapshot> refresh,
        Func<UacChatAuthorizationSnapshot> read, bool allowMissingConfirmationSource)
    {
        try { return refresh(); }
        catch (Boundary error) when (allowMissingConfirmationSource && error.Code == "uac_transcript_host_binding_required")
        {
            // Missing confirmation provenance grants no accept authority. The
            // protected record still preserves any actual denial or handoff.
            return read();
        }
    }
    private static UacChatAuthorizationSnapshot RefreshChatAuthorization(BrokerPolicy policy, Peer own, BrokerState core,
        string sessionHash, bool allowMissingConfirmationSource)
        => ReadRestrictionContext(() => UacTranscriptBinding.Refresh(policy, own, core, sessionHash),
            () => UacChatAuthorization.Read(policy, own.Session, sessionHash), allowMissingConfirmationSource);
    internal static void RequireChatCurrent(BrokerPolicy policy, int session, UacChatAuthorizationSnapshot snapshot, string command)
        => UacDecision.RequireChatSnapshotCurrent(snapshot, UacChatAuthorization.Read(policy, session, snapshot.SessionHash),
            Environment.TickCount64, command);
    // Ordinary host events identify restriction context only. They cannot grant
    // new elevation authority; production confirmation uses protected local
    // preauthorization. Fixed harmless tests retain their independent oracle.
    internal static int ResultTimeoutMilliseconds(long executionDeadline, long now)
        => checked((int)Math.Clamp(executionDeadline - now + 10000, 1, 55000));
    private sealed record Verification(int Schema, string Version, string NativeSha256, string HelperSha256, string ManagedHelperSha256,
        string ConsentSha256, string WindowsBuild, string CancelRoute, string AcceptRoute,
        bool SystemSessionVerified, bool SecureStopReachabilityVerified, bool CancelRouteVerified, bool AcceptRouteVerified,
        bool ProgramBindingVerified, bool SemanticAuthorityVerified);
    internal static string WindowsBuild()
    {
        using var machine = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
        using var version = machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            ?? throw new Boundary("uac_windows_build_unavailable");
        var build = version.GetValue("CurrentBuildNumber") as string;
        if (build is null || !Regex.IsMatch(build, "\\A[0-9]{1,10}\\z") || version.GetValue("UBR") is not int revision || revision < 0)
            throw new Boundary("uac_windows_build_unavailable");
        return build + "." + revision.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
    internal static string TaskName(string sid) => "FlowerControl.Uac." +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sid))).ToLowerInvariant()[..16];
    internal static string PipeName(BrokerPolicy policy) => "Flower.Uac.Bootstrap." + policy.Version + "." +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(policy.UserSid))).ToLowerInvariant()[..16];
    internal static void RestoreInputFault(BrokerPolicy policy, Peer own, BrokerState core)
    {
        if (policy.Fixture) return;
        try
        {
            if (own.Integrity == 8192)
            {
                if (UacClaimJournal.ReadOnlyInputFault(policy, own.Session)) core.Fault();
                return;
            }
            var journal = new UacClaimJournal(policy, own.Session);
            var entry = journal.Read();
            if (entry is not null && ((!entry.InputFree && entry.State is "dispatching" or "unknown")
                || entry.Reason == "explicit_stop_persistence_failed") && !journal.LegacyControlQuiesced()) core.Fault();
        }
        catch (Exception error)
        { core.Fault(); Console.Error.WriteLine(JsonSerializer.Serialize(new { uacRecovery = Program.Code(error) })); }
    }
    internal static UacCapabilities Capabilities()
    {
        // Old verification files remain historical evidence, not readiness for
        // a retired host-UAC capability. This does not alter saved permissions.
        return new(false, false, false, false, "host_uac_feature_retired")
            { ObserveAvailable = false, CancellationScopeAvailable = false };
    }
    internal static object Handle(BrokerPolicy policy, Peer own, Peer source, UacQuery query, string connectionId, BrokerState core, BrokerRequest owner)
    {
        if (policy.Fixture || own.Integrity != 12288 || query.ConnectionId != connectionId
            || !Regex.IsMatch(query.TaskId, "^[a-zA-Z0-9_-]{1,128}$")
            || query.Command is not ("status" or "reserve" or "release" or "observe" or "auto" or "cancel" or "accept")
            || query.PromptRef is not null && !Regex.IsMatch(query.PromptRef, "^[a-f0-9]{64}$"))
            throw new Boundary("uac_request_rejected");
        var capabilities = Capabilities();
        if (query.Command == "status")
        {
            object? permission = null;
            if (query.SessionHash is not null && Regex.IsMatch(query.SessionHash, "\\A[a-f0-9]{64}\\z"))
            {
                try { permission = PermissionView(UacTranscriptBinding.Refresh(policy, own, core, query.SessionHash)); }
                catch (Exception error) { permission = new { State = "unavailable", Reason = Program.Code(error) }; }
            }
            var currentSettings = UserPermissions.Read();
            return new { Phase = "uac", Capabilities = capabilities, Permission = permission,
                Mode = currentSettings.UacMode, CancellationScope = currentSettings.UacCancellationScope,
                SystemExecuted = false, InputDispatched = false };
        }
        var settings = UserPermissions.Read();
        if (settings.UacMode == "off" && query.Command != "release") return AuditedRefusal(policy, own, source, query,
            new { Phase = "uac", State = "disabled", Reason = "uac_disabled", CancellationScope = settings.UacCancellationScope, InputDispatched = false });
        try { core.CheckUac(write: query.Command is not ("observe" or "reserve" or "release")); }
        catch (Exception error)
        {
            _ = AuditedRefusal(policy, own, source, query, new { State = "blocked", Reason = Program.Code(error), InputDispatched = false });
            throw;
        }
        if (!UacOutcomeEvidence.CommandRouteAvailable(settings.UacMode, query.Command, capabilities))
            return AuditedRefusal(policy, own, source, query, new { Phase = "uac", State = "unavailable", Reason = capabilities.Reason,
                CancellationScope = settings.UacCancellationScope, InputDispatched = false });
        return Dispatch(policy, own, source, query, settings, core, owner);
    }
    private static object AuditedRefusal(BrokerPolicy policy, Peer own, Peer source, UacQuery query, object result)
    {
        if (query.Command is not ("auto" or "accept" or "cancel")) return result;
        try
        {
            ExecutionAudit.Open(policy, own).Append(new AuditEvent("uac_refused", query.TaskId, "", "not_dispatched_by_this_call",
                Thread: query.Thread, Evidence: new { query.Command, query.PromptRef, Source = source, Version = policy.Version, Result = result }));
            return result;
        }
        catch (Exception error)
        {
            var response = JsonSerializer.SerializeToNode(result)!.AsObject(); response["AuditWarning"] = Program.Code(error); return response;
        }
    }
    internal static object PermissionView(UacChatAuthorizationSnapshot snapshot)
    {
        var evaluation = UacChatAuthorization.Evaluate(snapshot, null);
        return new { State = snapshot.State == "allowed" ? "legacy_grant_inactive" : snapshot.State,
            GrantActive = false, snapshot.MessageRef, snapshot.MessageRevision, snapshot.GrantId,
            snapshot.ScopeKind, ProgramCount = snapshot.Programs.Length, snapshot.Revision,
            evaluation.Pending, evaluation.ExplicitlyDenied, evaluation.SemanticVerified,
            Provenance = "host_message_restrictions_only", HumanClickVerified = false, SemanticExpansionRemoved = true,
            PromptTextStored = false, ModeChanged = false, InputDispatched = false };
    }
    internal static object HandlePermission(BrokerPolicy policy, Peer own, UacPermissionQuery query, BrokerState core)
    {
        try
        {
        if (query.Phase != "uac_permission" || !Regex.IsMatch(query.SessionHash, "\\A[a-f0-9]{64}\\z")
            || string.IsNullOrWhiteSpace(query.TurnId) || query.TurnId.Length > 256 || query.TurnId.Any(char.IsControl)
            || query.Decision is not ("status" or "allow" or "keep" or "acknowledge" or "deny" or "revoke"))
            throw new Boundary("uac_permission_request_rejected");
        if (query.Decision is "allow" or "keep") throw new Boundary("uac_semantic_expansion_removed");
        UacDecision.RequirePermissionMode(UserPermissions.Read().UacMode, query.Decision);
        if (query.Decision is not ("deny" or "revoke"))
        {
            var reviewedMessage = RefreshChatAuthorization(policy, own, core, query.SessionHash, query.Decision == "status");
            // Tool turns and message turns are different host concepts. Bind
            // the decision to the exact fresh record/ref, never a guessed
            // parent/child turn relationship.
            query = query with { TurnId = reviewedMessage.TurnId ?? query.TurnId };
        }
        }
        catch (Exception error) { error.Data["PermissionWriteAttempted"] = false; throw; }
        if (query.Decision is "deny" or "revoke")
            foreach (var active in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == query.SessionHash))
                active.Cancel("uac_permission_revoked");
        var snapshot = query.Decision == "status"
            ? UacChatAuthorization.Read(policy, own.Session, query.SessionHash)
            : query.Decision is "deny" or "revoke"
                ? UacChatAuthorization.ReduceCurrentAuthority(policy, own.Session, query.SessionHash, query.TurnId, query.Decision)
            : UacChatAuthorization.Decide(policy, own.Session, query.SessionHash, query.TurnId,
                query.MessageRef ?? "", query.Decision, query.ScopeKind, query.ProgramPaths);
        if (snapshot.Changed)
            foreach (var pending in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == query.SessionHash))
                pending.Cancel("uac_permission_revision_changed");
        return new { Phase = "uac_permission", Permission = PermissionView(snapshot), InputDispatched = false };
    }
    internal static void AuthorizationFault(BrokerState core, Exception error)
    {
        if (error.Data["PersistenceFailure"] is not true) return;
        // The protected store keeps its own durable fault marker. Stop the
        // current executors even if the shared Stop write also fails.
        core.Fault();
        try { core.Pause(true); }
        catch (Exception stopError) { error.Data["StopPersistenceError"] = Program.Code(stopError); }
    }
    internal static bool AcceptExperimentConsistent(object? receipt, UacTestResult? business)
    {
        if (receipt is null || business is null || business.Status != "high_target_exited_zero" || business.Target is null || business.ExitCode != 0) return false;
        using var report = JsonSerializer.SerializeToDocument(receipt); var value = report.RootElement;
        return UacOutcomeEvidence.CleanupComplete(value)
            && value.TryGetProperty("PromptInstanceGone", out var gone) && gone.ValueKind == JsonValueKind.True
            && value.TryGetProperty("NativeResult", out var native) && native.ValueKind == JsonValueKind.Object
            && native.TryGetProperty("action", out var action) && action.GetString() == "accept"
            && native.TryGetProperty("uia_invoke_returned", out var returned) && returned.ValueKind == JsonValueKind.True
            && native.TryGetProperty("desktop_cleanup_verified", out var cleanup) && cleanup.ValueKind == JsonValueKind.True;
    }
    internal static bool CancelExperimentConsistent(object? receipt, UacTestResult? business)
    {
        if (receipt is null || business is null || business.Status != "business_cancelled" || business.Win32Error != 1223 || business.Target is not null) return false;
        using var report = JsonSerializer.SerializeToDocument(receipt);
        var value = report.RootElement;
        return UacOutcomeEvidence.CleanupComplete(value)
            && value.TryGetProperty("PromptInstanceGone", out var gone) && gone.ValueKind == JsonValueKind.True
            && value.TryGetProperty("NativeResult", out var native) && native.ValueKind == JsonValueKind.Object
            && native.TryGetProperty("input_dispatched", out var sent) && sent.ValueKind == JsonValueKind.True
            && native.TryGetProperty("route", out var route) && route.GetString() == "window_message"
            && native.TryGetProperty("messages_queued", out var count) && count.GetInt32() == 2
            && native.TryGetProperty("desktop_cleanup_verified", out var cleanup) && cleanup.ValueKind == JsonValueKind.True;
    }
    private static object Dispatch(BrokerPolicy policy, Peer own, Peer source, UacQuery query, UserPermissionSettings settings, BrokerState core, BrokerRequest owner)
        => throw new Boundary("host_uac_feature_retired");

}

internal static class UacSystemPipe
{
    // The worker reads Stop while writing progress/results. A synchronous
    // Stream serializes ReadAsync and WriteAsync and deadlocks that exchange.
    internal static NamedPipeClientStream OpenClient(string name)
        => new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { internal int Size; internal IntPtr Descriptor; internal int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern Microsoft.Win32.SafeHandles.SafePipeHandle CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint instances, uint output, uint input, uint timeout, ref Attributes attributes);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);
    internal static NamedPipeServerStream Create(string name)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;HI)", 1, out var descriptor, out _))
            throw new Boundary("uac_pipe_security_failed");
        try
        {
            var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
            var handle = CreateNamedPipeW("\\\\.\\pipe\\" + name, 0x40080003, 0x8, 1, 65536, 65536, 0, ref attributes);
            if (handle.IsInvalid) { handle.Dispose(); throw new Boundary("uac_pipe_create_failed", Marshal.GetLastWin32Error()); }
            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally { LocalFree(descriptor); }
    }
    internal static Peer Client(PipeStream pipe)
    {
        if (!Native.GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid)) throw new Boundary("uac_peer_unavailable");
        return Native.Process((int)pid).Identity;
    }
    internal static Peer Server(PipeStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid)) throw new Boundary("uac_peer_unavailable");
        return Native.Process((int)pid).Identity;
    }
    internal static void RequireFreshPeer(Peer peer)
    {
        if (Native.Process(peer.Pid).Identity != peer || Native.UiAccess(peer.Pid))
            throw new Boundary("uac_peer_identity_changed");
    }
    internal static void RequireHighParent(Peer peer, BrokerPolicy policy, int session)
    {
        RequireFreshPeer(peer);
        var application = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        if (peer.User != policy.UserSid || peer.Integrity != 12288 || session <= 0 || peer.Session != session
            || peer.ImageDigest != Native.Digest(application)
            || !Native.Process(peer.Pid).Image.Equals(application, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_high_parent_rejected");
    }
    internal static void RequireSameSystemImage(Peer peer, BrokerPolicy policy, int session)
    {
        RequireFreshPeer(peer);
        var application = Path.Combine(policy.Directory, "Flower.HighHelper.exe");
        if (peer.User != "S-1-5-18" || peer.Integrity != 16384 || peer.Session != session
            || peer.ImageDigest != Native.Digest(application)
            || !Native.Process(peer.Pid).Image.Equals(application, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_system_source_rejected");
    }
}
