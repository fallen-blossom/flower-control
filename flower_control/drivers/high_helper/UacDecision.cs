namespace Flower.HighHelper;

internal sealed record UacAuthority(bool GenuinePrompt, bool Stopped = false, bool Paused = false,
    bool ExplicitlyDenied = false, bool CredentialPrompt = false, bool SemanticVerified = false,
    bool SemanticScopeMatches = false, UacApplicationPermission? ActualProgram = null, string? ActualArgumentsSha256 = null);
internal sealed record UacChoice(string Action, string Reason, string Authority);

internal static class UacDecision
{
    internal static bool RestrictionsEnabled(string mode) => mode is "cancel" or "allowlist" or "semantic";
    internal static void RequirePermissionMode(string mode, string decision)
    {
        if (decision is "allow" or "keep") throw new Boundary("uac_semantic_expansion_removed");
        if (decision is "deny" or "revoke") return;
        if (!RestrictionsEnabled(mode)) throw new Boundary("uac_enabled_mode_required");
    }
    internal static bool HasUnreviewedMessage(UacChatAuthorizationSnapshot snapshot)
        => snapshot.MessageRef is not null && snapshot.Pending;
    internal static string? ChatBlockReason(UacChatAuthorizationSnapshot snapshot, string command)
    {
        var evaluation = UacChatAuthorization.Evaluate(snapshot, null);
        if (snapshot.Stopped) return "global_write_stopped";
        if (evaluation.ExplicitlyDenied) return "uac_current_user_denial";
        // An unreviewed real message may be Stop, human handoff or a denial.
        // Missing confirmation permission alone is a separate condition.
        if (HasUnreviewedMessage(snapshot)) return "uac_latest_message_review_required";
        return null;
    }
    internal static void RequireChatSnapshotCurrent(UacChatAuthorizationSnapshot expected,
        UacChatAuthorizationSnapshot current, long now, string command)
    {
        // Every production input is backed by local policy, never a chat grant.
        // Missing grant metadata is not a denial; real messages and restrictions
        // remain freshness barriers for both confirmation and cancellation.
        string? blocked = ChatBlockReason(current, "cancel") ?? ChatBlockReason(expected, "cancel");
        if (blocked is not null) throw new Boundary(blocked);
        if (expected.CapturedTick < 0 || expected.CapturedTick > now
            || now - expected.CapturedTick > UacChatAuthorization.SnapshotLifetimeMilliseconds)
            throw new Boundary("uac_chat_authority_not_current");
        // A missing accept grant/source may be stable cancellation context;
        // real messages still require review and every change cancels this run.
        var before = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(expected with { CapturedTick = 0, Changed = false });
        var after = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(current with { CapturedTick = 0, Changed = false });
        if (!before.SequenceEqual(after)) throw new Boundary("uac_chat_authority_changed");
    }
    internal static UacChoice ForCommand(string command, UacChoice choice, string mode, UacCapabilities capabilities)
    {
        if (choice.Action == "none") return choice;
        if (command == "cancel") return new("esc", "explicit_cancel", "saved_mode");
        if (command == "accept" && choice.Action != "accept") return new("none", "uac_accept_not_authorized", "none");
        // Allowlist eligibility never authorizes dismissing a different or
        // credential prompt. Cancellation is an explicit separate action.
        // Legacy semantic settings have the same reduced allowlist behavior.
        if (command == "auto" && (mode is "allowlist" or "semantic") && choice.Action == "esc")
            return new("none", choice.Reason, "none");
        if (command == "auto" && choice.Action == "accept"
            && !UacOutcomeEvidence.AuthorityRouteAvailable(mode, choice.Action, choice.Authority, capabilities))
            return new("none", "uac_confirmation_route_unavailable", "none");
        return choice;
    }
    // This function consumes verified evidence from the local executor. These
    // booleans are not fields accepted from a model/MCP request.
    internal static UacChoice Choose(UserPermissionSettings settings, UacAuthority evidence)
    {
        settings = UserPermissions.Effective(settings);
        if (settings.UacMode == "off") return new("none", "uac_disabled", "none");
        if (settings.UacMode == "observe") return new("none", "uac_observation_only", "none");
        if (!evidence.GenuinePrompt) return new("none", "genuine_uac_required", "none");
        if (evidence.Stopped || evidence.Paused || evidence.ExplicitlyDenied)
            return new("none", evidence.Stopped ? "global_write_stopped" : evidence.Paused ? "human_handoff" : "current_user_denial", "none");
        if (settings.UacMode == "cancel") return new("esc", "default_cancel", "saved_mode");
        if (evidence.CredentialPrompt) return new("esc", "credentials_required", "saved_mode");
        if (settings.UacMode == "semantic")
        {
            // A protected executable or a mode is not the missing work /
            // original launch / consent-instance causal proof. Keep explicit
            // cancel separate; auto/accept must not use the allowlist route.
            return new("esc", "uac_semantic_work_binding_unavailable", "none");
        }
        if (settings.UacMode != "allowlist") return new("none", "uac_mode_invalid", "none");
        // Confirmation cannot override the user's existing program denial.
        // Explicit cancellation keeps its independent selected-prompt route;
        // ForCommand maps auto/accept to no action for this ineligible target.
        if (evidence.ActualProgram is not null && UserPermissions.UacPromptDenied(settings, evidence.ActualProgram.Path))
            return new("esc", "window_disabled_by_user", "saved_mode");
        if (evidence.ActualProgram is not null && UserPermissions.UacAllowlisted(settings, evidence.ActualProgram,
            evidence.ActualArgumentsSha256 ?? (evidence.ActualProgram.Arguments is null ? null : UserPermissions.UacArgumentsSha256(evidence.ActualProgram.Arguments))))
            return new("accept", "allowlist_match", "local_allowlist");
        return new("esc", "uac_permission_missing", "saved_mode");
    }
}

internal static class UacSelfTests
{
    internal static object Run()
    {
        int assertions = 0;
        void Require(bool condition) { assertions++; if (!condition) throw new Boundary("uac_selftest_failed"); }
        // Real regression: cancel -> released -> accept compared the new UAC
        // against the completed cancel's HWND/PID, refusing before ready/go.
        var oldPrompt = new UacPromptIdentity(1, 14068, 134366163260907225, 26476990);
        var newPrompt = new UacPromptIdentity(1, 39068, 134366163744032352, 10686866);
        var completed = new UacClaimEntry(1, new string('a', 32), "cancel_done", new string('b', 64),
            "released", oldPrompt, new string('c', 64), true);
        foreach (var nextCommand in new[] { "accept", "cancel", "program0", "stop", "auto" })
        {
            var next = UacRuntime.BindRequestClaim(completed, nextCommand, completed.SourceDigest, null, false);
            Require(next.NewClaim && next.Entry.State == "reserved" && next.Entry.TaskId == nextCommand);
            Require(next.ExpectedPrompt is null && next.Entry.Prompt is null && next.Entry.PromptRef is null);
            Require(next.Entry.Nonce != completed.Nonce && completed.Prompt == oldPrompt);
        }
        var selected = UacRuntime.BindRequestClaim(completed, "next", completed.SourceDigest, newPrompt, false);
        Require(selected.NewClaim && selected.ExpectedPrompt == newPrompt);
        var active = completed with { State = "observed" };
        var retained = UacRuntime.BindRequestClaim(active, active.TaskId, active.SourceDigest, null, false);
        Require(!retained.NewClaim && retained.Entry == active && retained.ExpectedPrompt == oldPrompt);
        var unknown = completed with { State = "unknown" };
        var unresolved = UacRuntime.BindRequestClaim(unknown, unknown.TaskId, unknown.SourceDigest, null, false);
        Require(!unresolved.NewClaim && unresolved.Entry == unknown && unresolved.ExpectedPrompt == oldPrompt);
        var recovered = UacRuntime.BindRequestClaim(unknown, "new_fixed_test", unknown.SourceDigest, null, true);
        Require(recovered.NewClaim && recovered.ExpectedPrompt is null && unknown.State == "unknown");
        UacRuntime.RequireResumeClaimQuiescent(null); Require(true);
        UacRuntime.RequireResumeClaimQuiescent(completed); Require(true);
        UacRuntime.RequireResumeClaimQuiescent(unknown); Require(true);
        foreach (var state in new[] { "reserved", "observed", "dispatching", "unknown", "released" })
        {
            var pending = completed with { State = state, InputFree = state is not ("unknown" or "released") };
            try { UacRuntime.RequireResumeClaimQuiescent(pending); Require(false); }
            catch (Boundary error) { Require(error.Code == "uac_original_work_still_running"); }
        }
        var fixture = Path.Combine(Path.GetTempPath(), "flower-uac-decision-" + Guid.NewGuid().ToString("N") + ".exe");
        File.WriteAllText(fixture, "Owned non-executed identity matcher fixture.");
        try
        {
        var program = new UacApplicationPermission(fixture, "sha256", new string('a', 64), "Fixture", Arguments: "");
        var settings = new UserPermissionSettings { AdminLaunchEnabled = true, UacAllowlist = [program] };
        var observed = new UacAuthority(true, ActualProgram: program);
        foreach (var title in new[] { "", "future-private-window" })
        {
            var denied = settings with { UacMode = "allowlist", DeniedApplications = [new(program.Path, title)] };
            Require(!UserPermissions.UacAllowlisted(denied, program));
            var choice = UacDecision.Choose(denied, observed);
            Require(choice.Action == "esc" && choice.Reason == "window_disabled_by_user");
            var capability = new UacCapabilities(true, true, false, true, "fixture");
            Require(UacDecision.ForCommand("auto", choice, "allowlist", capability).Action == "none");
            Require(UacDecision.ForCommand("accept", choice, "allowlist", capability).Action == "none");
            Require(UacDecision.ForCommand("cancel", choice, "allowlist", capability).Action == "esc");
        }
        Require(UacDecision.Choose(settings with { UacMode = "allowlist", DeniedApplications = [new(program.Path, Enabled: false)] }, observed).Action == "accept");
        Require(UacDecision.Choose(settings with { UacMode = "allowlist", DeniedApplications = [new(fixture + ".other")] }, observed).Action == "accept");
        Require(UacDecision.Choose(settings with { UacMode = "off" }, observed).Action == "none");
        Require(UacDecision.Choose(settings with { UacMode = "cancel" }, observed).Action == "esc");
        Require(UacDecision.Choose(settings with { UacMode = "semantic" }, observed).Reason == "uac_semantic_work_binding_unavailable");
        Require(UacDecision.Choose(settings with { UacMode = "full", UacAllowlist = [] }, observed).Action == "none");
        Require(UacDecision.Choose(settings with { UacMode = "semantic" }, observed with { ActualProgram = null }).Action == "esc");
        Require(UacDecision.Choose(settings with { UacMode = "semantic" }, observed with {
            ActualProgram = null, SemanticVerified = true, SemanticScopeMatches = true }).Action == "esc");
        // Semantic tiers do not compare against a saved identity: the local
        // executor already computed ActualProgram from the real file.
        Require(UacDecision.Choose(settings with { UacMode = "semantic" }, observed with {
            ActualProgram = program with { Identity = new string('b', 64) } }).Action == "esc");
        var allCapabilities = new UacCapabilities(true, true, true, true, "fixture", true);
        Require(!UacOutcomeEvidence.AuthorityRouteAvailable("semantic", "accept", "tier_semantic", allCapabilities, true));
        Require(!UacOutcomeEvidence.RouteAvailable("semantic", "accept", allCapabilities));
        Require(UacOutcomeEvidence.AuthorityRouteAvailable("allowlist", "accept", "local_allowlist", allCapabilities, true));
        foreach (var mode in new[] { "cancel", "allowlist", "semantic" })
        {
            var current = settings with { UacMode = mode };
            Require(UacDecision.Choose(current, observed with { Stopped = true }).Action == "none");
            Require(UacDecision.Choose(current, observed with { ExplicitlyDenied = true }).Action == "none");
            Require(UacDecision.Choose(current, observed with { GenuinePrompt = false }).Action == "none");
        }
        Require(UacDecision.Choose(settings with { UacMode = "allowlist" }, observed with { CredentialPrompt = true }).Action == "esc");
        Require(UacDecision.Choose(settings with { UacMode = "semantic" }, observed with {
            ActualProgram = null, SemanticVerified = true, SemanticScopeMatches = false }).Action == "esc");
        System.Security.AccessControl.FileSystemAccessRule Rule(string sid, System.Security.AccessControl.PropagationFlags propagation = System.Security.AccessControl.PropagationFlags.None)
            => new(new System.Security.Principal.SecurityIdentifier(sid), System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit, propagation, System.Security.AccessControl.AccessControlType.Allow);
        Require(!UacClaimJournal.UntrustedAncestorMutation(Rule("S-1-5-18")));
        Require(!UacClaimJournal.UntrustedAncestorMutation(Rule("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")));
        Require(!UacClaimJournal.UntrustedAncestorMutation(Rule("S-1-3-0", System.Security.AccessControl.PropagationFlags.InheritOnly)));
        Require(UacClaimJournal.UntrustedAncestorMutation(Rule("S-1-5-32-545")));
        Require(UacClaimJournal.UntrustedAncestorMutation(Rule("S-1-5-80-1-2-3-4-5")));
        Require(UacInstallation.MissingTask(new FileNotFoundException()));
        Require(!UacInstallation.MissingTask(new IOException()));
        return new { assertions, nativeInputExecuted = false, systemExecuted = false, runtimeAccepted = false };
        }
        finally { File.Delete(fixture); }
    }
}
