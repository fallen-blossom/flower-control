using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

internal sealed record UacHostMessage(string Phase, string SessionHash, string HostKind, string TurnId, string PromptDigest,
    string? SessionId = null, string? TranscriptPath = null, string SourceEvent = "UserPromptSubmit")
{
    public string Purpose { get; init; } = "work";
    public string? WorkId { get; init; }
}

// A fixed native Hook adapter. It never parses permission words, saves prompt
// text, changes a mode or launches an elevation request. The High broker reads
// only this host-bound session's appended visible user records.
internal static class UacHostHook
{
    internal const int PreflightBudgetMilliseconds = 8000;
    internal static int PreflightTimeout(int stageLimit, long elapsedMilliseconds)
    {
        if (stageLimit <= 0 || elapsedMilliseconds < 0 || elapsedMilliseconds >= PreflightBudgetMilliseconds)
            throw new Boundary("deadline_expired");
        return (int)Math.Min(stageLimit, PreflightBudgetMilliseconds - elapsedMilliseconds);
    }
    internal sealed record PreflightFailure(string State, string Reason, string Stage);
    internal static PreflightFailure Failure(Exception error, string stage)
    {
        // Only fixed stage names cross the Hook boundary. Exception bodies can
        // contain private paths and are never serialized.
        if (stage is not ("policy" or "own_identity" or "admission" or "settings" or "decode"
            or "pipe_connect" or "server_identity" or "hello_write" or "hello_read"
            or "record_write" or "record_read" or "reference")) stage = "policy";
        string reason = error is TimeoutException ? "deadline_expired" : Program.Code(error);
        if (!Regex.IsMatch(reason, "\\A(?:uac|work|semantic_delegation)_[a-z_]{1,70}\\z")
            && reason is not ("deadline_expired" or "schema_rejected" or "pipe_disconnected"
                or "object_access_denied" or "resource_object_unavailable" or "file_not_found" or "helper_failure"
                or "client_user_session_rejected" or "flower_entry_rejected" or "codex_launch_chain_unverified"
                or "native_host_image_changed" or "dsh_direct_host_required" or "process_unavailable" or "image_unavailable"
                or "message_too_large" or "partial_message")) reason = "helper_failure";
        return new("unavailable", reason, stage);
    }
    internal static string HostFailureReason(string? reason)
        => reason is not null && Regex.IsMatch(reason, "\\A(?:uac|work|semantic_delegation)_[a-z_]{1,70}\\z")
            ? reason : reason is "process_unavailable" or "image_unavailable" or "object_access_denied" or "pipe_disconnected"
                or "client_user_session_rejected" or "flower_entry_rejected" or "codex_launch_chain_unverified"
                or "native_host_image_changed" or "dsh_direct_host_required"
                ? reason : "uac_prompt_record_unconfirmed";
    internal static UacHostMessage Decode(JsonDocument document)
    {
        Protocol.CheckUnique(document);
        var root = document.RootElement;
        var eventName = root.GetProperty("hook_event_name").GetString();
        if (eventName is not ("UserPromptSubmit" or "PreToolUse")) throw new Boundary("uac_prompt_event_required");
        if (eventName == "PreToolUse" && (!root.TryGetProperty("tool_name", out var tool)
            || tool.GetString() is not ("mcp__flower_app__flower_app_work_authority" or "mcp__flower-app__flower_app_work_authority"
                or "mcp__flower_app__flower_app_launch_admin" or "mcp__flower-app__flower_app_launch_admin")))
            throw new Boundary("uac_prompt_tool_rejected");
        string Identifier(string name)
        {
            var value = root.GetProperty(name).GetString();
            if (value is null || value.Length is < 1 or > 256 || value != value.Trim() || value.Any(char.IsControl))
                throw new Boundary("uac_prompt_identity_invalid");
            return value;
        }
        var session = Identifier("session_id");
        // Some native hosts omit a turn id. This placeholder is only a review
        // barrier; the actual message identity comes from the exact transcript.
        var turn = root.TryGetProperty("turn_id", out var turnValue) && turnValue.ValueKind != JsonValueKind.Null
            ? Identifier("turn_id") : "native-event-without-turn";
        var prompt = eventName == "PreToolUse" ? "preflight" : root.GetProperty("prompt").GetString();
        if (prompt is null || prompt.Length is < 1 or > 4194304) throw new Boundary("uac_prompt_content_unavailable");
        static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        var path = root.TryGetProperty("transcript_path", out var transcript) && transcript.ValueKind == JsonValueKind.String ? transcript.GetString() : null;
        string? workId = null;
        if (eventName == "PreToolUse" && root.TryGetProperty("work_id", out var work))
        {
            if (work.ValueKind != JsonValueKind.String || !Guid.TryParseExact(work.GetString(), "N", out _))
                throw new Boundary("work_authority_id_required");
            workId = work.GetString();
        }
        return new("uac_host_event", Hash("flower-session-v1\0" + session), "codex", turn, Hash(prompt), session, path, eventName!)
            { Purpose = "work", WorkId = workId };
    }

    internal static int Run(bool preflight = false)
    {
        object output = new { };
        string stage = "policy";
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        int Timeout(int limit) => preflight ? PreflightTimeout(limit, elapsed.ElapsedMilliseconds) : limit;
        try
        {
            var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
            stage = "own_identity";
            var own = Native.Process(Environment.ProcessId).Identity;
            stage = "admission";
            var admission = ClientAdmission.Verify(own.Pid, policy);
            if (policy.Fixture || own.Integrity != 8192 || !admission.Admin || admission.Evidence.Source != "codex-flower")
                throw new Boundary("uac_prompt_host_unverified");
            // This hook now serves only administrator work message provenance.
            stage = "settings";
            var settings = UserPermissions.Read();
            if (!(settings.AdminLaunchEnabled && settings.AdminLaunchMode == "semantic" && settings.SemanticDelegation is not null))
            { Console.WriteLine("{}"); return 0; }
            stage = "decode";
            using var input = Console.OpenStandardInput(); using var bytes = new MemoryStream();
            var buffer = new byte[4096]; int count;
            while ((count = input.Read(buffer)) > 0)
            { if (bytes.Length + count > 8 * 1024 * 1024) throw new Boundary("uac_prompt_event_too_large"); bytes.Write(buffer, 0, count); }
            using var document = JsonDocument.Parse(bytes.ToArray());
            var message = Decode(document); // Only the digest crosses the local pipe.
            if ((message.SourceEvent == "PreToolUse") != preflight) throw new Boundary("uac_prompt_event_required");
            using var pipe = new NamedPipeClientStream(".", BrokerPipe.Name(own), PipeDirection.InOut,
                PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
            stage = "pipe_connect";
            pipe.Connect(Timeout(1500));
            stage = "server_identity";
            if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
                throw new Boundary("uac_prompt_broker_unavailable");
            var (server, image) = Native.Process((int)pid);
            if (server.User != own.User || server.Session != own.Session || server.Integrity != 12288
                || !image.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase) || server.ImageDigest != own.ImageDigest)
                throw new Boundary("uac_prompt_broker_changed");
            stage = "hello_write";
            Protocol.Write(pipe, new { Phase = "hello", Parent = own, Channel = "flower-uac-hook" }, Timeout(500));
            stage = "hello_read";
            using var hello = Protocol.Read(pipe, Timeout(3000));
            if (hello is null || UacOutcomeEvidence.Text(hello.RootElement, "Phase") != "hello"
                || UacOutcomeEvidence.Text(hello.RootElement, "AssemblyDigest") != Program.AssemblyDigest)
                throw new Boundary("uac_prompt_broker_changed");
            stage = "record_write";
            Protocol.Write(pipe, message, Timeout(500));
            stage = "record_read";
            using var result = Protocol.Read(pipe, Timeout(5000));
            if (result is not null && UacOutcomeEvidence.Text(result.RootElement, "Phase") == "error")
            {
                var reason = UacOutcomeEvidence.Text(result.RootElement, "Reason");
                throw new Boundary(HostFailureReason(reason));
            }
            if (result is null || UacOutcomeEvidence.Text(result.RootElement, "Phase") != "uac_host_event")
                throw new Boundary("uac_prompt_record_unconfirmed");
            if (UacOutcomeEvidence.True(result.RootElement, "Ignored")) { Console.WriteLine("{}"); return 0; }
            stage = "reference";
            var reference = result.RootElement.GetProperty("Snapshot").GetProperty("MessageRef").GetString();
            if (reference is null || !Regex.IsMatch(reference, "\\A[a-f0-9]{32,64}\\z")) throw new Boundary("uac_prompt_reference_invalid");
            if (preflight)
            {
                Console.WriteLine(JsonSerializer.Serialize(new { State = "verified", MessageRef = reference })); return 0;
            }
            if (UacOutcomeEvidence.Text(result.RootElement, "Scope") != "work_message")
                throw new Boundary("work_source_unavailable");
            output = new { hookSpecificOutput = new { hookEventName = "UserPromptSubmit",
                additionalContext = "Flower administrator work message source registered. The reference grants no permission and does not clear denial or Stop." } };
        }
        catch (Exception error)
        {
            if (preflight) { Console.WriteLine(JsonSerializer.Serialize(Failure(error, stage))); return 2; }
            string reason = HostFailureReason(Program.Code(error));
            output = new { hookSpecificOutput = new { hookEventName = "UserPromptSubmit", additionalContext =
                reason == "work_host_message_not_appended"
                ? "Flower administrator work message registration is pending the native transcript append. Source status and the next administrator-work call recheck that original authenticated event. Ordinary work can continue; existing denial and Stop remain effective."
                : "Flower administrator work message source is unavailable (" + reason + "). "
                    + "Ordinary work can continue; existing denial and Stop remain effective." } };
        }
        Console.WriteLine(JsonSerializer.Serialize(output)); return 0;
    }
}
