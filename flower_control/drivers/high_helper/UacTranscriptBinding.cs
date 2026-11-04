using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Flower.HighHelper;

// Only the admitted fixed Hook process can register a path. MCP arguments
// never contain a transcript path, session id or caller-chosen message id.
internal static class UacTranscriptBinding
{
    private sealed class Binding(string session, string path, string turn)
    {
        internal readonly object Gate = new();
        internal readonly string Session = session, Path = path;
        internal string Turn = turn;
        internal long LastRefresh;
        internal string? WorkPromptDigest, WorkEventDigest, PreviousWorkEvent, WorkNativeTurn;
        internal bool WorkWatermarkPending;
        internal bool RestoredFromWork;
    }
    private static readonly ConcurrentDictionary<string, Binding> bindings = new();
    // An authenticated UPS is a barrier even when its path/read is broken.
    // Do not mistake that failure for a cold broker that never saw the event.
    private static readonly ConcurrentDictionary<string, byte> seenWorkPrompts = new();
    internal static string SessionHash(string session) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes("flower-session-v1\0" + session))).ToLowerInvariant();

    internal static UacChatAuthorizationSnapshot ObserveHook(BrokerPolicy policy, Peer own, BrokerState core, UacHostMessage message)
    {
        if (string.IsNullOrWhiteSpace(message.SessionId) || SessionHash(message.SessionId) != message.SessionHash
            || message.SourceEvent is not ("UserPromptSubmit" or "PreToolUse"))
            throw new Boundary("uac_transcript_host_binding_required");
        void Suspend()
        {
            Cancel(core, message.SessionHash, "uac_user_message_review_required");
            var barrier = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                "flower-uac-message-barrier\0" + Guid.NewGuid().ToString("N")))).ToLowerInvariant();
            _ = UacChatAuthorization.RegisterEvent(policy, own.Session, message.SessionHash, "codex", message.TurnId, barrier);
        }
        // Even a missing/changed transcript path must suspend the previous
        // review once the native source/session has been authenticated.
        if (message.SourceEvent == "UserPromptSubmit") Suspend();
        if (string.IsNullOrWhiteSpace(message.TranscriptPath))
        { if (message.SourceEvent != "UserPromptSubmit") Suspend(); throw new Boundary("uac_transcript_host_binding_required"); }
        if (!bindings.ContainsKey(message.SessionHash) && bindings.Count >= 2048)
            throw new Boundary("uac_transcript_binding_limit");
        var binding = bindings.GetOrAdd(message.SessionHash, _ => new(message.SessionId, message.TranscriptPath, message.TurnId));
        lock (binding.Gate)
        {
            if (binding.Session != message.SessionId || !binding.Path.Equals(message.TranscriptPath, StringComparison.OrdinalIgnoreCase))
            { if (message.SourceEvent != "UserPromptSubmit") Suspend(); throw new Boundary("uac_transcript_host_binding_changed"); }
            binding.Turn = message.TurnId;
            try { return RefreshLocked(policy, own, core, message.SessionHash, binding); }
            catch
            {
                Cancel(core, message.SessionHash, "uac_transcript_refresh_failed");
                throw;
            }
        }
    }

    internal static UacChatAuthorizationSnapshot Refresh(BrokerPolicy policy, Peer own, BrokerState core, string sessionHash)
    {
        if (DshMessageBinding.Known(sessionHash)) return DshMessageBinding.Refresh(policy, own, core, sessionHash);
        if (!bindings.TryGetValue(sessionHash, out var binding)) throw new Boundary("uac_transcript_host_binding_required");
        lock (binding.Gate) return RefreshLocked(policy, own, core, sessionHash, binding);
    }
    // Task attribution is independent of UAC review/denial. Only a native Hook
    // registered this path; no MCP caller may supply a message or transcript.
    internal static WorkHostMessage ReadWorkMessage(string sessionHash)
    {
        if (DshMessageBinding.Known(sessionHash)) return DshMessageBinding.Read(sessionHash);
        if (!bindings.TryGetValue(sessionHash, out var binding)) throw new Boundary("work_host_message_unavailable");
        lock (binding.Gate)
        {
            if (binding.RestoredFromWork && seenWorkPrompts.ContainsKey(sessionHash))
                throw new Boundary("work_host_new_message_requires_preflight");
            var latest = UacTranscriptReader.Read(binding.Path, binding.Session);
            if (binding.WorkEventDigest is null || latest.EventDigest != binding.WorkEventDigest)
                throw new Boundary("work_host_new_message_requires_preflight");
            return new(sessionHash, latest.EventDigest);
        }
    }
    internal static bool CanRecoverColdWork(UacHostMessage message)
    {
        if (message.HostKind != "codex" || message.SourceEvent != "PreToolUse"
            || string.IsNullOrWhiteSpace(message.SessionId) || SessionHash(message.SessionId) != message.SessionHash
            || !Guid.TryParseExact(message.WorkId, "N", out _) || seenWorkPrompts.ContainsKey(message.SessionHash)) return false;
        if (!bindings.TryGetValue(message.SessionHash, out var binding)) return true;
        lock (binding.Gate) return !seenWorkPrompts.ContainsKey(message.SessionHash)
            && binding.WorkEventDigest is null && binding.WorkPromptDigest is null
            && binding.PreviousWorkEvent is null && binding.WorkNativeTurn is null
            && !binding.WorkWatermarkPending && !binding.RestoredFromWork;
    }
    internal static WorkHostMessage ObserveWorkHook(BrokerPolicy policy, Peer own, UacHostMessage message)
    {
        // Read the committed anchor before taking the message lock. The
        // normal WorkAuthority path uses Guard -> message-lock ordering.
        string? digest = CanRecoverColdWork(message)
            ? WorkAuthority.RestoreSourceAnchor(policy, own, new("codex", message.SessionId!), message.WorkId!) : null;
        return ObserveWorkHook(message, digest);
    }
    internal static WorkHostMessage ObserveWorkHook(UacHostMessage message) => ObserveWorkHook(message, null);
    internal static WorkHostMessage ObserveWorkHook(UacHostMessage message, string? coldWorkDigest)
    {
        if (string.IsNullOrWhiteSpace(message.SessionId) || SessionHash(message.SessionId) != message.SessionHash
            || message.HostKind != "codex" || message.SourceEvent is not ("UserPromptSubmit" or "PreToolUse"))
            throw new Boundary("work_host_message_unavailable");
        if (message.SourceEvent == "UserPromptSubmit")
        {
            if (!seenWorkPrompts.ContainsKey(message.SessionHash) && seenWorkPrompts.Count >= 2048)
                throw new Boundary("uac_transcript_binding_limit");
            seenWorkPrompts.TryAdd(message.SessionHash, 0);
        }
        // Suspend an older task attribution even if this new native event has
        // a missing/broken path. A subsequent preflight may finish the binding.
        if (message.SourceEvent == "UserPromptSubmit" && bindings.TryGetValue(message.SessionHash, out var previous))
            lock (previous.Gate)
            {
                // Same-turn steering may repeat identical text. Without a
                // trusted unique native event id this is NOT proof of replay;
                // wait for a new transcript record instead of reviving the old.
                if (previous.WorkEventDigest is not null) previous.PreviousWorkEvent = previous.WorkEventDigest;
                previous.WorkEventDigest = null; previous.WorkPromptDigest = null;
                previous.WorkNativeTurn = null;
                previous.RestoredFromWork = false;
            }
        if (string.IsNullOrWhiteSpace(message.TranscriptPath)) throw new Boundary("work_host_message_unavailable");
        if (!bindings.ContainsKey(message.SessionHash) && bindings.Count >= 2048) throw new Boundary("uac_transcript_binding_limit");
        var binding = bindings.GetOrAdd(message.SessionHash, _ => new(message.SessionId, message.TranscriptPath, message.TurnId));
        lock (binding.Gate)
        {
            if (binding.Session != message.SessionId || !binding.Path.Equals(message.TranscriptPath, StringComparison.OrdinalIgnoreCase))
                throw new Boundary("work_host_binding_changed");
            if (message.SourceEvent == "UserPromptSubmit")
            {
                binding.WorkPromptDigest = message.PromptDigest; binding.WorkNativeTurn = message.TurnId;
                binding.WorkWatermarkPending = message.TurnId == "native-event-without-turn"
                    && binding.WorkEventDigest is null && binding.PreviousWorkEvent is null;
            }
            var latest = UacTranscriptReader.Read(binding.Path, binding.Session);
            if (coldWorkDigest is not null && CanRecoverColdWork(message))
            {
                if (latest.EventDigest != coldWorkDigest)
                    throw new Boundary("work_authority_new_message_requires_prepare");
                if (seenWorkPrompts.ContainsKey(message.SessionHash))
                    throw new Boundary("work_host_new_message_requires_preflight");
                binding.WorkEventDigest = latest.EventDigest;
                binding.RestoredFromWork = true;
            }
            // A cold turn-less Hook cannot identify an already-existing same-
            // text record as its new event. Establish a watermark and let the
            // real PreToolUse bind only a subsequently appended record. Hosts
            // with a native turn retain their direct exact-turn path.
            if (binding.WorkWatermarkPending)
            {
                binding.PreviousWorkEvent = latest.EventDigest;
                binding.WorkWatermarkPending = false;
                throw new Boundary("work_host_message_not_appended");
            }
            if (binding.WorkEventDigest is null)
            {
                if (binding.WorkPromptDigest is null || latest.PromptComparison(binding.WorkPromptDigest) == "mismatch"
                    || latest.EventDigest == binding.PreviousWorkEvent)
                    throw new Boundary("work_host_message_not_appended");
                if (binding.WorkNativeTurn != "native-event-without-turn" && binding.WorkNativeTurn != latest.TurnId)
                    throw new Boundary("work_host_turn_changed");
                binding.WorkEventDigest = latest.EventDigest;
            }
            if (latest.EventDigest != binding.WorkEventDigest) throw new Boundary("work_host_message_changed");
            return new(message.SessionHash, latest.EventDigest);
        }
    }
    internal static T DispatchWorkMessage<T>(string sessionHash, string expectedDigest, Func<T> create)
    {
        if (DshMessageBinding.Known(sessionHash)) return DshMessageBinding.Dispatch(sessionHash, expectedDigest, create);
        if (!bindings.TryGetValue(sessionHash, out var binding)) throw new Boundary("work_host_message_unavailable");
        // Native message registration and final creation share this boundary.
        // Once a new message has invalidated the old event, it cannot slip a
        // create between a successful read and releasing/reacquiring the gate.
        lock (binding.Gate)
        {
            if (ReadWorkMessage(sessionHash).EventDigest != expectedDigest)
                throw new Boundary("work_authority_new_message_requires_prepare");
            return create();
        }
    }
    internal static void Poll(BrokerPolicy policy, Peer own, BrokerState core, string sessionHash)
    {
        if (DshMessageBinding.Known(sessionHash)) { _ = DshMessageBinding.Refresh(policy, own, core, sessionHash); return; }
        if (!bindings.TryGetValue(sessionHash, out var binding)) throw new Boundary("uac_transcript_host_binding_required");
        lock (binding.Gate)
        {
            if (Environment.TickCount64 - binding.LastRefresh < 100) return;
            _ = RefreshLocked(policy, own, core, sessionHash, binding);
        }
    }
    private static UacChatAuthorizationSnapshot RefreshLocked(BrokerPolicy policy, Peer own, BrokerState core, string key, Binding binding)
    {
        UacTranscriptSnapshot latest;
        try { latest = UacTranscriptReader.Read(binding.Path, binding.Session); }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException)
        { throw new Boundary(System.Text.RegularExpressions.Regex.IsMatch(error.Message, "\\Auac_transcript_[a-z_]{1,60}\\z")
            ? error.Message : "uac_transcript_unavailable"); }
        // Event identity includes the actual record position, not only its
        // words: identical A-B-A user messages must not reuse old authority.
        var snapshot = UacChatAuthorization.RegisterEvent(policy, own.Session, key, "codex",
            latest.TurnId ?? "record:" + latest.EventDigest, latest.EventDigest);
        binding.LastRefresh = Environment.TickCount64;
        if (snapshot.Changed) Cancel(core, key, "uac_new_user_message");
        return snapshot;
    }
    private static void Cancel(BrokerState core, string key, string reason)
    {
        foreach (var pending in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == key)) pending.Cancel(reason);
    }

    internal static object InspectWorkSource(string sessionHash)
    {
        if (!bindings.TryGetValue(sessionHash, out var binding))
            return new { BindingPresent = false, Reason = "work_host_message_unavailable" };
        lock (binding.Gate)
        {
            string? localPath = null;
            try { localPath = UacTranscriptReader.NormalizeLocalPath(binding.Path); }
            catch (InvalidDataException) { }
            bool local = localPath is not null;
            bool exists = false; long? bytes = null; string? reason = null;
            string promptComparison = "unavailable";
            bool preflightCanComplete = false;
            try
            {
                if (local) { var info = new FileInfo(localPath!); exists = info.Exists; if (exists) bytes = info.Length; }
                var latest = UacTranscriptReader.Read(binding.Path, binding.Session);
                promptComparison = binding.WorkPromptDigest is null ? "not_seen" : latest.PromptComparison(binding.WorkPromptDigest);
                preflightCanComplete = binding.WorkEventDigest is null && binding.WorkPromptDigest is not null
                    && !binding.WorkWatermarkPending && promptComparison != "mismatch"
                    && latest.EventDigest != binding.PreviousWorkEvent
                    && (binding.WorkNativeTurn == "native-event-without-turn" || binding.WorkNativeTurn == latest.TurnId);
                _ = ReadWorkMessage(sessionHash);
            }
            catch (Exception error) { reason = Program.Code(error); }
            return new { BindingPresent = true, NativePromptSeen = binding.WorkPromptDigest is not null,
                MessageBound = binding.WorkEventDigest is not null, PathPresent = !string.IsNullOrWhiteSpace(binding.Path),
                RestoredFromCommittedWork = binding.RestoredFromWork,
                PathKind = local ? "local_absolute" : "unsupported", FileExists = exists, FileBytes = bytes,
                SourceReady = reason is null, Reason = reason, PromptComparison = promptComparison,
                PreflightCanComplete = preflightCanComplete };
        }
    }
}
