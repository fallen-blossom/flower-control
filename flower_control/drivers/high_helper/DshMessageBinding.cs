using System.Collections.Concurrent;
using System.Text.Json;

namespace Flower.HighHelper;

internal sealed record DshHostMessage(string Phase, string Command, string SessionId, string TranscriptPath,
    long Sequence, string InstanceId, long Revision);

internal static class DshMessageBinding
{
    private sealed class Binding(string session, string path, string root, NativeHostRule decoder)
    {
        internal readonly object Gate = new();
        internal readonly string Session = session, Path = path, Root = root;
        internal readonly NativeHostRule Decoder = decoder;
        internal long MinimumSequence = -1;
        internal long MinimumRevision = -1;
        internal string? Instance;
        internal bool Closed;
        internal readonly HashSet<string> Instances = new();
        internal DshSourceBarrier? Barrier;
        internal bool Dirty = true;
        internal DshTranscriptSnapshot? Current;
    }
    private static readonly ConcurrentDictionary<string, Binding> bindings = new();
    internal static bool Known(string hash) => bindings.ContainsKey(hash);
    internal static object Context(string session)
    {
        string key = DshTranscriptReader.SessionHash(session);
        if (!bindings.TryGetValue(key, out var binding)) throw new Boundary("work_host_message_unavailable");
        lock (binding.Gate)
        {
            _ = Read(key);
            return new { Phase = "dsh_context", SessionHash = key, TurnId = binding.Current!.Message.TurnId };
        }
    }

    internal static object Observe(BrokerPolicy policy, Peer own, BrokerState core, Admission admission, DshHostMessage message)
    {
        if (admission.Evidence.Source != "dsh-desktop-flower" || !admission.Admin || admission.Peer.Integrity != 8192
            || message.Phase != "dsh_host_event" || message.Command is not ("open" or "invalidate" or "preflight" or "close")
            || message.SessionId is null || message.TranscriptPath is null
            || message.SessionId.Length is < 1 or > 256 || message.SessionId.Trim() != message.SessionId
            || message.SessionId.Any(char.IsControl) || message.Sequence < -1 || message.TranscriptPath.Length is < 1 or > 32768
            || message.InstanceId is null || !System.Text.RegularExpressions.Regex.IsMatch(message.InstanceId, "\\A[0-9a-f]{32}\\z")
            || message.Revision < 0)
            throw new Boundary("dsh_host_event_rejected");
        var settings = UserPermissions.Read();
        // Source freshness is independent of approval mode. A manually
        // confirmed DSH launch still needs its original call epoch; reading a
        // message here neither creates delegation nor replaces confirmation.
        bool required = UacDecision.RestrictionsEnabled(settings.UacMode) || settings.AdminLaunchEnabled;
        var (host, image) = Native.Process(admission.Evidence.SourcePid);
        var rule = policy.NativeHosts.SingleOrDefault(r => r.Kind == "dsh-desktop" && r.Path.Equals(image, StringComparison.OrdinalIgnoreCase))
            ?? throw new Boundary("dsh_host_event_rejected");
        string root = DshHostIdentity.SessionRoot(host, rule);
        DshTranscriptReader.CheckPath(message.TranscriptPath, root);
        string key = DshTranscriptReader.SessionHash(message.SessionId);
        if (!bindings.ContainsKey(key) && bindings.Count >= 2048) throw new Boundary("dsh_transcript_binding_limit");
        var binding = bindings.GetOrAdd(key, _ => new(message.SessionId, message.TranscriptPath, root, rule));
        lock (binding.Gate)
        {
            if (binding.Session != message.SessionId || !binding.Path.Equals(message.TranscriptPath, StringComparison.OrdinalIgnoreCase)
                || !binding.Root.Equals(root, StringComparison.OrdinalIgnoreCase) || binding.Decoder != rule)
            { binding.Dirty = true; throw new Boundary("dsh_host_binding_changed"); }
            if (message.Command == "open")
            {
                if (binding.Instance == message.InstanceId && !binding.Closed)
                    return new { Phase = "dsh_host_event", State = "invalidated", SessionHash = key };
                if (binding.Instances.Count >= 2048 || binding.Instances.Contains(message.InstanceId))
                    throw new Boundary("dsh_host_instance_closed");
                binding.Dirty = true; binding.Current = null;
                DshSourceBarrier? candidate = null;
                try
                {
                    candidate = DshSourceBarrier.Open(binding.Path, message.InstanceId);
                    candidate.Require(message.Revision);
                }
                catch { candidate?.Dispose(); throw; }
                binding.Barrier?.Dispose(); binding.Barrier = candidate;
                binding.Instances.Add(message.InstanceId);
                binding.Instance = message.InstanceId; binding.Closed = false;
                binding.MinimumRevision = message.Revision; binding.MinimumSequence = message.Sequence;
                binding.Dirty = true; binding.Current = null;
                foreach (var pending in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == key))
                    pending.Cancel("uac_host_instance_changed");
                return new { Phase = "dsh_host_event", State = "invalidated", SessionHash = key };
            }
            if (binding.Instance != message.InstanceId || binding.Closed || message.Revision < binding.MinimumRevision)
                throw new Boundary("dsh_host_instance_closed_or_stale");
            binding.MinimumRevision = message.Revision;
            if (message.Command is "invalidate" or "close")
            {
                // A synchronous native acknowledgement is a reduction only.
                // It shares the final administrator-creation gate below.
                binding.Dirty = true; binding.Current = null;
                binding.Closed = message.Command == "close";
                if (binding.Closed) { binding.Barrier?.Dispose(); binding.Barrier = null; }
                binding.MinimumSequence = Math.Max(binding.MinimumSequence, message.Sequence);
                foreach (var pending in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == key))
                    pending.Cancel("uac_new_user_message");
                if (UacDecision.RestrictionsEnabled(UserPermissions.Read().UacMode))
                    _ = UacChatAuthorization.RegisterEvent(policy, own.Session, key, "dsh-desktop",
                        "native-invalidation", DshTranscriptReader.Hash("dsh-invalidated\0" + Guid.NewGuid().ToString("N")));
                return new { Phase = "dsh_host_event", State = "invalidated", SessionHash = key };
            }
            binding.Dirty = true;
            if (!required) return new { Phase = "dsh_host_event", State = "ignored", SourceRequired = false };
            if (binding.Barrier is null) throw new Boundary("dsh_host_source_invalidated");
            binding.Barrier.Require(message.Revision);
            var snapshot = DshTranscriptReader.Read(binding.Path, binding.Session, binding.Root, binding.Decoder);
            if (snapshot.Message.SessionId != binding.Session || snapshot.Sequence < binding.MinimumSequence || snapshot.Sequence < message.Sequence)
                throw new Boundary("dsh_host_message_not_flushed");
            binding.Current = snapshot; binding.Dirty = false;
            string reference = BoundDigest(binding, snapshot.Message.EventDigest);
            if (UacDecision.RestrictionsEnabled(UserPermissions.Read().UacMode))
            {
                var authorization = UacChatAuthorization.RegisterEvent(policy, own.Session, key, "dsh-desktop",
                    snapshot.Message.TurnId!, reference);
                reference = authorization.MessageRef ?? reference;
                if (authorization.Changed) foreach (var pending in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == key))
                    pending.Cancel("uac_new_user_message");
            }
            return new { Phase = "dsh_host_event", State = "verified", MessageRef = reference, SessionHash = key };
        }
    }

    internal static WorkHostMessage Read(string key)
    {
        if (!bindings.TryGetValue(key, out var binding)) throw new Boundary("work_host_message_unavailable");
        lock (binding.Gate)
        {
            if (DshCallSource.For(key) is { } expected) RequireGuardCore(binding, expected);
            if (binding.Closed || binding.Dirty || binding.Current is null) throw new Boundary("work_host_new_message_requires_preflight");
            if (binding.Barrier is null) throw new Boundary("dsh_host_source_invalidated");
            try { binding.Barrier.Require(binding.MinimumRevision); }
            catch { binding.Dirty = true; throw; }
            var current = DshTranscriptReader.Read(binding.Path, binding.Session, binding.Root, binding.Decoder);
            try { binding.Barrier.Require(binding.MinimumRevision); }
            catch { binding.Dirty = true; throw; }
            if (current.Message.EventDigest != binding.Current.Message.EventDigest)
            { binding.Dirty = true; throw new Boundary("work_host_new_message_requires_preflight"); }
            return new(key, BoundDigest(binding, current.Message.EventDigest));
        }
    }

    private static string BoundDigest(Binding binding, string digest) =>
        DshTranscriptReader.Hash("flower-dsh-binding-v1\0" + binding.Instance + "\0" + digest);

    private static void RequireGuardCore(Binding binding, DshCallSourceGuard expected)
    {
        if (binding.Closed || binding.Dirty || binding.Current is null || binding.Barrier is null
            || binding.Instance != expected.InstanceId || binding.MinimumRevision != expected.Revision)
            throw new Boundary("dsh_call_source_changed");
        binding.Barrier.Require(expected.Revision);
    }
    internal static void RequireGuard(string key, DshCallSourceGuard expected)
    {
        if (!bindings.TryGetValue(key, out var binding)) throw new Boundary("work_host_message_unavailable");
        lock (binding.Gate) RequireGuardCore(binding, expected);
    }
    internal static T DispatchGuard<T>(string key, DshCallSourceGuard expected, Func<T> create)
    {
        if (!bindings.TryGetValue(key, out var binding)) throw new Boundary("work_host_message_unavailable");
        lock (binding.Gate)
        {
            RequireGuardCore(binding, expected);
            _ = Read(key);
            return create();
        }
    }

    internal static T Dispatch<T>(string key, string expected, Func<T> create)
    {
        if (!bindings.TryGetValue(key, out var binding)) throw new Boundary("work_host_message_unavailable");
        lock (binding.Gate)
        {
            if (Read(key).EventDigest != expected) throw new Boundary("work_authority_new_message_requires_prepare");
            if (binding.Barrier is null) throw new Boundary("dsh_host_source_invalidated");
            try { binding.Barrier.Require(binding.MinimumRevision); }
            catch { binding.Dirty = true; throw; }
            return create();
        }
    }

    internal static UacChatAuthorizationSnapshot Refresh(BrokerPolicy policy, Peer own, BrokerState core, string key)
    {
        if (!bindings.TryGetValue(key, out var binding)) throw new Boundary("uac_transcript_host_binding_required");
        lock (binding.Gate)
        {
            var current = Read(key);
            var result = UacChatAuthorization.RegisterEvent(policy, own.Session, key, "dsh-desktop",
                binding.Current!.Message.TurnId!, current.EventDigest);
            if (result.Changed) foreach (var pending in core.Requests.Values.Where(r => r.Uac && r.UacSessionHash == key))
                pending.Cancel("uac_new_user_message");
            return result;
        }
    }
}
