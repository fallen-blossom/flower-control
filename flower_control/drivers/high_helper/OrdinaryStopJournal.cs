using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed record OrdinaryStopState(long Count, long Acknowledged)
{
    internal bool Stopped => Count != Acknowledged;
}

// High owns the fixed file and its parent. Medium has READ + APPEND_DATA only:
// it can durably add a Stop, never truncate, replace, delete or acknowledge it.
// Acknowledgement is a separate High-protected watermark, with an exact count.
internal static class OrdinaryStopJournal
{
    private const int UserRights = 0x12008d, Limit = 1024 * 1024;
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { internal int Size; internal IntPtr Descriptor; internal int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing, ref Attributes attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool WriteFile(SafeFileHandle file, byte[] bytes, uint size, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool FlushFileBuffers(SafeFileHandle file);
    private sealed record Ack(int Schema, string UserSid, int Session, bool Computer, long Count);
    private sealed class Reader(FileStream file)
    {
        internal readonly object Gate = new();
        internal readonly FileStream File = file;
        internal long Checked, CachedCount = -1, CachedAcknowledged, AckReadAt;
    }
    private static readonly ConcurrentDictionary<string, Lazy<Reader>> readers = new(StringComparer.OrdinalIgnoreCase);
    private static string DirectoryPath => Path.Combine(InstallationLocation.Current().ProgramRoot, "recovery", "ordinary-stop");
    private static string FilePath(string sid, int session, bool computer)
    {
        if (session <= 0 || new SecurityIdentifier(sid).Value != sid || !sid.StartsWith("S-1-5-21-")) throw new Boundary("ordinary_stop_context_rejected");
        return Path.Combine(DirectoryPath, sid + "." + session + (computer ? ".computer.bin" : ".global.bin"));
    }
    internal static void Prepare(Peer own)
    {
        if (own.Integrity != 12288 || Native.UiAccess(own.Pid)) throw new Boundary("ordinary_stop_high_preparation_required");
        string recovery = Path.GetDirectoryName(DirectoryPath)!;
        UacClaimJournal.CheckParent(Path.GetDirectoryName(recovery)!, false);
        SecurityLabel.CreateDirectory(recovery, own.User); SecurityLabel.CreateDirectory(DirectoryPath, own.User);
        foreach (bool computer in new[] { false, true })
        {
            string path = FilePath(own.User, own.Session, computer);
            if (!File.Exists(path))
            {
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW($"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{UserRights:x};;;{own.User})S:(ML;;NW;;;ME)", 1, out var descriptor, out _))
                    throw new Boundary("ordinary_stop_descriptor_failed", Marshal.GetLastWin32Error());
                try
                {
                    var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>(), Descriptor = descriptor };
                    using var handle = CreateFileW(path, 0x40000000, 3, ref attributes, 1, 0x80000000, IntPtr.Zero);
                    if (handle.IsInvalid) throw new Boundary("ordinary_stop_prepare_failed", Marshal.GetLastWin32Error());
                    if (!FlushFileBuffers(handle)) throw new Boundary("ordinary_stop_flush_failed", Marshal.GetLastWin32Error());
                }
                finally { LocalFree(descriptor); }
            }
            Check(path, own.User); _ = Read(own.User, own.Session, computer);
        }
    }
    private static void Check(string path, string sid, string? retainedDirectory = null)
    {
        UacClaimJournal.CheckParent(retainedDirectory ?? DirectoryPath, true); BrokerPolicy.RejectLinks(path);
        var descriptor = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var raw = new RawSecurityDescriptor(descriptor.GetSecurityDescriptorBinaryForm(), 0);
        if (raw.Owner?.Value is not ("S-1-5-18" or "S-1-5-32-544") || raw.DiscretionaryAcl is null
            || (raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0) throw new Boundary("ordinary_stop_unprotected");
        bool userAppend = false;
        foreach (GenericAce item in raw.DiscretionaryAcl)
        {
            if (item is not CommonAce ace || ace.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied)) throw new Boundary("ordinary_stop_unprotected");
            if (ace.AceQualifier != AceQualifier.AccessAllowed) continue;
            if (ace.SecurityIdentifier.Value is "S-1-5-18" or "S-1-5-32-544") continue;
            if (ace.SecurityIdentifier.Value != sid || (ace.AccessMask & ~UserRights) != 0) throw new Boundary("ordinary_stop_unprotected");
            userAppend |= (ace.AccessMask & 4) != 0;
        }
        var label = new RawSecurityDescriptor(SecurityLabel.Read(path));
        var labels = label.SystemAcl?.Cast<GenericAce>().Where(ace => (int)ace.AceType == 17).ToArray() ?? [];
        if (!userAppend || labels.Length != 1 || (labels[0].AceFlags & AceFlags.InheritOnly) != 0)
            throw new Boundary("ordinary_stop_label_rejected");
        var bytes = new byte[labels[0].BinaryLength]; labels[0].GetBinaryForm(bytes, 0);
        if (bytes.Length < 20 || BitConverter.ToInt32(bytes, 4) != 1 || new SecurityIdentifier(bytes, 8).Value != "S-1-16-8192")
            throw new Boundary("ordinary_stop_label_rejected");
    }
    internal static void ValidateRetained(string path,string sid)
    {
        if(!System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(path),
            "\\A"+System.Text.RegularExpressions.Regex.Escape(sid)+"\\.[1-9][0-9]*\\.(?:computer|global)\\.bin\\z"))
            throw new Boundary("ordinary_stop_context_rejected");
        Check(path,sid,Path.GetDirectoryName(path)!);
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
        _=ReadValidatedTail(file,0);
    }
    internal static long ReadValidatedTail(FileStream file, long validated)
    {
        long length = file.Length;
        if (length < validated) throw new Boundary("ordinary_stop_truncated");
        if (length > Limit) throw new Boundary("ordinary_stop_capacity");
        file.Position = validated;
        int next;
        while ((next = file.ReadByte()) != -1)
        {
            if (next != 0xa5) throw new Boundary("ordinary_stop_corrupt");
            if (file.Position > Limit) throw new Boundary("ordinary_stop_capacity");
        }
        // An append may arrive after the original Length sample. Only count
        // bytes actually validated, never that earlier, possibly stale length.
        return file.Position;
    }
    internal static OrdinaryStopState Read(string sid, int session, bool computer = false, bool forceAcknowledgement = false)
    {
        string path = FilePath(sid, session, computer);
        var lazy = readers.GetOrAdd(path, _ => new Lazy<Reader>(() =>
        {
            Check(path, sid);
            // No DELETE sharing: this verified append-only node stays pinned
            // for the broker lifetime. Medium cannot replace or truncate it.
            return new(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
        }, LazyThreadSafetyMode.ExecutionAndPublication));
        Reader reader;
        try { reader = lazy.Value; }
        catch { readers.TryRemove(new KeyValuePair<string, Lazy<Reader>>(path, lazy)); throw; }
        lock (reader.Gate)
        {
            long count = ReadValidatedTail(reader.File, reader.Checked);
            reader.Checked = count;
            long now = Environment.TickCount64;
            // Never cache the Stop count. A newly appended Stop invalidates
            // this acknowledgement cache immediately; a briefly stale High
            // acknowledgement can only keep an old Stop in force.
            if (forceAcknowledgement || reader.CachedCount != count || now - reader.AckReadAt >= 20)
            {
                reader.CachedAcknowledged = ReadAcknowledged(path, sid, session, computer, count);
                reader.CachedCount = count; reader.AckReadAt = now;
            }
            return new(count, reader.CachedAcknowledged);
        }
    }
    // Read-only metadata for a version update before the first role-aware
    // bootstrap creates these journals. Missing does not authorize execution:
    // the production Read path above still requires a prepared protected file.
    internal static OrdinaryStopState ReadBeforePreparation(string sid, int session, bool computer = false)
    {
        string path = FilePath(sid, session, computer);
        UacClaimJournal.CheckParent(Path.GetDirectoryName(DirectoryPath)!, true);
        try { UacClaimJournal.CheckParent(DirectoryPath, true); }
        catch (FileNotFoundException) { return new(0, 0); }
        catch (DirectoryNotFoundException) { return new(0, 0); }
        BrokerPolicy.RejectLinks(path);
        try { return Read(sid, session, computer, true); }
        catch (FileNotFoundException) { return new(0, 0); }
        catch (DirectoryNotFoundException) { return new(0, 0); }
    }
    private static long ReadAcknowledged(string path, string sid, int session, bool computer, long count)
    {
        long acknowledged = 0; string ackPath = path + ".ack.json";
        try
        {
            UserPermissions.CheckProtection(ackPath);
            using var file = new FileStream(ackPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (file.Length is < 1 or > 4096) throw new Boundary("ordinary_stop_ack_rejected");
            using var document = JsonDocument.Parse(file); var value = Protocol.Decode<Ack>(document);
            if (value.Schema != 1 || value.UserSid != sid || value.Session != session || value.Computer != computer || value.Count < 0 || value.Count > count)
                throw new Boundary("ordinary_stop_ack_rejected");
            acknowledged = value.Count;
        }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
        return acknowledged;
    }
    internal static void Append(Peer own, bool computer = false)
    {
        if (own.Integrity != 8192 || Native.UiAccess(own.Pid)) throw new Boundary("ordinary_stop_medium_required");
        string path = FilePath(own.User, own.Session, computer); Check(path, own.User);
        if (Read(own.User, own.Session, computer).Count >= Limit) throw new Boundary("ordinary_stop_capacity");
        var attributes = new Attributes { Size = Marshal.SizeOf<Attributes>() };
        using var handle = CreateFileW(path, 4 | 0x100000, 3, ref attributes, 3, 0x80000000, IntPtr.Zero);
        if (handle.IsInvalid || !WriteFile(handle, [0xa5], 1, out uint written, IntPtr.Zero) || written != 1 || !FlushFileBuffers(handle))
            throw new Boundary("ordinary_stop_append_unconfirmed", Marshal.GetLastWin32Error());
    }
    internal static void Acknowledge(Peer own, OrdinaryStopState expected, bool computer = false)
    {
        if (own.Integrity != 12288 || Native.UiAccess(own.Pid)) throw new Boundary("ordinary_stop_resume_high_required");
        using var mutex = new Mutex(false, "Local\\FlowerControl.OrdinaryStopAck." + own.User + "." + own.Session + "." + computer);
        bool held;
        try { held = mutex.WaitOne(2000); } catch (AbandonedMutexException) { held = true; }
        if (!held) throw new Boundary("ordinary_stop_ack_busy");
        try { AcknowledgeLocked(own, expected, computer); }
        finally { mutex.ReleaseMutex(); }
    }
    private static void AcknowledgeLocked(Peer own, OrdinaryStopState expected, bool computer)
    {
        string path = FilePath(own.User, own.Session, computer);
        if (Read(own.User, own.Session, computer, true) != expected) throw new Boundary("ordinary_stop_state_changed");
        string ack = path + ".ack.json", temporary = ack + "." + Guid.NewGuid().ToString("N") + ".tmp";
        SecurityLabel.Write(temporary, JsonSerializer.SerializeToUtf8Bytes(new Ack(1, own.User, own.Session, computer, expected.Count)), own.User);
        File.Move(temporary, ack, true);
        var result = Read(own.User, own.Session, computer, true);
        if (result.Acknowledged != expected.Count) throw new Boundary("ordinary_stop_ack_unconfirmed");
        // A later appended Stop remains outstanding. Never acknowledge a
        // newer count merely because this write succeeded.
    }
}
