using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

// Installer-local input pins. No directory traversal, link following, execution
// or environment acquisition; only exact prepared files can be copied.
public static class FlowerPinnedDelivery
{
    // Replaced only while sealing a prepared script, never from environment.
    private const string PreparedProgramRoot = "@@PREPARED_PROGRAM_ROOT@@";
    private static string ProgramRoot { get { return PreparedProgramRoot[0] == '@'
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper") : PreparedProgramRoot; } }
    private static readonly Dictionary<string, SafeFileHandle> Parents = new Dictionary<string, SafeFileHandle>(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, FileStream> Files = new Dictionary<string, FileStream>(StringComparer.OrdinalIgnoreCase);
    private static IntPtr GateMapping, GateMutex;
    private static int GateFenceThread;
    private static bool FreshGate;
    private static bool MaintenanceOriginallyStopped;
    private static long MaintenanceEpoch = -1, MaintenanceResume = -1;
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenFileMappingW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenMutexW(uint access, bool inherit, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateMutexW(ref Attributes attributes, bool owner, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileMappingW(IntPtr file, ref Attributes attributes, uint protect, uint high, uint low, string name);
    [DllImport("kernel32.dll")] private static extern void SetLastError(uint error);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReleaseMutex(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr MapViewOfFile(IntPtr mapping, uint access, uint high, uint low, UIntPtr size);
    [DllImport("kernel32.dll")] private static extern bool UnmapViewOfFile(IntPtr view);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint length, uint flags);
    [StructLayout(LayoutKind.Sequential)] private struct Attributes { public uint Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value, uint revision, out IntPtr descriptor, out uint length);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(string path, ref Attributes attributes);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] private static extern uint GetNamedSecurityInfoW(string path, int type, uint info, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")] private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    private static System.Security.AccessControl.RawSecurityDescriptor DirectoryAccess(string path)
    {
        IntPtr owner,group,dacl,sacl,descriptor;
        uint error=GetNamedSecurityInfoW(path,1,5,out owner,out group,out dacl,out sacl,out descriptor);
        if(error!=0) throw new Win32Exception((int)error,"delivery_log_acl_unreadable");
        try { byte[] bytes=new byte[GetSecurityDescriptorLength(descriptor)]; Marshal.Copy(descriptor,bytes,0,bytes.Length);
            return new System.Security.AccessControl.RawSecurityDescriptor(bytes,0); }
        finally { LocalFree(descriptor); }
    }

    public static bool ExistingWriteGatePresent(string sid)
    {
        if (sid != System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)
            throw new IOException("delivery_gate_identity_rejected");
        string name = "Local\\FlowerControl.WriteGate.v1." + sid;
        IntPtr mutex = OpenMutexW(0x100001, false, name + ".lock");
        int mutexError = mutex == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        IntPtr mapping = OpenFileMappingW(4, false, name);
        int mappingError = mapping == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        try {
            if (mutex != IntPtr.Zero && mapping != IntPtr.Zero) return true;
            if (mutex == IntPtr.Zero && mapping == IntPtr.Zero && mutexError == 2 && mappingError == 2) return false;
            if (mutex == IntPtr.Zero && mutexError != 2) throw new Win32Exception(mutexError,"delivery_gate_presence_unreadable");
            if (mapping == IntPtr.Zero && mappingError != 2) throw new Win32Exception(mappingError,"delivery_gate_presence_unreadable");
            throw new IOException("delivery_gate_partial_presence");
        } finally {
            if (mapping != IntPtr.Zero) CloseHandle(mapping);
            if (mutex != IntPtr.Zero) CloseHandle(mutex);
        }
    }

    // Installation-only Stop recovery after the old volatile namespace ended.
    // The caller holds the session/input leases and has verified the durable
    // stopped records. Never open and overwrite an existing generation.
    public static long[] CreateFreshStoppedWriteGate(string sid)
    {
        if (GateMapping != IntPtr.Zero || GateMutex != IntPtr.Zero || ExistingWriteGatePresent(sid))
            throw new IOException("delivery_fresh_gate_absence_required");
        string name = "Local\\FlowerControl.WriteGate.v1." + sid;
        IntPtr descriptor; uint length;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")S:(ML;;NW;;;ME)",1,out descriptor,out length))
            throw new Win32Exception(Marshal.GetLastWin32Error(),"delivery_gate_security_failed");
        bool owned = false, complete = false; IntPtr view = IntPtr.Zero;
        try {
            var attributes = new Attributes { Length = (uint)Marshal.SizeOf(typeof(Attributes)), Descriptor = descriptor };
            SetLastError(0);
            GateMutex = CreateMutexW(ref attributes,true,name + ".lock");
            int error = Marshal.GetLastWin32Error();
            if (GateMutex == IntPtr.Zero) throw new Win32Exception(error,"delivery_gate_create_failed");
            if (error == 183) throw new IOException("delivery_gate_creation_raced");
            owned = true;
            SetLastError(0);
            GateMapping = CreateFileMappingW(new IntPtr(-1),ref attributes,4,0,32,name);
            error = Marshal.GetLastWin32Error();
            if (GateMapping == IntPtr.Zero) throw new Win32Exception(error,"delivery_gate_create_failed");
            if (error == 183) throw new IOException("delivery_gate_creation_raced");
            view = MapViewOfFile(GateMapping,6,0,0,new UIntPtr(32));
            if (view == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(),"delivery_gate_create_failed");
            Marshal.WriteInt32(view,4,1); Marshal.WriteInt64(view,8,1);
            Marshal.WriteInt64(view,16,0); Marshal.WriteInt64(view,24,0);
            Marshal.WriteInt32(view,0,0x46435731);
            System.Threading.Thread.MemoryBarrier();
            complete = true;
            FreshGate = true;
        } finally {
            if (view != IntPtr.Zero) UnmapViewOfFile(view);
            int releaseError = 0;
            bool releaseFailed = owned && !ReleaseMutex(GateMutex);
            if (releaseFailed) { releaseError = Marshal.GetLastWin32Error(); complete = false; }
            if (!complete) Close();
            LocalFree(descriptor);
            if (releaseFailed) throw new Win32Exception(releaseError,"delivery_gate_release_unconfirmed");
        }
        return SnapshotWriteGate();
    }

    // Open, never create or write. Keep the original Stop generation alive
    // across the old-process exit, independent of other MCP connections.
    public static void HoldWriteGate(string sid)
    {
        if (GateMapping != IntPtr.Zero || sid != System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)
            throw new IOException("delivery_gate_identity_rejected");
        string name = "Local\\FlowerControl.WriteGate.v1." + sid;
        GateMutex = OpenMutexW(0x100001, false, name + ".lock");
        if (GateMutex == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "delivery_existing_gate_mutex_required");
        GateMapping = OpenFileMappingW(4, false, name);
        if (GateMapping == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "delivery_existing_gate_required");
        // Retaining alone never acquires it. Explicit read snapshots reject
        // abandonment; no snapshot writes or silently resumes this gate.
    }
    public static long[] SnapshotWriteGate()
    {
        if (GateMapping == IntPtr.Zero || GateMutex == IntPtr.Zero) throw new IOException("delivery_existing_gate_required");
        uint wait = WaitForSingleObject(GateMutex, 250);
        if (wait == 0x80) { ReleaseMutex(GateMutex); throw new IOException("delivery_gate_abandoned"); }
        if (wait != 0) throw new IOException("delivery_gate_busy");
        IntPtr view = IntPtr.Zero;
        try {
            view = MapViewOfFile(GateMapping, 4, 0, 0, new UIntPtr(32));
            if (view == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            int stopped = Marshal.ReadInt32(view, 4); long epoch = Marshal.ReadInt64(view, 8), resumed = Marshal.ReadInt64(view, 16);
            if (Marshal.ReadInt32(view) != 0x46435731 || (stopped != 0 && stopped != 1) || epoch < 0 || resumed < 0 || resumed > epoch || Marshal.ReadInt64(view, 24) != 0)
                throw new IOException("delivery_gate_layout_rejected");
            return new long[] { stopped, epoch, resumed };
        } finally { if (view != IntPtr.Zero) UnmapViewOfFile(view); ReleaseMutex(GateMutex); }
    }

    // A live, authenticated maintenance plan keeps the original mapping. Open
    // write access only to advance a STOPPED generation after broker drain;
    // this route cannot initialize a namespace or clear any Stop.
    public static void HoldMaintenanceWriteGate(string sid, long epoch, long resumeAllEpoch)
    { HoldMaintenanceWriteGate(sid, epoch, resumeAllEpoch, false); }
    public static void HoldMaintenanceWriteGate(string sid, long epoch, long resumeAllEpoch, bool originallyStopped)
    {
        HoldWriteGate(sid);
        var before = SnapshotWriteGate();
        if (epoch < 0 || epoch > long.MaxValue - 2 || resumeAllEpoch < 0 || resumeAllEpoch > epoch
            || before[0] != (originallyStopped ? 1 : 0) || before[1] != epoch || before[2] != resumeAllEpoch)
            throw new IOException("delivery_maintenance_gate_changed");
        // The original read handle remains open until the writable handle is
        // obtained, so replacement with a different mapping is impossible.
        var writable = OpenFileMappingW(6, false, "Local\\FlowerControl.WriteGate.v1." + sid);
        if (writable == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        CloseHandle(GateMapping); GateMapping = writable;
        MaintenanceEpoch = epoch; MaintenanceResume = resumeAllEpoch; MaintenanceOriginallyStopped = originallyStopped;
    }

    public static long AdvanceMaintenanceStoppedGeneration(long epoch, long resumeAllEpoch)
    {
        if (MaintenanceEpoch < 0 || epoch < MaintenanceEpoch + (MaintenanceOriginallyStopped ? 0 : 1) || epoch == long.MaxValue
            || resumeAllEpoch != MaintenanceResume || !StoppedWriteFenceHeld())
            throw new IOException("delivery_maintenance_stopped_fence_required");
        var status = SnapshotWriteGate();
        if (status[0] != 1 || status[1] != epoch || status[2] != resumeAllEpoch)
            throw new IOException("delivery_stopped_fence_changed");
        var view = MapViewOfFile(GateMapping, 6, 0, 0, new UIntPtr(32));
        if (view == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { Marshal.WriteInt64(view, 8, epoch + 1); System.Threading.Thread.MemoryBarrier(); }
        finally { UnmapViewOfFile(view); }
        MaintenanceEpoch = -1; MaintenanceResume = -1;
        return epoch + 1;
    }

    // Only for a stopped installer after the original broker exited. Holding
    // this real mutex parks legacy Python snapshot/resume/admit paths, including
    // background App/Web writes. It is not a claim that stdio clients exited.
    public static void EnterStoppedWriteFence(long epoch, long resumeAllEpoch)
    {
        if (GateMapping == IntPtr.Zero || GateMutex == IntPtr.Zero || GateFenceThread != 0)
            throw new IOException("delivery_stopped_fence_rejected");
        uint wait = WaitForSingleObject(GateMutex, 250);
        if (wait == 0x80) { ReleaseMutex(GateMutex); throw new IOException("delivery_gate_abandoned"); }
        if (wait != 0) throw new IOException("delivery_gate_busy");
        try {
            var status = SnapshotWriteGate(); // Recursive acquisition by this thread.
            if (status[0] != 1 || status[1] != epoch || status[2] != resumeAllEpoch)
                throw new IOException("delivery_stopped_fence_changed");
            GateFenceThread = System.Threading.Thread.CurrentThread.ManagedThreadId;
        } catch { ReleaseMutex(GateMutex); throw; }
    }
    public static bool StoppedWriteFenceHeld()
    {
        return GateFenceThread != 0 && GateFenceThread == System.Threading.Thread.CurrentThread.ManagedThreadId;
    }
    public static void ExitStoppedWriteFence()
    {
        if (GateFenceThread == 0) return;
        if (!StoppedWriteFenceHeld()) throw new IOException("delivery_stopped_fence_owner_changed");
        if (!ReleaseMutex(GateMutex)) throw new Win32Exception(Marshal.GetLastWin32Error(),"delivery_stopped_fence_release_failed");
        GateFenceThread = 0;
    }
    public static long AdvanceStoppedGeneration(long epoch,long resumeAllEpoch)
    {
        // Only this operation's fresh stopped namespace may be advanced.
        // Pending legacy resumes captured the previous epoch before waiting
        // for SQLite; they must fail their existing CAS after ledger release.
        if(!FreshGate||!StoppedWriteFenceHeld()) throw new IOException("delivery_fresh_stopped_fence_required");
        var status=SnapshotWriteGate();
        if(status[0]!=1||status[1]!=epoch||status[2]!=resumeAllEpoch||epoch==long.MaxValue)
            throw new IOException("delivery_stopped_fence_changed");
        IntPtr view=MapViewOfFile(GateMapping,6,0,0,new UIntPtr(32));
        if(view==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        try {Marshal.WriteInt64(view,8,epoch+1);System.Threading.Thread.MemoryBarrier();}
        finally {UnmapViewOfFile(view);}
        return epoch+1;
    }
    public static void CreateNewVersionDirectory(string path, string sid)
    {
        string versions = Path.Combine(ProgramRoot,"versions");
        string full = Path.GetFullPath(path), leaf = Path.GetFileName(full);
        Guid version;
        if (sid != System.Security.Principal.WindowsIdentity.GetCurrent().User.Value ||
            !String.Equals(Path.GetDirectoryName(full),versions,StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(leaf,"N",out version)) throw new IOException("delivery_version_directory_rejected");
        PinDirectory(versions);
        IntPtr descriptor; uint length;
        string sddl="O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+sid+")S:(ML;;NW;;;HI)";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out descriptor,out length))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            var attrs=new Attributes{Length=(uint)Marshal.SizeOf(typeof(Attributes)),Descriptor=descriptor};
            if(!CreateDirectoryW(full,ref attrs))throw new Win32Exception(Marshal.GetLastWin32Error(),"delivery_new_version_directory_required");
        } finally {LocalFree(descriptor);}
    }

    public static string CreateLogDirectory(string operation, string sid)
    {
        Guid id;
        if (!Guid.TryParseExact(operation, "N", out id) || sid != System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)
            throw new IOException("delivery_log_identity_rejected");
        string parent = Path.Combine(ProgramRoot, "recovery");
        PinDirectory(parent);
        string path = Path.Combine(parent, "installation-" + operation);
        IntPtr descriptor; uint length;
        string sddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + sid + ")S:(ML;OICI;NW;;;HI)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out length)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var attrs = new Attributes { Length = (uint)Marshal.SizeOf(typeof(Attributes)), Descriptor = descriptor };
            if (!CreateDirectoryW(path, ref attrs)) throw new Win32Exception(Marshal.GetLastWin32Error(), "delivery_new_log_directory_required");
        }
        finally { LocalFree(descriptor); }
        PinDirectory(path); return path;
    }

    public static string RequireLogDirectory(string operation, string sid)
    {
        Guid id;
        if (!Guid.TryParseExact(operation, "N", out id) || sid != System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)
            throw new IOException("delivery_log_identity_rejected");
        string path = Path.Combine(ProgramRoot, "recovery", "installation-" + operation);
        PinDirectory(path);
        var sections = System.Security.AccessControl.AccessControlSections.Owner | System.Security.AccessControl.AccessControlSections.Access;
        var expected = new System.Security.AccessControl.DirectorySecurity();
        expected.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + sid + ")", sections);
        var actual = DirectoryAccess(path);
        if ((actual.ControlFlags & System.Security.AccessControl.ControlFlags.DiscretionaryAclProtected) == 0 || actual.GetSddlForm(sections) != expected.GetSecurityDescriptorSddlForm(sections))
            throw new IOException("delivery_protected_log_changed");
        return path;
    }

    internal static void Canonical(SafeFileHandle handle, string expected)
    {
        var path = new StringBuilder(32768);
        uint size = GetFinalPathNameByHandleW(handle, path, (uint)path.Capacity, 0);
        if (size == 0 || size >= path.Capacity || !path.ToString().StartsWith(@"\\?\", StringComparison.Ordinal)
            || !Path.GetFullPath(path.ToString().Substring(4)).Equals(Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
            throw new IOException("delivery_input_path_changed");
    }
    public static void PinDirectory(string directory)
    {
        var paths = new Stack<string>();
        for (string item = Path.GetFullPath(directory); item != null; item = Path.GetDirectoryName(item)) paths.Push(item);
        while (paths.Count > 0)
        {
            string path = paths.Pop();
            if (Parents.ContainsKey(path)) continue;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("delivery_input_link_rejected");
            var handle = CreateFileW(path, 0x20080, 1, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "delivery_directory_pin_failed"); }
            try { Canonical(handle, path); Parents.Add(path, handle); }
            catch { handle.Dispose(); throw; }
        }
    }
    private static FileStream Open(string path, string expected)
    {
        path = Path.GetFullPath(path);
        PinDirectory(Path.GetDirectoryName(path));
        FileStream file;
        if (!Files.TryGetValue(path, out file))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("delivery_input_link_rejected");
            var handle = CreateFileW(path, 0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "delivery_file_pin_failed"); }
            try { Canonical(handle, path); file = new FileStream(handle, FileAccess.Read); Files.Add(path, file); }
            catch { handle.Dispose(); throw; }
        }
        file.Position = 0;
        string actual;
        using (var hash = SHA256.Create()) actual = BitConverter.ToString(hash.ComputeHash(file)).Replace("-", "").ToLowerInvariant();
        file.Position = 0;
        if (!String.Equals(actual, expected, StringComparison.Ordinal)) throw new IOException("delivery_input_hash_changed");
        return file;
    }
    public static string ReadText(string path, string expected)
    {
        var file = Open(path, expected);
        using (var reader = new StreamReader(file, Encoding.UTF8, true, 4096, true)) return reader.ReadToEnd();
    }
    public static void VerifyFile(string path, string expected) { Open(path, expected); }
    public static void CopyFile(string source, string target, string expected)
    {
        var file = Open(source, expected);
        PinDirectory(Path.GetDirectoryName(target));
        using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        { file.CopyTo(output); output.Flush(true); }
    }
    public static void ReplaceFile(string source, string target)
    {
        // PS5 converts an untyped $null backup argument to an empty path.
        // Keep the actual CLR null inside C# for the atomic replacement.
        File.Replace(source, target, null);
    }
    public static void CloseInputs()
    {
        foreach (var file in Files.Values) file.Dispose(); Files.Clear();
        foreach (var parent in Parents.Values) parent.Dispose(); Parents.Clear();
    }
    public static void Close()
    {
        try { ExitStoppedWriteFence(); }
        finally {
            CloseInputs(); FreshGate=false; MaintenanceEpoch=-1; MaintenanceResume=-1; MaintenanceOriginallyStopped=false;
            if (GateMapping != IntPtr.Zero) { CloseHandle(GateMapping); GateMapping = IntPtr.Zero; }
            if (GateMutex != IntPtr.Zero) { CloseHandle(GateMutex); GateMutex = IntPtr.Zero; }
        }
    }
}

// A rollback-mode SQLite writer reservation spans the handoff from the shared
// Stop mutex to the new broker. Old Python resumes and App/Web admission enter
// BEGIN IMMEDIATE before touching the shared gate. No rows are changed here.
public sealed class FlowerLedgerFence : IDisposable
{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
    private static extern IntPtr GetProcAddress(IntPtr library, string name);
    [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr library);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int OpenDb(byte[] path,out IntPtr db,int flags,IntPtr vfs);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ExecDb(IntPtr db,byte[] sql,IntPtr callback,IntPtr context,out IntPtr error);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int CloseDb(IntPtr db);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int InitializeDb();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void FreeError(IntPtr error);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Row(IntPtr context,int count,IntPtr values,IntPtr names);
    private readonly List<IDisposable> pins = new List<IDisposable>();
    private IntPtr library, db;
    private ExecDb exec; private CloseDb close; private FreeError free;
    private bool held;
    private static byte[] Utf8(string value) { return Encoding.UTF8.GetBytes(value + "\0"); }
    private T Function<T>(string name) where T : class
    {
        IntPtr address=GetProcAddress(library,name);
        if(address==IntPtr.Zero) throw new IOException("ledger_sqlite_export_missing");
        return Marshal.GetDelegateForFunctionPointer(address,typeof(T)) as T;
    }
    private void PinParents(string path)
    {
        for(string directory=Path.GetDirectoryName(path);directory!=null;directory=Path.GetDirectoryName(directory)) {
            if((File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0) throw new IOException("ledger_path_link_rejected");
            var handle=CreateFileW(directory,0x20080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(handle.IsInvalid) { handle.Dispose();throw new IOException("ledger_parent_pin_failed"); }
            pins.Add(handle);
        }
        if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0) throw new IOException("ledger_path_link_rejected");
    }
    private void Execute(string sql, Row callback)
    {
        IntPtr error;
        int code=exec(db,Utf8(sql),callback==null?IntPtr.Zero:Marshal.GetFunctionPointerForDelegate(callback),IntPtr.Zero,out error);
        if(error!=IntPtr.Zero) free(error);
        GC.KeepAlive(callback);
        if(code!=0) throw new IOException("ledger_fence_sql_failed_"+code);
    }
    public static FlowerLedgerFence Acquire(string path,string dll,string expected)
    {
        var lease=new FlowerLedgerFence();
        try {
            if(!Path.IsPathRooted(path)||!Path.IsPathRooted(dll)) throw new IOException("ledger_absolute_path_required");
            path=Path.GetFullPath(path);dll=Path.GetFullPath(dll);
            lease.PinParents(dll);lease.PinParents(path);
            var binary=new FileStream(dll,FileMode.Open,FileAccess.Read,FileShare.Read);lease.pins.Add(binary);
            FlowerPinnedDelivery.Canonical(binary.SafeFileHandle,dll);
            using(var hash=SHA256.Create()) {
                if(BitConverter.ToString(hash.ComputeHash(binary)).Replace("-", "").ToLowerInvariant()!=expected)
                    throw new IOException("ledger_sqlite_hash_changed");
            }
            // Hold the original database against replacement, without denying
            // SQLite's own read/write opens. Opening never creates a new ledger.
            var original=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);lease.pins.Add(original);
            FlowerPinnedDelivery.Canonical(original.SafeFileHandle,path);
            var header=new byte[20];
            if(original.Read(header,0,20)!=20||Encoding.ASCII.GetString(header,0,16)!="SQLite format 3\0"||header[18]!=1||header[19]!=1)
                throw new IOException("ledger_rollback_database_required");
            foreach(string suffix in new[]{"-wal","-shm"})
                if(File.Exists(path+suffix)||Directory.Exists(path+suffix)) throw new IOException("ledger_pending_journal_present");
            // DELETE-mode metadata transactions also create a rollback journal.
            // Its mere existence cannot distinguish a live writer from a cold
            // journal. Keep link/directory checks and let SQLite acquire the
            // actual writer reservation; never delete a journal ourselves.
            if(Directory.Exists(path+"-journal")) throw new IOException("ledger_journal_directory_rejected");
            if(File.Exists(path+"-journal")) {
                try { lease.PinParents(path+"-journal"); }
                catch(FileNotFoundException) { } // The owning transaction committed.
            }
            lease.library=LoadLibraryExW(dll,IntPtr.Zero,0x900); // Exact DLL directory + System32 only.
            if(lease.library==IntPtr.Zero) throw new IOException("ledger_sqlite_load_failed");
            // CPython's Windows DLL is built with SQLITE_OMIT_AUTOINIT.
            // Opening it outside _sqlite3 requires explicit initialization.
            if(lease.Function<InitializeDb>("sqlite3_initialize")()!=0) throw new IOException("ledger_sqlite_initialize_failed");
            var open=lease.Function<OpenDb>("sqlite3_open_v2");
            lease.exec=lease.Function<ExecDb>("sqlite3_exec");lease.close=lease.Function<CloseDb>("sqlite3_close");lease.free=lease.Function<FreeError>("sqlite3_free");
            if(open(Utf8(path),out lease.db,2,IntPtr.Zero)!=0) throw new IOException("ledger_sqlite_open_failed"); // READWRITE, never CREATE.
            lease.Execute("PRAGMA busy_timeout=5000",null);
            lease.Execute("BEGIN IMMEDIATE",null);lease.held=true;
            // A started background write must finish before a stopped update.
            // Never cancel, acknowledge or rewrite an unresolved action here.
            int writers=-1;
            Row count=(context,n,values,names)=> { int value;
                if(n!=1||!int.TryParse(Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(values)),out value)||value<0)return 1;
                writers=value;return 0; };
            lease.Execute("SELECT COUNT(*) FROM actions a LEFT JOIN action_effects e ON e.action=a.id WHERE a.state IN ('queued','running') AND COALESCE(e.read_only,0)=0",count);
            if(writers!=0) throw new IOException("ledger_unresolved_writes_present");
            return lease;
        } catch { lease.Dispose();throw; }
    }
    public bool Held { get { return held&&db!=IntPtr.Zero; } }
    public void Dispose()
    {
        try { if(db!=IntPtr.Zero) { try { if(held)Execute("ROLLBACK",null); }
            finally { held=false;int code=close(db);db=IntPtr.Zero;if(code!=0)throw new IOException("ledger_fence_close_unconfirmed"); } } }
        finally { if(library!=IntPtr.Zero){FreeLibrary(library);library=IntPtr.Zero;}
            foreach(var pin in pins)pin.Dispose();pins.Clear(); }
    }
}
