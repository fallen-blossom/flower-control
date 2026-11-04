using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

internal sealed record AdminLaunchWorkloadSnapshot(string State, AdminLaunchedProcess[] Processes, string? Reason = null);

// An anonymous job identifies this helper lifetime's descendants; it grants no
// authority to operate them. The caller must recheck each returned identity and
// window against current policy. There is deliberately no kill/breakaway limit.
internal sealed class AdminLaunchWorkload : IDisposable
{
    private readonly object gate = new();
    private readonly IAdminLaunchWorkloadNative native;
    private readonly SafeHandle job;
    private bool assigned, disposed;

    private AdminLaunchWorkload() : this(new AdminLaunchWorkloadNative()) { }
    // Native I/O seam for the isolated fixture, never selected by an MCP field.
    internal AdminLaunchWorkload(IAdminLaunchWorkloadNative native)
    { this.native = native; job = native.CreateJob(); }
    internal static AdminLaunchWorkload Create() => new();

    // The caller owns CREATE_SUSPENDED -> Assign -> ResumeThread. A failed
    // assignment must never resume user code or fall back to an untracked run.
    internal void Assign(SafeProcessHandle process)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (assigned) throw new InvalidOperationException("program_launch_workload_already_assigned");
            if (process.IsInvalid || process.IsClosed) throw new ArgumentException("program_launch_workload_invalid_process");
            native.Assign(job, process);
            assigned = true;
        }
    }

    internal AdminLaunchWorkloadSnapshot Observe(Func<SafeProcessHandle, int, AdminLaunchedProcess> readProcess)
    {
        ArgumentNullException.ThrowIfNull(readProcess);
        lock (gate)
        {
            AdminLaunchWorkloadSnapshot Unknown(string reason) => new("unknown", [], reason);
            if (disposed) return Unknown("program_launch_workload_disposed");
            if (!assigned) return Unknown("program_launch_workload_not_assigned");
            try
            {
                var pids = native.ProcessIds(job);
                if (pids.Length > 1024 || pids.Any(p => p <= 0) || pids.Distinct().Count() != pids.Length)
                    return Unknown("program_launch_workload_invalid_process_list");
                var facts = new List<AdminLaunchedProcess>();
                foreach (int pid in pids)
                {
                    using var process = native.Open(pid);
                    if (process.IsInvalid || process.IsClosed || !native.IsMember(job, process) || !native.IsRunning(process))
                        return Unknown("program_launch_workload_member_changed");
                    var identity = readProcess(process, pid);
                    if (identity.Pid != pid || identity.Created <= 0 || !native.IsMember(job, process) || !native.IsRunning(process))
                        return Unknown("program_launch_workload_identity_changed");
                    facts.Add(identity);
                }
                // A launcher can spawn/exit while metadata is read. Do not
                // mistake an incomplete set for a completed workload.
                var after = native.ProcessIds(job);
                if (!pids.Order().SequenceEqual(after.Order()))
                    return Unknown("program_launch_workload_changed_during_observation");
                return new(pids.Length == 0 ? "exited" : "running", facts.ToArray());
            }
            catch (Exception error)
            { return Unknown("program_launch_workload_observation_unverified:" + error.GetType().Name); }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            job.Dispose(); // Closing this job does not terminate its processes.
        }
    }
}

internal interface IAdminLaunchWorkloadNative
{
    SafeHandle CreateJob();
    void Assign(SafeHandle job, SafeProcessHandle process);
    int[] ProcessIds(SafeHandle job);
    SafeProcessHandle Open(int pid);
    bool IsMember(SafeHandle job, SafeProcessHandle process);
    bool IsRunning(SafeProcessHandle process);
}

internal sealed class AdminLaunchWorkloadNative : IAdminLaunchWorkloadNative
{
    private sealed class JobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal JobHandle(IntPtr handle) : base(true) { SetHandle(handle); }
        protected override bool ReleaseHandle() => CloseHandle(handle);
    }
    public SafeHandle CreateJob()
    {
        // No SetInformationJobObject: no KILL_ON_JOB_CLOSE, BREAKAWAY_OK,
        // SILENT_BREAKAWAY_OK, UI restrictions or limits on user results.
        var handle = new JobHandle(CreateJobObjectW(IntPtr.Zero, null));
        if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "program_launch_workload_create_failed"); }
        return handle;
    }
    public void Assign(SafeHandle job, SafeProcessHandle process)
    {
        if (!AssignProcessToJobObject(job, process))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "program_launch_workload_assign_failed");
        if (!IsMember(job, process)) throw new InvalidOperationException("program_launch_workload_assignment_unconfirmed");
    }
    public int[] ProcessIds(SafeHandle job)
    {
        for (int capacity = 16; capacity <= 1024; capacity *= 2)
        {
            int bytes = checked(8 + capacity * IntPtr.Size);
            var data = Marshal.AllocHGlobal(bytes);
            try
            {
                if (!QueryInformationJobObject(job, 3, data, (uint)bytes, out _))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 234 && capacity < 1024) continue;
                    throw new Win32Exception(error, "program_launch_workload_query_failed");
                }
                uint assigned = (uint)Marshal.ReadInt32(data), count = (uint)Marshal.ReadInt32(data, 4);
                if (assigned > count && capacity < 1024) continue;
                if (assigned != count || count > capacity) throw new InvalidOperationException("program_launch_workload_list_incomplete");
                var result = new int[count];
                for (int i = 0; i < count; i++)
                {
                    long pid = Marshal.ReadIntPtr(data, 8 + i * IntPtr.Size).ToInt64();
                    if (pid <= 0 || pid > int.MaxValue) throw new InvalidOperationException("program_launch_workload_invalid_pid");
                    result[i] = (int)pid;
                }
                return result;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        throw new InvalidOperationException("program_launch_workload_process_limit");
    }
    public SafeProcessHandle Open(int pid) => OpenProcess(0x1000 | 0x100000, false, pid);
    public bool IsMember(SafeHandle job, SafeProcessHandle process)
    {
        if (!IsProcessInJob(process, job, out bool member)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return member;
    }
    public bool IsRunning(SafeProcessHandle process)
    {
        uint state = WaitForSingleObject(process, 0);
        if (state is not (0 or 258)) throw new Win32Exception(Marshal.GetLastWin32Error());
        return state == 258;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeHandle job, SafeProcessHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(SafeHandle job, int kind, IntPtr data, uint size, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(SafeProcessHandle process, SafeHandle job, out bool member);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeProcessHandle process, uint timeout);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}
