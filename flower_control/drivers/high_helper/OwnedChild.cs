using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Flower.HighHelper;

// This job contains only a fixed child started here and its own descendants.
internal sealed class OwnedChild : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] private struct Basic
    {
        public long ProcessTime, JobTime; public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcesses;
        public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Io
    { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct Extended
    {
        public Basic Basic; public Io Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref Extended value, int size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    private readonly SafeFileHandle job;
    private readonly Action<bool>? exitSink;
    internal Process Process { get; }
    internal OwnedChild(ProcessStartInfo info, bool allowDescendantBreakaway = false, Action<bool>? exitSink = null)
    {
        this.exitSink = exitSink;
        job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Boundary("owned_job_failed", Marshal.GetLastWin32Error());
        // MCP supervision owns its exact Python only. Its user applications and
        // separately supervised workers leave this job automatically; explicit
        // CREATE_BREAKAWAY_FROM_JOB remains compatible as well.
        var limits = new Extended { Basic = new Basic { Flags = 0x2000U | (allowDescendantBreakaway ? 0x1800U : 0U) } };
        if (!SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf<Extended>()))
        { job.Dispose(); throw new Boundary("owned_job_failed", Marshal.GetLastWin32Error()); }
        Process = System.Diagnostics.Process.Start(info) ?? throw new Boundary("owned_child_start_failed");
        if (!AssignProcessToJobObject(job, Process.Handle))
        {
            var error = Marshal.GetLastWin32Error();
            // This newly created fixed worker has received no work yet.
            try { Process.Kill(entireProcessTree: !allowDescendantBreakaway); Process.WaitForExit(1000); } finally { Process.Dispose(); job.Dispose(); }
            throw new Boundary("owned_job_assignment_failed", error);
        }
    }
    public void Dispose()
    {
        job.Dispose();
        var exited = Process.WaitForExit(1000);
        exitSink?.Invoke(exited);
        if (!exited) throw new Boundary("owned_child_exit_unconfirmed");
        Process.Dispose();
    }
}
