using System.Diagnostics;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class LifecycleTests
{
    internal static int StdioChild()
    {
        Console.Error.Write("stdio-child-diagnostics\n"); Console.Error.Flush();
        Console.OpenStandardInput().CopyTo(Console.OpenStandardOutput());
        return 23;
    }
    internal static int StdioSupervisor(bool earlyExit)
    {
        var info = new ProcessStartInfo(Environment.ProcessPath!, earlyExit ? "--stdio-early-child" : "--stdio-child")
        { UseShellExecute = false, CreateNoWindow = true };
        return ClientAdmission.SuperviseMcp(info);
    }
    internal static int Child()
    {
        using var leaf = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--lifecycle-leaf")
        { UseShellExecute = false, CreateNoWindow = true }) ?? throw new Boundary("selftest_child_failed");
        Console.WriteLine(leaf.Id); Console.Out.Flush();
        Thread.Sleep(5000);
        return 0;
    }
    internal static int Leaf() { Thread.Sleep(3000); return 0; }
    internal static object Run()
    {
        var stage = "token";
        try { return RunCore(value => stage = value); }
        catch (Boundary) { throw; }
        catch (Exception error) { throw new Boundary("lifecycle_" + stage + "_" + error.GetType().Name.ToLowerInvariant()); }
    }
    private static object RunCore(Action<string> stage)
    {
        if (Native.Process(Environment.ProcessId).Identity.Integrity != 8192) throw new Boundary("selftest_medium_required");
        int assertions = 0;
        void Require(bool value) { ++assertions; if (!value) throw new Boundary("lifecycle_selftest_failed"); }
        foreach (bool breakaway in new[] { true, false })
        {
            stage(breakaway ? "mcp_start" : "worker_start");
            var info = new ProcessStartInfo(Environment.ProcessPath!, "--lifecycle-child")
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
            var owned = new OwnedChild(info, allowDescendantBreakaway: breakaway);
            int child = owned.Process.Id;
            var line = owned.Process.StandardOutput.ReadLineAsync();
            if (!line.Wait(1500) || !int.TryParse(line.Result, out var leaf)) throw new Boundary("lifecycle_selftest_failed");
            stage("leaf_identity");
            using var exactLeaf = Process.GetProcessById(leaf);
            var identity = Native.Process(leaf).Identity;
            Require(identity.Created >= Native.Process(child).Identity.Created);
            stage("owned_dispose"); owned.Dispose(); stage("leaf_result");
            if (breakaway)
            {
                stage("leaf_alive");
                Require(!exactLeaf.HasExited && Native.Process(leaf).Identity == identity);
                stage("leaf_wait");
                Require(exactLeaf.WaitForExit(5000));
            }
            else { stage("worker_leaf_wait"); Require(exactLeaf.WaitForExit(1000)); }
        }
        return new { assertions, ownedProcessLifecycleVerified = true, nativeInputExecuted = false,
            userApplicationsTouched = false, highVerified = false };
    }
}
