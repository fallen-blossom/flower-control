using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Real candidate predicates only. No broker, Hook registration, transcript,
// SharedWriteGate, permission writer, elevation or user input is constructed.
if (args[1] == "wait") { Console.ReadLine(); return; }
var image = Assembly.LoadFrom(args[0]);
object? Call(string type, string method, params object?[] values)
    => image.GetType("Flower.HighHelper." + type, true)!.GetMethod(method,
        BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, values);
try
{
    if (args[1] == "signer")
    {
        bool accepted = (bool)Call("CodexHostIdentity", "IsPublisherImage", args[2], args[3], args[4],
            int.Parse(args[5]), args[6] == "null" ? (long?)null : long.Parse(args[6]))!;
        Console.WriteLine(JsonSerializer.Serialize(new { accepted }));
    }
    else if (args[1] == "chain")
    {
        int pid = Environment.ProcessId;
        bool found = false;
        for (int depth = 0; depth < 12 && pid > 0; ++depth)
        {
            var pair = Call("Native", "Process", pid, false)!;
            var peer = pair.GetType().GetField("Item1")!.GetValue(pair)!;
            var path = (string)pair.GetType().GetField("Item2")!.GetValue(pair)!;
            if (Path.GetFileName(path).Equals("codex.exe", StringComparison.OrdinalIgnoreCase))
            {
                long created = (long)peer.GetType().GetProperty("Created")!.GetValue(peer)!;
                bool accepted = (bool)Call("CodexHostIdentity", "IsOfficialCodexImage", path, pid, (long?)created)!;
                bool wrongCreated = (bool)Call("CodexHostIdentity", "IsOfficialCodexImage", path, pid, (long?)(created + 1))!;
                Console.WriteLine(JsonSerializer.Serialize(new { found = true, accepted, wrongCreated }));
                found = true; break;
            }
            pid = (int)Call("Native", "ParentPid", pid)!;
        }
        if (!found) Console.WriteLine(JsonSerializer.Serialize(new { found = false }));
    }
    else if (args[1] is "archive" or "archive-held")
    {
        using var archive = new FileStream(args[2], FileMode.Open, FileAccess.Read, FileShare.Read);
        var held = new List<FileStream>();
        var directories = new List<SafeFileHandle>();
        try
        {
            Call("DshSignedArchive", "Verify", archive, args[3], args[4], held, directories);
            if (args[1] == "archive-held")
            {
                bool blocked = false;
                try { Directory.Move(args[4], args[4] + ".moved"); Directory.Move(args[4] + ".moved", args[4]); }
                catch (IOException) { blocked = true; }
                Console.WriteLine(JsonSerializer.Serialize(new { accepted = true, directoryLocked = blocked }));
            }
            else Console.WriteLine(JsonSerializer.Serialize(new { accepted = true, unpacked = held.Count }));
        }
        finally { foreach (var file in held) file.Dispose(); foreach (var directory in directories) directory.Dispose(); }
    }
    else if (args[1] == "resource")
        Console.WriteLine(JsonSerializer.Serialize(new { header = Call("DshSignedArchive", "HeaderDigest", args[2]) }));
    else if (args[1] == "lease-live")
    {
        Process Owner()
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true };
            start.ArgumentList.Add(args[0]); start.ArgumentList.Add("wait");
            return Process.Start(start)!;
        }
        using var first = Owner(); using var second = Owner();
        bool Blocked()
        {
            try { using var writer = new FileStream(args[2], FileMode.Open, FileAccess.ReadWrite, FileShare.Read); return false; }
            catch (IOException) { return true; }
        }
        try
        {
            string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(args[2]))).ToLowerInvariant();
            foreach (var owner in new[] { first, second })
            {
                var pair = Call("Native", "Process", owner.Id, false)!;
                var peer = pair.GetType().GetField("Item1")!.GetValue(pair)!;
                Call("DshHostIdentity", "PinRuntime", args[2], hash, peer, args[2]);
            }
            Call("DshHostIdentity", "ReapRuntimePins"); bool live = Blocked();
            first.StandardInput.WriteLine("done"); first.WaitForExit();
            Call("DshHostIdentity", "ReapRuntimePins"); bool oneLive = Blocked();
            second.StandardInput.WriteLine("done"); second.WaitForExit();
            var clock = Stopwatch.StartNew();
            while (Blocked() && clock.ElapsedMilliseconds < 6000) Thread.Sleep(50);
            Console.WriteLine(JsonSerializer.Serialize(new { live, oneLive, released = !Blocked() }));
        }
        finally
        {
            foreach (var owner in new[] { first, second })
                if (!owner.HasExited) { owner.StandardInput.Close(); owner.WaitForExit(); }
        }
    }
    else if (args[1] == "lease")
    {
        using var owner = Process.Start(new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec")!, "/d /c exit 0")
            { UseShellExecute = false, CreateNoWindow = true })!;
        // A dead, exact synthetic owner exercises retirement; it cannot grant a
        // production identity, and the archive is a newly generated fixture.
        owner.WaitForExit();
        var peerType = image.GetType("Flower.HighHelper.Peer", true)!;
        var peer = Activator.CreateInstance(peerType, owner.Id, 1L, 0, "fixture", "", 8192)!;
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(args[2]))).ToLowerInvariant();
        Call("DshHostIdentity", "PinRuntime", args[2], hash, peer, args[2]);
        bool blocked = false;
        try { using var writer = new FileStream(args[2], FileMode.Open, FileAccess.ReadWrite, FileShare.Read); }
        catch (IOException) { blocked = true; }
        Call("DshHostIdentity", "ReapRuntimePins");
        using var after = new FileStream(args[2], FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        Console.WriteLine(JsonSerializer.Serialize(new { blocked, released = true }));
    }
    else throw new Exception("unknown_probe");
}
catch (Exception error)
{
    while (error is TargetInvocationException && error.InnerException is not null) error = error.InnerException;
    Console.WriteLine(JsonSerializer.Serialize(new { accepted = false,
        reason = error.GetType().GetProperty("Code")?.GetValue(error) ?? error.GetType().Name }));
}
