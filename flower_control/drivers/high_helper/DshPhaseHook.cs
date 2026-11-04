using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Reduction-only local metadata. No High pipe, message registration, task
// creation, grant, input dispatch, resume or arbitrary Python/argv surface.
internal static class DshPhaseHook
{
    internal static void Validate(JsonElement value)
    {
        var fields = new[] { "session_id", "instance_id", "event_seq", "kind", "observed_ns" };
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != fields.Length
            || !value.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(fields))
            throw new Boundary("dsh_phase_rejected");
        string Text(string name) => value.GetProperty(name).ValueKind == JsonValueKind.String
            ? value.GetProperty(name).GetString()! : throw new Boundary("dsh_phase_rejected");
        var session = Text("session_id");
        if (session.Length is < 1 or > 256 || session != session.Trim() || session.Any(char.IsControl)
            || !Regex.IsMatch(Text("instance_id"), "\\A[a-f0-9]{32}\\z")
            || value.GetProperty("event_seq").ValueKind != JsonValueKind.Number
            || !value.GetProperty("event_seq").TryGetInt64(out var sequence) || sequence is < 0 or > 9007199254740991L
            || Text("kind") is not ("idle" or "turn_end")
            || !Regex.IsMatch(Text("observed_ns"), "\\A[0-9]{1,20}\\z")
            || !ulong.TryParse(Text("observed_ns"), out var observed)) throw new Boundary("dsh_phase_rejected");
        double age = (double)Stopwatch.GetTimestamp() / Stopwatch.Frequency - observed / 1_000_000_000.0;
        if (age < 0 || age >= 5) throw new Boundary("dsh_phase_expired");
    }
    internal static int Run()
    {
        try
        {
            var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
            var own = Native.Process(Environment.ProcessId).Identity;
            var admission = ClientAdmission.Verify(own.Pid, policy);
            if (policy.Fixture || own.Integrity != 8192 || !admission.Admin || admission.Evidence.Source != "dsh-desktop-flower")
                throw new Boundary("dsh_phase_host_rejected");
            using var input = Console.OpenStandardInput();
            using var bytes = new MemoryStream();
            var buffer = new byte[1024]; int count;
            while ((count = input.Read(buffer)) != 0)
            { if (bytes.Length + count > 4096) throw new Boundary("dsh_phase_rejected"); bytes.Write(buffer, 0, count); }
            using var document = JsonDocument.Parse(bytes.ToArray());
            Validate(document.RootElement);
            policy.VerifySource("flower-computer");
            Validate(document.RootElement); // Source hashing cannot extend the original metadata lifetime.
            var info = new ProcessStartInfo(policy.Python.Path) { UseShellExecute = false, CreateNoWindow = true,
                WorkingDirectory = policy.Repository, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            info.ArgumentList.Add("-I");
            info.ArgumentList.Add(Path.Combine(policy.Directory, "flower_hook_bootstrap.py"));
            info.ArgumentList.Add("--dsh-phase");
            if (policy.DataRoot.Length > 0) info.Environment["FLOWER_DATA_ROOT"] = policy.DataRoot;
            using var child = Process.Start(info) ?? throw new Boundary("dsh_phase_unavailable");
            try
            {
                var output = child.StandardOutput.ReadToEndAsync();
                var errors = child.StandardError.ReadToEndAsync();
                child.StandardInput.Write(document.RootElement.GetRawText()); child.StandardInput.Close();
                if (!child.WaitForExit(2000)) throw new Boundary("dsh_phase_unavailable");
                Task.WaitAll([output, errors], 500);
                if (!output.IsCompletedSuccessfully || !errors.IsCompletedSuccessfully || child.ExitCode != 0
                    || output.Result.Length > 1024) throw new Boundary("dsh_phase_unavailable");
                using var result = JsonDocument.Parse(output.Result);
                if (result.RootElement.GetProperty("phase").GetString() != "dsh_phase"
                    || result.RootElement.GetProperty("state").GetString() is not ("published" or "ignored"))
                    throw new Boundary("dsh_phase_unavailable");
                Console.WriteLine(result.RootElement.GetRawText()); return 0;
            }
            finally
            {
                if (!child.HasExited) { child.Kill(entireProcessTree: true); child.WaitForExit(500); }
            }
        }
        catch
        { Console.WriteLine("{\"phase\":\"dsh_phase\",\"state\":\"unavailable\"}"); return 2; }
    }
}
