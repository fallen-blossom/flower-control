using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace Flower.HighHelper;

internal static class DshHostHook
{
    internal static int Run()
    {
        try
        {
            var policy = BrokerPolicy.Load(Path.Combine(AppContext.BaseDirectory, "broker.json"), false);
            var own = Native.Process(Environment.ProcessId).Identity;
            var admission = ClientAdmission.Verify(own.Pid, policy);
            if (policy.Fixture || own.Integrity != 8192 || !admission.Admin || admission.Evidence.Source != "dsh-desktop-flower")
                throw new Boundary("dsh_host_event_rejected");
            using var input = Console.OpenStandardInput(); using var bytes = new MemoryStream();
            var buffer = new byte[4096]; int count;
            while ((count = input.Read(buffer)) != 0)
            { if (bytes.Length + count > 65536) throw new Boundary("dsh_host_event_too_large"); bytes.Write(buffer, 0, count); }
            using var document = JsonDocument.Parse(bytes.ToArray());
            var message = Protocol.Decode<DshHostMessage>(document);
            using var pipe = new NamedPipeClientStream(".", BrokerPipe.Name(own), PipeDirection.InOut,
                PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
            pipe.Connect(1500);
            if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var pid))
                throw new Boundary("dsh_host_broker_unavailable");
            var (server, image) = Native.Process((int)pid);
            if (server.User != own.User || server.Session != own.Session || server.Integrity != 12288
                || !image.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase) || server.ImageDigest != own.ImageDigest)
                throw new Boundary("dsh_host_broker_changed");
            Protocol.Write(pipe, new { Phase = "hello", Parent = own, Channel = "flower-uac-hook" });
            using var hello = Protocol.Read(pipe, 3000);
            if (hello is null || UacOutcomeEvidence.Text(hello.RootElement, "Phase") != "hello"
                || UacOutcomeEvidence.Text(hello.RootElement, "AssemblyDigest") != Program.AssemblyDigest)
                throw new Boundary("dsh_host_broker_changed");
            Protocol.Write(pipe, message);
            using var result = Protocol.Read(pipe, 15000);
            if (result is null || UacOutcomeEvidence.Text(result.RootElement, "Phase") != "dsh_host_event")
                throw new Boundary(result is not null ? UacOutcomeEvidence.Text(result.RootElement, "Reason") ?? "dsh_host_event_unconfirmed" : "dsh_host_event_unconfirmed");
            Console.WriteLine(result.RootElement.GetRawText()); return 0;
        }
        catch (Exception error)
        { Console.WriteLine(JsonSerializer.Serialize(new { State = "unavailable", Reason = Program.Code(error) })); return 2; }
    }
}
