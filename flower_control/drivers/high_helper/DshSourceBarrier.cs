using System.Text.Json;

namespace Flower.HighHelper;

// This local witness only removes source validity. It cannot establish a
// source, grant permissions, provide message text or replace native admission.
internal sealed class DshSourceBarrier : IDisposable
{
    private readonly FileStream file;
    private readonly string instance;
    private DshSourceBarrier(FileStream file, string instance) { this.file = file; this.instance = instance; }
    internal static DshSourceBarrier Open(string transcript, string instance)
    {
        string path = transcript + ".flower-" + instance + ".source";
        BrokerPolicy.RejectLinks(path);
        // Pin this object against rename/delete for the binding lifetime.
        var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, bufferSize: 1);
        try { DshTranscriptReader.CheckHandle(file, path); return new(file, instance); }
        catch { file.Dispose(); throw; }
    }
    internal void Require(long revision)
    {
        try
        {
            if (file.Length is <= 0 or > 4096) throw new Boundary("dsh_host_source_invalidated");
            var bytes = new byte[(int)file.Length]; file.Position = 0; file.ReadExactly(bytes);
            if (file.Length != bytes.Length || bytes[^1] != 10) throw new Boundary("dsh_host_source_invalidated");
            using var doc = JsonDocument.Parse(bytes); Protocol.CheckUnique(doc);
            var row = doc.RootElement;
            if (row.GetProperty("InstanceId").GetString() != instance || row.GetProperty("Revision").GetInt64() != revision
                || row.GetProperty("Closed").ValueKind != JsonValueKind.False)
                throw new Boundary("dsh_host_source_invalidated");
        }
        catch (Exception error) when (error is not Boundary)
        { throw new Boundary("dsh_host_source_invalidated"); }
    }
    public void Dispose() => file.Dispose();
}
