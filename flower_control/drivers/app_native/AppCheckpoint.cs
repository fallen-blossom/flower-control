using System.Diagnostics;
using System.Text.Json;

// Fixed, content-free stages on the private stderr pipe. One request per worker.
enum AppCheckpointStage
{
    request_validated, uia_initialize_enter, uia_initialize_exit,
    root_bind_enter, root_bind_exit, exact_lookup_enter, exact_lookup_exit,
    pattern_enter, pattern_exit, ready, business_enter, dispose_enter, disposed,
}

static class AppCheckpoint
{
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static int emitted;
    internal static void Start() { _ = Clock.ElapsedMilliseconds; }
    internal static void Record(AppCheckpointStage stage)
    {
        if (Interlocked.Increment(ref emitted) > 128) return;
        try
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { flower_app_checkpoint = 1,
                stage = stage.ToString(), elapsed_ms = Math.Clamp(Clock.ElapsedMilliseconds, 0, 600_000) }));
            Console.Error.Flush();
        }
        catch (IOException) { }
        catch (ObjectDisposedException) { }
    }
    internal static T Measure<T>(AppCheckpointStage enter, AppCheckpointStage exit, Func<T> action)
    {
        Record(enter);
        var value = action();
        Record(exit);
        return value;
    }
}

sealed class CheckpointDisposal(IDisposable resource) : IDisposable
{
    public void Dispose()
    {
        AppCheckpoint.Record(AppCheckpointStage.dispose_enter);
        resource.Dispose();
        AppCheckpoint.Record(AppCheckpointStage.disposed);
    }
}
