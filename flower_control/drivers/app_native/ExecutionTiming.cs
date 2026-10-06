using System.Diagnostics;
using System.Text.Json;

sealed class ObservationBudget
{
    private readonly long _started = Stopwatch.GetTimestamp();
    internal int Milliseconds { get; }
    internal ObservationBudget(int milliseconds) => Milliseconds = milliseconds;
    internal bool Expired => Stopwatch.GetElapsedTime(_started).TotalMilliseconds >= Milliseconds;
}

sealed class ExecutionState
{
    internal bool WriteStarted { get; private set; }
    internal string Stage { get; set; } = "native_validation";
    internal object? Result { get; set; }
    internal Dictionary<string, long> Timings { get; } = new();

    internal void BeginWrite()
    {
        WriteStarted = true;
        Stage = "uia_write";
    }

    internal T Time<T>(string field, Func<T> action)
    {
        long started = Stopwatch.GetTimestamp();
        try { return action(); }
        finally
        {
            long milliseconds = Math.Max(0, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            Timings[field] = Timings.GetValueOrDefault(field) + milliseconds;
        }
    }

    internal void Time(string field, Action action) => Time<object?>(field, () => { action(); return null; });
    internal IDisposable Measure(string field) => new TimingScope(this, field);

    private sealed class TimingScope : IDisposable
    {
        private readonly ExecutionState _execution;
        private readonly string _field;
        private readonly long _started = Stopwatch.GetTimestamp();
        private bool _disposed;
        internal TimingScope(ExecutionState execution, string field) { _execution = execution; _field = field; }
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            long elapsed = Math.Max(0, (long)Stopwatch.GetElapsedTime(_started).TotalMilliseconds);
            _execution.Timings[_field] = _execution.Timings.GetValueOrDefault(_field) + elapsed;
        }
    }

    internal object WithTimings(object result)
    {
        var fields = JsonSerializer.SerializeToElement(result).EnumerateObject()
            .ToDictionary(property => property.Name, property => (object?)property.Value.Clone());
        fields["timing_ms"] = new Dictionary<string, long>(Timings);
        return fields;
    }
}

sealed class TimedDisposal : IDisposable
{
    private readonly IDisposable _resource;
    private readonly ExecutionState _execution;
    internal TimedDisposal(IDisposable resource, ExecutionState execution)
    {
        _resource = resource;
        _execution = execution;
    }
    public void Dispose()
    {
        string previous = _execution.Stage;
        _execution.Stage = "uia_dispose";
        _execution.Time("native_uia_dispose", _resource.Dispose);
        _execution.Stage = previous;  // failure retains the actual disposal stage
    }
}
