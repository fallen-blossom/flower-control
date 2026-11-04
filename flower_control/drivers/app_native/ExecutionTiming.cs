using System.Diagnostics;
using System.Text.Json;

internal sealed class ProviderPropertyFailure : Exception
{
    internal string Property { get; }
    internal ProviderPropertyFailure(string property, Exception cause) : base("UIA property unavailable", cause) => Property = property;
}

sealed class ObservationBudget
{
    private readonly long _started = Stopwatch.GetTimestamp();
    internal int Milliseconds { get; }
    internal int Calls { get; private set; }
    internal int MaxCalls { get; }
    internal string? Trigger => Calls >= MaxCalls ? "max_provider_calls" : TimeExpired ? "max_ms" : null;
    internal ObservationBudget(int milliseconds, int maxCalls = 5000) { Milliseconds = milliseconds; MaxCalls = maxCalls; }
    private bool TimeExpired => Stopwatch.GetElapsedTime(_started).TotalMilliseconds >= Milliseconds;
    internal bool Expired => TimeExpired || Calls >= MaxCalls;
    internal bool PropertiesIncomplete { get; private set; }
    internal HashSet<string> PropertyErrors { get; } = new();
    internal T Read<T>(Func<T> read, T fallback)
    {
        if (Expired) { PropertiesIncomplete = true; return fallback; }
        Calls++;
        try { return read(); }
        catch (Exception error)
        {
            PropertiesIncomplete = true;
            if (error is ProviderPropertyFailure failure && PropertyErrors.Count < 16) PropertyErrors.Add(failure.Property);
            return fallback;
        }
    }
    internal void RequireRemaining()
    {
        if (Expired) throw new ObservationBudgetExceeded(Trigger, Calls);
        Calls++;
    }
}

sealed class ObservationBudgetExceeded : Exception
{
    internal string? Trigger { get; }
    internal int Calls { get; }
    internal ObservationBudgetExceeded(string? trigger, int calls) { Trigger = trigger; Calls = calls; }
}
sealed class BackgroundFocusChangedBeforeWrite : Exception { }

sealed class ExecutionState
{
    internal bool WriteStarted { get; private set; }
    internal string Stage { get; set; } = "native_validation";
    internal string? Pattern { get; set; }
    internal object? Result { get; set; }
    internal Dictionary<string, long> Timings { get; } = new();
    internal bool Background { get; set; }
    internal Func<bool>? BackgroundFocusMatches { get; set; }
    internal bool BackgroundFocusChanged { get; private set; }
    private void CheckBackgroundFocus()
    {
        if (Background && BackgroundFocusMatches?.Invoke() == false) BackgroundFocusChanged = true;
    }

    internal void BeginWrite()
    {
        CheckBackgroundFocus();
        if (BackgroundFocusChanged) throw new BackgroundFocusChangedBeforeWrite();
        WriteStarted = true;
        Stage = "uia_write";
    }

    internal T Time<T>(string field, Func<T> action)
    {
        long started = Stopwatch.GetTimestamp();
        try { return action(); }
        finally
        {
            CheckBackgroundFocus();
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
            _execution.CheckBackgroundFocus();
        }
    }

    internal object WithTimings(object result)
    {
        var fields = JsonSerializer.SerializeToElement(result).EnumerateObject()
            .ToDictionary(property => property.Name, property => (object?)property.Value.Clone());
        fields["timing_ms"] = new Dictionary<string, long>(Timings);
        if (Background)
        {
            CheckBackgroundFocus();
            fields["execution_mode"] = "must_background";
            fields["foreground_requested"] = false;
            fields["background_focus_unchanged"] = !BackgroundFocusChanged;
            if (BackgroundFocusChanged)
            {
                var prior = fields.GetValueOrDefault("state") is JsonElement oldState ? oldState.GetString() : null;
                fields["provider_state_before_focus_check"] = prior;
                // A focus contract failure does not erase a provider's known
                // dispatch/readback. Unknown provider effects remain unknown;
                // a known completed call can be freshly checked without replay.
                fields["state"] = !WriteStarted ? "rejected" : prior == "outcome_uncertain" ? "outcome_uncertain" : "not_verified";
                fields["dispatched"] = WriteStarted;
                if (!fields.TryGetValue("reason", out var reason)
                    || reason is JsonElement element && element.ValueKind == JsonValueKind.Null)
                    fields["reason"] = "background_focus_changed";
            }
        }
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
