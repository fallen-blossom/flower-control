namespace Flower.HighHelper;

// Only this broker's notification icon. Shell absence is recoverable; it does
// not end the desktop/Stop listener or create an input permission.
internal sealed class TrayRegistration(Func<bool> add, Func<bool> modify, Action remove, Func<bool>? exists = null)
{
    internal bool Registered { get; private set; }
    private long nextCheck;
    private int failures;
    private string? lastSummary;
    private bool retryPending, closed;
    internal void Tick(long now, string summary)
    {
        if (closed || now < nextCheck && (retryPending || !Registered || summary == lastSummary)) return;
        if (!Registered && exists?.Invoke() == true) Registered = true;
        if (Registered)
        {
            if (modify()) { Updated(now, summary); return; }
            // A failed modification does not prove the icon was discarded.
            // Presence also does not prove its tooltip was updated: retry the
            // modification with backoff, including when the summary changes.
            if (exists?.Invoke() == true) { Retry(now); return; }
            Registered = false;
        }
        var added = add();
        Registered = added || exists?.Invoke() == true;
        if (added) Updated(now, summary);
        else Retry(now); // An existing icon must resume MODIFY on the next check.
    }
    private void Updated(long now, string summary)
    {
        Registered = true; failures = 0; retryPending = false;
        lastSummary = summary; nextCheck = now + 1000;
    }
    private void Retry(long now)
    {
        retryPending = true; failures = Math.Min(failures + 1, 5);
        nextCheck = now + failures * 1000;
    }
    internal void ExplorerRestarted(long now)
    {
        if (closed) return;
        Registered = false; failures = 0; retryPending = false; nextCheck = now;
    }
    internal void Close()
    {
        if (closed) return;
        closed = true; Registered = false; remove();
    }
}
