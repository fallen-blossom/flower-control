namespace Flower.HighHelper;

// The original dispatcher and all its locks remain the owner. Recovery is
// possible only before an unsent step with a known, empty input ledger.
internal sealed class ForegroundPriority(Func<string> releaseState, Action authority,
    Action restore, Action restart)
{
    private bool used, recovering;
    internal static bool Recoverable(string code) => code is "foreground_changed" or "target_minimized"
        or "external_input_held" or "external_keyboard_activity" or "external_mouse_activity";
    internal bool Recover(string code)
    {
        if (used || recovering || !Recoverable(code) || releaseState() != "released") return false;
        used = true; recovering = true;
        try
        {
            authority();
            restore();
            authority();
            restart();
            authority();
            return true;
        }
        finally { recovering = false; }
    }
    internal void Check(Action check)
    {
        try { check(); }
        catch (Boundary error)
        {
            if (!Recover(error.Code)) throw;
            check(); // One new observation, never another recovery loop.
        }
    }
}

internal sealed class ForegroundObservation(Func<ForegroundEvents> create) : IDisposable
{
    private ForegroundEvents? current = create();
    internal void Check() => (current ?? throw new Boundary("foreground_watch_unavailable")).Check();
    internal void CheckRecovery() => (current ?? throw new Boundary("foreground_watch_unavailable")).CheckRecovery();
    internal void Suspend() { current?.Dispose(); current = null; }
    internal void Restart() { if (current is not null) throw new Boundary("foreground_watch_already_started"); current = create(); }
    public void Dispose() => Suspend();
}
