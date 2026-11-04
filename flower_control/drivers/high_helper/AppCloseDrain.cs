namespace Flower.HighHelper;

// Drains one already-sent Invoke while its admitted owner takes foreground
// during child teardown. The enclosing request supplies the live deadline and
// Stop checks; a short presentation delay is not an independent failure limit.
// It never authorizes a new provider call.
internal sealed class AppCloseDrain(Func<long> elapsedMs)
{
    private long ancestorTransition = -1;
    internal bool TransitionStarted => Volatile.Read(ref ancestorTransition) >= 0;
    internal static bool HiddenTargetCanDrain(bool invokeSent, bool exists, bool visible,
                                              bool exactIdentity, bool exactOwner)
        => invokeSent && exists && !visible && exactIdentity && exactOwner;
    internal bool Allows(bool targetGone, bool admittedAncestor)
    {
        if (!admittedAncestor) return false;
        if (targetGone) return true;
        var now = elapsedMs();
        Interlocked.CompareExchange(ref ancestorTransition, now, -1);
        return true;
    }
}
