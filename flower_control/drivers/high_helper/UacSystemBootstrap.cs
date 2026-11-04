namespace Flower.HighHelper;

// The retired SYSTEM host is never admitted. Existing call sites may still
// encounter its persisted state and must fail closed without changing it.
internal static class UacSystemBootstrap
{
    internal static void VerifyInteractiveUser(int session, string sid)
        => throw new Boundary("host_uac_feature_retired");
}
