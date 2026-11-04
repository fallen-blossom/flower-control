namespace Flower.HighHelper;

internal static class NativeRoleIdentity
{
    internal static void Require(Peer peer, BrokerPolicy policy, int integrity)
    {
        var actual = Native.Process(peer.Pid);
        string expected = Path.GetFullPath(Path.Combine(policy.Directory, "Flower.HighHelper.exe"));
        // An apphost hash alone is insufficient: a copied apphost can load an
        // unrelated DLL. The process must be the protected installed image in
        // this exact version directory, with the expected actual token.
        if (actual.Identity != peer || peer.User != policy.UserSid || peer.Integrity != integrity || Native.UiAccess(peer.Pid)
            || !Path.GetFullPath(actual.Image).Equals(expected, StringComparison.OrdinalIgnoreCase)
            || Native.Digest(expected) != peer.ImageDigest)
            throw new Boundary("installed_role_identity_rejected");
        BrokerPolicy.RejectLinks(expected);
        UserPermissions.CheckSystemExecutableProtection(expected);
    }
}
