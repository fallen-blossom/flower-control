namespace Flower.HighHelper;

// Data shape retained only for reading historical qualification evidence.
internal sealed record UacTestResult(string Nonce, Peer Launcher, string Status,
    int Win32Error, Peer? Target, int? ExitCode);
