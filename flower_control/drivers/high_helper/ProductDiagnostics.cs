using System.Text.Json;
using System.Text.RegularExpressions;

namespace Flower.HighHelper;

// Deliberately content-free. This surface never captures window titles, paths,
// messages, target/task identifiers, screenshots, credentials or action values.
internal sealed record ProductRuntimeStatus(string Role, int Connections, int WebRequests, int AppRequests,
    int ComputerRequests, int PendingRecoveries, bool AllWritesStopped, bool ComputerPaused,
    bool ReleaseFault, string? StopPersistenceError, string? ComputerPausePersistenceError,
    bool? EmergencyHotkeyRegistered = null, int? EmergencyHotkeyError = null);

internal sealed partial class BrokerState
{
    private bool? emergencyHotkeyRegistered;
    private int? emergencyHotkeyError;
    internal void EmergencyHotkeyAvailable(bool value, int? error = null)
    { lock (gate) { emergencyHotkeyRegistered = value; emergencyHotkeyError = error; } }
    internal bool? EmergencyHotkeyRegistered { get { lock (gate) return emergencyHotkeyRegistered; } }
    internal int? EmergencyHotkeyError { get { lock (gate) return emergencyHotkeyError; } }
    internal ProductRuntimeStatus ProductStatus()
    {
        lock (gate)
        {
            var requests = Requests.Values.ToArray();
            return new(OrdinaryResident ? "medium" : "high", Math.Max(0, Volatile.Read(ref Connections)),
                requests.Count(r => r.Channel == "flower-web"), requests.Count(r => r.Channel == "flower-app"),
                requests.Count(r => r.Channel == "flower-computer"), completed.Values.Count(c => !c.Acknowledged),
                IsPaused, computerPaused, releaseFault, protectedStopError, computerPauseError,
                emergencyHotkeyRegistered, emergencyHotkeyError);
        }
    }
}

internal sealed record ProductDiagnosticEvent(long Sequence, string Utc, ProductRuntimeStatus Status);

// A bounded, per-helper-run metadata timeline complements the authenticated
// execution audit. It does not read/decrypt, acknowledge or repair that audit.
internal sealed class ProductDiagnostics
{
    internal const int Capacity = 256;
    internal static readonly ProductDiagnostics Current = new();
    private readonly object gate = new();
    private readonly Queue<ProductDiagnosticEvent> events = new();
    private long sequence;
    internal static string? SafeCode(string? code) => code is null ? null
        : Regex.IsMatch(code, "^[a-z][a-z0-9_]{0,95}$", RegexOptions.CultureInvariant) ? code : "unavailable";
    private static ProductRuntimeStatus Redact(ProductRuntimeStatus value) => value with {
        Role = value.Role is "high" or "medium" ? value.Role : "unverified",
        StopPersistenceError = SafeCode(value.StopPersistenceError),
        ComputerPausePersistenceError = SafeCode(value.ComputerPausePersistenceError)
    };
    internal void Observe(ProductRuntimeStatus status)
    {
        status = Redact(status);
        lock (gate)
        {
            if (events.LastOrDefault()?.Status == status) return;
            events.Enqueue(new(++sequence, DateTimeOffset.UtcNow.ToString("O"), status));
            while (events.Count > Capacity) events.Dequeue();
        }
    }
    internal ProductDiagnosticEvent[] Snapshot() { lock (gate) return events.ToArray(); }
    internal string Export(ProductRuntimeStatus? status, string identityState, string loadedVersion, string installedVersion,
        string integrityState = "unverified", int verifiedFiles = 0, string? integrityError = null)
    {
        if (status is not null) Observe(status);
        static string Version(string value) => Regex.IsMatch(value, "^[a-f0-9]{16,64}$") ? value : "unverified";
        return JsonSerializer.Serialize(new {
            schema = 1, scope = "current_helper_run_metadata", capacity = Capacity,
            host_chat_injection = "unverified", selected_target = "not_observed_by_settings",
            version_state = identityState is "match" or "mismatch" ? identityState : "unverified",
            loaded_version = Version(loadedVersion), installed_version = Version(installedVersion),
            integrity_state = integrityState == "verified" ? "verified" : "unverified",
            verified_files = Math.Clamp(verifiedFiles, 0, 50000), integrity_error = SafeCode(integrityError),
            screenshot_included = false, content_included = false, events = Snapshot(),
            input_replay = false, stop_or_permissions_changed = false
        }, new JsonSerializerOptions { WriteIndented = true });
    }
    internal static int SelfTest()
    {
        int assertions = 0;
        void Check(bool value) { ++assertions; if (!value) throw new Boundary("product_diagnostics_selftest_failed_" + assertions); }
        var log = new ProductDiagnostics();
        var state = new ProductRuntimeStatus("medium", 0, 0, 0, 0, 0, false, false, false, null, null);
        log.Observe(state); log.Observe(state);
        Check(log.Snapshot().Length == 1);
        for (int i = 1; i <= Capacity + 20; ++i) log.Observe(state with { Connections = i });
        Check(log.Snapshot().Length == Capacity && log.Snapshot()[0].Sequence == 22);
        var stopped = state with { AllWritesStopped = true, ComputerPaused = true, PendingRecoveries = 3,
            StopPersistenceError = @"C:\private\secret.txt", ComputerPausePersistenceError = "computer_pause_state_changed" };
        string exported = log.Export(stopped, "secret state", @"D:\private\source", new string('a', 32));
        using var document = JsonDocument.Parse(exported);
        Check(!exported.Contains("secret", StringComparison.Ordinal) && !exported.Contains("private", StringComparison.Ordinal));
        Check(document.RootElement.GetProperty("version_state").GetString() == "unverified");
        Check(log.Snapshot()[^1].Status is { AllWritesStopped: true, ComputerPaused: true, PendingRecoveries: 3,
            StopPersistenceError: "unavailable", ComputerPausePersistenceError: "computer_pause_state_changed" });
        var broker = new BrokerState();
        broker.Requests.TryAdd("computer", new() { Channel = "flower-computer" });
        broker.Requests.TryAdd("app", new() { Channel = "flower-app", AdminLaunch = true });
        Check(HostWindow.HandleStopHotkey(broker, 9));
        Check(broker.Requests["computer"].Stop.IsCancellationRequested && !broker.Requests["app"].Stop.IsCancellationRequested);
        Check(HostWindow.HandleStopHotkey(broker, 10));
        Check(broker.ProductStatus() is { AllWritesStopped: true, ComputerRequests: 1, AppRequests: 1 });
        Check(broker.Requests["app"].Stop.IsCancellationRequested);
        broker.EmergencyHotkeyAvailable(false, 1409);
        Check(broker.ProductStatus() is { EmergencyHotkeyRegistered: false, EmergencyHotkeyError: 1409 });
        broker.EmergencyHotkeyAvailable(true);
        Check(broker.ProductStatus() is { EmergencyHotkeyRegistered: true, EmergencyHotkeyError: null });
        Check(!HostWindow.HandleStopHotkey(broker, 999));
        Check(HostWindow.ShouldOpenFirstRun(new() { Revision = "absent", AuthorityTier = 0 }));
        Check(!HostWindow.ShouldOpenFirstRun(new() { Revision = "saved", AuthorityTier = 2 }));
        Check(!HostWindow.ShouldOpenFirstRun(new() { Revision = "absent", AuthorityTier = 1 }));
        Check(TrayMenu.ShouldAnimate(false, true, true) && !TrayMenu.ShouldAnimate(true, true, true)
            && !TrayMenu.ShouldAnimate(false, false, true) && !TrayMenu.ShouldAnimate(false, true, false));
        var sleeping = new BrokerState();
        sleeping.Requests.TryAdd("sleep", new() { Channel = "flower-computer" });
        long beforeSleep = sleeping.Revision;
        Check(HostWindow.HandlePowerMessage(sleeping, 0x218, 4) && sleeping.Revision > beforeSleep
            && sleeping.Requests["sleep"].Stop.IsCancellationRequested && !sleeping.IsPaused);
        int probes = 0;
        Check(HostWindow.HandlePowerMessage(sleeping, 0x218, 18, current => { ++probes; current.Desktop(true); })
            && probes == 1 && sleeping.Requests["sleep"].Stop.IsCancellationRequested);
        Check(!HostWindow.HandlePowerMessage(sleeping, 0x218, 0x8013) && !sleeping.Shutdown.IsCancellationRequested);
        return assertions + InstallationHealth.SelfTest();
    }
}
