using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Definitions;
using FlaUI.UIA3;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// One request per process. The Python parent owns the ledger permit, execution
// lock and kill-on-close Job. Do not log request bodies or provider exceptions.
Console.InputEncoding = new UTF8Encoding(false, true);
Console.OutputEncoding = new UTF8Encoding(false);
if (args.Length == 1 && args[0] == "--privacy-session")
{
    // The single-threaded action-local process owns one UIA connection. Each
    // request still validates identity and obtains fresh root/focus metadata.
    if (!Native.SetProcessDpiAwarenessContext(new nint(-4))) return 2;
    UIA3Automation? privacyAutomation = null;
    try
    {
        var started = Stopwatch.StartNew();
        for (int count = 0; count < 128 && started.Elapsed < TimeSpan.FromSeconds(15); count++)
        {
            var privacyLine = Console.ReadLine();
            if (privacyLine is null) return 0;
            if (privacyLine.Length > 4096) return 2;
            try
            {
                using var privacyDocument = JsonDocument.Parse(privacyLine);
                privacyAutomation ??= PasswordPixels.CreateAutomation();
                Emit(PasswordPixels.Scan(privacyDocument.RootElement, privacyAutomation));
            }
            catch (Exception error) { Emit(PasswordPixels.Failure(error)); return 2; }
        }
        // Preserve the exact peer until EOF after quota; reject extra input.
        return Console.In.Read() == -1 ? 0 : 2;
    }
    finally { privacyAutomation?.Dispose(); }

}
AppCheckpoint.Start();
var line = Console.ReadLine();
// Larger synthetic tree fixture only; real worker requests retain the original cap.
int inputCap = args.Length == 1 && args[0] == "--observation-budget-only" ? 512_000 : 32768;
if (line is null || line.Length > inputCap)
    return 2;
var execution = new ExecutionState();
try
{
    using var document = JsonDocument.Parse(line);
    var request = document.RootElement;
    if (args.Length == 1 && args[0] == "--privacy-compatibility-only")
    {
        Emit(new { assertions = PasswordPixels.CompatibilityTests(), nativeInputExecuted = false,
            productionPolicyReadOrWritten = false });
        return 0;
    }
    if (args.Length == 1 && args[0] == "--privacy-only")
    {
        // Internal screenshot companion. It never reads Name/Value/Text.
        if (!Native.SetProcessDpiAwarenessContext(new nint(-4))) throw new ArgumentException();
        try { Emit(PasswordPixels.Scan(request)); return 0; }
        catch (Exception error) { Emit(PasswordPixels.Failure(error)); return 2; }
    }
    var command = RequiredString(request, "command");
    var arguments = Required(request, "arguments");
    Validate(command, arguments);
    AppCheckpoint.Record(AppCheckpointStage.request_validated);
    if (args.Length == 1 && args[0] == "--tree-page-only" && command == "observe")
    {
        // Offline algorithm Oracle only; no window/UIA or input access.
        var nodes = request.GetProperty("fixture_tree").EnumerateArray().ToArray();
        var byId = nodes.ToDictionary(node => node.GetProperty("id").GetInt32());
        var children = nodes.ToDictionary(node => node.GetProperty("id").GetInt32(),
            node => node.GetProperty("children").EnumerateArray().Select(x => x.GetInt32()).ToArray());
        var siblings = new Dictionary<int, int>();
        foreach (var list in children.Values)
            for (int i = 0; i + 1 < list.Length; i++) siblings[list[i]] = list[i + 1];
        string root = nodes[0].GetProperty("id").GetInt32().ToString();
        var pages = new BoundedTreePages<string>(root,
            arguments.TryGetProperty("tree", out var cursor) ? cursor : null,
            id => new[] { int.Parse(id) },
            id => children[int.Parse(id)].FirstOrDefault() is var first && first != 0 ? first.ToString() : null,
            id => siblings.TryGetValue(int.Parse(id), out var next) ? next.ToString() : null);
        var ids = new List<int>();
        int count = arguments.GetProperty("limits").GetProperty("max_nodes").GetInt32();
        int depth = arguments.GetProperty("limits").GetProperty("max_depth").GetInt32();
        while (pages.Count > 0 && ids.Count < count)
        {
            var node = pages.Peek(); ids.Add(int.Parse(node.Element)); pages.Commit(node.Element, depth);
        }
        Emit(new { state = "observed", target_read = false, dispatched = false, ids,
            tree_next = pages.Count > 0 ? pages.Cursor(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) : null });
        return 0;
    }
    if (args.Length == 1 && args[0] == "--observation-budget-only" && command == "observe")
    {
        // OWN synthetic provider Oracle: shared budget and tree traversal, no UIA/window.
        var limits = arguments.GetProperty("limits");
        var nodes = request.GetProperty("fixture_tree").EnumerateArray().ToArray();
        var byId = nodes.ToDictionary(n => n.GetProperty("id").GetInt32().ToString());
        var children = nodes.ToDictionary(n => n.GetProperty("id").GetInt32().ToString(),
            n => n.GetProperty("children").EnumerateArray().Select(x => x.GetInt32().ToString()).ToArray());
        var siblings = new Dictionary<string, string>();
        foreach (var list in children.Values) for (int i=0;i+1<list.Length;i++) siblings[list[i]]=list[i+1];
        int Number(string key, int fallback) => limits.TryGetProperty(key,out var n) ? n.GetInt32() : fallback;
        var budget = new ObservationBudget(Number("max_ms",1800),Number("max_provider_calls",5000));
        var pages = new BoundedTreePages<string>(nodes[0].GetProperty("id").GetInt32().ToString(),
            arguments.TryGetProperty("tree",out var cursor) ? cursor : null,
            id=>new[]{int.Parse(id)}, id=>children[id].FirstOrDefault(),
            id=>siblings.TryGetValue(id,out var next)?next:null, budget.RequireRemaining);
        JsonElement? filter = limits.TryGetProperty("filter",out var f)?f:null;
        var entries = new List<JsonElement>(); int bytes=0,visited=0,committed=0; string? trigger=null; bool truncated=false;
        while(pages.Count>0)
        {
            if(budget.Expired){trigger=budget.Trigger;break;}
            if(pages.Count>256){trigger="tree_cursor_capacity";break;}
            if(visited>=Number("max_nodes",96)){trigger="max_nodes";break;}
            try
            {
                var node=pages.Peek(); var value=byId[node.Element];
                string Read(string key)=>budget.Read(()=>value.TryGetProperty(key,out var v)?v.GetString()??"":"","");
                string auto=Read("automation_id"),type=Read("control_type"),name=Read("name");
                if(value.TryGetProperty("delay_ms",out var delay)) Thread.Sleep(delay.GetInt32());
                if(budget.Expired){trigger=budget.Trigger;break;}
                visited++;
                if(MatchesObservationFilter(filter,auto,type,name))
                {
                    int size=JsonSerializer.SerializeToUtf8Bytes(value).Length+1;
                    if(bytes+size>Number("max_bytes",80000)){trigger="max_bytes";break;}
                    truncated|=pages.Commit(node.Element,Number("max_depth",6)); committed++;
                    entries.Add(value);bytes+=size;
                }
                else { truncated|=pages.Commit(node.Element,Number("max_depth",6)); committed++; }
            }
            catch(ObservationBudgetExceeded){trigger=budget.Trigger;break;}
        }
        Emit(new {state="observed",target_read=false,dispatched=false,entries,provider_calls=budget.Calls,
            visited_nodes=visited,retained_bytes=bytes,budget_trigger=trigger,truncated=truncated||pages.Count>0,
            tree_next=committed>0 && pages.Count is >0 and <=256?pages.Cursor(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()):null,
            new_observation_required=pages.Count>256 || pages.Count>0 && committed==0});
        return 0;
    }
    if (args.Length == 1 && args[0] == "--text-page-only" && command == "read_text")
    {
        var page = TextPages.Read(RequiredString(request, "fixture_text"), Required(arguments, "text"));
        page["target_read"] = false;
        Emit(page);
        return 0;
    }
    if (args.Length == 1 && args[0] == "--validate-only")
    {
        Emit(new { state = "observed", contract_valid = true, target_read = false,
            dispatched = false,
            request_utf8_sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(line))).ToLowerInvariant() });
        return 0;
    }
    if (args.Length != 0)
        return 2;
    // UIA geometry must use the same physical pixels as WGC and Computer input.
    // Each disposable worker sets its own context before creating any UIA COM objects.
    if (!Native.SetProcessDpiAwarenessContext(new nint(-4)))
    {
        Emit(new { state = "rejected", dispatched = false,
            reason = "per_monitor_dpi_awareness_required" });
        return 0;
    }
    Execute(command, arguments, execution);
    if (execution.Result is not null)
        Emit(execution.WithTimings(execution.Result));
    return 0;
}
catch (Exception error)
{
    if (error is BackgroundFocusChangedBeforeWrite)
    {
        Emit(execution.WithTimings(new { state = "rejected", dispatched = false,
            reason = "background_focus_changed", stage = execution.Stage }));
        return 0;
    }
    // Never include provider messages or request content in the receipt.
    // Mark only entry into a mutating provider call as a possible side effect.
    if (error is ObservationBudgetExceeded budget)
    {
        Emit(new { state = "not_verified", dispatched = false, reason = "observation_budget_exhausted",
            budget_trigger = budget.Trigger, provider_calls = budget.Calls,
            new_observation_required = true,
            recovery_hint = "observe_with_larger_budget_or_narrower_scope" });
        return 0;
    }
    if (error is ProviderIdentityUnavailable)
    {
        var cause = error.InnerException ?? error;
        Emit(execution.WithTimings(new { state = execution.WriteStarted ? "outcome_uncertain" : "rejected",
            dispatched = execution.WriteStarted, reason = "uia_provider_identity_unavailable",
            stage = execution.Stage, exception_type = cause.GetType().Name, hresult = cause.HResult,
            unsupported_property = "RuntimeId", recovery_hint = "use_computer_channel" }));
        return 0;
    }
    var actualError = error is ProviderPropertyFailure ? error.InnerException ?? error : error;
    var reason = error is TreeCursorChanged ? "tree_cursor_changed"
        : error is ProviderPropertyFailure { Property: "IsPassword" } ? "uia_privacy_unavailable"
        : actualError.HResult == unchecked((int)0x80070005) ? "uia_access_denied"
        : actualError.HResult == unchecked((int)0x80040201) ? "uia_element_unavailable"
        : actualError is TimeoutException ? "uia_timeout"
        : execution.Stage + "_failed";
    Emit(execution.WithTimings(new { state = execution.WriteStarted ? "outcome_uncertain" : "rejected",
        dispatched = execution.WriteStarted, reason, stage = execution.Stage,
        exception_type = actualError.GetType().Name, hresult = actualError.HResult,
        failure_property = (error as ProviderPropertyFailure)?.Property,
        failure_pattern = execution.Pattern,
        cursor_cause = (error as TreeCursorChanged)?.Cause }));
    return 0;
}

static bool MatchesObservationFilter(JsonElement? filter, string automationId, string controlType, string? name) =>
    filter is null || filter.Value.EnumerateObject().All(field => field.Value.GetString() ==
        (field.Name == "automation_id" ? automationId : field.Name == "control_type" ? controlType : name));

static void Execute(string command, JsonElement arguments, ExecutionState execution)
{
    // Deliver the final result only after the using scopes actually dispose.
    // Ready/go remains immediate via the separate WaitForGo method.
    void Emit(object value) => execution.Result = value;
    execution.Stage = "native_preflight";
    // Observation cannot read UIA content until the parent has rechecked the
    // permit after this process is ready. Writes wait again after preflight.
    if (command is "observe" or "read_text" && !WaitForGo())
        return;
    var target = Required(arguments, "target");
    int pid = RequiredInt(target, "pid");
    long startTime = RequiredLong(target, "process_start_filetime");
    nint hwnd = (nint)RequiredLong(target, "hwnd");
    if (!Native.IsWindow(hwnd) || !Native.IsWindowVisible(hwnd)
        || Native.GetWindowThreadProcessId(hwnd, out var actualPid) == 0 || actualPid != pid)
    {
        Emit(new { state = "rejected", reason = "window_identity_changed", dispatched = false });
        return;
    }
    using var process = Process.GetProcessById(pid);
    if (process.StartTime.ToUniversalTime().ToFileTimeUtc() != startTime)
    {
        Emit(new { state = "rejected", reason = "process_instance_changed", dispatched = false });
        return;
    }
    using var backgroundFocus = arguments.TryGetProperty("execution_mode", out _) ? new BackgroundFocusEvents(hwnd) : null;
    if (backgroundFocus is not null)
    {
        execution.Background = true;
        var initialForeground = Native.GetForegroundWindow();
        execution.BackgroundFocusMatches = () => backgroundFocus.Unchanged &&
            (Native.GetForegroundWindow() == initialForeground || !Native.IsForegroundRoot(hwnd));
    }
    execution.Stage = "uia_initialization";
    var automation = AppCheckpoint.Measure(AppCheckpointStage.uia_initialize_enter,
        AppCheckpointStage.uia_initialize_exit, () => execution.Time("native_uia_initialize", () => new UIA3Automation
    {
        ConnectionTimeout = TimeSpan.FromSeconds(1),
        TransactionTimeout = TimeSpan.FromSeconds(2),
    }));
    using var automationLifetime = new CheckpointDisposal(new TimedDisposal(automation, execution));
    execution.Stage = "uia_read";
    AppCheckpoint.Record(AppCheckpointStage.root_bind_enter);
    var root = automation.FromHandle(hwnd);
    var walker = automation.TreeWalkerFactory.GetControlViewWalker();
    if (ProviderReads.Required("ProcessId", () => root.Properties.ProcessId.Value) != pid)
    {
        Emit(new { state = "rejected", reason = "uia_root_mismatch", dispatched = false });
        return;
    }
    var rootId = TreePages.ReadRuntimeId(() => root.Properties.RuntimeId.Value);
    var expectedRoot = IntArray(Required(target, "root_runtime_id"));
    if (expectedRoot.Length > 0 && !rootId.SequenceEqual(expectedRoot))
    {
        Emit(new { state = "rejected", reason = "root_version_changed", dispatched = false });
        return;
    }
    AppCheckpoint.Record(AppCheckpointStage.root_bind_exit);
    var lookupRoot = root;
    if (command == "observe" && arguments.TryGetProperty("local", out var local))
    {
        lookupRoot = execution.Time("native_local_resolve", () =>
            LocalScope.Resolve(walker, root, local, FindExact));
        if (lookupRoot is null)
        {
            Emit(new { state = "rejected", reason = "local_item_scope_changed", dispatched = false });
            return;
        }
    }
    bool localScopeChanged = false;
    AutomationElement? FindCurrent(int[] id, string automationId)
    {
        var currentRoot = arguments.TryGetProperty("local", out var currentLocal)
            ? execution.Time("native_local_resolve", () => LocalScope.Resolve(walker, root, currentLocal, FindExact,
                command == "read_text" ? 300_000 : 15_000)) : root;
        if (currentRoot is null) localScopeChanged = true;
        return currentRoot is null ? null : FindExact(walker, currentRoot, id, automationId);
    }
    AutomationElement? RebindCurrent(int[] id, string automationId, bool allowDisabled = false)
    {
        var current = FindCurrent(id, automationId);
        return current is not null && (allowDisabled || ProviderReads.Required("IsEnabled", () => current.IsEnabled))
            && !PasswordProperty.Read(current) ? current : null;
    }
    if (command == "observe" && arguments.TryGetProperty("diagnostic", out var diagnostic))
    {
        execution.Stage = "uia_property_preflight";
        var diagnosticBudget = new ObservationBudget(1800);
        var diagnosticObservation = diagnostic.GetProperty("observation");
        long diagnosticAge = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - diagnosticObservation.GetProperty("observed_at_ms").GetInt64();
        if (diagnosticAge is < 0 or > 15_000 || !rootId.SequenceEqual(IntArray(diagnosticObservation.GetProperty("root_runtime_id"))))
        {
            Emit(new { state = "rejected", dispatched = false, reason = "observation_stale" });
            return;
        }
        var diagnosticReference = diagnostic.GetProperty("reference");
        var diagnosticReferenceId = IntArray(diagnosticReference.GetProperty("runtime_id"));
        string diagnosticAutomationId = RequiredString(diagnosticReference, "automation_id");
        var diagnosticControl = execution.Time("native_control_lookup", () => FindCurrent(diagnosticReferenceId, diagnosticAutomationId));
        if (diagnosticControl is null)
        {
            Emit(new { state = "rejected", dispatched = false, reason = "control_unavailable" });
            return;
        }
        if (PasswordProperty.Read(diagnosticControl))
        {
            Emit(new { state = "rejected", dispatched = false, reason = "property_privacy_unavailable",
                properties = new { help_text = new { state = "redacted" } } });
            return;
        }
        execution.Stage = "uia_property_read";
        var diagnosticProperty = PropertyDiagnostics.ReadHelpText(() => {
            bool supported = diagnosticControl.Properties.HelpText.TryGetValue(out var value);
            return (supported, value);
        }, diagnosticBudget.Expired);
        execution.Stage = "uia_property_return";
        var diagnosticCurrent = FindCurrent(diagnosticReferenceId, diagnosticAutomationId);
        long diagnosticReturnAge = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - diagnosticObservation.GetProperty("observed_at_ms").GetInt64();
        if (diagnosticReturnAge is < 0 or > 15_000 || diagnosticCurrent is null || PasswordProperty.Read(diagnosticCurrent)
            || !Native.IsWindow(hwnd) || Native.GetWindowThreadProcessId(hwnd, out actualPid) == 0 || actualPid != pid
            || process.StartTime.ToUniversalTime().ToFileTimeUtc() != startTime
            || !TreePages.ReadRuntimeId(() => root.Properties.RuntimeId.Value).SequenceEqual(rootId))
        {
            Emit(new { state = "rejected", dispatched = false, reason = "property_return_not_authorized", content_suppressed = true });
            return;
        }
        Emit(new { state = "observed", dispatched = false, pid, hwnd = (long)hwnd,
            process_start_filetime = startTime, root_runtime_id = rootId, reference_runtime_id = diagnosticReferenceId,
            properties = new Dictionary<string, object?> { ["help_text"] = diagnosticProperty } });
        return;
    }
    if (command == "observe")
    {
        using var observationTimer = execution.Measure("native_observation_read");
        var limits = Required(arguments, "limits");
        int maxNodes = RequiredInt(limits, "max_nodes");
        int maxDepth = RequiredInt(limits, "max_depth");
        bool contentAllowed = RequiredString(arguments, "privacy") == "content_allowed";
        var entries = new List<object>();
        int entryBytes = 0;
        // A selected top-level window can host UIA descendants in another
        // process (for example, ApplicationFrameHost hosting Calculator).
        // Keep the exact window root as the traversal boundary.
        JsonElement? tree = arguments.TryGetProperty("tree", out var treeCursor) ? treeCursor : null;
        if (tree is not null)
        {
            long cursorAge = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - tree.Value.GetProperty("observed_at_ms").GetInt64();
            if (cursorAge < 0) throw new TreeCursorChanged("clock_invalid");
            if (cursorAge > 15_000) throw new TreeCursorChanged("cursor_expired");
        }
        bool truncated = false;
        // Return useful partial refs before the parent's hard worker timeout.
        // COM calls remain subject to the existing provider timeout; this
        // budget bounds traversal between calls, not an in-flight COM call.
        int maxBytes = limits.TryGetProperty("max_bytes", out var bytesLimit) ? bytesLimit.GetInt32() : 80_000;
        int maxMs = limits.TryGetProperty("max_ms", out var msLimit) ? msLimit.GetInt32() : 1800;
        int maxCalls = limits.TryGetProperty("max_provider_calls", out var callsLimit) ? callsLimit.GetInt32() : 5000;
        JsonElement? filter = limits.TryGetProperty("filter", out var filterValue) ? filterValue : null;
        int visited = 0, committedNodes = 0;
        string? budgetTrigger = null;
        var observationBudget = new ObservationBudget(maxMs, maxCalls);
        var queue = new TreePages(walker, lookupRoot, tree, observationBudget.RequireRemaining);
        bool truncatedByTime = false;
        while (queue.Count > 0)
        {
            if (observationBudget.Expired)
            {
                truncated = true;
                truncatedByTime = observationBudget.Trigger == "max_ms";
                break;
            }
            if (queue.Count > 256)
            {
                truncated = true;
                budgetTrigger = "tree_cursor_capacity";
                break;
            }
            if (visited >= maxNodes)
            {
                truncated = true;
                budgetTrigger = "max_nodes";
                break;
            }
            (AutomationElement element, int depth, int[][] treePath) node;
            try { node = queue.Peek(); }
            catch (ObservationBudgetExceeded) { truncated = true; truncatedByTime = observationBudget.Trigger == "max_ms"; break; }
            var (element, depth, treePath) = node;
            observationBudget.PropertyErrors.Clear();
            bool password = observationBudget.Read(() => PasswordProperty.Read(element), true);
            var runtimeId = observationBudget.Read(() => element.Properties.RuntimeId.Value, Array.Empty<int>());
            if (runtimeId.Length == 0) { truncated = true; break; }
            var rawAutomationId = observationBudget.Read(() => element.AutomationId, (string?)null);
            var observedAutomationId = BoundRunes(rawAutomationId ?? "", 256).Text;
            var controlType = observationBudget.Read(() => element.ControlType.ToString(), "Unknown");
            var screenBounds = observationBudget.Read(() => ReadScreenBounds(element), null);
            var enabled = observationBudget.Read(() => ProviderReads.Required("IsEnabled", () => element.IsEnabled), (bool?)null);
            var focusable = observationBudget.Read(() => ProviderReads.Required("IsKeyboardFocusable", () => element.Properties.IsKeyboardFocusable.Value), (bool?)null);
            var focused = observationBudget.Read(() => ProviderReads.Required("HasKeyboardFocus", () => element.Properties.HasKeyboardFocus.Value), (bool?)null);
            var offscreen = observationBudget.Read(() => ProviderReads.Required("IsOffscreen", () => element.IsOffscreen), (bool?)null);
            string? name = null;
            string? filterName = null;
            bool nameTruncated = false;
            bool nameReadError = false;
            if (contentAllowed && !password && !observationBudget.Expired)
            {
                try
                {
                    var rawName = observationBudget.Read(() => ProviderReads.Required("Name", () => element.Name), (string?)null);
                    filterName = rawName;
                    if (rawName is null) nameReadError = true;
                    else
                    {
                        var boundedName = BoundRunes(rawName, 128);
                        name = boundedName.Text;
                        nameTruncated = boundedName.Truncated;
                    }
                }
                catch (Exception) { nameReadError = true; }
            }
            // Retain identity, label and bounds before optional pattern scans.
            bool hasValue = observationBudget.Read(() => element.Patterns.Value.TryGetPattern(out _), false);
            bool hasText = observationBudget.Read(() => element.Patterns.Text.TryGetPattern(out _), false);
            bool hasInvoke = observationBudget.Read(() => element.Patterns.Invoke.TryGetPattern(out _), false);
            bool hasToggle = false;
            bool hasSelectionItem = false;
            bool hasExpandCollapse = false;
            bool hasScroll = false;
            bool hasVirtualizedItem = observationBudget.Read(
                () => element.Patterns.VirtualizedItem.TryGetPattern(out _), false);
            bool hasItemContainer = observationBudget.Read(
                () => element.Patterns.ItemContainer.TryGetPattern(out _), false);
            string? toggleState = null;
            bool? selected = null;
            string? expandCollapseState = null;
            bool? horizontallyScrollable = null;
            bool? verticallyScrollable = null;
            double? horizontalScrollPercent = null;
            double? verticalScrollPercent = null;
            bool expandCollapseReadError = false;
            bool scrollReadError = false;
            try
            {
                var togglePattern = observationBudget.Read(() =>
                    element.Patterns.Toggle.TryGetPattern(out var pattern) ? pattern : null, null);
                hasToggle = togglePattern is not null;
                if (contentAllowed && !password && hasToggle && togglePattern is not null)
                    toggleState = observationBudget.Read(() => ProviderReads.Required("ToggleState", () => togglePattern.ToggleState.Value).ToString(), null);
            }
            catch (Exception) { hasToggle = false; }
            try
            {
                var selectionPattern = observationBudget.Read(() =>
                    element.Patterns.SelectionItem.TryGetPattern(out var pattern) ? pattern : null, null);
                hasSelectionItem = selectionPattern is not null;
                if (contentAllowed && !password && hasSelectionItem && selectionPattern is not null)
                    selected = observationBudget.Read(() => ProviderReads.Required("IsSelected", () => selectionPattern.IsSelected.Value), (bool?)null);
            }
            catch (Exception) { hasSelectionItem = false; }
            try
            {
                var expandPattern = observationBudget.Read(() =>
                    element.Patterns.ExpandCollapse.TryGetPattern(out var pattern) ? pattern : null, null);
                hasExpandCollapse = expandPattern is not null;
                if (contentAllowed && !password && hasExpandCollapse && expandPattern is not null)
                    expandCollapseState = observationBudget.Read(() => ProviderReads.Required("ExpandCollapseState", () => expandPattern.ExpandCollapseState.Value).ToString(), null);
            }
            catch (Exception) { hasExpandCollapse = false; expandCollapseReadError = true; }
            try
            {
                var scrollPattern = observationBudget.Read(() =>
                    element.Patterns.Scroll.TryGetPattern(out var pattern) ? pattern : null, null);
                hasScroll = scrollPattern is not null;
                if (contentAllowed && !password && hasScroll && scrollPattern is not null)
                {
                    horizontallyScrollable = observationBudget.Read(() => ProviderReads.Required("HorizontallyScrollable", () => scrollPattern.HorizontallyScrollable.Value), (bool?)null);
                    verticallyScrollable = observationBudget.Read(() => ProviderReads.Required("VerticallyScrollable", () => scrollPattern.VerticallyScrollable.Value), (bool?)null);
                    horizontalScrollPercent = observationBudget.Read(() => ProviderReads.Required("HorizontalScrollPercent", () => scrollPattern.HorizontalScrollPercent.Value), (double?)null);
                    verticalScrollPercent = observationBudget.Read(() => ProviderReads.Required("VerticalScrollPercent", () => scrollPattern.VerticalScrollPercent.Value), (double?)null);
                }
            }
            catch (Exception) { hasScroll = false; scrollReadError = true; }
            string? value = null;
            string? valueSha256 = null;
            bool valueTruncated = false;
            bool valueReadError = false;
            if (contentAllowed && !password && hasValue)
            {
                try
                {
                    var valuePattern = observationBudget.Read(() =>
                        element.Patterns.Value.TryGetPattern(out var pattern) ? pattern : null, null);
                    if (valuePattern is not null && !observationBudget.Expired)
                    {
                        var rawValue = observationBudget.Read(() => ProviderReads.Required("Value", () => valuePattern.Value.Value), (string?)null);
                        if (rawValue is null) valueReadError = true;
                        else
                        {
                            var boundedValue = BoundRunes(rawValue, 256);
                            if (rawValue.Length <= 1_048_576)
                                valueSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawValue))).ToLowerInvariant();
                            value = boundedValue.Text;
                            valueTruncated = boundedValue.Truncated;
                        }
                    }
                }
                catch (Exception)
                {
                    valueReadError = true;
                }
            }
            var entry = new {
                depth, tree_path = treePath,
                runtime_id = runtimeId, automation_id = observedAutomationId, control_type = controlType,
                enabled, focusable, focused, offscreen,
                bounding_rect_screen = screenBounds,
                clickable_point_screen = observationBudget.Read(() => ReadClickablePoint(element), null),
                properties_incomplete = observationBudget.PropertiesIncomplete,
                property_errors = observationBudget.PropertyErrors.ToArray(),
                password_read_error = observationBudget.PropertyErrors.Contains("IsPassword"),
                password, value_supported = hasValue && !password, value_sha256 = valueSha256,
                text_supported = hasText && !password,
                invoke_supported = hasInvoke, toggle_supported = hasToggle && !password,
                toggle_state = toggleState,
                selection_item_supported = hasSelectionItem && !password,
                selected, expand_collapse_supported = hasExpandCollapse && !password,
                expand_collapse_state = expandCollapseState,
                expand_collapse_read_error = expandCollapseReadError,
                scroll_supported = hasScroll && !password,
                horizontally_scrollable = horizontallyScrollable,
                vertically_scrollable = verticallyScrollable,
                horizontal_scroll_percent = horizontalScrollPercent,
                vertical_scroll_percent = verticalScrollPercent,
                scroll_read_error = scrollReadError,
                virtualized_item_supported = hasVirtualizedItem,
                item_container_supported = hasItemContainer,
                name, value,
                name_truncated = nameTruncated, name_read_error = nameReadError,
                value_truncated = valueTruncated, value_read_error = valueReadError,
            };
            bool matched = MatchesObservationFilter(filter, rawAutomationId ?? "", controlType, password ? null : filterName);
            visited++;
            if (!matched)
            {
                try { truncated |= queue.Commit(element, maxDepth); committedNodes++; }
                catch (ObservationBudgetExceeded) { truncated = true; truncatedByTime = observationBudget.Trigger == "max_ms"; break; }
                continue;
            }
            int encodedBytes = JsonSerializer.SerializeToUtf8Bytes(entry).Length + 1;
            if (entryBytes + encodedBytes > maxBytes)
            {
                truncated = true;
                budgetTrigger = "max_bytes";
                break;
            }
            try { truncated |= queue.Commit(element, maxDepth); committedNodes++; }
            catch (ObservationBudgetExceeded) { truncated = true; truncatedByTime = observationBudget.Trigger == "max_ms"; break; }
            entries.Add(entry);
            entryBytes += encodedBytes;
        }
        if (arguments.TryGetProperty("local", out var checkedLocal))
        {
            var checkedScope = execution.Time("native_local_resolve", () => LocalScope.Resolve(walker, root, checkedLocal, FindExact));
            if (checkedScope is null || !checkedScope.Properties.RuntimeId.Value.SequenceEqual(lookupRoot.Properties.RuntimeId.Value))
            {
                Emit(new { state = "rejected", reason = "local_item_scope_changed", dispatched = false });
                return;
            }
        }
        Emit(new { state = "observed", pid, hwnd = (long)hwnd,
            process_start_filetime = startTime, root_runtime_id = rootId,
            scope_runtime_id = queue.Scope[^1],
            observed_at_ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            coordinate_space = "physical_screen_pixels",
            dpi_awareness = "per_monitor_v2",
            entries, truncated, truncated_by_time = truncatedByTime,
            tree_next = committedNodes > 0 && queue.Count is > 0 and <= 256 ? queue.Cursor(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) : null,
            new_observation_required = queue.Count > 256 || queue.Count > 0 && committedNodes == 0,
            recovery_hint = queue.Count > 256 ? "observe_narrower_root_or_depth"
                : queue.Count > 0 && committedNodes == 0 ? "observe_with_larger_budget_or_narrower_scope" : null,
            observation_budget_ms = observationBudget.Milliseconds,
            provider_calls = observationBudget.Calls, visited_nodes = visited,
            retained_bytes = entryBytes, budget_trigger = budgetTrigger ?? observationBudget.Trigger,
            window_enabled = Native.IsWindowEnabled(hwnd),
            dispatched = false });
        return;
    }
    execution.Stage = "uia_preflight";
    var observation = Required(arguments, "observation");
    var observedAt = RequiredLong(observation, "observed_at_ms");
    long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - observedAt;
    long maxAge = command == "read_text" ? 300_000 : 15_000;
    if (age < 0 || age > maxAge || !rootId.SequenceEqual(IntArray(Required(observation, "root_runtime_id"))))
    {
        Emit(new { state = "rejected", reason = "observation_stale", dispatched = false });
        return;
    }
    if (command != "read_text" && !Native.IsWindowEnabled(hwnd))
    {
        Emit(new { state = "rejected", reason = "window_disabled", dispatched = false });
        return;
    }
    if (command is "invoke" or "focus" or "guarded_input" && (Native.IsIconic(hwnd) || !Native.IsForegroundRoot(hwnd)))
    {
        Emit(new { state = "rejected", reason = "foreground_required", dispatched = false });
        return;
    }
    var reference = Required(arguments, "reference");
    var referenceId = IntArray(Required(reference, "runtime_id"));
    var automationId = RequiredString(reference, "automation_id");
    if (!referenceId.SequenceEqual(IntArray(Required(observation, "reference_runtime_id"))))
    {
        Emit(new { state = "rejected", reason = "reference_changed", dispatched = false });
        return;
    }
    var control = execution.Time("native_control_lookup", () => FindCurrent(referenceId, automationId));
    bool transitionRequest = command == "invoke" && arguments.TryGetProperty("transition", out _);
    if (control is null || command != "read_text" && !transitionRequest && !ProviderReads.Required("IsEnabled", () => control.IsEnabled) || PasswordProperty.Read(control))
    {
        Emit(new { state = "rejected", reason = localScopeChanged ? "local_item_scope_changed" : "control_unavailable", dispatched = false });
        return;
    }
    if (arguments.TryGetProperty("execution_mode", out var executionMode))
    {
        if (executionMode.GetString() != "must_background" || command is not
            ("set_value" or "set_toggle" or "select_item" or "expand_collapse")) throw new ArgumentException();
        var framework = ProviderReads.Required("FrameworkId", () => control.Properties.FrameworkId.Value) ?? "";
        var className = ProviderReads.Required("ClassName", () => control.Properties.ClassName.Value) ?? "";
        if (!BackgroundPatterns.Supports(command, framework, className))
        {
            Emit(new { state = "rejected", reason = "background_provider_unsupported", dispatched = false,
                background_capable = false, foreground_requested = false });
            return;
        }
    }
    // Recheck exact identity and foreground immediately before the provider call.
    if (!Native.IsWindow(hwnd) || command != "read_text" && !Native.IsWindowEnabled(hwnd)
        || (command is "invoke" or "focus" or "guarded_input" && (Native.IsIconic(hwnd) || !Native.IsForegroundRoot(hwnd)))
        || Native.GetWindowThreadProcessId(hwnd, out actualPid) == 0 || actualPid != pid
        || !TreePages.ReadRuntimeId(() => root.Properties.RuntimeId.Value).SequenceEqual(rootId))
    {
        Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
        return;
    }
    if (command == "read_text")
    {
        execution.Pattern = "Text";
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasTextPattern = control.Patterns.Text.TryGetPattern(out var textPattern);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasTextPattern || textPattern is null)
        {
            Emit(new { state = "rejected", dispatched = false, reason = "text_pattern_unavailable" });
            return;
        }
        // Return bounded pages, not the tree's short Value preview. Never use
        // GetText(-1): provider work and protocol output both stay bounded.
        const int documentLimit = TextPages.DocumentLimit;
        var embedded = textPattern.DocumentRange.GetChildren();
        if (!EmbeddedTextPrivacyAllowed(embedded, out var unknownEmbedded))
        {
            Emit(new { state = "rejected", dispatched = false, reason = "text_embedded_privacy_unavailable",
                embedded_password_unknown_count = unknownEmbedded });
            return;
        }
        var text = textPattern.DocumentRange.GetText(documentLimit + 1);
        var options = Required(arguments, "text");
        var page = TextPages.Read(text, options);
        if (!Equals(page["state"], "observed"))
        {
            Emit(page);
            return;
        }
        // Detect edits during provider reading, and rebind before content leaves.
        var current = FindCurrent(referenceId, automationId);
        if (current is null || PasswordProperty.Read(current)
            || !current.Patterns.Text.TryGetPattern(out var currentText) || currentText is null
            || !EmbeddedTextPrivacyAllowed(currentText.DocumentRange.GetChildren(), out unknownEmbedded)
            || currentText.DocumentRange.GetText(documentLimit + 1) != text
            || !Native.IsWindow(hwnd) || !TreePages.ReadRuntimeId(() => root.Properties.RuntimeId.Value).SequenceEqual(rootId))
        {
            Emit(new { state = "rejected", dispatched = false, reason = "text_changed_during_read",
                requires_new_observation = true, embedded_password_unknown_count = unknownEmbedded });
            return;
        }
        page["source"] = "TextPattern.DocumentRange";
        page["embedded_password_check"] = "known_password_range_children";
        page["embedded_password_unknown_count"] = unknownEmbedded;
        page["pid"] = pid;
        page["hwnd"] = (long)hwnd;
        page["process_start_filetime"] = startTime;
        page["root_runtime_id"] = rootId;
        page["reference_runtime_id"] = referenceId;
        page["observed_at_ms"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        Emit(page);
        return;
    }
    bool VisibleForInput(AutomationElement element) => ProviderReads.VisibleForInput(
        () => element.Properties.IsOffscreen.Value, () => Native.IsWindow(hwnd) && Native.IsWindowVisible(hwnd),
        () => ReadScreenBounds(element), () => ReadScreenBounds(root));
    if (command is "focus" or "guarded_input")
    {
        if (!ProviderReads.Required("IsKeyboardFocusable", () => control.Properties.IsKeyboardFocusable.Value) || !VisibleForInput(control))
        {
            Emit(new { state = "rejected", reason = "target_not_focusable", dispatched = false });
            return;
        }
        if (!WaitForGo()) return;
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (!StillInteractive(hwnd, pid, root, rootId, true) || control is null
            || !ProviderReads.Required("IsKeyboardFocusable", () => control.Properties.IsKeyboardFocusable.Value) || !VisibleForInput(control))
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        bool dispatched = false;
        if (!ProviderReads.Required("HasKeyboardFocus", () => control.Properties.HasKeyboardFocus.Value))
        {
            AppCheckpoint.Record(AppCheckpointStage.business_enter);
            execution.BeginWrite();
            execution.Time("native_pattern_call", () => control.Focus());
            dispatched = true;
        }
        execution.Stage = "uia_readback";
        var after = RebindCurrent(referenceId, automationId);
        bool matched = StillInteractive(hwnd, pid, root, rootId, true) && after is not null
            && ProviderReads.Required("IsKeyboardFocusable", () => after.Properties.IsKeyboardFocusable.Value)
            && VisibleForInput(after) && ProviderReads.Required("HasKeyboardFocus", () => after.Properties.HasKeyboardFocus.Value);
        if (command == "guarded_input" && matched)
        {
            // Only the High broker emits input. Keep this exact UIA root and
            // ref alive while it requests one focus check per short batch.
            Console.WriteLine("{\"phase\":\"guarded_focus_ready\"}");
            while (true)
            {
                string? next = Console.ReadLine();
                if (next == "finish_input")
                {
                    Emit(new { state = "not_verified", dispatched = true,
                        verification = "business_postcondition_required" });
                    return;
                }
                if (next != "check_input")
                {
                    Emit(new { state = "outcome_uncertain", dispatched = execution.WriteStarted,
                        reason = "guarded_input_interrupted" });
                    return;
                }
                var fresh = RebindCurrent(referenceId, automationId);
                if (!StillInteractive(hwnd, pid, root, rootId, true) || fresh is null
                    || !VisibleForInput(fresh) || !ProviderReads.Required("IsKeyboardFocusable", () => fresh.Properties.IsKeyboardFocusable.Value)
                    || !ProviderReads.Required("HasKeyboardFocus", () => fresh.Properties.HasKeyboardFocus.Value))
                {
                    Emit(new { state = "rejected", dispatched = execution.WriteStarted,
                        reason = "guarded_input_focus_changed" });
                    return;
                }
                Console.WriteLine("{\"phase\":\"guarded_focus_checked\",\"focused\":true}");
            }
        }
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            verification = "exact_control_focus_readback", reference_runtime_id = referenceId,
            focus_ready = matched, input_dispatched = false,
            requires_guarded_input_executor = command == "guarded_input" });
        return;
    }
    if (command == "set_value")
    {
        execution.Pattern = "Value";
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasValuePattern = control.Patterns.Value.TryGetPattern(out var pattern);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasValuePattern || pattern is null)
        {
            Emit(new { state = "rejected", reason = "value_pattern_unavailable", dispatched = false });
            return;
        }
        string value = RequiredString(arguments, "value");
        if (!WaitForGo())
            return;
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (control is null || !control.Patterns.Value.TryGetPattern(out pattern)
            || pattern is null)
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        var foregroundBeforeProvider = Native.GetForegroundWindow();
        bool backgroundValue = arguments.TryGetProperty("execution_mode", out _);
        nint backgroundEdit = nint.Zero;
        if (backgroundValue)
        {
            if (ProviderReads.Required("Value.IsReadOnly", () => pattern.IsReadOnly.Value))
            {
                Emit(new { state = "rejected", reason = "control_read_only", dispatched = false });
                return;
            }
            backgroundEdit = (nint)ProviderReads.Required("NativeWindowHandle", () => control.Properties.NativeWindowHandle.Value);
            BackgroundPatterns.RequireEdit(hwnd, backgroundEdit, pid);
        }
        nint richEdit = nint.Zero;
        if (!backgroundValue)
        {
            // Some providers expose no HWND; retain their existing Value path.
            nint candidate;
            try { candidate = (nint)control.Properties.NativeWindowHandle.Value; }
            catch (FlaUI.Core.Exceptions.PropertyNotSupportedException) { candidate = nint.Zero; }
            if (BackgroundPatterns.IsNativeRichEdit(candidate))
            {
                if (value.Contains('\0'))
                {
                    Emit(new { state = "rejected", reason = "invalid_value", dispatched = false });
                    return;
                }
                if (ProviderReads.Required("Value.IsReadOnly", () => pattern.IsReadOnly.Value))
                {
                    Emit(new { state = "rejected", reason = "control_read_only", dispatched = false });
                    return;
                }
                if (!StillInteractive(hwnd, pid, root, rootId, true))
                {
                    Emit(new { state = "rejected", reason = "foreground_required", dispatched = false });
                    return;
                }
                BackgroundPatterns.RequireRichEdit(hwnd, candidate, pid, ReadScreenBounds(control));
                richEdit = candidate;
            }
        }
        if (arguments.TryGetProperty("expected_value_hash", out var expectedValueHash))
        {
            string? currentValue = ProviderReads.Required("Value", () => pattern.Value.Value);
            if (currentValue is null || currentValue.Length > 1_048_576 || Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(currentValue))).ToLowerInvariant() != expectedValueHash.GetString())
            {
                Emit(new { state = "rejected", reason = "target_content_changed", dispatched = false, requires_new_observation = true });
                return;
            }
        }
        AppCheckpoint.Record(AppCheckpointStage.business_enter);
        execution.BeginWrite();
        execution.Time("native_pattern_call", () => {
            if (backgroundValue) BackgroundPatterns.SetValue(backgroundEdit, value);
            else if (richEdit != nint.Zero) BackgroundPatterns.ReplaceRichEdit(richEdit, value, () => {
                var fresh = RebindCurrent(referenceId, automationId);
                if (fresh is null || !StillInteractive(hwnd, pid, root, rootId, true)
                    || (nint)ProviderReads.Required("NativeWindowHandle", () => fresh.Properties.NativeWindowHandle.Value) != richEdit
                    || !fresh.Patterns.Value.TryGetPattern(out var freshPattern) || freshPattern is null
                    || ProviderReads.Required("Value.IsReadOnly", () => freshPattern.IsReadOnly.Value))
                    throw new ArgumentException("rich_edit_target_changed");
                BackgroundPatterns.RequireRichEdit(hwnd, richEdit, pid, ReadScreenBounds(fresh));
            });
            else pattern.SetValue(value);
        });
        execution.Stage = "uia_readback";
        using var readbackTimer = execution.Measure("native_internal_readback");
        var foregroundAfterProvider = Native.GetForegroundWindow();
        var after = FindCurrent(referenceId, automationId);
        bool sameTarget = Native.IsWindow(hwnd) && !Native.IsIconic(hwnd)
            && after is not null;
        string? readback = sameTarget && after!.Patterns.Value.TryGetPattern(out var afterPattern)
            && afterPattern is not null ? ProviderReads.Required("Value", () => afterPattern.Value.Value) : null;
        bool matched = readback is not null && TextValueComparison.Matches(value, readback);
        var foregroundAfterReadback = Native.GetForegroundWindow();
        Emit(new { state = matched ? "verified" : "not_verified", dispatched = true,
            verification = TextValueComparison.Verification(value, readback, matched),
            business_outcome_verified = false,
            value_comparison = !matched ? "not_matched" : readback != value ? "line_endings_normalized" : "exact",
            foreground_diagnostic = new {
                foreground_before_provider = (long)foregroundBeforeProvider,
                foreground_after_provider = (long)foregroundAfterProvider,
                foreground_after_readback = (long)foregroundAfterReadback,
                provider_changed_foreground = foregroundBeforeProvider != foregroundAfterProvider,
                readback_changed_foreground = foregroundAfterProvider != foregroundAfterReadback
            }});
        return;
    }
    if (command == "set_toggle")
    {
        execution.Pattern = "Toggle";
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasTogglePattern = control.Patterns.Toggle.TryGetPattern(out var pattern);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasTogglePattern || pattern is null)
        {
            Emit(new { state = "rejected", reason = "toggle_pattern_unavailable", dispatched = false });
            return;
        }
        bool desired = Required(arguments, "desired").GetBoolean();
        if (!WaitForGo())
            return;
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (control is null || !control.Patterns.Toggle.TryGetPattern(out pattern)
            || pattern is null)
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        bool dispatched = false;
        var desiredState = desired ? ToggleState.On : ToggleState.Off;
        if (ProviderReads.Required("ToggleState", () => pattern.ToggleState.Value) != desiredState)
        {
            AppCheckpoint.Record(AppCheckpointStage.business_enter);
            execution.BeginWrite();
            execution.Time("native_pattern_call", () => pattern.Toggle());
            dispatched = true;
        }
        execution.Stage = "uia_readback";
        using var readbackTimer = execution.Measure("native_internal_readback");
        var after = FindCurrent(referenceId, automationId);
        bool matched = after is not null && after.Patterns.Toggle.TryGetPattern(out var afterPattern)
            && afterPattern is not null && ProviderReads.Required("ToggleState", () => afterPattern.ToggleState.Value) == desiredState;
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            verification = "exact_control_toggle_readback", business_outcome_verified = false });
        return;
    }
    if (command == "select_item")
    {
        execution.Pattern = "SelectionItem";
        bool desired = !arguments.TryGetProperty("desired", out var selectionDesired) || selectionDesired.GetBoolean();
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasSelectionItemPattern = control.Patterns.SelectionItem.TryGetPattern(out var pattern);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasSelectionItemPattern || pattern is null)
        {
            Emit(new { state = "rejected", reason = "selection_item_pattern_unavailable", dispatched = false });
            return;
        }
        if (!WaitForGo())
            return;
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (control is null || !control.Patterns.SelectionItem.TryGetPattern(out pattern)
            || pattern is null)
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        bool dispatched = false;
        if (ProviderReads.Required("IsSelected", () => pattern.IsSelected.Value) != desired)
        {
            AppCheckpoint.Record(AppCheckpointStage.business_enter);
            execution.BeginWrite();
            execution.Time("native_pattern_call", () => {
                if (desired) pattern.Select();
                else pattern.RemoveFromSelection();
            });
            dispatched = true;
        }
        execution.Stage = "uia_readback";
        bool matched = execution.Time("native_internal_readback", () =>
        {
            var after = FindCurrent(referenceId, automationId);
            return after is not null && after.Patterns.SelectionItem.TryGetPattern(out var afterPattern)
                && afterPattern is not null && ProviderReads.Required("IsSelected", () => afterPattern.IsSelected.Value) == desired;
        });
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            verification = "exact_control_selection_readback", business_outcome_verified = false });
        return;
    }
    if (command == "expand_collapse")
    {
        execution.Pattern = "ExpandCollapse";
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasExpandCollapsePattern = control.Patterns.ExpandCollapse.TryGetPattern(out var pattern);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasExpandCollapsePattern || pattern is null)
        {
            Emit(new { state = "rejected", reason = "expand_collapse_pattern_unavailable", dispatched = false });
            return;
        }
        string desired = RequiredString(arguments, "desired");
        if (desired is not ("Expanded" or "Collapsed"))
        {
            Emit(new { state = "rejected", reason = "invalid_expand_collapse_state", dispatched = false });
            return;
        }
        if (!WaitForGo())
            return;
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        var currentControl = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke") || currentControl is null
            || !currentControl.Patterns.ExpandCollapse.TryGetPattern(out pattern)
            || pattern is null)
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        bool dispatched = false;
        ExpandCollapseState beforeState;
        try { beforeState = ProviderReads.Required("ExpandCollapseState", () => pattern.ExpandCollapseState.Value); }
        catch (Exception error)
        {
            Emit(execution.WithTimings(ProviderReads.Rejection(error, "expand_collapse_state_unavailable", execution.Stage, execution.Pattern)));
            return;
        }
        if (desired == "Expanded" && beforeState != ExpandCollapseState.Expanded)
        {
            AppCheckpoint.Record(AppCheckpointStage.business_enter);
            execution.BeginWrite();
            execution.Time("native_pattern_call", () => pattern.Expand());
            dispatched = true;
        }
        else if (desired == "Collapsed" && beforeState != ExpandCollapseState.Collapsed)
        {
            AppCheckpoint.Record(AppCheckpointStage.business_enter);
            execution.BeginWrite();
            execution.Time("native_pattern_call", () => pattern.Collapse());
            dispatched = true;
        }
        execution.Stage = "uia_readback";
        using var readbackTimer = execution.Measure("native_internal_readback");
        var after = FindCurrent(referenceId, automationId);
        string? observedState = null;
        if (after is not null && after.Patterns.ExpandCollapse.TryGetPattern(out var afterPattern)
            && afterPattern is not null)
            observedState = ProviderReads.Required("ExpandCollapseState", () => afterPattern.ExpandCollapseState.Value).ToString();
        bool matched = observedState == desired;
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            expand_collapse_state = observedState,
            verification = "exact_control_expand_collapse_readback" });
        return;
    }
    if (command == "scroll")
    {
        execution.Pattern = "Scroll";
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasScrollPattern = control.Patterns.Scroll.TryGetPattern(out var pattern);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasScrollPattern || pattern is null)
        {
            Emit(new { state = "rejected", reason = "scroll_pattern_unavailable", dispatched = false });
            return;
        }
        string direction = RequiredString(arguments, "direction");
        string amount = RequiredString(arguments, "amount");
        if (direction is not ("up" or "down" or "left" or "right")
            || amount is not ("small" or "large"))
        {
            Emit(new { state = "rejected", reason = "invalid_scroll_request", dispatched = false });
            return;
        }
        bool vertical = direction is "up" or "down";
        bool scrollable;
        try { scrollable = vertical ? ProviderReads.Required("VerticallyScrollable", () => pattern.VerticallyScrollable.Value) : ProviderReads.Required("HorizontallyScrollable", () => pattern.HorizontallyScrollable.Value); }
        catch (Exception error)
        {
            Emit(execution.WithTimings(ProviderReads.Rejection(error, "scroll_axis_state_unavailable", execution.Stage, execution.Pattern)));
            return;
        }
        if (!scrollable)
        {
            Emit(new { state = "rejected", reason = "scroll_axis_unavailable", dispatched = false });
            return;
        }
        if (!WaitForGo())
            return;
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        var currentControl = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (currentControl is null
            || !currentControl.Patterns.Scroll.TryGetPattern(out pattern) || pattern is null)
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        try { scrollable = vertical ? ProviderReads.Required("VerticallyScrollable", () => pattern.VerticallyScrollable.Value) : ProviderReads.Required("HorizontallyScrollable", () => pattern.HorizontallyScrollable.Value); }
        catch (Exception error)
        {
            Emit(execution.WithTimings(ProviderReads.Rejection(error, "scroll_axis_state_unavailable", execution.Stage, execution.Pattern)));
            return;
        }
        if (!scrollable)
        {
            Emit(new { state = "rejected", reason = "scroll_axis_unavailable", dispatched = false });
            return;
        }
        var increment = amount == "small" ? ScrollAmount.SmallIncrement : ScrollAmount.LargeIncrement;
        var decrement = amount == "small" ? ScrollAmount.SmallDecrement : ScrollAmount.LargeDecrement;
        var horizontalAmount = direction == "left" ? decrement
            : direction == "right" ? increment : ScrollAmount.NoAmount;
        var verticalAmount = direction == "up" ? decrement
            : direction == "down" ? increment : ScrollAmount.NoAmount;
        AppCheckpoint.Record(AppCheckpointStage.business_enter);
        execution.BeginWrite();
        execution.Time("native_pattern_call", () => pattern.Scroll(horizontalAmount, verticalAmount));
        execution.Stage = "uia_readback";
        using var readbackTimer = execution.Measure("native_internal_readback");
        var after = FindCurrent(referenceId, automationId);
        bool readBack = false;
        double? horizontalPercent = null;
        double? verticalPercent = null;
        if (after is not null && after.Patterns.Scroll.TryGetPattern(out var afterPattern)
            && afterPattern is not null)
        {
            horizontalPercent = ProviderReads.Required("HorizontalScrollPercent", () => afterPattern.HorizontalScrollPercent.Value);
            verticalPercent = ProviderReads.Required("VerticalScrollPercent", () => afterPattern.VerticalScrollPercent.Value);
            readBack = true;
        }
        Emit(new { state = readBack ? "verified" : "not_verified", dispatched = true,
            horizontal_scroll_percent = horizontalPercent,
            vertical_scroll_percent = verticalPercent,
            verification = "exact_control_scroll_readback" });
        return;
    }
    if (command == "realize_item")
    {
        execution.Pattern = "ItemContainer";
        if (arguments.TryGetProperty("local", out var previousLocal)
            && previousLocal.GetProperty("anchors").GetArrayLength() >= 8)
        {
            Emit(new { state = "rejected", reason = "local_item_scope_limit", dispatched = false });
            return;
        }
        AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
        bool hasItemContainerPattern = control.Patterns.ItemContainer.TryGetPattern(out var container);
        AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
        if (!hasItemContainerPattern
            || container is null)
        {
            Emit(new { state = "rejected", reason = "item_container_unavailable", dispatched = false });
            return;
        }
        string itemName = RequiredString(arguments, "item_name");
        if (!WaitForGo())
            return;
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (control is null || !control.Patterns.ItemContainer.TryGetPattern(out container)
            || container is null)
        {
            Emit(new { state = "rejected", reason = "item_container_changed", dispatched = false });
            return;
        }
        // UIA virtualized items are absent from normal tree traversal. Search
        // one exact name in the observed container; reject duplicate names.
        // The disposable worker bounds a provider that blocks this lookup.
        AutomationElement? item;
        AutomationElement? duplicate;
        try
        {
            var nameProperty = control.FrameworkAutomationElement.PropertyIdLibrary.Name;
            item = container.FindItemByProperty(null, nameProperty, itemName);
            duplicate = item is null ? null
                : container.FindItemByProperty(item, nameProperty, itemName);
        }
        catch (Exception)
        {
            Emit(new { state = "rejected", reason = "virtual_item_lookup_failed", dispatched = false });
            return;
        }
        if (item is null || duplicate is not null)
        {
            Emit(new { state = "rejected",
                reason = item is null ? "virtual_item_missing" : "virtual_item_ambiguous",
                dispatched = false });
            return;
        }
        if (PasswordProperty.Read(item))
        {
            Emit(new { state = "rejected", reason = "control_unavailable", dispatched = false });
            return;
        }
        if (!item.Patterns.VirtualizedItem.TryGetPattern(out var virtualized)
            || virtualized is null)
        {
            Emit(new { state = "rejected", reason = "virtualized_item_pattern_unavailable",
                dispatched = false });
            return;
        }
        if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        AppCheckpoint.Record(AppCheckpointStage.business_enter);
        execution.BeginWrite();
        execution.Time("native_pattern_call", () => virtualized.Realize());
        using var readbackTimer = execution.Measure("native_internal_readback");
        if (!StillInteractive(hwnd, pid, root, rootId, false)
            || !LocalScope.BelongsTo(walker, item, control) || item.Name != itemName
            || PasswordProperty.Read(item))
        {
            Emit(new { state = "not_verified", dispatched = true,
                reason = "realized_item_scope_unavailable", verification = "fresh_observation_required" });
            return;
        }
        Emit(new { state = "not_verified", dispatched = true,
            realized_item = new { container_runtime_id = referenceId,
                container_automation_id = automationId, item_runtime_id = item.Properties.RuntimeId.Value,
                item_name = itemName },
            observed_at_ms = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            verification = "fresh_observation_required" });
        return;
    }
    AppCheckpoint.Record(AppCheckpointStage.pattern_enter);
    execution.Pattern = "Invoke";
    bool hasInvokePattern = control.Patterns.Invoke.TryGetPattern(out var invoke);
    AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
    if ((!hasInvokePattern || invoke is null) && !transitionRequest)
    {
        Emit(new { state = "rejected", reason = "invoke_pattern_unavailable", dispatched = false });
        return;
    }
    if (!WaitForGo())
        return;
    if (!StillInteractive(hwnd, pid, root, rootId, command == "invoke"))
    {
        Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
        return;
    }
    control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId, transitionRequest));
    bool readyToInvoke = control is not null && ProviderReads.Required("IsEnabled", () => control.IsEnabled)
        && control.Patterns.Invoke.TryGetPattern(out invoke) && invoke is not null;
    if (!readyToInvoke && !transitionRequest)
    {
        Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
        return;
    }
    if (arguments.TryGetProperty("transition", out var transition))
    {
        var conditions = Flower.App.TransitionGate.Parse(transition);
        // Complete bounded subtree lookups before the final property reads.
        // Never do a second tree scan after testing the business precondition.
        var conditionControls = conditions.Select(condition => FindCurrent(condition.RuntimeId, condition.AutomationId)).ToArray();
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId, true));
        if (control is null || !StillInteractive(hwnd, pid, root, rootId, true))
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        readyToInvoke = ProviderReads.Required("IsEnabled", () => control.IsEnabled)
            && control.Patterns.Invoke.TryGetPattern(out invoke) && invoke is not null;
        object? ReadCondition(Flower.App.TransitionCondition condition)
        {
            var current = conditionControls[ReferenceEquals(condition, conditions[0]) ? 0 : 1];
            if (current is null || PasswordProperty.Read(current)
                || !TreePages.ReadRuntimeId(() => current.Properties.RuntimeId.Value).SequenceEqual(condition.RuntimeId)
                || !ProviderReads.MatchesAutomationId(condition.AutomationId, () => current.AutomationId))
                throw new ArgumentException();
            return condition.Field switch
            {
                "name" => ProviderReads.Required("Name", () => current.Properties.Name.Value),
                "focused" => ProviderReads.Required("HasKeyboardFocus", () => current.Properties.HasKeyboardFocus.Value),
                "value" when current.Patterns.Value.TryGetPattern(out var valuePattern) && valuePattern is not null
                    => ProviderReads.Required("Value", () => valuePattern.Value.Value),
                "selected" when current.Patterns.SelectionItem.TryGetPattern(out var selectedPattern) && selectedPattern is not null
                    => ProviderReads.Required("IsSelected", () => selectedPattern.IsSelected.Value),
                "toggle_state" when current.Patterns.Toggle.TryGetPattern(out var togglePattern) && togglePattern is not null
                    => ProviderReads.Required("ToggleState", () => togglePattern.ToggleState.Value).ToString(),
                "expand_collapse_state" when current.Patterns.ExpandCollapse.TryGetPattern(out var expandPattern) && expandPattern is not null
                    => ProviderReads.Required("ExpandCollapseState", () => expandPattern.ExpandCollapseState.Value).ToString(),
                _ => throw new ArgumentException()
            };
        }
        var decision = execution.Time("native_transition_preflight", () =>
            Flower.App.TransitionGate.Check(conditions, ReadCondition));
        // Property reads may block. Check time and Win32 identity/foreground
        // again, with no host round trip or UIA tree search before Invoke.
        long transitionAge = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - observedAt;
        if (transitionAge is < 0 or > 15_000 || !Native.IsWindow(hwnd) || !Native.IsWindowEnabled(hwnd)
            || Native.IsIconic(hwnd) || !Native.IsForegroundRoot(hwnd)
            || Native.GetWindowThreadProcessId(hwnd, out actualPid) == 0 || actualPid != pid)
        {
            Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
            return;
        }
        if (decision is not null)
        {
            Emit(new { state = decision == "already_satisfied" ? "verified" : "rejected",
                reason = decision, dispatched = false });
            return;
        }
        if (!readyToInvoke)
        {
            Emit(new { state = "rejected", reason = "invoke_control_unavailable", dispatched = false });
            return;
        }
    }
    AppCheckpoint.Record(AppCheckpointStage.business_enter);
    execution.BeginWrite();
    execution.Time("native_pattern_call", () => invoke!.Invoke());
    Emit(new { state = "not_verified", dispatched = true,
        verification = "business_postcondition_required" });
}

static bool StillInteractive(nint hwnd, int pid, AutomationElement root, int[] rootId, bool needsForeground) =>
    Native.IsWindow(hwnd) && Native.IsWindowEnabled(hwnd)
    && (!needsForeground || (!Native.IsIconic(hwnd) && Native.IsForegroundRoot(hwnd)))
    && Native.GetWindowThreadProcessId(hwnd, out var actualPid) != 0 && actualPid == pid
    && TreePages.ReadRuntimeId(() => root.Properties.RuntimeId.Value).SequenceEqual(rootId);

static bool WaitForGo()
{
    AppCheckpoint.Record(AppCheckpointStage.ready);
    Emit(new { phase = "ready" });
    Console.Out.Flush();
    return Console.ReadLine() == "go";
}

static AutomationElement? FindExact(ITreeWalker walker, AutomationElement root,
                                    int[] runtimeId, string automationId)
{
    return AppCheckpoint.Measure(AppCheckpointStage.exact_lookup_enter,
        AppCheckpointStage.exact_lookup_exit, () =>
    {
        // Rebind only within the currently selected window's UIA subtree.
        bool Matches(AutomationElement element) => TreePages.ReadRuntimeId(() => element.Properties.RuntimeId.Value).SequenceEqual(runtimeId)
            && ProviderReads.MatchesAutomationId(automationId, () => element.AutomationId);
        if (Matches(root))
            return root;
        var queue = new Queue<(AutomationElement Element, int Depth)>();
        queue.Enqueue((root, 0));
        int admitted = 1;
        while (queue.Count > 0 && admitted < 192)
        {
            var (element, depth) = queue.Dequeue();
            if (depth < 8)
            {
                var child = walker.GetFirstChild(element);
                while (child is not null && admitted < 192)
                {
                    // Test each admitted node before fetching its later siblings.
                    // Already checked queue entries only need their descendants.
                    admitted++;
                    if (Matches(child))
                        return child;
                    queue.Enqueue((child, depth + 1));
                    if (admitted == 192)
                        break;
                    child = walker.GetNextSibling(child);
                }
            }
        }
        return null;
    });
}

static void Validate(string command, JsonElement arguments)
{
    if (arguments.TryGetProperty("transition", out var transition))
    {
        if (command != "invoke") throw new ArgumentException();
        _ = Flower.App.TransitionGate.Parse(transition);
    }
    if (arguments.TryGetProperty("expected_value_hash", out var valueHash)
        && (command != "set_value" || valueHash.GetString() is not { } hash
            || !System.Text.RegularExpressions.Regex.IsMatch(hash, "^[a-f0-9]{64}$"))) throw new ArgumentException();
    if (arguments.TryGetProperty("execution_mode", out var executionMode)
        && (executionMode.GetString() != "must_background" || command is not
            ("set_value" or "set_toggle" or "select_item" or "expand_collapse"))) throw new ArgumentException();
    if (command is not ("observe" or "set_value" or "invoke" or "focus" or "guarded_input" or "set_toggle" or "select_item"
        or "expand_collapse" or "scroll" or "realize_item" or "read_text"))
        throw new ArgumentException();
    var target = Required(arguments, "target");
    if (RequiredInt(target, "pid") <= 0 || RequiredLong(target, "hwnd") <= 0
        || RequiredLong(target, "process_start_filetime") <= 0)
        throw new ArgumentException();
    _ = IntArray(Required(target, "root_runtime_id"));
    var privacy = RequiredString(arguments, "privacy");
    if (privacy is not ("structure_only" or "content_allowed"))
        throw new ArgumentException();
    var privacyScope = RequiredString(arguments, "privacy_scope");
    if (privacyScope.Length > 256 || (privacy == "content_allowed") != (privacyScope.Length > 0))
        throw new ArgumentException();
    if (arguments.TryGetProperty("local", out var local))
    {
        LocalScope.Validate(local);
        if (privacy != "content_allowed" || IntArray(Required(target, "root_runtime_id")).Length == 0)
            throw new ArgumentException();
    }
    if (command == "observe")
    {
        if (arguments.TryGetProperty("diagnostic", out var diagnostic))
        {
            if (privacy != "content_allowed" || arguments.TryGetProperty("tree", out _)) throw new ArgumentException();
            PropertyDiagnostics.Validate(diagnostic, target);
        }
        if (arguments.TryGetProperty("tree", out var tree))
        {
            TreePages.Validate(tree);
            if (IntArray(Required(target, "root_runtime_id")).Length == 0)
                throw new ArgumentException();
        }
        var limits = Required(arguments, "limits");
        var allowedLimits = new HashSet<string> { "max_nodes", "max_depth", "max_bytes", "max_ms", "max_provider_calls", "filter", "projection" };
        if (limits.ValueKind != JsonValueKind.Object || limits.EnumerateObject().Any(field => !allowedLimits.Contains(field.Name))
            || RequiredInt(limits, "max_nodes") is < 1 or > 500 || RequiredInt(limits, "max_depth") is < 0 or > 12)
            throw new ArgumentException();
        foreach (var pair in new[] { ("max_bytes", 1_000_000), ("max_ms", 2000), ("max_provider_calls", 5000) })
            if (limits.TryGetProperty(pair.Item1, out var value) && (value.GetInt32() < 1 || value.GetInt32() > pair.Item2)) throw new ArgumentException();
        if (limits.TryGetProperty("projection", out var projection) && projection.GetString() is not ("full" or "compact" or "actionable")) throw new ArgumentException();
        if (limits.TryGetProperty("filter", out var filter))
        {
            if (filter.ValueKind != JsonValueKind.Object) throw new ArgumentException();
            foreach (var field in filter.EnumerateObject())
                if (field.Name is not ("automation_id" or "control_type" or "name")
                    || field.Value.GetString() is not { Length: > 0 } text
                    || text.EnumerateRunes().Count() > 256 || text.EnumerateRunes().Any(Rune.IsControl)
                    || field.Name == "name" && privacy != "content_allowed") throw new ArgumentException();
        }
        return;
    }
    if (privacy != "content_allowed")
        throw new ArgumentException();
    var reference = Required(arguments, "reference");
    if (IntArray(Required(reference, "runtime_id")).Length == 0
        || RequiredString(reference, "automation_id").Length > 256)
        throw new ArgumentException();
    var observation = Required(arguments, "observation");
    if (IntArray(Required(observation, "root_runtime_id")).Length == 0
        || IntArray(Required(observation, "reference_runtime_id")).Length == 0
        || RequiredLong(observation, "observed_at_ms") <= 0)
        throw new ArgumentException();
    if (command == "set_value" && RequiredString(arguments, "value").Length > 8192)
        throw new ArgumentException();
    if (command == "guarded_input" && RequiredString(arguments, "text").Length is < 1 or > 8192)
        throw new ArgumentException();
    if (command == "guarded_input" && arguments.TryGetProperty("replace", out var replace)
        && replace.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new ArgumentException();
    if (command == "set_toggle" && Required(arguments, "desired").ValueKind is not
        (JsonValueKind.True or JsonValueKind.False))
        throw new ArgumentException();
    if (command == "select_item" && arguments.TryGetProperty("desired", out var selectionDesired)
        && selectionDesired.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        throw new ArgumentException();
    if (command == "expand_collapse" && RequiredString(arguments, "desired") is not ("Expanded" or "Collapsed"))
        throw new ArgumentException();
    if (command == "scroll" &&
        (RequiredString(arguments, "direction") is not ("up" or "down" or "left" or "right")
         || RequiredString(arguments, "amount") is not ("small" or "large")))
        throw new ArgumentException();
    if (command == "realize_item" &&
        (string.IsNullOrWhiteSpace(RequiredString(arguments, "item_name"))
         || RequiredString(arguments, "item_name").EnumerateRunes().Count() > 256))
        throw new ArgumentException();
    if (command == "read_text")
    {
        var options = Required(arguments, "text");
        var version = Required(options, "version");
        if (RequiredInt(options, "offset") is < 0 or > 1_048_576
            || RequiredInt(options, "max_chars") is < 1 or > 4096
            || version.ValueKind != JsonValueKind.Null && (version.ValueKind != JsonValueKind.String
                || version.GetString()!.Length != 64 || version.GetString()!.Any(c => !"0123456789abcdef".Contains(c))))
            throw new ArgumentException();
    }
}

static JsonElement Required(JsonElement parent, string key) => parent.GetProperty(key);
static bool EmbeddedTextPrivacyAllowed(AutomationElement[] embedded, out int unknown)
{
    // GetChildren describes objects in this text range, not an arbitrary
    // control-tree subtree. Links/tables must not inherit the UIA tree cap.
    // This is a known-password exclusion, not proof that a provider exposes
    // every descendant or implements privacy attributes correctly.
    unknown = 0;
    foreach (var element in embedded)
    {
        try
        {
            if (PasswordProperty.Read(element))
                return false;
        }
        catch (Exception) { unknown++; return false; }
    }
    return true;
}
static string RequiredString(JsonElement parent, string key) => Required(parent, key).GetString() ?? throw new ArgumentException();
static int RequiredInt(JsonElement parent, string key) => Required(parent, key).GetInt32();
static long RequiredLong(JsonElement parent, string key) => Required(parent, key).GetInt64();
static int[] IntArray(JsonElement value) => value.EnumerateArray().Select(item => item.GetInt32()).ToArray();
static (string Text, bool Truncated) BoundRunes(string? value, int max)
{
    if (value is null)
        return ("", false);
    var builder = new StringBuilder();
    int count = 0;
    foreach (var rune in value.EnumerateRunes())
    {
        if (count >= max)
            return (builder.ToString(), true);
        builder.Append(rune);
        count++;
    }
    return (builder.ToString(), false);
}
static int[]? ReadScreenBounds(AutomationElement element)
{
    try
    {
        var rect = element.BoundingRectangle;
        if (!double.IsFinite(rect.Left) || !double.IsFinite(rect.Top)
            || !double.IsFinite(rect.Right) || !double.IsFinite(rect.Bottom)
            || rect.Left < int.MinValue || rect.Top < int.MinValue
            || rect.Right > int.MaxValue || rect.Bottom > int.MaxValue
            || rect.Right <= rect.Left || rect.Bottom <= rect.Top)
            return null;
        return new[] { (int)Math.Floor((double)rect.Left),
            (int)Math.Floor((double)rect.Top),
            (int)Math.Ceiling((double)rect.Right),
            (int)Math.Ceiling((double)rect.Bottom) };
    }
    catch (Exception) { return null; }
}
static int[]? ReadClickablePoint(AutomationElement element)
{
    try
    {
        return element.TryGetClickablePoint(out var point)
            ? new[] { point.X, point.Y } : null;
    }
    catch (Exception) { return null; }
}
static void Emit(object value)
{
    var encoded = JsonSerializer.Serialize(value);
    if (Encoding.UTF8.GetByteCount(encoded) + 1 > 1_100_000)
        encoded = "{\"state\":\"not_verified\",\"dispatched\":false,\"reason\":\"tree_message_too_large\",\"new_observation_required\":true}";
    Console.WriteLine(encoded);
}

static class Native
{
    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool SetProcessDpiAwarenessContext(nint value);
    [DllImport("user32.dll")]
    internal static extern bool IsWindow(nint hwnd);
    [DllImport("user32.dll")]
    internal static extern bool IsWindowVisible(nint hwnd);
    [DllImport("user32.dll")]
    internal static extern bool IsWindowEnabled(nint hwnd);
    [DllImport("user32.dll")]
    internal static extern bool IsIconic(nint hwnd);
    [DllImport("user32.dll")]
    internal static extern nint GetForegroundWindow();
    [DllImport("user32.dll")]
    internal static extern nint GetAncestor(nint hwnd, uint flags);
    internal static bool IsForegroundRoot(nint hwnd)
    {
        var foreground = GetForegroundWindow();
        return foreground != nint.Zero && GetAncestor(foreground, 2) == hwnd;
    }
    [DllImport("user32.dll")]
    internal static extern uint GetWindowThreadProcessId(nint hwnd, out uint pid);
}
