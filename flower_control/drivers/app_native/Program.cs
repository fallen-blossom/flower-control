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
AppCheckpoint.Start();
var line = Console.ReadLine();
if (line is null || line.Length > 32768)
    return 2;
var execution = new ExecutionState();
try
{
    using var document = JsonDocument.Parse(line);
    var request = document.RootElement;
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
    // Never include provider messages or request content in the receipt.
    // Mark only entry into a mutating provider call as a possible side effect.
    if (error is ProviderIdentityUnavailable)
    {
        var cause = error.InnerException ?? error;
        Emit(execution.WithTimings(new { state = execution.WriteStarted ? "outcome_uncertain" : "rejected",
            dispatched = execution.WriteStarted, reason = "uia_provider_identity_unavailable",
            stage = execution.Stage, exception_type = cause.GetType().Name, hresult = cause.HResult,
            unsupported_property = "RuntimeId", recovery_hint = "use_computer_channel" }));
        return 0;
    }
    var reason = error is TreeCursorChanged ? "tree_cursor_changed"
        : error.HResult == unchecked((int)0x80070005) ? "uia_access_denied"
        : error.HResult == unchecked((int)0x80040201) ? "uia_element_unavailable"
        : error is TimeoutException ? "uia_timeout"
        : execution.Stage + "_failed";
    Emit(execution.WithTimings(new { state = execution.WriteStarted ? "outcome_uncertain" : "rejected",
        dispatched = execution.WriteStarted, reason, stage = execution.Stage,
        exception_type = error.GetType().Name, hresult = error.HResult }));
    return 0;
}

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
    if (root.Properties.ProcessId.Value != pid)
    {
        Emit(new { state = "rejected", reason = "uia_root_mismatch", dispatched = false });
        return;
    }
    var rootId = root.Properties.RuntimeId.Value ?? Array.Empty<int>();
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
    AutomationElement? RebindCurrent(int[] id, string automationId)
    {
        var current = FindCurrent(id, automationId);
        return current is not null && ReadOr(() => current.IsEnabled, false)
            && !ReadOr(() => current.Properties.IsPassword.Value, true) ? current : null;
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
        if (tree is not null && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            - tree.Value.GetProperty("observed_at_ms").GetInt64() is < 0 or > 15_000)
            throw new TreeCursorChanged();
        var queue = new TreePages(walker, lookupRoot, tree);
        bool truncated = false;
        // Return useful partial refs before the parent's hard worker timeout.
        // COM calls remain subject to the existing provider timeout; this
        // budget bounds traversal between calls, not an in-flight COM call.
        var observationBudget = new ObservationBudget(1800);
        bool truncatedByTime = false;
        while (queue.Count > 0)
        {
            if (observationBudget.Expired)
            {
                truncated = truncatedByTime = true;
                break;
            }
            if (entries.Count >= maxNodes)
            {
                truncated = true;
                break;
            }
            var (element, depth, treePath) = queue.Peek();
            bool password = ReadOr(() => element.Properties.IsPassword.Value, true);
            bool hasValue = ReadOr(() => element.Patterns.Value.TryGetPattern(out _), false);
            bool hasText = ReadOr(() => element.Patterns.Text.TryGetPattern(out _), false);
            bool hasInvoke = ReadOr(() => element.Patterns.Invoke.TryGetPattern(out _), false);
            bool hasToggle = false;
            bool hasSelectionItem = false;
            bool hasExpandCollapse = false;
            bool hasScroll = false;
            bool hasVirtualizedItem = ReadOr(
                () => element.Patterns.VirtualizedItem.TryGetPattern(out _), false);
            bool hasItemContainer = ReadOr(
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
                hasToggle = element.Patterns.Toggle.TryGetPattern(out var togglePattern);
                if (contentAllowed && !password && hasToggle && togglePattern is not null)
                    toggleState = togglePattern.ToggleState.Value.ToString();
            }
            catch (Exception) { hasToggle = false; }
            try
            {
                hasSelectionItem = element.Patterns.SelectionItem.TryGetPattern(out var selectionPattern);
                if (contentAllowed && !password && hasSelectionItem && selectionPattern is not null)
                    selected = selectionPattern.IsSelected.Value;
            }
            catch (Exception) { hasSelectionItem = false; }
            try
            {
                hasExpandCollapse = element.Patterns.ExpandCollapse.TryGetPattern(out var expandPattern);
                if (contentAllowed && !password && hasExpandCollapse && expandPattern is not null)
                    expandCollapseState = expandPattern.ExpandCollapseState.Value.ToString();
            }
            catch (Exception) { hasExpandCollapse = false; expandCollapseReadError = true; }
            try
            {
                hasScroll = element.Patterns.Scroll.TryGetPattern(out var scrollPattern);
                if (contentAllowed && !password && hasScroll && scrollPattern is not null)
                {
                    horizontallyScrollable = scrollPattern.HorizontallyScrollable.Value;
                    verticallyScrollable = scrollPattern.VerticallyScrollable.Value;
                    horizontalScrollPercent = scrollPattern.HorizontalScrollPercent.Value;
                    verticalScrollPercent = scrollPattern.VerticalScrollPercent.Value;
                }
            }
            catch (Exception) { hasScroll = false; scrollReadError = true; }
            string? name = null;
            bool nameTruncated = false;
            bool nameReadError = false;
            if (contentAllowed && !password)
            {
                try
                {
                    var boundedName = BoundRunes(element.Name, 128);
                    name = boundedName.Text;
                    nameTruncated = boundedName.Truncated;
                }
                catch (Exception) { nameReadError = true; }
            }
            string? value = null;
            bool valueTruncated = false;
            bool valueReadError = false;
            if (contentAllowed && !password && hasValue)
            {
                try
                {
                    if (element.Patterns.Value.TryGetPattern(out var valuePattern) && valuePattern is not null)
                    {
                        var boundedValue = BoundRunes(valuePattern.Value.Value, 256);
                        value = boundedValue.Text;
                        valueTruncated = boundedValue.Truncated;
                    }
                }
                catch (Exception)
                {
                    valueReadError = true;
                }
            }
            var entry = new {
                depth, tree_path = treePath,
                runtime_id = ReadOr(() => element.Properties.RuntimeId.Value, Array.Empty<int>()),
                automation_id = ReadOr(() => BoundRunes(element.AutomationId, 256).Text, ""),
                control_type = ReadOr(() => element.ControlType.ToString(), "Unknown"),
                enabled = ReadOr(() => element.IsEnabled, false),
                focusable = ReadOr(() => element.Properties.IsKeyboardFocusable.Value, false),
                focused = ReadOr(() => element.Properties.HasKeyboardFocus.Value, false),
                offscreen = ReadOr(() => element.IsOffscreen, true),
                bounding_rect_screen = ReadScreenBounds(element),
                clickable_point_screen = ReadClickablePoint(element),
                password, value_supported = hasValue && !password,
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
            int encodedBytes = JsonSerializer.SerializeToUtf8Bytes(entry).Length + 1;
            if (entryBytes + encodedBytes > 80_000)
            {
                truncated = true;
                break;
            }
            entries.Add(entry);
            entryBytes += encodedBytes;
            truncated |= queue.Commit(element, maxDepth);
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
            tree_next = queue.Count > 0 ? queue.Cursor(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) : null,
            observation_budget_ms = observationBudget.Milliseconds,
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
    if (control is null || command != "read_text" && !control.IsEnabled || control.Properties.IsPassword.Value)
    {
        Emit(new { state = "rejected", reason = localScopeChanged ? "local_item_scope_changed" : "control_unavailable", dispatched = false });
        return;
    }
    // Recheck exact identity and foreground immediately before the provider call.
    if (!Native.IsWindow(hwnd) || command != "read_text" && !Native.IsWindowEnabled(hwnd)
        || (command is "invoke" or "focus" or "guarded_input" && (Native.IsIconic(hwnd) || !Native.IsForegroundRoot(hwnd)))
        || Native.GetWindowThreadProcessId(hwnd, out actualPid) == 0 || actualPid != pid
        || !root.Properties.RuntimeId.Value.SequenceEqual(rootId))
    {
        Emit(new { state = "rejected", reason = "target_changed_before_dispatch", dispatched = false });
        return;
    }
    if (command == "read_text")
    {
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
            Emit(new { state = "rejected", dispatched = false, reason = "text_embedded_privacy_unavailable" });
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
        if (current is null || current.Properties.IsPassword.Value
            || !current.Patterns.Text.TryGetPattern(out var currentText) || currentText is null
            || !EmbeddedTextPrivacyAllowed(currentText.DocumentRange.GetChildren(), out unknownEmbedded)
            || currentText.DocumentRange.GetText(documentLimit + 1) != text
            || !Native.IsWindow(hwnd) || !root.Properties.RuntimeId.Value.SequenceEqual(rootId))
        {
            Emit(new { state = "rejected", dispatched = false, reason = "text_changed_during_read",
                requires_new_observation = true });
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
    if (command is "focus" or "guarded_input")
    {
        if (!control.Properties.IsKeyboardFocusable.Value || control.IsOffscreen)
        {
            Emit(new { state = "rejected", reason = "target_not_focusable", dispatched = false });
            return;
        }
        if (!WaitForGo()) return;
        control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
        if (!StillInteractive(hwnd, pid, root, rootId, true) || control is null
            || !control.Properties.IsKeyboardFocusable.Value || control.IsOffscreen)
        {
            Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
            return;
        }
        bool dispatched = false;
        if (!control.Properties.HasKeyboardFocus.Value)
        {
            AppCheckpoint.Record(AppCheckpointStage.business_enter);
            execution.BeginWrite();
            execution.Time("native_pattern_call", () => control.Focus());
            dispatched = true;
        }
        execution.Stage = "uia_readback";
        var after = FindCurrent(referenceId, automationId);
        bool matched = StillInteractive(hwnd, pid, root, rootId, true) && after is not null
            && after.Properties.HasKeyboardFocus.Value;
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
                    || fresh.IsOffscreen || !fresh.Properties.IsKeyboardFocusable.Value
                    || !fresh.Properties.HasKeyboardFocus.Value)
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
        AppCheckpoint.Record(AppCheckpointStage.business_enter);
        execution.BeginWrite();
        execution.Time("native_pattern_call", () => pattern.SetValue(value));
        execution.Stage = "uia_readback";
        using var readbackTimer = execution.Measure("native_internal_readback");
        var foregroundAfterProvider = Native.GetForegroundWindow();
        var after = FindCurrent(referenceId, automationId);
        bool sameTarget = Native.IsWindow(hwnd) && !Native.IsIconic(hwnd)
            && after is not null;
        bool matched = sameTarget && after!.Patterns.Value.TryGetPattern(out var afterPattern)
            && afterPattern is not null && afterPattern.Value.Value == value;
        var foregroundAfterReadback = Native.GetForegroundWindow();
        Emit(new { state = matched ? "verified" : "not_verified", dispatched = true,
            verification = "exact_control_value_readback", business_outcome_verified = false,
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
        if (pattern.ToggleState.Value != desiredState)
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
            && afterPattern is not null && afterPattern.ToggleState.Value == desiredState;
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            verification = "exact_control_toggle_readback", business_outcome_verified = false });
        return;
    }
    if (command == "select_item")
    {
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
        if (pattern.IsSelected.Value != desired)
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
                && afterPattern is not null && afterPattern.IsSelected.Value == desired;
        });
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            verification = "exact_control_selection_readback", business_outcome_verified = false });
        return;
    }
    if (command == "expand_collapse")
    {
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
        try { beforeState = pattern.ExpandCollapseState.Value; }
        catch (Exception)
        {
            Emit(new { state = "rejected", reason = "expand_collapse_state_unavailable", dispatched = false });
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
            observedState = afterPattern.ExpandCollapseState.Value.ToString();
        bool matched = observedState == desired;
        Emit(new { state = matched ? "verified" : "not_verified", dispatched,
            expand_collapse_state = observedState,
            verification = "exact_control_expand_collapse_readback" });
        return;
    }
    if (command == "scroll")
    {
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
        try { scrollable = vertical ? pattern.VerticallyScrollable.Value : pattern.HorizontallyScrollable.Value; }
        catch (Exception)
        {
            Emit(new { state = "rejected", reason = "scroll_axis_state_unavailable", dispatched = false });
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
        try { scrollable = vertical ? pattern.VerticallyScrollable.Value : pattern.HorizontallyScrollable.Value; }
        catch (Exception)
        {
            Emit(new { state = "rejected", reason = "scroll_axis_state_unavailable", dispatched = false });
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
            horizontalPercent = afterPattern.HorizontalScrollPercent.Value;
            verticalPercent = afterPattern.VerticalScrollPercent.Value;
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
            || item.Properties.IsPassword.Value)
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
    bool hasInvokePattern = control.Patterns.Invoke.TryGetPattern(out var invoke);
    AppCheckpoint.Record(AppCheckpointStage.pattern_exit);
    if (!hasInvokePattern || invoke is null)
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
    control = execution.Time("native_go_rebind", () => RebindCurrent(referenceId, automationId));
    if (control is null || !control.Patterns.Invoke.TryGetPattern(out invoke)
        || invoke is null)
    {
        Emit(new { state = "rejected", reason = "control_changed_before_dispatch", dispatched = false });
        return;
    }
    AppCheckpoint.Record(AppCheckpointStage.business_enter);
    execution.BeginWrite();
    execution.Time("native_pattern_call", () => invoke.Invoke());
    Emit(new { state = "not_verified", dispatched = true,
        verification = "business_postcondition_required" });
}

static bool StillInteractive(nint hwnd, int pid, AutomationElement root, int[] rootId, bool needsForeground) =>
    Native.IsWindow(hwnd) && Native.IsWindowEnabled(hwnd)
    && (!needsForeground || (!Native.IsIconic(hwnd) && Native.IsForegroundRoot(hwnd)))
    && Native.GetWindowThreadProcessId(hwnd, out var actualPid) != 0 && actualPid == pid
    && root.Properties.RuntimeId.Value.SequenceEqual(rootId);

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
        bool Matches(AutomationElement element) => element.Properties.RuntimeId.Value.SequenceEqual(runtimeId)
            && element.AutomationId == automationId;
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
        if (arguments.TryGetProperty("tree", out var tree))
        {
            TreePages.Validate(tree);
            if (IntArray(Required(target, "root_runtime_id")).Length == 0)
                throw new ArgumentException();
        }
        var limits = Required(arguments, "limits");
        if (RequiredInt(limits, "max_nodes") is < 1 or > 192
            || RequiredInt(limits, "max_depth") is < 0 or > 8)
            throw new ArgumentException();
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
            if (element.Properties.IsPassword.Value)
                return false;
        }
        catch (Exception) { unknown++; }
    }
    return true;
}
static T ReadOr<T>(Func<T> reader, T fallback)
{
    try { return reader(); }
    catch (Exception) { return fallback; }
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
static void Emit(object value) => Console.WriteLine(JsonSerializer.Serialize(value));

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
