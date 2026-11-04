using FlaUI.Core;
using FlaUI.Core.Conditions;
using FlaUI.Core.Exceptions;
using FlaUI.UIA3;
using FlaUI.Core.AutomationElements;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;

// Disposable, metadata-only scan of a single already-authorized HWND.
internal static class PasswordPixels
{
    // UIA_IsPasswordPropertyId has the documented default FALSE. Only an
    // explicit unsupported result uses that default; provider/COM failures
    // propagate. This does not claim a provider exposes every password field.
    internal static bool PasswordFlag(Func<(bool Supported, bool Value)> query)
    {
        try
        {
            var result = query();
            return result.Supported && result.Value;
        }
        catch (PropertyNotSupportedException) { return false; }
    }
    private static bool PasswordFlag(AutomationElement element) => PasswordFlag(() =>
    {
        bool supported = element.Properties.IsPassword.TryGetValue(out bool value);
        return (supported, value);
    });
    private static T At<T>(string stage, Func<T> read)
    {
        try { return read(); }
        catch (Exception error) { error.Data["PrivacyStage"] = stage; throw; }
    }
    internal static object Failure(Exception error) => new { state = "rejected", dispatched = false,
        reason = "privacy_scan_incomplete", stage = error.Data["PrivacyStage"] as string ?? "request_or_identity",
        exception_type = error.GetType().Name, hresult = error.HResult };
    internal static int CompatibilityTests()
    {
        int assertions = 0;
        void Check(bool value) { assertions++; if (!value) throw new Exception("privacy_default_test_failed_" + assertions); }
        Check(PasswordFlag(() => (true, true)));
        Check(!PasswordFlag(() => (true, false)));
        Check(!PasswordFlag(() => (false, false)));
        Check(!PasswordFlag(() => (false, true)));
        foreach (Exception original in new Exception[] { new TimeoutException(), new COMException("synthetic"),
            new InvalidOperationException(), new ArgumentException() })
        {
            Exception? caught = null;
            try { PasswordFlag(() => throw original); } catch (Exception error) { caught = error; }
            Check(ReferenceEquals(original, caught));
        }
        var fault = new COMException("DO-NOT-RETURN-THIS-SYNTHETIC-TEXT");
        try { At<int>("password_descendants", () => throw fault); } catch (COMException) { }
        string json = JsonSerializer.Serialize(Failure(fault));
        Check(json.Contains("password_descendants") && !json.Contains("DO-NOT-RETURN"));
        return assertions;
    }
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint hwnd, out int pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern nint GetPropW(nint hwnd, string name);
    internal static UIA3Automation CreateAutomation() => new()
    {
        // Provider calls remain bounded by the parent's exact process deadline.
        ConnectionTimeout = TimeSpan.FromMilliseconds(500),
        TransactionTimeout = TimeSpan.FromMilliseconds(700)
    };

    internal static object Scan(JsonElement request, UIA3Automation? sharedAutomation = null)
    {
        var names = request.EnumerateObject().Select(p => p.Name).ToArray();
        var required = new[] { "pid", "hwnd", "process_created", "window_nonce" };
        if (!(names.Length == 4 && names.ToHashSet().SetEquals(required)
            || names.Length == 5 && names.ToHashSet().SetEquals(required.Append("scope"))))
            throw new ArgumentException();
        bool focusOnly = request.TryGetProperty("scope", out var scope);
        if (focusOnly && scope.GetString() != "keyboard_focus") throw new ArgumentException();
        int pid = request.GetProperty("pid").GetInt32();
        nint hwnd = (nint)request.GetProperty("hwnd").GetInt64();
        long nonce = request.GetProperty("window_nonce").GetInt64();
        var created = DateTimeOffset.Parse(request.GetProperty("process_created").GetString()!, CultureInfo.InvariantCulture);
        void Check()
        {
            GetWindowThreadProcessId(hwnd, out int actual);
            using var process = Process.GetProcessById(pid);
            if (pid <= 0 || actual != pid || nonce <= 0 || GetPropW(hwnd, "FlowerControl.WindowNonce.v1").ToInt64() != nonce
                || process.StartTime.ToUniversalTime().Ticks / 10000 != created.UtcTicks / 10000)
                throw new ArgumentException();
        }
        Check();
        using var ownedAutomation = sharedAutomation is null ? CreateAutomation() : null;
        var automation = sharedAutomation ?? ownedAutomation!;
        var root = At("root", () => automation.FromHandle(hwnd));
        if (focusOnly)
        {
            // Physical keyboard segments need fresh focused-element metadata,
            // not an enumeration of unrelated password fields in the window.
            // Password ancestors and exact root membership still matter.
            var result = PasswordFocus.Read(root, pid, () => automation.FocusedElement(),
                element => element.Properties.ProcessId.Value, element => element.Properties.RuntimeId.Value,
                element => element.Parent, PasswordFlag,
                element => {
                    var box = element.BoundingRectangle;
                    return box.Width > 0 && box.Height > 0 ? new[] { box.Left, box.Top, box.Right, box.Bottom } : null;
                });
            Check();
            return new { state = "observed", rectangles = Array.Empty<int[]>(), focus_rectangle = result.Rectangle,
                focus_password = (bool?)result.Password, coverage = "uia_password_focus", dispatched = false };
        }
        var descendants = At("password_descendants", () => root.FindAllDescendants(new PropertyCondition(automation.PropertyLibrary.Element.IsPassword, true)));
        var fields = At("root_password", () => PasswordFlag(root)) ? new[] { root }.Concat(descendants).ToArray() : descendants;
        if (fields.Length > 128) throw new ArgumentException();
        var rectangles = new List<int[]>();
        foreach (var field in fields)
        {
            if (!At("password_recheck", () => PasswordFlag(field))) throw new ArgumentException();
            if (At("password_offscreen", () => field.Properties.IsOffscreen.Value)) continue;
            var box = At("password_rectangle", () => field.BoundingRectangle);
            if (box.Width > 0 && box.Height > 0)
                rectangles.Add(new[] { box.Left - 3, box.Top - 3, box.Right + 3, box.Bottom + 3 });
        }
        int[]? focusRectangle = null; bool? focusPassword = null;
        try
        {
            var focused = automation.FocusedElement();
            if (focused is not null && focused.Properties.ProcessId.Value == pid)
            {
                var rootId = root.Properties.RuntimeId.Value;
                var parent = focused;
                for (int depth = 0; parent is not null && depth < 32; depth++, parent = parent.Parent)
                    if (parent.Properties.RuntimeId.Value.SequenceEqual(rootId))
                    {
                        var box = focused.BoundingRectangle;
                        if (box.Width > 0 && box.Height > 0) focusRectangle = [box.Left, box.Top, box.Right, box.Bottom];
                        focusPassword = PasswordFlag(focused); break;
                    }
            }
        }
        catch { focusRectangle = null; focusPassword = null; } // A background capture need not have keyboard focus.
        Check();
        return new { state = "observed", rectangles, focus_rectangle = focusRectangle,
            focus_password = focusPassword, coverage = "uia_password_property", dispatched = false };
    }
}
