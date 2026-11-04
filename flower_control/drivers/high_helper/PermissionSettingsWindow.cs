using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

internal static partial class PermissionSettingsWindow
{
    private delegate IntPtr Procedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct Class
    { public uint Size, Style; public IntPtr Proc; public int Extra, WindowExtra; public IntPtr Instance, Icon, Cursor, Background; public string? Menu; public string Name; public IntPtr SmallIcon; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? name);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern ushort RegisterClassExW(ref Class value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateWindowExW(uint ex, string kind, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr id, IntPtr instance, IntPtr data);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool EnableWindow(IntPtr hwnd, bool enabled);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int MessageBoxW(IntPtr hwnd, string text, string title, uint flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr wp, string text);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetWindowTextW(IntPtr hwnd, string text);
    [DllImport("gdi32.dll")] private static extern IntPtr GetStockObject(int index);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateFontW(int height, int width, int angle, int orientation, int weight, uint italic, uint underline, uint strike, uint charset, uint output, uint clip, uint quality, uint pitch, string face);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr item);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr item);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int DrawTextW(IntPtr dc, string text, int count, ref Native.Rect rect, uint flags);
    [DllImport("user32.dll")] private static extern bool IsDialogMessageW(IntPtr hwnd, ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProcedure proc, IntPtr data);
    private delegate bool EnumProcedure(IntPtr hwnd, IntPtr data);
    [DllImport("user32.dll")] private static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool AppendMenuW(IntPtr menu, uint flags, UIntPtr id, string text);
    [DllImport("user32.dll")] private static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr owner, IntPtr rect);
    [DllImport("user32.dll")] private static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetPropW(IntPtr hwnd, string name, IntPtr value);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Native.Rect rect);
    [DllImport("user32.dll")] private static extern bool ScreenToClient(IntPtr hwnd, ref Native.Point point);
    [StructLayout(LayoutKind.Sequential)] private struct ScrollInfo { public uint Size, Mask; public int Min, Max; public uint Page; public int Position, Track; }
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo { public uint Size; public Native.Rect Monitor, Work; public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct MinMaxInfo { public Native.Point Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack; }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] private static extern bool GetMonitorInfoW(IntPtr monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int SetScrollInfo(IntPtr hwnd, int bar, ref ScrollInfo info, bool redraw);
    [DllImport("user32.dll")] private static extern bool GetScrollInfo(IntPtr hwnd, int bar, ref ScrollInfo info);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int w, int h, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr BeginDeferWindowPos(int count);
    [DllImport("user32.dll")] private static extern IntPtr DeferWindowPos(IntPtr batch, IntPtr hwnd, IntPtr after, int x, int y, int w, int h, uint flags);
    [DllImport("user32.dll")] private static extern bool EndDeferWindowPos(IntPtr batch);
    [DllImport("user32.dll")] private static extern bool RedrawWindow(IntPtr hwnd, IntPtr rect, IntPtr region, uint flags);
    [DllImport("user32.dll")] private static extern uint GetWindowLongW(IntPtr hwnd, int index);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int width, int height);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern uint GetPixel(IntPtr dc, int x, int y);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetFocus();
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetNextDlgTabItem(IntPtr hwnd, IntPtr control, bool previous);
    [DllImport("user32.dll")] private static extern short GetKeyState(int key);
    [DllImport("user32.dll")] private static extern bool IsChild(IntPtr parent, IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);
    [DllImport("user32.dll")] private static extern int GetMessageW(out HostWindow.Message message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool PostMessageW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool RegisterHotKey(IntPtr hwnd, int id, uint modifiers, uint key);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool UnregisterHotKey(IntPtr hwnd, int id);
    [DllImport("user32.dll", SetLastError = true)] private static extern UIntPtr SetTimer(IntPtr hwnd, UIntPtr id, uint interval, IntPtr procedure);
    [DllImport("user32.dll")] private static extern bool KillTimer(IntPtr hwnd, UIntPtr id);
    [DllImport("user32.dll")] private static extern bool SystemParametersInfoW(uint action, uint param, out uint value, uint flags);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct OpenFileName
    {
        public uint Size; public IntPtr Owner, Instance;
        public string Filter; public IntPtr CustomFilter; public uint CustomFilterLength, FilterIndex;
        public IntPtr File; public uint FileLength; public IntPtr FileTitle; public uint FileTitleLength;
        public string? InitialDirectory, Title; public uint Flags; public ushort FileOffset, FileExtension;
        public string? DefaultExtension; public IntPtr Data, Hook; public string? Template;
        public IntPtr Reserved; public uint ReservedValue, ExtendedFlags;
    }
    [DllImport("comdlg32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool GetOpenFileNameW(ref OpenFileName value);
    [DllImport("comdlg32.dll")] private static extern uint CommDlgExtendedError();
    private const int WindowWidth = 984, WindowHeight = 780, BodyLeft = 216, BodyTop = 158, ContentWidth = 720, FooterHeight = 88;
    // Below this the header, page chrome and footer collide; WM_GETMINMAXINFO and the restore path both enforce it.
    private const int MinWindowWidth = 760, MinWindowHeight = 620;
    internal enum SettingsPage { General, Admin, Launch, Uac, Privacy, Validation, Overview }
    private static SettingsPage page = SettingsPage.Admin, buildingPage;
    private static readonly int[] pageScroll = new int[7];
    private static readonly string[] PageNames = ["常规", "管理员能力", "直接启动", "UAC 后备", "隐私保护", "系统接入", "状态总览"];
    private static readonly string[] PageDescriptions = [
        "操作手感与可选服务。改动先保留为草稿，点保存后生效。",
        "四档互斥。普通档立即降权；管理员档经 Windows 确认后切换。其它编辑保存后生效。",
        "03 的执行方式与独立名单；语义方式未就绪时不能新启用。",
        "用于需要处理 Windows 安全桌面提示的场景。属于按需开启的高级能力。",
        "指定禁止程序，并在截图里遮住敏感区域。",
        "准备、停用与验证会在这里逐项说明即时效果。",
        "本机控制与权限一览。先看这里，再决定要不要开更高权限。"];
    private static readonly int[] PageHeights = [384, 492, 708, 836, 678, 644, 760];
    // The rail mirrors the prototype: the direct-launch list is a sub-page of
    // 管理员能力 reached from a card button, not a seventh rail item.
    private static readonly SettingsPage[] NavPages = [SettingsPage.Overview, SettingsPage.General, SettingsPage.Admin, SettingsPage.Uac, SettingsPage.Privacy, SettingsPage.Validation];
    private static bool explanationOpen;
    private static double scale = 1;
    private static int scrollPosition;
    private static int wheelRemainder;
    private static int smoothTarget = -1;
    private static int smoothStep;
    private static int Px(int value) => (int)Math.Round(value * scale);
    private static readonly Procedure Proc = WindowProc;
    private static readonly Dictionary<int, IntPtr> controls = [];
    private sealed record LayoutItem(IntPtr Handle, string Kind, int X, int Y, int W, int H, bool Fixed, bool Footer, SettingsPage Page);
    private static readonly List<LayoutItem> layout = [];
    private static IntPtr font, nameFont, headingFont, titleFont, smallFont;
    private static PermissionVisual? visual;
    private static SettingsTooltips? help;
    private static PermissionPageLayout.Result? activeLayout;
    private static int bodyLeft = BodyLeft, bodyTop = BodyTop, footerHeight = FooterHeight;
    private static bool compactNavigation, conflict, closeAfterSave, positioning;
    private static string detailMode = "", notice = "";
    private static int detailReturnScroll;
    private static IntPtr detailReturnFocus;
    private static UserPermissionSettings? previewSaved;
    private static bool? lastStopped;
    private static bool? lastComputerPaused;
    private static readonly Dictionary<int, PermissionPageLayout.Box> positioned = [];
    private sealed record PendingProgram(string Path, WindowCandidate? Candidate, SelectionContext Context, UacApplicationPermission Inspected, string Digest);
    private static PendingProgram? pendingProgram;
    private static int lastWidth = WindowWidth, lastHeight = WindowHeight;
    private static readonly List<PrivacyMask> masks = [];
    private static readonly List<UacApplicationPermission> uacAllowlist = [];
    private static readonly List<UacApplicationPermission> adminLaunchAllowlist = [];
    internal enum ProgramListKind { Launch, Uac }
    private static List<UacApplicationPermission> Programs(ProgramListKind kind) => kind == ProgramListKind.Launch ? adminLaunchAllowlist : uacAllowlist;
    private static string ProgramListName(ProgramListKind kind) => kind == ProgramListKind.Launch ? "管理员直接启动名单" : "UAC 确认名单";
    private static int ListControl(ProgramListKind kind, int launchId) => kind == ProgramListKind.Launch ? launchId : launchId + 100;
    private const int UacPickHotkey = 80;
    private const int UacLocalStopHotkey = 82;
    private static bool localStopHotkey;
    private static readonly UIntPtr UacPickTimer = new(81);
    private static readonly UIntPtr StopStatusTimer = new(83);
    private static readonly UIntPtr SmoothTimer = new(84);
    private static UacWindowPick? uacWindowPick;
    private sealed record WindowCandidate(IntPtr Hwnd, Peer Peer, string Image, string Title);
    private sealed record SelectionContext(long Generation, long? StopEpoch, bool WasPaused, ProgramListKind Kind);
    internal sealed class UacWindowPick(long generation, long deadline, long? stopEpoch, bool wasPaused, Action release, ProgramListKind kind = ProgramListKind.Uac) : IDisposable
    {
        private Action? close = release;
        internal ProgramListKind Kind => kind;
        internal long Generation => generation;
        internal long? StopEpoch => stopEpoch;
        internal bool WasPaused => wasPaused;
        internal bool Expired(long now) => now >= deadline;
        public void Dispose() => Interlocked.Exchange(ref close, null)?.Invoke();
    }
    private static UacCapabilities uacCapabilities = new(false, false, false, false, "UAC 组件尚未就绪。");
    private static string uacMode = "off";
    private static string uacSubmode = "allowlist";
    private static string uiBaselineSubmode = "allowlist";
    private static SettingsUiPreference uiPreference = new();
    private static bool uiPreferencePending;
    private static string uacCancellationScope = "task";
    private static readonly string[] CancellationScopes = ["task", "selected_prompt_in_session"];
    private static bool policyValid = true;
    private static bool fullyDisabled;
    private static string launchMode = "allowlist";
    private static IntPtr window, body;
    private static BrokerState? broker;
    private static UserPermissionSettings? original;
    private static int[]? selectedSize;
    private static bool registered;
    private const uint UacWorkFinished = 0x8317;
    private sealed record WorkReply(long WindowGeneration, string Kind, string? Error,
        UserPermissionSettings? Saved = null, bool CloseOnSuccess = false, UserPermissionSettings? SubmittedDraft = null,
        SettingsUiSave? UiSave = null, bool PreferenceOnly = false, SettingsSurfaceHandoff? RoleSurface = null);
    private static bool RefreshCapabilitiesAfterWork(string kind, bool preferenceOnly)
        => kind != "save" || !preferenceOnly;
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<long, WorkReply> uacReplies = new();
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<long, long> pendingUiReplies = new();
    private static readonly SemaphoreSlim uacSerial = new(1, 1);
    internal sealed class OwnedWork
    {
        private readonly List<(Task Task, bool AffectsBusy)> tasks = [];
        internal bool Busy { get { lock (tasks) return tasks.Any(item => item.AffectsBusy && !item.Task.IsCompleted); } }
        internal void Track(Task task, bool affectsBusy = true)
        { lock (tasks) { tasks.RemoveAll(item => item.Task.IsCompleted); tasks.Add((task, affectsBusy)); } }
        internal Task Drain() { lock (tasks) return Task.WhenAll(tasks.Select(item => item.Task).ToArray()); }
    }
    private static readonly OwnedWork uacOwnedWork = new();
    private static CancellationTokenSource? uacWorkStop;
    private static bool shutdownRequested;
    private static long windowGeneration, workGeneration;
    private static bool UacBusy => uacOwnedWork.Busy || pendingUiReplies.Any(item => item.Value == windowGeneration);
    private static void RequireUacWorkResult(object result, string field, bool evidenceRequired = false)
    {
        using var document = System.Text.Json.JsonSerializer.SerializeToDocument(result);
        if (!UacOutcomeEvidence.True(document.RootElement, field)
            || field == "QualificationComplete" && UacOutcomeEvidence.Text(document.RootElement, "State") != "completed"
            || evidenceRequired && !UacOutcomeEvidence.True(document.RootElement, "EvidencePersisted"))
            throw new Boundary(field == "QualificationComplete" && UacOutcomeEvidence.Text(document.RootElement, "ControllerError") is { } detail ? detail
                : field == "StopExperimentConsistent" ? "uac_physical_stop_unverified"
                : field == "EscExperimentConsistent" ? "uac_esc_test_unverified"
                : field == "QualificationComplete" ? "uac_local_qualification_incomplete" : "uac_verification_registration_unconfirmed");
    }
    private static void BeginUacWork(string kind, Action<CancellationToken> action,
        Func<UserPermissionSettings?>? savedSnapshot = null, bool closeOnSuccess = false,
        Func<SettingsUiSave?>? uiSnapshot = null, bool preferenceOnly = false, SettingsSurfaceHandoff? roleSurface = null)
    {
        if (preview || broker is null) throw new Boundary("permission_preview_readonly");
        if (shutdownRequested) throw new Boundary("permission_settings_shutting_down");
        if (surfaceFault && kind != "disable") throw new Boundary("permission_surface_reload_required");
        EndUacWindowPick();
        if (UacBusy && kind != "disable") throw new Boundary("uac_settings_work_busy");
        if (kind == "disable")
        {
            try { uacWorkStop?.Cancel(); } catch (ObjectDisposedException) { }
            broker?.CancelUacRequests("uac_component_disabled");
        }
        var token = ++workGeneration; var generation = windowGeneration;
        var submittedDraft = kind == "save" ? EditedSettings() : null;
        pendingUiReplies[token] = generation;
        var cancelled = new CancellationTokenSource(); uacWorkStop = cancelled;
        var working = Task.Run(async () => {
            string? error = null; bool held = false; UserPermissionSettings? saved = null;
            try
            {
                await uacSerial.WaitAsync(cancelled.Token); held = true;
                cancelled.Token.ThrowIfCancellationRequested(); action(cancelled.Token); saved = savedSnapshot?.Invoke();
            }
            catch (Exception failure) { error = Program.Code(failure); }
            finally { if (held) uacSerial.Release(); cancelled.Dispose(); }
            return new WorkReply(generation, kind, error, saved, closeOnSuccess, submittedDraft, uiSnapshot?.Invoke(), preferenceOnly, roleSurface);
        });
        uacOwnedWork.Track(working);
        var delivery = working.ContinueWith(completion => {
            var reply = completion.GetAwaiter().GetResult();
            uacReplies[token] = reply;
            var destination = window;
            if (destination == IntPtr.Zero || !PostMessageW(destination, UacWorkFinished, new UIntPtr((ulong)token), IntPtr.Zero))
            {
                // The pre-registered owner-thread timer can consume this exact
                // reply even if the message queue temporarily rejects a post.
                if (KeepRoleReplyForTimer(reply.Kind, reply.WindowGeneration, windowGeneration, destination != IntPtr.Zero)) return;
                uacReplies.TryRemove(token, out _);
                pendingUiReplies.TryRemove(token, out _);
                if (reply.Error is not null) Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { uacSettings = reply.Error }));
            }
        }, TaskScheduler.Default);
        // The continuation is owned for shutdown; pendingUiReplies keeps Busy
        // until the corresponding result is consumed on the UI thread.
        uacOwnedWork.Track(delivery, affectsBusy: false);
        UpdateUacControls();
    }
    private static bool preview;
    private static bool localSettings;
    internal static int RunLocal()
    {
        var role = Native.Process(Environment.ProcessId, digestImage: false).Identity;
        if (role.Integrity != 12288 || Native.UiAccess(role.Pid)) throw new Boundary("uac_local_settings_high_required");
        var policyPath = Path.Combine(AppContext.BaseDirectory, "broker.json");
        var policy = BrokerPolicy.Load(policyPath, false);
        var own = Native.Process(Environment.ProcessId).Identity;
        UacSystemPipe.RequireHighParent(own, policy, own.Session);
        if (policy.Fixture || own.User != policy.UserSid || own.Integrity != 12288 || Native.UiAccess(own.Pid))
            throw new Boundary("uac_local_settings_high_required");
        var expectedDirectory = Path.Combine(InstallationLocation.Discover(policy.UserSid).ProgramRoot,
            "versions", policy.Version);
        if (!Path.GetFullPath(policy.Directory).TrimEnd('\\').Equals(expectedDirectory, StringComparison.OrdinalIgnoreCase))
            throw new Boundary("uac_local_settings_installation_rejected");
        UacClaimJournal.CheckParent(Path.GetDirectoryName(Path.GetDirectoryName(expectedDirectory))!, false);
        // The shared versions parent predates per-version High labels. Its
        // owner/DACL must prevent non-admin mutation; never relabel it merely
        // to open this coexisting page. The candidate itself remains High.
        UacClaimJournal.CheckParent(Path.GetDirectoryName(expectedDirectory)!, false);
        UacClaimJournal.CheckParent(expectedDirectory, true);
        var sealPath = Path.Combine(policy.Directory, "installation.json");
        UserPermissions.CheckProtection(policyPath); UserPermissions.CheckProtection(sealPath);
        using (var seal = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(sealPath)))
        {
            Protocol.CheckUnique(seal);
            var hashes = seal.RootElement.GetProperty("hashes");
            foreach (var name in new[] { "Flower.HighHelper.exe", "Flower.HighHelper.dll" })
            {
                var path = Path.Combine(policy.Directory, name);
                if (name.EndsWith(".exe", StringComparison.Ordinal)) UserPermissions.CheckSystemExecutableProtection(path);
                else UserPermissions.CheckProtection(path);
                if (!hashes.TryGetProperty(name, out var digest) || digest.GetString() != ProgramDigest(path))
                    throw new Boundary("uac_local_settings_installation_rejected");
            }
        }
        using var writeGate = new SharedWriteGate();
        var core = new BrokerState(writeGate: writeGate, protectedStop: true);
        UacRuntime.RestoreInputFault(policy, own, core);
        localSettings = true;
        try
        {
            // This process owns only this page and its explicit work. It does
            // not start a broker listener/tray or reconcile saved modes on open.
            Create(IntPtr.Zero, core, UserPermissions.Read(), true);
            localStopHotkey = RegisterHotKey(window, UacLocalStopHotkey, 0x4003, 0x39);
            UpdateUacControls();
            while (true)
            {
                int result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result == 0) break;
                if (result < 0) throw new Boundary("uac_local_settings_messages_failed");
                if (!HandleDialogMessage(ref message)) { TranslateMessage(ref message); DispatchMessageW(ref message); }
            }
        }
        finally
        {
            try { core.Stop(); }
            finally { try { ShutdownOwnedWork(); } finally { localSettings = false; } }
        }
        return 0;
    }
    internal static void ShowError(IntPtr owner, string message) => MessageBoxW(owner, message, "Flower Control", 0x10);
    internal static bool HandleDialogMessage(ref HostWindow.Message message)
    {
        if (window == IntPtr.Zero || !IsWindowVisible(window) || !IsWindowEnabled(window) || IsIconic(window)
            || message.Hwnd != window && !IsChild(window, message.Hwnd)) return false;
        help?.Relay(message.Hwnd, message.Kind, message.Wp, message.Lp);
        if (window != IntPtr.Zero && message.Kind == 0x100 &&
            (message.Hwnd == window || IsChild(window, message.Hwnd)))
        {
            bool control = GetKeyState(17) < 0, alt = GetKeyState(18) < 0;
            int key = (int)message.Wp.ToUInt64();
            if (key == 27 && uacWindowPick is not null)
            { EndUacWindowPick(); UpdateUacControls(); return true; }
            if (key == 9 && !control && !alt)
            {
                var next = GetNextDlgTabItem(window, GetFocus(), GetKeyState(16) < 0);
                SendMessageW(window, 0x127, new IntPtr((1 << 16) | 2), IntPtr.Zero); // Keyboard focus cues become visible.
                if (next != IntPtr.Zero) SetFocus(next);
                EnsureFocusedVisible(); return true;
            }
            if (key == 27 && new[] { 7, 81 }.All(id => SendMessageW(controls[id], 0x157, IntPtr.Zero, IntPtr.Zero) == IntPtr.Zero))
            { if (detailMode.Length > 0) CloseDetails(); else RequestClose(); return true; }
            if (key == 112) { OpenHelp(GetDlgCtrlID(GetFocus())); return true; }
            if (key == 0x53 && control && !alt)
            { SendMessageW(window, 0x111, new IntPtr(30), IntPtr.Zero); return true; }
        }
        // Native mouse messages go to the original Button procedure. Dialog
        // translation is for this visible page's keyboard messages only.
        var handled = message.Kind is >= 0x100 and <= 0x109 && IsDialogMessageW(window, ref message);
        if (handled && window != IntPtr.Zero) EnsureFocusedVisible();
        return handled;
    }
    internal static double LayoutScale(uint dpi, int workWidth) => Math.Max(1, dpi / 96.0);
    internal static void Show(IntPtr owner, BrokerState core)
    {
        if (Native.IsWindow(window)) { PresentSettings(); return; }
        UserPermissionSettings settings;
        try { settings = UserPermissions.Read(); }
        catch (Boundary) { settings = new() { UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            Revision = UserPermissions.Revision }; ShowError(owner, "原权限配置无法读取，本页仅供查看，不能用默认草稿覆盖原配置。请先修复配置后重新打开。停止功能仍可用。" ); }
        try { Create(owner, core, settings, true); }
        catch { CloseAfterFailure(); throw; }
    }
    private static void CloseAfterFailure()
    {
        EndUacWindowPick();
        if (Native.IsWindow(window)) DestroyWindow(window);
        window = body = IntPtr.Zero; broker = null; original = null; changingExecutionRole = false;
        visual?.Dispose(); visual = null;
    }
    internal static void ShutdownOwnedWork()
    {
        // Called on the UI owner thread after its message loop ends. Delivery
        // only posts a result; draining never depends on dispatching that post.
        shutdownRequested = true;
        try { uacWorkStop?.Cancel(); }
        catch (Exception error) { try { Console.Error.WriteLine("settings_work_shutdown:" + Program.Code(error)); } catch { } }
        try { EndUacWindowPick(); }
        catch (Exception error) { try { Console.Error.WriteLine("settings_pick_shutdown:" + Program.Code(error)); } catch { } }
        try { uacOwnedWork.Drain().GetAwaiter().GetResult(); }
        finally
        {
            uacReplies.Clear(); pendingUiReplies.Clear();
            CloseAfterFailure();
        }
    }
    private static void Create(IntPtr owner, BrokerState? core, UserPermissionSettings settings, bool display,
        SettingsSurfaceHandoff? roleSnapshot = null)
    {
        windowGeneration++;
        broker = core; original = settings; changingExecutionRole = false;
        previewSaved = core is null ? settings : null;
        conflict = closeAfterSave = false; detailMode = notice = ""; pendingProgram = null; lastStopped = lastComputerPaused = null;
        restoreFocus = IntPtr.Zero; surfaceFault = false;
        policyValid = !settings.Revision.StartsWith("invalid:", StringComparison.Ordinal);
        var opening = UserPermissions.Effective(settings);
        uacMode = opening.UacMode;
        uiPreference = !preview && display && core is not null ? UserPermissions.ReadUiPreference() : new();
        uacSubmode = UserPermissions.PreferredUacSubmode(opening.UacMode, uiPreference);
        uiBaselineSubmode = uacSubmode;
        uiPreferencePending = false;
        if (uiPreference.Error is not null) notice = "未能读取 04 界面模式偏好；当前权限仍以已保存配置为准。";
        uacCancellationScope = settings.UacCancellationScope;
        launchMode = opening.AdminLaunchMode;
        fullyDisabled = UserPermissions.TierOf(settings) < 0;
        deniedLaunchPrograms.Clear(); deniedLaunchPrograms.AddRange(settings.DeniedAdminLaunchApplications);
        deniedUacPrograms.Clear(); deniedUacPrograms.AddRange(settings.DeniedUacApplications);
        // Hidden probes and standalone previews must not read deployment or policy.
        uacCapabilities = core is null ? new(false, false, false, false, "预览不读取 UAC 组件状态。") : ReadUacCapabilities();
        visual = new PermissionVisual(settingsSurface: true, inputObserved: ObserveButtonInput);
        var instance = GetModuleHandleW(null);
        if (!registered)
        {
            var cls = new Class { Size = (uint)Marshal.SizeOf<Class>(), Style = 3, Proc = Marshal.GetFunctionPointerForDelegate(Proc), Instance = instance, Name = "FlowerControl.LocalPermissions" };
            if (RegisterClassExW(ref cls) == 0) throw new Boundary("permission_window_failed");
            registered = true;
        }
        var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
        if (!GetMonitorInfoW(MonitorFromWindow(owner, 2), ref monitor)) throw new Boundary("permission_work_area_unavailable");
        scale = LayoutScale(GetDpiForWindow(owner), monitor.Work.Right - monitor.Work.Left);
        if (scale < .75) throw new Boundary("permission_screen_too_small");
        var width = Math.Min(Math.Max(Px(lastWidth), Px(MinWindowWidth)), monitor.Work.Right - monitor.Work.Left - 24);
        var height = Math.Min(Math.Max(Px(lastHeight), Px(MinWindowHeight)), monitor.Work.Bottom - monitor.Work.Top - 24);
        scrollPosition = wheelRemainder = 0; Array.Clear(pageScroll); page = SettingsPage.Overview; explanationOpen = false;
        // WS_EX_COMPOSITED stays: measured wheel-frame repaint cost was 31 ms
        // with the composited surface and 50 ms without it, so stripping it was
        // a regression rather than a fix. Scrolling moves children
        // SWP_NOCOPYBITS and repaints the tree once per frame.
        window = CreateWindowExW(0x02010000 | 0x00040000, "FlowerControl.LocalPermissions", preview ? "Flower Control · 设置预览（不保存本机配置）" : "Flower Control · 本机权限与隐私", 0x00CF0000 | 0x02000000,
            monitor.Work.Left + 12, monitor.Work.Top + 12, width, height, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
        if (window == IntPtr.Zero || !SetPropW(window, "FlowerControlTaskIndicator", new IntPtr(1))) throw new Boundary("permission_window_failed");
        // Ownerless previews and a window created on a different monitor must
        // use the actual target DPI, not GetDpiForWindow(NULL)'s zero fallback.
        var actualScale = LayoutScale(GetDpiForWindow(window), monitor.Work.Right - monitor.Work.Left);
        if (Math.Abs(actualScale - scale) > .001)
        {
            scale = actualScale;
            width = Math.Min(Math.Max(Px(lastWidth), Px(MinWindowWidth)), monitor.Work.Right - monitor.Work.Left - 24);
            height = Math.Min(Math.Max(Px(lastHeight), Px(MinWindowHeight)), monitor.Work.Bottom - monitor.Work.Top - 24);
            SetWindowPos(window, IntPtr.Zero, monitor.Work.Left + 12, monitor.Work.Top + 12, width, height, 0x14);
        }
        visual.Reload(window);
        body = CreateWindowExW(0x10000, "FlowerControl.LocalPermissions", "权限与隐私设置内容", 0x56000000 | 0x00200000,
            Px(BodyLeft), Px(BodyTop), Px(ContentWidth), Math.Max(1, height - Px(BodyTop + FooterHeight)), window, new IntPtr(90), instance, IntPtr.Zero);
        if (body == IntPtr.Zero) throw new Boundary("permission_window_failed");
        visual.Attach(body, "STATIC", 0, 90);
        // The body owns a native scrollbar. Re-apply dark theming to the body
        // itself; theming its child controls did not touch the non-client bar.
        visual.ThemeBody(body);
        controls.Clear(); layout.Clear(); masks.Clear(); masks.AddRange(original.Masks);
        uacAllowlist.Clear(); uacAllowlist.AddRange(original.UacAllowlist);
        adminLaunchAllowlist.Clear(); adminLaunchAllowlist.AddRange(original.AdminLaunchAllowlist);
        Add(1000, "STATIC", "Flower Control", 68, 18, 410, 26, fixedPart: true);
        Add(2000, "STATIC", preview ? "本机权限与隐私 · 内存预览" : "本机权限与隐私", 69, 47, 510, 22, fixedPart: true);
        Add(1010, "STATIC", PageNames[(int)page], 232, 88, 680, 34, fixedPart: true);
        Add(2015, "STATIC", PageDescriptions[(int)page], 232, 130, 680, 22, fixedPart: true);
        for (int index = 0; index < NavPages.Length; index++)
            Add(300 + index, "BUTTON", PageNames[(int)NavPages[index]], 16, 98 + index * 46, 180, 40, fixedPart: true);
        Add(2016, "STATIC", "更改保留为草稿\r\n保存后才应用", 28, 398, 164, 44, fixedPart: true);
        Add(306, "BUTTON", "分区  ▾", 16, 88, 128, 38, fixedPart: true);

        buildingPage = SettingsPage.Overview;
        Add(3000, "STATIC", "Flower Control", 28, 40, 680, 30);
        Add(3001, "STATIC", "本机控制与权限一览 · 助手正在运行", 28, 70, 680, 24);
        Add(3002, "STATIC", "", 20, 160, 300, 46);
        Add(3003, "STATIC", "", 20, 160, 300, 46);
        Add(3004, "STATIC", "", 20, 160, 300, 46);
        Add(3010, "STATIC", "你现在可以做什么", 20, 230, 680, 26);
        Add(3011, "STATIC", "让 AI 操作网页、应用和屏幕", 20, 270, 520, 24);
        Add(3012, "STATIC", "直接在对话里描述任务即可；普通窗口无需额外设置。", 20, 296, 520, 22);
        Add(3015, "BUTTON", "怎么用？", 560, 270, 108, 32, 4);
        Add(3013, "STATIC", "需要管理员程序或 UAC 时", 20, 340, 520, 24);
        Add(3014, "STATIC", "先开启管理员能力，再按需开启下级开关；关闭时不影响普通控制。", 20, 366, 520, 22);
        Add(3016, "BUTTON", "去开启", 560, 340, 108, 32);
        Add(3020, "STATIC", "", 20, 420, 680, 52);
        Add(3021, "STATIC", "下一步建议", 20, 500, 680, 26);
        Add(3022, "STATIC", "先用普通控制跑一次任务；真遇到要管理员权限的程序，再回来开管理员能力；系统提示相关的问题去「系统接入」页。", 20, 530, 680, 44);

        buildingPage = SettingsPage.General;
        Add(2020, "STATIC", "鼠标始终平滑移动。", 20, 17, 680, 28);
        Add(6, "BUTTON", "折叠悬浮提示详情(&H)", 20, 107, 680, 28, 3); Check(6, original.HudCompact);
        Add(2021, "STATIC", "保留停止按钮；不需要完整详情时可以折叠。", 20, 142, 680, 22);
        Add(1002, "STATIC", "悬浮提示位置", 20, 199, 330, 24);
        Add(2023, "STATIC", "自动找空位，或固定到屏幕四角。", 20, 230, 500, 22);
        Add(7, "COMBOBOX", "", 430, 191, 270, 180, 3 | 0x00200000);
        foreach (var label in new[] { "自动找空位", "左上角", "右上角", "左下角", "右下角" }) SendMessageW(controls[7], 0x143, IntPtr.Zero, label);
        var positions = new[] { "auto", "top_left", "top_right", "bottom_left", "bottom_right" };
        SendMessageW(controls[7], 0x14e, new IntPtr(Array.IndexOf(positions, original.HudPosition)), IntPtr.Zero);
        Add(4, "BUTTON", "允许 Jev 接收过滤后的短文字候选(&J)", 20, 281, 680, 28, 3); Check(4, original.JevEnabled);
        Add(2022, "STATIC", "关闭后 Flower 不再请求 Jev；主 AI 与本地程序继续处理。外联范围按 F1 查看。", 20, 316, 680, 44);

        buildingPage = SettingsPage.Admin;
        // The legacy master/launch/UAC checkboxes remain as hidden state
        // carriers so every page and self-test keeps one source of truth.
        Add(1, "BUTTON", "", -4000, 20, 8, 8, 3); Check(1, opening.AdminWindows);
        Add(78, "BUTTON", "", -4000, 40, 8, 8, 3); Check(78, opening.AdminLaunchEnabled);
        Add(79, "BUTTON", "", -4000, 60, 8, 8, 3); Check(79, opening.UacMode != "off");
        for (int tier = 0; tier < 4; tier++) Add(3301 + tier, "BUTTON", "", 20 + tier * 170, 20, 164, 52);
        Add(2001, "STATIC", "", 20, 82, 680, 62);
        Add(2034, "STATIC", "再点一次当前档位会关掉全部四档，进入完全禁止。\r\n03、04 的「名单 / 语义授权」只决定名单外请求怎么处理，白名单与黑名单的优先级不变。", 20, 148, 680, 44);
        Add(3401, "STATIC", "管理员窗口黑名单", 20, 202, 680, 26);
        Add(3402, "EDIT", Lines(settings.DeniedAdminWindowApplications), 20, 242, 680, 112, 0x00200000 | 0x1000 | 4 | 0x40 | 0x80);
        Add(3403, "BUTTON", "从运行窗口添加…", 20, 366, 224, 36);
        Add(3404, "STATIC", "每行一个完整程序路径，可用 | 附加窗口标题条件；行首 # 停用。仅保存后生效，普通窗口的规则另行维护。", 20, 410, 680, 48);
        Add(3033, "STATIC", "下级设置", 20, 256, 680, 24);
        Add(310, "BUTTON", "启动方式与程序名单  ›", 492, 280, 208, 34);
        Add(311, "BUTTON", "配置 UAC 确认名单  ›", 492, 322, 208, 34);
        Add(3030, "STATIC", "", 20, 372, 680, 62);
        Add(3031, "BUTTON", "四档权限与语义授权  ▾ 展开", 20, 442, 680, 34, 4);
        Add(3032, "STATIC", "01 普通控制：只操作普通窗口。\r\n02 管理员窗口：可以观察与操作管理员窗口，不启动管理员进程。\r\n03 管理员执行：可以按名单或本任务授权直接启动，不制造 UAC。\r\n04 系统级接管：在 03 之上处理 UAC 观察、取消与确认；火绒类提示按实测归位。\r\n每档都有自己的黑名单，匹配到就拒绝，优先级高于白名单和语义授权。AI 不能给自己加权限。", 20, 484, 680, 140);
        Add(2009, "STATIC", "切到低档会立即收紧保存后的权限；已经在运行的程序和成果不受影响。\r\n完全禁止会同步停掉 App、Computer 与 Web；托盘、停止和暂停仍可用。", 20, 574, 680, 60);
        Add(2040, "STATIC", "", 20, 640, 680, 48);

        buildingPage = SettingsPage.Launch;
        Add(3331, "STATIC", "03 管理员执行方式", 20, 17, 680, 26);
        Add(3311, "BUTTON", "名单模式", 20, 55, 224, 36);
        Add(3312, "BUTTON", "语义授权", 254, 55, 224, 36);
        Add(2035, "STATIC", "", 20, 100, 680, 48);
        AddBlockedProgramControls(ProgramListKind.Launch);
        Add(2209, "STATIC", "直接启动属于第 03 档：先在「管理员能力」页选 03，再在这里维护名单。", 20, 17, 680, 44);
        Add(2006, "STATIC", "", 20, 112, 680, 68);
        Add(1005, "STATIC", "已批准程序", 20, 200, 400, 25);
        Add(62, "BUTTON", "添加程序…  ▾", 488, 239, 212, 36);
        Add(63, "BUTTON", "按键选择窗口(&G)", 20, 239, 224, 34);
        Add(76, "BUTTON", "从运行窗口选择…(&W)", 254, 239, 224, 34);
        Add(77, "BUTTON", "选择程序文件…", 488, 239, 212, 34);
        Add(2100, "STATIC", "按键选择：切到目标窗口后按 Ctrl+Alt+8，30 秒内有效。\r\n选择只提出候选，核对身份并确认后加入草稿；文件选择作兜底。", 20, 284, 680, 44);
        Add(66, "LISTBOX", "", 20, 339, 680, 96, 0x00200000 | 0x100 | 1);
        Add(2008, "EDIT", "", 20, 445, 680, 104, 0x00200000 | 0x800 | 4 | 0x40);
        Add(64, "BUTTON", "启用 / 停用条目(&V)", 20, 559, 330, 34);
        Add(65, "BUTTON", "移除条目(&Z)", 360, 559, 340, 34);
        Add(2101, "STATIC", "新登记仅批准无参数启动；旧准确参数只读保留。窗口、启动器和关联程序不继承授权。", 20, 603, 680, 26);
        Add(2007, "STATIC", "直接启动只用原 High，不准备或启用 SYSTEM。关闭 UAC 不撤销启动许可。\r\n关闭启动也关闭 UAC，重新开启不自动恢复；撤权不关闭已启动的成果程序。", 20, 648, 680, 48);

        buildingPage = SettingsPage.Uac;
        Add(3332, "STATIC", "04 UAC 确认方式", 20, 17, 680, 26);
        Add(3321, "BUTTON", "名单模式", 20, 55, 224, 36);
        Add(3322, "BUTTON", "语义授权", 254, 55, 224, 36);
        Add(2036, "STATIC", "", 20, 100, 680, 48);
        AddBlockedProgramControls(ProgramListKind.Uac);
        Add(2210, "STATIC", "UAC 处理属于第 04 档：先在「管理员能力」页选 04，系统接入未就绪时不会切换。", 20, 17, 680, 44);
        Add(2106, "STATIC", "", 20, 112, 680, 120);
        Add(3040, "STATIC", "", 20, 60, 680, 62);
        Add(3041, "BUTTON", "UAC 后备的能力与边界  ▾ 展开", 20, 130, 680, 34, 4);
        Add(3042, "STATIC", "SYSTEM 权限高于管理员，只走已准备的同版受限入口，不会常驻。\r\n取消和确认绑定到准确的那一条提示；过期、归属不明、明确拒绝都会停。\r\n确认只批准名单里程序的空参数提示；名单与「直接启动」那份互相独立，不会自动导入。\r\n关闭时停用 SYSTEM 入口、取消在途请求，保留历史回执，不清未知结果。\r\n火绒之类的安全软件提示不归这一项管。", 20, 170, 680, 120);
        Add(2032, "STATIC", "取消范围", 20, 258, 680, 22);
        Add(81, "COMBOBOX", "", 20, 290, 680, 190, 3 | 0x00200000);
        Add(1008, "STATIC", "UAC 确认名单", 20, 356, 680, 25);
        Add(162, "BUTTON", "添加程序…  ▾", 488, 446, 212, 36);
        Add(2211, "STATIC", "与直接启动名单独立，不互相导入。观察和取消仍为逐次动作，不因出现提示自动 Esc。", 20, 391, 680, 44);
        Add(163, "BUTTON", "按键选择 UAC 程序", 20, 446, 224, 34);
        Add(176, "BUTTON", "从运行窗口选择…", 254, 446, 224, 34);
        Add(177, "BUTTON", "选择程序文件…", 488, 446, 212, 34);
        Add(166, "LISTBOX", "", 20, 491, 680, 96, 0x00200000 | 0x100 | 1);
        Add(2108, "EDIT", "", 20, 597, 680, 112, 0x00200000 | 0x800 | 4 | 0x40);
        Add(164, "BUTTON", "启用 / 停用 UAC 条目", 20, 719, 330, 34);
        Add(165, "BUTTON", "移除 UAC 条目", 360, 719, 340, 34);
        Add(2033, "STATIC", "仅批准准确程序的空参数 UAC 确认；不会批准直接启动。\r\n不输入密码、不解锁、不修改自身权限。", 20, 766, 680, 48);

        buildingPage = SettingsPage.Privacy;
        Add(1003, "STATIC", "禁止程序", 20, 17, 420, 25);
        Add(13, "BUTTON", "从运行窗口添加(&N)", 476, 13, 224, 34);
        Add(2003, "STATIC", "优先于允许名单。行首 # 停用规则；Web 标题规则保护整个浏览器。\r\n这些规则仅限制 Flower，不限制其它插件或 Shell。", 20, 54, 680, 44);
        Add(11, "EDIT", Lines(original.DeniedApplications), 20, 109, 680, 108, 0x00200000 | 0x1000 | 4 | 0x40 | 0x80);
        Add(1004, "STATIC", "截图遮挡", 20, 267, 680, 25);
        Add(20, "BUTTON", "选择需要遮挡的窗口…(&W)", 20, 305, 260, 34);
        Add(21, "EDIT", "", 290, 305, 410, 34, 0x800);
        Add(2004, "STATIC", "按客户区物理像素填写；窗口尺寸变化后需重新选择。", 20, 350, 680, 24);
        for (int i = 0; i < 4; i++)
        {
            Add(2010 + i, "STATIC", new[] { "左(&X)", "上(&Y)", "宽(&I)", "高(&E)" }[i], 20 + 98 * i, 385, 86, 22);
            Add(22 + i, "EDIT", "0", 20 + 98 * i, 414, 86, 34, 0x2000);
        }
        Add(26, "BUTTON", "添加遮挡(&B)", 422, 414, 132, 34);
        Add(27, "BUTTON", "移除选中(&R)", 564, 414, 136, 34);
        Add(28, "LISTBOX", "", 20, 460, 680, 128, 0x00200000 | 0x100 | 1); RefreshMasks();
        Add(2005, "STATIC", "截图交给主 AI 后仍进入宿主的数据处理范围。\r\n更改只保留在本页草稿，保存后才应用。", 20, 604, 680, 48);

        buildingPage = SettingsPage.Validation;
        Add(1006, "STATIC", "立即执行的系统操作", 20, 17, 680, 25);
        Add(2102, "STATIC", "仅 UAC 后备需要此接入，直接启动不需要 SYSTEM。\r\n首次安装确认由你处理；后续无害测试 UAC 不要手点。\r\n停用只关闭 UAC，保留启动许可、名单和记录。", 20, 54, 680, 66);
        Add(67, "BUTTON", "准备 UAC 系统接入(&1)", 20, 132, 330, 34);
        Add(68, "BUTTON", "关闭 UAC / 停用接入(&D)", 360, 132, 340, 34);
        Add(69, "BUTTON", "仅测试一次 Esc(&E)", 20, 211, 270, 34);
        Add(72, "BUTTON", "运行 5 项受限验证(&2)", 300, 211, 400, 34);
        Add(2103, "STATIC", "5 次无害提示包括取消、确认和三类固定程序校准，由 Flower 自行处理。\r\n失败或结果未知就停止，不重放；只测同版程序，不改模式、名单或 Stop。", 20, 257, 680, 66);
        Add(73, "BUTTON", "单独测试物理 Stop(&3)", 20, 363, 680, 34);
        Add(2104, "STATIC", "需要你操作：提示出现后按 Ctrl+Alt+9，随后由你按 Esc 取消。\r\nStop 只停止 Flower；测试后保持停止，不自动恢复。\r\n未知动作不重试。", 20, 409, 680, 66);
        Add(74, "BUTTON", "登记已有验证结果(&4)", 20, 515, 680, 34);
        Add(2105, "STATIC", "立即登记受保护的同版本真实回执，并更新派生能力；不弹新 UAC、不改模式、不恢复 Stop。\r\n关闭状态不能运行 SYSTEM 测试；先启用并保存，再做本机校准。路线验证不等于任意程序可确认。", 20, 561, 680, 66);
        Add(2212, "STATIC", "", 20, 170, 680, 44);

        // One in-page, keyboard-reachable details/confirmation area. Essential
        // permission risks remain in their sections when this area is closed.
        Add(1091, "STATIC", "详细说明", 20, 0, 680, 26);
        Add(92, "EDIT", "", 20, 32, 680, 152, 0x00200000 | 0x800 | 4 | 0x40);
        Add(93, "BUTTON", "收起说明(&R)", 20, 190, 200, 36);
        Add(95, "BUTTON", "保存并关闭(&S)", 20, 190, 200, 36);
        Add(98, "BUTTON", "放弃草稿并关闭", 240, 190, 200, 36);
        Add(99, "BUTTON", "返回编辑(&B)", 460, 190, 200, 36);
        Add(100, "BUTTON", "放弃草稿并重新载入", 20, 190, 300, 36);
        Add(96, "BUTTON", "加入当前名单草稿", 20, 190, 300, 36);
        Add(97, "BUTTON", "取消候选", 340, 190, 300, 36);

        Add(32, "BUTTON", "结束控制(&X)", 24, 25, 148, 36, fixedPart: true, footer: true);
        Add(40, "STATIC", "", 192, 20, 360, 48, fixedPart: true, footer: true);
        Add(30, "BUTTON", preview ? "保存到预览(&S)" : "保存并立即应用(&S)", 632, 25, 178, 36, 1, fixedPart: true, footer: true);
        Add(31, "BUTTON", "取消(&C)", 822, 25, 112, 36, fixedPart: true, footer: true);
        Add(91, "BUTTON", "说明 · F1", 174, 25, 100, 36, fixedPart: true, footer: true);
        Add(94, "BUTTON", "重新载入", 286, 25, 112, 36, fixedPart: true, footer: true);
        // The three capability switches live on the admin page, exactly like the
        // prototype; the launch and UAC pages only manage their own lists.
        for (int index = 0; index < layout.Count; index++)
            if (GetDlgCtrlID(layout[index].Handle) is 78 or 79 or 2209 or 2210)
                layout[index] = layout[index] with { Page = SettingsPage.Admin };
        // Retired switches carry state only. Exclude them and their retired
        // descriptions from layout, hit-testing, keyboard focus and audits.
        foreach (int id in new[] { 1, 78, 79, 2209, 2210 }) ShowWindow(controls[id], 0);
        layout.RemoveAll(item => GetDlgCtrlID(item.Handle) is 1 or 78 or 79 or 2209 or 2210);
        RefreshBlockedPrograms(ProgramListKind.Launch); RefreshBlockedPrograms(ProgramListKind.Uac);
        RefreshUacAllowlist(); RefreshUacAllowlist(kind: ProgramListKind.Launch); UpdateUacControls();
        visual.SelectPage(NavIndex(page));
        Relayout(); UpdateScroll();
        controlBaseline = EditedSettings();      // normalized opening state
        if (roleSnapshot is not null) ApplyRoleSurface(roleSnapshot, settings);
        help = new SettingsTooltips(window);
        foreach (var item in layout)
        { string hint = PermissionHelp.Short(GetDlgCtrlID(item.Handle)); if (hint.Length > 0) help.Register(item.Handle, hint); }
        if (SystemParametersInfoW(0x100a, 0, out var cues, 0) && cues == 0)
            SendMessageW(window, 0x127, new IntPtr((3 << 16) | 1), IntPtr.Zero);
        if (display)
        {
            ShowWindow(window, 5); if (!IsWindowVisible(window)) ShowWindow(window, 5);
            help?.Refresh(); PresentSettings();
            if (broker is not null && SetTimer(window, StopStatusTimer, 800, IntPtr.Zero) == UIntPtr.Zero)
                SetNotice("停止状态不能自动刷新；可重新载入查看，结束控制仍可用。");
        }
    }
    internal static object NativeLayoutProbe()
    {
        // Synthetic, hidden settings only. No policy read/write, input, broker
        // connection, tray registration, production Stop, or focus change.
        var settings = new UserPermissionSettings { UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value };
        int assertions = 0;
        bool visibleScrollRepaint = false;
        void Require(bool value, [System.Runtime.CompilerServices.CallerArgumentExpression("value")] string assertion = "")
        {
            assertions++;
            if (!value) { Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { fixture = "settings-layout", assertions, assertion }));
                throw new Boundary("permission_window_picker_probe_failed"); }
        }
        void CheckFieldFrames()
        {
            Require(GetClientRect(body, out var viewport));
            var frames = visual!.FieldFrames(body).ToArray();
            var expected = new HashSet<IntPtr>();
            foreach (var field in layout.Where(item => !item.Fixed && item.Kind is "EDIT" or "LISTBOX"))
            {
                Require(GetWindowRect(field.Handle, out var bounds));
                var position = new Native.Point { X = bounds.Left, Y = bounds.Top };
                Require(ScreenToClient(body, ref position));
                bool intersects = position.X - 1 < viewport.Right && position.X + bounds.Right - bounds.Left + 1 > 0
                    && position.Y - 1 < viewport.Bottom && position.Y + bounds.Bottom - bounds.Top + 1 > 0;
                if ((GetWindowLongW(field.Handle, -16) & 0x10000000) != 0 && intersects) expected.Add(field.Handle);
            }
            Require(expected.SetEquals(frames.Select(frame => frame.Handle)));
            Require(frames.All(frame => frame.Bounds.Left < viewport.Right && frame.Bounds.Right > 0
                && frame.Bounds.Top < viewport.Bottom && frame.Bounds.Bottom > 0));
            if (page is SettingsPage.General or SettingsPage.Validation) Require(frames.Length == 0);
        }
        IntPtr owned = IntPtr.Zero, ordinary = IntPtr.Zero;
        bool originalPreview = preview;
        try
        {
            Create(IntPtr.Zero, null, settings, false);
            // The compact rail popup and the rail buttons must share one map.
            Require(NavPageFor(0) == SettingsPage.Overview && NavPageFor(1) == SettingsPage.General
                && NavPageFor(2) == SettingsPage.Admin && NavPageFor(3) == SettingsPage.Uac
                && NavPageFor(4) == SettingsPage.Privacy && NavPageFor(5) == SettingsPage.Validation);
            Require(!controls.ContainsKey(70) && !controls.ContainsKey(71) && !controls.ContainsKey(75));
            Require(new[] { 63, 76, 77 }.All(controls.ContainsKey));
            Require(new[] { 1, 78, 79, 81, 163, 164, 165, 166, 176, 177 }.All(controls.ContainsKey));
            Require(new[] { 2, 10, 12, 80 }.All(id => !controls.ContainsKey(id)));
            Require(EditedSettings() is { AdminWindows: true, AdminLaunchEnabled: false, UacMode: "off" });
            // A representable draft is separate from permission to save or run.
            Require(UacSelectionAvailable("semantic", new(true, true, true, true, "fixture")));
            Require(HostWindow.PrivilegeSummary(settings with { AdminWindows = false, AdminLaunchEnabled = true, UacMode = "allowlist" }).Contains("管理员能力关闭", StringComparison.Ordinal));
            Require(HostWindow.PrivilegeSummary(settings with { AdminLaunchEnabled = false, UacMode = "allowlist" }).Contains("不启动管理员进程", StringComparison.Ordinal));
            Require(HostWindow.PrivilegeSummary(settings with { AdminLaunchEnabled = true }).Contains("管理员执行", StringComparison.Ordinal));
            void Click(int id, bool value)
            {
                Check(id, value); HandleMessage(window, 0x111, new UIntPtr((uint)id), controls[id]);
            }
            Click(78, true); Click(79, true);
            Require(EditedSettings() is { AdminLaunchEnabled: true, UacMode: "allowlist" });
            Require(original is { AdminLaunchEnabled: false, UacMode: "off" });
            Click(1, false);
            Require(EditedSettings() is { AdminWindows: false, AdminLaunchEnabled: false, UacMode: "off" });
            Click(1, true);
            Require(!Checked(78) && !Checked(79));
            Click(78, true); Click(79, true); Click(78, false); Click(78, true);
            Require(EditedSettings().UacMode == "off" && !Checked(79));
            uacMode = "observe"; Check(79, true); UpdateUacControls();
            Require(EditedSettings().UacMode == "observe");
            uacMode = "cancel"; UpdateUacControls(); Require(EditedSettings().UacMode == "cancel");
            Click(79, false); Click(79, true); Require(EditedSettings().UacMode == "allowlist");
            uacMode = "off"; Check(79, false); UpdateUacControls();
            var launchRule = new UacApplicationPermission(@"C:\Fixture\Launch.exe", "sha256", new string('a', 64), "启动", true, "");
            var uacRule = launchRule with { Path = @"C:\Fixture\Uac.exe", DisplayName = "UAC" };
            adminLaunchAllowlist.Add(launchRule); uacAllowlist.Add(uacRule);
            Require(EditedSettings().AdminLaunchAllowlist.SequenceEqual(new[] { launchRule }));
            Require(EditedSettings().UacAllowlist.SequenceEqual(new[] { uacRule }));
            Require(original!.AdminLaunchAllowlist.Length == 0 && original.UacAllowlist.Length == 0);
            RefreshUacAllowlist(0, ProgramListKind.Launch); RefreshUacAllowlist(0, ProgramListKind.Uac);
            Require(Text(2008).Contains("Launch.exe", StringComparison.Ordinal));
            Require(Text(2108).Contains("Uac.exe", StringComparison.Ordinal));
            adminLaunchAllowlist.Clear();
            Require(uacAllowlist.Count == 1 && EditedSettings().AdminLaunchAllowlist.Length == 0);
            uacAllowlist.Clear();
            // Hidden probe does not write even preview settings; draft isolation
            // is checked against the original immutable record above.
            original = settings; Click(1, true); Click(78, false);
            Require(LayoutScale(192, 800) == 2); // Narrow monitors cannot shrink fonts.
            Require(help is not null && help.Count > 35);
            foreach (int id in new[] { 1, 4, 6, 78, 79 }) Require((GetWindowLongW(controls[id], -16) & 15) == 3);
            Require(!controls.ContainsKey(5) && GetDlgItem(body, 5) == IntPtr.Zero);
            Require(Text(2020) == "鼠标始终平滑移动。");
            var generalLayout = PermissionPageLayout.Build(0, 720, (_, _) => 28);
            Require(!generalLayout.Controls.ContainsKey(5) && generalLayout.Controls.ContainsKey(2020));
            Require(SameSettings(settings, settings with { Revision = "changed" }));
            Require(!SameSettings(settings, settings with { SmoothPointer = !settings.SmoothPointer }));
            Require(!SameSettings(settings, settings with { AdminScope = "allowlist" }));
            var enabledBaseline = settings with { AdminLaunchEnabled = true, UacMode = "allowlist" };
            Require(OnlyUacDisabled(enabledBaseline, enabledBaseline with { Revision = "next", UacMode = "off" }));
            Require(!OnlyUacDisabled(enabledBaseline, enabledBaseline with { Revision = "next", UacMode = "off", AdminWindows = false }));
            Require(!OnlyUacDisabled(enabledBaseline, enabledBaseline with { Revision = "next", UacMode = "off", SmoothPointer = true }));
            Require(!OnlyUacDisabled(enabledBaseline, enabledBaseline with { Revision = "next", UacMode = "off", AdminScope = "allowlist" }));
            Require(!OnlyUacDisabled(enabledBaseline, enabledBaseline));
            Check(6, true); original = enabledBaseline;
            ReconcileImmediateDisable(enabledBaseline with { Revision = "next", UacMode = "off" });
            Require(original.Revision == "next" && Checked(6) && !Checked(79) && !conflict && Dirty);
            ReconcileImmediateDisable(enabledBaseline with { Revision = "external", UacMode = "off", AdminWindows = false });
            Require(conflict && original.Revision == "next" && Checked(6));
            conflict = false; original = settings;
            Require((GetWindowLongW(controls[30], -16) & 15) == 11); // Owner-draw survives default-button styling.
            SendMessageW(controls[30], 0xF4, new IntPtr(1), new IntPtr(1));
            Require((GetWindowLongW(controls[30], -16) & 15) == 11);
            bool savedCompact = original!.HudCompact;
            ShowPage(SettingsPage.General); Check(6, !savedCompact);
            ShowPage(SettingsPage.Admin); Require(Checked(6) == !savedCompact && EditedSettings().HudCompact == !savedCompact);
            Require(original.HudCompact == savedCompact);
            var colorDc = GetDC(body);
            Require(colorDc != IntPtr.Zero);
            try
            {
                var editableBrush = SendMessageW(body, 0x133, colorDc, controls[11]);
                var readOnlyBrush = SendMessageW(body, 0x138, colorDc, controls[2008]);
                var staticBrush = SendMessageW(body, 0x138, colorDc, controls[2001]);
                Require(editableBrush != IntPtr.Zero && readOnlyBrush == editableBrush);
                Require(staticBrush != editableBrush);
            }
            finally { ReleaseDC(body, colorDc); }
            Require(uacWindowPick is null);
            int released = 0;
            var selection = new UacWindowPick(4, 100, 7, false, () => released++);
            Require(selection.Generation == 4 && selection.StopEpoch == 7 && !selection.WasPaused && selection.Kind == ProgramListKind.Uac);
            using var launchSelection = new UacWindowPick(4, 100, 7, false, () => { }, ProgramListKind.Launch);
            Require(launchSelection.Kind == ProgramListKind.Launch && selection.Kind == ProgramListKind.Uac);
            Require(!selection.Expired(99) && selection.Expired(100));
            selection.Dispose(); selection.Dispose(); Require(released == 1);
            var pending = new TaskCompletionSource(); var newer = new TaskCompletionSource();
            var ownedWork = new OwnedWork(); ownedWork.Track(pending.Task); ownedWork.Track(newer.Task);
            newer.SetResult(); var drain = ownedWork.Drain();
            Require(ownedWork.Busy && !drain.IsCompleted);
            pending.SetResult(); drain.GetAwaiter().GetResult(); Require(!ownedWork.Busy);
            var deliveryPending = new TaskCompletionSource(); ownedWork.Track(deliveryPending.Task, affectsBusy: false);
            var deliveryDrain = ownedWork.Drain(); Require(!ownedWork.Busy && !deliveryDrain.IsCompleted);
            deliveryPending.SetResult(); deliveryDrain.GetAwaiter().GetResult();
            Require(SelectionMatches(4, 7, false, 4, 7, false));
            Require(!SelectionMatches(4, 7, false, 4, 8, false));
            Require(!SelectionMatches(4, 7, false, 4, 7, true));
            Require(!SelectionMatches(4, 7, false, 5, 7, false));
            var peer = new Peer(10, 20, 1, "fixture-user", "", 8192);
            Require(WindowCandidateMatches(peer, @"C:\Fixture\Editor.exe", peer, @"c:\fixture\editor.exe"));
            Require(!WindowCandidateMatches(peer, @"C:\Fixture\Editor.exe", peer with { Created = 21 }, @"C:\Fixture\Editor.exe"));
            Require(!WindowCandidateMatches(peer, @"C:\Fixture\Editor.exe", peer with { Pid = 11 }, @"C:\Fixture\Editor.exe"));
            Require(!WindowCandidateMatches(peer, @"C:\Fixture\Editor.exe", peer with { Session = 2 }, @"C:\Fixture\Editor.exe"));
            Require(!WindowCandidateMatches(peer, @"C:\Fixture\Editor.exe", peer, @"C:\Fixture\Other.exe"));
            owned = CreateWindowExW(0, "STATIC", "Owned hidden probe", 0x80000000, 0, 0, 10, 10,
                window, IntPtr.Zero, GetModuleHandleW(null), IntPtr.Zero);
            ordinary = CreateWindowExW(0, "STATIC", "Ordinary hidden probe", 0x80000000, 0, 0, 10, 10,
                IntPtr.Zero, IntPtr.Zero, GetModuleHandleW(null), IntPtr.Zero);
            Require(owned != IntPtr.Zero && ordinary != IntPtr.Zero);
            Require(Native.ProtectedWindowOrOwner(owned));
            Require(!Native.ProtectedWindowOrOwner(ordinary));
            // Reading/selecting legacy rows must never replace unknown or
            // previously exact arguments with the new empty-argument default.
            preview = true;
            var unknown = new UacApplicationPermission(@"C:\Fixture\Old.exe", "sha256", new string('a', 64), "旧未知规则", false);
            var exact = unknown with { DisplayName = "旧准确规则", Arguments = "--existing=exact", Enabled = true };
            uacAllowlist.Add(unknown); uacAllowlist.Add(exact);
            RefreshUacAllowlist(0); Require(uacAllowlist[0] == unknown && uacAllowlist[0].Arguments is null);
            RefreshUacAllowlist(1); Require(uacAllowlist[1] == exact && uacAllowlist[1].Arguments == "--existing=exact");
            foreach (var factor in new[] { 1.0, 1.5, 2.0 })
            foreach (var logicalWidth in new[] { 984, 760, 480 })
            {
                scale = factor; scrollPosition = 0;
                SetWindowPos(window, IntPtr.Zero, 0, 0, Px(logicalWidth), Px(620), 0x1c);
                Relayout();
                GetClientRect(window, out var rootRect);
                Require(compactNavigation == (rootRect.Right / scale < PermissionPageLayout.NavigationThreshold || rootRect.Bottom / scale < 560));
                foreach (int id in new[] { 30, 31, 32, 91, 94, 40 })
                { var box = positioned[id]; Require(box.X >= 0 && Px(box.X + box.W) <= rootRect.Right && box.Y >= 0 && Px(box.Y + box.H) <= rootRect.Bottom); }
                foreach (var current in Enum.GetValues<SettingsPage>())
                {
                    ShowPage(current); UpdateScroll();
                    var sections = activeLayout!.Sections;
                    Require(sections.Zip(sections.Skip(1), (left, right) => left.Top + left.Height <= right.Top).All(value => value));
                    Require(GetClientRect(body, out var bodyRect));
                    // Boxes may live in a card, a warning banner, the hero band
                    // or a status chip; each region must still contain its box.
                    var regions = sections.Select(item => (item.Top, item.Height))
                        .Concat(activeLayout.Banners).Concat(activeLayout.Heroes)
                        .Concat(activeLayout.Chips.Select(chip => (chip.Top, chip.Height))).ToArray();
                    foreach (var box in activeLayout.Controls.Values)
                    { Require(box.X >= 0 && Px(box.X + box.W) <= bodyRect.Right); Require(regions.Any(region => box.Y >= region.Top && box.Y + box.H <= region.Top + region.Height)); }
                    CheckFieldFrames();
                    // A page control that has scrolled entirely out of the body
                    // viewport is hidden on purpose: Windows keeps hit-testing
                    // children outside the parent's client area, so an offscreen
                    // window would swallow clicks on the fixed chrome.
                    foreach (var item in layout.Where(item => !item.Fixed))
                    {
                        int probeId = GetDlgCtrlID(item.Handle);
                        bool expectedVisible = item.Page == current && activeLayout.Controls.TryGetValue(probeId, out var probeBox)
                            && ScrollVisible(probeBox.Y, Px(item.Kind == "COMBOBOX" ? Math.Max(190, probeBox.H) : probeBox.H), bodyRect.Bottom);
                        Require(((GetWindowLongW(item.Handle, -16) & 0x10000000) != 0) == expectedVisible);
                    }
                    Scroll(7); int bottom = scrollPosition;
                    CheckFieldFrames();
                    Require(bottom >= 0 && bottom <= Px(PageHeights[(int)current]));
                    foreach (var item in layout.Where(item => !item.Fixed && item.Page == current && activeLayout.Controls.ContainsKey(GetDlgCtrlID(item.Handle))))
                    {
                        Require(GetWindowRect(item.Handle, out var moved));
                        var at = new Native.Point { X = moved.Left, Y = moved.Top };
                        Require(ScreenToClient(body, ref at));
                        var box = activeLayout.Controls[GetDlgCtrlID(item.Handle)];
                        Require(at.Y == Px(box.Y) - bottom && at.X == Px(box.X));
                        Require(moved.Right - moved.Left == Px(box.W));
                    }
                    Scroll(6); Require(scrollPosition == 0);
                    CheckFieldFrames();
                    Scroll(7); Require(scrollPosition == bottom);
                    Scroll(6);
                }
            }
            // Real paint check: the scrolled surface must actually change. A
            // hidden window can still paint into a memory DC through
            // WM_PRINTCLIENT, so this needs no foreground window or input.
            scale = 1; SetWindowPos(window, IntPtr.Zero, 0, 0, Px(WindowWidth), Px(WindowHeight), 0x1c); Relayout();
            ShowPage(SettingsPage.Uac);
            if (GetClientRect(body, out var paintViewport) && paintViewport.Right > 40 && paintViewport.Bottom > 40)
            {
                string Signature()
                {
                    int width = Math.Min(paintViewport.Right, 360), height = Math.Min(paintViewport.Bottom, 240);
                    var screen = GetDC(body); var memory = CreateCompatibleDC(screen); var bitmap = CreateCompatibleBitmap(screen, width, height);
                    var previous = SelectObject(memory, bitmap);
                    try
                    {
                        SendMessageW(body, 0x318, memory, new IntPtr(4));   // WM_PRINTCLIENT, PRF_CLIENT
                        var text = new StringBuilder();
                        for (int y = 2; y < height; y += 6)
                            for (int x = 2; x < width; x += 6)
                                text.Append(GetPixel(memory, x, y).ToString("x8"));
                        return text.ToString();
                    }
                    finally { SelectObject(memory, previous); DeleteObject(bitmap); DeleteDC(memory); ReleaseDC(body, screen); }
                }
                scrollPosition = 0; PositionControls(); UpdateScroll();
                string atTop = Signature();
                Scroll(3);
                string atBottom = Signature();
                visibleScrollRepaint = atTop.Length > 200 && atBottom.Length > 200 && atTop != atBottom;
                Require(visibleScrollRepaint);
            }
            var stableOriginal = original;
            foreach (int id in new[] { 13, 20, 63, 76, 77, 163, 176, 177, 67, 68, 69, 72, 73, 74 })
            { HandleMessage(window, 0x111, new UIntPtr((uint)id), IntPtr.Zero); Require(original == stableOriginal && !UacBusy && pendingProgram is null); }
            Require(PermissionHelp.Detail(4).Contains("遥测", StringComparison.Ordinal));
            Require(PermissionHelp.Detail(79).Contains("SYSTEM", StringComparison.Ordinal));
            foreach (int id in new[] { 67, 68, 69, 72, 73, 74 }) Require(PermissionHelp.PageDetail(5).Contains(PermissionHelp.Short(id), StringComparison.Ordinal));
            for (int current = 0; current < 7; current++) Require(PermissionHelp.PageDetail(current).Length > 100);
            // Preference-only changes are dirty without changing a capability.
            SetTier(2); uacSubmode = uiBaselineSubmode = "allowlist";
            uiPreference = new("allowlist", "synthetic-ui-old");
            controlBaseline = EditedSettings(); original = controlBaseline;
            Require(!Dirty);
            uacSubmode = "semantic"; UpdateUacControls();
            Require(Dirty && SameSettings(controlBaseline, EditedSettings()) && EditedSettings().UacMode == "off");
            var preferenceSubmitted = EditedSettings() with { Revision = new string('d', 64) };
            closeAfterSave = true;
            CompleteSave(preferenceSubmitted, true, preferenceSubmitted,
                new("semantic", Error: "synthetic_preference_write_failure", PolicyWritten: true));
            Require(Native.IsWindow(window) && !closeAfterSave && Dirty);
            Require(original == preferenceSubmitted && SameSettings(controlBaseline!, EditedSettings()));
            Require(uiBaselineSubmode == "allowlist" && uacSubmode == "semantic");
            CompleteSave(preferenceSubmitted, false, preferenceSubmitted,
                new("semantic", new("semantic", "synthetic-ui-new")));
            Require(!Dirty && uiBaselineSubmode == "semantic" && uiPreference.UacSubmode == "semantic");
            previewSaved = preferenceSubmitted;
            uacSubmode = "allowlist"; Require(Dirty);
            ReloadSaved();
            Require(!Dirty && CurrentTier() == 2 && uacMode == "off" && uacSubmode == "semantic");
            // A late acknowledgement cannot mark a newer mode edit as saved.
            uacSubmode = "allowlist";
            CompleteSave(preferenceSubmitted, false, preferenceSubmitted,
                new("semantic", new("semantic", "synthetic-ui-new")));
            Require(Dirty && uacSubmode == "allowlist" && uiBaselineSubmode == "semantic");
            Require(!RefreshCapabilitiesAfterWork("save", true));
            Require(RefreshCapabilitiesAfterWork("save", false));
            Require(RefreshCapabilitiesAfterWork("disable", true));
            // A downgrade can need persistence without changing the visible mode.
            uiPreference = new("allowlist", "synthetic-old");
            uiBaselineSubmode = uacSubmode = "semantic"; uiPreferencePending = false;
            CompleteSave(preferenceSubmitted, false, preferenceSubmitted,
                new("semantic", Error: "synthetic_downgrade_preference_failure", PolicyWritten: true));
            Require(Dirty && uiPreferencePending && SameSettings(controlBaseline!, EditedSettings()));
            Require(UserPermissions.UiPreferenceNeedsSave(original!.UacMode, EditedSettings().UacMode,
                uacSubmode, uiBaselineSubmode, uiPreference, uiPreferencePending));
            CompleteSave(preferenceSubmitted, false, preferenceSubmitted,
                new("semantic", new("semantic", "synthetic-retry")));
            Require(!Dirty && !uiPreferencePending);
            // An unrelated settings save must not be held by a newer UI file.
            uiPreference = new("allowlist", "opaque", "settings_ui_preferences_unsupported");
            uiBaselineSubmode = uacSubmode = "allowlist";
            CompleteSave(preferenceSubmitted, false, preferenceSubmitted,
                new("allowlist", PolicyWritten: true, PreferenceRequested: false));
            Require(!Dirty && uiPreference.Error == "settings_ui_preferences_unsupported");
            uiPreference = new(); uiBaselineSubmode = uacSubmode = "allowlist";
            // Exercise the real asynchronous success branch with owned synthetic
            // replies, including consecutive saves and a later immediate off.
            foreach (char revision in new[] { 'a', 'b' })
            {
                Check(6, !Checked(6)); Require(Dirty);
                OpenPanel("close", "synthetic", "synthetic unsaved edits");
                var committed = EditedSettings() with { Revision = new string(revision, 64) };
                long token = ++workGeneration;
                uacReplies[token] = new(windowGeneration, "save", null, committed);
                WindowProc(window, UacWorkFinished, new UIntPtr((ulong)token), IntPtr.Zero);
                Require(Native.IsWindow(window) && original == committed && !Dirty && detailMode == "");
            }
            var savedBeforeOff = EditedSettings() with { Revision = new string('c', 64) };
            conflict = true; uacMode = "off"; Check(79, false);
            long offToken = ++workGeneration;
            uacReplies[offToken] = new(windowGeneration, "save", null, savedBeforeOff, true);
            WindowProc(window, UacWorkFinished, new UIntPtr((ulong)offToken), IntPtr.Zero);
            Require(Native.IsWindow(window) && conflict && uacMode == "off" && !Checked(79));
            conflict = false;
            long staleToken = ++workGeneration; var beforeStale = original;
            uacReplies[staleToken] = new(windowGeneration - 1, "save", null, savedBeforeOff, true);
            WindowProc(window, UacWorkFinished, new UIntPtr((ulong)staleToken), IntPtr.Zero);
            Require(Native.IsWindow(window) && original == beforeStale);
            closeAfterSave = true;
            OpenPanel("close", "synthetic", "synthetic save pending");
            CloseDetails(); // The user returned to editing before completion.
            long cancelledCloseToken = ++workGeneration;
            uacReplies[cancelledCloseToken] = new(windowGeneration, "save", null, EditedSettings(), true);
            WindowProc(window, UacWorkFinished, new UIntPtr((ulong)cancelledCloseToken), IntPtr.Zero);
            Require(Native.IsWindow(window) && !closeAfterSave && !Dirty);
            closeAfterSave = true;
            long closeToken = ++workGeneration;
            uacReplies[closeToken] = new(windowGeneration, "save", null, EditedSettings(), true);
            WindowProc(window, UacWorkFinished, new UIntPtr((ulong)closeToken), IntPtr.Zero);
            Require(!Native.IsWindow(window));
            return new { assertions, hiddenWindow = true, nativeInputExecuted = false, policyReadOrWritten = false,
                foregroundChanged = false, responsiveDpiLayoutVerified = true, previewRealCommandsBlocked = true,
                currentPageFieldFramesVerified = true, visibleScrollRepaintVerified = visibleScrollRepaint };
        }
        finally
        {
            if (owned != IntPtr.Zero) DestroyWindow(owned);
            if (ordinary != IntPtr.Zero) DestroyWindow(ordinary);
            preview = originalPreview; CloseAfterFailure();
        }
    }
    private static void Add(int id, string kind, string text, int x, int y, int w, int h, uint extra = 0, bool fixedPart = false, bool footer = false)
    {
        // Owner-draw pushbuttons use WM_DRAWITEM, including the dialog
        // manager's default-button redraw. Checkboxes keep BS_AUTOCHECKBOX
        // so their native check state and accessibility remain authoritative.
        uint nativeExtra = kind == "BUTTON" && (extra & 15) != 3 ? (extra & ~15u) | 11 : extra;
        // Text that sits on the hero / chip / banner artwork must not erase its
        // own background, or it punches an opaque rectangle through the gradient.
        uint exStyle = id is 3000 or 3001 or 3002 or 3003 or 3004 or 3020 or 3030 or 3040 ? 0x00000020u : 0u;
        var control = CreateWindowExW(exStyle, kind, text,
            0x50000000 | (kind == "STATIC" ? 0u : 0x10000u) | nativeExtra, Px(x), Px(y), Px(w), Px(h), fixedPart ? window : body, new IntPtr(id), GetModuleHandleW(null), IntPtr.Zero);
        if (control == IntPtr.Zero) throw new Boundary("permission_control_failed");
        layout.Add(new(control, kind, x, y, w, h, fixedPart, footer, buildingPage));
        visual!.Attach(control, kind, extra, id, onCard: !fixedPart);
        SendMessageW(control, 0x30, GetStockObject(17), new IntPtr(1));
        if (id != 0) controls[id] = control;
        if (kind == "EDIT") SendMessageW(control, 0xC5, new IntPtr(id is 10 or 11 or 92 or 2008 or 2108 or 3402 ? 32768 : 2048), IntPtr.Zero);
    }
    private static void Check(int id, bool value) => SendMessageW(controls[id], 0xF1, new IntPtr(value ? 1 : 0), IntPtr.Zero);
    private static bool Checked(int id) => SendMessageW(controls[id], 0xF0, IntPtr.Zero, IntPtr.Zero).ToInt64() == 1;
    private static string Text(int id) { var value = new StringBuilder(32769); GetWindowTextW(controls[id], value, value.Capacity); return value.ToString(); }
    internal static ApplicationPermission[] ParseLines(string text) => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
        .Select(line => line.Trim()).Where(line => line.Length > 0).Select(line => {
            var enabled = !line.StartsWith('#'); if (!enabled) line = line[1..].Trim();
            var parts = line.Split('|', 2); return new ApplicationPermission(parts[0].Trim(), parts.Length == 2 ? parts[1].Trim() : "", enabled);
        }).ToArray();
    private static string Lines(IEnumerable<ApplicationPermission> rules) => string.Join("\r\n", rules.Select(r => (r.Enabled ? "" : "# ") + r.Path + (r.TitleContains.Length == 0 ? "" : " | " + r.TitleContains)));
    private static void RefreshMasks()
    {
        SendMessageW(controls[28], 0x184, IntPtr.Zero, IntPtr.Zero);
        foreach (var mask in masks) SendMessageW(controls[28], 0x180, IntPtr.Zero,
            $"{Path.GetFileName(mask.Path)} · {string.Join(", ", mask.Rect)} · 客户区 {mask.ClientSize[0]} × {mask.ClientSize[1]}");
    }
    internal static string UacToggleMode(string mode, bool enabled) => !enabled ? "off" : "allowlist";
    internal sealed record PrivilegePreset(bool AdminLaunchEnabled, string UacMode, string UacCancellationScope = "task");
    internal static PrivilegePreset? PresetSettings(int index) => index switch {
        0 => new(false, "off"), 1 => new(true, "off"), 2 => new(true, "cancel"), 3 => new(true, "allowlist"), _ => null };
    internal static int MatchingPreset(bool launch, string mode, string scope) => scope != "task" ? 4
        : (launch, mode) switch { (false, "off") => 0, (true, "off") => 1, (true, "cancel") => 2, (true, "allowlist") => 3, _ => 4 };
    internal static bool UacSelectionAvailable(string mode, UacCapabilities capabilities) => mode switch
    {
        "off" or "observe" => true,
        // Selection records user intent; unqualified routes remain unavailable
        // at execution. Otherwise the first-use qualification would be circular.
        "cancel" or "allowlist" or "semantic" => true,
        _ => false,
    };
    internal static bool UacCancellationScopeSelectionAvailable(string scope, string savedScope, UacCapabilities capabilities)
        => scope == "task" || scope == "selected_prompt_in_session"
            && (capabilities.CancellationScopeAvailable || savedScope == "selected_prompt_in_session");
    private static void SetCancellationScopeDraft(string scope)
    {
        if (!UacCancellationScopeSelectionAvailable(scope, original!.UacCancellationScope, uacCapabilities))
            throw new Boundary("uac_cancellation_scope_unavailable");
        uacCancellationScope = scope;
    }
    internal static string UacCancellationStatus(UacCapabilities capabilities, string scope, string mode)
    {
        string range = scope == "selected_prompt_in_session" ? "当前会话所选提示（可能含人工提示）" : "仅本任务可确认归属";
        string effective = mode is "off" or "observe" ? "关闭（当前行为不取消）"
            : scope != "selected_prompt_in_session" ? "不可用（本任务准确归属未就绪）"
            : !capabilities.CancellationScopeAvailable ? "不可用（所选提示接入未就绪）"
            : !capabilities.CancelAvailable ? "不可用（取消路线未验证）" : "可逐次核验所选提示；只取消";
        return $"取消路线：{(capabilities.CancelAvailable ? "已验证" : "未验证")}；范围：{range}\r\n取消是否有效：{effective}";
    }
    internal static bool UacAllowlistExpands(IEnumerable<UacApplicationPermission> saved, IEnumerable<UacApplicationPermission> edited)
        => edited.Any(row => row.Enabled && !saved.Any(prior => prior.Enabled && prior.IdentityKind == row.IdentityKind
            && prior.Identity == row.Identity && prior.Arguments is not null && prior.Arguments == row.Arguments
            && Path.GetFullPath(prior.Path).Equals(Path.GetFullPath(row.Path), StringComparison.OrdinalIgnoreCase)));
    private static UacCapabilities ReadUacCapabilities()
    {
        try { return UacRuntime.Capabilities(); }
        catch (Exception) { return new(false, false, false, false, "UAC 组件状态无法读取，当前不执行自动处理。") { CancellationScopeAvailable = false }; }
    }
    private static string UacModeLabel(string mode) => mode switch
    { "off" => "关闭", "observe" => "仅观察", "cancel" => "只取消", "allowlist" => "白名单确认", "semantic" => "语义授权", _ => "不可识别" };
    private static string UacReasonText(string reason) => reason.Any(c => c is >= '\u4e00' and <= '\u9fff') ? reason : reason switch
    {
        "uac_host_origin_not_authenticated" => uacCapabilities.AllowlistAvailable
            ? "本机名单确认路线已核；聊天语义来源未就绪。取消能力另按所选范围核验。"
            : "宿主来源未通过安全验证；生产确认不可用。取消能力另按所选范围核验。",
        "uac_local_allowlist_only" => "本机名单确认路线已核；聊天语义不额外放行。取消能力另按所选范围核验。",
        "verified" => "路线已有同版验证；生产执行仍逐次核准确归属、范围与授权。",
        "uac_routes_not_fully_verified" => "仍有 UAC 路径未通过同版本检查，未就绪模式不能新启用。",
        "uac_verification_version_mismatch" => "UAC 接入版本与验证记录不一致，需重新核实后才能处理。",
        "user_policy_unprotected" => "UAC 组件或验证记录的文件保护未通过检查，当前不可用。",
        "uac_system_session_unverified" => "当前版本尚未核实 SYSTEM 会话路线。",
        "uac_physical_stop_unverified" => "当前版本尚缺人工停止校准，不能启用系统接管。",
        _ => "UAC 系统接入尚未就绪；需先完成固定接入与同版本实际验证。",
    };
    private static void UpdateUacControls()
    {
        RefreshStopStatus(force: true);
        bool writable = policyValid && !surfaceFault && !UacBusy && !changingExecutionRole;
        bool master = Checked(1), launch = master && Checked(78);
        foreach (int id in new[] { 4, 6, 7, 11, 13, 20, 22, 23, 24, 25, 26, 27, 28, 3402, 3403 })
            EnableWindow(controls[id], writable);
        if (!master) Check(78, false);
        if (!launch) Check(79, false);
        uacMode = !launch || !Checked(79) ? "off" : uacMode == "off" ? uacSubmode : uacMode;
        if ((uacMode is "allowlist" or "semantic") && !uiPreferencePending && uacSubmode == uiBaselineSubmode) uacSubmode = uacMode;
        bool enabled = uacMode != "off";
        EnableWindow(controls[1], writable);
        EnableWindow(controls[78], writable && master);
        EnableWindow(controls[79], writable && launch);
        UpdateTierControls(writable);
        UpdateBlockedProgramControls(writable);
        EnableWindow(controls[81], writable && enabled
            && (uacCapabilities.CancellationScopeAvailable || original!.UacCancellationScope == "selected_prompt_in_session"));
        SendMessageW(controls[81], 0x14B, IntPtr.Zero, IntPtr.Zero);
        SendMessageW(controls[81], 0x143, IntPtr.Zero, "仅本任务可确认归属（默认；当前归属未就绪）");
        if (uacCapabilities.CancellationScopeAvailable || original!.UacCancellationScope == "selected_prompt_in_session")
            SendMessageW(controls[81], 0x143, IntPtr.Zero, uacCapabilities.CancellationScopeAvailable
                ? "当前会话所选提示（可能含人工提示；只取消）" : "当前会话所选提示（旧存值；接入未就绪）");
        SendMessageW(controls[81], 0x14E, new IntPtr(Array.IndexOf(CancellationScopes, uacCancellationScope)), IntPtr.Zero);
        foreach (var kind in new[] { ProgramListKind.Launch, ProgramListKind.Uac })
        {
            bool canAdd = writable && broker is not null && Programs(kind).Count < 128;
            EnableWindow(controls[ListControl(kind, 62)], canAdd);
            SetWindowTextW(controls[ListControl(kind, 62)], uacWindowPick?.Kind == kind ? "取消窗口选择" : "添加程序…  ▾");
            EnableWindow(controls[ListControl(kind, 63)], canAdd);
            EnableWindow(controls[ListControl(kind, 76)], canAdd && uacWindowPick is null);
            EnableWindow(controls[ListControl(kind, 77)], canAdd && uacWindowPick is null);
            SetWindowTextW(controls[ListControl(kind, 63)], uacWindowPick?.Kind == kind ? "取消窗口选择" : "按键选择窗口 · " + (kind == ProgramListKind.Launch ? "启动" : "UAC"));
            EnableWindow(controls[ListControl(kind, 66)], !UacBusy);
            UpdateUacDetail(kind);
        }
        SetWindowTextW(controls[2006], $"直接启动（已保存 / 草稿）：{(original!.AdminLaunchEnabled ? "开启" : "关闭")} / {(launch ? "开启" : "关闭")}\r\n"
            + (launchMode == "semantic" ? "每项工作需本机确认，执行时绑定程序、参数和入口文件。\r\n"
                : launch && !adminLaunchAllowlist.Any(row => row.Enabled) ? "启动名单为空，需在本区登记；旧 UAC 名单不会自动导入。\r\n"
                : "名单模式只使用本区独立启动名单；登记与选择均保存后生效。\r\n")
            + "实际执行还需核对当前档位、黑名单、工作授权与 Stop。");
        string scope = uacCancellationScope == "selected_prompt_in_session" ? "当前会话所选提示" : "仅本任务归属";
        string cancel = uacMode is "off" or "observe" ? "关闭"
            : uacCancellationScope != "selected_prompt_in_session" ? "归属未就绪"
            : !uacCapabilities.CancellationScopeAvailable ? "接入未就绪"
            : !uacCapabilities.CancelAvailable ? "路线未验证" : "可逐次核验";
        SetWindowTextW(controls[2106], $"UAC（已保存 / 草稿）：{UacModeLabel(original!.UacMode)} / {UacModeLabel(uacMode)}\r\n"
            + $"名单确认：{(uacCapabilities.AllowlistAvailable ? "已验证，执行仍逐次核验" : "未就绪")} · 取消：{cancel}（{scope}）\r\n"
            + (uacMode is "observe" or "cancel" ? "保留旧模式；需明确关闭再开启才改为名单确认。" : "关闭不使用 SYSTEM；Stop 后不补 Esc，不输入密码。"));
        if (original.UacPolicyError is not null)
            SetWindowTextW(controls[2006], "启动与 UAC 配置需要修复，当前按关闭处理；不保存默认草稿。\r\n" + original.UacPolicyError);
        SetWindowTextW(controls[30], preview ? "保存到预览(&S)" : "保存并立即应用(&S)");
        EnableWindow(controls[32], broker is not null);
        EnableWindow(controls[30], policyValid && !surfaceFault && !conflict && !UacBusy);
        EnableWindow(controls[94], !UacBusy);
        EnableWindow(controls[95], policyValid && !surfaceFault && !conflict && !UacBusy);
        EnableWindow(controls[98], !UacBusy);
        EnableWindow(controls[67], broker is not null && policyValid && !UacBusy);
        EnableWindow(controls[68], broker is not null);
        // The local High entry rechecks prepared components and Stop itself.
        // Its purpose is to establish route evidence, so later program-binding
        // proof must not prevent entering this fixed harmless experiment.
        foreach (var id in new[] { 69, 72, 73, 74 }) EnableWindow(controls[id], false);
        SetWindowTextW(controls[2104], "宿主安全桌面 UAC 功能已停用；普通窗口控制和 04 High 启动仍按各自权限运行。");
        EnableWindow(controls[66], !UacBusy);
        SetWindowTextW(controls[2212], preview ? "预览：真实系统操作全部不可执行。不会登记入口、枚举窗口或弹出 UAC。"
            : UacBusy ? "系统操作正在进行；可立即停止，结果未知时不重试。"
            : original!.UacMode == "off" ? "可准备固定系统入口，但关闭状态的首次校准路线尚未交付；准备不会开启 04。原档位保留，不需要反复切换或保存。"
            : "准备只登记固定系统入口；真实校准立即开始。物理 Stop 需要本人操作；登记会更新派生能力。");
        SetWindowTextW(controls[2100], preview ? "名单为空时无法直接启动；预览不登记真实程序。\r\n可查看合成条目身份；真实登记支持按键选窗、窗口菜单和文件兜底。"
            : Programs(ProgramListKind.Launch).Count >= 128 ? "名单已达 128 条，需先移除条目才能继续添加。"
            : "添加程序优先按键选窗：切到目标后按 Ctrl+Alt+8，30 秒有效。\r\n核对准确身份后加入草稿，整页保存才生效；窗口菜单和文件选择可兜底。");
        SetWindowTextW(controls[2211], "与直接启动名单独立，不互相导入。观察和取消为逐次动作，不自动 Esc。\r\n"
            + (preview ? "预览不登记真实程序；可查看合成身份。" : Programs(ProgramListKind.Uac).Count == 0 ? "名单为空：无法按名单确认 UAC；先添加并保存准确程序。" : "从当前名单选择条目以查看、停用或移除。"));
        SetWindowTextW(controls[2209], launchMode == "semantic" ? "03 语义方式需本机工作授权；普通代码修订沿同一工作，执行时重新绑定准确文件。"
            : "03 名单方式使用本区独立规则；档位立即切换，名单编辑保存后生效。");
        SetWindowTextW(controls[2210], "04 在 03 之上增加受限 SYSTEM 后备；需要同版本路线与人工停止校准，准备成功不等于已启用。");
        RefreshFooter();
    }
    private static void RefreshUacAllowlist(int selected = -1, ProgramListKind kind = ProgramListKind.Uac)
    {
        SendMessageW(controls[ListControl(kind, 66)], 0x184, IntPtr.Zero, IntPtr.Zero);
        foreach (var row in Programs(kind)) SendMessageW(controls[ListControl(kind, 66)], 0x180, IntPtr.Zero,
            (row.Arguments is null ? "待批准参数 · " : row.Enabled ? "启用 · " : "停用 · ")
            + (row.DisplayName.Length == 0 ? Path.GetFileName(row.Path) : row.DisplayName)
            + (row.Arguments is null ? "" : row.Arguments.Length == 0 ? " · 仅无参数" : " · 准确参数"));
        if (selected >= 0 && selected < Programs(kind).Count) SendMessageW(controls[ListControl(kind, 66)], 0x186, new IntPtr(selected), IntPtr.Zero);
        UpdateUacDetail(kind);
    }
    private static int UacSelectedIndex(ProgramListKind kind = ProgramListKind.Uac) => SendMessageW(controls[ListControl(kind, 66)], 0x188, IntPtr.Zero, IntPtr.Zero).ToInt32();
    private static void UpdateUacDetail(ProgramListKind kind = ProgramListKind.Uac)
    {
        int index = UacSelectedIndex(kind); bool selected = index >= 0 && index < Programs(kind).Count;
        EnableWindow(controls[ListControl(kind, 64)], !UacBusy && policyValid && broker is not null && selected
            && (Programs(kind)[index].Enabled || Programs(kind)[index].Arguments == ""));
        EnableWindow(controls[ListControl(kind, 65)], !UacBusy && policyValid && selected);
        SetWindowTextW(controls[ListControl(kind, 64)], selected && Programs(kind)[index].Enabled ? "停用条目(&V)" : "启用条目(&V)");
        bool unsupported = selected && !preview && !UacIdentity.AllowlistSupported(Programs(kind)[index].Path);
        SetWindowTextW(controls[ListControl(kind, 2008)], selected ? $"文件：{Programs(kind)[index].Path}\r\n"
            + $"身份：{(Programs(kind)[index].IdentityKind == "signed" ? "本机可信发布者密钥" : "无签名文件 SHA-256")}\r\n{Programs(kind)[index].Identity}"
            + (Programs(kind)[index].Arguments is null ? "\r\n旧条目的参数未知，不能启用。原规则保留；如需无参数启动，请重新从窗口或文件登记。"
                : Programs(kind)[index].Arguments!.Length == 0 ? "\r\n批准用途：" + ProgramListName(kind) + "；仅空参数。"
                : "\r\n旧准确参数（只读，可停用或移除）：" + System.Text.Json.JsonSerializer.Serialize(Programs(kind)[index].Arguments))
            + (unsupported ? "\r\n此条目不能免授权：程序为解释器／代理执行宿主，或文件当前不可读取。可停用或移除。" : "")
            : Programs(kind).Count == 0 ? "尚未添加程序\r\n" + ProgramListName(kind) + "为空。添加后核对身份，再保存整页；不会从另一名单导入。"
            : "请选择条目\r\n可查看并复制完整路径、身份及参数范围；保存后生效，不影响另一个名单。");
    }
    private static void ToggleProgram(ProgramListKind kind)
    {
        int index = UacSelectedIndex(kind); var rows = Programs(kind);
        if (index < 0 || index >= rows.Count) return;
        if (UacBusy || !policyValid || broker is null) throw new Boundary("uac_allowlist_unavailable");
        if (!rows[index].Enabled)
        {
            if (rows[index].Arguments != "") throw new Boundary("uac_allowlist_arguments_approval_required");
            var fresh = UacIdentity.InspectForAllowlist(rows[index].Path);
            if (!Path.GetFullPath(fresh.Path).Equals(Path.GetFullPath(rows[index].Path), StringComparison.OrdinalIgnoreCase)
                || fresh.IdentityKind != rows[index].IdentityKind || fresh.Identity != rows[index].Identity)
                throw new Boundary("uac_program_changed");
        }
        rows[index] = rows[index] with { Enabled = !rows[index].Enabled };
        RefreshUacAllowlist(index, kind);
    }
    private static void AddUacApplication(ProgramListKind kind)
    {
        EndUacWindowPick();
        if (UacBusy || !policyValid || broker is null || Programs(kind).Count >= 128) throw new Boundary("uac_allowlist_unavailable");
        var context = CaptureSelectionContext(kind);
        var file = Marshal.AllocHGlobal(32768 * sizeof(char));
        string path;
        try
        {
            Marshal.Copy(new byte[32768 * sizeof(char)], 0, file, 32768 * sizeof(char));
            var picker = new OpenFileName { Size = (uint)Marshal.SizeOf<OpenFileName>(), Owner = window,
                Filter = "程序文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0\0", File = file, FileLength = 32768,
                Title = "选择程序文件 · " + ProgramListName(kind), Flags = 0x00080000 | 0x00001000 | 0x00000800 | 0x00000008 | 0x02000000 };
            // The file picker and following confirmation inherit the protected
            // page's owner chain; neither creates an MCP policy-writing surface.
            if (!GetOpenFileNameW(ref picker))
            { if (CommDlgExtendedError() != 0) throw new Boundary("uac_file_picker_failed"); return; }
            path = Marshal.PtrToStringUni(file) ?? throw new Boundary("uac_file_picker_failed");
        }
        finally { Marshal.FreeHGlobal(file); }
        ConfirmUacApplication(path, null, context);
    }
    private static string ProgramDigest(string path)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(file)).ToLowerInvariant();
    }
    private static string UacWindowPickError(Exception error) => error is Boundary boundary ? boundary.Code switch
    {
        "uac_window_pick_hotkey_unavailable" => "Ctrl+Alt+8 已被占用或无法注册，没有开始选择。请用“从运行窗口选择”或“选择程序文件”兜底。",
        "uac_window_pick_timer_unavailable" => "窗口选择计时器不可用，快捷键已撤回，没有更改名单。请使用运行窗口菜单或文件选择。",
        "uac_window_pick_cleanup_failed" => "窗口选择的快捷键收束失败，设置页已关闭以释放注册。管理员助手仍保留原状态。",
        "uac_window_pick_expired" => "选择已超时、窗口已关闭或发生停止，没有更改名单。请重新开始选择。",
        "uac_window_pick_target_changed" => "选定窗口或程序实例已经变化，没有登记。请重新选择当前窗口。",
        "uac_program_changed" => "选定文件在确认期间发生变化，没有登记。请重新选择稳定的程序。",
        "uac_allowlist_program_writable" => "程序或目录可被普通进程改写，不能预授权，未更改名单。",
        "uac_allowlist_payload_host_rejected" => "所选窗口属于解释器或代理执行宿主，不能作为 UAC 程序白名单。请选择实际程序。",
        _ => "此窗口无法作为 UAC 程序候选，没有更改名单。请用运行窗口菜单或程序文件选择，并核对实际提权程序。",
    } : "无法核实所选窗口，没有更改名单。请重新选择，或使用运行窗口菜单与文件选择。";
    internal static bool WindowCandidateMatches(Peer expected, string image, Peer actual, string actualImage)
        => expected.Pid == actual.Pid && expected.Created == actual.Created && expected.Session == actual.Session
            && expected.User == actual.User && expected.Integrity == actual.Integrity
            && image.Equals(actualImage, StringComparison.OrdinalIgnoreCase);
    internal static bool SelectionMatches(long generation, long? epoch, bool wasPaused, long currentGeneration, long? currentEpoch, bool paused)
        => generation == currentGeneration && epoch == currentEpoch && (wasPaused || !paused);
    private static SelectionContext CaptureSelectionContext(ProgramListKind kind)
    {
        var core = broker ?? throw new Boundary("uac_allowlist_unavailable");
        return new(windowGeneration, core.ProtectedStopEpoch, core.IsPaused, kind);
    }
    private static void RequireSelectionContext(SelectionContext context)
    {
        var core = broker;
        if (core is null || core.Shutdown.IsCancellationRequested
            || !SelectionMatches(context.Generation, context.StopEpoch, context.WasPaused,
                windowGeneration, core.ProtectedStopEpoch, core.IsPaused))
            throw new Boundary("uac_window_pick_expired");
    }
    private static WindowCandidate CaptureUacWindow(IntPtr hwnd)
    {
        hwnd = Native.GetAncestor(hwnd, 2);
        if (hwnd == IntPtr.Zero || !Native.IsWindow(hwnd) || !Native.IsWindowVisible(hwnd)
            || Native.ProtectedWindowOrOwner(hwnd)) throw new Boundary("uac_window_pick_target_rejected");
        Native.GetWindowThreadProcessId(hwnd, out var pid);
        var process = Native.Process((int)pid, digestImage: false);
        var own = Native.Process(Environment.ProcessId, digestImage: false).Identity;
        if (process.Identity.User != own.User || process.Identity.Session != own.Session
            || process.Identity.Integrity is not (8192 or 12288)
            || new[] { "consent.exe", "credentialuibroker.exe", "logonui.exe" }.Contains(Path.GetFileName(process.Image), StringComparer.OrdinalIgnoreCase))
            throw new Boundary("uac_window_pick_target_rejected");
        var title = new StringBuilder(160); GetWindowTextW(hwnd, title, title.Capacity);
        return new(hwnd, process.Identity, process.Image, title.Length == 0 ? Path.GetFileName(process.Image) + "（无标题）" : title.ToString());
    }
    private static void RecheckUacWindow(WindowCandidate candidate)
    {
        var actual = CaptureUacWindow(candidate.Hwnd);
        if (!WindowCandidateMatches(candidate.Peer, candidate.Image, actual.Peer, actual.Image))
            throw new Boundary("uac_window_pick_target_changed");
    }
    private static void ConfirmUacApplication(string path, WindowCandidate? candidate, SelectionContext context)
    {
        var kind = context.Kind;
        var rows = Programs(kind);
        if (UacBusy || !policyValid || broker is null || rows.Count >= 128) throw new Boundary("uac_allowlist_unavailable");
        var generation = windowGeneration;
        RequireSelectionContext(context);
        if (candidate is not null) RecheckUacWindow(candidate);
        var digest = ProgramDigest(path);
        var inspected = UacIdentity.InspectForAllowlist(path);
        UserPermissions.Validate(kind == ProgramListKind.Launch ? original! with { AdminLaunchAllowlist = [inspected] } : original! with { UacAllowlist = [inspected] });
        if (candidate is not null) RecheckUacWindow(candidate);
        if (digest != ProgramDigest(path)) throw new Boundary("uac_program_changed");
        pendingProgram = new(path, candidate, context, inspected, digest);
        OpenPanel("candidate", "核对程序身份 · " + ProgramListName(kind), "将此程序加入" + ProgramListName(kind) + "？\r\n" + (kind == ProgramListKind.Launch ? "仅用于直接启动，不批准 UAC 确认。" : "仅用于 UAC 确认，不批准直接启动。") + "\r\n\r\n"
            + (candidate is null ? "来源：本机文件选择\r\n" : "来源：选定窗口（标题仅供辨认）\r\n")
            + inspected.Path + "\r\n"
            + $"{(inspected.IdentityKind == "signed" ? "可信发布者密钥身份" : "无签名文件 SHA-256")}：{inspected.Identity}\r\n\r\n"
            + "仅批准此程序的空参数规则；未知或其它参数未获准。选中启动器不会批准其关联程序。\r\n加入后仍需保存整页；本页不启动该程序。");
        SetFocus(controls[97]);
    }
    private static void AcceptPendingProgram()
    {
        var pending = pendingProgram ?? throw new Boundary("uac_window_pick_expired");
        var (path, candidate, context, inspected, digest) = pending;
        var kind = context.Kind; var rows = Programs(kind); var generation = context.Generation;
        if (generation != windowGeneration || window == IntPtr.Zero || original is null || broker is null || UacBusy)
            throw new Boundary("uac_window_pick_target_changed");
        RequireSelectionContext(context);
        if (candidate is not null) RecheckUacWindow(candidate);
        var fresh = UacIdentity.InspectForAllowlist(path);
        if (digest != ProgramDigest(path) || fresh.Path != inspected.Path || fresh.IdentityKind != inspected.IdentityKind || fresh.Identity != inspected.Identity)
            throw new Boundary("uac_program_changed");
        if (candidate is not null) RecheckUacWindow(candidate);
        RequireSelectionContext(context);
        int existing = rows.FindIndex(row => Path.GetFullPath(row.Path).Equals(Path.GetFullPath(fresh.Path), StringComparison.OrdinalIgnoreCase)
            && row.Arguments == "");
        if (existing >= 0) rows[existing] = fresh;
        else { existing = rows.Count; rows.Add(fresh); }
        CloseDetails(relayout: false);
        RefreshUacAllowlist(existing, kind); UpdateUacControls();
        SetNotice(ProgramListName(kind) + "：仅无参数规则已加入草稿，保存后生效。");
        PositionControls(); UpdateScroll(); SetFocus(controls[ListControl(kind, 66)]);
    }
    private static void EndUacWindowPick()
    {
        var selection = uacWindowPick; uacWindowPick = null;
        selection?.Dispose();
    }
    private static void StopSettingsWork()
    {
        EndUacWindowPick();
        try { uacWorkStop?.Cancel(); } catch (ObjectDisposedException) { }
        // The footer action follows today's Stop contract: it ends the current
        // Computer Use run and cancels in-flight page work. App and Web keep
        // working, nothing durable is written, and the next run starts fresh.
        broker?.StopComputerUse();
        if (window != IntPtr.Zero)
        {
            UpdateUacControls();
            SetNotice("已结束当前 Computer Use；再次使用需 AI 重新调用。");
        }
    }
    private static bool RefreshStopStatus(bool force = false)
    {
        if (!controls.ContainsKey(2040)) return false;
        bool stopped = broker?.IsPaused == true;
        bool computerPaused = broker?.ComputerPaused == true, revisionChanged = false;
        if (broker is not null && original is not null && policyValid && !conflict && !UacBusy
            && UserPermissions.Revision != original.Revision)
        {
            conflict = revisionChanged = true;
            notice = "已保存配置在外部发生变化；草稿保留，请重新载入核对。";
            EnableWindow(controls[30], false); EnableWindow(controls[95], false);
        }
        if (!force && !revisionChanged && lastStopped == stopped && lastComputerPaused == computerPaused) return false;
        lastStopped = stopped; lastComputerPaused = computerPaused;
        SetWindowTextW(controls[2040], broker is null ? "预览不读取实际停止状态。"
            : stopped ? "全部写入处于保护性停止；新的系统操作会被拒绝，解除由受控流程完成。"
            : computerPaused ? "Computer 输入处于暂停；可从托盘继续。App 与 Web 仍按已保存权限运行。"
            : "当前未停止。结束控制只结束当前的电脑操作；App 与 Web 不受影响。");
        return true;
    }
    private static void BeginUacWindowPick(ProgramListKind kind)
    {
        if (uacWindowPick is not null) { EndUacWindowPick(); UpdateUacControls(); return; }
        if (preview || broker is null || UacBusy || !policyValid || Programs(kind).Count >= 128)
            throw new Boundary("uac_allowlist_unavailable");
        var target = window;
        // Read shared/protected state before acquiring a native registration:
        // a busy shared mutex must not leave an untracked global hotkey.
        var context = CaptureSelectionContext(kind);
        var selection = new UacWindowPick(context.Generation, Environment.TickCount64 + 30000, context.StopEpoch, context.WasPaused, () => {
            KillTimer(target, UacPickTimer);
            if (!UnregisterHotKey(target, UacPickHotkey) && Native.IsWindow(target))
            {
                // Destroying this settings HWND also releases its hotkey. Do
                // not retain an invisible registration after a cleanup fault.
                Console.Error.WriteLine("uac_window_pick_cleanup_failed");
                DestroyWindow(target);
            }
        }, kind);
        if (!RegisterHotKey(target, UacPickHotkey, 0x4003, 0x38))
            throw new Boundary("uac_window_pick_hotkey_unavailable", Marshal.GetLastWin32Error());
        uacWindowPick = selection;
        try
        {
            if (SetTimer(target, UacPickTimer, 200, IntPtr.Zero) == UIntPtr.Zero)
                throw new Boundary("uac_window_pick_timer_unavailable");
            UpdateUacControls();
            SetNotice("切到目标后按 Ctrl+Alt+8，30 秒有效；Esc 或再次点击可取消。");
        }
        catch { EndUacWindowPick(); throw; }
    }
    private static void CompleteUacWindowPick()
    {
        var selection = uacWindowPick;
        if (selection is null) return;
        // Unregister before validation, foreground changes, or a modal dialog.
        EndUacWindowPick();
        if (window == IntPtr.Zero) throw new Boundary("uac_window_pick_cleanup_failed");
        UpdateUacControls();
        if (selection.Generation != windowGeneration || selection.Expired(Environment.TickCount64)
            || broker is null || broker.ProtectedStopEpoch != selection.StopEpoch || !selection.WasPaused && broker.IsPaused)
            throw new Boundary("uac_window_pick_expired");
        var candidate = CaptureUacWindow(Native.GetForegroundWindow());
        ShowWindow(window, 5); Native.SetForegroundWindow(window);
        ConfirmUacApplication(candidate.Image, candidate, new(selection.Generation, selection.StopEpoch, selection.WasPaused, selection.Kind));
    }
    private static void AddUacRunningWindow(ProgramListKind kind)
    {
        EndUacWindowPick();
        if (preview || broker is null || UacBusy || !policyValid || Programs(kind).Count >= 128)
            throw new Boundary("uac_allowlist_unavailable");
        var context = CaptureSelectionContext(kind);
        var candidates = new List<WindowCandidate>();
        EnumWindows((hwnd, _) => {
            if (candidates.Count >= 64) return true;
            try { candidates.Add(CaptureUacWindow(hwnd)); }
            catch (Exception) { /* Unavailable windows never become candidates. */ }
            return true;
        }, IntPtr.Zero);
        var menu = CreatePopupMenu();
        WindowCandidate? selected = null;
        try
        {
            for (int i = 0; i < candidates.Count; ++i)
                AppendMenuW(menu, 0, new UIntPtr((uint)i + 1), (candidates[i].Title + " · " + Path.GetFileName(candidates[i].Image)).Replace("&", "&&"));
            if (candidates.Count == 0) { ShowError(window, "没有可选择的普通窗口。可用“选择程序文件”兜底；没有更改名单。" ); return; }
            if (!GetWindowRect(controls[ListControl(kind, 62)], out var location)) throw new Boundary("uac_window_pick_target_rejected");
            var choice = TrackPopupMenu(menu, 0x102, location.Left, location.Bottom, 0, window, IntPtr.Zero);
            if (choice >= 1 && choice <= candidates.Count) selected = candidates[(int)choice - 1];
        }
        finally { DestroyMenu(menu); UpdateUacControls(); }
        if (selected is not null) ConfirmUacApplication(selected.Image, selected, context);
    }
    private static (string Image, string Title, int[] Size)? ChooseRunningWindow(IntPtr anchor)
    {
        var windows = preview ? new List<(string Image, string Title, int[] Size)> {
            ("E:\\Preview\\Editor.exe", "示例编辑器", [1280, 720]),
            ("E:\\Preview\\Canvas.exe", "示例画布", [1200, 800]),
            ("E:\\Preview\\Notes.exe", "示例便笺", [960, 640]),
        } : [];
        if (!preview) EnumWindows((hwnd, _) => {
            if (windows.Count >= 64 || !Native.IsWindowVisible(hwnd) || Native.GetAncestor(hwnd, 2) != hwnd) return true;
            try
            {
                Native.GetWindowThreadProcessId(hwnd, out var pid); var process = Native.Process((int)pid, false);
                if (process.Identity.User != System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value || Native.GetPropW(hwnd, "FlowerControlTaskIndicator") != IntPtr.Zero) return true;
                var title = new StringBuilder(160); GetWindowTextW(hwnd, title, title.Capacity);
                if (GetClientRect(hwnd, out var rect) && rect.Right > 0 && rect.Bottom > 0)
                    windows.Add((process.Image, title.Length == 0 ? Path.GetFileName(process.Image) + "（无标题）" : title.ToString(), [rect.Right, rect.Bottom]));
            }
            catch (Exception) { /* Local user picker: unavailable windows are omitted. */ }
            return true;
        }, IntPtr.Zero);
        var menu = CreatePopupMenu();
        try
        {
            for (int i = 0; i < windows.Count; i++) AppendMenuW(menu, 0, new UIntPtr((uint)i + 1), windows[i].Title.Replace("&", "&&"));
            if (windows.Count == 0) { MessageBoxW(window, "当前没有可选择的普通窗口。也可以直接在程序名单中填写完整路径。", "Flower Control", 0x40); return null; }
            if (!GetWindowRect(anchor, out var location)) return null;
            var choice = TrackPopupMenu(menu, 0x102, location.Left, location.Bottom, 0, window, IntPtr.Zero);
            return choice < 1 || choice > windows.Count ? null : windows[(int)choice - 1];
        }
        finally { DestroyMenu(menu); }
    }
    private static void SelectWindow()
    {
        var selected = ChooseRunningWindow(controls[20]);
        if (selected is not { } item) return;
        selectedSize = item.Size;
        SetWindowTextW(controls[21], item.Image); SetWindowTextW(controls[22], "0"); SetWindowTextW(controls[23], "0");
        SetWindowTextW(controls[24], item.Size[0].ToString()); SetWindowTextW(controls[25], item.Size[1].ToString());
    }
    private static void AddApplication(int editor, int picker)
    {
        var selected = ChooseRunningWindow(controls[picker]);
        if (selected is not { } item) return;
        var current = ParseLines(Text(editor));
        // Selection adds a pending full-program rule; it does not switch scope,
        // change a disabled existing rule or write live settings before Save.
        if (current.Any(rule => Path.GetFullPath(rule.Path).Equals(Path.GetFullPath(item.Image), StringComparison.OrdinalIgnoreCase)
            && rule.TitleContains.Length == 0 && rule.Enabled)) return;
        SetWindowTextW(controls[editor], Lines([..current, new ApplicationPermission(item.Image)]));
    }
    private static void UpdateScroll(bool redraw = true)
    {
        if (body == IntPtr.Zero || !GetClientRect(body, out var rect)) return;
        var info = new ScrollInfo { Size = (uint)Marshal.SizeOf<ScrollInfo>(), Mask = 0x17, Min = 0,
            Max = Px(PageHeights[(int)page]) - 1, Page = (uint)Math.Max(1, rect.Bottom), Position = scrollPosition };
        var next = SetScrollInfo(body, 1, ref info, redraw);
        visual?.ThemeBody(body);
        bool moved = next != scrollPosition;
        pageScroll[(int)page] = scrollPosition = next;
        if (moved && redraw) PositionControls();
    }
    private static int FooterTop() => GetClientRect(window, out var rect) ? Math.Max(Px(bodyTop), rect.Bottom - Px(footerHeight)) : 0;
    // Read-only structural audit of the settings window. It builds every page
    // in memory, then reports what the user would actually experience: controls
    // from another page left visible, controls overlapping each other, controls
    // outside the viewport, and chrome collisions. No policy, input or broker.
    internal static object AuditLayout()
    {
        var settings = new UserPermissionSettings { UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            Revision = "audit", AdminWindows = true, AdminScope = "allowlist", SmoothPointer = true, HudCompact = true };
        preview = true;
        var issues = new List<object>();
        var pageRows = new List<object>();
        try
        {
            Create(IntPtr.Zero, null, settings, false);
            // Catch escape sequences pasted as literal text. This is exactly
            // how "`r`n" reached the admin and UAC explanation boxes.
            foreach (var item in layout)
            {
                int id = GetDlgCtrlID(item.Handle);
                string value = Text(id);
                if (value.Contains("`r`n", StringComparison.Ordinal) || value.Contains("\\r\\n", StringComparison.Ordinal))
                    issues.Add(new { kind = "literal_escape", id, text = value });
            }
            foreach (var target in new[] { SettingsPage.Overview, SettingsPage.General, SettingsPage.Admin, SettingsPage.Launch, SettingsPage.Uac, SettingsPage.Privacy, SettingsPage.Validation })
            {
                ShowPage(target);
                int visibleCount = 0;
                var visible = new List<(int Id, string Text, int Left, int Top, int Right, int Bottom)>();
                foreach (var item in layout)
                {
                    int id = GetDlgCtrlID(item.Handle);
                    bool shown = (GetWindowLongW(item.Handle, -16) & 0x10000000) != 0;
                    if (!shown) continue;
                    visibleCount++;
                    if (item.Fixed) continue;
                    if (!GetWindowRect(item.Handle, out var screen)) continue;
                    var point = new Native.Point { X = screen.Left, Y = screen.Top };
                    ScreenToClient(body, ref point);
                    visible.Add((id, Text(id), point.X, point.Y, point.X + screen.Right - screen.Left, point.Y + screen.Bottom - screen.Top));
                    if (item.Page != target && !(id is 1091 or 92 or 93 or 95 or 96 or 97 or 98 or 99 or 100))
                        issues.Add(new { page = target.ToString(), kind = "foreign_control", id, text = Text(id) });
                }
                for (int i = 0; i < visible.Count; i++)
                    for (int j = i + 1; j < visible.Count; j++)
                    {
                        var a = visible[i]; var b = visible[j];
                        if (a.Left < b.Right && b.Left < a.Right && a.Top < b.Bottom && b.Top < a.Bottom)
                            issues.Add(new { page = target.ToString(), kind = "overlap", a = a.Id, b = b.Id, at = $"{a.Left},{a.Top}" });
                    }
                GetClientRect(body, out var viewport);
                foreach (var row in visible)
                    if (row.Right > viewport.Right + 2 || row.Bottom < -2 || row.Top > viewport.Bottom + 2)
                        issues.Add(new { page = target.ToString(), kind = "outside_viewport", id = row.Id, text = row.Text, box = $"{row.Left},{row.Top},{row.Right},{row.Bottom}" });
                // Hit-test proof: the centre of every visible interactive control
                // must resolve back to that control inside our own window, so a
                // sibling can never shadow it (the "switch not clickable" class).
                foreach (var item in layout.Where(item => !item.Fixed && item.Page == target))
                {
                    int id = GetDlgCtrlID(item.Handle);
                    if ((GetWindowLongW(item.Handle, -16) & 0x10000000) == 0) continue;
                    if (!GetWindowRect(item.Handle, out var box)) continue;
                    if (item.Kind is not ("BUTTON" or "EDIT" or "COMBOBOX" or "LISTBOX")) continue;
                    if (!IsWindowEnabled(item.Handle)) continue;   // disabled controls cannot be clicked by design
                    var centre = new Native.Point { X = (box.Left + box.Right) / 2, Y = (box.Top + box.Bottom) / 2 };
                    // Page controls are children of the scrolled body, not of the
                    // root window, so hit-test inside the body they belong to.
                    var local = centre; var parent = GetParent(item.Handle); ScreenToClient(parent, ref local);
                    if (!GetClientRect(parent, out var parentClient)) continue;
                    if (local.X < parentClient.Left || local.X >= parentClient.Right || local.Y < parentClient.Top || local.Y >= parentClient.Bottom)
                        continue;   // scrolled out of the viewport, covered by outside_viewport
                    // Skip hidden siblings only: a hidden control must never be able to
                    // shadow, while a disabled one still owns its rectangle.
                    var hit = ChildWindowFromPointEx(parent, local, 0x1);
                    if (hit != item.Handle)
                        issues.Add(new { page = target.ToString(), kind = "shadowed", id, hit = GetDlgCtrlID(hit), at = $"{centre.X},{centre.Y}" });
                }
                pageRows.Add(new { page = target.ToString(), visible = visibleCount, ids = visible.Select(v => v.Id).ToArray() });
                // Every non-fixed control must have a box on its own page, or it
                // is unreachable forever (the UAC switch used to be like this).
                foreach (var item in layout.Where(item => !item.Fixed && item.Page == target))
                {
                    int id = GetDlgCtrlID(item.Handle);
                    bool detail = id is 1091 or 92 or 93 or 95 or 96 or 97 or 98 or 99 or 100;
                    bool conditional = id is 3032 or 3042;   // only laid out while its explanation is open
                    if (!detail && !(conditional && !explanationOpen) && !activeLayout!.Controls.ContainsKey(id))
                        issues.Add(new { page = target.ToString(), kind = "no_box", id, text = Text(id) });
                }
                // Text written after the last measurement is the other way a
                // row gets clipped: the box height still belongs to the old
                // string. Measure now and compare with the box we actually use.
                foreach (var item in layout.Where(item => !item.Fixed && item.Page == target))
                {
                    int id = GetDlgCtrlID(item.Handle);
                    if (id is 1091 or 92 or 93 or 95 or 96 or 97 or 98 or 99 or 100) continue;
                    if (id is 3000 or 3001 or 3002 or 3003 or 3004 or 3020 or 3030 or 3040) continue;   // fixed artwork boxes
                    if (!activeLayout!.Controls.TryGetValue(id, out var box)) continue;
                    int needed = MeasureControl(id, box.W);
                    if (needed > box.H + 2)
                        issues.Add(new { page = target.ToString(), kind = "text_clipped", id, needed, height = box.H, text = Text(id) });
                }
                // Content must be reachable by scrolling: the tallest control's
                // bottom has to fit inside the scrollable extent.
                int extent = Px(activeLayout!.Height);
                foreach (var box in activeLayout.Controls.Values)
                    if (box.Y + box.H > activeLayout.Height)
                        issues.Add(new { page = target.ToString(), kind = "past_extent", y = box.Y, h = box.H, extent = activeLayout.Height });
            }
            // The capability switches belong to the admin page, matching the prototype.
            ShowPage(SettingsPage.Admin);
            foreach (int id in new[] { 1, 78, 79 })
                if (!layout.Any(item => GetDlgCtrlID(item.Handle) == id && (GetWindowLongW(item.Handle, -16) & 0x10000000) != 0))
                    issues.Add(new { page = "Admin", kind = "missing_control", id });
            // Fixed chrome must never collide, at both the default and the
            // supported minimum size (that is where the footer used to climb
            // into the header).
            void CheckChrome(string label)
            {
                var ids = new[] { 1000, 2000, 1010, 2015, 306, 300, 301, 302, 303, 304, 305, 2016, 40, 32, 30, 31, 91, 94 };
                bool Shown(int id) => controls.TryGetValue(id, out var handle) && (GetWindowLongW(handle, -16) & 0x10000000) != 0;
                for (int i = 0; i < ids.Length; i++)
                {
                    if (!positioned.TryGetValue(ids[i], out var a)) { issues.Add(new { page = label, kind = "chrome_missing", id = ids[i] }); continue; }
                    if (!Shown(ids[i])) continue;   // hidden chrome (compact rail, note) cannot collide
                    for (int j = i + 1; j < ids.Length; j++)
                    {
                        if (!positioned.TryGetValue(ids[j], out var b) || !Shown(ids[j])) continue;
                        if (a.X < b.X + b.W && b.X < a.X + a.W && a.Y < b.Y + b.H && b.Y < a.Y + a.H)
                            issues.Add(new { page = label, kind = "chrome_overlap", a = ids[i], b = ids[j] });
                    }
                }
            }
            SetWindowPos(window, IntPtr.Zero, 0, 0, Px(WindowWidth), Px(WindowHeight), 0x1c); Relayout(); CheckChrome("default");
            SetWindowPos(window, IntPtr.Zero, 0, 0, Px(MinWindowWidth), Px(MinWindowHeight), 0x1c); Relayout(); CheckChrome("minimum");
            // Rail clicks must land on the page the label promises.
            SetWindowPos(window, IntPtr.Zero, 0, 0, Px(WindowWidth), Px(WindowHeight), 0x1c); Relayout();
            for (int index = 0; index < NavPages.Length; index++)
            {
                HandleMessage(window, 0x111, new UIntPtr((uint)(300 + index)), IntPtr.Zero);
                if (page != NavPages[index]) issues.Add(new { page = "rail", kind = "wrong_page", rail = PageNames[(int)NavPages[index]], actual = page.ToString() });
                if (Text(1010) != PageNames[(int)NavPages[index]]) issues.Add(new { page = "rail", kind = "wrong_title", rail = index, title = Text(1010) });
            }
            // A clean window must close; a dirty one must ask first and survive.
            ShowPage(SettingsPage.General);
            SendMessageW(window, 0x112, new IntPtr(0xF060), IntPtr.Zero);   // SC_CLOSE, the caption X
            if (window != IntPtr.Zero) issues.Add(new { page = "close", kind = "clean_close_blocked" });
            Create(IntPtr.Zero, null, settings, false);
            Check(6, !Checked(6));   // make the draft dirty
            if (!Dirty) issues.Add(new { page = "close", kind = "dirty_not_detected" });
            SendMessageW(window, 0x112, new IntPtr(0xF060), IntPtr.Zero);
            if (window == IntPtr.Zero) issues.Add(new { page = "close", kind = "dirty_window_closed_without_prompt" });
            else
            {
                if (detailMode != "close") issues.Add(new { page = "close", kind = "prompt_missing", mode = detailMode });
                foreach (int id in new[] { 95, 98, 99 })
                    if (!positioned.ContainsKey(id) || (GetWindowLongW(controls[id], -16) & 0x10000000) == 0)
                        issues.Add(new { page = "close", kind = "prompt_button_missing", id });
                // Returning to the editor must keep the draft and the window.
                HandleMessage(window, 0x111, new UIntPtr(99), IntPtr.Zero);
                if (detailMode.Length != 0 || !Dirty) issues.Add(new { page = "close", kind = "return_editor_lost_draft" });
                // Discarding is the escape hatch when the user really wants out.
                SendMessageW(window, 0x112, new IntPtr(0xF060), IntPtr.Zero);
                HandleMessage(window, 0x111, new UIntPtr(98), IntPtr.Zero);
                if (window != IntPtr.Zero) issues.Add(new { page = "close", kind = "discard_did_not_close" });
            }

            return new { issues = issues.ToArray(), pages = pageRows.ToArray(), issueCount = issues.Count };
        }
        finally
        {
            preview = false;
            if (Native.IsWindow(window)) DestroyWindow(window);
            CloseAfterFailure();
        }
    }
    private static int NavIndex(SettingsPage value) => value == SettingsPage.Launch ? 2 : Array.IndexOf(NavPages, value);
    internal static SettingsPage NavPageFor(int index) => NavPages[index];
    private static void ShowPage(SettingsPage next)
    {
        if (page == next) return;
        EndUacWindowPick();
        CloseDetails(relayout: false);
        pageScroll[(int)page] = scrollPosition;
        StopSmoothScroll();
        page = next; scrollPosition = pageScroll[(int)page]; wheelRemainder = 0;
        SetWindowTextW(controls[1010], PageNames[(int)page]);
        SetWindowTextW(controls[2015], PageDescriptions[(int)page]);
        visual?.SelectPage(NavIndex(page));
        // Text first: UpdateUacControls rewrites several descriptions and the
        // footer. Measuring before those writes made the new page use the old
        // page's line counts, which is how clipped rows and overlaps appeared.
        UpdateUacControls(); PositionControls(); UpdateScroll();
    }
    private static void RepaintTree(bool now = true)
    {
        if (window == IntPtr.Zero) return;
        // Parent-only invalidation excludes WS_CLIPCHILDREN. Repaint the
        // complete descendant tree and nonclient scrollbars after the batched
        // move; otherwise clipped native controls retain pixels. Animation
        // frames invalidate without UPDATENOW -- repainting every control
        // synchronously on each tick is what made the wheel stutter.
        RedrawWindow(window, IntPtr.Zero, IntPtr.Zero, now ? 0x585u : 0x485u);
    }
    // Wheel-animation path: reuse the boxes from the last full layout and only
    // re-apply the scroll offset. Re-measuring every control's text and forcing
    // a synchronous repaint of the whole tree per frame is what made scrolling
    // feel stuck; the geometry cannot change while only the offset moves.
    private static void ApplyScroll()
    {
        if (positioning || body == IntPtr.Zero || layout.Count == 0 || activeLayout is null) { PositionControls(); return; }
        if (!GetClientRect(body, out var applied)) { PositionControls(); return; }
        int applyViewport = Math.Max(1, applied.Bottom);
        positioning = true;
        try
        {
            var moving = new List<(LayoutItem Item, PermissionPageLayout.Box Box)>();
            foreach (var item in layout)
            {
                if (item.Fixed) continue;
                int id = GetDlgCtrlID(item.Handle);
                bool detail = id is 1091 or 92 or 93 or 95 or 98 or 99 or 96 or 97 or 100;
                if ((detail || item.Page == page) && activeLayout.Controls.TryGetValue(id, out var box)) moving.Add((item, box));
            }
            if (moving.Count == 0) return;
            var batch = BeginDeferWindowPos(moving.Count);
            if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
            foreach (var (item, box) in moving)
            {
                int height = Px(item.Kind == "COMBOBOX" ? Math.Max(190, box.H) : box.H);
                uint flags = 0x11c | (ScrollVisible(box.Y, height, applyViewport) ? 0x40u : 0x80u);
                batch = DeferWindowPos(batch, item.Handle, IntPtr.Zero, Px(box.X), Px(box.Y) - scrollPosition, Px(box.W), height, flags);
                if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
            }
            if (!EndDeferWindowPos(batch)) throw new Boundary("permission_layout_failed");
            RepaintTree(now: false);
        }
        finally { positioning = false; }
    }
    [StructLayout(LayoutKind.Sequential)] private struct WindowPlacement
    { public uint Size, Flags, ShowCommand; public Native.Point MinPosition, MaxPosition; public Native.Rect Normal; }
    [DllImport("user32.dll")] private static extern bool GetWindowPlacement(IntPtr hwnd, ref WindowPlacement placement);
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr ChildWindowFromPointEx(IntPtr parent, Native.Point point, uint flags);
    // A minimized window reports a ~237x39 rect and a force-closed one can be
    // destroyed mid-layout. Persisting either made the next window open at that
    // degenerate size -- the "settings shrinks every time" report. Only a real
    // restore rect is accepted, and it is clamped to the supported minimum.
    private static void RememberWindowSize(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero || scale <= 0) return;
        Native.Rect bounds;
        if (IsIconic(hwnd))
        {
            var placement = new WindowPlacement { Size = (uint)Marshal.SizeOf<WindowPlacement>() };
            if (!GetWindowPlacement(hwnd, ref placement)) return;
            bounds = placement.Normal;
        }
        else if (!GetWindowRect(hwnd, out bounds)) return;
        int w = (int)Math.Round((bounds.Right - bounds.Left) / scale), h = (int)Math.Round((bounds.Bottom - bounds.Top) / scale);
        if (w < 320 || h < 240) return;
        lastWidth = Math.Clamp(w, MinWindowWidth, 4096); lastHeight = Math.Clamp(h, MinWindowHeight, 4096);
    }
    [StructLayout(LayoutKind.Sequential)] private struct WindowPosition
    { public IntPtr Window, InsertAfter; public int X, Y, Width, Height; public uint Flags; }
    // WM_GETMINMAXINFO only guards interactive sizing. A restored or programmatic
    // size bypasses it, which is how a degenerate remembered rect could still
    // create an unusable window, so clamp every real resize here as well.
    private static bool ClampWindowPosition(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero || scale <= 0 || windowStateChange > 0 || IsIconic(window)) return false;
        var position = Marshal.PtrToStructure<WindowPosition>(pointer);
        if ((position.Flags & 0x0001u) != 0) return false; // SWP_NOSIZE
        int minWidth = Px(MinWindowWidth), minHeight = Px(MinWindowHeight);
        if (position.Width >= minWidth && position.Height >= minHeight) return false;
        position.Width = Math.Max(position.Width, minWidth); position.Height = Math.Max(position.Height, minHeight);
        Marshal.StructureToPtr(position, pointer, false);
        return true;
    }
    internal static object WindowInteractionProbe()
    {
        int assertions = 0;
        void Require(bool value, [System.Runtime.CompilerServices.CallerArgumentExpression("value")] string assertion = "")
        {
            assertions++;
            if (!value) { Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { fixture = "settings-window", assertions, assertion }));
                throw new Boundary("permission_window_probe_failed"); }
        }
        var settings = new UserPermissionSettings { UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value };
        preview = true;
        try
        {
            Create(IntPtr.Zero, null, settings, false);
            Require(window != IntPtr.Zero && body != IntPtr.Zero);
            (int Left, int Top, int Right, int Bottom) Box(int id)
            {
                Require(positioned.TryGetValue(id, out var box));
                return (Px(box.X), Px(box.Y), Px(box.X + box.W), Px(box.Y + box.H));
            }
            bool Overlaps((int, int, int, int) a, (int, int, int, int) b) =>
                a.Item1 < b.Item3 && b.Item1 < a.Item3 && a.Item2 < b.Item4 && b.Item2 < a.Item4;
            void CheckChrome(int[] ids)
            {
                for (int i = 0; i < ids.Length; i++)
                    for (int j = i + 1; j < ids.Length; j++)
                        Require(!Overlaps(Box(ids[i]), Box(ids[j])));
            }
            // 1) A normal size exposes the sidebar navigation and four footer buttons.
            SetWindowPos(window, IntPtr.Zero, 0, 0, Px(WindowWidth), Px(WindowHeight), 0x1c); Relayout();
            Require(!compactNavigation);
            CheckChrome([1000, 2000, 1010, 2015, 300, 301, 302, 303, 304, 305, 2016, 40, 32, 31, 30, 91, 94]);
            // 2) A deliberately too-small resize is clamped to the supported minimum.
            SetWindowPos(window, IntPtr.Zero, 0, 0, Px(400), Px(300), 0x1c);
            Require(GetWindowRect(window, out var tiny));
            Require(Math.Round((tiny.Right - tiny.Left) / scale) >= MinWindowWidth - 2);
            Require(Math.Round((tiny.Bottom - tiny.Top) / scale) >= MinWindowHeight - 2);
            Relayout();
            Require(compactNavigation);
            CheckChrome([1000, 2000, 1010, 306, 40, 32, 31, 30, 91, 94]);
            Require(Box(40).Item2 >= Box(1010).Item4); // status line sits below the page title
            // 3) Page switching still lands on the requested page.
            for (int index = 0; index < NavPages.Length; index++)
            {
                HandleMessage(window, 0x111, new UIntPtr((uint)(300 + index)), IntPtr.Zero);
                Require(page == NavPages[index] && Text(1010) == PageNames[(int)NavPages[index]]);
            }
            // 4a) Minimizing must not overwrite the remembered size with the
            // ~237x39 minimized rect; only the restore placement is accepted.
            SetWindowPos(window, IntPtr.Zero, 0, 0, Px(WindowWidth), Px(WindowHeight), 0x1c); Relayout();
            int normalWidth = lastWidth, normalHeight = lastHeight;
            ShowWindow(window, 6);
            Require(IsIconic(window));
            RememberWindowSize(window);
            Require(lastWidth == normalWidth && lastHeight == normalHeight);
            ShowWindow(window, 9);
            // 4) Closing a clean window actually closes it.
            Require(!Dirty);
            SendMessageW(window, 0x10, IntPtr.Zero, IntPtr.Zero);
            Require(window == IntPtr.Zero);
            // 5) The remembered size is a sane minimum, not a minimized rect.
            Require(lastWidth >= MinWindowWidth && lastHeight >= MinWindowHeight);
            // 6) A realistic saved policy must open clean: a spurious draft made
            // the X button ask to save every time, which reads as "cannot close".
            var realistic = settings with { AdminWindows = true, AdminLaunchEnabled = false, UacMode = "allowlist", AdminScope = "allowlist" };
            Create(IntPtr.Zero, null, realistic, false);
            Require(!Dirty);
            // Saving must not silently widen a legacy allowlist policy.
            Require(EditedSettings().AdminScope == "allowlist");
            SendMessageW(window, 0x10, IntPtr.Zero, IntPtr.Zero);
            Require(window == IntPtr.Zero);
            return new { assertions, closed = true, minimumEnforced = true, pageSwitchVerified = true, remembersMinimum = new { width = lastWidth, height = lastHeight } };
        }
        finally
        {
            preview = false;
            if (Native.IsWindow(window)) DestroyWindow(window);
            CloseAfterFailure();
        }
    }
    private static void PositionControls()
    {
        if (positioning || body == IntPtr.Zero || IsIconic(window) || !GetClientRect(window, out var rect) || layout.Count == 0) return;
        positioning = true;
        try
        {
        int width = (int)Math.Floor(rect.Right / scale), height = (int)Math.Floor(rect.Bottom / scale);
        compactNavigation = width < PermissionPageLayout.NavigationThreshold || height < 560;
        bodyLeft = compactNavigation ? 12 : BodyLeft; bodyTop = compactNavigation ? 174 : BodyTop;
        int statusHeight = Math.Clamp(MeasureControl(40, width - 40), width < 760 ? 44 : 28, 96);
        footerHeight = 10 + statusHeight + 10 + 36 + 16 + (width < 760 ? 40 : 0);
        int bodyWidth = Math.Max(240, width - bodyLeft - 12 - 18);
        activeLayout = PermissionPageLayout.Build((int)page, bodyWidth, MeasureControl, detailMode.Length > 0, detailMode, explanationOpen);
        PageHeights[(int)page] = activeLayout.Height;
        int viewport = Math.Max(1, rect.Bottom - Px(bodyTop + footerHeight + 8));
        scrollPosition = Math.Clamp(scrollPosition, 0, Math.Max(0, Px(activeLayout.Height) - viewport));
        positioned.Clear();
        positioned[1000] = new(68, 18, Math.Max(180, width - 84), 26);
        positioned[2000] = new(69, 47, Math.Max(180, width - 85), 22);
        positioned[1010] = new(compactNavigation ? 160 : 232, 88, Math.Max(180, width - (compactNavigation ? 176 : 248)), 34);
        positioned[2015] = new(compactNavigation ? 20 : 232, 132, Math.Max(200, width - (compactNavigation ? 40 : 248)), 36);
        positioned[306] = new(16, 88, 128, 38);
        positioned[2016] = new(28, 398, 164, 96);
        for (int i = 0; i < 6; i++) positioned[300 + i] = new(16, 98 + i * 46, 180, 40);
        // The footer must never climb into the header even if a stale rect or a tiny work area slips through.
        int footer = Math.Max(Px(bodyTop + 40), height - footerHeight);
        positioned[40] = new(20, footer + 10, width - 40, statusHeight);
        int actionY = footer + 20 + statusHeight + (width < 760 ? 40 : 0);
        if (width >= 760)
        {
            positioned[32] = new(20, actionY, 132, 36); positioned[91] = new(164, actionY, 108, 36);
            positioned[94] = new(284, actionY, 112, 36);
            positioned[30] = new(width - 318, actionY, 178, 36); positioned[31] = new(width - 128, actionY, 108, 36);
        }
        else
        {
            positioned[91] = new(20, footer + statusHeight + 16, (width - 52) / 2, 28);
            positioned[94] = new(32 + (width - 52) / 2, footer + statusHeight + 16, (width - 52) / 2, 28);
            positioned[32] = new(20, actionY, 104, 36); positioned[31] = new(width - 100, actionY, 80, 36);
            positioned[30] = new(136, actionY, Math.Max(120, width - 248), 36);
        }
        visual?.SetSettingsLayout(activeLayout.Sections, activeLayout.Banners, activeLayout.Heroes, activeLayout.Chips,
            activeLayout.Separators, compactNavigation);
        UpdateOverviewText();
        // DeferWindowPos requires a common parent in each batch. The viewport
        // and fixed chrome share the root; page controls share only the body.
        var batch = BeginDeferWindowPos(layout.Count(item => item.Fixed) + 1);
        if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
        batch = DeferWindowPos(batch, body, IntPtr.Zero, Px(bodyLeft), Px(bodyTop), Px(bodyWidth + 18), viewport, 0x11c);
        if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
        foreach (var item in layout.Where(item => item.Fixed))
        {
            int id = GetDlgCtrlID(item.Handle); var box = positioned[id];
            bool visible = id == 306 ? compactNavigation : id == 2016 ? !compactNavigation && height - footerHeight >= 510
                : id is >= 300 and <= 305 ? !compactNavigation : true;
            batch = DeferWindowPos(batch, item.Handle, IntPtr.Zero, Px(box.X), Px(box.Y), Px(box.W), Px(box.H), 0x11c | (visible ? 0x40u : 0x80u));
            if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
        }
        if (!EndDeferWindowPos(batch)) throw new Boundary("permission_layout_failed");
        batch = BeginDeferWindowPos(layout.Count(item => !item.Fixed));
        if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
        foreach (var item in layout.Where(item => !item.Fixed))
        {
            int id = GetDlgCtrlID(item.Handle);
            bool detail = id is 1091 or 92 or 93 or 95 or 98 or 99 or 96 or 97 or 100;
            bool visible = (detail || item.Page == page) && activeLayout.Controls.TryGetValue(id, out _);
            var box = visible ? activeLayout.Controls[id] : new PermissionPageLayout.Box(item.X, item.Y, item.W, item.H);
            if (visible)
            {
                positioned[id] = box;
                visible = ScrollVisible(box.Y, Px(item.Kind == "COMBOBOX" ? Math.Max(190, box.H) : box.H), viewport);
            }
            uint flags = 0x11c | (visible ? 0x40u : 0x80u); // NOREDRAW|NOCOPYBITS plus SHOW/HIDE
            batch = DeferWindowPos(batch, item.Handle, IntPtr.Zero, Px(box.X), Px(box.Y) - scrollPosition, Px(box.W), Px(item.Kind == "COMBOBOX" ? Math.Max(190, box.H) : box.H), flags);
            if (batch == IntPtr.Zero) throw new Boundary("permission_layout_failed");
        }
        if (!EndDeferWindowPos(batch)) throw new Boundary("permission_layout_failed");
        help?.Refresh();
        RepaintTree();
        }
        finally { positioning = false; }
    }
    // Windows keeps hit-testing a child window that sits outside its parent's
    // client area even though the parent clips its pixels. A page control that
    // has scrolled completely out of the body therefore used to swallow clicks
    // on the fixed chrome above the viewport (the switch under the page blurb
    // became unclickable). Hide it as soon as it leaves the viewport instead.
    private static bool ScrollVisible(int boxTop, int heightPx, int viewport)
    {
        int top = Px(boxTop) - scrollPosition;
        return top + heightPx > 0 && top < viewport;
    }
    // The prototype keeps a live status strip on the overview page: the rail
    // never shows stale switches, and the banner follows the real state.
    private static void UpdateOverviewText()
    {
        if (!controls.TryGetValue(3002, out var ready)) return;
        var saved = UserPermissions.Effective(original!);
        int savedTier = UserPermissions.TierOf(saved), draftTier = CurrentTier();
        bool ordinaryReady = policyValid && !conflict && savedTier >= 0 && lastStopped != true;
        bool adminReady = ordinaryReady && savedTier >= 1;
        bool uacReady = ordinaryReady && savedTier >= 3 && (saved.UacMode switch {
            "observe" => uacCapabilities.ObserveAvailable,
            "cancel" => uacCapabilities.CancelAvailable,
            "allowlist" => uacCapabilities.AllowlistAvailable,
            "semantic" => uacCapabilities.SemanticAuthorityAvailable,
            _ => false });
        SetWindowTextW(ready, !policyValid || conflict ? "普通控制  状态需核对"
            : savedTier < 0 ? "普通控制  完全禁止" : lastStopped == true ? "普通控制  已停止" : "普通控制  已允许");
        SetWindowTextW(controls[3003], adminReady ? "管理员窗口  已允许" : "管理员窗口  不可用");
        SetWindowTextW(controls[3004], savedTier < 3 ? "UAC 后备  未开启" : uacReady ? "UAC 后备  路线就绪" : "UAC 后备  路线未就绪");
        visual?.SetChipStates(adminReady, uacReady, ordinaryReady, savedTier >= 3);
        if (controls.TryGetValue(3020, out var banner))
            SetWindowTextW(banner, savedTier < 0 ? "已保存为完全禁止，三个控制通道均不派发。可到管理员能力选择所需档位。"
                : "上方显示已保存权限和路线状态。档位立即切换，其它编辑保存后生效；已允许不等于具体动作已成功。");
        if (controls.TryGetValue(3030, out var adminBanner))
            SetWindowTextW(adminBanner, draftTier < 0 ? "已选择完全禁止，三个控制通道均不派发。已运行的成果程序保留。"
                : "01 普通控制，02 增加管理员窗口，03 增加管理员执行，04 增加 UAC 后备。普通档立即降权；管理员档经 Windows 确认后切换。");
        if (controls.TryGetValue(3040, out var uacBanner))
            SetWindowTextW(uacBanner, "SYSTEM 级别，是这里最危险的一项。只在管理员任务真的卡在系统提示时开；密码、解锁、改自身权限都不碰。");
        if (controls.TryGetValue(3031, out var adminToggle))
            SetWindowTextW(adminToggle, "管理员能力包含什么、开到哪为止    " + (explanationOpen ? "▴ 收起" : "▾ 展开"));
        if (controls.TryGetValue(3041, out var uacToggle))
            SetWindowTextW(uacToggle, "UAC 后备的能力与边界    " + (explanationOpen ? "▴ 收起" : "▾ 展开"));
    }
    private static int MeasureControl(int id, int width)
    {
        var hwnd = controls[id]; var item = layout.First(item => item.Handle == hwnd);
        if (item.Kind == "COMBOBOX") return 34;
        if (item.Kind == "LISTBOX") return id == 28 ? 128 : 112;
        if (item.Kind == "EDIT") return id == 92 ? 152 : id is 2008 or 2108 ? 132 : id is 11 or 3402 ? 112 : 34;
        bool checkbox = item.Kind == "BUTTON" && (GetWindowLongW(hwnd, -16) & 15) == 3;
        int padding = item.Kind == "BUTTON" ? checkbox ? 96 : 24 : 0;
        var dc = GetDC(hwnd); if (dc == IntPtr.Zero) return item.H;
        var old = SelectObject(dc, SendMessageW(hwnd, 0x31, IntPtr.Zero, IntPtr.Zero));
        try
        {
            var rect = new Native.Rect { Right = Px(Math.Max(80, width - padding)) };
            string text = Text(id);
            DrawTextW(dc, text.Length == 0 ? " " : text, -1, ref rect, 0x400 | 0x10); // CALCRECT|WORDBREAK
            int measured = (int)Math.Ceiling(rect.Bottom / scale);
            return item.Kind == "BUTTON" ? Math.Max(checkbox ? 44 : 36, measured + 16) : Math.Max(22, measured + 2);
        }
        finally { SelectObject(dc, old); ReleaseDC(hwnd, dc); }
    }
    private static void Relayout()
    {
        var previous = new[] { font, nameFont, headingFont, titleFont, smallFont };
        // One family for the whole surface. The old Segoe UI body next to a
        // Microsoft YaHei UI tray menu made the two windows look unrelated,
        // and CJK fallback changed the line height between controls.
        IntPtr Font(int size, int weight) => CreateFontW(-Px(size), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, "Microsoft YaHei UI");
        font = Font(13, 400); nameFont = Font(14, 400); headingFont = Font(14, 600);
        titleFont = Font(21, 600); smallFont = Font(12, 400);
        if (new[] { font, nameFont, headingFont, titleFont, smallFont }.Any(item => item == IntPtr.Zero)) throw new Boundary("permission_font_failed");
        if (window != IntPtr.Zero) SendMessageW(window, 0x30, font, new IntPtr(1));
        foreach (var item in layout)
        {
            var id = GetDlgCtrlID(item.Handle);
            bool toggle = item.Kind == "BUTTON" && (GetWindowLongW(item.Handle, -16) & 15) == 3;
            var selected = id is 1010 or 3000 ? titleFont
                : id is 1000 or 3010 or 1003 or 1004 or 1005 or 1006 or 1008 or 3033 or 1091 ? headingFont
                : toggle || id is 1002 or 2032 ? nameFont
                : id == 3001 ? smallFont
                : font;
            SendMessageW(item.Handle, 0x30, selected, new IntPtr(1));
        }
        PositionControls();
        foreach (var old in previous) if (old != IntPtr.Zero) DeleteObject(old);
    }
    private static void StopSmoothScroll()
    {
        smoothTarget = -1;
        if (window != IntPtr.Zero) KillTimer(window, SmoothTimer);
    }
    private static void Scroll(int command, int track = -1)
    {
        StopSmoothScroll();
        var info = new ScrollInfo { Size = (uint)Marshal.SizeOf<ScrollInfo>(), Mask = 0x17 };
        if (!GetScrollInfo(body, 1, ref info)) return;
        int next = command switch { 0 => scrollPosition - Px(24), 1 => scrollPosition + Px(24),
            2 => scrollPosition - (int)info.Page, 3 => scrollPosition + (int)info.Page,
            4 or 5 => track >= 0 ? track : info.Track, 6 => 0, 7 => info.Max, _ => scrollPosition };
        next = Math.Clamp(next, 0, Math.Max(0, info.Max - (int)info.Page + 1));
        if (next != scrollPosition) { scrollPosition = next; PositionControls(); UpdateScroll(); }
    }
    private static void EnsureFocusedVisible()
    {
        var focus = GetFocus();
        if (body == IntPtr.Zero || !IsChild(body, focus) || !GetWindowRect(focus, out var rect) || !GetClientRect(body, out var viewport)) return;
        var point = new Native.Point { X = rect.Left, Y = rect.Top };
        if (!ScreenToClient(body, ref point)) return;
        int next = scrollPosition;
        if (point.Y < 0) next += point.Y - Px(12);
        else if (point.Y + rect.Bottom - rect.Top > viewport.Bottom)
            next += point.Y + rect.Bottom - rect.Top - viewport.Bottom + Px(12);
        next = Math.Clamp(next, 0, Math.Max(0, Px(PageHeights[(int)page]) - viewport.Bottom));
        if (next != scrollPosition) { scrollPosition = next; PositionControls(); UpdateScroll(); }
    }
    internal static int RunPreview()
    {
        // Explicit standalone preview: no broker, tray, hotkey or protected policy.
        preview = true;
        var settings = PreviewSettings();
        try
        {
            Create(IntPtr.Zero, null, settings, true);
            Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { preview = "permission-interface",
                pid = Environment.ProcessId, hwnd = window.ToInt64(), dpi = GetDpiForWindow(window),
                artwork = visual?.ArtworkState, policyReadOrWritten = false }));
            while (true)
            {
                int result = GetMessageW(out var message, IntPtr.Zero, 0, 0);
                if (result == 0) break;
                if (result < 0) throw new Boundary("permission_preview_messages_failed");
                if (!HandleDialogMessage(ref message)) { TranslateMessage(ref message); DispatchMessageW(ref message); }
            }
            return 0;
        }
        finally { CloseAfterFailure(); preview = false; }
    }

    private static UserPermissionSettings PreviewSettings()
        => new() { UserSid = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value,
            Revision = "synthetic-preview", AdminScope = "allowlist", SmoothPointer = true,
            AdminLaunchAllowlist = [new(@"E:\Preview\Editor.exe", "sha256", new string('a', 64), "示例编辑器（合成）", true, "")],
            UacAllowlist = [new(@"E:\Preview\Setup.exe", "sha256", new string('b', 64), "示例安装程序（合成）", false, "")],
            AllowedAdminApplications = [new("E:\\Preview\\Editor.exe"), new("E:\\Preview\\Canvas.exe", "画布")],
            DeniedApplications = [new("E:\\Preview\\Private.exe")],
            Masks = [new("E:\\Preview\\Editor.exe", [20, 20, 260, 110], [1280, 720])] };

    // Offscreen-only capture for visual evidence. The window is placed outside
    // the desktop, shown without activation and rendered to a bitmap; no input,
    // no broker and no policy write. Used by --snapshot-permission-window.
    internal static int RunSnapshot(string directory, int width = 1500, int height = 1000)
    {
        preview = true;
        try
        {
            Create(IntPtr.Zero, null, PreviewSettings(), true);
            SettingsArtwork.PlaceOffscreen(window, width, height);
            Thread.Sleep(300);
            Directory.CreateDirectory(directory);
            var target = Path.Combine(directory, "settings-production-offscreen.png");
            SettingsArtwork.SaveWindowPng(window, width, height, target);
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { state = "snapshot_saved",
                path = target, width, height, dpi = GetDpiForWindow(window),
                high_contrast = visual?.HighContrast, policyReadOrWritten = false, keyboard_input = false }));
            return 0;
        }
        finally { CloseAfterFailure(); preview = false; }
    }
    private static int CurrentTier() => fullyDisabled ? -1
        : !Checked(1) ? 0 : !Checked(78) ? 1 : Checked(79) ? 3 : 2;
    private static void UpdateTierControls(bool writable)
    {
        int tier = CurrentTier();
        visual?.SetTier(tier);
        string[] names = ["普通控制", "管理员窗口", "管理员执行", "系统级接管"];
        string[] hints = [
            "只操作普通窗口；管理员窗口、管理员进程、SYSTEM 与 UAC 全部关闭。",
            "可以观察与操作管理员窗口；不会启动管理员进程，也不处理 UAC。",
            "可以在名单或本任务授权范围内执行 High 启动；不处理 UAC。",
            "在 03 之上处理 UAC 观察、取消与确认；系统接入未就绪时不会切到这一档。"];
        for (int index = 0; index < 4; index++)
            if (controls.TryGetValue(3301 + index, out var handle))
            {
                SetWindowTextW(handle, (tier == index ? "● " : "○ ") + "0" + (index + 1) + "  " + names[index]);
                EnableWindow(handle, writable);
            }
        if (controls.TryGetValue(2001, out var summary))
        {
            int savedTier = UserPermissions.TierOf(original!);
            string label(int value) => value < 0 ? "完全禁止" : "0" + (value + 1) + " " + names[value];
            SetWindowTextW(summary, "已保存：" + label(savedTier) + "\r\n草稿：" + label(tier)
                + (tier == savedTier ? "（档位未改）" : "（保存后应用）") + "\r\n"
                + (tier < 0 ? "三个控制通道均不派发；托盘、结束控制和设置仍可用。" : hints[tier]));
        }
        if (controls.TryGetValue(2035, out var mode))
            SetWindowTextW(mode, launchMode == "semantic"
                ? "按本机批准的工作范围及逐次执行绑定处理。不是沙盒；撤销不终止已启动程序。与 04 独立。"
                : "直接启动名单外请求拒绝；与 04 的 UAC 确认方式及名单独立。");
        if (controls.TryGetValue(2036, out var uacDescription))
            SetWindowTextW(uacDescription, uacSubmode == "semantic"
                ? "工作授权下的 UAC 确认尚未就绪，当前不能新启用。与 03 独立。"
                : "仅确认 UAC 名单中的程序；与 03 的直接启动方式及名单独立。");
        if (controls.TryGetValue(3311, out var allow))
        {
            SetWindowTextW(allow, (launchMode == "allowlist" ? "● " : "") + "名单模式");
            EnableWindow(allow, writable && tier >= 2);
        }
        if (controls.TryGetValue(3312, out var semantic))
        {
            SetWindowTextW(semantic, (launchMode == "semantic" ? "● " : "") + "任务授权");
            EnableWindow(semantic, writable && tier >= 2);
        }
        foreach (int id in new[] { 3321, 3322 })
        {
            SetWindowTextW(controls[id], ((id == 3322) == (uacSubmode == "semantic") ? "● " : "")
                + (id == 3321 ? "名单模式" : "语义授权 · 未就绪"));
            EnableWindow(controls[id], writable && tier >= 3 && id == 3321);
        }
    }
    private static void SetTier(int tier)
    {
        EndUacWindowPick();
        fullyDisabled = tier < 0;
        Check(1, tier >= 1); Check(78, tier >= 2); Check(79, tier >= 3);
        if (tier < 3) uacMode = "off";
        UpdateUacControls();
    }
    private static void RequestSystemTier()
    {
        if (!preview && broker is not null) { RequestExecutionTier(3); return; }
        if (!policyValid || conflict || UacBusy) throw new Boundary("uac_settings_work_busy");
        if (CurrentTier() == 3) { SetTier(-1); return; }
        if (uacCapabilities.AllowlistAvailable) { SetTier(3); return; }
        SetNotice("预览不准备系统入口；原档位不变。实际接入完成并通过同版本路线检查后才可选择 04。");
    }
    private static bool CompleteSystemTierPreparation(UserPermissionSettings expected, UserPermissionSettings current, UacCapabilities capabilities)
    {
        if (original is null || expected.Revision != original.Revision || current.Revision != expected.Revision)
        { conflict = true; SetNotice("准备期间已保存设置发生变化，未切换档位。请重新载入核对；本次草稿仍保留。"); UpdateUacControls(); return false; }
        if (!capabilities.AllowlistAvailable)
        {
            ShowPage(SettingsPage.Validation);
            OpenPanel("help", "04 尚不可用 · 原档位保留", "固定入口准备已结束，但当前版本的校准证据尚未齐备："
                + UacReasonText(capabilities.Reason)
                + "\r\n\r\n准备入口不等于系统接管已启用。当前从关闭状态完成全部校准的入口仍未交付；本次不改变原档位、名单或停止状态。");
            SetNotice("04 的校准尚未齐备；已展开具体原因，原档位保持。"); return false;
        }
        SetTier(3);
        SetNotice("同版本系统接入与路线检查通过，草稿已选择 04；保存后应用。本次未处理任何 UAC 提示。");
        return true;
    }
    private static UserPermissionSettings EditedSettings() => original! with { AdminWindows = Checked(1),
        // This page does not edit AdminScope. Forcing "all" here silently
        // widened a legacy allowlist policy on any unrelated save.
        AdminScope = original!.AdminScope, AdminLaunchEnabled = Checked(1) && Checked(78),
        AuthorityTier = CurrentTier(), AdminLaunchMode = launchMode,
        UacMode = CurrentTier() >= 3 ? uacMode == "off" ? "allowlist" : uacMode : "off",
        UacCancellationScope = uacCancellationScope,
        AdminLaunchAllowlist = adminLaunchAllowlist.ToArray(), UacAllowlist = uacAllowlist.ToArray(), JevEnabled = Checked(4),
        SmoothPointer = original!.SmoothPointer, HudCompact = Checked(6),
        HudPosition = new[] { "auto", "top_left", "top_right", "bottom_left", "bottom_right" }[Math.Clamp(SendMessageW(controls[7], 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32(), 0, 4)],
        DeniedApplications = ParseLines(Text(11)), DeniedAdminWindowApplications = ParseLines(Text(3402)),
        DeniedAdminLaunchApplications = deniedLaunchPrograms.ToArray(), DeniedUacApplications = deniedUacPrograms.ToArray(),
        Masks = masks.ToArray() };
    internal static bool SameSettings(UserPermissionSettings left, UserPermissionSettings right)
        => System.Text.Json.JsonSerializer.Serialize(left with { Revision = "" })
            == System.Text.Json.JsonSerializer.Serialize(right with { Revision = "" })
            && left.UacPolicyError == right.UacPolicyError;
    internal static bool OnlyUacDisabled(UserPermissionSettings baseline, UserPermissionSettings actual)
        => actual.UacMode == "off"
            && System.Text.Json.JsonSerializer.Serialize(UserPermissions.Effective(UserPermissions.WithoutUac(baseline)) with { Revision = "" })
                == System.Text.Json.JsonSerializer.Serialize(UserPermissions.Effective(actual) with { Revision = "" })
            && baseline.UacPolicyError == actual.UacPolicyError;
    // Compare against the draft captured from the controls, not the raw saved
    // record. A saved policy can carry values the page cannot represent
    // (for example UAC "allowlist" while direct launch is off), and
    // comparing raw values marked every such window as dirty, so X always
    // asked to save instead of closing.
    private static UserPermissionSettings? controlBaseline;
    private static bool Dirty => controlBaseline is not null && controls.ContainsKey(1)
        && (!SameSettings(controlBaseline, EditedSettings()) || uiBaselineSubmode != uacSubmode || uiPreferencePending);
    private static bool CompleteSave(UserPermissionSettings saved, bool close, UserPermissionSettings? submittedDraft = null,
        SettingsUiSave? uiSave = null)
    {
        // This is the exact committed snapshot, not a fresh read that could
        // belong to a later disable or another writer. Keep all current drafts.
        original = saved;
        // A delayed completion must never mark edits made after submission as
        // saved. Busy spans worker completion through consumption of its reply.
        controlBaseline = (submittedDraft ?? saved) with { Revision = saved.Revision, UacPolicyError = saved.UacPolicyError };
        if (uiSave is null) { uiBaselineSubmode = uacSubmode; uiPreferencePending = false; }
        else if (uiSave.PreferenceRequested)
        {
            uiPreferencePending = uiSave.Error is not null;
            if (uiSave.Error is null && uiSave.Saved is not null)
            { uiPreference = uiSave.Saved; uiBaselineSubmode = uiSave.SubmittedMode; }
        }
        if (PreferenceSaveConflicts(uiSave?.Error)) conflict = true;
        policyValid = !saved.Revision.StartsWith("invalid:", StringComparison.Ordinal);
        bool shouldClose = close && closeAfterSave && uiSave?.Error is null;
        closeAfterSave = false;
        if (shouldClose && !Dirty && !UacBusy && !conflict) { DestroyWindow(window); return true; }
        if (detailMode is "close" or "reload" && !Dirty) CloseDetails();
        UpdateUacControls(); RefreshFooter(); PositionControls(); UpdateScroll();
        SetNotice(uiSave?.Error is not null ? (uiSave.PolicyWritten ? "权限设置已保存；" : "本次没有修改权限；")
                + "04 模式偏好未确认保存（" + uiSave.Error + "）。请重新载入核对，未保存的模式选择仍保留。"
            : conflict ? "本次保存已完成，但后续配置发生变化；草稿保留，请重新载入核对。"
            : preview ? "已保存到预览内存；本机权限未读取或写入。" : "已保存并应用；窗口保留，可继续编辑。");
        return false;
    }
    private static void SetNotice(string message)
    { notice = message; RefreshFooter(); }
    private static void ReportProblem(string message)
    {
        closeAfterSave = false;
        SetNotice("操作未完成，编辑保留；详细原因见页内说明。");
        OpenPanel("help", "操作未完成 · 草稿保留", message);
    }
    private static void RefreshFooter()
    {
        if (!controls.ContainsKey(40) || original is null) return;
        string state = conflict ? "配置已在外部更改：草稿保留，保存已阻止。请重新载入后核对。"
            : surfaceFault ? "界面操作未完成，草稿保留；重新载入前不会保存。"
            : !policyValid ? "原配置不可读取，不能保存默认草稿；结束控制仍可用。"
            : UacBusy ? "正在执行系统操作；结束控制仍可用，结果未知时不会重试。"
            : (Dirty ? "有未保存草稿 · 跨分区保留 · Ctrl+S 保存" : "全部分区已保存")
                + (preview ? " · 内存预览，不读写本机权限" : " · 托盘开关立即生效");
        if (localSettings) state = (localStopHotkey ? "本页 Ctrl+Alt+9 已注册；结束控制可用。" : "本页未取得 Ctrl+Alt+9 热键；结束控制仍可用，物理 Stop 测试不可用。") + "\r\n" + state;
        if (lastStopped == true) state = "全部写入处于保护性停止\r\n" + state;
        else if (lastComputerPaused == true) state = "Computer 输入已暂停 · 可从托盘继续\r\n" + state;
        string brief = notice.Length > 42 ? notice[..42] + "…" : notice;
        SetWindowTextW(controls[40], brief.Length == 0 ? state : brief + "\r\n" + state);
    }
    private static void OpenPanel(string mode, string title, string text)
    {
        if (detailMode.Length == 0) { detailReturnScroll = scrollPosition; detailReturnFocus = GetFocus(); }
        if (mode != "candidate") pendingProgram = null;
        detailMode = mode; SetWindowTextW(controls[1091], title); SetWindowTextW(controls[92], text);
        StopSmoothScroll(); scrollPosition = 0; PositionControls(); UpdateScroll();
    }
    private static void OpenHelp(int id)
    {
        if (detailMode == "candidate") { SetFocus(controls[92]); return; }
        bool section = id is 0 or 91 or >= 300 and <= 311 || PermissionHelp.Short(id).Length == 0;
        string text = section ? PermissionHelp.PageDetail((int)page) : PermissionHelp.Detail(id);
        if (section && page == SettingsPage.Validation) text += "\r\n\r\n当前可用性：\r\n" + Text(2212) + "\r\n" + Text(2104);
        OpenPanel("help", section ? PageNames[(int)page] + " · 全部说明" : "详细说明 · F1", text);
        SetFocus(controls[92]);
    }
    private static void CloseDetails(bool relayout = true)
    {
        StopSmoothScroll();
        if (detailMode.Length > 0) scrollPosition = detailReturnScroll;
        detailMode = ""; pendingProgram = null; closeAfterSave = false;
        if (relayout && window != IntPtr.Zero)
        {
            PositionControls(); UpdateScroll();
            if (Native.IsWindow(detailReturnFocus) && Native.IsWindowVisible(detailReturnFocus) && IsWindowEnabled(detailReturnFocus)) SetFocus(detailReturnFocus);
            else SetFocus(controls[91]);
            EnsureFocusedVisible();
        }
    }
    private static void RequestClose()
    {
        EndUacWindowPick();
        if (!Dirty && !UacBusy) { DestroyWindow(window); return; }
        OpenPanel("close", UacBusy ? "系统操作仍在进行" : "保存这些更改后关闭？",
            UacBusy ? "本次系统操作仍在进行，不能把未知结果当作完成。可使用页脚结束控制，等待本次结果后再关闭；草稿保留。"
            : "所有分区共用的草稿尚未保存。\r\n\r\n保存并关闭：应用整页草稿，保存失败会保留编辑。\r\n放弃草稿并关闭：保留已经生效的系统动作和托盘更改。\r\n返回编辑：继续保留所有草稿。"
                + (conflict ? "\r\n\r\n配置已发生外部变化，旧草稿不能覆盖。请返回编辑并重新载入，或放弃草稿关闭。" : ""));
        EnableWindow(controls[95], policyValid && !surfaceFault && !conflict && !UacBusy);
        EnableWindow(controls[98], !UacBusy);
        SetFocus(controls[99]);
    }
    private static void RequestReload()
    {
        if (UacBusy) { SetNotice("系统操作仍在进行，请等本次结果后重新载入。"); return; }
        if (Dirty)
        {
            OpenPanel("reload", "放弃草稿并重新载入？", "这会丢弃所有分区未保存的编辑，读取当前已保存设置。已完成的即时动作不会撤销。\r\n\r\n需要保留的内容可先从详情或输入框选中复制；也可返回继续编辑。");
            SetFocus(controls[99]); return;
        }
        ReloadSaved();
    }
    private static void ReloadSaved()
    {
        if (UacBusy) return;
        var loaded = broker is null ? previewSaved ?? original! : UserPermissions.Read();
        original = loaded; policyValid = !loaded.Revision.StartsWith("invalid:", StringComparison.Ordinal); surfaceFault = false;
        var effective = UserPermissions.Effective(loaded);
        fullyDisabled = effective.AuthorityTier < 0; launchMode = effective.AdminLaunchMode;
        Check(1, effective.AdminWindows); Check(78, effective.AdminLaunchEnabled);
        uacMode = effective.UacMode;
        uiPreference = !preview && broker is not null ? UserPermissions.ReadUiPreference() : uiPreference;
        uacSubmode = UserPermissions.PreferredUacSubmode(effective.UacMode, uiPreference);
        uiBaselineSubmode = uacSubmode;
        uiPreferencePending = false;
        Check(79, uacMode != "off"); uacCancellationScope = loaded.UacCancellationScope;
        Check(4, loaded.JevEnabled); Check(6, loaded.HudCompact);
        SendMessageW(controls[7], 0x14e, new IntPtr(Array.IndexOf(new[] { "auto", "top_left", "top_right", "bottom_left", "bottom_right" }, loaded.HudPosition)), IntPtr.Zero);
        SetWindowTextW(controls[11], Lines(loaded.DeniedApplications));
        SetWindowTextW(controls[3402], Lines(loaded.DeniedAdminWindowApplications));
        deniedLaunchPrograms.Clear(); deniedLaunchPrograms.AddRange(loaded.DeniedAdminLaunchApplications);
        deniedUacPrograms.Clear(); deniedUacPrograms.AddRange(loaded.DeniedUacApplications);
        RefreshBlockedPrograms(ProgramListKind.Launch); RefreshBlockedPrograms(ProgramListKind.Uac);
        masks.Clear(); masks.AddRange(loaded.Masks); RefreshMasks();
        adminLaunchAllowlist.Clear(); adminLaunchAllowlist.AddRange(loaded.AdminLaunchAllowlist);
        uacAllowlist.Clear(); uacAllowlist.AddRange(loaded.UacAllowlist);
        conflict = false; CloseDetails(relayout: false); notice = uiPreference.Error is null
            ? "已重新载入当前保存的设置。" : "权限设置已重新载入；04 界面模式偏好未能读取，当前权限不受影响。";
        controlBaseline = EditedSettings();
        RefreshUacAllowlist(kind: ProgramListKind.Launch); RefreshUacAllowlist(); UpdateUacControls(); PositionControls(); UpdateScroll();
    }
    private static void ReconcileImmediateDisable(UserPermissionSettings actual)
    {
        // Only this page's precisely known side effect may advance the CAS
        // baseline. Any sibling/tray change must never be overwritten by draft.
        if (original is not null && OnlyUacDisabled(original, actual))
        {
            original = actual;
            if (controlBaseline is not null) controlBaseline = SameRoleSubmission(controlBaseline, actual);
            fullyDisabled = UserPermissions.TierOf(actual) < 0;
        }
        else conflict = true;
        uacMode = "off"; Check(79, false);
    }
    private static void SourceMenu(ProgramListKind kind)
    {
        if (uacWindowPick is not null) { EndUacWindowPick(); UpdateUacControls(); return; }
        if (preview || broker is null) { SetNotice("预览不枚举真实窗口或登记程序；可查看合成名单详情。"); return; }
        var menu = CreatePopupMenu();
        try
        {
            AppendMenuW(menu, 0, new UIntPtr((uint)ListControl(kind, 63)), "按键选择窗口 · Ctrl+Alt+8（优先）");
            AppendMenuW(menu, 0, new UIntPtr((uint)ListControl(kind, 76)), "从运行窗口选择…");
            AppendMenuW(menu, 0, new UIntPtr((uint)ListControl(kind, 77)), "选择程序文件…（兜底）");
            GetWindowRect(controls[ListControl(kind, 62)], out var bounds);
            uint command = TrackPopupMenu(menu, 0x100, bounds.Left, bounds.Bottom, 0, window, IntPtr.Zero);
            if (command != 0) SendMessageW(window, 0x111, new IntPtr(command), IntPtr.Zero);
        }
        finally { DestroyMenu(menu); }
    }
    private static void NavigationMenu()
    {
        var menu = CreatePopupMenu();
        try
        {
            for (int i = 0; i < NavPages.Length; i++)
                AppendMenuW(menu, page == NavPages[i] ? 8u : 0, new UIntPtr((uint)(300 + i)), PageNames[(int)NavPages[i]]);
            GetWindowRect(controls[306], out var bounds);
            uint choice = TrackPopupMenu(menu, 0x100, bounds.Left, bounds.Bottom, 0, window, IntPtr.Zero);
            // The rail order is not the enum order: Overview is last in the
            // enum but first in the nav. Map through NavPages for the compact
            // "分区" popup, exactly like the rail buttons do.
            if (choice is >= 300 and <= 305) { ShowPage(NavPageFor((int)choice - 300)); SetFocus(controls[306]); }
        }
        finally { DestroyMenu(menu); }
    }
    private static IntPtr WindowMessageCore(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        if (hwnd == window && message == 0x113 && wp == ExecutionRoleReplyTimer)
        { DrainExecutionRoleReply(); return IntPtr.Zero; }
        if (message == UacWorkFinished)
        {
            long replyToken = (long)wp.ToUInt64();
            if (!uacReplies.TryRemove(replyToken, out var reply)) return IntPtr.Zero;
            pendingUiReplies.TryRemove(replyToken, out _);
            if (reply.WindowGeneration != windowGeneration || window == IntPtr.Zero) return IntPtr.Zero;
            if (reply.Kind == "tier")
            {
                try { CompleteExecutionTier(reply); }
                catch (Exception error) { changingExecutionRole = false; EnableWindow(window, true); conflict = true;
                    ReportProblem("档位切换后的界面核对未完成：" + Program.Code(error) + "。原草稿保留，请重新载入核对。"); return IntPtr.Zero; }
                if (reply.Error is null) return IntPtr.Zero;
            }
            if (RefreshCapabilitiesAfterWork(reply.Kind, reply.PreferenceOnly))
                uacCapabilities = broker is null ? new(false, false, false, false, "预览不读取接入状态。") : ReadUacCapabilities();
            if (reply.Kind == "disable" && reply.Error is null)
            {
                try { ReconcileImmediateDisable(UserPermissions.Read()); }
                catch { conflict = true; uacMode = "off"; Check(79, false); }
            }
            if (reply.Kind == "save" && reply.Error is null)
            {
                try
                {
                    if (reply.Saved is null) throw new Boundary("user_policy_save_snapshot_unavailable");
                    CompleteSave(reply.Saved, reply.CloseOnSuccess, reply.SubmittedDraft, reply.UiSave);
                }
                catch (Exception error)
                { conflict = true; closeAfterSave = false; ReportProblem("保存后的界面复核未完成：" + Program.Code(error) + "。原草稿保留，请重新载入核对。"); }
                return IntPtr.Zero;
            }
            if (reply.Kind == "prepare_tier" && reply.Error is null)
            {
                try
                {
                    if (reply.Saved is null) throw new Boundary("user_policy_save_snapshot_unavailable");
                    CompleteSystemTierPreparation(reply.Saved, broker is null ? previewSaved ?? original! : UserPermissions.Read(), uacCapabilities);
                }
                catch (Exception error) { ReportProblem("系统准备后的检查未完成：" + Program.Code(error) + "。原档位保留，不自动重试。"); }
                finally { if (window != IntPtr.Zero) { UpdateUacControls(); PositionControls(); UpdateScroll(); } }
                return IntPtr.Zero;
            }
            if (reply.Error is not null && reply.Kind is "save" or "disable" or "tier")
            {
                closeAfterSave = false;
                try { if (ProtectedWorkFailureConflicts(reply.Error, UserPermissions.Read().Revision, original!.Revision)) conflict = true; }
                catch { conflict = true; }
            }
            if (window != IntPtr.Zero) UpdateUacControls();
            if (reply.Error is not null)
                ReportProblem("操作未完成：" + reply.Error + "。\r\n本次编辑与原动作结果保留；结果未知时不会自动重试。"
                    + (conflict ? "\r\n保存版本已变化或无法核实，已阻止旧草稿覆盖。请重新载入当前设置后核对。" : "\r\n可返回当前分区继续编辑，或根据本次原因修复后重新尝试保存。"));
            else SetNotice(reply.Kind == "prepare" ? "固定系统入口已准备。尚未通过真实安全界面验证的能力仍不可用。"
                    : reply.Kind == "disable" ? "UAC 与系统入口已立即停用；其它不冲突草稿、名单和记录保留。"
                    : reply.Kind == "qualification" ? "5 次固定无害测试已通过并完成登记。物理 Stop 仍需单独测试；已保存模式和名单未改变，也未自动恢复 Stop。"
                    : reply.Kind == "physical_stop" ? "物理 Stop 与证据保存检查通过。Stop 保持停止；若提示仍在，由你按 Esc 取消。本页不会自动恢复或重放动作。"
                    : reply.Kind == "register" ? "已有真实证据已登记，实际能力请看本页状态。未弹新 UAC、未改模式、未恢复 Stop；这不代表任意确认已开放。"
                    : "单次 Esc 取消与证据保存检查通过；已保存模式未改变。");
            PositionControls(); UpdateScroll();
            return IntPtr.Zero;
        }
        bool command = message == 0x111 && (hwnd == window || hwnd == body);
        int controlId = (int)(wp.ToUInt64() & 0xffff), notification = (int)(wp.ToUInt64() >> 16);
        if (command) PublishSurface("command_received", controlId, notification);
        var result = HandleMessage(hwnd, message, wp, lp);
        if (command) PublishSurface("command_handler_returned", controlId, notification);
        return result;
    }
    private static IntPtr HandleMessage(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        if (hwnd == window && message == 0x112 && (wp.ToUInt64() & 0xfff0) is 0xf020 or 0xf030 or 0xf120)
        {
            ++windowStateChange;
            try { return DefWindowProcW(hwnd, message, wp, lp); }
            finally { --windowStateChange; PublishSurface("window_state_changed"); }
        }
        if (hwnd == window && message == 6 && (wp.ToUInt64() & 0xffff) != 0)
        {
            var result = DefWindowProcW(hwnd, message, wp, lp);
            RestoreSettingsFocus(); return result;
        }
        if (hwnd == window && message == 7) { RestoreSettingsFocus(); return IntPtr.Zero; }
        if (message == 0x46 && hwnd == window) { ClampWindowPosition(lp); return DefWindowProcW(hwnd, message, wp, lp); }
        if (message == 0x24 && hwnd == window && scale > 0)
        {
            var bounds = Marshal.PtrToStructure<MinMaxInfo>(lp);
            bounds.MinTrack = new Native.Point { X = Px(MinWindowWidth), Y = Px(MinWindowHeight) };
            Marshal.StructureToPtr(bounds, lp, false); return IntPtr.Zero;
        }
        if (hwnd == window && message == 0x312 && wp.ToUInt64() == UacLocalStopHotkey)
        {
            StopSettingsWork(); return IntPtr.Zero;
        }
        if (hwnd == window && message == 0x312 && wp.ToUInt64() == UacPickHotkey)
        {
            try { CompleteUacWindowPick(); }
            catch (Exception error) { if (window != IntPtr.Zero) ShowError(window, UacWindowPickError(error)); }
            return IntPtr.Zero;
        }
        if (hwnd == window && message == 0x113 && wp == UacPickTimer)
        {
            var selection = uacWindowPick;
            if (selection is not null && (selection.Expired(Environment.TickCount64) || selection.Generation != windowGeneration
                || broker is null || broker.Shutdown.IsCancellationRequested || broker.ProtectedStopEpoch != selection.StopEpoch
                || !selection.WasPaused && broker.IsPaused))
            {
                EndUacWindowPick();
                if (window != IntPtr.Zero) { UpdateUacControls(); SetNotice("窗口选择已结束，没有更改名单；可重新开始。"); }
            }
            return IntPtr.Zero;
        }
        if (hwnd == window && message == 0x113 && wp == StopStatusTimer)
        {
            try { if (RefreshStopStatus()) { RefreshFooter(); PositionControls(); UpdateScroll(); } }
            catch { SetNotice("停止状态读取失败；结束控制仍可用。"); }
            return IntPtr.Zero;
        }
        if (hwnd == window && message == 0x113 && wp == SmoothTimer)
        {
            // Ease toward the wheel target; the last frame settles the page
            // with one full layout so nothing is left half-applied.
            int distance = smoothTarget - scrollPosition;
            if (smoothTarget < 0 || distance == 0) { KillTimer(hwnd, SmoothTimer); smoothTarget = -1; return IntPtr.Zero; }
            int before = scrollPosition;
            int step = smoothStep > 0 ? smoothStep : (smoothStep = Math.Max(1, (int)Math.Ceiling(Math.Abs(distance) / 3.0))); // three-frame travel
            scrollPosition += Math.Sign(distance) * Math.Min(step, Math.Abs(distance));
            bool settled = scrollPosition == before || scrollPosition == smoothTarget;
            if (settled) { smoothTarget = -1; smoothStep = 0; KillTimer(hwnd, SmoothTimer); PositionControls(); }
                else ApplyScroll();
                UpdateScroll(redraw: false);
            return IntPtr.Zero;
        }
        if (message is >= 0x132 and <= 0x138 && visual is not null)
            return visual.ControlColor(new IntPtr(unchecked((long)wp.ToUInt64())), message, GetParent(lp) == body, GetDlgCtrlID(lp), lp);
        if (message == 0x2b && visual is not null && visual.DrawItem(lp)) return new IntPtr(1);
        if (message == 0xF && visual is not null)
        { visual.PaintSurface(hwnd, hwnd == body, (int)page, scrollPosition, scale, Px(footerHeight)); return IntPtr.Zero; }
        if (message == 0x318 && visual is not null)
        { visual.PaintSurface(hwnd, hwnd == body, (int)page, scrollPosition, scale, Px(footerHeight), new IntPtr(unchecked((long)wp.ToUInt64()))); return IntPtr.Zero; }
        if (message == 0x14) return new IntPtr(1);
        if (message == 0x115)
        {
            int scrollCommand = (int)(wp.ToUInt64() & 0xffff);
            int track = (int)((wp.ToUInt64() >> 16) & 0xffff);
            Scroll(scrollCommand, scrollCommand is 4 or 5 ? track : -1);
            return IntPtr.Zero;
        }
        if (message == 0x20a)
        {
            wheelRemainder += unchecked((short)(wp.ToUInt64() >> 16));
            SystemParametersInfoW(0x68, 0, out var lines, 0);
            if (Math.Abs(wheelRemainder) >= 120)
            {
                int steps = wheelRemainder / 120; wheelRemainder %= 120;
                if (GetClientRect(body, out var viewport))
                {
                    int delta = steps * (lines == uint.MaxValue ? viewport.Bottom : Px(24) * (int)Math.Min(lines, 100));
                    int from = smoothTarget >= 0 ? smoothTarget : scrollPosition;
                    int next = Math.Clamp(from - delta, 0, Math.Max(0, Px(PageHeights[(int)page]) - viewport.Bottom));
                    if (next != scrollPosition)
                    {
                        smoothTarget = next; smoothStep = 0;
                        if (SetTimer(window, SmoothTimer, 15, IntPtr.Zero) == UIntPtr.Zero)
                        { smoothTarget = -1; scrollPosition = next; PositionControls(); UpdateScroll(); }
                    }
                }
            }
            return IntPtr.Zero;
        }
        if (hwnd == body && message is 2 or 0x82 or 5) return DefWindowProcW(hwnd, message, wp, lp);
        if (message == 0x400 && hwnd == window) return new IntPtr((0x534b << 16) | 30);
        if (message is 0x31a or 0x1a && visual is not null && hwnd == window)
        { visual.Reload(window); help?.Refresh(); RepaintTree(); return IntPtr.Zero; }
        if (message == 0x10) { RequestClose(); return IntPtr.Zero; }
        if (message == 2)
        {
            RememberWindowSize(hwnd);
            help?.Dispose(); help = null;
            KillTimer(hwnd, StopStatusTimer);
            KillTimer(hwnd, ExecutionRoleReplyTimer);
            KillTimer(hwnd, SmoothTimer); smoothTarget = -1;
            EndUacWindowPick();
            if (localStopHotkey) { UnregisterHotKey(hwnd, UacLocalStopHotkey); localStopHotkey = false; }
            try { uacWorkStop?.Cancel(); } catch (ObjectDisposedException) { }
            window = body = IntPtr.Zero; controls.Clear(); layout.Clear(); positioned.Clear(); pendingProgram = null; detailMode = ""; changingExecutionRole = false;
            restoreFocus = IntPtr.Zero; PublishSurface("closed");
            foreach (var value in new[] { font, nameFont, headingFont, titleFont, smallFont }) if (value != IntPtr.Zero) DeleteObject(value);
            font = nameFont = headingFont = titleFont = smallFont = IntPtr.Zero; original = null; controlBaseline = null; broker = null; selectedSize = null; uacAllowlist.Clear(); adminLaunchAllowlist.Clear();
            if (preview || localSettings) PostQuitMessage(0); return IntPtr.Zero;
        }
        if (message == 0x82 && hwnd != body) { visual?.Dispose(); visual = null; return DefWindowProcW(hwnd, message, wp, lp); }
        if (message == 0x232 && hwnd == window) { RememberWindowSize(hwnd); return DefWindowProcW(hwnd, message, wp, lp); }
        if (message == 5)
        {
            if (hwnd == window && wp.ToUInt64() != 1 && !IsIconic(hwnd)) { PositionControls(); UpdateScroll(); }
            if (hwnd == window) PublishSurface("size_changed");
            return IntPtr.Zero;
        }
        if (message == 0x2e0)
        {
            var rect = Marshal.PtrToStructure<Native.Rect>(lp);
            var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
            if (!GetMonitorInfoW(MonitorFromWindow(hwnd, 2), ref monitor)) return IntPtr.Zero;
            var old = scale; scale = LayoutScale((uint)(wp.ToUInt64() & 0xffff), monitor.Work.Right - monitor.Work.Left);
            scrollPosition = (int)Math.Round(scrollPosition * scale / old);
            var width = Math.Min(rect.Right - rect.Left, monitor.Work.Right - monitor.Work.Left - 24); var height = Math.Min(rect.Bottom - rect.Top, monitor.Work.Bottom - monitor.Work.Top - 24);
            SetWindowPos(hwnd, IntPtr.Zero, Math.Clamp(rect.Left, monitor.Work.Left, Math.Max(monitor.Work.Left, monitor.Work.Right - width)),
                Math.Clamp(rect.Top, monitor.Work.Top, Math.Max(monitor.Work.Top, monitor.Work.Bottom - height)), width, height, 0x14);
            Relayout();
            UpdateScroll(); return IntPtr.Zero;
        }
        if (message != 0x111) return DefWindowProcW(hwnd, message, wp, lp);
        int controlId = (int)(wp.ToUInt64() & 0xffff), notification = (int)(wp.ToUInt64() >> 16);
        if (notification == 0 && controlId is >= 300 and <= 305)
        { ShowPage(NavPageFor(controlId - 300)); return IntPtr.Zero; }
        if (controlId == 2 && lp == IntPtr.Zero) { RequestClose(); return IntPtr.Zero; }
        if (controlId is 11 or 3402 && notification == 0x300) { RefreshFooter(); return IntPtr.Zero; }
        if (controlId == 7 && notification == 1) { RefreshFooter(); PositionControls(); UpdateScroll(); return IntPtr.Zero; }
        if (controlId is 66 or 166 && notification == 1)
        {
            UpdateUacDetail(controlId == 66 ? ProgramListKind.Launch : ProgramListKind.Uac); return IntPtr.Zero;
        }
        if (controlId is 3412 or 3422 && notification == 1)
        { UpdateBlockedProgramControls(policyValid && !UacBusy); PositionControls(); UpdateScroll(); return IntPtr.Zero; }
        if (notification != 0 && !(notification == 1 && controlId == 81))
            return DefWindowProcW(hwnd, message, wp, lp);
        try
        {
            // Preview cannot reach actual windows, policy, UAC or calibration,
            // even if a synthetic test sends WM_COMMAND to a disabled button.
            if ((preview || broker is null) && controlId is 13 or 20 or 33 or 63 or 76 or 77 or 163 or 176 or 177 or 67 or 68 or 69 or 72 or 73 or 74 or 3403 or 3413 or 3423)
            { SetNotice("内存预览：此真实系统操作不可执行，未读取窗口或本机权限。"); return IntPtr.Zero; }
            switch ((int)(wp.ToUInt64() & 0xffff))
            {
                case 306: NavigationMenu(); break;
                case 3015: OpenHelp(1); break;
                case 3016: ShowPage(SettingsPage.Admin); break;
                case 3031: case 3041: explanationOpen = !explanationOpen; PositionControls(); UpdateScroll(); break;
                case 310: ShowPage(SettingsPage.Launch); SetFocus(controls[compactNavigation ? 306 : 302]); break;
                case 311: ShowPage(SettingsPage.Uac); SetFocus(controls[compactNavigation ? 306 : 303]); break;
                case 62: SourceMenu(ProgramListKind.Launch); break;
                case 162: SourceMenu(ProgramListKind.Uac); break;
                case 91: OpenHelp(0); SetFocus(controls[92]); break;
                case 93: case 97: case 99: CloseDetails(); break;
                case 94: RequestReload(); break;
                case 100: if (detailMode == "reload") { ReloadSaved(); SetFocus(controls[94]); } break;
                case 95: if (detailMode == "close" && !surfaceFault && !conflict && !UacBusy) { closeAfterSave = true; SendMessageW(window, 0x111, new IntPtr(30), IntPtr.Zero); } break;
                case 98: if (detailMode == "close" && !UacBusy) DestroyWindow(window); return IntPtr.Zero;
                case 96: AcceptPendingProgram(); break;
                case 1:
                    EndUacWindowPick();
                    if (!preview && broker is not null) { RequestExecutionTier(Checked(1) ? 1 : 0, toggle: false); break; }
                    if (!Checked(1)) { Check(78, false); Check(79, false); }
                    UpdateUacControls(); break;
                case 3301: RequestExecutionTier(0); break;
                case 3302: RequestExecutionTier(1); break;
                case 3303: RequestExecutionTier(2); break;
                case 3304: RequestExecutionTier(3); break;
                case 3311: launchMode = "allowlist"; UpdateUacControls(); break;
                case 3312: launchMode = "semantic"; UpdateUacControls(); break;
                case 3321: uacSubmode = "allowlist"; uacMode = "allowlist"; UpdateUacControls(); break;
                case 3322: uacSubmode = "semantic"; uacMode = "semantic"; UpdateUacControls(); break;
                case 3403: AddApplication(3402, 3403); break;
                case 3413: case 3423: AddBlockedProgram(controlId == 3413 ? ProgramListKind.Launch : ProgramListKind.Uac); break;
                case 3414: case 3424: EditBlockedProgram(controlId == 3414 ? ProgramListKind.Launch : ProgramListKind.Uac, remove: true); break;
                case 3415: case 3425: EditBlockedProgram(controlId == 3415 ? ProgramListKind.Launch : ProgramListKind.Uac, remove: false); break;
                case 3412: case 3422: UpdateBlockedProgramControls(policyValid && !UacBusy); PositionControls(); UpdateScroll(); break;
                case 78:
                    EndUacWindowPick();
                    if (!preview && broker is not null) { RequestExecutionTier(Checked(78) ? 2 : 1, toggle: false); break; }
                    if (!Checked(78)) Check(79, false);
                    UpdateUacControls(); break;
                case 79:
                    EndUacWindowPick();
                    if (!preview && broker is not null) { RequestExecutionTier(Checked(79) ? 3 : 2, toggle: false); break; }
                    uacMode = Checked(79) ? "allowlist" : "off";
                    UpdateUacControls(); break;
                case 81:
                    var scopeChoice = SendMessageW(controls[81], 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32();
                    if (scopeChoice < 0 || scopeChoice >= CancellationScopes.Length) throw new Boundary("user_policy_invalid");
                    try { SetCancellationScopeDraft(CancellationScopes[scopeChoice]); }
                    finally { UpdateUacControls(); }
                    break;
                case 63: BeginUacWindowPick(ProgramListKind.Launch); break;
                case 163: BeginUacWindowPick(ProgramListKind.Uac); break;
                case 76: AddUacRunningWindow(ProgramListKind.Launch); break;
                case 176: AddUacRunningWindow(ProgramListKind.Uac); break;
                case 77: AddUacApplication(ProgramListKind.Launch); break;
                case 177: AddUacApplication(ProgramListKind.Uac); break;
                case 67:
                    if (broker is null) { ShowError(hwnd, "预览不登记系统入口。"); break; }
                    var preparingBroker = broker; string preparingRevision = original!.Revision;
                    BeginUacWork("prepare", token => PrepareRoleSource(preparingBroker, preparingRevision, token)); break;
                case 68:
                    if (broker is null) { ShowError(hwnd, "预览不改系统入口或设置。"); break; }
                    var disablingBroker = broker;
                    string disablingRevision = disablingBroker.OrdinaryResident ? UserPermissions.Read().Revision : original!.Revision;
                    BeginUacWork("disable", token => DisableRoleSource(disablingBroker, disablingRevision, token)); break;
                case 69:
                case 72:
                case 73:
                case 74:
                    throw new Boundary("host_uac_feature_retired");
                case 64:
                case 164:
                    ToggleProgram(controlId == 64 ? ProgramListKind.Launch : ProgramListKind.Uac); break;
                case 65:
                case 165:
                    var removeKind = controlId == 65 ? ProgramListKind.Launch : ProgramListKind.Uac;
                    int removed = UacSelectedIndex(removeKind);
                    var removeRows = Programs(removeKind);
                    if (UacBusy || !policyValid) throw new Boundary("uac_allowlist_unavailable");
                    if (removed >= 0 && removed < removeRows.Count) { removeRows.RemoveAt(removed); RefreshUacAllowlist(kind: removeKind); UpdateUacControls(); }
                    break;
                case 20: SelectWindow(); break;
                case 13: AddApplication(11, 13); break;
                case 26:
                    if (selectedSize is null) throw new Boundary("select_mask_window_first");
                    var values = Enumerable.Range(22, 4).Select(id => int.Parse(Text(id))).ToArray();
                    var mask = new PrivacyMask(Text(21), [values[0], values[1], checked(values[0] + values[2]), checked(values[1] + values[3])], selectedSize.ToArray());
                    UserPermissions.Validate(original! with { Masks = [..masks, mask] }); masks.Add(mask); RefreshMasks(); break;
                case 27:
                    int index = SendMessageW(controls[28], 0x188, IntPtr.Zero, IntPtr.Zero).ToInt32();
                    if (index >= 0 && index < masks.Count) { masks.RemoveAt(index); RefreshMasks(); } break;
                case 30:
                    if (surfaceFault) throw new Boundary("permission_surface_reload_required");
                    if (!policyValid) throw new Boundary("user_policy_unavailable");
                    if (conflict) throw new Boundary("user_policy_changed_reopen_settings");
                    EndUacWindowPick();
                    var edited = preview ? EditedSettings() : SameRoleSubmission(EditedSettings(), original!);
                    bool policyChanged = controlBaseline is null || !SameSettings(preview ? controlBaseline : SameRoleSubmission(controlBaseline, original!), edited);
                    if (policyChanged && edited.UacMode == "semantic") throw new Boundary("uac_component_unavailable");
                    if (policyChanged && !preview) uacCapabilities = ReadUacCapabilities();
                    if (policyChanged && !UacCancellationScopeSelectionAvailable(edited.UacCancellationScope, original!.UacCancellationScope, uacCapabilities))
                        throw new Boundary("uac_cancellation_scope_unavailable");
                    if (preview) { UserPermissions.Validate(edited); previewSaved = edited;
                        var memoryPreference = new SettingsUiPreference(uacSubmode, "preview");
                        if (CompleteSave(edited, closeAfterSave, edited, new(uacSubmode, memoryPreference))) return IntPtr.Zero; break; }
                    if (policyChanged && edited.UacMode != original!.UacMode && !UacSelectionAvailable(edited.UacMode, uacCapabilities))
                    { UpdateUacControls(); throw new Boundary("uac_component_unavailable"); }
                    var savingBroker = broker!;
                    var priorSaved = original!; var priorUiPreference = uiPreference; string submittedMode = uacSubmode;
                    bool preferenceRequested = UserPermissions.UiPreferenceNeedsSave(priorSaved.UacMode, edited.UacMode,
                        submittedMode, uiBaselineSubmode, priorUiPreference, uiPreferencePending);
                    UserPermissionSettings? committed = null;
                    SettingsUiSave? preferenceResult = null;
                    BeginUacWork("save", token => {
                        token.ThrowIfCancellationRequested();
                        if (savingBroker.OrdinaryResident)
                        {
                            var outcome = LocalUiWriter.Execute(savingBroker, SameRoleSaveOperation(edited, priorSaved,
                                policyChanged, submittedMode, priorUiPreference, preferenceRequested), null, token);
                            committed = outcome.Current;
                            preferenceResult = RolePreferenceResult(outcome, submittedMode, policyChanged, preferenceRequested); return;
                        }
                        committed = policyChanged ? UacInstallation.SaveSettings(edited, savingBroker, token) : priorSaved;
                        if (!preferenceRequested)
                        { preferenceResult = new(submittedMode, PolicyWritten: policyChanged, PreferenceRequested: false); return; }
                        try
                        {
                            // Even a preference-only edit checks both revisions
                            // under the policy mutex, without running off-first.
                            token.ThrowIfCancellationRequested();
                            var preference = UserPermissions.SaveUiPreference(committed.Revision, priorUiPreference.Revision, submittedMode, token);
                            preferenceResult = new(submittedMode, preference, PolicyWritten: policyChanged);
                        }
                        catch (Exception error) { preferenceResult = new(submittedMode, Error: Program.Code(error), PolicyWritten: policyChanged); }
                    }, () => committed, closeAfterSave, () => preferenceResult, preferenceOnly: !policyChanged);
                    break;
                case 31: RequestClose(); break;
                case 32: StopSettingsWork(); break;
            }
            if (window != IntPtr.Zero) { RefreshFooter(); PositionControls(); UpdateScroll(); }
        }
        catch (Boundary error) when (error.Code == "user_policy_changed_reopen_settings")
        { conflict = true; SetNotice("设置已在外部变更，旧草稿未覆盖它；请用重新载入核对。"); UpdateUacControls(); }
        catch (Boundary error) when (error.Code is "uac_component_unavailable" or "uac_allowlist_unavailable")
        { ReportProblem("所选模式目前不可执行，或本机名单编辑不可用，未保存此更改。名单可先在关闭模式下批准并保存；实际 UAC 处理仍由执行端核验。"); }
        catch (Boundary error)
        {
            ReportProblem(error.Code switch
            {
                "user_policy_invalid" => "当前配置内容或版本无法校验，未覆盖原配置。请先修复配置，再重新打开此页。",
                "semantic_authority_design_pending" => "工作授权方案已确定，管理员脚本的精确载荷执行仍在接入，当前不新启用此模式。草稿已保留，可继续编辑其它设置。",
                "user_policy_unavailable" => "当前权限配置无法读取，未写入新设置。请检查文件是否可用后重新打开此页。",
                "user_policy_migration_required" => "现有配置需要单独迁移，未覆盖原文件。UAC 保持关闭，其它偏好仍可读取。",
                "user_policy_unprotected" => "权限配置的文件保护未通过校验，未保存此更改。请先修复安装或配置保护。",
                "user_policy_save_busy" => "另一个权限设置写入尚未结束，未保存本页草稿。请稍后重新打开此页核对。",
                "user_policy_save_outcome_unknown" => "设置写入后的复核和恢复未能完成，保存结果未知。请先核对实际配置，停止功能仍可用。",
                "uac_program_signature_unknown" => "所选程序的签名无法在本机可靠验证，未添加白名单。不联网补验，也不按名称放行。",
                "uac_allowlist_payload_host_rejected" => "此程序是脚本解释器或代理执行宿主，或其文件身份无法读取，不能按程序文件预授权任意负载。请停用或移除此名单条目；明确聊天授权仍按原范围判断。",
                "uac_allowlist_program_writable" => "此程序或安装目录可被普通程序改写，不能直接预授权。请先核实其安装位置与文件保护，当前未添加或启用。",
                "uac_disabled" => "UAC 功能已关闭，本次没有运行测试。关闭状态的首次校准路线尚未交付；固定入口准备不会开启 04，原档位保留。",
                "uac_cancellation_scope_unavailable" => "当前会话所选提示接入尚未就绪，不能新启用。可保留旧存值或改回“仅本任务可确认归属”；路线验证与实际执行仍需分别核验。",
                "uac_allowlist_arguments_approval_required" => "此旧条目的参数未知或非空，当前页面不能重新启用。原记录保留；可重新选择窗口或程序文件，仅登记无参数规则。",
                "uac_window_pick_hotkey_unavailable" or "uac_window_pick_timer_unavailable" or "uac_window_pick_cleanup_failed"
                    or "uac_window_pick_target_rejected" or "uac_window_pick_target_changed" or "uac_window_pick_expired" => UacWindowPickError(error),
                "uac_settings_work_busy" => "本机验证仍在进行，请等本次结果。停止热键和停用入口仍可用；结果未知时不要重试。",
                "settings_live_broker_required" => "此独立校准窗口没有当前执行器，不能切换档位。请打开实际 Flower 托盘的设置切换；本次未改变权限或草稿。",
                "permission_role_reply_unavailable" => "档位切换的界面回执入口未就绪，本次未改权限。草稿保留，请重新打开实际托盘设置后再操作。",
                "uac_diagnostic_requires_admin_tier" => "普通执行器不运行真实系统诊断。请先从实际托盘设置切换管理员档位，再明确启动所需诊断。",
                "uac_program_changed" => "所选程序在读取身份时发生变化，未添加白名单。请重新选择稳定的程序文件。",
                "uac_program_path_rejected" or "uac_program_local_drive_required" => "请选择本机固定磁盘上的完整程序文件路径，不能使用网络或特殊文件路径。",
                "permission_write_failed" or "permission_directory_failed" => "权限配置无法写入，未保存此更改。请检查安装目录及文件保护后重新打开设置。",
                _ => "设置保存或复核未完成。请重新打开设置核对实际内容，并检查程序路径、遮挡范围和配置保护。",
            });
        }
        catch (Exception) { ReportProblem("设置保存或复核失败，编辑仍保留。请核对程序路径、遮挡范围和配置保护；若已有外部更改，使用重新载入核对后再保存。"); }
        return IntPtr.Zero;
    }
}
