using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Security.Principal;

namespace Flower.HighHelper;

// New settings surface: a single hero panel instead of the legacy seven-page
// rail. All geometry is device independent and scaled once per window DPI.
internal static partial class SettingsWorkspace
{
    private const int BaseWidth = 1500, BaseHeight = 1000;
    private static readonly string[] NavNames = [UiText.Get("总览"), UiText.Get("权限"), UiText.Get("隐私"), UiText.Get("常规"), UiText.Get("诊断")];
    private static readonly string[] TierNames = [UiText.Get("普通控制"), UiText.Get("管理员窗口"), UiText.Get("管理员执行"), UiText.Get("系统接管")];
    private const int NavBase = 100, TierBase = 200, SaveId = 300, StopId = 301, AddId = 302, ReloadId = 303, NoticeDetailsId = 304, HelpId = 305;

    private static IntPtr window, instance;
    private static double scale = 1.5;
    private static SettingsArtwork? artwork;
    private static SettingsWorkspaceModel model = null!;
    private static UserPermissionSettings saved => model.Saved;
    private static UserPermissionSettings draft => model.Draft;
    private static BrokerState? core;
    private static bool preview, registered, standalone;
    private static int page;
    private static int tier => model.DraftTier;
    private static string notice = "";

    internal static int RunPreview(int initialPage = 0)
    {
        preview = true;
        Initialize(Synthetic());
        page = initialPage;
        return Loop();
    }

    // Opened from the tray inside the broker's existing message loop. No new
    // loop and no process exit on close; Stop and Save use the live broker.
    internal static void Show(IntPtr owner, BrokerState state)
    {
        if (window != IntPtr.Zero) { ShowWindow(window, IsIconic(window) ? 9 : 5); Native.SetForegroundWindow(window); if (restoreFocus != IntPtr.Zero && IsChild(window, restoreFocus)) SetFocus(restoreFocus); return; }
        preview = false; standalone = false;
        Initialize(UserPermissions.Read());
        ImportHandoff();
        Create(owner, state);
    }

    internal static int Run(string? snapshotDirectory, int initialPage = 0)
    {
        // A snapshot is also the standalone visual preview: it never reads or
        // writes the real policy, so it can run without the High parent.
        preview = snapshotDirectory is not null;
        Initialize(preview ? Synthetic() : UserPermissions.Read());
        page = initialPage;
        try { return Loop(snapshotDirectory); }
        catch (Exception error) { Console.Error.WriteLine("settings_workspace_failed: " + error); throw; }
    }

    private static UserPermissionSettings Synthetic() => new()
    {
        UserSid = WindowsIdentity.GetCurrent().User!.Value,
        Revision = "synthetic-workspace",
        AuthorityTier = 2,
        AdminWindows = true,
        AdminLaunchEnabled = true,
        AdminScope = "all",
        AdminLaunchAllowlist = [new(@"C:\Windows\System32\notepad.exe", "sha256", new string('a',64), UiText.Get("记事本"), true, ""),
                               new(@"E:\Preview\Canvas.exe", "sha256", new string('b',64), UiText.Get("画布"), true, "")],
        UacAllowlist = [],
        DeniedApplications = [new(@"E:\Preview\Private.exe", UiText.Get("私人窗口"))],
        Masks = [new(@"E:\Preview\Editor.exe", [20, 20, 220, 100], [1280, 720])],
    };

    private static int Loop(string? snapshot = null)
    {
        standalone = true;
        Create();
        if (snapshot is not null)
        {
            UpdateWindow(window);
            Render(snapshot);
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                state = "snapshot_saved",
                path = snapshot,
                artwork = ArtworkState,
                tier,
                dpi = GetDpiForWindow(window)
            }));
            DestroyWindow(window);
            return 0;
        }
        Console.Error.WriteLine(JsonSerializer.Serialize(new
        {
            workspace = "settings",
            pid = Environment.ProcessId,
            hwnd = window.ToInt64(),
            dpi = GetDpiForWindow(window),
            artwork = ArtworkState,
            preview,
            scale,
            width = Px(BaseWidth),
            height = Px(BaseHeight)
        }));
        while (GetMessageW(out var message, IntPtr.Zero, 0, 0) > 0)
        { if (!HandleDialogMessage(ref message)) { TranslateMessage(ref message); DispatchMessageW(ref message); } }
        return 0;
    }

    private static string ArtworkState => artwork is null ? "unavailable"
        : artwork.HasFlower ? (artwork.Background is null ? "flower_without_background" : "complete") : "background_only";

    private static void Render(string path)
    {
        GetWindowRect(window, out var rect);
        SettingsArtwork.SaveWindowPng(window, rect.Right - rect.Left, rect.Bottom - rect.Top, path);
    }

    private static void Create(IntPtr owner = default, BrokerState? state = null)
    {
        if (state is not null) core = state;
        instance = GetModuleHandleW(null);
        if (!registered)
        {
            var cls = new WindowClass
            {
                Size = (uint)Marshal.SizeOf<WindowClass>(),
                Style = 3,
                Proc = Marshal.GetFunctionPointerForDelegate(Procedure),
                Instance = instance,
                Name = "Flower.SettingsWorkspace"
            };
            if (RegisterClassExW(ref cls) == 0) throw new InvalidOperationException("settings_window_failed");
            registered = true;
        }
        var monitor = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
        var targetMonitor = StartupMonitor(owner);
        if (!GetMonitorInfoW(targetMonitor, ref monitor) && !SystemParametersInfoW(0x0030, 0, ref monitor.Work, 0))
            monitor.Work = new Rect { Right = 1280, Bottom = 720 };
        uint targetDpi = GetDpiForMonitor(targetMonitor, 0, out var monitorDpi, out _) == 0 ? monitorDpi : GetDpiForSystem();
        double dpiScale = Math.Max(96, targetDpi) / 96.0;
        int workWidth = monitor.Work.Right - monitor.Work.Left - 48;
        int workHeight = monitor.Work.Bottom - monitor.Work.Top - 86;
        scale = Math.Min(dpiScale * (1120.0 / BaseWidth), Math.Min(workWidth / (double)BaseWidth, workHeight / (double)BaseHeight));
        scale = Math.Max(.5, scale);
        var outer = new Rect { Right = Px(BaseWidth), Bottom = Px(BaseHeight) };
        AdjustWindowRectExForDpi(ref outer, 0x00CF0000 | 0x02000000, false, 0, Math.Max(96, targetDpi));
        var placement = CenterInWorkArea(monitor.Work, outer.Right - outer.Left, outer.Bottom - outer.Top);
        window = CreateWindowExW(0x40000, "Flower.SettingsWorkspace", "Flower Control",
            0x00CF0000 | 0x02000000, placement.Left, placement.Top,
            placement.Right - placement.Left, placement.Bottom - placement.Top, IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
        if (window == IntPtr.Zero || !SetPropW(window, "FlowerControlTaskIndicator", new IntPtr(1)))
            throw new InvalidOperationException("settings_window_failed");
        artwork = SettingsArtwork.TryCreate();
        if (preview) workspaceIconState = TrayStateIcons.Select(model.EffectiveTier, true, false);
        ApplyWindowMaterial();
        AddButton(NavBase + 0, 2, UiText.Get("总览")); AddButton(NavBase + 1, 2, UiText.Get("权限"));
        AddButton(NavBase + 2, 2, UiText.Get("隐私")); AddButton(NavBase + 3, 2, UiText.Get("外观"));
        AddButton(NavBase + 4, 2, UiText.Get("诊断"));
        SetWindowTextW(GetDlgItem(window, NavBase + 3), UiText.Get("常规"));
        for (int index = 0; index < 4; index++) AddButton(TierBase + index, 2, AuthorityPresentation.Label(AuthorityPresentation.ButtonTier(index)));
        AddButton(AddId, 3, UiText.Get("+ 添加程序"));
        AddButton(StopId, 4, UiText.Get("■ 结束电脑操作"));
        AddButton(SaveId, 5, UiText.Get("保存"));
        AddButton(ReloadId, 5, UiText.Get("重新载入"));
        AddButton(NoticeDetailsId, 5, UiText.Get("详情"));
        AddButton(HelpId, 5, UiText.Get("使用说明"));
        BuildPage();
        UpdateChrome();
        SetTimer(window, new UIntPtr(OverviewTimer), 1000, IntPtr.Zero);
        // STARTF_USESHOWWINDOW from a background launcher can consume the first
        // ShowWindow call as SW_HIDE. Explicit settings activation must still
        // produce a visible taskbar window after that one-time startup hint.
        ShowWindow(window, 0);
        ShowWindow(window, 5);
        Native.SetForegroundWindow(window);
        UpdateWindow(window);
    }

    private static void AddButton(int id, int kind, string text)
    {
        var handle = CreateWindowExW(0, "BUTTON", text, 0x5001000B, 0, 0, 10, 10, window,
            new IntPtr(id), instance, IntPtr.Zero);
        SetWindowTheme(handle, " ", " ");
        _ = kind;
    }

    private static void UpdateChrome()
    {
        if (pageRebuildPending || surfaceClosePending) return;
        bool pageChanged = pageLayoutDirty;
        pageLayoutDirty = false;
        bool layout = NeedsChromeLayout() || pageChanged;
        using var batch = BeginPositionBatch(layout);
        if (layout)
        {
            for (int index = 0; index < NavNames.Length; index++)
                Position(NavBase + index, Layout.Nav(index));
            for (int index = 0; index < 4; index++)
                Position(TierBase + index, Layout.Tier(index));
            Position(StopId, page == 0 ? OverviewStopBounds() : Layout.Stop);
            Position(SaveId, Layout.Save);
            Position(ReloadId, Layout.Reload);
            Position(NoticeDetailsId, Layout.NoticeDetails);
            Position(HelpId, Layout.Help);
        }
        if (layout || pageChanged)
        {
            Position(AddId, Layout.Add);
            PositionPageControls();
            FlushPositionBatch();
            // Build fields hidden, place the complete page, then reveal it.
            // No visible 1px fields at (0,0) while changing pages.
            foreach (var c in pageControls)
                ShowChromeControl(c.Handle, !(PermissionPage && ruleLayer >= 2
                    && (c.Id is DetailId or ToggleId or RemoveId or ProgramMenuId || c.Id == 612 && CompactSurface)));
            ShowChromeControl(GetDlgItem(window, AddId), page == 1 || page == 2 && privacyTab == 1);
            RestorePageFocus();
            RevealAddedProgram();
            PositionProgramMenu();
        }
        string addText = page == 2 ? UiText.Get("+ 添加遮挡") : PermissionPage && ruleLayer >= 2
            ? denied ? UiText.Get("+ 添加黑名单程序") : UiText.Get("+ 添加白名单程序") : UiText.Get("+ 添加程序");
        SetChromeText(GetDlgItem(window, AddId), addText);
        SetChromeText(GetDlgItem(window, SaveId), UiText.Get("保存权限与操作偏好"));
        EnableChromeControl(GetDlgItem(window, SaveId), Dirty && !Busy && !model.Conflict && !surfaceFault && !invalidEdit
            && AuthorityPresentation.Selectable(model.EffectiveTier) && (preview || core is not null));
        EnableChromeControl(GetDlgItem(window, ReloadId), !Busy);
        EnableChromeControl(GetDlgItem(window, HelpId), !Busy);
        EnableChromeControl(GetDlgItem(window, AddId), !Busy && (page == 1 || page == 2 && privacyTab == 1) && RowCount < 128);
        ShowChromeControl(GetDlgItem(window, NoticeDetailsId), !string.IsNullOrEmpty(notice));
        ShowChromeControl(GetDlgItem(window, HelpId), true);
        if (page != 0 && GetFocus() == GetDlgItem(window, StopId)) SetFocus(GetDlgItem(window, NavBase + page));
        ShowChromeControl(GetDlgItem(window, StopId), page == 0);
        RefreshProductButtons();
        RefreshOverview();
        UpdateTierAccessibleText();
        RefreshSemanticDelegationControl();
        UpdateDisplayPreferenceControl();
        RefreshChromePaint(layout, pageChanged);
        PublishWorkspaceStatus("updated");
        ResumeSurfaceRedraw();
    }

    private static Native.Point MinimumSurfaceSize(IntPtr handle)
    {
        double dpi = Math.Max(96, GetDpiForWindow(handle)) / 96.0;
        var minimum = new Native.Point { X = (int)Math.Ceiling(1000 * dpi), Y = (int)Math.Ceiling(680 * dpi) };
        var monitorInfo = new MonitorInfo { Size = (uint)Marshal.SizeOf<MonitorInfo>() };
        if (GetMonitorInfoW(MonitorFromWindow(handle, 2), ref monitorInfo))
        {
            minimum.X = Math.Min(minimum.X, monitorInfo.Work.Right - monitorInfo.Work.Left);
            minimum.Y = Math.Min(minimum.Y, monitorInfo.Work.Bottom - monitorInfo.Work.Top);
        }
        return minimum;
    }

    private static void Position(int id, Rect r)
    {
        var handle = GetDlgItem(window, id);
        if (handle == IntPtr.Zero) return;
        SetWindowPos(handle, IntPtr.Zero, r.Left, r.Top, r.Right - r.Left, r.Bottom - r.Top, 0x14);
    }

    private static IEnumerable<IntPtr> Children()
    {
        var list = new List<IntPtr>();
        EnumChildWindows(window, (handle, _) => { list.Add(handle); return true; }, IntPtr.Zero);
        return list;
    }

    private static IntPtr WindowProcedure(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        try { return WindowMessage(hwnd, message, wp, lp); }
        catch (Exception error)
        {
            surfaceFault |= error is not Boundary; notice = UiText.Get("操作未完成，草稿保留：") + Program.Code(error);
            ResumeSurfaceRedraw();
            if (message == 0xF) ValidateRect(hwnd, IntPtr.Zero);
            if (window != IntPtr.Zero)
            {
                if (error is Boundary) UpdateChrome();
                else EnableWindow(GetDlgItem(window, SaveId), false);
                InvalidateRect(window, IntPtr.Zero, false);
            }
            Console.Error.WriteLine("settings_workspace_error: " + Program.Code(error));
            PublishWorkspaceStatus("window_handler_failed", error: Program.Code(error));
            return IntPtr.Zero;
        }
        finally
        {
            if (message == 0x111)
                PublishWorkspaceStatus("command", (int)(wp.ToUInt64() & 0xffff), (int)((wp.ToUInt64() >> 16) & 0xffff));
            else if (message is 2 or 5 or 6 or 7 or 8 or 0x18 or 0x86)
                PublishWorkspaceStatus("window_state");
        }
    }

    private static IntPtr WindowMessage(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp)
    {
        if (message == RebuildPageMessage) { CompletePageRebuild(hwnd, lp); return IntPtr.Zero; }
        if (message == UxProbeTick) { uxProbeAction?.Invoke(); return IntPtr.Zero; }
        if (message == BrowserOpenFinished) { CompleteBrowserProfileOpen(); return IntPtr.Zero; }
        if (message == WorkFinished) { CompleteWork(); return IntPtr.Zero; }
        if (message == 0x0113 && (uint)wp == WorkCompletionTimer) { CompleteWork(); return IntPtr.Zero; }
        if (message == HealthFinished) { var list = PageHandle(ProgramListId); if (list != IntPtr.Zero) InvalidateRect(list, IntPtr.Zero, false); return IntPtr.Zero; }
        if (message == 0x15)
        {
            // Activation is the common foreground-switch path. The scene,
            // backdrop and control rasters are still valid; releasing them
            // here caused a full artwork redraw on every alt-tab and made the
            // window visibly stutter. Keep the warm frame and let Windows
            // repaint only if composition actually exposed pixels.
            return DefWindowProcW(hwnd, message, wp, lp);
        }
        if (message is 0x1A or 0x31A)
        {
            ApplyWindowMaterial(); RefreshPageFont(); chromeLayoutDirty = true; UpdateChrome();
            foreach (var control in pageControls)
                SetWindowTheme(control.Handle, HighContrast() ? "" : "DarkMode_CFD", "");
            InvalidateRect(hwnd, IntPtr.Zero, true);
            EnumChildWindows(hwnd, (child, _) =>
            { InvalidateRect(child, IntPtr.Zero, true); return true; }, IntPtr.Zero);
        }
        if (message == 0x0113 && (uint)wp == OverviewTimer) { RefreshOverview(); return IntPtr.Zero; }
        if (message == 0x0113 && (uint)wp == PickTimer) { EndPick(); notice = UiText.Get("选窗已超时，没有更改名单。"); UpdateChrome(); return IntPtr.Zero; }
        if (message == 0x0312 && (int)wp == 187 && picking)
        { CompleteWindowPick(); return IntPtr.Zero; }
        if (message is 0x0133 or 0x0134 or 0x0135 or 0x0138)
        {
            // Read-only EDIT sends CTLCOLORSTATIC, too. Native scrolling must
            // erase old glyphs; transparent text is only for static/button art.
            bool nativeText = message is 0x0133 or 0x0134 || pageControls.Any(c => c.Handle == lp && c.Kind == "EDIT");
            SetTextColor((IntPtr)wp, HighContrast() ? GetSysColor(8) : 0xEFEAF2);
            SetBkMode((IntPtr)wp, nativeText ? 2 : 1);
            SetBkColor((IntPtr)wp, HighContrast() ? GetSysColor(5) : 0x2B2320);
            return HighContrast() ? GetSysColorBrush(5) : pageBrush;
        }
        switch (message)
        {
            case 0x0231: // WM_ENTERSIZEMOVE: retain the existing artwork while the native size loop runs.
                ReleaseInteractiveControls(); interactiveWindowMove = true; interactiveRasterResized = false; return IntPtr.Zero;
            case 0x0232: // WM_EXITSIZEMOVE: regenerate at the final dimensions, without changing layout/input semantics.
                interactiveWindowMove = false; ReleaseInteractiveControls();
                if (!interactiveRasterResized) return IntPtr.Zero;
                interactiveRasterResized = false; ReleaseScene(); ReleaseBackdrop();
                InvalidateRect(hwnd, IntPtr.Zero, false);
                foreach (var child in Children()) InvalidateRect(child, IntPtr.Zero, false);
                return IntPtr.Zero;
            case 0x0024:
                {
                    var info = Marshal.PtrToStructure<MinMaxInfo>(lp);
                    info.MinTrack = MinimumSurfaceSize(hwnd);
                    Marshal.StructureToPtr(info, lp, false); return IntPtr.Zero;
                }
            case 0x0318:
                {
                    var dc = (IntPtr)wp; var paint = new PaintStruct(); Paint(dc, ref paint); return IntPtr.Zero;
                }
            case 0x000F:
                {
                    if (surfaceRedrawSuspended) { ValidateRect(hwnd, IntPtr.Zero); return IntPtr.Zero; }
                    var paint = new PaintStruct();
                    var dc = BeginPaint(hwnd, ref paint);
                    try { Paint(dc, ref paint); } finally { EndPaint(hwnd, ref paint); }
                    return IntPtr.Zero;
                }
            case 0x002C:
                return MeasureThemedItem(lp) ? new IntPtr(1) : DefWindowProcW(hwnd, message, wp, lp);
            case 0x002B:
                {
                    var data = Marshal.PtrToStructure<DrawItem>(lp);
                    if (!PaintInteractiveControl(data)) PaintNativeControl(data);
                    return new IntPtr(1);
                }
            case 0x0111:
                {
                    int id = (int)((long)wp & 0xFFFF);
                    bool nativeControl = lp != IntPtr.Zero;
                    if (nativeControl) ++nativeCommandDepth;
                    try { OnCommand(id, (int)((long)wp >> 16) & 0xffff); }
                    finally
                    {
                        if (nativeControl) --nativeCommandDepth;
                        if (nativeCommandDepth == 0 && nativeCallbackDepth == 0) PostPendingPageRebuild();
                    }
                    return IntPtr.Zero;
                }
            case 0x0005:
                {
                    if (window != IntPtr.Zero && (long)wp != 1)
                    {
                        if (interactiveWindowMove) interactiveRasterResized = true;
                        GetClientRect(hwnd, out var client);
                        scale = Math.Max(.1, Math.Min(client.Right / (double)BaseWidth, client.Bottom / (double)BaseHeight));
                        RefreshPageFont();
                        UpdateChrome();
                    }
                    return IntPtr.Zero;
                }
            case 0x0014:
                {
                    return new IntPtr(1);
                }
            case 0x0002:
                ShutdownSurface();
                return IntPtr.Zero;
            case 0x0010:
                RequestClose();
                return IntPtr.Zero;
            case 0x02E0:
                var suggested = Marshal.PtrToStructure<Rect>(lp);
                SetWindowPos(hwnd, IntPtr.Zero, suggested.Left, suggested.Top, suggested.Right - suggested.Left, suggested.Bottom - suggested.Top, 0x14);
                RefreshPageFont(); chromeLayoutDirty = true; UpdateChrome();
                ApplyWindowIcons();
                return IntPtr.Zero;
        }
        return DefWindowProcW(hwnd, message, wp, lp);
    }

    private static void OnCommand(int id, int notification = 0)
    {
        if (loadingControls) return;
        if (PageCommand(id, notification)) return;
        if (id is >= NavBase and < NavBase + 5) { if (notification != 0 || page == id - NavBase) return; if (invalidEdit) { notice = UiText.Get("当前字段无效，请修正或重新载入后换页。"); UpdateChrome(); return; } page = id - NavBase; BuildPage(); UpdateChrome(); return; }
        if (id is >= TierBase and < TierBase + 4)
        {
            RequestTier(AuthorityPresentation.ButtonTier(id - TierBase)); return;
        }
        if (id == SaveId)
        {
            RequestSave(); return;
        }
        if (id == StopId)
        {
            StopWork();
            UpdateChrome(); return;
        }
        if (id == AddId) AddSourceMenu();
        if (id == ReloadId) RequestReload();
        if (id == NoticeDetailsId) MessageBoxW(window, notice, UiText.Get("操作详情"), 0x40);
    }

    private static void Paint(IntPtr dc, ref PaintStruct paint)
    {
        GetClientRect(window, out var rect);
        if (rect.Right <= 0 || rect.Bottom <= 0) return;
        // The destination retains the update region and child clip. Exposed
        // pixels reuse the completed scene; unchanged flowers/text are not
        // resampled and recreated for every paint while moving the window.
        if (!EnsureScene(dc, rect.Right, rect.Bottom)
            || !CopyRaster(dc, 0, 0, rect.Right, rect.Bottom, sceneDc, 0, 0, sceneGeometry.Width, sceneGeometry.Height, 0x00CC0020)) PaintScene(dc);
    }

    private static void PaintScene(IntPtr dc)
    {
        GetClientRect(window, out var rect);
        PaintBackdrop(dc, rect);
        PaintFieldFrames(dc);
        if (!HighContrast())
        {
            artwork?.DrawFlower(dc, NativeRect(Layout.Flower), model.EffectiveTier);
            PaintBrandIcon(dc);
        }
        Text(dc, "Flower Control", Layout.Brand, 26, 0xF2F2F2, bold: false, face: "Georgia");
        if (PermissionPage && !CompactSurface)
        {
            PaintPermissionChrome(dc);
            return;
        }
        PaintFlowerAnnotations(dc);
        Text(dc, UiText.Get("已保存档位"), Layout.CurrentLabel, 18, 0xC1B9B8, false, centered: true, shadow: true);
        Text(dc, TierDisplay(model.EffectiveTier), Layout.CurrentValue, UiText.English && CompactSurface ? 29 : 40, AuthorityPresentation.Ink(model.EffectiveTier), false, centered: true, face: DisplayFace, shadow: true);
        Text(dc, CurrentModeText(), Layout.CurrentMode, 21, runtimeNotice.Length == 0 ? AuthorityPresentation.Ink(model.EffectiveTier) : 0xA9DCEEu, false, centered: true, shadow: true);
        Text(dc, PageTitle(), Layout.PageTitle, 43, 0xEAF2F6, true);
        if (PermissionPage && ruleLayer >= 2) Text(dc, RowCount + UiText.Get(" 个程序"), CompactSurface ? Layout.C(815, 98, 145, 30) : Layout.R(1300, 181, 150, 32), 18, 0xC1B9B8, false, centered: true);
        if (UiText.English && PermissionPage) WrappedText(dc, PageLead(), Layout.PageLead, 17, 0xC0B3B4);
        else Text(dc, PageLead(), Layout.PageLead, 17, 0xC0B3B4, false);
        Text(dc, CompactSurface && preview && !Dirty ? UiText.Get("预览 · 合成数据") : StatusLine(), Layout.Status, 15, 0xBCAFC5, false);
        Text(dc, preview ? UiText.Get("保存后更新预览 · 不写入真实设置") : UiText.Get("档位立即切换 · 其余编辑保存生效"), Layout.TierCaption, 15, 0xD6C7DF, false, centered: true);
        WrappedText(dc, VisibleNotice(), Layout.Notice, 15, 0xF0D9E7);
    }

    private static void PaintNativeControl(DrawItem data)
    {
        if (data.Type == 3) PaintComboItem(data);
        else if (data.Type == 1) PaintMenuItem(data);
        else if (data.Id == ProgramListId) PaintProgramItem(data);
        else if (data.Id == MaskListId) PaintMaskItem(data);
        else if (data.Id == DecisionListId) PaintDecisionItem(data);
        else if (data.Id == BrowserSystemId) PaintBrowserSystemLabel(data);
        else if (data.Id is BrowserPersonalNoteId or BrowserAiNoteId or BrowserTemporaryNoteId) PaintBrowserDescription(data);
        else if (data.Type == 5) PaintPageLabel(data);
        else PaintButton(data);
    }

    private static string TierDisplay(int value) => AuthorityPresentation.Label(value);

    private static void PaintPermissionChrome(IntPtr dc)
    {
        Text(dc, UiText.Get("已保存档位"), Layout.CurrentLabel, 16, 0xB2D4EF, false, shadow: true);
        Text(dc, TierDisplay(model.EffectiveTier), Layout.CurrentValue, UiText.English && CompactSurface ? 29 : 38, AuthorityPresentation.Ink(model.EffectiveTier), true, face: DisplayFace, shadow: true);
        Text(dc, runtimeNotice.Length == 0 ? UiText.Get("已保存 · ") + EffectiveMode() : UiText.BrokerSummary(runtimeNotice), Layout.SavedStatus, 15, 0xC6B6C5, false, shadow: true);
        string pending = !Dirty ? UiText.Get("无未保存更改")
            : tier == model.EffectiveTier ? UiText.Get("待保存  ") + TierDisplay(tier) + UiText.Get(" · 名单有变更")
            : UiText.Get("待保存  ") + TierDisplay(tier);
        Text(dc, pending, Layout.PendingDraft, 16,
            Dirty ? 0x8BC0FFu : 0xC6B6C5u, false, shadow: true);
        Text(dc, UiText.Get("权限档位"), Layout.TierCaption, 15, 0xC6B6C5, false);
        Text(dc, preview ? UiText.Get("预览仅修改草稿") : UiText.Get("点击立即切换"), Layout.TierHint, 13, 0xA58C9E, false);

        Text(dc, PageTitle(), Layout.PageTitle, 43, 0xF2F0F7, true);
        if (UiText.English) WrappedText(dc, PageLead(), Layout.PageLead, 17, 0xC6B6C5);
        else Text(dc, PageLead(), Layout.PageLead, 17, 0xC6B6C5, false);

        Text(dc, UiText.Get("正在查看"), Layout.ViewLabel, 14, 0xFFC9DC, false);
        Text(dc, TierDisplay(ruleLayer), Layout.ViewTier, 20, AuthorityPresentation.Ink(ruleLayer), true);
        var badge = ViewBadge();
        SoftSurface(dc, Layout.ViewBadge, badge.Color, badge.Fill, 9);
        Text(dc, badge.Text, Layout.ViewBadge, 12, badge.Color, false, centered: true);

        if (!HighContrast() && ruleLayer >= 2)
        {
            Frame(dc, Layout.R(596, 388, 858, 436), 0x332A3D);
            Text(dc, UiText.Get("只修改草稿；不会启动或终止程序。"), Layout.R(930, 752, 480, 20), 14, 0xA58C9E, false);
            Text(dc, UiText.Get("黑名单优先；降档会保留本层名单。"), Layout.R(600, 832, 850, 20), 14, 0xA58C9E, false);
        }
        if (ruleLayer >= 2) Text(dc, UiText.Get("本层 ") + RowCount + " / 128", Layout.R(1310, 392, 140, 20), 14, 0xA58C9E, false);
        Text(dc, FooterStatusText(), Layout.Status, 15, Dirty ? 0x8BC0FFu : 0xC6B6C5u, false);
        WrappedText(dc, VisibleNotice(), Layout.Notice, 15, 0xF0D9E7);
    }

    private static (string Text, uint Color, byte Fill) ViewBadge()
    {
        if (Dirty && ruleLayer == tier)
            return tier == model.EffectiveTier ? (UiText.Get("有草稿"), 0x8BC0FFu, (byte)26) : (UiText.Get("待保存层"), 0x8BC0FFu, (byte)26);
        if (ruleLayer == model.EffectiveTier) return (UiText.Get("已保存层"), AuthorityPresentation.Ink(ruleLayer), (byte)20);
        return (UiText.Get("仅查看"), 0xFFC9DCu, (byte)18);
    }

    private static string FooterStatusText()
    {
        string effective = TierDisplay(model.EffectiveTier);
        if (!Dirty) return UiText.Get("已保存 · ") + effective + (DecisionDirty ? UiText.Get(" · 服务待保存") : "");
        if (tier == model.EffectiveTier) return UiText.Get("有未保存更改 · 本层名单已修改") + (DecisionDirty ? UiText.Get(" · 服务待保存") : "");
        string pending = tier < 0 ? UiText.Get("完全禁止") : TierDisplay(tier);
        return UiText.Get("有未保存更改 · 档位 ") + effective + " → " + pending + (DecisionDirty ? UiText.Get(" · 服务待保存") : "");
    }

    private static void PaintPrograms(IntPtr dc)
    {
        var rows = draft?.AllowedAdminApplications ?? [];
        int count = Math.Min(rows.Length, 4);
        for (int index = 0; index < count; index++)
        {
            var row = Layout.Row(index);
            Fill(dc, row, 0x1F1B2A);
            Text(dc, string.IsNullOrWhiteSpace(rows[index].TitleContains) ? Path.GetFileName(rows[index].Path) : rows[index].TitleContains,
                Inset(row, 24, 14, 300, 26), 20, 0xF0F0F5, true);
            Text(dc, Path.GetFileName(rows[index].Path), Inset(row, 24, 46, 400, 20), 15, 0x9595A6, false);
            Text(dc, rows[index].Enabled ? UiText.Get("✓ 允许") : UiText.Get("已禁用"), Inset(row, 700, 24, 160, 24), 17, 0xCBD7FF, false);
        }
        if (count == 0) Text(dc, UiText.Get("名单为空：目前没有单独授权的程序"), Layout.Row(0), 18, 0x8E8E9E, false);
    }

    private static string PageTitle() => page switch
    {
        0 => UiText.Get("状态总览"),
        1 => ruleLayer < 2 ? UiText.Get("窗口禁止规则") : UiText.Get("程序允许与禁止"),
        2 => UiText.Get("隐私保护"),
        3 => UiText.Get("常规设置"),
        _ => UiText.Get("诊断与回执")
    };

    private static string PageLead() => page switch
    {
        0 => UiText.Get("权限、隐私与电脑操作状态。"),
        1 => ruleLayer < 2
            ? UiText.Get("按完整路径或标题条件阻止窗口；行首 # 表示停用。查看规则层不会改变待保存档位。")
            : ruleLayer == 3
                ? UiText.Get("白名单在左，黑名单在右；黑名单优先。04 的系统入口检查在保存前进行。")
                : (draft.AdminLaunchMode == "semantic"
                    ? UiText.Get("04名单仅用于 High 启动；工作授权无需白名单，黑名单优先。")
                    : UiText.Get("04名单仅用于 High 启动；名单模式按白名单，黑名单优先。"))
                    + (model.ProgramsOverlap(ruleLayer) ? UiText.Get(" 名单有历史重叠，请检查。") : ""),
        2 => UiText.Get("密码框自动遮蔽；敏感词在返回 AI 前抹除。"),
        3 => generalSection == 1 ? UiText.Get("个人、AI 与临时登录态分开打开。") : UiText.Get("本机操作偏好与可选决策服务。"),
        _ => UiText.Get("最近的通道状态与失败原因。")
    };

    private static string StatusLine()
    {
        if (Busy) return UiText.Get("正在保存或准备 · 其它草稿保留");
        if (!AuthorityPresentation.Selectable(model.EffectiveTier)) return UiText.Get("旧系统接管已冻结 · 先选择 01–04 档位");
        if (model.Conflict) return UiText.Get("外部配置变化 · 草稿保留");
        if (surfaceFault) return UiText.Get("界面操作异常 · 保存已暂停");
        if (Dirty && DecisionDirty) return UiText.Get("权限/偏好与服务均有草稿");
        if (Dirty) return UiText.Get("权限/偏好有未保存更改");
        if (DecisionDirty) return UiText.Get("决策服务有未保存更改");
        return preview ? UiText.Get("预览 · 不读取或写入真实权限") : UiText.Get("已保存");
    }

    private static void PaintButtonArt(IntPtr dc)
    {
        for (int index = 0; index < NavNames.Length; index++)
            Art(NavBase + index, NavNames[index], Layout.Nav(index), page == index, 0x140F1Cu, 0xC8C8D6u);
        for (int index = 0; index < 4; index++)
            Art(TierBase + index, AuthorityPresentation.Label(index - 1), Layout.Tier(index), tier == index - 1,
                tier == index - 1 ? 0x3A2E5Eu : 0x1A1526u, AuthorityPresentation.Ink(index - 1));
        Art(AddId, UiText.Get("+ 添加程序"), Layout.Add, false, 0x1C2E22, 0xBFE8C8);
        Art(HelpId, UiText.Get("使用说明"), Layout.Help, false, 0x1C2E22, 0xBFE8C8);
        if (page == 0) Art(StopId, UiText.Get("■ 结束电脑操作"), OverviewStopBounds(), false, 0x4A1F2A, 0xF7D6DC);
        Art(SaveId, UiText.Get("保存权限"), Layout.Save, false, 0x241E36, 0xFFFFFF);

        void Art(int id, string text, Rect bounds, bool active, uint fill, uint ink)
        {
            Fill(dc, bounds, fill);
            Frame(dc, bounds, id == StopId ? 0x5C2A38u : 0x3A3450u);
            Text(dc, text, bounds, 18, ink, active || id is SaveId or StopId, centered: true);
        }
    }

    private static void PaintButton(DrawItem item)
    {
        int id = (int)item.Id;
        var bounds = item.Rect;
        if (IsDecisionButton(id)) { PaintDecisionButton(item); return; }
        if (PermissionPage && id is >= ViewLayerBase and <= ViewLayerBase + 3)
        {
            if (CompactSurface) PaintPermissionViewTickCompact(item, id - ViewLayerBase);
            else PaintPermissionViewTick(item, id - ViewLayerBase);
            return;
        }
        if (PermissionPage && !CompactSurface && id is >= TierBase and <= TierBase + 3)
        { PaintPermissionTier(item, id - TierBase); return; }
        if (PermissionPage && CompactSurface && id is >= TierBase and <= TierBase + 3)
        { PaintPermissionTierCompact(item, id - TierBase); return; }
        if (PermissionPage && id is >= ListKindBase and <= ListKindBase + 1)
        {
            if (CompactSurface) PaintPermissionListKindCompact(item, id == ListKindBase + 1);
            else PaintPermissionListKind(item, id == ListKindBase + 1);
            return;
        }
        if (PermissionPage && (id is >= ModeChoiceBase and <= ModeChoiceBase + 1 || id is >= CancelScopeBase and <= CancelScopeBase + 1))
        { PaintPermissionTextChoice(item); return; }
        if (id == SaveId) { PaintPermissionSave(item); return; }
        if (id == StopId) { PaintPermissionStop(item); return; }
        if (PermissionPage && !CompactSurface && !HighContrast() && id == NoticeDetailsId) { PaintPermissionNoticeDetails(item); return; }
        bool active = IsPermissionChoice(id) ? PermissionChoiceSelected(id) : id is >= NavBase and < NavBase + 5 ? page == id - NavBase
            : id is >= TierBase and < TierBase + 4 ? tier == AuthorityPresentation.ButtonTier(id - TierBase)
            : id == GeneralPreferencesId ? page == 3 && generalSection == 0
            : id == GeneralWebId && page == 3 && generalSection == 1;
        uint fill = id >= TierBase && id < TierBase + 4 ? (active ? 0x3A2E5Eu : 0x1A1526u)
            : id == StopId ? 0x4A1F2A
            : id == AddId ? 0x1C2E22
            : id == HelpId ? 0x1C2E22
            : id == RuleHelpId ? 0x241E36
            : active ? 0x2A2340u : 0x140F1C;
        PaintControlBackdrop(item);
        if (HighContrast()) Fill(item.Dc, bounds, fill);
        if (!HighContrast())
        {
            if (id == AddId)
            {
                artwork?.DrawQuietLeaf(item.Dc, NativeRect(bounds), (item.State & 4) == 0);
            }
            if (id == StopId)
            {
                PaintRoseControl(item.Dc, bounds);
            }
            if (active && id is >= NavBase and < NavBase + 5)
                artwork?.DrawControl(item.Dc, NativeRect(new Rect { Left = Px(2), Top = Px(4), Right = Px(22), Bottom = bounds.Bottom - Px(4) }), "crystal");
        }
        uint color = active || id is SaveId or StopId ? 0xFFFFFFu : id == HelpId ? 0xBFE8C8u : 0xC8C8D6u;
        if (id == StopId) color = 0xF7D6DC;
        if (id is >= TierBase and < TierBase + 4) color = AuthorityPresentation.Ink(AuthorityPresentation.ButtonTier(id - TierBase));
        if (id == AddId) color = 0x162E19;
        if ((item.State & 4) != 0) color = 0x89838D;
        bool contrast = HighContrast();
        if (contrast)
        {
            var r = bounds; FillRect(item.Dc, ref r, GetSysColorBrush(active ? 13 : 15));
            color = GetSysColor((item.State & 4) != 0 ? 17 : active ? 14 : 18);
            Frame(item.Dc, bounds, GetSysColor(18));
        }
        if (!contrast && id is >= TierBase and < TierBase + 4)
            SoftSurface(item.Dc, bounds, AuthorityPresentation.Ink(AuthorityPresentation.ButtonTier(id - TierBase)), (byte)(active ? 45 : 12), 12);
        if (!contrast && IsPermissionChoice(id))
        {
            SoftSurface(item.Dc, bounds, 0x826956, (byte)((item.State & 4) != 0 ? 18 : active ? 165 : 45), 9);
            if (active) Line(item.Dc, bounds.Left + Px(12), bounds.Bottom - Px(2), bounds.Right - Px(12), bounds.Bottom - Px(2), 0xE3BCD8, 2);
        }
        if (!contrast && id is GeneralPreferencesId or GeneralWebId)
            SoftSurface(item.Dc, bounds, 0x80664F, (byte)(active ? 110 : 24), 10);
        if (!contrast && id is OpenPersonalBrowserId or OpenAiBrowserId or OpenTemporaryBrowserId)
            SoftSurface(item.Dc, bounds, 0x826956, (byte)((item.State & 4) == 0 ? 90 : 24), 10);
        if (!contrast && id == SaveId && (item.State & 4) == 0)
            SoftSurface(item.Dc, bounds, 0xA27681, 220, 13);
        if (!contrast && id == NoticeDetailsId)
            SoftSurface(item.Dc, bounds, 0x826956, 90, 9);
        if (!contrast && id == SemanticEnableId)
            SoftSurface(item.Dc, bounds, 0x826956, (byte)((item.State & 4) == 0 ? 90 : 24), 9);
        if (!contrast && id is >= EmergencyStopId and <= ExportDiagnosticsId)
        {
            bool danger = id == EmergencyStopId;
            SoftSurface(item.Dc, bounds, danger ? 0x4A1F2Au : 0x826956u,
                (byte)((item.State & 4) == 0 ? danger ? 220 : 70 : 20), 9);
            if (danger && (item.State & 4) == 0) color = 0xF7D6DC;
        }
        if (!contrast && id is HelpId or RuleHelpId)
            SoftSurface(item.Dc, bounds, 0x826956, (byte)((item.State & 4) == 0 ? 68 : 20), 9);
        if (!contrast && (id is MaskToggleId or MaskRemoveId || id is >= 480 and <= 485 && (item.State & 4) == 0))
            SoftSurface(item.Dc, bounds, 0x826956, (byte)((item.State & 4) == 0 ? 40 : 16), 10);
        if (PermissionPage && !contrast && id == ProgramMenuId)
        {
            var list = PageHandle(ProgramListId); GetClientRect(list, out var row);
            row.Top = (Selection(ProgramListId) - SendMessageW(list, 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32()) * ProgramRowHeight;
            row.Bottom = row.Top + ProgramRowHeight; MapWindowPoints(list, item.Window, ref row, 2);
            SoftSurface(item.Dc, row, 0x826956, 32, 13);
        }
        if (id == AddId && !contrast)
        {
            string addCaption = Text(item.Window).TrimStart('+', ' ');
            if (CompactSurface && PermissionPage && ruleLayer >= 2) addCaption = denied ? UiText.Get("添加黑名单") : UiText.Get("添加白名单");
            int fontSize = CompactSurface ? 14 : 17;
            int arm = CompactSurface ? Px(6) : Px(8);
            int gap = Px(8);
            int inset = Px(CompactSurface ? 28 : 34);
            int maxText = Math.Max(Px(24), bounds.Right - bounds.Left - inset * 2);
            int textWidth = Math.Min(MeasureText(item.Dc, addCaption, fontSize), maxText);
            int center = (bounds.Left + bounds.Right) / 2;
            int textLeft = center - textWidth / 2;
            var label = new Rect { Left = textLeft, Top = bounds.Top, Right = textLeft + textWidth, Bottom = bounds.Bottom };
            int plusX = textLeft - gap - arm;
            bool enabled = (item.State & 4) == 0;
            uint leafInk = enabled ? 0x173A22u : 0x666B5Eu;
            uint leafLift = enabled ? 0xD8EEC1u : 0xD2D2C4u;
            var lift = label; lift.Left += 1; lift.Right += 1; lift.Top += 1; lift.Bottom += 1;
            Text(item.Dc, addCaption, lift, fontSize, leafLift, true, centered: true);
            Text(item.Dc, addCaption, label, fontSize, leafInk, true, centered: true);
            int y = (bounds.Top + bounds.Bottom) / 2;
            Line(item.Dc, plusX - arm + 1, y + 1, plusX + arm + 1, y + 1, leafLift, 2);
            Line(item.Dc, plusX + 1, y - arm + 1, plusX + 1, y + arm + 1, leafLift, 2);
            Line(item.Dc, plusX - arm, y, plusX + arm, y, leafInk, 2);
            Line(item.Dc, plusX, y - arm, plusX, y + arm, leafInk, 2);
        }
        else
        {
            string caption = IsPermissionChoice(id) ? PermissionChoiceText(id)
                : id == ProgramMenuId ? "···"
                : id is >= TierBase and <= TierBase + 3 ? AuthorityPresentation.Label(AuthorityPresentation.ButtonTier(id - TierBase))
                : Text(item.Window);
            Text(item.Dc, caption, bounds, IsPermissionChoice(id) ? 18 : id == ProgramMenuId ? 27 : id is >= NavBase and < NavBase + 5 ? 23 : id == StopId ? 22 : id == RuleHelpId ? 16 : UiText.English && id is >= TierBase and < TierBase + 4 ? 16 : 19,
                color, id == StopId || active, centered: true, nativeColor: contrast, shadow: id is >= TierBase and < TierBase + 4);
        }
        if (GetFocus() == item.Window)
        {
            var focus = new Rect
            {
                Left = bounds.Left + Px(3),
                Top = bounds.Top + Px(3),
                Right = bounds.Right - Px(3),
                Bottom = bounds.Bottom - Px(3)
            };
            if (id is >= NavBase and < NavBase + 5 && !contrast)
            {
                if (keyboardNavigation) Line(item.Dc, focus.Left + Px(12), focus.Bottom, focus.Right - Px(12), focus.Bottom, 0xE3BCD8, 2);
            }
            else PaintKeyboardFocus(item.Dc, ref focus);
        }
    }

    private static string Text(IntPtr hwnd)
    {
        int size = Math.Clamp(GetWindowTextLengthW(hwnd) + 1, 2, 32769);
        var buffer = new StringBuilder(size);
        GetWindowTextW(hwnd, buffer, size);
        return buffer.ToString();
    }

    private static int MeasureText(IntPtr dc, string value, int size)
    {
        var font = UiFont(-FontPixels(size), 600, BodyFace);
        var previous = SelectObject(dc, font);
        try
        {
            var measured = new Rect();
            DrawTextW(dc, value, -1, ref measured, 0x400 | 0x20 | 0x800);
            return Math.Max(1, measured.Right - measured.Left);
        }
        finally { SelectObject(dc, previous); }
    }

    private static void Text(IntPtr dc, string value, Rect rect, int size, uint color, bool bold, bool centered = false, string? face = null, bool nativeColor = false, bool shadow = false)
    {
        if (HighContrast() && !nativeColor) color = GetSysColor(8);
        var font = UiFont(-FontPixels(size), bold ? 600 : 400, face ?? BodyFace);
        var previous = SelectObject(dc, font);
        uint old = SetTextColor(dc, color);
        SetBkMode(dc, 1);   // TRANSPARENT: text must never punch white boxes
        try
        {
            uint format = (uint)(0x20 | 0x4 | 0x800 | 0x8000 | (centered ? 1 : 0));
            if (shadow && !HighContrast())
            {
                SetTextColor(dc, 0x170E19);
                var shade = rect; shade.Left += 1; shade.Right += 1; shade.Top += 1; shade.Bottom += 1;
                DrawTextW(dc, value, -1, ref shade, format); SetTextColor(dc, color);
            }
            DrawTextW(dc, value, -1, ref rect, format);
        }
        finally { SetTextColor(dc, old); SelectObject(dc, previous); }
    }

    private static void Fill(IntPtr dc, Rect rect, uint color)
    {
        if (HighContrast()) color = GetSysColor(5);
        var brush = CreateSolidBrush(color);
        try { FillRect(dc, ref rect, brush); } finally { DeleteObject(brush); }
    }

    private static void Frame(IntPtr dc, Rect rect, uint color)
    {
        var pen = CreatePen(0, Math.Max(1, Px(1)), color);
        var previous = SelectObject(dc, pen);
        var brush = GetStockObject(5);
        var oldBrush = SelectObject(dc, brush);
        try { Rectangle(dc, rect.Left, rect.Top, rect.Right, rect.Bottom); }
        finally { SelectObject(dc, oldBrush); SelectObject(dc, previous); DeleteObject(pen); }
    }

    private static Rect Inset(Rect rect, int x, int y, int w, int h)
        => new() { Left = rect.Left + Px(x), Top = rect.Top + Px(y), Right = rect.Left + Px(x + w), Bottom = rect.Top + Px(y + h) };

    private static int Px(int value) => (int)Math.Round(value * scale);

    internal static bool HighContrast()
    {
        var contrast = new Contrast { Size = (uint)Marshal.SizeOf<Contrast>() };
        return SystemParametersInfoContrast(0x0042, contrast.Size, ref contrast, 0) && (contrast.Flags & 1) != 0;
    }

    private static Native.Rect NativeRect(Rect value) => new()
    { Left = value.Left, Top = value.Top, Right = value.Right, Bottom = value.Bottom };

    internal static void Attach(BrokerState state) => core = state;

    private static class Layout
    {
        internal static Rect BrandIcon => CompactSurface ? C(15, 16, 28, 28) : R(30, 20, 38, 38);
        internal static Rect Brand => CompactSurface ? C(55, 8, 220, 44) : R(83, 15, 360, 44);
        internal static Rect Help => CompactSurface ? C(15, 92, 190, 34) : R(1350, 30, 120, 36);
        internal static Rect Flower => CompactSurface ? C(22, 145, 240, 240) : PermissionPage ? R(95, 165, 470, 470) : R(150, 185, 550, 550);
        internal static Rect Anchor1 => CompactSurface ? default : R(125, 235, 175, 35);
        internal static Rect Anchor2 => CompactSurface ? default : R(670, 250, 160, 35);
        internal static Rect Anchor3 => CompactSurface ? default : R(90, 590, 155, 35);
        internal static Rect Anchor4 => CompactSurface ? default : R(710, 625, 100, 35);
        internal static Rect CurrentLabel => CompactSurface ? C(15, 395, 260, 30) : PermissionPage ? R(60, 640, 500, 26) : R(160, 765, 530, 30);
        internal static Rect CurrentValue => CompactSurface ? C(15, 425, 260, 50) : PermissionPage ? R(60, 660, 540, 54) : R(100, 797, 650, 68);
        internal static Rect CurrentMode => CompactSurface ? C(15, 475, 260, 35) : PermissionPage ? R(60, 724, 540, 30) : R(145, 870, 560, 34);
        internal static Rect SavedStatus => CompactSurface ? C(15, 500, 260, 24) : PermissionPage ? R(60, 720, 540, 26) : R(865, 924, 500, 20);
        internal static Rect PendingDraft => CompactSurface ? C(15, 526, 260, 24) : PermissionPage ? R(60, 750, 540, 26) : R(865, 944, 500, 22);
        internal static Rect TierHint => CompactSurface ? C(15, 552, 260, 20) : PermissionPage ? R(300, 784, 240, 22) : R(280, 907, 500, 22);
        internal static Rect ViewLabel => CompactSurface ? C(310, 190, 70, 20) : R(600, 240, 70, 20);
        internal static Rect ViewTier => CompactSurface ? C(380, 186, 230, 28) : R(670, 236, 230, 28);
        internal static Rect ViewBadge => CompactSurface ? C(310, 190, 100, 26) : R(910, 238, 108, 24);
        internal static Rect ViewHelp => CompactSurface ? C(310, 190, 100, 32) : R(1020, 236, 94, 30);
        internal static Rect ViewTab(int index) => CompactSurface ? C(410 + index * 138, 186, 132, 32) : R(1120 + index * 100, 236, 96, 30);
        internal static Rect PageTitle => CompactSurface ? C(310, 85, PermissionPage && ruleLayer >= 2 ? 485 : 650, 55) : PermissionPage ? R(600, 148, 680, 58) : R(865, 214, 590, 80);
        internal static Rect PageContent => CompactSurface ? C(302, 78, 680, 450) : R(850, 156, 620, 664);
        internal static Rect PageLead => CompactSurface ? C(310, 145, 650, UiText.English && PermissionPage ? 48 : 34) : PermissionPage ? R(600, 206, 660, UiText.English ? 48 : 30) : R(867, 304, 585, 38);
        internal static Rect Add => CompactSurface
            ? PermissionPage ? C(310, 510, 260, 82) : C(310, 524, 300, 56)
            : PermissionPage ? (ruleLayer < 2 ? R(615, 675, 300, 92) : R(615, 715, 300, 92))
            : page == 2 ? R(860, 790, 300, 95) : R(860, 733, 350, 110);
        internal static Rect Stop => CompactSurface ? C(650, 528, 305, 52) : PermissionPage ? R(1290, 910, 185, 50) : R(1160, 806, 300, 75);
        internal static Rect Save => CompactSurface ? C(800, 602, 155, 30) : PermissionPage ? R(1100, 914, 180, 42) : R(1290, 935, 170, 43);
        internal static Rect Reload => CompactSurface ? C(690, 602, 100, 30) : PermissionPage ? R(1005, 918, 80, 34) : R(1110, 935, 165, 43);
        internal static Rect Status => CompactSurface ? C(700, 582, 260, 20) : PermissionPage ? R(600, 924, 400, 26) : R(865, 945, 235, 28);
        internal static Rect Notice => CompactSurface ? (page == 3 ? C(310, 180, 570, 20) : C(310, 600, 300, 38)) : PermissionPage ? R(600, 892, 490, 26) : R(865, 894, 490, 36);
        internal static Rect NoticeDetails => CompactSurface ? (page == 3 ? C(900, 179, 88, 22) : C(620, 602, 60, 32)) : PermissionPage ? R(1100, 890, 60, 24) : R(1370, 890, 85, 42);
        internal static Rect Nav(int index) => CompactSurface ? C(310 + index * 133, 16, 125, 40) : R(885 + index * 114, 90, 108, 46);
        internal static Rect TierCaption => CompactSurface ? C(15, 512, 260, 22) : PermissionPage ? R(60, 784, 220, 22) : R(75, 907, 735, 22);
        internal static Rect Tier(int index) => CompactSurface ? C(20 + index % 2 * 130, 538 + index / 2 * 38, 125, 32) : PermissionPage ? R(60, 810 + index * 43, 500, 40) : R(75 + index * 187, 933, 176, 40);
        internal static Rect C(int x, int y, int w, int h)
        {
            GetClientRect(window, out var client);
            return new Rect { Left = x * client.Right / 1000, Top = y * client.Bottom / 640,
                Right = (x + w) * client.Right / 1000, Bottom = (y + h) * client.Bottom / 640 };
        }
        internal static Rect Row(int index) => R(650, 290 + index * 94, 790, 80);
        internal static Rect R(int x, int y, int w, int h) => new()
        {
            Left = (int)Math.Round(x * scale),
            Top = (int)Math.Round(y * scale),
            Right = (int)Math.Round((x + w) * scale),
            Bottom = (int)Math.Round((y + h) * scale)
        };
    }

    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct PaintStruct
    { public IntPtr Dc; public bool Erase; public Rect Rect; public bool Restore, Update; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Reserved; public PaintStruct WithHdc(IntPtr dc) { Dc = dc; Reserved = new byte[32]; return this; } }
    [StructLayout(LayoutKind.Sequential)]
    private struct DrawItem
    { public uint Type, Id, Item, Action, State; public IntPtr Window, Dc; public Rect Rect; public UIntPtr Data; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WindowClass
    { public uint Size, Style; public IntPtr Proc; public int Extra, WindowExtra; public IntPtr Instance, Icon, Cursor, Background; public string? Menu; public string Name; public IntPtr SmallIcon; }
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo { public uint Size; public Rect Monitor, Work; public uint Flags; }
    [StructLayout(LayoutKind.Sequential)] private struct Contrast { public uint Size, Flags; public IntPtr Scheme; }
    [StructLayout(LayoutKind.Sequential)] private struct MinMaxInfo { public Native.Point Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack; }
    [StructLayout(LayoutKind.Sequential)] private struct Msg { public IntPtr Hwnd; public uint Message; public UIntPtr W, L; public uint Time; public int X, Y; }

    private delegate IntPtr WndProc(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    private delegate bool EnumProc(IntPtr hwnd, IntPtr data);
    private static readonly WndProc Procedure = WindowProcedure;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern ushort RegisterClassExW(ref WindowClass value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr CreateWindowExW(uint ex, string kind, string title, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr id, IntPtr instance, IntPtr data);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] private static extern int GetMessageW(out HostWindow.Message message, IntPtr hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessageW(ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr GetFocus();
    [DllImport("user32.dll")] private static extern bool DrawFocusRect(IntPtr dc, ref Rect rect);
    [DllImport("user32.dll")] private static extern bool SystemParametersInfoW(uint action, uint param, ref Rect rect, uint flags);
    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
    private static extern bool SystemParametersInfoContrast(uint action, uint param, ref Contrast value, uint flags);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool UpdateWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr BeginPaint(IntPtr hwnd, ref PaintStruct paint);
    [DllImport("user32.dll")] private static extern bool EndPaint(IntPtr hwnd, ref PaintStruct paint);
    [DllImport("user32.dll")] private static extern bool InvalidateRect(IntPtr hwnd, IntPtr rect, bool erase);
    [DllImport("user32.dll", EntryPoint = "SetWindowPos")] private static extern bool SetWindowPosNative(IntPtr hwnd, IntPtr after, int x, int y, int w, int h, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumProc proc, IntPtr data);
    [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern uint GetDpiForSystem();
    [DllImport("user32.dll")] private static extern uint GetSysColor(int index);
    [DllImport("user32.dll")] private static extern IntPtr GetSysColorBrush(int index);
    [DllImport("user32.dll")] private static extern bool AdjustWindowRectExForDpi(ref Rect rect, uint style, bool menu, uint ex, uint dpi);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
    [DllImport("user32.dll")] private static extern bool GetMonitorInfoW(IntPtr monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowTextLengthW(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr SetClassLongPtrW(IntPtr hwnd, int index, IntPtr value);
    [DllImport("gdi32.dll")] private static extern IntPtr GetStockObject(int index);
    [DllImport("user32.dll")] private static extern int FillRect(IntPtr dc, ref Rect rect, IntPtr brush);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int DrawTextW(IntPtr dc, string text, int length, ref Rect rect, uint format);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFontW(int height, int width, int angle, int orientation,
        int weight, uint italic, uint underline, uint strike, uint charSet, uint outPrecision, uint clipPrecision, uint quality, uint pitch, string face);
    [DllImport("gdi32.dll")] private static extern uint SetTextColor(IntPtr dc, uint color);
    [DllImport("gdi32.dll")] private static extern int SetBkMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateSolidBrush(uint color);
    [DllImport("gdi32.dll")] private static extern IntPtr CreatePen(int style, int width, uint color);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool Rectangle(IntPtr dc, int left, int top, int right, int bottom);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int width, int height);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandleW(string? module);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] private static extern int SetWindowTheme(IntPtr hwnd, string? app, string? id);
    [DllImport("gdiplus.dll", CharSet = CharSet.Unicode)] private static extern int GdipSaveImageToFile(IntPtr image, string filename, ref Guid encoder, IntPtr parameters);
    [DllImport("gdiplus.dll")] private static extern int GdipCreateBitmapFromHBITMAP(IntPtr bitmap, IntPtr palette, out IntPtr image);
    [DllImport("gdiplus.dll")] private static extern int GdipDisposeImage(IntPtr image);
    private static readonly Guid PngEncoder = new("557CF406-1A04-11D3-9A73-0000F81EF32E");
    private static void SavePng(IntPtr dc, int width, int height, string path)
    {
        var bitmap = CreateCompatibleBitmap(dc, width, height);
        var copy = CreateCompatibleDC(dc);
        var previous = SelectObject(copy, bitmap);
        try
        {
            BitBlt(copy, 0, 0, width, height, dc, 0, 0, 0x00CC0020);
            if (GdipCreateBitmapFromHBITMAP(bitmap, IntPtr.Zero, out var image) == 0)
            {
                var png = PngEncoder;
                GdipSaveImageToFile(image, path, ref png, IntPtr.Zero);
                GdipDisposeImage(image);
            }
        }
        finally { SelectObject(copy, previous); DeleteDC(copy); DeleteObject(bitmap); }
    }
    [DllImport("gdi32.dll")] private static extern bool BitBlt(IntPtr dest, int x, int y, int w, int h, IntPtr source, int sx, int sy, uint op);
}

