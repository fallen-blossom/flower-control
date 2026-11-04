using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const uint WorkFinished = 0x8000 + 187, PickTimer = 187, WorkCompletionTimer = 189;
    private sealed record WorkReply(string Kind, UserPermissionSettings? Submitted = null, UserPermissionSettings? Committed = null,
        SettingsUiPreference? Preference = null, SettingsWordSnapshot? Words = null, string? Error = null,
        string? PreferenceError = null, string? WordError = null, string? SubmittedWords = null, string? SubmittedMode = null,
        DecisionProviderSnapshot? DecisionSettings = null, DecisionProviderPreferences? SubmittedDecisionSettings = null);
    private static Task<WorkReply>? work;
    private static CancellationTokenSource? workStop;
    private static SettingsWordSnapshot words = new("", "absent");
    private static SettingsUiPreference preference = new();
    private static string wordDraft = "", preferredMode = "allowlist", modeBaseline = "allowlist";
    private static bool preferencePending, surfaceFault, closeAfterSave, picking;
    private static IntPtr restoreFocus;
    private static long generation;
    private static DateTime pickExpiry;
    private static bool Busy => work is not null;
    private static bool Dirty => model.Dirty || wordDraft != words.Text || preferredMode != modeBaseline || preferencePending || invalidEdit;
    private static string TierName(int value) => AuthorityPresentation.Name(value);
    private static string UserFacingError(string code) => code switch
    {
        "jev_disabled" => UiText.Get("决策 API 总开关已关闭；当前聊天主模型仍可用"),
        "task_jev_disabled" or "jev_disabled_or_not_allowed" => UiText.Get("此任务未允许调用远程决策服务；当前聊天主模型仍可用"),
        "client_unavailable" => UiText.Get("决策服务客户端暂不可用"),
        "decision_settings_conflict" => UiText.Get("决策服务设置已被其他窗口修改"),
        "settings_ui_preferences_changed" => UiText.Get("界面偏好已被其他窗口修改"),
        "privacy_words_changed" => UiText.Get("敏感词表已被其他窗口修改"),
        "browser_not_found" or "brave_not_found" or "browser_executable_unavailable" or "selected_browser_not_installed" => UiText.Get("未找到可用的已安装浏览器"),
        "browser_profile_not_installed" or "browser_profile_bundle_unavailable" => UiText.Get("浏览器登录态入口尚未安装"),
        "uac_settings_validation_incomplete" => UiText.Get("系统验证尚未形成完整证据"),
        "uac_settings_evidence_incomplete" => UiText.Get("系统验证结果未能安全保存"),
        "uac_component_unavailable" => UiText.Get("当前系统入口尚未就绪"),
        _ when code.Contains("outcome_unknown", StringComparison.Ordinal) => UiText.Get("写入结果待核对；请保留草稿并重新读取"),
        _ when code.Contains("conflict", StringComparison.Ordinal) || code.Contains("changed", StringComparison.Ordinal) => UiText.Get("设置已被其他窗口修改；请重新读取"),
        _ when code.Contains("busy", StringComparison.Ordinal) || code.Contains("in_progress", StringComparison.Ordinal) => UiText.Get("已有操作尚未结束，请稍后再试"),
        _ => code
    };

    private static void Initialize(UserPermissionSettings value)
    {
        pageRebuildPending = pageRebuildPosted = surfaceClosePending = false;
        ++generation; model = new(value); page = 0; ruleLayer = Math.Clamp(model.DraftTier, 0, 2);
        pendingProgramReveal = null; windowPickContext = null;
        ResetBrowserOpening(); generalSection = 0;
        ResetDecisionSettings();
        AttachBrowserProfileBrowserOpener(preview ? null : BrowserProfileOpen.RequestBrowserAsync);
        notice = ""; invalidEdit = surfaceFault = preferencePending = closeAfterSave = false;
        preference = preview ? new() : UserPermissions.ReadUiPreference();
        modeBaseline = preferredMode = UserPermissions.PreferredUacSubmode(value.UacMode, preference);
        words = preview ? new(UiText.Get("示例敏感词\r\nexample-secret"), "preview") : UserPermissions.ReadSettingsWords();
        wordDraft = words.Text;
        programHealth.Clear();
        InitializeDisplayPreference();
    }
    private static string CapabilityText()
    {
        return AuthorityPresentation.FrozenNotice + UiText.Get("\r\n管理员进程连接不等于真实业务已通过。");
    }
    private static void RequestTier(int target)
    {
        if (!AuthorityPresentation.Selectable(target))
        { notice = AuthorityPresentation.FrozenNotice; UpdateChrome(); return; }
        if (Busy || invalidEdit || model.Conflict) { notice = UiText.Get("请先等待操作完成或核对未保存字段。"); UpdateChrome(); return; }
        EndPick();
        if (!preview && core is not null)
        {
            if (BrowserOpening) { notice = UiText.Get("浏览器打开操作尚未收束；请先等待原结果。"); UpdateChrome(); return; }
            var broker = core; var prior = saved; var surface = CaptureHandoff();
            bool roleMatches = broker.OrdinaryResident == (model.EffectiveTier <= 0);
            if (model.EffectiveTier == target && roleMatches) return;
            int chosen = target;
            StartWork(token =>
            {
                if (broker.OrdinaryResident)
                {
                    var outcome = LocalUiWriter.Execute(broker, new("tier", prior.Revision, Tier: chosen), surface, token);
                    return new("tier", prior, outcome.Current);
                }
                broker.BeginLocalTransition(token);
                bool switched = false;
                try
                {
                    UserPermissions.RequireCurrentRevision(prior.Revision, UserPermissions.Read().Revision);
                    var committed = UacInstallation.SaveSettings(UserPermissions.Effective(prior with { AuthorityTier = chosen }), broker, token);
                    if (chosen <= 0) { RoleHandoff.ToOrdinary(broker, surface, token); switched = true; }
                    return new("tier", prior, committed);
                }
                finally { if (!switched) broker.EndLocalTransition(); }
            });
            roleWork = true; EnableWindow(window, false);
            notice = chosen <= 0 ? UiText.Get("正在保存普通权限并释放管理员执行器；其他草稿保留。") : broker.OrdinaryResident
                ? UiText.Get("正在请求 Windows 管理员确认；取消会保留普通执行器和草稿。") : UiText.Get("正在切换管理员档位；其他草稿保留。");
            UpdateChrome(); return;
        }
        model.SelectTier(target); notice = UiText.Get("档位草稿已更改；左侧花保持已保存档位。"); UpdateChrome();
    }
    private static void StartWork(Func<CancellationToken, WorkReply> run)
    {
        if (Busy) throw new Boundary("uac_settings_work_busy");
        if (SetTimer(window, new UIntPtr(WorkCompletionTimer), 100, IntPtr.Zero) == UIntPtr.Zero)
            throw new Boundary("settings_work_completion_timer_unavailable");
        workStop = new(); var token = workStop.Token; var handle = window; long expected = generation;
        work = Task.Run(() => { try { return run(token); } catch (Exception error) { return new WorkReply("failed", Error: Program.Code(error)); } });
        _ = work.ContinueWith(_ => { if (expected == generation) PostMessageW(handle, WorkFinished, UIntPtr.Zero, IntPtr.Zero); }, TaskScheduler.Default);
        UpdateDecisionButtons();
    }
    private static void RequestSave(bool close = false)
    {
        if (Busy || model.Conflict || surfaceFault || invalidEdit) { notice = UiText.Get("当前不能保存；草稿保留，请核对提示或重新载入。"); UpdateChrome(); return; }
        if (!Dirty) { if (close) CloseSurfaceSafely(); return; }
        if (!AuthorityPresentation.Selectable(model.EffectiveTier))
        { notice = UiText.Get("旧系统接管配置已冻结。请先选择 01–04 中的档位，再保存其他草稿；原配置和名单保留。"); UpdateChrome(); return; }
        UserPermissions.Validate(draft); UserPermissions.ValidateSettingsWords(wordDraft); EndPick();
        closeAfterSave = close;
        var submitted = draft; var prior = saved; var priorWords = words; var submittedWords = wordDraft;
        var priorPreference = preference; string submittedMode = preferredMode;
        bool policyChanged = model.Dirty, wordsChanged = submittedWords != priorWords.Text;
        bool preferenceChanged = UserPermissions.UiPreferenceNeedsSave(prior.UacMode, submitted.UacMode, submittedMode, modeBaseline, priorPreference, preferencePending);
        if (wordsChanged && priorWords.Error is not null) throw new Boundary("privacy_words_unreadable");
        if (preview)
        {
            var committed = submitted with { Revision = "preview-" + Guid.NewGuid().ToString("N") };
            ApplySave(new("save", submitted, committed, new(submittedMode, "preview"), new(submittedWords, "preview"), SubmittedWords: submittedWords, SubmittedMode: submittedMode)); return;
        }
        if (core is null) throw new Boundary("settings_live_broker_required");
        if (policyChanged && submitted.UacMode != "off")
        {
            var c = UacRuntime.Capabilities();
            if (submitted.UacMode == "semantic" || !c.AllowlistAvailable) throw new Boundary("uac_component_unavailable");
            if (!PermissionSettingsWindow.UacCancellationScopeSelectionAvailable(submitted.UacCancellationScope, prior.UacCancellationScope, c))
                throw new Boundary("uac_cancellation_scope_unavailable");
        }
        var broker = core;
        StartWork(token =>
        {
            if (broker.OrdinaryResident)
            {
                var outcome = LocalUiWriter.Execute(broker, new("save", prior.Revision, Submitted: submitted,
                    PolicyChanged: policyChanged, Words: wordsChanged ? submittedWords : null,
                    WordsRevision: wordsChanged ? priorWords.Revision : null, Mode: preferenceChanged ? submittedMode : null,
                    ModeRevision: preferenceChanged ? priorPreference.Revision : null), null, token);
                return new("save", submitted, outcome.Current, outcome.Preference, outcome.Words,
                    PreferenceError: outcome.PreferenceError, WordError: outcome.WordError, SubmittedWords: submittedWords, SubmittedMode: submittedMode);
            }
            var committed = policyChanged ? UacInstallation.SaveSettings(submitted, broker, token) : prior;
            SettingsUiPreference? newPreference = null; SettingsWordSnapshot? newWords = null; string? prefError = null, wordError = null;
            if (preferenceChanged) try { newPreference = UserPermissions.SaveUiPreference(committed.Revision, priorPreference.Revision, submittedMode, token); } catch (Exception error) { prefError = Program.Code(error); }
            if (wordsChanged) try { newWords = UserPermissions.SaveSettingsWords(submittedWords, priorWords.Revision, committed.Revision, token); } catch (Exception error) { wordError = Program.Code(error); }
            return new("save", submitted, committed, newPreference, newWords, PreferenceError: prefError, WordError: wordError, SubmittedWords: submittedWords, SubmittedMode: submittedMode);
        });
        notice = UiText.Get("正在保存；可以切换页面，保存完成不会吞掉后续草稿。"); UpdateChrome();
    }
    private static void CompleteWork()
    {
        if (work is null || !work.IsCompleted) return;
        KillTimer(window, new UIntPtr(WorkCompletionTimer));
        var reply = work.GetAwaiter().GetResult(); work = null; workStop?.Dispose(); workStop = null;
        if (roleWork) { roleWork = false; if (window != IntPtr.Zero) EnableWindow(window, true); }
        if (reply.Kind == "decision_save") { CompleteDecisionServiceSave(reply); return; }
        if (reply.Kind == "browser_preferences") { CompleteBrowserPreferenceSave(reply); return; }
        if (reply.Kind == "display_preferences") { CompleteDisplayPreferenceSave(reply); return; }
        if (reply.Error is not null)
        {
            closeAfterSave = false; notice = (reply.Error.Contains("outcome_unknown") ? UiText.Get("结果待核对：") : UiText.Get("操作未完成：")) + UserFacingError(reply.Error) + "（" + reply.Error + UiText.Get("）；原草稿保留，不自动重试。");
            if (!preview) { try { if (UserPermissions.Read().Revision != saved.Revision) model.Conflict = true; } catch { model.Conflict = true; } }
            if (reply.Error.Contains("outcome_unknown")) model.Conflict = true;
        }
        else if (reply.Kind == "save") ApplySave(reply);
        else if (reply.Kind == "tier")
        {
            model.ReconcileTier(reply.Submitted!, reply.Committed!);
            notice = UiText.Get("执行档位已保存；其他未保存更改保留。");
        }
        else if (reply.Kind == "semantic_enable")
        {
            bool reconciled = model.ReconcileSemanticDelegation(reply.Submitted!, reply.Committed!);
            notice = reconciled ? UiText.Get("04 工作授权已启用；其他草稿未保存，未启动程序。")
                : UiText.Get("委托写入后基线出现变化；草稿保留，请重新载入核对。");
        }
        else if (reply.Kind == "prepare")
        {
            if (reply.Committed?.Revision != saved.Revision || reply.Submitted?.Revision != saved.Revision)
            { model.Conflict = true; notice = UiText.Get("准备期间设置变化，未改变档位；请重新载入核对。"); }
            else if (UacRuntime.Capabilities().AllowlistAvailable)
            { model.SelectTier(3); notice = UiText.Get("同版本路线就绪，04 已进入草稿；保存后生效。"); }
            else notice = UiText.Get("04 的校准证据尚未齐备；原档位保留。请查看诊断。");
        }
        else if (reply.Kind == "disable")
        {
            // An immediate revoke changes the saved record; keep unrelated
            // drafts, and do not let a later Save restore the revoked tier.
            var current = reply.Committed!;
            if (reply.Submitted is null) model.Conflict = true;
            bool reconciled = model.ReconcileImmediateRevoke(current, reply.Submitted);
            if (!reconciled) closeAfterSave = false;
            notice = reconciled ? UiText.Get("UAC 与系统入口已立即停用。未恢复 Stop，未重放动作。")
                : UiText.Get("停用期间设置出现外部变化；原草稿保留，未推进保存基线。请重新载入核对。未恢复 Stop，未重放动作。");
        }
        else notice = UiText.Get("验证或登记已结束；未自动启用权限、恢复 Stop 或重放原动作。");
        if (window != IntPtr.Zero) { if (page is 0 or 4 && !invalidEdit) BuildPage(); UpdateDecisionButtons(); UpdateChrome(); }
    }
    private static void ApplySave(WorkReply reply)
    {
        model.Commit(reply.Submitted!, reply.Committed!);
        if (preview) SetVisualState(TrayStateIcons.Select(model.EffectiveTier, true, false));
        if (reply.Preference is not null) { preference = reply.Preference; modeBaseline = reply.SubmittedMode!; preferencePending = false; }
        if (reply.PreferenceError is not null) preferencePending = true;
        if (reply.Words is not null) { words = reply.Words; if (wordDraft == reply.SubmittedWords) wordDraft = reply.Words.Text; }
        if (reply.PreferenceError is "user_policy_changed_reopen_settings" or "settings_ui_preferences_changed" or "settings_ui_preferences_save_outcome_unknown"
            || reply.WordError is "user_policy_changed_reopen_settings" or "privacy_words_changed" or "privacy_words_save_outcome_unknown") model.Conflict = true;
        notice = reply.PreferenceError is not null || reply.WordError is not null
            ? UiText.Get("权限已保存；") + (reply.PreferenceError is not null ? UiText.Get("界面偏好待保存（") + UserFacingError(reply.PreferenceError) + "） " : "") + (reply.WordError is not null ? UiText.Get("词表待保存（") + UserFacingError(reply.WordError) + "）" : "")
            : preview ? UiText.Get("已保存到预览内存；真实权限与词表未写入。") : UiText.Get("已保存并应用。");
        bool close = closeAfterSave && !Dirty; closeAfterSave = false;
        if (close) { CloseSurfaceSafely(); return; }
        if (page is 0 or 4 && !invalidEdit) BuildPage(); UpdateDecisionButtons(); UpdateChrome();
    }
    private static void StopWork()
    {
        EndPick(); workStop?.Cancel(); core?.StopComputerUse();
        notice = preview ? UiText.Get("预览没有真实电脑操作；在途页面操作已请求取消。") : UiText.Get("已结束当前 Computer Use 并取消页面在途工作；App/Web 保持。");
    }
    private static void RequestClose()
    {
        if (Busy) { notice = UiText.Get("操作尚未收束，暂不能关闭。可先结束电脑操作，等待原结果。"); UpdateChrome(); return; }
        EndPick();
        bool mainDirty = Dirty, servicesDirty = DecisionDirty;
        if (!mainDirty && !servicesDirty) { CloseSurfaceSafely(); return; }
        string scope = mainDirty && servicesDirty ? UiText.Get("权限/操作偏好和决策服务都有未保存更改。")
            : servicesDirty ? UiText.Get("决策服务还有未保存更改；主权限草稿保持原状。")
            : UiText.Get("还有未保存的权限或操作偏好更改。");
        int answer = MessageBoxW(window, scope + UiText.Get("\r\n保存全部后关闭、放弃全部更改，或返回继续编辑。"), UiText.Get("关闭设置"), 3 | 0x20 | 0x200);
        if (answer == 6)
        {
            if (servicesDirty) RequestDecisionServiceSave(true);
            else if (mainDirty) RequestSave(true);
            return;
        }
        if (answer != 7) return;
        DiscardAllDrafts();
        CloseSurfaceSafely();
    }
    private static void DiscardAllDrafts()
    {
        model.Reload(saved);
        wordDraft = words.Text; preferredMode = modeBaseline; preferencePending = false; invalidEdit = false;
        decisionDraft = decisionSnapshot?.Value?.Copy(); closeAfterDecisionSave = false;
    }
    private static void RequestReload()
    {
        if (Busy) return;
        if ((Dirty || DecisionDirty) && MessageBoxW(window, UiText.Get("重新载入会放弃所有未保存草稿，包括服务启停与顺序。继续？"), UiText.Get("重新载入"), 4 | 0x30 | 0x100) != 6) return;
        var current = preview ? saved : UserPermissions.Read(); var oldPage = page;
        Initialize(current); page = oldPage; BuildPage(); notice = UiText.Get("已重新载入；没有重放系统动作或恢复 Stop。"); UpdateChrome();
    }
    internal static void ShutdownOwnedWork()
    {
        // HostWindow.Run calls this after its outer message loop and native
        // dispatch unwind. No deferred message loop remains during shutdown.
        EndPick(); workStop?.Cancel();
        try { work?.GetAwaiter().GetResult(); } finally { work = null; workStop?.Dispose(); workStop = null; }
        if (window != IntPtr.Zero) DestroyWindow(window);
    }
    private static void ShutdownSurface()
    {
        KillTimer(window, new UIntPtr(OverviewTimer));
        KillTimer(window, new UIntPtr(WorkCompletionTimer));
        pageRebuildPending = pageRebuildPosted = surfaceClosePending = false;
        EndPick(); ++generation;
        ResetBrowserOpening();
        foreach (var icon in programIcons.Values) if (icon != IntPtr.Zero) DestroyIcon(icon); programIcons.Clear();
        pageControls.Clear();
        ReleaseUiFonts();
        if (pageFont != IntPtr.Zero) { DeleteObject(pageFont); pageFont = IntPtr.Zero; }
        if (pageBrush != IntPtr.Zero) { DeleteObject(pageBrush); pageBrush = IntPtr.Zero; }
        interactiveWindowMove = interactiveRasterResized = false; surfaceRedrawSuspended = false;
        ReleaseInteractiveControls(); ReleaseScene(); ReleaseBackdrop();
        artwork?.Dispose(); artwork = null; window = IntPtr.Zero; core = null;
        if (standalone) PostQuitMessage(0);
    }
    internal static bool HandleDialogMessage(ref HostWindow.Message message)
    {
        try { return HandleDialogMessageCore(ref message); }
        catch (Exception error)
        {
            surfaceFault |= error is not Boundary; notice = UiText.Get("操作未完成，草稿保留：") + Program.Code(error);
            if (window != IntPtr.Zero) UpdateChrome();
            Console.Error.WriteLine("settings_keyboard_error: " + Program.Code(error)); return true;
        }
    }
    private static bool HandleDialogMessageCore(ref HostWindow.Message message)
    {
        if (window == IntPtr.Zero || !(message.Hwnd == window || IsChild(window, message.Hwnd))) return false;
        if (message.Kind is 0x201 or 0x204 or 0x207 or 0x20B or 0x246) SetKeyboardNavigation(false);
        var focused = GetFocus(); if (focused != IntPtr.Zero && IsChild(window, focused)) restoreFocus = focused;
        if (message.Kind == 0x100)
        {
            int key = (int)message.Wp.ToUInt64(); bool control = GetKeyState(17) < 0;
            if (key is 9 or 37 or 38 or 39 or 40) SetKeyboardNavigation(true);
            if (GetDlgCtrlID(focused) == ModeChoiceBase && key is 37 or 39)
            { SetModeChoice(key == 37 ? 0 : 1); return true; }
            if (key is 37 or 38 or 39 or 40 && IsPermissionChoice(GetDlgCtrlID(focused)))
            {
                int id = GetDlgCtrlID(focused), start = id is >= 510 and <= 513 ? ViewLayerBase : id is >= 520 and <= 521 ? ListKindBase : id is >= 530 and <= 531 ? ModeChoiceBase : CancelScopeBase;
                int count = start == ViewLayerBase ? 3 : 2, direction = key is 37 or 38 ? -1 : 1;
                int next = start + (id - start + direction + count) % count;
                if (IsWindowEnabled(PageHandle(next))) { SetFocus(PageHandle(next)); SendMessageW(PageHandle(next), 0xF5, IntPtr.Zero, IntPtr.Zero); }
                return true;
            }
            if (key == 9 && !control && GetKeyState(18) >= 0)
            {
                var order = Enumerable.Range(0, 5).Select(i => GetDlgItem(window, NavBase + i))
                    .Concat(pageControls.Where(x => x.Id != 0 && x.Kind != "STATIC").Select(x => x.Handle))
                    .Concat(Enumerable.Range(0, 4).Select(i => GetDlgItem(window, TierBase + i)))
                    .Concat(new[] { GetDlgItem(window, AddId), GetDlgItem(window, StopId), GetDlgItem(window, NoticeDetailsId), GetDlgItem(window, HelpId), GetDlgItem(window, ReloadId), GetDlgItem(window, SaveId) })
                    .Where(h => h != IntPtr.Zero && IsWindowVisible(h) && IsWindowEnabled(h)).ToArray();
                if (order.Length > 0) { int index = Array.IndexOf(order, GetFocus()); int next = (index + (GetKeyState(16) < 0 ? -1 : 1) + order.Length) % order.Length; SetFocus(order[next]); restoreFocus = order[next]; }
                return true;
            }
            if (key == 27)
            {
                // The open native combo owns Escape and cancels its popup.
                if (pageControls.Any(c => c.Kind == "COMBOBOX" && SendMessageW(c.Handle, 0x157, IntPtr.Zero, IntPtr.Zero) != IntPtr.Zero)) return false;
                if (picking) { EndPick(); notice = UiText.Get("选窗已取消。"); UpdateChrome(); } else RequestClose(); return true;
            }
            if (key == 0x53 && control) { RequestSave(); return true; }
            if (key == 112) { ShowWorkspaceHelp(); return true; }
        }
        return message.Kind is >= 0x100 and <= 0x109 && IsDialogMessageW(window, ref message);
    }

    private static void RequestDiagnostic(int id)
    {
        if (preview || core is null || Busy) { notice = UiText.Get("预览不执行真实系统操作。"); UpdateChrome(); return; }
        EndPick(); var broker = core; var prior = saved;
        if (id == 481 && Dirty && MessageBoxW(window, UiText.Get("立即停用会撤销已保存 UAC。无关草稿将保留；继续？"), UiText.Get("立即停用 UAC"), 4 | 0x30 | 0x100) != 6) return;
        StartWork(token =>
        {
            token.ThrowIfCancellationRequested();
            if (id != 481) throw new Boundary("host_uac_feature_retired");
            if (broker.OrdinaryResident)
            {
                var outcome = LocalUiWriter.Execute(broker, new("disable", prior.Revision), null, token);
                return new("disable", prior, outcome.Current);
            }
            UacInstallation.Disable(); broker.RefreshPermissions(); return new("disable", prior, UserPermissions.Read());
        }); notice = UiText.Get("系统操作进行中；结束电脑操作可以请求取消，结果未知时不重试。"); UpdateChrome();
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct OpenFileName
    { public uint Size; public IntPtr Owner, Instance; public string Filter; public IntPtr CustomFilter; public uint CustomFilterLength, FilterIndex; public IntPtr File; public uint FileLength; public IntPtr FileTitle; public uint FileTitleLength; public string? InitialDirectory, Title; public uint Flags; public ushort FileOffset, FileExtension; public string? DefaultExtension; public IntPtr Data, Hook; public string? Template; public IntPtr Reserved; public uint ReservedValue, ExtendedFlags; }
    [DllImport("user32.dll")] private static extern bool PostMessageW(IntPtr h, uint m, UIntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetPropW(IntPtr h, string name, IntPtr value);
    [DllImport("user32.dll")] private static extern bool IsChild(IntPtr parent, IntPtr child);
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern short GetKeyState(int key);
    [DllImport("user32.dll")] private static extern bool IsDialogMessageW(IntPtr hwnd, ref HostWindow.Message message);
    [DllImport("user32.dll")] private static extern bool EnableMenuItem(IntPtr menu, uint item, uint flags);
    [DllImport("user32.dll")] private static extern int TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr owner, IntPtr rect);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out Native.Point point);
    [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(Native.Point point);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc call, IntPtr data);
    [DllImport("user32.dll")] private static extern bool RegisterHotKey(IntPtr hwnd, int id, uint modifiers, uint key);
    [DllImport("user32.dll")] private static extern bool UnregisterHotKey(IntPtr hwnd, int id);
    [DllImport("user32.dll")] private static extern UIntPtr SetTimer(IntPtr hwnd, UIntPtr id, uint interval, IntPtr proc);
    [DllImport("user32.dll")] private static extern bool KillTimer(IntPtr hwnd, UIntPtr id);
    [DllImport("comdlg32.dll", CharSet = CharSet.Unicode)] private static extern bool GetOpenFileNameW(ref OpenFileName picker);
    [DllImport("comdlg32.dll")] private static extern uint CommDlgExtendedError();
}
