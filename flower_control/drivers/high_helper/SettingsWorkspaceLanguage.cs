namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int DisplayLanguageId = 930;
    private static DisplayPreferenceSnapshot displayPreference = new();

    private static void InitializeDisplayPreference()
    {
        displayPreference = preview ? new(UiText.Language) : DisplayPreferences.Read();
        UiText.SetLanguage(displayPreference.Language);
        RefreshWorkspaceLanguageLabels();
    }
    private static void BuildDisplayPreferenceControls()
    {
        Label(UiText.Get("界面语言"), 650, 777, 300, 32, fontSize: 17);
        // Language names remain their own autonyms in either interface.
        Combo(DisplayLanguageId, ["简体中文", "English"], displayPreference.Language == "en" ? 1 : 0, 1000, 770, 440);
        if (displayPreference.Error is not null && notice.Length == 0)
            notice = UiText.Get("界面语言偏好无法读取；当前使用简体中文，原文件未被覆盖。");
    }
    private static bool DisplayLanguageCommand(int id, int notification)
    {
        if (id != DisplayLanguageId) return false;
        if (notification != 1 || page != 3 || generalSection != 0 || Busy || BrowserOpening || displayPreference.Error is not null) return true;
        int selection = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32();
        if (selection is 0 or 1) RequestDisplayLanguage(selection == 1 ? "en" : "zh-CN");
        return true;
    }
    private static void RequestDisplayLanguage(string language)
    {
        if (!DisplayPreferences.ValidLanguage(language) || Busy || BrowserOpening) return;
        if (invalidEdit)
        {
            var control = PageHandle(DisplayLanguageId);
            if (control != IntPtr.Zero)
                SendMessageW(control, 0x14E, new IntPtr(displayPreference.Language == "en" ? 1 : 0), IntPtr.Zero);
            notice = UiText.Get("当前字段无效，请先修正或重新载入；原输入保留。");
            UpdateChrome(); return;
        }
        if (language == displayPreference.Language) return;
        if (preview)
        {
            ApplyDisplayPreference(displayPreference with { Language = language });
            notice = UiText.Get("预览语言已切换；没有写入真实偏好，其他草稿保留。");
            UpdateChrome(); return;
        }
        string? revision = displayPreference.Revision;
        StartWork(token => {
            try
            {
                var result = BrowserProfileOpen.SaveDisplayPreferenceAsync(language, revision, token).GetAwaiter().GetResult();
                return new("display_preferences", Error: result.State == "saved" ? null : result.Reason ?? result.State);
            }
            catch (Exception error) { return new("display_preferences", Error: Program.Code(error)); }
        });
        notice = UiText.Get("正在保存界面语言；权限、服务和其他草稿保留。"); UpdateChrome();
    }
    private static void CompleteDisplayPreferenceSave(WorkReply reply)
    {
        ApplyDisplayPreference(DisplayPreferences.Read());
        notice = reply.Error is null && displayPreference.Error is null
            ? UiText.Get("界面语言已保存并应用；权限、服务和其他草稿保留。")
            : UiText.Get("界面语言未确认保存：") + UserFacingError(reply.Error ?? displayPreference.Error!)
                + UiText.Get("；已重读实际偏好，其他草稿保留，不自动重试。");
        UpdateChrome();
    }
    internal static void RefreshDisplayPreference()
    {
        if (preview || !DisplayPreferences.HasProductionRoot) return;
        RefreshDisplayPreferenceFrom(() => DisplayPreferences.Read());
    }
    private static void RefreshDisplayPreferenceFrom(Func<DisplayPreferenceSnapshot> read)
    {
        // Invalid text can live only in its edit control until validation
        // succeeds. Keep that control and its selection intact; the next tick
        // reads the actual preference after the user repairs the field.
        if (window != IntPtr.Zero && (Busy || invalidEdit)) return;
        var current = read();
        if (window == IntPtr.Zero) { UiText.SetLanguage(current.Language); return; }
        ApplyDisplayPreference(current);
    }
    private static void ApplyDisplayPreference(DisplayPreferenceSnapshot current)
    {
        bool changed = UiText.Language != current.Language;
        displayPreference = current;
        UiText.SetLanguage(current.Language);
        if (!changed) { UpdateDisplayPreferenceControl(); return; }
        RefreshWorkspaceLanguageLabels();
        if (window == IntPtr.Zero) return;
        chromeLayoutDirty = true;
        ReleaseScene(); ReleaseBackdrop(); ReleaseInteractiveControls();
        BuildPage(); UpdateChrome();
        InvalidateRect(window, IntPtr.Zero, true);
    }
    private static void RefreshWorkspaceLanguageLabels()
    {
        string[] navigation = [UiText.Get("总览"), UiText.Get("权限"), UiText.Get("隐私"), UiText.Get("常规"), UiText.Get("诊断")];
        string[] tiers = [UiText.Get("普通控制"), UiText.Get("管理员窗口"), UiText.Get("管理员执行"), UiText.Get("系统接管")];
        Array.Copy(navigation, NavNames, NavNames.Length); Array.Copy(tiers, TierNames, TierNames.Length);
        if (window == IntPtr.Zero) return;
        for (int i = 0; i < navigation.Length; i++) SetChromeText(GetDlgItem(window, NavBase + i), navigation[i]);
        for (int i = 0; i < 4; i++) SetChromeText(GetDlgItem(window, TierBase + i), AuthorityPresentation.Label(AuthorityPresentation.ButtonTier(i)));
        SetChromeText(GetDlgItem(window, StopId), UiText.Get("■ 结束电脑操作"));
        SetChromeText(GetDlgItem(window, ReloadId), UiText.Get("重新载入"));
        SetChromeText(GetDlgItem(window, NoticeDetailsId), UiText.Get("详情"));
        SetChromeText(GetDlgItem(window, HelpId), UiText.Get("使用说明"));
    }
    private static void UpdateDisplayPreferenceControl()
    {
        var language = PageHandle(DisplayLanguageId);
        if (language != IntPtr.Zero) EnableChromeControl(language, !Busy && !BrowserOpening && displayPreference.Error is null);
    }
}
