using System.Diagnostics;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int DecisionServicesId = 495, DecisionListId = 496, DecisionUpId = 497, DecisionDownId = 498,
        DecisionPerplexityId = 499, DecisionJevId = 500, DecisionSaveId = 501, DecisionReloadId = 502,
        DecisionPrivacyId = 503, DecisionPerplexityPrivacyId = 504, DecisionJevPrivacyId = 505, DecisionInfoId = 506,
        DecisionEditId = 940, DecisionAddId = 941, DecisionRemoveId = 942, DecisionSelectedEnableId = 943, DecisionCustomPrivacyId = 944,
        DecisionHostNoticeId = 945;
    private static DecisionProviderSnapshot? decisionSnapshot;
    private static DecisionProviderPreferences? decisionDraft;
    private static string? decisionPath;
    private static int decisionSelection;
    private static bool decisionSelectionInitialized;
    private static bool closeAfterDecisionSave;
    private static bool DecisionDirty => decisionDraft is not null && decisionSnapshot?.Value is { } baseline && !decisionDraft.Same(baseline);

    private static readonly string DecisionPrivacyText = UiText.Get("发送给决策 API 的内容\r\n")
        + UiText.Get("当前的简短目标、候选控件文字和待选操作。不会发送截图、完整 DOM、UIA 树、源码、文件内容或凭据。\r\n\r\n")
        + UiText.Get("本地脱敏\r\n")
        + UiText.Get("程序一次处理已识别的密钥、个人信息和自定义敏感词，不调用主模型来脱敏。普通任务词句保留；同一请求内，相同对象使用相同临时代号，不同对象保持可区分。\r\n")
        + UiText.Get("脱敏不保证完整匿名；未识别的标题等文字仍可能包含个人信息。\r\n\r\n")
        + UiText.Get("服务方处理\r\n")
        + UiText.Get("Perplexity 默认不把 API 内容用于生成式 AI 训练；零数据保留（ZDR）并非默认。Jev 不用于训练，保留范围取决于协议，可能保留反滥用元数据。具体条款以本页的官方隐私链接为准。\r\n\r\n")
        + UiText.Get("自定义服务的数据接收方由你填写的请求地址决定；请先核对该服务的隐私政策。没有填写隐私网址不表示不留存。\r\n\r\n")
        + UiText.Get("回退与保存\r\n")
        + UiText.Get("按列表从上到下尝试已启用的 API；服务故障、限流或超时才继续下一项。停止、撤权或观察失效不会切换服务继续操作。主模型表示交回当前聊天，不会另发一次远程模型请求；它后面的 API 不会自动调用。\r\n")
        + UiText.Get("本页的“保存服务设置，立即生效”只保存服务启停与顺序。操作偏好的决策 API 总开关仍随主权限草稿保存。密钥只存于 Windows 凭据管理器，本页不会读取或显示密钥。");

    private static void ResetDecisionSettings()
    { decisionSnapshot = null; decisionDraft = null; decisionPath = null; decisionSelection = 0; decisionSelectionInitialized = false; closeAfterDecisionSave = false; }
    private static void EnsureDecisionSettings()
    {
        if (decisionSnapshot is not null) return;
        try
        {
            if (preview) decisionSnapshot = new(DecisionProviderSettings.Legacy(true), Legacy: true);
            else { decisionPath = DecisionProviderSettings.LivePath(); decisionSnapshot = DecisionProviderSettings.Read(decisionPath); }
        }
        catch (Exception error) { decisionSnapshot = new(null, Error: Program.Code(error)); }
        decisionDraft = decisionSnapshot.Value?.Copy();
        if (!decisionSelectionInitialized && decisionDraft is { } initial)
        {
            int remote = Array.FindIndex(initial.Order, value => value != "host" && initial.Enabled.Contains(value));
            int host = Array.IndexOf(initial.Order, "host");
            decisionSelection = remote >= 0 ? remote : Math.Max(0, host);
            decisionSelectionInitialized = true;
        }
    }
    private static string DecisionServiceLabel(string provider) => provider switch
    { "perplexity" => "Perplexity Decisions", "jev" => "Jev", "host" => UiText.Get("当前聊天主模型"),
        _ => decisionDraft?.Providers.FirstOrDefault(p => p.Id == provider)?.Name ?? UiText.Get("自定义服务") };
    private static string DecisionStatusText()
    {
        if (decisionSnapshot?.Error is not null) return UiText.Get("服务配置无法读取或不受支持；API 关闭。\r\n不会用默认值覆盖。修正原文件后重新读取。");
        string state = DecisionDirty ? UiText.Get("服务草稿待保存。") : decisionSnapshot?.Legacy == true ? UiText.Get("沿用旧服务设置。") : UiText.Get("服务设置已保存。");
        string master = saved.JevEnabled ? UiText.Get("API 总开关已开启。") : UiText.Get("API 总开关未开启。");
        return state + master + UiText.Get("当前聊天主模型始终可用，不是远程服务，也不需要密钥。\r\n列表顺序决定远程后备；主模型之后的 API 不会自动调用。");
    }
    private static void BuildGeneralDecisionPage()
    {
        EnsureDecisionSettings();
        if (decisionSnapshot?.Error is { } error) notice = UiText.Get("服务设置未加载：") + error + UiText.Get("；API 关闭，原文件保留。");
        Label(DecisionStatusText(), 650, 270, 790, 68, fontSize: 16, id: DecisionInfoId);
        Label(UiText.Get("服务顺序 · 可直接看到前四项；更多服务在列表内滚动。"), 650, 342, 520, 26, fontSize: 14);
        var list = Field(DecisionListId, "LISTBOX", "", 650, 370, 520, 188, 0x100 | 0x10 | 0x40 | 1);
        if (decisionDraft is { } value)
        {
            int hostIndex = Array.IndexOf(value.Order, "host");
            for (int i = 0; i < value.Order.Length; i++)
            {
                string provider = value.Order[i];
                string status = provider == "host" ? UiText.Get("交回当前聊天") : !value.Enabled.Contains(provider) ? UiText.Get("停用") : i > hostIndex ? UiText.Get("主模型之后，不自动调用") : UiText.Get("启用");
                SendMessageText(list, 0x180, IntPtr.Zero, (i + 1) + ". " + DecisionServiceLabel(provider) + " · " + status);
            }
            decisionSelection = Math.Clamp(decisionSelection, 0, value.Order.Length - 1); SendMessageW(list, 0x186, new IntPtr(decisionSelection), IntPtr.Zero);
        }
        PageButton(DecisionUpId, UiText.Get("↑ 上移"), 1190, 370, 250, 42); PageButton(DecisionDownId, UiText.Get("↓ 下移"), 1190, 420, 250, 42);
        string selected = decisionDraft?.Order.ElementAtOrDefault(decisionSelection) ?? "host";
        if (selected == "host")
            Label(UiText.Get("当前聊天主模型：可用 · 交回当前聊天处理，不占用服务开关。"), 650, 566, 520, 38, fontSize: 16,
                ink: 0xB8DDB7, id: DecisionHostNoticeId);
        else
            CheckField(DecisionSelectedEnableId, UiText.Get("启用选中服务 · ") + DecisionServiceLabel(selected), decisionDraft?.Enabled.Contains(selected) == true, 566, 520);
        PageButton(DecisionEditId, UiText.Get("配置 / 密钥"), 1190, 470, 250, 42);
        PageButton(DecisionAddId, UiText.Get("+ 添加服务"), 1190, 520, 250, 42);
        PageButton(DecisionRemoveId, UiText.Get("移除选中服务"), 1190, 570, 250, 38);
        PageButton(DecisionSaveId, UiText.Get("保存服务设置，立即生效"), 650, 620, 520, 44);
        PageButton(DecisionReloadId, UiText.Get("重新读取"), 1190, 620, 250, 44);
        Label(UiText.Get("此处只保存顺序与启停；API 总开关随“操作偏好”保存，主模型不是 API 服务。"), 650, 670, 790, 30, fontSize: 14);
        Label(UiText.Get("外发提示：目标与候选文字会发给启用的服务；本机脱敏仍可能遗漏个人信息。"), 650, 707, 790, 38,
            fontSize: 16, ink: 0xA9DCEE);
        PageButton(DecisionPrivacyId, UiText.Get("查看发送内容与隐私"), 650, 758, 250, 42);
        var custom = decisionDraft?.Providers.FirstOrDefault(p => p.Id == selected);
        if (custom is null)
        {
            PageButton(DecisionPerplexityPrivacyId, UiText.Get("Perplexity 隐私政策 ↗"), 920, 758, 250, 42);
            PageButton(DecisionJevPrivacyId, UiText.Get("Jev 隐私政策 ↗"), 1190, 758, 250, 42);
        }
        else
        {
            PageButton(DecisionCustomPrivacyId, custom.PrivacyUrl == "" ? UiText.Get("尚未填写此服务的隐私政策") : UiText.Get("打开选中服务的隐私政策 ↗"), 920, 758, 520, 42);
            EnableWindow(PageHandle(DecisionCustomPrivacyId), custom.PrivacyUrl != "");
        }
        UpdateDecisionButtons();
    }

    private static void SizeDecisionRows()
    {
        var list = PageHandle(DecisionListId);
        if (list == IntPtr.Zero) return;
        GetClientRect(list, out var bounds);
        SendMessageW(list, 0x1A0, IntPtr.Zero, new IntPtr(Math.Max(1, bounds.Bottom / 4)));
    }

    private static void PaintDecisionItem(DrawItem item)
    {
        if (decisionDraft is null || item.Item >= decisionDraft.Order.Length) return;
        bool selected = (item.State & 1) != 0, disabled = (item.State & 4) != 0;
        bool contrast = HighContrast();
        if (contrast) Fill(item.Dc, item.Rect, GetSysColor(selected ? 13 : 5));
        else
        {
            PaintControlBackdrop(item);
            SoftSurface(item.Dc, item.Rect, selected ? 0x71535Fu : 0x3C2B38u, (byte)(selected ? 190 : 155), 9);
            if (selected) Line(item.Dc, item.Rect.Left + Px(2), item.Rect.Top + Px(8),
                item.Rect.Left + Px(2), item.Rect.Bottom - Px(8), 0xB8DDB7, 3);
        }
        string provider = decisionDraft.Order[item.Item];
        int host = Array.IndexOf(decisionDraft.Order, "host");
        string status = provider == "host" ? UiText.Get("可用 · 交回聊天") : !decisionDraft.Enabled.Contains(provider) ? UiText.Get("停用")
            : item.Item > host ? UiText.Get("主模型之后 · 不自动调用") : UiText.Get("API 可用");
        var label = item.Rect; label.Left += Px(15); label.Right -= Px(12);
        uint ink = contrast ? GetSysColor(disabled ? 17 : selected ? 14 : 8) : disabled ? 0x89838Du : 0xE4F1FFu;
        string title = $"{item.Item + 1:00}  {DecisionServiceLabel(provider)}";
        int statusWidth = Math.Min(label.Right - label.Left - Px(70), Px(190));
        var titleRect = label; titleRect.Right = Math.Max(titleRect.Left + Px(70), label.Right - statusWidth);
        var statusRect = label; statusRect.Left = titleRect.Right;
        Text(item.Dc, title, titleRect, 18, ink, selected, nativeColor: contrast);
        uint statusInk = provider == "host" ? 0xB8DDB7u : disabled ? 0x89838Du : 0xC9BFD0u;
        Text(item.Dc, status, statusRect, 14, contrast ? ink : statusInk, false, nativeColor: contrast);
        if ((item.State & 0x10) != 0) { var focus = item.Rect; PaintKeyboardFocus(item.Dc, ref focus); }
    }

    private static bool IsDecisionButton(int id) => id is DecisionServicesId or DecisionUpId or DecisionDownId
        or DecisionSaveId or DecisionReloadId or DecisionPrivacyId or DecisionPerplexityPrivacyId or DecisionJevPrivacyId
        or DecisionEditId or DecisionAddId or DecisionRemoveId or DecisionCustomPrivacyId;

    private static void PaintDecisionButton(DrawItem item)
    {
        bool disabled = (item.State & 4) != 0, pressed = (item.State & 1) != 0;
        bool tab = item.Id == DecisionServicesId;
        bool primary = item.Id == DecisionSaveId;
        bool active = tab && generalSection == 2;
        bool external = item.Id is DecisionPerplexityPrivacyId or DecisionJevPrivacyId or DecisionCustomPrivacyId;
        bool contrast = HighContrast();
        PaintControlBackdrop(item);
        uint ink = contrast ? GetSysColor(disabled ? 17 : 18) : disabled ? 0x89838Du : external ? 0xF2D7E8u : active ? 0xF2F0F7u : 0xE4F1FFu;
        if (contrast) { Fill(item.Dc, item.Rect, GetSysColor(15)); Frame(item.Dc, item.Rect, ink); }
        else
        {
            SoftSurface(item.Dc, item.Rect, primary ? 0x71535Fu : active ? 0x5A4267u : 0x3D2936u,
                (byte)(disabled ? 42 : pressed ? 250 : primary ? 210 : active ? 190 : 165), 10);
            var line = item.Rect; line.Left += Px(10); line.Right -= Px(10);
            Line(item.Dc, line.Left, line.Bottom - Px(2), line.Right, line.Bottom - Px(2), disabled ? 0x65535Du : active ? 0xE3BCD8u : 0xB49BB2u);
        }
        var bounds = item.Rect; bounds.Left += Px(8); bounds.Right -= Px(8);
        Text(item.Dc, Text(item.Window), bounds, tab ? 16 : external ? 16 : 18, ink, primary || active, centered: true, nativeColor: contrast);
        if ((item.State & 0x10) != 0) { var focus = item.Rect; focus.Left += 2; focus.Top += 2; focus.Right -= 2; focus.Bottom -= 2; PaintKeyboardFocus(item.Dc, ref focus); }
    }
    private static void UpdateDecisionButtons()
    {
        if (PageHandle(DecisionInfoId) != IntPtr.Zero) SetWindowTextW(PageHandle(DecisionInfoId), DecisionStatusText());
        bool editable = !Busy && decisionDraft is not null && decisionSnapshot?.Error is null;
        foreach (int id in new[] { DecisionListId, DecisionPerplexityId, DecisionJevId, DecisionSaveId, DecisionAddId })
            if (PageHandle(id) != IntPtr.Zero) EnableWindow(PageHandle(id), editable);
        if (PageHandle(DecisionUpId) != IntPtr.Zero) EnableWindow(PageHandle(DecisionUpId), editable && decisionSelection > 0);
        if (PageHandle(DecisionDownId) != IntPtr.Zero) EnableWindow(PageHandle(DecisionDownId), editable && decisionSelection < decisionDraft!.Order.Length - 1);
        string provider = decisionDraft?.Order.ElementAtOrDefault(decisionSelection) ?? "host";
        foreach (int id in new[] { DecisionSelectedEnableId, DecisionEditId, DecisionRemoveId })
            if (PageHandle(id) != IntPtr.Zero) EnableWindow(PageHandle(id), editable && provider != "host" && (id != DecisionRemoveId || provider.StartsWith("custom_")));
        if (PageHandle(DecisionReloadId) != IntPtr.Zero) EnableWindow(PageHandle(DecisionReloadId), !Busy);
    }
    private static bool DecisionServicesCommand(int id, int notification)
    {
        if (id == DecisionServicesId)
        { if (notification == 0 && page == 3) { generalSection = 2; BuildPage(); UpdateChrome(); } return true; }
        if (!(id is >= DecisionListId and <= DecisionInfoId or >= DecisionEditId and <= DecisionCustomPrivacyId)) return false;
        if (page != 3 || generalSection != 2) return true;
        if (id == DecisionListId && notification == 1)
        { decisionSelection = Math.Clamp(Selection(DecisionListId), 0, (decisionDraft?.Order.Length ?? 1) - 1); BuildPage(); UpdateChrome(); return true; }
        if (notification != 0) return true;
        if (id == DecisionPrivacyId) { MessageBoxW(window, DecisionPrivacyText, UiText.Get("决策服务的发送内容与隐私"), 0x40); return true; }
        if (id is DecisionPerplexityPrivacyId or DecisionJevPrivacyId or DecisionCustomPrivacyId) { OpenDecisionPrivacy(id); return true; }
        if (Busy) return true;
        if (id == DecisionReloadId)
        {
            if (DecisionDirty && MessageBoxW(window, UiText.Get("重新读取会放弃尚未保存的服务启停与顺序。主权限草稿保留。"), UiText.Get("重新读取服务设置"), 4 | 0x30 | 0x100) != 6) return true;
            ResetDecisionSettings(); BuildPage(); notice = UiText.Get("服务设置已重新读取；主权限草稿保留。"); UpdateChrome(); return true;
        }
        if (decisionDraft is null || decisionSnapshot?.Error is not null) return true;
        if (id is DecisionEditId or DecisionAddId) { EditDecisionProvider(id == DecisionAddId); return true; }
        if (id == DecisionRemoveId)
        {
            string selected = decisionDraft.Order[decisionSelection];
            if (selected.StartsWith("custom_"))
            {
                decisionDraft = decisionDraft with { Custom = decisionDraft.Providers.Where(p => p.Id != selected).ToArray(),
                    Order = decisionDraft.Order.Where(p => p != selected).ToArray(), Enabled = decisionDraft.Enabled.Where(p => p != selected).ToArray() };
                decisionSelection = Math.Min(decisionSelection, decisionDraft.Order.Length - 1);
            }
        }
        else if (id == DecisionSelectedEnableId)
            decisionDraft = decisionDraft.Enable(decisionDraft.Order[decisionSelection], SendMessageW(PageHandle(id), 0xF0, IntPtr.Zero, IntPtr.Zero).ToInt64() == 1);
        else if (id is DecisionUpId or DecisionDownId)
        {
            int delta = id == DecisionUpId ? -1 : 1, destination = decisionSelection + delta;
            if (destination >= 0 && destination < decisionDraft.Order.Length) { decisionDraft = decisionDraft.Move(decisionSelection, delta); decisionSelection = destination; }
        }
        else if (id is DecisionPerplexityId or DecisionJevId)
            decisionDraft = decisionDraft.Enable(id == DecisionPerplexityId ? "perplexity" : "jev", SendMessageW(PageHandle(id), 0xF0, IntPtr.Zero, IntPtr.Zero).ToInt64() == 1);
        else if (id == DecisionSaveId) { RequestDecisionServiceSave(); return true; }
        else return true;
        notice = UiText.Get("服务草稿已修改；点“保存服务设置，立即生效”后应用。");
        BuildPage(); UpdateChrome(); return true;
    }
    private static string? DecisionPrivacyUrl(int id) => id switch
    {
        DecisionPerplexityPrivacyId => "https://docs.perplexity.ai/docs/resources/privacy-security",
        DecisionJevPrivacyId => "https://help.typesafe.ai/articles/5974925716-how-is-submitted-data-used-or-retained",
        DecisionCustomPrivacyId => decisionDraft?.Providers.FirstOrDefault(p => p.Id == decisionDraft.Order.ElementAtOrDefault(decisionSelection))?.PrivacyUrl is { Length: > 0 } url ? url : null,
        _ => null
    };
    private static void OpenDecisionPrivacy(int id)
    {
        if (DecisionPrivacyUrl(id) is not { } url) return;
        if (preview) { notice = UiText.Get("预览不打开浏览器；正式入口打开服务隐私说明，自定义服务使用你填写的网址。"); UpdateChrome(); return; }
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); notice = UiText.Get("已请求打开服务方官方隐私说明。"); }
        catch { notice = UiText.Get("无法打开浏览器；请稍后再试。服务设置草稿保留。"); }
        UpdateChrome();
    }
    private static void RequestDecisionServiceSave(bool continueClose = false)
    {
        EnsureDecisionSettings();
        if (Busy || decisionDraft is null || decisionSnapshot?.Error is not null) return;
        closeAfterDecisionSave = continueClose; var submitted = decisionDraft.Copy(); var revision = decisionSnapshot!.Revision;
        if (preview) { CompleteDecisionServiceSave(new("decision_save", DecisionSettings: new(submitted.Copy(), "preview"), SubmittedDecisionSettings: submitted)); return; }
        var path = decisionPath!;
        StartWork(token => {
            try { return new("decision_save", DecisionSettings: DecisionProviderSettings.Save(path, revision, submitted, token), SubmittedDecisionSettings: submitted); }
            catch (Exception error) { return new("decision_save", Error: Program.Code(error)); }
        });
        notice = UiText.Get("正在单独保存服务设置；主权限草稿保留。"); BuildPage(); UpdateChrome();
    }
    private static void CompleteDecisionServiceSave(WorkReply reply)
    {
        if (reply.Error is not null)
        {
            closeAfterDecisionSave = false;
            notice = reply.Error == "decision_settings_conflict" ? UiText.Get("服务设置已被其他窗口修改；原草稿保留，请重新读取后核对。")
                : UiText.Get("服务设置未确认保存：") + UserFacingError(reply.Error) + UiText.Get("；草稿保留，不自动重试。");
        }
        else
        {
            decisionSnapshot = reply.DecisionSettings!;
            if (decisionDraft?.Same(reply.SubmittedDecisionSettings!) == true) decisionDraft = decisionSnapshot.Value!.Copy();
            notice = preview ? UiText.Get("服务设置已存入预览内存；真实服务与权限未写入。")
                : UiText.Get("服务设置已保存，对新决策立即生效；主权限草稿保留。");
        }
        bool close = closeAfterDecisionSave && !DecisionDirty; closeAfterDecisionSave = false;
        if (close) { RequestSave(true); return; }
        if (page == 3 && generalSection == 2) BuildPage(); UpdateChrome();
    }
}
