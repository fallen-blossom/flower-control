using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Concurrent;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int ProgramListId = 420, LayerId = 410, RuleKindId = 411, ModeId = 412,
        ToggleId = 421, RemoveId = 422, DetailId = 423, RulesId = 430, PrivacyTabId = 440,
        WordsId = 441, MaskListId = 450, MaskToggleId = 451, MaskRemoveId = 452,
        JevId = 470, SmoothId = 471, CompactId = 472, PositionId = 473;
    private sealed record PageControl(int Id, IntPtr Handle, int X, int Y, int W, int H, string Kind,
        bool Emphasis = false, int FontSize = 0, uint? Ink = null);
    private static readonly List<PageControl> pageControls = [];
    private static readonly Dictionary<string, IntPtr> programIcons = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, string> programHealth = new();
    private const uint HealthFinished = 0x8000 + 188;
    private static readonly int[] listSelection = new int[8], listTop = new int[8];
    private static int ruleLayer = 2, privacyTab, renderedListKey, selectedMask;
    private static bool denied, loadingControls, invalidEdit;
    private static IntPtr pageBrush, pageFont;
    private static int pageFocusToRestore;
    private static int RowCount => page == 2 ? draft.Masks.Length : ruleLayer < 2 ? model.WindowRules(ruleLayer).Length : model.Programs(ruleLayer, denied).Length;
    private static int ListKey => ruleLayer * 2 + (denied ? 1 : 0);

    private static IntPtr Field(int id, string kind, string value, int x, int y, int w, int h, uint style = 0)
    {
        var handle = CreateWindowExW(0, kind, value,
            0x40000000 | (kind is "EDIT" or "COMBOBOX" or "LISTBOX" or "BUTTON" ? 0x10000u : 0) | style,
            0, 0, 1, 1, window, new IntPtr(id), instance, IntPtr.Zero);
        if (handle == IntPtr.Zero) throw new Boundary("settings_control_unavailable");
        pageControls.Add(new(id, handle, x, y, w, h, kind));
        SetWindowTheme(handle, HighContrast() ? "" : "DarkMode_CFD", "");
        if (kind == "COMBOBOX" || kind == "BUTTON" && style == 3 || id == ModeChoiceBase || id == MaskListId)
            SetWindowSubclass(handle, ThemeProcedure, new UIntPtr(1), UIntPtr.Zero);
        if (kind == "EDIT" || kind == "LISTBOX")
            SetWindowSubclass(handle, ScrollThemeProcedure, new UIntPtr(2), UIntPtr.Zero);
        SendMessageW(handle, 0x30, pageFont, new IntPtr(1));
        if (kind == "EDIT") SendMessageW(handle, 0xC5, new IntPtr(32768), IntPtr.Zero);
        return handle;
    }
    private static IntPtr PageHandle(int id) => pageControls.FirstOrDefault(x => x.Id == id)?.Handle ?? IntPtr.Zero;
    private static void Label(string text, int x, int y, int w = 780, int h = 40, bool emphasis = false,
        int fontSize = 0, uint? ink = null, int id = 0)
    {
        Field(id, "STATIC", text, x, y, w, h, 0xD);
        pageControls[^1] = pageControls[^1] with { Emphasis = emphasis, FontSize = fontSize, Ink = ink };
    }
    private static void PageButton(int id, string text, int x, int y, int w, int h = 38)
        => Field(id, "BUTTON", text, x, y, w, h, 0xB);
    private static void Combo(int id, string[] choices, int selected, int x, int y, int w)
    {
        var handle = Field(id, "COMBOBOX", "", x, y, w, 260, 3 | 0x10 | 0x200 | 0x200000);
        foreach (string choice in choices) SendMessageText(handle, 0x143, IntPtr.Zero, choice);
        SendMessageW(handle, 0x14E, new IntPtr(selected), IntPtr.Zero);
        SizeComboItems(handle);
    }
    private static void CheckField(int id, string text, bool check, int y, int width = 790)
    {
        var handle = Field(id, "BUTTON", text, 650, y, width, 40, 3);
        SendMessageW(handle, 0xF1, new IntPtr(check ? 1 : 0), IntPtr.Zero);
    }
    private static void BuildPage()
    {
        if (DeferPageRebuild()) return;
        SuspendSurfaceRedraw();
        pageLayoutDirty = true;
        pageFocusToRestore = pageControls.FirstOrDefault(x => x.Handle == GetFocus())?.Id ?? 0;
        loadingControls = true;
        try
        {
            if (PageHandle(ProgramListId) != IntPtr.Zero)
            {
                listSelection[renderedListKey] = Math.Max(0, SendMessageW(PageHandle(ProgramListId), 0x188, IntPtr.Zero, IntPtr.Zero).ToInt32());
                listTop[renderedListKey] = Math.Max(0, SendMessageW(PageHandle(ProgramListId), 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32());
            }
            foreach (var control in pageControls) DestroyWindow(control.Handle);
            pageControls.Clear();
            RefreshPageFont();
            if (pageBrush == IntPtr.Zero) pageBrush = CreateSolidBrush(0x2B2320);
            switch (page)
            {
                case 0:
                    BuildOverviewPage();
                    break;
                case 1: BuildPermissionPage(); break;
                case 2: BuildPrivacyPage(); break;
                case 3:
                    PageButton(GeneralPreferencesId, UiText.Get("操作偏好"), 0, 0, 135, 42);
                    PageButton(GeneralWebId, UiText.Get("Web 登录态"), 0, 0, 135, 42);
                    PageButton(DecisionServicesId, UiText.Get("决策服务"), 0, 0, 135, 42);
                    if (generalSection == 1) { BuildGeneralBrowserPage(); break; }
                    if (generalSection == 2) { BuildGeneralDecisionPage(); break; }
                    CheckField(JevId, UiText.Get("启用决策 API（服务总开关）"), draft.JevEnabled, 275);
                    Label(UiText.Get("此总开关随主权限草稿保存；服务启停与顺序在下方单独设置。"), 650, 320, 790, 48);
                    Label(UiText.Get("服务顺序、启停、密钥和隐私入口在顶部“决策服务”中单独管理。"), 650, 382, 790, 36, fontSize: 16);
                    Label(UiText.Get("Computer Use · 前台状态提示"), 650, 438, 790, 38, fontSize: 21, emphasis: true);
                    CheckField(CompactId, UiText.Get("紧凑显示任务、阶段和停止入口"), draft.HudCompact, 486);
                    Label(UiText.Get("屏幕提示位置"), 650, 548, 300, 32, emphasis: true);
                    Combo(PositionId, [UiText.Get("自动避让目标"), UiText.Get("屏幕左上角"), UiText.Get("屏幕右上角"), UiText.Get("屏幕左下角"), UiText.Get("屏幕右下角")], Array.IndexOf(new[] { "auto", "top_left", "top_right", "bottom_left", "bottom_right" }, draft.HudPosition), 1000, 540, 440);
                    Label(UiText.Get("显示任务、执行阶段和停止状态；不代表 AI 一直占用前台，也不会显示密钥或输入内容。"), 650, 606, 790, 52, fontSize: 16);
                    Label(UiText.Get("Computer Use 与需要真实键鼠的 App 操作使用此提示；纯 Web、文件和后台计算不显示。"), 650, 672, 790, 48, fontSize: 15);
                    Label(UiText.Get("动画跟随 Windows 设置；高对比模式保留系统控件和完整键盘焦点。"), 650, 738, 790, 36, fontSize: 15);
                    BuildDisplayPreferenceControls();
                    break;
                case 4:
                    BuildProductDiagnosticsPage();
                    break;
            }
        }
        finally { loadingControls = false; }
    }
    private static void RestorePageFocus()
    {
        var focused = PageHandle(pageFocusToRestore);
        pageFocusToRestore = 0;
        if (focused != IntPtr.Zero && IsWindowVisible(focused) && IsWindowEnabled(focused)) SetFocus(focused);
    }
    private static void BuildPermissionPage() => BuildPermissionSurface();
    private static void BuildPrivacyPage()
    {
        Combo(PrivacyTabId, [UiText.Get("敏感词"), UiText.Get("截图遮挡"), UiText.Get("普通禁止规则")], privacyTab, 650, 265, 790);
        if (privacyTab == 0)
        {
            Label(UiText.Get("一行一个词；在返回 AI / Jev 前屏蔽，不改你的输入或文件。"), 650, 325, 790, 48);
            Field(WordsId, "EDIT", wordDraft, 650, 385, 790, 210, 0x200000 | 4 | 0x40 | 0x1000);
            Label(UiText.Get("密码框和 Bitwarden 自动保护；剪贴板不额外防护。"), 650, 620);
            Label(words.Error is null ? UiText.Get("此页编辑受保护主词表；用户目录中的追加词表仍保留。") : UiText.Get("词表读取失败，不能覆盖空表：") + words.Error, 650, 660, 790, 55);
        }
        else if (privacyTab == 2)
        {
            Label(UiText.Get("与权限 01 共用一份草稿；不是第二套规则。"), 650, 325);
            Field(RulesId, "EDIT", RuleText(draft.DeniedApplications), 650, 380, 790, 220, 0x200000 | 4 | 0x40 | 0x1000);
            Label(UiText.Get("完整路径 | 标题条件；行首 # 表示停用。"), 650, 625);
        }
        else
        {
            var list = Field(MaskListId, "LISTBOX", "", 650, 330, 790, 140, 0x200000 | 0x100 | 0x10 | 0x40 | 1);
            SendMessageW(list, 0x1A0, IntPtr.Zero, new IntPtr(MaskRowHeight));
            foreach (var mask in draft.Masks) SendMessageText(list, 0x180, IntPtr.Zero, (mask.Enabled ? UiText.Get("遮挡  ") : UiText.Get("停用  ")) + Path.GetFileName(mask.Path) + "  " + string.Join(", ", mask.Rect));
            selectedMask = Math.Clamp(selectedMask, 0, Math.Max(0, draft.Masks.Length - 1));
            if (draft.Masks.Length > 0) SendMessageW(list, 0x186, new IntPtr(selectedMask), IntPtr.Zero);
            Label(UiText.Get("客户区物理像素：左 / 上 / 右 / 下"), 650, 490);
            for (int i = 0; i < 4; i++) Field(460 + i, "EDIT", draft.Masks.Length > 0 ? draft.Masks[selectedMask].Rect[i].ToString() : "0", 650 + i * 195, 535, 175, 36, 0x80);
            PageButton(MaskToggleId, UiText.Get("启用 / 停用"), 650, 605, 260);
            PageButton(MaskRemoveId, UiText.Get("移除遮挡"), 930, 605, 260);
            Label(UiText.Get("添加时选定真实窗口；窗口尺寸变化后需要重新选择。"), 650, 650, 790, 45);
            foreach (var c in pageControls.Where(x => x.Id is >= 460 and <= 463 or MaskToggleId or MaskRemoveId))
                EnableWindow(c.Handle, draft.Masks.Length > 0);
        }
    }
    private static void PositionPageControls()
    {
        foreach (var c in pageControls)
        {
            var r = PageBounds(c);
            int height = c.Id == ProgramListId ? Math.Min(ruleLayer == 3 ? 3 : 4, Math.Max(1, RowCount)) * ProgramRowHeight + 2 : r.Bottom - r.Top;
            // Win32 includes the popup list in a combo's requested height.
            // A short closed-field layout must not shrink its list to 2px.
            if (c.Kind == "COMBOBOX")
            {
                SizeComboItems(c.Handle);
                int rows = Math.Clamp(SendMessageW(c.Handle, 0x146, IntPtr.Zero, IntPtr.Zero).ToInt32(), 1, 12);
                int item = SendMessageW(c.Handle, 0x154, IntPtr.Zero, IntPtr.Zero).ToInt32();
                int closed = SendMessageW(c.Handle, 0x154, new IntPtr(-1), IntPtr.Zero).ToInt32();
                // FontPixels has a DPI readability floor; a compact Px(260)
                // alone can leave a five-option popup shorter than its rows.
                height = Math.Max(Math.Max(height, Px(c.H)), closed + rows * item + Math.Max(8, Px(12)));
            }
            if (c.Kind == "STATIC") height = Math.Max(height, PageLabelHeight(c, r.Right - r.Left));
            SetWindowPos(c.Handle, IntPtr.Zero, r.Left, r.Top, r.Right - r.Left, height, 0x14);
            if (c.Kind == "COMBOBOX") SizeComboItems(c.Handle);
        }
        if (PageHandle(ProgramListId) != IntPtr.Zero) SendMessageW(PageHandle(ProgramListId), 0x1A0, IntPtr.Zero, new IntPtr(ProgramRowHeight));
        if (PageHandle(MaskListId) != IntPtr.Zero) SendMessageW(PageHandle(MaskListId), 0x1A0, IntPtr.Zero, new IntPtr(MaskRowHeight));
        SizeDecisionRows();
    }
    private static string RuleText(IEnumerable<ApplicationPermission> rows) => string.Join("\r\n", rows.Select(x => (x.Enabled ? "" : "# ") + x.Path + (x.TitleContains.Length > 0 ? " | " + x.TitleContains : "")));
    private static string FieldText(int id) { var b = new StringBuilder(32769); GetWindowTextW(PageHandle(id), b, b.Capacity); return b.ToString(); }
    private static int Selection(int id) => SendMessageW(PageHandle(id), 0x188, IntPtr.Zero, IntPtr.Zero).ToInt32();
    private static bool PageCommand(int id, int notification)
    {
        if (ProductCommand(id, notification)) return true;
        if (MaintenanceCommand(id, notification)) return true;
        if (id is >= 480 and <= 485 or 513 or 550 or 551)
        { notice = AuthorityPresentation.FrozenNotice; UpdateChrome(); return true; }
        if (id == HelpId) { ShowWorkspaceHelp(); return true; }
        if (id == RuleHelpId) { ShowRuleHelp(); return true; }
        var comboControl = pageControls.FirstOrDefault(c => c.Id == id && c.Kind == "COMBOBOX");
        if (comboControl is not null)
        {
            if (notification == 10) { InvalidateRect(comboControl.Handle, IntPtr.Zero, false); return true; }
            bool accepted = notification == 9;
            if (notification == 1 && SendMessageW(comboControl.Handle, 0x157, IntPtr.Zero, IntPtr.Zero) != IntPtr.Zero) return true;
            if (accepted) notification = 1;
        }
        if (PermissionChoiceCommand(id)) return true;
        if (DisplayLanguageCommand(id, notification)) return true;
        if (id == SemanticEnableId && notification == 0) { RequestSemanticDelegation(); return true; }
        if (GeneralBrowserCommand(id, notification)) return true;
        if (DecisionServicesCommand(id, notification)) return true;
        if (id == ProgramMenuId) { ShowProgramActionMenu(); return true; }
        if (id == ProgramListId && notification == 1) { PositionProgramMenu(); return true; }
        if (invalidEdit && id == MaskListId && notification == 1) { SendMessageW(PageHandle(id), 0x186, new IntPtr(selectedMask), IntPtr.Zero); notice = UiText.Get("请先修正当前遮挡坐标；输入保留。"); return true; }
        if (invalidEdit && id is MaskToggleId or MaskRemoveId) { notice = UiText.Get("请先修正当前坐标，或重新载入后再移除；输入保留。"); UpdateChrome(); return true; }
        if (invalidEdit && notification == 1 && id is LayerId or RuleKindId or PrivacyTabId or ModeId or 414)
        {
            notice = UiText.Get("当前字段无效，请先修正或重新载入；原输入保留。");
            int selected = id == LayerId ? ruleLayer : id == RuleKindId ? denied ? 1 : 0 : id == PrivacyTabId ? privacyTab : id == 414 ? draft.UacCancellationScope == "task" ? 0 : 1 : (ruleLayer == 2 ? draft.AdminLaunchMode : preferredMode) == "semantic" ? 1 : 0;
            SendMessageW(PageHandle(id), 0x14E, new IntPtr(selected), IntPtr.Zero); UpdateChrome(); return true;
        }
        if (id == LayerId && notification == 1) { int chosen = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32(); if (chosen != ruleLayer) BuildPageAfter(() => ruleLayer = chosen); return true; }
        if (id == RuleKindId && notification == 1) { bool chosen = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32() == 1; if (chosen != denied) BuildPageAfter(() => denied = chosen); return true; }
        if (id == PrivacyTabId && notification == 1) { int chosen = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32(); if (chosen != privacyTab) { privacyTab = chosen; BuildPage(); UpdateChrome(); } return true; }
        if (id == ModeId && notification == 1)
        {
            string choice = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32() == 1 ? "semantic" : "allowlist";
            if (ruleLayer == 3 && choice == "semantic") { notice = UiText.Get("UAC 语义方式尚未就绪；原选择保持。"); SendMessageW(PageHandle(id), 0x14E, new IntPtr(preferredMode == "semantic" ? 1 : 0), IntPtr.Zero); }
            else if (ruleLayer == 2) model.Edit(x => x with { AdminLaunchMode = choice });
            else { preferredMode = choice; if (tier == 3) model.Edit(x => x with { UacMode = choice }); }
            UpdateChrome(); return true;
        }
        if (id == 414 && notification == 1) { string scope = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32() == 1 ? "selected_prompt_in_session" : "task"; model.Edit(x => x with { UacCancellationScope = scope }); UpdateChrome(); return true; }
        if (id == RulesId && notification == 0x300)
        {
            var rows = PermissionSettingsWindow.ParseLines(FieldText(id));
            try { var test = draft with { DeniedApplications = rows }; UserPermissions.Validate(test); model.WindowRules(page == 2 ? 0 : ruleLayer, rows); invalidEdit = false; notice = UiText.Get("禁止规则已修改草稿。"); }
            catch { invalidEdit = true; notice = UiText.Get("规则未生效：请填写完整本地路径，最多 128 条。"); }
            UpdateChrome(); return true;
        }
        if (id == WordsId && notification == 0x300) { wordDraft = FieldText(id); try { UserPermissions.ValidateSettingsWords(wordDraft); invalidEdit = false; } catch { invalidEdit = true; notice = UiText.Get("词表每词最多 200 字，最多 2000 词。"); } UpdateChrome(); return true; }
        if (id is JevId or CompactId)
        {
            bool value = SendMessageW(PageHandle(id), 0xF0, IntPtr.Zero, IntPtr.Zero).ToInt64() == 1;
            model.Edit(x => id == JevId ? x with { JevEnabled = value } : x with { HudCompact = value }); UpdateChrome(); return true;
        }
        if (id == PositionId && notification == 1) { var values = new[] { "auto", "top_left", "top_right", "bottom_left", "bottom_right" }; int index = SendMessageW(PageHandle(id), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32(); model.Edit(x => x with { HudPosition = values[Math.Clamp(index, 0, 4)] }); UpdateChrome(); return true; }
        if (id == ProgramListId && notification == 2 || id == DetailId) { ShowProgramDetails(); return true; }
        if (id is ToggleId or RemoveId) { EditProgram(id == RemoveId); return true; }
        if (id == MaskListId && notification == 1) { selectedMask = Math.Max(0, Selection(MaskListId)); LoadMaskFields(); return true; }
        if (id is >= 460 and <= 463 && notification == 0x300) { EditMaskCoordinates(); return true; }
        if (id is MaskToggleId or MaskRemoveId) { int index = Selection(MaskListId); if (index >= 0) { var rows = draft.Masks.ToList(); if (id == MaskRemoveId) rows.RemoveAt(index); else rows[index] = rows[index] with { Enabled = !rows[index].Enabled }; model.Edit(x => x with { Masks = rows.ToArray() }); BuildPage(); UpdateChrome(); } return true; }
        return false;
    }
    private static void BuildPageAfter(Action change)
    { if (PageHandle(ProgramListId) != IntPtr.Zero) { listSelection[ListKey] = Math.Max(0, Selection(ProgramListId)); listTop[ListKey] = Math.Max(0, SendMessageW(PageHandle(ProgramListId), 0x18E, IntPtr.Zero, IntPtr.Zero).ToInt32()); } change(); BuildPage(); UpdateChrome(); }
    private static void EditProgram(bool remove)
    {
        int index = Selection(ProgramListId); var rows = model.Programs(ruleLayer, denied).ToList(); if (index < 0 || index >= rows.Count) return;
        if (remove) rows.RemoveAt(index);
        else
        {
            var row = rows[index];
            if (!row.Enabled && !denied && !preview)
            {
                if (row.Arguments != "") throw new Boundary("uac_allowlist_arguments_approval_required");
                var fresh = UacIdentity.InspectForAllowlist(row.Path);
                if (fresh.IdentityKind != row.IdentityKind || fresh.Identity != row.Identity) throw new Boundary("uac_program_changed");
            }
            if (!row.Enabled && model.ProgramOnOppositeSide(ruleLayer, denied, row.Path))
            {
                var context = SelectionContext();
                if (MessageBoxW(window, UiText.Get("该程序已在另一侧。确认后将从另一侧移除该路径的所有规则，并启用当前规则；两侧都需保存才生效。"),
                    UiText.Get("确认移动程序"), 4 | 0x20 | 0x100) != 6) return;
                RequireSelectionContext(context);
                var current = model.Programs(context.Layer, context.Denied);
                if (index >= current.Length || current[index] != row) throw new Boundary("uac_window_pick_expired");
                model.Programs(context.Layer, !context.Denied, model.Programs(context.Layer, !context.Denied)
                    .Where(old => !old.Path.Equals(row.Path, StringComparison.OrdinalIgnoreCase)).ToArray());
            }
            rows[index] = row with { Enabled = !row.Enabled };
        }
        model.Programs(ruleLayer, denied, rows.ToArray()); BuildPage(); notice = UiText.Get("名单草稿已更新；不会删除文件或终止程序。"); UpdateChrome();
    }
    private static void ShowProgramDetails()
    {
        int index = Selection(ProgramListId); var rows = model.Programs(ruleLayer, denied); if (index < 0 || index >= rows.Length) return;
        var row = rows[index];
        MessageBoxW(window, row.DisplayName + "\r\n" + row.Path + "\r\n" + row.IdentityKind + "  " + row.Identity + UiText.Get("\r\n参数范围：") + (row.Arguments is null ? UiText.Get("旧记录未明确，不新启用") : row.Arguments.Length == 0 ? UiText.Get("不带参数") : row.Arguments) + UiText.Get("\r\n\r\nCtrl+C 可复制此对话框内容。"), UiText.Get("程序详情"), 0x40);
    }
    private static void LoadMaskFields()
    { int index = Selection(MaskListId); if (index < 0 || index >= draft.Masks.Length) return; loadingControls = true; try { for (int i = 0; i < 4; i++) SetWindowTextW(PageHandle(460 + i), draft.Masks[index].Rect[i].ToString()); } finally { loadingControls = false; } }
    private static void EditMaskCoordinates()
    {
        int index = Selection(MaskListId); if (index < 0 || index >= draft.Masks.Length) return;
        var rect = new int[4]; for (int i = 0; i < 4; i++) if (!int.TryParse(FieldText(460 + i), out rect[i])) { invalidEdit = true; UpdateChrome(); return; }
        var rows = draft.Masks.ToArray(); rows[index] = rows[index] with { Rect = rect };
        try { UserPermissions.Validate(draft with { Masks = rows }); model.Edit(x => x with { Masks = rows }); invalidEdit = false; notice = UiText.Get("遮挡坐标已修改草稿。"); }
        catch { invalidEdit = true; notice = UiText.Get("遮挡需在原客户区内，右/下须大于左/上。"); }
        UpdateChrome();
    }
    private static void PaintProgramItem(DrawItem item)
    {
        // Empty owner-drawn lists can send itemID=-1 for a focus change. Keep
        // the original range guard outside the buffer: no unpainted pixels.
        if (item.Item >= model.Programs(ruleLayer, denied).Length) return;
        GetClientRect(item.Window, out var client);
        if (client.Right <= 0 || client.Bottom <= 0) return;
        var memory = CreateCompatibleDC(item.Dc);
        var bitmap = memory == IntPtr.Zero ? IntPtr.Zero : CreateCompatibleBitmap(item.Dc, client.Right, client.Bottom);
        if (bitmap == IntPtr.Zero)
        {
            if (memory != IntPtr.Zero) DeleteDC(memory);
            PaintProgramItemContent(item); return;
        }
        var previous = SelectObject(memory, bitmap);
        try
        {
            var buffered = item; buffered.Dc = memory;
            PaintProgramItemContent(buffered);
            BitBlt(item.Dc, item.Rect.Left, item.Rect.Top, item.Rect.Right - item.Rect.Left,
                item.Rect.Bottom - item.Rect.Top, memory, item.Rect.Left, item.Rect.Top, 0x00CC0020);
        }
        finally { SelectObject(memory, previous); DeleteObject(bitmap); DeleteDC(memory); }
    }

    private static void PaintProgramItemContent(DrawItem item)
    {
        var rows = model.Programs(ruleLayer, denied); if (item.Item >= rows.Length) return; var row = rows[item.Item];
        PaintControlBackdrop(item);
        if ((item.State & 1) != 0 && HighContrast()) { var selected = item.Rect; FillRect(item.Dc, ref selected, GetSysColorBrush(13)); }
        else if ((item.State & 1) != 0 && PermissionPage) SoftSurface(item.Dc, item.Rect, 0x826956, 32, 13);
        else if ((item.State & 1) != 0) Line(item.Dc, item.Rect.Left, item.Rect.Top + Px(5), item.Rect.Left, item.Rect.Bottom - Px(5), 0xD2A6E7);
        if ((item.State & 1) != 0 && !PermissionPage) Text(item.Dc, "›", Inset(item.Rect, 1, 12, 14, 32), 24, 0xE8BCF7, false, centered: true);
        var icon = ProgramIcon(row.Path);
        int iconSize = CompactSurface ? Math.Max(Px(32), 26) : Px(52);
        if (icon != IntPtr.Zero) DrawIconEx(item.Dc, item.Rect.Left + Px(14), item.Rect.Top + (ProgramRowHeight - iconSize) / 2, icon, iconSize, iconSize, 0, IntPtr.Zero, 3);
        int left = item.Rect.Left + Math.Max(Px(CompactSurface ? 65 : 85), 42), line = Math.Max(Px(PermissionPage ? 27 : 34), FontPixels(PermissionPage ? 18 : 20) + 3);
        int actionWidth = PermissionPage ? Px(60) : 0, statusWidth = Math.Max(Px(110), 85);
        var title = new Rect { Left = left, Top = item.Rect.Top + Px(5), Right = item.Rect.Right - statusWidth - actionWidth, Bottom = item.Rect.Top + Px(5) + line };
        var detail = title; detail.Top += line; detail.Bottom += line;
        bool systemSelection = HighContrast() && (item.State & 1) != 0;
        Text(item.Dc, row.DisplayName, title, PermissionPage ? 20 : 24, systemSelection ? GetSysColor(14) : 0xEAF2F6u, true, nativeColor: systemSelection);
        Text(item.Dc, Path.GetFileName(row.Path), detail, PermissionPage ? 16 : 18, systemSelection ? GetSysColor(14) : PermissionPage ? 0xC0B3B4u : 0xD3BFD9u, false, nativeColor: systemSelection);
        string state = !row.Enabled ? UiText.Get("停用") : denied ? UiText.Get("禁止") : preview ? UiText.Get("允许") : programHealth.GetValueOrDefault(HealthKey(row), UiText.Get("未核对"));
        var stateBounds = new Rect { Left = item.Rect.Right - statusWidth - actionWidth, Top = item.Rect.Top, Right = item.Rect.Right - actionWidth, Bottom = item.Rect.Bottom };
        uint statusColor = PermissionPage ? (state == UiText.Get("允许") || state == UiText.Get("已核对")) ? 0xB8DDB7u : state == UiText.Get("禁止") ? 0xAEB4ECu : 0xC1B9B8u : 0xE4C9EFu;
        Text(item.Dc, state, stateBounds, 19, systemSelection ? GetSysColor(14) : statusColor, false, centered: true, nativeColor: systemSelection);
        if (PermissionPage)
            Text(item.Dc, "···", new Rect { Left = item.Rect.Right - actionWidth, Top = item.Rect.Top, Right = item.Rect.Right, Bottom = item.Rect.Bottom }, 27, systemSelection ? GetSysColor(14) : 0xC9C4CEu, false, centered: true, nativeColor: systemSelection);
        if ((item.State & 16) != 0) { var r = item.Rect; PaintKeyboardFocus(item.Dc, ref r); }
    }

    private static int ProgramRowHeight => Math.Max(Px(70), (FontPixels(PermissionPage ? 18 : 20) + 3) * 2 + Px(10));
    private static int MaskRowHeight => FontPixels(20) * 2 + Px(16);
    private static void PaintMaskItem(DrawItem item)
    {
        if (item.Item >= draft.Masks.Length) return;
        var mask = draft.Masks[item.Item]; bool selected = (item.State & 1) != 0, contrast = HighContrast();
        var background = item.Rect;
        if (contrast) FillRect(item.Dc, ref background, GetSysColorBrush(selected ? 13 : 5));
        else
        {
            PaintControlBackdrop(item);
            if (selected) SoftSurface(item.Dc, background, 0x826956, 32, 13);
        }
        var text = background; text.Left += Px(16); text.Right -= Px(12); text.Top += Px(5); text.Bottom = text.Top + FontPixels(20) + Px(4);
        uint color = contrast ? GetSysColor(selected ? 14 : 8) : mask.Enabled ? 0xEAF2F6u : 0xC1B9B8u;
        Text(item.Dc, (mask.Enabled ? UiText.Get("遮挡  ") : UiText.Get("停用  ")) + Path.GetFileName(mask.Path), text, 20, color, false, nativeColor: contrast);
        text.Top = text.Bottom; text.Bottom = background.Bottom - Px(3);
        Text(item.Dc, UiText.Get("左 / 上 / 右 / 下    ") + string.Join("  ·  ", mask.Rect), text, 17, contrast ? color : 0xC1B9B8u, false, nativeColor: contrast);
        if ((item.State & 16) != 0) { var focus = background; PaintKeyboardFocus(item.Dc, ref focus); }
    }

    private static string HealthKey(UacApplicationPermission row) => row.Path + "|" + row.IdentityKind + "|" + row.Identity;
    private static void QueueProgramHealth()
    {
        if (preview) return;
        long expected = generation; var handle = window;
        var rows = model.Programs(ruleLayer, denied).Where(x => x.Enabled && !programHealth.ContainsKey(HealthKey(x))).ToArray();
        if (rows.Length == 0) return;
        _ = Task.Run(() =>
        {
            foreach (var row in rows)
            {
                string status = UiText.Get("需重新核对");
                try { var current = UacIdentity.Inspect(row.Path); if (current.IdentityKind == row.IdentityKind && current.Identity == row.Identity) status = UiText.Get("已核对"); } catch { }
                if (expected != generation) return; programHealth[HealthKey(row)] = status;
            }
            if (expected == generation) PostMessageW(handle, HealthFinished, UIntPtr.Zero, IntPtr.Zero);
        });
    }
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] private static extern bool GetClientRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] private static extern bool EnableWindow(IntPtr hwnd, bool value);
    [DllImport("user32.dll")] private static extern bool ValidateRect(IntPtr hwnd, IntPtr rect);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool SetWindowTextW(IntPtr hwnd, string value);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr SendMessageW(IntPtr hwnd, uint message, IntPtr w, IntPtr l);
    [DllImport("user32.dll", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode)] private static extern IntPtr SendMessageText(IntPtr hwnd, uint message, IntPtr w, string l);
    [DllImport("gdi32.dll")] private static extern uint SetBkColor(IntPtr dc, uint color);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint PrivateExtractIconsW(string file, int index, int w, int h, out IntPtr icon, out uint resource, uint count, uint flags);
    [DllImport("user32.dll")] private static extern bool DrawIconEx(IntPtr dc, int x, int y, IntPtr icon, int w, int h, uint step, IntPtr brush, uint flags);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr LoadIconW(IntPtr instance, IntPtr name);
    [DllImport("user32.dll")] private static extern IntPtr CopyIcon(IntPtr icon);
}
