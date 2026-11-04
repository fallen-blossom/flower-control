namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static int? modeMouseChoice;
    private const int ViewLayerBase = 510, ListKindBase = 520, ModeChoiceBase = 530, CancelScopeBase = 550;
    private static bool IsPermissionChoice(int id) => id is >= 510 and <= 512 or >= 520 and <= 521 or >= 530 and <= 531;
    private static bool PermissionChoiceSelected(int id) => id is >= 510 and <= 512 ? ruleLayer == id - ViewLayerBase
        : id is >= 520 and <= 521 ? (denied ? 1 : 0) == id - ListKindBase
        : id is >= 530 and <= 531 ? ((ruleLayer == 2 ? draft.AdminLaunchMode : preferredMode) == "semantic" ? 1 : 0) == id - ModeChoiceBase
        : id is >= 550 and <= 551 && (draft.UacCancellationScope == "task" ? 0 : 1) == id - CancelScopeBase;
    private static string PermissionChoiceText(int id) => id is >= 510 and <= 512
        ? new[] { UiText.Get("02 普通"), UiText.Get("03 管理"), UiText.Get("04 执行") }[id - ViewLayerBase]
        : id == ListKindBase ? UiText.Get("白名单  ") + model.Programs(ruleLayer, false).Length
        : id == ListKindBase + 1 ? UiText.Get("黑名单  ") + model.Programs(ruleLayer, true).Length
        : id == ModeChoiceBase ? UiText.Get("程序名单") : id == ModeChoiceBase + 1 ? UiText.Get("按工作授权")
        : id == CancelScopeBase ? UiText.Get("仅本任务") : UiText.Get("会话中选定提示");

    private static void PermissionCaption(int id, string text) => Field(id, "STATIC", text, 0, 0, 1, 1, 0xD);
    private static void PermissionChoice(int id)
    {
        string name = id is >= 510 and <= 512 ? UiText.Get("查看 ") + AuthorityPresentation.Label(id - ViewLayerBase) + UiText.Get("规则") : PermissionChoiceText(id);
        if (PermissionChoiceSelected(id)) name += UiText.Get(" · 已选");
        PageButton(id, name, 0, 0, 1, 1);
    }
    private static void BuildPermissionSurface()
    {
        // Legacy handoffs may contain UAC's old layer. Preserve its policy
        // arrays without making a frozen route editable or selectable.
        ruleLayer = Math.Clamp(ruleLayer, 0, 2);
        for (int i = 0; i < 3; i++) PermissionChoice(ViewLayerBase + i);
        PageButton(RuleHelpId, UiText.Get("规则说明"), 0, 0, 1, 1);
        if (ruleLayer < 2)
        {
            PermissionCaption(614, UiText.Get("窗口禁止规则 · 完整路径 | 标题条件；# 表示停用"));
            Field(RulesId, "EDIT", RuleText(model.WindowRules(ruleLayer)), 0, 0, 1, 1, 0x200000 | 4 | 0x40 | 0x1000);
            PermissionCaption(615, UiText.Get("空表表示没有禁止项。修改只进入本层草稿，不会更改 Windows 权限。"));
            return;
        }
        PermissionCaption(611, UiText.Get("授权方式"));
        PageButton(ModeChoiceBase, ModeToggleAccessibleText(), 0, 0, 1, 1);
        if (ruleLayer == 2) PageButton(SemanticEnableId, UiText.Get("启用工作授权"), 0, 0, 1, 1);
        PermissionCaption(612, denied ? UiText.Get("黑名单程序") : UiText.Get("白名单程序"));
        for (int i = 0; i < 2; i++) PermissionChoice(ListKindBase + i);
        if (ruleLayer == 3)
        {
            PermissionCaption(613, UiText.Get("取消范围"));
            PermissionChoice(CancelScopeBase); PermissionChoice(CancelScopeBase + 1);
            EnableWindow(PageHandle(ModeChoiceBase), false);
        }
        renderedListKey = ListKey;
        var list = Field(ProgramListId, "LISTBOX", "", 0, 0, 1, 1, 0x200000 | 0x10 | 0x40 | 0x100 | 1);
        SendMessageW(list, 0x1A0, IntPtr.Zero, new IntPtr(ProgramRowHeight));
        foreach (var row in model.Programs(ruleLayer, denied)) SendMessageText(list, 0x180, IntPtr.Zero, (row.Enabled ? denied ? UiText.Get("禁止  ") : UiText.Get("允许  ") : UiText.Get("停用  ")) + row.DisplayName + "  " + row.Path);
        QueueProgramHealth();
        SendMessageW(list, 0x186, new IntPtr(Math.Min(listSelection[ListKey], Math.Max(0, RowCount - 1))), IntPtr.Zero);
        SendMessageW(list, 0x197, new IntPtr(listTop[ListKey]), IntPtr.Zero);
        // Keep the same three command IDs and bound-row checks behind the
        // visible row menu, including keyboard and context-menu access.
        PageButton(DetailId, UiText.Get("详情 / 复制路径"), 0, 0, 1, 1);
        PageButton(ToggleId, UiText.Get("启用 / 停用"), 0, 0, 1, 1);
        PageButton(RemoveId, UiText.Get("移除"), 0, 0, 1, 1);
        PageButton(ProgramMenuId, UiText.Get("程序操作"), 0, 0, 1, 1);
    }
    private static bool PermissionChoiceCommand(int id)
    {
        if (!IsPermissionChoice(id)) return false;
        if (id == ModeChoiceBase)
        {
            int choice = modeMouseChoice ?? (PermissionChoiceSelected(ModeChoiceBase) ? 1 : 0);
            return SetModeChoice(choice);
        }
        if (PermissionChoiceSelected(id)) return true;
        if (invalidEdit) { notice = UiText.Get("请先修正当前输入或重新载入；原草稿保留。"); UpdateChrome(); return true; }
        if (id is >= 510 and <= 512) BuildPageAfter(() => ruleLayer = id - ViewLayerBase);
        else if (id is >= 520 and <= 521) BuildPageAfter(() => denied = id == ListKindBase + 1);
        else
        {
            model.Edit(x => x with { UacCancellationScope = id == CancelScopeBase ? "task" : "selected_prompt_in_session" });
            foreach (var c in pageControls.Where(c => c.Id is >= 550 and <= 551)) InvalidateRect(c.Handle, IntPtr.Zero, false);
            UpdateChrome();
        }
        return true;
    }
    private static string ModeToggleAccessibleText()
        => UiText.Get("授权方式") + ": " + (PermissionChoiceSelected(ModeChoiceBase) ? UiText.Get("程序名单") : UiText.Get("按工作授权"))
            + UiText.Get("；左右方向键切换");
    private static bool SetModeChoice(int choice)
    {
        int id = ModeChoiceBase + choice;
        if (PermissionChoiceSelected(id)) return true;
        if (invalidEdit) { notice = UiText.Get("请先修正当前输入或重新载入；原草稿保留。"); UpdateChrome(); return true; }
        if (ruleLayer == 3 && choice == 1) { notice = UiText.Get("04 按工作授权尚未就绪；原选择保留。"); UpdateChrome(); return true; }
        string value = choice == 0 ? "allowlist" : "semantic";
        if (ruleLayer == 2) model.Edit(x => x with { AdminLaunchMode = value });
        else { preferredMode = value; if (tier == 3) model.Edit(x => x with { UacMode = value }); }
        var control = PageHandle(ModeChoiceBase);
        SetChromeText(control, ModeToggleAccessibleText()); InvalidateRect(control, IntPtr.Zero, false);
        UpdateChrome(); return true;
    }
    private static Rect PermissionBounds(PageControl c)
    {
        if (c.Id == SemanticEnableId) return CompactSurface ? Layout.C(800, 226, 160, 32) : Layout.R(1120, 280, 325, 32);
        if (c.Id is >= 510 and <= 512)
            return Layout.ViewTab(c.Id - ViewLayerBase);
        if (c.Id is >= 520 and <= 521)
            return CompactSurface ? Layout.C(410 + (c.Id - ListKindBase) * 280, 266, 266, 32)
                : c.Id == ListKindBase ? Layout.R(600, 320, 420, 64) : Layout.R(1021, 320, 424, 64);
        if (c.Id == ModeChoiceBase)
            return CompactSurface ? Layout.C(410, 226, 380, 32) : Layout.R(675, 280, 355, 32);
        if (c.Id is >= 550 and <= 551)
            return CompactSurface ? Layout.C(410 + (c.Id - CancelScopeBase) * 280, 306, 266, 32)
                : c.Id == CancelScopeBase ? Layout.R(1045, 284, 80, 24) : Layout.R(1135, 284, 150, 24);
        if (c.Id == RuleHelpId) return Layout.ViewHelp;
        if (c.Id == 611) return CompactSurface ? Layout.C(310, 230, 100, 26) : Layout.R(600, 286, 70, 20);
        if (c.Id == 612) return CompactSurface ? Layout.C(310, 270, 180, 22) : Layout.R(615, 392, 180, 20);
        if (c.Id == 613) return CompactSurface ? Layout.C(310, 310, 100, 26) : Layout.R(965, 286, 75, 20);
        if (c.Id == 614) return CompactSurface ? Layout.C(310, 244, 650, 40) : Layout.R(600, 320, 850, 24);
        if (c.Id == RulesId) return CompactSurface ? Layout.C(310, 294, 650, 180) : Layout.R(600, 350, 850, 280);
        if (c.Id == 615) return CompactSurface ? Layout.C(310, 484, 650, 32) : Layout.R(600, 660, 850, 28);
        if (c.Id == ProgramListId) return CompactSurface ? Layout.C(310, ruleLayer == 3 ? 346 : 306, 650, 200) : Layout.R(600, 420, 850, 280);
        if (c.Id == ProgramMenuId) return CompactSurface ? Layout.C(902, 318, 52, 32) : Layout.R(1390, 415, 48, 32);
        return Layout.R(600, 700, 1, 1); // hidden legacy command buttons
    }
}
