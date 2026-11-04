namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int SemanticEnableId = 415;
    private static bool CanConfirmSemanticDelegation => !Busy && !model.Conflict && !surfaceFault && !invalidEdit
        && saved.AdminLaunchEnabled && saved.AdminLaunchMode == "semantic" && !SemanticDelegation.IncludesDsh(saved.SemanticDelegation)
        && draft.AdminLaunchEnabled && draft.AdminLaunchMode == "semantic" && (preview || core is not null);
    private static void RefreshSemanticDelegationControl()
    {
        var handle = PageHandle(SemanticEnableId);
        SetChromeText(handle, SemanticDelegation.IncludesDsh(saved.SemanticDelegation) ? CompactSurface ? UiText.Get("委托已启用") : UiText.Get("工作授权已启用")
            : saved.SemanticDelegation is not null ? CompactSurface ? UiText.Get("为 DSH 启用") : UiText.Get("为 DSH 启用工作授权")
            : saved.AdminLaunchEnabled && saved.AdminLaunchMode == "semantic" ? UiText.Get("启用工作授权")
            : CompactSurface ? UiText.Get("先保存模式") : UiText.Get("工作授权 · 先保存模式"));
        EnableChromeControl(handle, CanConfirmSemanticDelegation);
    }
    private static void RequestSemanticDelegation()
    {
        if (!CanConfirmSemanticDelegation) return;
        var baseline = saved;
        if (MessageBoxW(window, UiText.Get("允许 Codex 和 DeepSeek Harness 在你分别授权的任务范围内执行 High 启动？\r\n这会建立两个宿主的本机工作委托；聊天、任务和授权保持独立，黑名单仍优先。\r\n仅更新这份委托，不保存其他草稿，不启动程序。旧任务不会继承新委托。"), UiText.Get("启用 04 工作授权"), 4 | 0x30 | 0x100) != 6) return;
        if (preview)
        {
            model.ReconcileSemanticDelegation(baseline, baseline with { Revision = "preview-" + Guid.NewGuid().ToString("N"),
                SemanticDelegation = SemanticDelegation.ForExplicitSelection(baseline.UserSid) });
            notice = UiText.Get("仅在预览内存启用；真实权限没有写入。"); UpdateChrome(); return;
        }
        StartWork(token => new("semantic_enable", baseline, core!.OrdinaryResident
            ? LocalUiWriter.Execute(core, new("semantic", baseline.Revision), null, token).Current
            : UacInstallation.ConfirmSemanticDelegation(baseline.Revision, core, token)));
        notice = UiText.Get("正在建立本机工作委托；其他草稿保留。"); UpdateChrome();
    }
}
