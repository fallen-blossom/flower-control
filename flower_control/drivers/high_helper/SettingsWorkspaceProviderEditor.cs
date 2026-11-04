namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static void EditDecisionProvider(bool add)
    {
        if (decisionDraft is null || decisionSnapshot?.Error is not null) return;
        string selected = add ? "custom_" + Guid.NewGuid().ToString("N") : decisionDraft.Order[decisionSelection];
        if (selected == "host") return;
        bool custom = selected.StartsWith("custom_");
        var existing = decisionDraft.Providers.FirstOrDefault(p => p.Id == selected);
        if (add && decisionDraft.Providers.Length >= 16) { notice = UiText.Get("最多可配置16个兼容服务。"); UpdateChrome(); return; }
        var definition = existing ?? new CustomDecisionProvider(selected, UiText.Get("自定义服务"), "openai_chat",
            "https://api.example.com/v1/chat/completions", "", "");
        var fields = custom ? new EditorField[] {
            new(1100, UiText.Get("服务名称"), definition.Name),
            new(1101, UiText.Get("协议"), definition.Protocol == "decisions" ? UiText.Get("Decisions 兼容") : UiText.Get("OpenAI Chat 兼容"), Choices: [UiText.Get("OpenAI Chat 兼容"), UiText.Get("Decisions 兼容")]),
            new(1102, UiText.Get("完整请求地址"), definition.Endpoint), new(1103, UiText.Get("模型名称"), definition.Model),
            new(1104, UiText.Get("隐私政策网址"), definition.PrivacyUrl), new(1105, UiText.Get("API 密钥"), "", Secret: true) }
            : new EditorField[] { new(1100, UiText.Get("服务"), DecisionServiceLabel(selected), ReadOnly: true),
                new(1102, UiText.Get("请求地址"), selected == "jev" ? "https://api.typesafe.ai/v1/systemone" : "https://api.perplexity.ai/v1/decisions", ReadOnly: true),
                new(1103, UiText.Get("模型名称"), selected == "jev" ? decisionDraft.JevModel : decisionDraft.PerplexityModel),
                new(1105, UiText.Get("API 密钥"), "", Secret: true) };
        string explanation = UiText.Get("密钥留空不变，填入后保存即更新；服务参数需回列表保存。\r\n新服务或换地址后默认停用，启用前核对发送目标及隐私条款。\r\n兼容服务须支持 Chat Completions JSON 或 Decisions；仅用 HTTPS。");
        bool Save(AppDialog dialog)
        {
            string Read(int id) => Text(GetDlgItem(dialog.Window, id));
            try
            {
                var draftValue = decisionDraft!;
                CustomDecisionProvider? submitted = null;
                if (custom)
                {
                    submitted = definition with { Name = Read(1100).Trim(), Protocol = SendMessageW(GetDlgItem(dialog.Window, 1101), 0x147, IntPtr.Zero, IntPtr.Zero).ToInt32() == 1 ? "decisions" : "openai_chat",
                        Endpoint = Read(1102).Trim(), Model = Read(1103).Trim(), PrivacyUrl = Read(1104).Trim() };
                    DecisionProviderSettings.ValidateProvider(submitted);
                    draftValue = draftValue with { Custom = draftValue.Providers.Where(p => p.Id != selected).Append(submitted).ToArray(),
                        Order = add ? draftValue.Order.Append(selected).ToArray() : draftValue.Order };
                    if (existing is null || existing.Endpoint != submitted.Endpoint || existing.Protocol != submitted.Protocol)
                        draftValue = draftValue.Enable(selected, false);
                }
                else draftValue = selected == "jev" ? draftValue with { JevModel = Read(1103).Trim() } : draftValue with { PerplexityModel = Read(1103).Trim() };
                _ = DecisionProviderSettings.Parse(DecisionProviderSettings.Serialize(draftValue));
                string key = Read(1105);
                try { if (key.Length > 0 && !preview) DecisionCredential.Store(decisionPath!, selected, submitted, key); }
                finally { key = ""; }
                decisionDraft = draftValue; decisionSelection = Array.IndexOf(draftValue.Order, selected);
                SetWindowTextW(GetDlgItem(dialog.Window, 1105), "");
                return true;
            }
            catch (Exception error)
            {
                string code = Program.Code(error);
                SetWindowTextW(dialog.Body, UiText.Get("未完成保存：") + code + UiText.Get("。检查模型和HTTPS地址。密钥若写入未确认，可能已经写入；请重填同一项恢复，不自动重试或发送测试请求。"));
                return false;
            }
        }
        int result = MessageBoxW(window, explanation, add ? UiText.Get("添加决策服务") : UiText.Get("配置服务与密钥"), 4, fields, Save);
        if (result == 6) { notice = UiText.Get("服务参数已进入草稿；密钥如有填写已单独更新。点击保存服务设置后应用参数与顺序。"); BuildPage(); UpdateChrome(); }
    }
}
