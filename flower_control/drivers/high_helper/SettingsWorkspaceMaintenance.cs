using System.Runtime.InteropServices;
using System.Text.Json;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const int ExportSettingsId = 950, ImportSettingsId = 951, StorageUsageId = 952, CacheCleanupId = 953;
    private static string maintenanceAction = "", maintenancePath = "", maintenanceSummary = "";
    private static bool maintenancePending;
    private static string? maintenancePlanSha;
    private static MaintenanceToolResult? maintenanceResult;

    private static void BuildMaintenanceControls()
    {
        PageButton(ExportSettingsId, UiText.Get("备份普通设置与名单"), 650, 688, 380, 36);
        PageButton(ImportSettingsId, UiText.Get("导入设置到草稿"), 1050, 688, 390, 36);
        PageButton(StorageUsageId, UiText.Get("查看本地空间用量"), 650, 749, 380, 36);
        PageButton(CacheCleanupId, UiText.Get("检查可回收缓存"), 1050, 749, 390, 36);
        foreach (int id in new[] { ExportSettingsId, ImportSettingsId, StorageUsageId, CacheCleanupId })
            EnableWindow(PageHandle(id), !Busy && !BrowserOpening);
    }

    private static bool MaintenanceCommand(int id, int notification)
    {
        if (id is < ExportSettingsId or > CacheCleanupId) return false;
        if (notification != 0 || Busy || BrowserOpening) return true;
        if (id == ImportSettingsId)
        {
            if (invalidEdit || model.Conflict) { notice = UiText.Get("请先核对当前草稿，再导入设置。"); UpdateChrome(); return true; }
            string? input = PickMaintenanceJson(false);
            if (input is null) return true;
            var imported = SettingsPortability.Read(input, draft);
            if (MessageBoxW(window, UiText.Get("名单和普通操作偏好将进入当前草稿；导入的允许规则均禁用，需要逐项核对。当前权限档位、Stop 和未完成动作保持。继续？"),
                    UiText.Get("导入设置到草稿"), 4 | 0x20 | 0x100) != 6) return true;
            model.Edit(_ => imported.Settings);
            notice = UiText.Get("已导入到草稿；请核对名单并按 Ctrl+S 保存。允许规则保持禁用。");
            BuildPage(); UpdateChrome();
            if ((imported.Browser is not null || imported.Language is not null)
                && MessageBoxW(window, UiText.Get("浏览器选择和界面语言使用独立保存。现在立即应用导入的这些普通偏好？名单草稿仍需 Ctrl+S。")
                    + "\r\n" + (imported.Browser ?? "—") + " / " + (imported.Language ?? "—"), UiText.Get("应用普通偏好"), 4 | 0x20 | 0x100) == 6)
                ImportOrdinaryPreferences(imported);
            return true;
        }
        if (preview) { notice = UiText.Get("预览不会备份真实设置、扫描资料或清理文件。"); UpdateChrome(); return true; }
        if (id == ExportSettingsId)
        {
            string? output = PickMaintenanceJson(true);
            if (output is not null) StartMaintenance("settings_export", output);
        }
        else if (id == StorageUsageId) StartMaintenance("storage_usage", null);
        else
        {
            // Plan files contain metadata only. The Medium child writes them;
            // the High settings process never removes a user-data path.
            string directory = Path.Combine(Path.GetTempPath(), "flower-cache-review-" + Guid.NewGuid().ToString("N"));
            BrokerPolicy.RejectLinks(Path.GetTempPath()); Directory.CreateDirectory(directory); BrokerPolicy.RejectLinks(directory);
            StartMaintenance("cache_plan", Path.Combine(directory, "plan.json"));
        }
        return true;
    }

    private static void StartMaintenance(string action, string? path)
    {
        maintenanceAction = action; maintenancePath = path ?? ""; maintenanceResult = null; maintenancePending = true;
        string? digest = action == "cache_recycle" ? maintenancePlanSha : null;
        try { StartWork(token => { maintenanceResult = BrowserProfileOpen.RunMaintenanceAsync(action, path, token, digest).GetAwaiter().GetResult(); return new("maintenance"); }); }
        catch { maintenancePending = false; throw; }
        notice = UiText.Get("正在处理本地维护请求；现有草稿保留。"); UpdateChrome();
    }

    private static void ImportOrdinaryPreferences(PortableSettingsDraft imported)
    {
        if (preview)
        {
            if (imported.Language is not null) ApplyDisplayPreference(displayPreference with { Language = imported.Language });
            browserPreferences = BrowserPreferences.Synthetic() with { Preference = imported.Browser ?? "system" };
            notice = UiText.Get("预览只更新内存；没有写入真实偏好。"); UpdateChrome(); return;
        }
        var browser = BrowserPreferences.Read(); var display = DisplayPreferences.Read();
        if (browser.Error is not null && browser.Error != "selected_browser_not_installed" || display.Error is not null)
            throw new Boundary("settings_preferences_unverified");
        maintenanceAction = "import_preferences"; maintenancePending = true; maintenanceSummary = "";
        try { StartWork(token => {
            var notes = new List<string>();
            if (imported.Browser is not null)
            {
                var reply = BrowserProfileOpen.SavePreferenceAsync(imported.Browser, browser.Revision, token).GetAwaiter().GetResult();
                notes.Add("browser: " + reply.State);
                if (reply.State != "saved") throw new Boundary(reply.Reason ?? "browser_preferences_outcome_unknown");
            }
            if (imported.Language is not null)
            {
                var reply = BrowserProfileOpen.SaveDisplayPreferenceAsync(imported.Language, display.Revision, token).GetAwaiter().GetResult();
                notes.Add("language: " + reply.State);
                if (reply.State != "saved") throw new Boundary(reply.Reason ?? "display_preferences_outcome_unknown");
            }
            maintenanceSummary = string.Join("\r\n", notes); return new("maintenance");
        }); }
        catch { maintenancePending = false; throw; }
        notice = UiText.Get("正在独立保存浏览器和语言偏好；名单草稿保留。"); UpdateChrome();
    }

    private static bool CompleteMaintenanceWork(WorkReply reply)
    {
        if (reply.Kind != "maintenance" && !maintenancePending) return false;
        maintenancePending = false;
        if (maintenanceAction == "import_preferences")
        {
            browserPreferences = BrowserPreferences.Read(); ApplyDisplayPreference(DisplayPreferences.Read());
            notice = reply.Error is null ? UiText.Get("普通偏好已分别保存；名单草稿仍需 Ctrl+S。")
                : UiText.Get("普通偏好仅部分完成或结果待核对；已重读实际值，不自动重试。") + " " + UserFacingError(reply.Error);
            BuildPage(); UpdateChrome(); return true;
        }
        var result = maintenanceResult;
        if (reply.Error is not null || result?.State != "completed" || result.Result is null)
        {
            notice = UiText.Get("本地维护未确认完成；请核对实际文件和草稿，不自动重试。") + " " + UserFacingError(reply.Error ?? result?.Error ?? result?.State ?? "maintenance_unavailable");
            UpdateChrome(); return true;
        }
        var value = result.Result.Value;
        if (maintenanceAction == "settings_export")
            notice = UiText.Get("已备份普通设置和名单；密钥、Cookie、聊天、授权和未完成动作不在备份内。") + " " + maintenancePath;
        else if (maintenanceAction == "storage_usage")
        {
            string text = string.Join("\r\n", value.GetProperty("categories").EnumerateArray().Select(row =>
                row.GetProperty("category").GetString() + ": " + row.GetProperty("files").GetInt32() + " files / "
                + row.GetProperty("bytes").GetInt64() + " bytes / unreadable " + row.GetProperty("unreadable").GetInt32()
                + "\r\n" + row.GetProperty("path").GetString()));
            MessageBoxW(window, text + "\r\n\r\n" + UiText.Get("仅统计文件元数据；未读取资料内容。链接和无法访问的文件不计入完整用量。"), UiText.Get("本地空间用量"), 0);
        }
        else if (maintenanceAction == "cache_plan")
        {
            maintenancePlanSha = value.GetProperty("plan_sha256").GetString();
            BrokerPolicy.RejectLinks(maintenancePath);
            if (Native.Digest(maintenancePath) != maintenancePlanSha) throw new Boundary("cache_reviewed_plan_changed");
            using var planStream = new FileStream(maintenancePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (planStream.Length > 32_000_000) throw new Boundary("cache_plan_too_large");
            using var planDocument = JsonDocument.Parse(planStream); Protocol.CheckUnique(planDocument);
            var planned = planDocument.RootElement;
            int count = value.GetProperty("file_count").GetInt32(); long bytes = value.GetProperty("bytes").GetInt64();
            if (count == 0) notice = UiText.Get("没有符合保留期和安全条件的可回收缓存。");
            else
            {
                string details = count + " files / " + bytes + " bytes\r\n" + string.Join("\r\n", planned.GetProperty("files").EnumerateArray().Select(row =>
                    row.GetProperty("path").GetString() + " (" + row.GetProperty("bytes").GetInt64() + " bytes)"));
                if (MessageBoxW(window, UiText.Get("以下旧缓存将移交 Windows 回收站。活动登录态、资料账本和恢复记录不在清单内。继续？") + "\r\n\r\n" + details,
                    UiText.Get("确认回收缓存"), 4 | 0x30 | 0x100) == 6) { StartMaintenance("cache_recycle", maintenancePath); return true; }
                notice = UiText.Get("已取消回收；文件保持原状。");
            }
        }
        else notice = value.GetProperty("state").GetString() == "recycled" ? UiText.Get("所选旧缓存已移交 Windows 回收站。")
            : UiText.Get("回收未全部完成；请核对已回收清单和失败项，没有改用永久删除。");
        UpdateChrome(); return true;
    }

    private static string? PickMaintenanceJson(bool save)
    {
        var memory = Marshal.AllocHGlobal(65536);
        try
        {
            Marshal.Copy(new byte[65536], 0, memory, 65536);
            if (save)
            {
                byte[] initial = System.Text.Encoding.Unicode.GetBytes("Flower-Control-settings-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".json\0");
                Marshal.Copy(initial, 0, memory, initial.Length);
            }
            var picker = new OpenFileName { Size = (uint)Marshal.SizeOf<OpenFileName>(), Owner = window,
                Filter = "Flower settings (*.json)\0*.json\0\0", File = memory, FileLength = 32768, DefaultExtension = "json",
                Title = UiText.Get(save ? "备份普通设置与名单" : "导入设置到草稿"),
                Flags = 0x80000 | 0x800 | 8 | 0x02000000 | (save ? 0u : 0x1000u) };
            if (!(save ? GetSaveFileNameW(ref picker) : GetOpenFileNameW(ref picker)))
            {
                if (CommDlgExtendedError() != 0) throw new Boundary("settings_file_picker_failed");
                return null;
            }
            string path = Marshal.PtrToStringUni(memory) ?? throw new Boundary("settings_file_picker_failed");
            if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal)) throw new Boundary("settings_path_rejected");
            if (save && File.Exists(path)) throw new Boundary("settings_backup_output_exists");
            return path;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }
    [DllImport("comdlg32.dll", CharSet = CharSet.Unicode)] private static extern bool GetSaveFileNameW(ref OpenFileName picker);
}
