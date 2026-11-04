using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private sealed record ProgramSelectionContext(IntPtr Window, long Generation, int Page, int PrivacyTab, int Layer, bool Denied,
        string Revision, long? StopEpoch, bool Paused);
    private sealed record WindowChoice(IntPtr Hwnd, Peer Peer, string Image, string Title, int Width, int Height,
        Peer? FramePeer = null);
    private sealed record ProgramReveal(int Key, string Path, string? Arguments);
    private static ProgramSelectionContext? windowPickContext;
    private static ProgramReveal? pendingProgramReveal;

    private static ProgramSelectionContext SelectionContext()
        => new(window, generation, page, privacyTab, ruleLayer, denied, saved.Revision, core?.ProtectedStopEpoch, core?.IsPaused == true);

    private static void RequireSelectionContext(ProgramSelectionContext context)
    {
        if (context.Window != window || context.Page != page || context.PrivacyTab != privacyTab || context.Layer != ruleLayer || context.Denied != denied
            || context.Revision != saved.Revision || Busy
            || !PermissionSettingsWindow.SelectionMatches(context.Generation, context.StopEpoch, context.Paused,
                generation, core?.ProtectedStopEpoch, core?.IsPaused == true))
            throw new Boundary("uac_window_pick_expired");
    }

    private static string SelectionError(string code) => code switch
    {
        "uac_allowlist_payload_host_rejected" => UiText.Get("此程序依赖解释器或 .NET 运行时，不能加入当前启动白名单；请使用按工作授权。"),
        "uac_allowlist_program_writable" => UiText.Get("程序或目录可被普通用户改写，不符合当前启动白名单条件；请使用按工作授权。"),
        "uac_program_signature_unknown" => UiText.Get("程序文件已找到，但无法确认其签名状态；名单要求签名可验证或确认未签名并绑定文件摘要。请检查文件签名和本机证书后重试。"),
        "uac_window_pick_expired" => UiText.Get("页面、名单或停止状态已变化；本次没有添加，请从当前页面重新选择。"),
        "uac_window_pick_host_ambiguous" => UiText.Get("无法唯一识别此宿主窗口里的应用；请使用选择程序文件。"),
        "uac_window_pick_target_rejected" => UiText.Get("此窗口不是可选的应用窗口；请重新选择或选择程序文件。"),
        _ => UiText.Get("程序未加入，原草稿保留：") + code
    };

    private static void RunProgramSelection(Action action)
    {
        PublishWorkspaceStatus("selection_started");
        try { action(); UpdateChrome(); }
        catch (Boundary error)
        {
            notice = SelectionError(error.Code); UpdateChrome();
            MessageBoxW(window, notice, UiText.Get("程序未加入"), 0x30);
            PublishWorkspaceStatus("selection_failed", error: error.Code);
        }
    }

    private static void AddSourceMenu()
    {
        if (Busy || invalidEdit || RowCount >= 128) return;
        var context = SelectionContext();
        RunProgramSelection(() =>
        {
            var menu = CreatePopupMenu();
            if (menu == IntPtr.Zero) throw new Boundary("settings_menu_unavailable");
            int choice;
            try
            {
                AppendMenuW(menu, 0, 701, UiText.Get("选择程序文件"));
                AppendMenuW(menu, 0, 702, UiText.Get("从运行窗口选择"));
                AppendMenuW(menu, 0, 703, UiText.Get("按 Ctrl+Alt+8 选择窗口（30 秒）"));
                if (page == 2) EnableMenuItem(menu, 701, 1);
                GetCursorPos(out var point);
                choice = TrackPopupMenu(menu, 0x102, point.X, point.Y, 0, window, IntPtr.Zero);
            }
            finally { DestroyMenu(menu); }
            RequireSelectionContext(context);
            if (choice == 701) PickFile(context);
            else if (choice == 702) PickRunning(context);
            else if (choice == 703)
            {
                EndPick();
                if (!RegisterHotKey(window, 187, 0x4000 | 3, 0x38)) throw new Boundary("uac_window_pick_hotkey_unavailable");
                picking = true; windowPickContext = context; pickExpiry = DateTime.UtcNow.AddSeconds(30);
                if (SetTimer(window, new UIntPtr(PickTimer), 30000, IntPtr.Zero) == UIntPtr.Zero)
                { EndPick(); throw new Boundary("uac_window_pick_timer_unavailable"); }
                notice = UiText.Get("将鼠标移到目标窗口，按 Ctrl+Alt+8；Esc 取消，30 秒后失效。");
            }
            UpdateChrome();
        });
    }

    private static void EndPick()
    {
        windowPickContext = null;
        if (!picking) return;
        picking = false; KillTimer(window, new UIntPtr(PickTimer)); UnregisterHotKey(window, 187);
    }

    private static void CompleteWindowPick()
    {
        var context = windowPickContext; bool expired = DateTime.UtcNow > pickExpiry; EndPick();
        RunProgramSelection(() =>
        {
            if (expired || context is null) throw new Boundary("uac_window_pick_expired");
            RequireSelectionContext(context);
            GetCursorPos(out var point); var chosen = CaptureWindow(WindowFromPoint(point));
            ConfirmCandidate(chosen.Image, chosen, context);
        });
    }

    // A visible style is insufficient: shell/utility and cloaked windows are
    // not application choices. Keep genuine untitled application roots.
    private static bool PickableWindow(string className, uint extendedStyle, bool visible, bool cloaked,
        bool owned, string title, string image)
        => visible && !cloaked && (extendedStyle & 0x80) == 0
            && (!owned || (extendedStyle & 0x40000) != 0)
            && className is not ("Progman" or "WorkerW" or "Shell_TrayWnd" or "Shell_SecondaryTrayWnd" or "#32768" or "tooltips_class32")
            && !(string.IsNullOrWhiteSpace(title) && Path.GetFileName(image).Equals("explorer.exe", StringComparison.OrdinalIgnoreCase));

    private static WindowChoice CaptureWindow(IntPtr handle)
    {
        handle = Native.GetAncestor(handle, 2);
        if (handle == IntPtr.Zero || Native.ProtectedWindowOrOwner(handle)) throw new Boundary("uac_window_pick_target_rejected");
        Native.GetWindowThreadProcessId(handle, out var pid);
        var process = Native.Process((int)pid, false); var own = Native.Process(Environment.ProcessId, false).Identity;
        if (process.Identity.Pid == Environment.ProcessId || process.Identity.User != own.User || process.Identity.Session != own.Session
            || process.Identity.Integrity is not (8192 or 12288)) throw new Boundary("uac_window_pick_target_rejected");
        var name = new StringBuilder(256); PickerGetClassName(handle, name, name.Capacity);
        bool cloaked = PickerGetWindowAttribute(handle, 14, out int cloak, sizeof(int)) == 0 && cloak != 0;
        string title = Text(handle);
        bool selectable = page == 2 ? Native.IsWindowVisible(handle)
            : PickableWindow(name.ToString(), GetWindowLongW(handle, -20), Native.IsWindowVisible(handle), cloaked,
                Native.GetWindow(handle, 4) != IntPtr.Zero, title, process.Image);
        if (!selectable) throw new Boundary("uac_window_pick_target_rejected");
        GetClientRect(handle, out var rect);
        if (rect.Right <= 0 || rect.Bottom <= 0) throw new Boundary("uac_window_pick_target_rejected");
        Peer? frame = null;
        if (page != 2 && Path.GetFileName(process.Image).Equals("ApplicationFrameHost.exe", StringComparison.OrdinalIgnoreCase))
        {
            var children = new Dictionary<int, (Peer Identity, string Image)>();
            EnumChildWindows(handle, (child, _) =>
            {
                try
                {
                    Native.GetWindowThreadProcessId(child, out var childPid);
                    if (childPid == pid || !Native.IsWindowVisible(child) || children.ContainsKey((int)childPid)) return true;
                    var app = Native.Process((int)childPid, false);
                    if (app.Identity.User == own.User && app.Identity.Session == own.Session && app.Identity.Integrity is 8192 or 12288)
                        children[(int)childPid] = (app.Identity, app.Image);
                }
                catch (Boundary) { }
                return true;
            }, IntPtr.Zero);
            if (children.Count != 1) throw new Boundary("uac_window_pick_host_ambiguous");
            frame = process.Identity; var app = children.Values.Single(); process = (app.Identity, app.Image);
        }
        return new(handle, process.Identity, process.Image, title, rect.Right, rect.Bottom, frame);
    }

    private static List<WindowChoice> RunningProgramChoices()
    {
        var choices = new List<WindowChoice>();
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        EnumWindows((handle, _) =>
        {
            if (choices.Count >= 50) return false;
            try
            {
                var choice = CaptureWindow(handle);
                // Permission entries are programs, not browser tabs/documents.
                // Privacy masks still retain each exact window's geometry.
                if (identities.Add(page == 2 ? choice.Hwnd.ToString() : choice.Image)) choices.Add(choice);
            }
            catch (Boundary) { }
            return true;
        }, IntPtr.Zero);
        return choices;
    }

    private static void PickRunning(ProgramSelectionContext context)
    {
        var choices = RunningProgramChoices();
        if (choices.Count == 0) { notice = UiText.Get("没有可选择的应用窗口；可选择程序文件。"); return; }
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero) throw new Boundary("settings_menu_unavailable");
        int selected;
        try
        {
            for (int i = 0; i < choices.Count; i++)
            {
                var row = choices[i];
                string title = string.IsNullOrWhiteSpace(row.Title) ? UiText.Get("无标题窗口") : row.Title;
                string label = title + " · " + Path.GetFileName(row.Image) + " · PID " + row.Peer.Pid;
                AppendMenuW(menu, 0, (uint)(800 + i), label.Replace("&", "&&"), ProgramIcon(row.Image));
            }
            GetCursorPos(out var point); selected = TrackPopupMenu(menu, 0x102, point.X, point.Y, 0, window, IntPtr.Zero) - 800;
        }
        finally { DestroyMenu(menu); }
        RequireSelectionContext(context);
        if (selected >= 0 && selected < choices.Count) ConfirmCandidate(choices[selected].Image, choices[selected], context);
    }

    private static void PickFile(ProgramSelectionContext context)
    {
        var memory = Marshal.AllocHGlobal(65536);
        try
        {
            Marshal.Copy(new byte[65536], 0, memory, 65536);
            var picker = new OpenFileName { Size = (uint)Marshal.SizeOf<OpenFileName>(), Owner = window,
                Filter = UiText.Get("程序文件 (*.exe)\0*.exe\0\0"), File = memory, FileLength = 32768,
                Title = UiText.Get("选择程序 · 只加入草稿，不启动"), Flags = 0x80000 | 0x1000 | 0x800 | 8 | 0x02000000 };
            if (!GetOpenFileNameW(ref picker))
            {
                if (CommDlgExtendedError() != 0) throw new Boundary("uac_file_picker_failed");
                notice = UiText.Get("已取消选择，名单没有更改。"); return;
            }
            RequireSelectionContext(context);
            ConfirmCandidate(Marshal.PtrToStringUni(memory) ?? throw new Boundary("uac_file_picker_failed"), null, context);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static void ConfirmCandidate(string path, WindowChoice? candidate, ProgramSelectionContext? originalContext = null)
    {
        var context = originalContext ?? SelectionContext(); RequireSelectionContext(context);
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\") || !File.Exists(path)) throw new Boundary("user_policy_invalid");
        UacApplicationPermission? program = context.Page == 1 && context.Layer >= 2
            ? (context.Denied ? UacIdentity.Inspect(path) : UacIdentity.InspectForAllowlist(path)) with { Arguments = "" } : null;
        bool moveOpposite = program is not null && model.ProgramOnOppositeSide(context.Layer, context.Denied, program.Path);
        string destination = context.Page == 2 ? UiText.Get("截图遮挡") : context.Layer < 2 ? UiText.Get("本层禁止规则")
            : context.Denied ? UiText.Get("本层禁止名单") : UiText.Get("本层允许名单");
        string identity = program is null ? UiText.Get("完整本地路径") : program.IdentityKind + "  " + program.Identity
            + UiText.Get("\r\n只允许不带参数的新规则；旧准确参数规则保留。");
        if (MessageBoxW(window, path + UiText.Get("\r\n来源：") + (candidate is null ? UiText.Get("系统文件选择器") : UiText.Get("运行窗口 · ") + candidate.Title)
            + UiText.Get("\r\n身份：") + identity + UiText.Get("\r\n\r\n加入") + destination
            + UiText.Get("草稿？\r\n保存前不生效，不会启动程序。")
            + (moveOpposite ? UiText.Get("\r\n该程序已在另一侧。确认后将从另一侧移除该路径的所有规则，并加入当前侧；两侧都需保存才生效。") : ""), UiText.Get("确认程序来源"), 4 | 0x20 | 0x100) != 6)
        { notice = UiText.Get("已取消选择，名单没有更改。"); return; }
        RequireSelectionContext(context);
        if (candidate is not null)
        {
            var fresh = CaptureWindow(candidate.Hwnd);
            if (!SameWindowChoice(candidate, fresh))
                throw new Boundary("uac_window_pick_target_changed");
        }
        if (program is not null)
        {
            var fresh = context.Denied ? UacIdentity.Inspect(path) : UacIdentity.InspectForAllowlist(path);
            if (fresh.Identity != program.Identity || fresh.IdentityKind != program.IdentityKind) throw new Boundary("uac_program_changed");
            model.AddProgram(context.Layer, context.Denied, program, moveOpposite);
            pendingProgramReveal = new(ListKey, program.Path, program.Arguments);
        }
        else if (context.Page == 2)
        {
            if (candidate is null) throw new Boundary("mask_window_required");
            model.Edit(x => x with { Masks = x.Masks.Append(new PrivacyMask(path, [0, 0, Math.Min(320, candidate.Width), Math.Min(80, candidate.Height)], [candidate.Width, candidate.Height])).ToArray() });
        }
        else model.AddWindowRule(context.Layer, path);
        BuildPage(); notice = UiText.Get("候选已加入草稿；保存后生效。"); UpdateChrome();
    }

    private static bool SameWindowChoice(WindowChoice original, WindowChoice fresh)
        => original.Hwnd == fresh.Hwnd && original.FramePeer == fresh.FramePeer
            && original.Width == fresh.Width && original.Height == fresh.Height
            && PermissionSettingsWindow.WindowCandidateMatches(original.Peer, original.Image, fresh.Peer, fresh.Image);

    private static void RevealAddedProgram()
    {
        if (pendingProgramReveal is not { } requested) return;
        pendingProgramReveal = null;
        if (page != 1 || ruleLayer < 2 || ListKey != requested.Key) return;
        var rows = model.Programs(ruleLayer, denied);
        int index = Array.FindIndex(rows, x => x.Path.Equals(requested.Path, StringComparison.OrdinalIgnoreCase) && x.Arguments == requested.Arguments);
        var list = PageHandle(ProgramListId);
        if (index < 0 || list == IntPtr.Zero) return;
        // Apply after the real list size is known; rebuilding would otherwise
        // restore the previous first row and leave the new entry off-screen.
        SendMessageW(list, 0x186, new IntPtr(index), IntPtr.Zero);
        GetClientRect(list, out var client);
        int visibleRows = Math.Max(1, client.Bottom / ProgramRowHeight);
        int top = Math.Max(0, index - visibleRows + 1);
        SendMessageW(list, 0x197, new IntPtr(top), IntPtr.Zero);
        listSelection[ListKey] = index; listTop[ListKey] = top;
        SetFocus(list); InvalidateRect(list, IntPtr.Zero, false);
    }

    private static IntPtr ProgramIcon(string path)
    {
        if (programIcons.TryGetValue(path, out var icon)) return icon;
        PrivateExtractIconsW(path, 0, 32, 32, out icon, out _, 1, 0);
        if (icon == IntPtr.Zero) icon = CopyIcon(LoadIconW(IntPtr.Zero, new IntPtr(32512)));
        programIcons[path] = icon; return icon;
    }

    [DllImport("user32.dll", EntryPoint = "GetClassNameW", CharSet = CharSet.Unicode)]
    private static extern int PickerGetClassName(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("dwmapi.dll", EntryPoint = "DwmGetWindowAttribute")]
    private static extern int PickerGetWindowAttribute(IntPtr hwnd, uint attribute, out int value, int size);
}
