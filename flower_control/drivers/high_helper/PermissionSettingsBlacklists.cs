using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class PermissionSettingsWindow
{
    private static readonly List<UacApplicationPermission> deniedLaunchPrograms = [];
    private static readonly List<UacApplicationPermission> deniedUacPrograms = [];
    private static List<UacApplicationPermission> BlockedPrograms(ProgramListKind kind)
        => kind == ProgramListKind.Launch ? deniedLaunchPrograms : deniedUacPrograms;
    private static int BlockedControl(ProgramListKind kind, int offset)
        => (kind == ProgramListKind.Launch ? 3410 : 3420) + offset;
    private static string BlockedName(ProgramListKind kind)
        => kind == ProgramListKind.Launch ? "High 启动黑名单" : "UAC 确认黑名单";
    private static int BlockedSelection(ProgramListKind kind)
        => SendMessageW(controls[BlockedControl(kind, 2)], 0x188, IntPtr.Zero, IntPtr.Zero).ToInt32();

    private static void AddBlockedProgramControls(ProgramListKind kind)
    {
        Add(BlockedControl(kind, 1), "STATIC", BlockedName(kind), 20, 650, 680, 26);
        Add(BlockedControl(kind, 2), "LISTBOX", "", 20, 690, 680, 112, 0x00200000 | 0x100 | 1);
        Add(BlockedControl(kind, 3), "BUTTON", "选择程序并禁止…", 20, 814, 224, 36);
        Add(BlockedControl(kind, 4), "BUTTON", "移除选中", 254, 814, 224, 36);
        Add(BlockedControl(kind, 5), "BUTTON", "停用 / 启用", 488, 814, 212, 36);
        Add(BlockedControl(kind, 6), "STATIC", "", 20, 862, 680, 66);
    }

    private static void RefreshBlockedPrograms(ProgramListKind kind, int selected = -1)
    {
        var handle = controls[BlockedControl(kind, 2)];
        SendMessageW(handle, 0x184, IntPtr.Zero, IntPtr.Zero);
        foreach (var row in BlockedPrograms(kind))
            SendMessageW(handle, 0x180, IntPtr.Zero, (row.Enabled ? "禁止  " : "已停用  ") + row.Path);
        if (selected >= 0 && selected < BlockedPrograms(kind).Count)
            SendMessageW(handle, 0x186, new IntPtr(selected), IntPtr.Zero);
        UpdateBlockedProgramDetail(kind);
    }

    private static void UpdateBlockedProgramDetail(ProgramListKind kind)
    {
        int selected = BlockedSelection(kind); var rows = BlockedPrograms(kind);
        string explanation = "按完整路径拒绝，文件更新后仍拒绝；不按参数放宽。优先于本层白名单和语义授权。保存后生效，仅限制 Flower。";
        if (selected >= 0 && selected < rows.Count)
            explanation += "\r\n" + rows[selected].Path + (rows[selected].Enabled ? "（已启用）" : "（已停用）");
        SetWindowTextW(controls[BlockedControl(kind, 6)], explanation);
    }

    private static void UpdateBlockedProgramControls(bool writable)
    {
        foreach (var kind in new[] { ProgramListKind.Launch, ProgramListKind.Uac })
        {
            int selected = BlockedSelection(kind); var rows = BlockedPrograms(kind);
            bool hasSelection = selected >= 0 && selected < rows.Count;
            EnableWindow(controls[BlockedControl(kind, 2)], !UacBusy);
            EnableWindow(controls[BlockedControl(kind, 3)], writable && broker is not null && rows.Count < 128);
            EnableWindow(controls[BlockedControl(kind, 4)], writable && hasSelection);
            EnableWindow(controls[BlockedControl(kind, 5)], writable && hasSelection);
            UpdateBlockedProgramDetail(kind);
        }
    }

    private static void AddBlockedProgram(ProgramListKind kind)
    {
        EndUacWindowPick();
        var rows = BlockedPrograms(kind);
        if (preview || broker is null || UacBusy || !policyValid || rows.Count >= 128)
            throw new Boundary("permission_blacklist_unavailable");
        long generation = windowGeneration;
        var file = Marshal.AllocHGlobal(32768 * sizeof(char));
        string path;
        try
        {
            Marshal.Copy(new byte[32768 * sizeof(char)], 0, file, 32768 * sizeof(char));
            var picker = new OpenFileName { Size = (uint)Marshal.SizeOf<OpenFileName>(), Owner = window,
                Filter = "程序文件 (*.exe)\0*.exe\0所有文件 (*.*)\0*.*\0\0", File = file, FileLength = 32768,
                Title = "选择禁止的程序 · " + BlockedName(kind),
                Flags = 0x00080000 | 0x00001000 | 0x00000800 | 0x00000008 | 0x02000000 };
            if (!GetOpenFileNameW(ref picker))
            { if (CommDlgExtendedError() != 0) throw new Boundary("uac_file_picker_failed"); return; }
            path = Marshal.PtrToStringUni(file) ?? throw new Boundary("uac_file_picker_failed");
        }
        finally { Marshal.FreeHGlobal(file); }
        if (generation != windowGeneration || original is null || UacBusy || !policyValid)
            throw new Boundary("permission_blacklist_unavailable");
        // Denying a path does not authorize execution. Inspect its real identity
        // for storage, without the allowlist's protected-file/payload-host veto.
        var row = UacIdentity.Inspect(path) with { Enabled = true };
        var edited = kind == ProgramListKind.Launch
            ? original with { DeniedAdminLaunchApplications = [row] }
            : original with { DeniedUacApplications = [row] };
        UserPermissions.Validate(edited);
        int index = rows.FindIndex(prior => Path.GetFullPath(prior.Path).Equals(Path.GetFullPath(row.Path), StringComparison.OrdinalIgnoreCase));
        if (index >= 0) rows[index] = row;
        else { index = rows.Count; rows.Add(row); }
        RefreshBlockedPrograms(kind, index); UpdateUacControls();
        SetNotice(BlockedName(kind) + "已更新草稿，保存后生效；没有启动程序。");
        PositionControls(); UpdateScroll();
    }

    private static void EditBlockedProgram(ProgramListKind kind, bool remove)
    {
        if (UacBusy || !policyValid) throw new Boundary("permission_blacklist_unavailable");
        var rows = BlockedPrograms(kind); int index = BlockedSelection(kind);
        if (index < 0 || index >= rows.Count) return;
        if (remove) rows.RemoveAt(index);
        else rows[index] = rows[index] with { Enabled = !rows[index].Enabled };
        RefreshBlockedPrograms(kind, Math.Min(index, rows.Count - 1)); UpdateUacControls();
        SetNotice(BlockedName(kind) + "已更新草稿，保存后生效。");
        PositionControls(); UpdateScroll();
    }
}
