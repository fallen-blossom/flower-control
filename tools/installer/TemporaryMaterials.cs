using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace FlowerControl.Setup;

internal sealed record TemporaryTree(string Path, long Created, int Files, long Bytes);

internal static class TemporaryMaterials
{
    internal static TemporaryTree Inspect(string path)
    {
        path = System.IO.Path.GetFullPath(path);
        string parent = System.IO.Path.GetDirectoryName(path)!;
        if (!parent.Equals(System.IO.Path.GetTempPath().TrimEnd(System.IO.Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
            || !Regex.IsMatch(System.IO.Path.GetFileName(path), "^flower-(setup|install)-[a-f0-9]{32}$"))
            throw new IOException("临时材料不在本次安装器的准确临时目录范围内。");
        int files = 0; long bytes = 0;
        for (string? ancestor = path; ancestor is not null; ancestor = System.IO.Path.GetDirectoryName(ancestor))
            if ((File.GetAttributes(ancestor) & FileAttributes.ReparsePoint) != 0) throw new IOException("临时目录含链接，请保留并手动核对。");
        var pending = new Stack<string>(); pending.Push(path);
        while (pending.Count > 0)
            foreach (string entry in Directory.EnumerateFileSystemEntries(pending.Pop()))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("临时材料中出现链接，未回收。");
                if ((attributes & FileAttributes.Directory) != 0) pending.Push(entry);
                else { ++files; bytes += new FileInfo(entry).Length; }
            }
        return new(path, Directory.GetCreationTimeUtc(path).Ticks, files, bytes);
    }

    internal static void Recycle(TemporaryTree expected)
    {
        if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            throw new IOException("请从普通权限安装向导回收用户临时材料，未使用管理员权限清理。");
        if (Inspect(expected.Path) != expected) throw new IOException("临时材料在审阅后发生变化，请重新核对。");
        IShellItem? item = null; IFileOperation? operation = null;
        try
        {
            var iid = new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
            SHCreateItemFromParsingName(expected.Path, IntPtr.Zero, ref iid, out item);
            operation = (IFileOperation)new FileOperation();
            // Forced recycle and early failure; never use permanent fallback.
            Marshal.ThrowExceptionForHR(operation.SetOperationFlags(0x00180414));
            Marshal.ThrowExceptionForHR(operation.DeleteItem(item, IntPtr.Zero));
            Marshal.ThrowExceptionForHR(operation.PerformOperations());
            Marshal.ThrowExceptionForHR(operation.GetAnyOperationsAborted(out bool aborted));
            if (aborted || Directory.Exists(expected.Path)) throw new IOException("临时材料回收未确认完成；未改用永久删除。");
        }
        finally
        {
            if (item is not null) Marshal.ReleaseComObject(item);
            if (operation is not null) Marshal.ReleaseComObject(operation);
        }
    }

    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        [PreserveSig] int BindToHandler(IntPtr context, ref Guid handler, ref Guid iid, out IntPtr value);
        [PreserveSig] int GetParent(out IShellItem parent);
        [PreserveSig] int GetDisplayName(uint displayName, out IntPtr name);
        [PreserveSig] int GetAttributes(uint mask, out uint attributes);
        [PreserveSig] int Compare(IShellItem other, uint hint, out int order);
    }
    [ComImport, Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOperation
    {
        [PreserveSig] int Advise(IntPtr sink, out uint cookie);
        [PreserveSig] int Unadvise(uint cookie);
        [PreserveSig] int SetOperationFlags(uint flags);
        [PreserveSig] int SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string message);
        [PreserveSig] int SetProgressDialog(IntPtr dialog);
        [PreserveSig] int SetProperties(IntPtr properties);
        [PreserveSig] int SetOwnerWindow(uint window);
        [PreserveSig] int ApplyPropertiesToItem(IntPtr item);
        [PreserveSig] int ApplyPropertiesToItems(IntPtr items);
        [PreserveSig] int RenameItem(IntPtr item, IntPtr name, IntPtr sink);
        [PreserveSig] int RenameItems(IntPtr items, IntPtr name);
        [PreserveSig] int MoveItem(IntPtr item, IntPtr destination, IntPtr name, IntPtr sink);
        [PreserveSig] int MoveItems(IntPtr items, IntPtr destination);
        [PreserveSig] int CopyItem(IntPtr item, IntPtr destination, IntPtr name, IntPtr sink);
        [PreserveSig] int CopyItems(IntPtr items, IntPtr destination);
        [PreserveSig] int DeleteItem(IShellItem item, IntPtr sink);
        [PreserveSig] int DeleteItems(IntPtr items);
        [PreserveSig] int NewItem(IntPtr destination, uint attributes, IntPtr name, IntPtr template, IntPtr sink);
        [PreserveSig] int PerformOperations();
        [PreserveSig] int GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool aborted);
    }
    [ComImport, Guid("3AD05575-8857-4850-9277-11B85BDB8E09")]
    private class FileOperation { }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    private static extern void SHCreateItemFromParsingName(string path, IntPtr context, ref Guid iid, out IShellItem item);
}
