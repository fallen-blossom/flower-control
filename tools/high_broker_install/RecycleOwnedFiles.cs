using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// Installer-only exact-file recycling. RECYCLEONDELETE never falls back to a
// permanent delete; unsupported volumes, cancellation and failures are errors.
public static class FlowerUninstallRecycle
{
    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IShellItem
    {
        [PreserveSig] int BindToHandler(IntPtr context, ref Guid handler, ref Guid iid, out IntPtr value);
        [PreserveSig] int GetParent(out IShellItem parent);
        [PreserveSig] int GetDisplayName(uint displayName, out IntPtr name);
        [PreserveSig] int GetAttributes(uint mask, out uint attributes);
        [PreserveSig] int Compare(IShellItem other, uint hint, out int order);
    }
    [ComImport, Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IFileOperation
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
    class FileOperation { }
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, PreserveSig=false)]
    static extern void SHCreateItemFromParsingName(string path, IntPtr context, ref Guid iid,
        out IShellItem item);
    static void Check(int result) { Marshal.ThrowExceptionForHR(result); }
    public static void Recycle(string path, string expectedHash)
    {
        if(!Path.IsPathRooted(path) || path.StartsWith("\\\\",StringComparison.Ordinal) || path!=Path.GetFullPath(path)
            || !File.Exists(path) || expectedHash==null || expectedHash.Length!=64) throw new IOException("uninstall_recycle_scope_rejected");
        for(string cursor=path;cursor!=null;cursor=Path.GetDirectoryName(cursor))
            if((File.GetAttributes(cursor)&FileAttributes.ReparsePoint)!=0) throw new IOException("uninstall_recycle_link_rejected");
        string actual;
        using(var input=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read))
        using(var sha=SHA256.Create()) actual=BitConverter.ToString(sha.ComputeHash(input)).Replace("-","").ToLowerInvariant();
        if(actual!=expectedHash) throw new IOException("uninstall_recycle_file_changed");
        IShellItem item=null; IFileOperation operation=null;
        try {
            var iid=new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
            SHCreateItemFromParsingName(path,IntPtr.Zero,ref iid,out item);
            operation=(IFileOperation)new FileOperation();
            // Silent, no confirmation/error UI, forced recycle, early failure.
            Check(operation.SetOperationFlags(0x00180414));
            Check(operation.DeleteItem(item,IntPtr.Zero));
            Check(operation.PerformOperations());
            bool aborted; Check(operation.GetAnyOperationsAborted(out aborted));
            if(aborted || File.Exists(path)) throw new IOException("uninstall_recycle_unconfirmed");
        } finally {
            if(item!=null) Marshal.FinalReleaseComObject(item);
            if(operation!=null) Marshal.FinalReleaseComObject(operation);
        }
    }
}
