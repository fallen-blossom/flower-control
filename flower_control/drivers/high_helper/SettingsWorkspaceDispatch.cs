namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private const uint RebuildPageMessage = 0x8000 + 203;
    private static int nativeCallbackDepth, nativeCommandDepth;
    private static bool pageRebuildPending, pageRebuildPosted, surfaceClosePending;

    // A native control can synchronously notify its parent while comctl32 is
    // still using its subclass chain. Never destroy/recreate that chain from
    // the notification, or from a nested menu/dropdown message loop.
    private static bool DeferPageRebuild()
    {
        if (nativeCallbackDepth == 0 && nativeCommandDepth == 0 && appDialog is null)
        { pageRebuildPending = false; return false; }
        pageRebuildPending = true;
        PostPendingPageRebuild();
        return true;
    }

    private static void PostPendingPageRebuild()
    {
        if ((!pageRebuildPending && !surfaceClosePending) || pageRebuildPosted || window == IntPtr.Zero) return;
        if (!PostMessageW(window, RebuildPageMessage, UIntPtr.Zero, new IntPtr(generation)))
        {
            // This function is also called from a reverse-P/Invoke finally.
            // A managed exception must never escape that native boundary.
            pageRebuildPending = pageRebuildPosted = surfaceClosePending = false;
            surfaceFault = true; notice = UiText.Get("界面更新未完成，草稿保留。请重新载入。");
            EnableWindow(GetDlgItem(window, SaveId), false);
            InvalidateRect(window, IntPtr.Zero, false);
            try { Console.Error.WriteLine("settings_page_rebuild_queue_failed"); } catch { }
            return;
        }
        pageRebuildPosted = true;
    }

    private static void FinishNativeCallback()
    {
        --nativeCallbackDepth;
        if (nativeCallbackDepth == 0 && nativeCommandDepth == 0) PostPendingPageRebuild();
    }

    private static void NativeCallbackFailed(Exception error)
    {
        // Never retry DefSubclassProc: it may already have dispatched input.
        surfaceFault = true; notice = UiText.Get("界面回调未完成，草稿保留：") + Program.Code(error);
        if (window != IntPtr.Zero) { EnableWindow(GetDlgItem(window, SaveId), false); InvalidateRect(window, IntPtr.Zero, false); }
        try { Console.Error.WriteLine("settings_native_callback: " + Program.Code(error)); } catch { }
    }

    private static void CompletePageRebuild(IntPtr hwnd, IntPtr expected)
    {
        if (hwnd != window || expected.ToInt64() != generation) return;
        pageRebuildPosted = false;
        if (nativeCallbackDepth != 0 || nativeCommandDepth != 0 || appDialog is not null) return;
        if (surfaceClosePending) { surfaceClosePending = false; DestroyWindow(window); return; }
        if (!pageRebuildPending) return;
        pageRebuildPending = false;
        BuildPage(); UpdateChrome();
    }

    private static void CloseSurfaceSafely()
    {
        if (window == IntPtr.Zero) return;
        if (nativeCallbackDepth == 0 && nativeCommandDepth == 0 && appDialog is null)
        { DestroyWindow(window); return; }
        surfaceClosePending = true;
        if (appDialog is { } dialog)
        {
            dialog.Result = dialog.Cancel;
            // A readonly EDIT's context menu belongs to this dialog root,
            // rather than the main settings window. End that nested loop too.
            if (dialog.Window != IntPtr.Zero && IsWindow(dialog.Window))
                PostMessageW(dialog.Window, 0x1F, UIntPtr.Zero, IntPtr.Zero);
        }
        PostPendingPageRebuild();
        // Dismiss only menus owned by this settings window so an async
        // save-and-close does not wait indefinitely inside TrackPopupMenu.
        PostMessageW(window, 0x1F, UIntPtr.Zero, IntPtr.Zero);
    }
}
