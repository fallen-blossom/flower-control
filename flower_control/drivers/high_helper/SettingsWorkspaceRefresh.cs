using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static bool pageLayoutDirty = true;
    private static bool chromeLayoutDirty = true;
    private static bool surfaceRedrawSuspended;
    private static (IntPtr Window, int Width, int Height, uint Dpi) chromeGeometry;
    private sealed record ChromePaintState(int EffectiveTier, int DraftTier, PrivacyMask[] Masks,
        int Page, string Mode, string Status, string Notice, string Title, string Lead);
    private static ChromePaintState? chromePaintState;

    private static bool NeedsChromeLayout()
    {
        GetClientRect(window, out var client);
        var geometry = (window, client.Right, client.Bottom, GetDpiForWindow(window));
        bool changed = chromeLayoutDirty || geometry != chromeGeometry;
        chromeLayoutDirty = false;
        chromeGeometry = geometry;
        return changed;
    }

    private static void EnableChromeControl(IntPtr handle, bool enabled)
    {
        if (handle != IntPtr.Zero && IsWindowEnabled(handle) != enabled) EnableWindow(handle, enabled);
    }

    private static void SetChromeText(IntPtr handle, string text)
    {
        if (handle != IntPtr.Zero && Text(handle) != text) SetWindowTextW(handle, text);
    }

    private static void ShowChromeControl(IntPtr handle, bool visible)
    {
        if (handle != IntPtr.Zero && ((GetWindowLongW(handle, -16) & 0x10000000) != 0) != visible)
            ShowWindow(handle, visible ? 8 : 0); // SW_SHOWNA: revealing a child never activates its top-level window.
    }

    private static void RefreshChromePaint(bool layout, bool pageChanged)
    {
        var next = new ChromePaintState(model.EffectiveTier, tier, draft.Masks,
            page,
            CurrentModeText(),
            CompactSurface && preview && !Dirty ? UiText.Get("预览 · 合成数据") : StatusLine(),
            VisibleNotice(), PageTitle(), PageLead());
        var previous = chromePaintState;
        chromePaintState = next;
        if (layout || previous is null || previous.EffectiveTier != next.EffectiveTier)
        {
            InvalidateRect(window, IntPtr.Zero, false);
            foreach (var child in Children()) InvalidateRect(child, IntPtr.Zero, false);
            return;
        }
        if (previous.DraftTier != next.DraftTier)
            for (int i = 0; i < 4; i++) InvalidateRect(GetDlgItem(window, TierBase + i), IntPtr.Zero, false);
        if (previous.Page != next.Page)
        {
            InvalidateRect(GetDlgItem(window, NavBase + previous.Page), IntPtr.Zero, false);
            InvalidateRect(GetDlgItem(window, NavBase + next.Page), IntPtr.Zero, false);
        }
        // Rebuilding page fields must not invalidate the flower or fixed chrome.
        if (pageChanged) InvalidateChrome(Layout.PageContent);
        if (previous.Masks != next.Masks && PageHandle(MaskListId) != IntPtr.Zero)
            InvalidateRect(PageHandle(MaskListId), IntPtr.Zero, false);
        if (previous.Mode != next.Mode) InvalidateChrome(Layout.CurrentMode);
        if (previous.Status != next.Status) InvalidateChrome(Layout.Status);
        if (previous.Notice != next.Notice) InvalidateChrome(Layout.Notice);
        if (previous.Title != next.Title) InvalidateChrome(Layout.PageTitle);
        if (previous.Lead != next.Lead) InvalidateChrome(Layout.PageLead);
    }

    private static void InvalidateChrome(Rect rectangle)
        => InvalidateChromeRegion(window, ref rectangle, false);

    // New fields stay hidden until UpdateChrome positions the complete page.
    // Coalesce parent painting on this UI thread; WM_SETREDRAW on the root
    // removes WS_VISIBLE and makes a live settings window stop hit-testing.
    private static void SuspendSurfaceRedraw()
    {
        if (surfaceRedrawSuspended || window == IntPtr.Zero || !IsWindowVisible(window)) return;
        surfaceRedrawSuspended = true;
    }

    private static void ResumeSurfaceRedraw(bool repaint = true)
    {
        if (!surfaceRedrawSuspended) return;
        surfaceRedrawSuspended = false;
        if (window == IntPtr.Zero) return;
        // Repaint after the complete layout, including new children and native
        // frames. Keep it asynchronous; PrintWindow/UpdateWindow would conceal
        // the missing screen invalidation which made logical navigation pass.
        if (repaint) RedrawSettingsSurface(window, IntPtr.Zero, IntPtr.Zero, 0x485);
    }
    [DllImport("user32.dll", EntryPoint = "InvalidateRect")]
    private static extern bool InvalidateChromeRegion(IntPtr hwnd, ref Rect rectangle, bool erase);
    [DllImport("user32.dll", EntryPoint = "RedrawWindow")]
    private static extern bool RedrawSettingsSurface(IntPtr hwnd, IntPtr rectangle, IntPtr region, uint flags);
    [DllImport("user32.dll")] private static extern uint GetWindowLongW(IntPtr hwnd, int index);
}
