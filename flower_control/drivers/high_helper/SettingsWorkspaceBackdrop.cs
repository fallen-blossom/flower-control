namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private static IntPtr backdropDc, backdropBitmap, backdropPrevious;
    private static bool interactiveWindowMove, interactiveRasterResized;
    private static (IntPtr Window, int Width, int Height, uint Dpi, bool Contrast) backdropKey;

    private static bool EnsureBackdrop(IntPtr dc, int width, int height)
    {
        var key = (window, width, height, GetDpiForWindow(window), HighContrast());
        if (backdropDc != IntPtr.Zero && backdropKey == key) return true;
        // A native resize loop may deliver every pixel step. Keep the same
        // artwork raster for these transient dimensions, then regenerate on
        // WM_EXITSIZEMOVE. DPI/contrast/window changes never borrow this raster.
        if (interactiveWindowMove && !key.Item5 && backdropDc != IntPtr.Zero && backdropKey.Window == window
            && backdropKey.Dpi == key.Item4 && backdropKey.Contrast == key.Item5) return true;
        ReleaseBackdrop();
        if (width <= 0 || height <= 0) return false;
        var memory = CreateCompatibleDC(dc);
        var bitmap = memory == IntPtr.Zero ? IntPtr.Zero : CreateCompatibleBitmap(dc, width, height);
        if (bitmap == IntPtr.Zero) { if (memory != IntPtr.Zero) DeleteDC(memory); return false; }
        var previous = SelectObject(memory, bitmap);
        if (previous == IntPtr.Zero || previous == new IntPtr(-1))
        { DeleteObject(bitmap); DeleteDC(memory); return false; }
        backdropDc = memory; backdropBitmap = bitmap; backdropPrevious = previous;
        try { PaintBackdropUncached(memory, new Rect { Right = width, Bottom = height }); }
        catch { ReleaseBackdrop(); throw; }
        backdropKey = key; return true;
    }

    private static void ReleaseBackdrop()
    {
        if (backdropDc != IntPtr.Zero)
        {
            if (backdropPrevious != IntPtr.Zero) SelectObject(backdropDc, backdropPrevious);
            if (backdropBitmap != IntPtr.Zero) DeleteObject(backdropBitmap);
            DeleteDC(backdropDc);
        }
        backdropDc = backdropBitmap = backdropPrevious = IntPtr.Zero;
        backdropKey = default;
    }
}
