using System.Runtime.InteropServices;

namespace Flower.HighHelper;

internal static partial class SettingsWorkspace
{
    private sealed record WindowPlacement(IntPtr Window, IntPtr After, int X, int Y, int Width, int Height, uint Flags);
    private sealed class PositionBatch : IDisposable
    {
        internal readonly List<WindowPlacement> Rows = [];
        // Used only by the explicit synthetic UI fixture to exercise the same
        // native fallback before any placement, and after partial placement.
        internal Func<IReadOnlyList<WindowPlacement>, bool>? ApplyForFixture;
        public void Dispose() { if (ReferenceEquals(positionBatch, this)) FlushPositionBatch(); }
    }
    private static PositionBatch? positionBatch;

    private static PositionBatch? BeginPositionBatch(bool enabled)
    {
        if (!enabled || positionBatch is not null) return null;
        return positionBatch = new();
    }

    private static bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int width, int height, uint flags)
    {
        if (positionBatch is { } batch && GetParent(hwnd) == window)
        { batch.Rows.Add(new(hwnd, after, x, y, width, height, flags)); return true; }
        return SetWindowPosNative(hwnd, after, x, y, width, height, flags);
    }

    private static void FlushPositionBatch()
    {
        var batch = positionBatch; positionBatch = null;
        if (batch is null || batch.Rows.Count == 0) return;
        bool placed = batch.ApplyForFixture is { } fixture ? fixture(batch.Rows) : ApplyDeferredPositions(batch.Rows);
        // A failed End can have moved some children already. Reapplying the
        // original exact geometry/flags is idempotent; never leave half a row.
        if (!placed)
            foreach (var row in batch.Rows)
                SetWindowPosNative(row.Window, row.After, row.X, row.Y, row.Width, row.Height, row.Flags);
        // Preserve the original combo order: item heights are applied both
        // before and after the actual native size change, including fallback.
        foreach (var row in batch.Rows)
            if (pageControls.Any(c => c.Handle == row.Window && c.Kind == "COMBOBOX")) SizeComboItems(row.Window);
        SizeDecisionRows();
    }

    private static bool ApplyDeferredPositions(IReadOnlyList<WindowPlacement> rows)
    {
        var pending = BeginDeferWindowPos(rows.Count);
        foreach (var row in rows)
        {
            if (pending == IntPtr.Zero) return false;
            // On failure Windows destroys the deferred structure. Do not
            // call End with a discarded handle; fall back for the whole row.
            pending = DeferWindowPos(pending, row.Window, row.After, row.X, row.Y, row.Width, row.Height, row.Flags);
        }
        return pending != IntPtr.Zero && EndDeferWindowPos(pending);
    }

    private static IntPtr sceneDc, sceneBitmap, scenePrevious;
    private static (IntPtr Window, int Width, int Height, uint Dpi, bool Contrast) sceneGeometry;
    private sealed record SceneState(ChromePaintState? Chrome, int Layer, bool Denied, int Rows, bool Dirty, int Icon, bool Compact,
        string SavedMode, string CurrentNotice, string CurrentStatus, bool Fault, IntPtr FirstField, IntPtr LastField, string BodyFont, string DisplayFont);
    private static SceneState? sceneState;
    private sealed record ControlRasterKey(uint State, string Text, uint Dpi, bool Contrast, bool Compact,
        ChromePaintState? Chrome, int Layer, bool Denied, bool Selected);
    private sealed record ControlRaster(IntPtr Dc, IntPtr Bitmap, IntPtr Previous, int Width, int Height, ControlRasterKey Key);
    private static readonly Dictionary<IntPtr, ControlRaster> interactiveControls = [];

    private static bool PaintInteractiveControl(DrawItem item)
    {
        // Only a native drag/resize loop borrows a raster. Menus, rows and
        // editable controls retain their existing native painting throughout.
        if (!interactiveWindowMove || HighContrast() || item.Type is not (4 or 5)) return false;
        int width = item.Rect.Right - item.Rect.Left, height = item.Rect.Bottom - item.Rect.Top;
        if (width <= 0 || height <= 0) return false;
        var key = new ControlRasterKey(item.State, Text(item.Window), GetDpiForWindow(window), HighContrast(), CompactSurface,
            chromePaintState, ruleLayer, denied, IsPermissionChoice((int)item.Id) && PermissionChoiceSelected((int)item.Id));
        if (!interactiveControls.TryGetValue(item.Window, out var raster) || raster.Key != key)
        {
            if (raster is not null) { ReleaseControlRaster(raster); interactiveControls.Remove(item.Window); }
            var memory = CreateCompatibleDC(item.Dc);
            var bitmap = memory == IntPtr.Zero ? IntPtr.Zero : CreateCompatibleBitmap(item.Dc, width, height);
            if (bitmap == IntPtr.Zero) { if (memory != IntPtr.Zero) DeleteDC(memory); return false; }
            var previous = SelectObject(memory, bitmap);
            if (previous == IntPtr.Zero || previous == new IntPtr(-1)) { DeleteObject(bitmap); DeleteDC(memory); return false; }
            raster = new(memory, bitmap, previous, width, height, key);
            var cached = item; cached.Dc = memory; cached.Rect = new Rect { Right = width, Bottom = height };
            try { PaintNativeControl(cached); }
            catch { ReleaseControlRaster(raster); throw; }
            interactiveControls[item.Window] = raster;
        }
        return CopyRaster(item.Dc, item.Rect.Left, item.Rect.Top, width, height,
            raster.Dc, 0, 0, raster.Width, raster.Height, 0x00CC0020);
    }

    private static void ReleaseControlRaster(ControlRaster raster)
    {
        SelectObject(raster.Dc, raster.Previous); DeleteObject(raster.Bitmap); DeleteDC(raster.Dc);
    }

    private static void ReleaseInteractiveControls()
    {
        foreach (var raster in interactiveControls.Values) ReleaseControlRaster(raster);
        interactiveControls.Clear();
    }

    private static IntPtr StartupMonitor(IntPtr owner)
    {
        if (owner != IntPtr.Zero && IsWindow(owner) && IsWindowVisible(owner)) return MonitorFromWindow(owner, 2);
        GetCursorPos(out var anchor); return MonitorFromPoint(anchor, 2);
    }

    private static Rect CenterInWorkArea(Rect work, int width, int height)
    {
        width = Math.Clamp(width, 1, Math.Max(1, work.Right - work.Left));
        height = Math.Clamp(height, 1, Math.Max(1, work.Bottom - work.Top));
        int left = work.Left + (work.Right - work.Left - width) / 2;
        int top = work.Top + (work.Bottom - work.Top - height) / 2;
        return new Rect { Left = left, Top = top, Right = left + width, Bottom = top + height };
    }

    private static bool EnsureScene(IntPtr dc, int width, int height)
    {
        var geometry = (window, width, height, GetDpiForWindow(window), HighContrast());
        // Native error paths can invalidate directly, without UpdateChrome.
        var state = new SceneState(chromePaintState, ruleLayer, denied, RowCount, Dirty, workspaceIconState, CompactSurface, CurrentModeText(),
            VisibleNotice(), StatusLine(), surfaceFault,
            pageControls.FirstOrDefault()?.Handle ?? IntPtr.Zero, pageControls.LastOrDefault()?.Handle ?? IntPtr.Zero, BodyFace, DisplayFace);
        if (interactiveWindowMove && sceneDc != IntPtr.Zero && sceneGeometry.Window == window
            && sceneGeometry.Dpi == geometry.Item4 && sceneGeometry.Contrast == geometry.Item5 && !geometry.Item5
            && sceneState == state && sceneGeometry.Width > 0 && sceneGeometry.Height > 0 && height > 0
            && Math.Abs(width * sceneGeometry.Height / (height * (double)sceneGeometry.Width) - 1) <= .05)
            return true;
        if (sceneDc == IntPtr.Zero || geometry != sceneGeometry)
        {
            ReleaseScene();
            sceneDc = CreateCompatibleDC(dc);
            sceneBitmap = sceneDc == IntPtr.Zero ? IntPtr.Zero : CreateCompatibleBitmap(dc, width, height);
            if (sceneBitmap == IntPtr.Zero) { ReleaseScene(); return false; }
            scenePrevious = SelectObject(sceneDc, sceneBitmap);
            if (scenePrevious == IntPtr.Zero || scenePrevious == new IntPtr(-1)) { ReleaseScene(); return false; }
            sceneGeometry = geometry;
        }
        if (state != sceneState)
        {
            try { PaintScene(sceneDc); }
            catch { ReleaseScene(); throw; }
            sceneState = state;
        }
        return true;
    }

    private static void ReleaseScene()
    {
        if (sceneDc != IntPtr.Zero)
        {
            if (scenePrevious != IntPtr.Zero && scenePrevious != new IntPtr(-1)) SelectObject(sceneDc, scenePrevious);
            if (sceneBitmap != IntPtr.Zero) DeleteObject(sceneBitmap);
            DeleteDC(sceneDc);
        }
        sceneDc = sceneBitmap = scenePrevious = IntPtr.Zero;
        sceneState = null; sceneGeometry = default;
    }

    private static bool CopyRaster(IntPtr destination, int x, int y, int width, int height,
        IntPtr source, int sx, int sy, int sourceWidth, int sourceHeight, uint operation)
    {
        if (width == sourceWidth && height == sourceHeight) return BitBlt(destination, x, y, width, height, source, sx, sy, operation);
        int state = SaveDC(destination); if (state == 0) return false;
        try
        {
            SetStretchBltMode(destination, 4); // HALFTONE: avoid COLORONCOLOR/BLACKONWHITE reduction artifacts.
            SetBrushOrgEx(destination, 0, 0, IntPtr.Zero);
            return StretchBlt(destination, x, y, width, height, source, sx, sy, sourceWidth, sourceHeight, operation);
        }
        finally { RestoreDC(destination, state); }
    }

    [DllImport("user32.dll")] private static extern IntPtr MonitorFromPoint(Native.Point point, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern IntPtr BeginDeferWindowPos(int count);
    [DllImport("user32.dll")] private static extern IntPtr DeferWindowPos(IntPtr batch, IntPtr hwnd, IntPtr after, int x, int y, int width, int height, uint flags);
    [DllImport("user32.dll")] private static extern bool EndDeferWindowPos(IntPtr batch);
    [DllImport("shcore.dll")] private static extern int GetDpiForMonitor(IntPtr monitor, int kind, out uint x, out uint y);
    [DllImport("gdi32.dll")] private static extern bool StretchBlt(IntPtr dest, int x, int y, int width, int height,
        IntPtr source, int sx, int sy, int sourceWidth, int sourceHeight, uint operation);
    [DllImport("gdi32.dll")] private static extern int SetStretchBltMode(IntPtr dc, int mode);
    [DllImport("gdi32.dll")] private static extern bool SetBrushOrgEx(IntPtr dc, int x, int y, IntPtr previous);
}
