using System.Reflection;
using System.Runtime.InteropServices;

namespace Flower.HighHelper;

// Fixed, user-supplied artwork decoded locally through GDI+. No network, no
// image generation, no per-petal masks. Missing or undecodable assets fall back
// to the previous solid painting instead of failing the settings window.
internal sealed class SettingsArtwork : IDisposable
{
    private readonly UIntPtr token;
    private readonly List<Image> images = [];
    internal Image? Background { get; }
    internal Image? DimFlower { get; }
    internal Image? FlowerStates { get; }
    internal Image? Controls { get; }
    internal Image? Brand { get; }
    internal Image? QuietLeaf { get; }

    private SettingsArtwork()
    {
        var startup = new GdiStartup { Version = 1 };
        Check(GdiplusStartup(out token, ref startup, IntPtr.Zero), "gdi_startup");
        try
        {
            Background = TryLoad("Flower.Settings.background.png");
            DimFlower = TryLoad("Flower.Settings.flower-dim.png");
            FlowerStates = TryLoad("Flower.Settings.flower-states.png");
            Controls = TryLoad("Flower.Settings.controls.png");
            Brand = TryLoad("Flower.Settings.brand.png");
            QuietLeaf = TryLoad("Flower.Settings.quiet-leaf.png");
        }
        catch { Dispose(); throw; }
    }

    internal static SettingsArtwork? TryCreate()
    {
        try { return new SettingsArtwork(); }
        catch { return null; }
    }

    internal bool HasFlower => DimFlower is not null && FlowerStates is not null;

    private static Native.Rect Rect(int left, int top, int width, int height)
        => new() { Left = left, Top = top, Right = left + width, Bottom = top + height };

    private Image? TryLoad(string name)
    {
        try
        {
            using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
            if (resource is null) return null;
            var image = new Image(resource);
            images.Add(image);
            return image;
        }
        catch { return null; }
    }

    // Alpha keeps the original dark surface underneath, so text contrast does
    // not depend on wherever the artwork happens to be light.
    internal void DrawBackground(IntPtr dc, Native.Rect rect, float alpha)
        => Background?.DrawCover(dc, rect, alpha);

    internal void DrawBrand(IntPtr dc, Native.Rect rect) => Brand?.Draw(dc, rect);
    internal void DrawQuietLeaf(IntPtr dc, Native.Rect rect, bool enabled)
    {
        // The generated PNG is preserved byte-for-byte, including its alpha.
        // Bounds trim transparent padding at draw time; no raster rewrite.
        if (QuietLeaf is null) { DrawControl(dc, rect, "leaf", enabled); return; }
        QuietLeaf.Draw(dc, rect, Rect(66, 9, 2028, 707), enabled ? 1 : .55f);
    }

    internal void DrawFlower(IntPtr dc, Native.Rect rect, int tier)
    {
        int width = rect.Right - rect.Left, height = rect.Bottom - rect.Top;
        if (width <= 0 || height <= 0) return;
        if (tier < 0 || DimFlower is null) { DimFlower?.Draw(dc, rect, alpha: 0.95f, keyBlack: true); return; }
        if (FlowerStates is null || tier > 3) return;
        // Each quadrant is one complete user-supplied flower. Never crop petals.
        int halfWidth = FlowerStates.Width / 2, halfHeight = FlowerStates.Height / 2;
        int state = AuthorityPresentation.FlowerState(tier);
        FlowerStates.Draw(dc, rect, Rect((state % 2) * halfWidth, (state / 2) * halfHeight, halfWidth, halfHeight), 0.95f, keyBlack: true);
    }

    internal void DrawControl(IntPtr dc, Native.Rect rect, string kind, bool enabled = true)
    {
        // Fixed sprite regions of the user-supplied sheet. The images contain
        // no text: names, focus and native hit targets remain live controls.
        var source = kind switch {
            "leaf" => Rect(20, 495, 1225, 445),
            "stop" => Rect(50, 950, 1160, 270),
            _ => Rect(490, 20, 255, 450) };
        double fit = Math.Min((rect.Right - rect.Left) / (double)(source.Right - source.Left),
            (rect.Bottom - rect.Top) / (double)(source.Bottom - source.Top));
        int width = (int)Math.Round((source.Right - source.Left) * fit), height = (int)Math.Round((source.Bottom - source.Top) * fit);
        int left = rect.Left + (rect.Right - rect.Left - width) / 2, top = rect.Top + (rect.Bottom - rect.Top - height) / 2;
        Controls?.Draw(dc, Rect(left, top, width, height), source, enabled ? 1 : .55f, brightness: kind == "stop" ? .72f : 1);
    }

    public void Dispose()
    {
        foreach (var image in images) image.Dispose();
        images.Clear();
        if (token != UIntPtr.Zero) GdiplusShutdown(token);
    }

    internal static void PlaceVisible(IntPtr hwnd, int width, int height)
    {
        SetWindowPos(hwnd, IntPtr.Zero, 40, 40, width, height, 0x14);
        ShowWindow(hwnd, 5);   // SW_SHOW, on-screen so the composited paint is real
        UpdateWindow(hwnd);
        Thread.Sleep(600);
    }

    internal static void PlaceOffscreen(IntPtr hwnd, int width, int height)
    {
        SetWindowPos(hwnd, IntPtr.Zero, -32000, -32000, width, height, 0x14 | 0x40);
        ShowWindow(hwnd, 4);   // SW_SHOWNOACTIVATE
        UpdateWindow(hwnd);
        Thread.Sleep(250);
    }

    internal static void SaveWindowPng(IntPtr hwnd, int width, int height, string path)
    {
        var screen = GetDC(hwnd);
        if (screen == IntPtr.Zero) throw new InvalidOperationException("window_dc_unavailable");
        var memory = CreateCompatibleDC(screen);
        if (memory == IntPtr.Zero) throw new InvalidOperationException("memory_dc_unavailable");
        var bitmap = CreateCompatibleBitmap(screen, width, height);
        ReleaseDC(hwnd, screen);
        if (bitmap == IntPtr.Zero) { DeleteDC(memory); throw new InvalidOperationException("bitmap_unavailable"); }
        var previous = SelectObject(memory, bitmap);
        try
        {
            if (!PrintWindow(hwnd, memory, 2))
                throw new InvalidOperationException("print_window_failed");
            Check(GdipCreateBitmapFromHBITMAP(bitmap, IntPtr.Zero, out var image), "bitmap_image");
            try
            {
                var png = PngEncoderGuid;
                Check(GdipSaveImageToFile(image, path, ref png, IntPtr.Zero), "png_save");
            }
            finally { GdipDisposeImage(image); }
        }
        finally
        {
            SelectObject(memory, previous);
            DeleteObject(bitmap);
            DeleteDC(memory);
        }
    }

    // Fixed GDI+ PNG encoder CLSID; avoids marshalling the codec table.
    private static readonly Guid PngEncoderGuid = new("557CF406-1A04-11D3-9A73-0000F81EF32E");

    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] private static extern bool UpdateWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr hwnd, IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int width, int height);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdiplus.dll")] private static extern int GdipCreateBitmapFromHBITMAP(IntPtr bitmap, IntPtr palette, out IntPtr image);

    private static void Check(int status, string code)
    { if (status != 0) throw new InvalidOperationException(code); }

    [StructLayout(LayoutKind.Sequential)] private struct GdiStartup { public uint Version; public IntPtr Callback; public IntPtr Unused; }
    [DllImport("gdiplus.dll")] private static extern int GdiplusStartup(out UIntPtr token, ref GdiStartup input, IntPtr output);
    [DllImport("gdiplus.dll")] private static extern void GdiplusShutdown(UIntPtr token);
    [DllImport("gdiplus.dll")] internal static extern int GdipCreateFromHDC(IntPtr dc, out IntPtr graphics);
    [DllImport("gdiplus.dll")] internal static extern int GdipDeleteGraphics(IntPtr graphics);
    [DllImport("gdiplus.dll")] internal static extern int GdipSetInterpolationMode(IntPtr graphics, int mode);
    [DllImport("gdiplus.dll")] internal static extern int GdipSetPixelOffsetMode(IntPtr graphics, int mode);
    [DllImport("gdiplus.dll")] internal static extern int GdipLoadImageFromStream(IntPtr stream, out IntPtr image);
    [DllImport("gdiplus.dll")] internal static extern int GdipDisposeImage(IntPtr image);
    [DllImport("gdiplus.dll")] internal static extern int GdipGetImageWidth(IntPtr image, out uint width);
    [DllImport("gdiplus.dll")] internal static extern int GdipGetImageHeight(IntPtr image, out uint height);
    [DllImport("gdiplus.dll")] internal static extern int GdipCreateImageAttributes(out IntPtr attributes);
    [DllImport("gdiplus.dll")] internal static extern int GdipDisposeImageAttributes(IntPtr attributes);
    [DllImport("gdiplus.dll")] internal static extern int GdipSetImageAttributesColorMatrix(IntPtr attributes, int type, bool enable, float[] matrix, IntPtr gray, int flags);
    [DllImport("gdiplus.dll")] internal static extern int GdipDrawImageRectRectI(IntPtr graphics, IntPtr image, int dx, int dy, int dw, int dh,
        int sx, int sy, int sw, int sh, int unit, IntPtr attributes, IntPtr callback, IntPtr callbackData);
    [DllImport("gdiplus.dll", CharSet = CharSet.Unicode)] internal static extern int GdipSaveImageToFile(IntPtr image, string filename, ref Guid encoder, IntPtr parameters);
    [DllImport("gdiplus.dll")] internal static extern int GdipGetImageEncodersSize(out uint count, out uint size);
    [DllImport("gdiplus.dll")] internal static extern int GdipGetImageEncoders(uint count, uint size, IntPtr encoders);
    [DllImport("shlwapi.dll")] internal static extern IntPtr SHCreateMemStream(byte[]? data, uint length);

    internal sealed class Image : IDisposable
    {
        private IntPtr image, stream;
        internal int Width { get; }
        internal int Height { get; }

        internal Image(Stream resource)
        {
            using var memory = new MemoryStream();
            resource.CopyTo(memory);
            var bytes = memory.ToArray();
            stream = SHCreateMemStream(bytes, (uint)bytes.Length);
            if (stream == IntPtr.Zero) throw new InvalidOperationException("asset_stream_failed");
            try
            {
                Check(GdipLoadImageFromStream(stream, out image), "decode_asset");
                Check(GdipGetImageWidth(image, out uint width), "asset_width");
                Check(GdipGetImageHeight(image, out uint height), "asset_height");
                Width = checked((int)width); Height = checked((int)height);
            }
            catch { Dispose(); throw; }
        }

        internal void DrawCover(IntPtr dc, Native.Rect dest, float alpha)
        {
            int width = dest.Right - dest.Left, height = dest.Bottom - dest.Top;
            if (width <= 0 || height <= 0 || Width <= 0 || Height <= 0) return;
            double scale = Math.Max((double)width / Width, (double)height / Height);
            int cropWidth = Math.Min(Width, (int)Math.Round(width / scale));
            int cropHeight = Math.Min(Height, (int)Math.Round(height / scale));
            Draw(dc, dest, Rect(Math.Max(0, (Width - cropWidth) / 2), Math.Max(0, (Height - cropHeight) / 2),
                cropWidth, cropHeight), alpha);
        }

        internal void Draw(IntPtr dc, Native.Rect dest, Native.Rect? source = null, float alpha = 1, bool keyBlack = false, float brightness = 1)
        {
            int width = dest.Right - dest.Left, height = dest.Bottom - dest.Top;
            if (width <= 0 || height <= 0 || alpha <= 0) return;
            Check(GdipCreateFromHDC(dc, out var graphics), "graphics");
            IntPtr attributes = IntPtr.Zero;
            try
            {
                Check(GdipSetInterpolationMode(graphics, 7), "interpolation");
                Check(GdipSetPixelOffsetMode(graphics, 4), "pixel_offset");
                if (alpha < 1 || keyBlack || brightness < 1)
                {
                    Check(GdipCreateImageAttributes(out attributes), "image_attributes");
                    if (alpha < 1 || brightness < 1)
                    {
                        float[] matrix = [brightness,0,0,0,0, 0,brightness,0,0,0, 0,0,brightness,0,0, 0,0,0,alpha,0, 0,0,0,0,1];
                        Check(GdipSetImageAttributesColorMatrix(attributes, 1, true, matrix, IntPtr.Zero, 0), "image_matrix");
                    }
                    // The supplied RGB atlases have an almost-black matte (0..8).
                    // Remove that matte during compositing, keeping original sprite
                    // geometry and state pixels instead of using regenerated flowers.
                    if (keyBlack) Check(GdipSetImageAttributesColorKeys(attributes, 1, true, 0xFF000000, 0xFF080808), "image_black_matte");
                }
                var src = source ?? Rect(0, 0, Width, Height);
                int sourceWidth = src.Right - src.Left, sourceHeight = src.Bottom - src.Top;
                Check(GdipDrawImageRectRectI(graphics, image, dest.Left, dest.Top, width, height,
                    src.Left, src.Top, sourceWidth, sourceHeight, 2, attributes, IntPtr.Zero, IntPtr.Zero), "draw_asset");
            }
            finally
            {
                if (attributes != IntPtr.Zero) GdipDisposeImageAttributes(attributes);
                GdipDeleteGraphics(graphics);
            }
        }

        public void Dispose()
        {
            if (image != IntPtr.Zero) { GdipDisposeImage(image); image = IntPtr.Zero; }
            if (stream != IntPtr.Zero) { Marshal.Release(stream); stream = IntPtr.Zero; }
        }
    }
    [DllImport("gdiplus.dll")] private static extern int GdipSetImageAttributesColorKeys(IntPtr attributes, int type, bool enabled, uint low, uint high);
}

