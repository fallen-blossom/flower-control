using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using Windows.Foundation;
using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.DirectX.Direct3D11;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using WinRT;

// One authorized request per process. The Python worker owns the Windows Job,
// parent-death/stop monitor, and the pre/post permission and geometry checks.
// This child only captures the already bound HWND; no picker or disk I/O.
internal static class Program
{
    private const int MaxPixels = 3840 * 2160;
    private const string NonceProperty = "FlowerControl.WindowNonce.v1";
    private static readonly Guid CaptureItemIid = new("79C3F95B-31F7-4EC2-A464-632EF5D30760");
    private static readonly Guid CaptureInteropIid = new("3628E81B-3CAC-4C60-B7F4-23CE0E0C3356");
    private static readonly Guid DxgiDeviceIid = new("54EC77FA-1377-44E6-8C32-88FD5F44C84C");
    private static readonly HashSet<string> SafeErrors = new(StringComparer.Ordinal) {
        "dpi_context_unavailable", "invalid_request_size", "invalid_request_shape",
        "invalid_request_identity", "target_identity_changed", "target_process_changed",
        "target_geometry_invalid", "target_geometry_changed", "wgc_unsupported",
        "frame_format_or_size_invalid", "frame_stride_invalid", "frame_buffer_incomplete",
        "fresh_frame_timeout"
    };

    private static async Task<int> Main(string[] args)
    {
        try
        {
            if (!SetProcessDpiAwarenessContext((nint)(-4)))
                throw new InvalidOperationException("dpi_context_unavailable");
            if (args.Length > 1 || (args.Length == 1 && args[0] != "--session"))
                throw new InvalidOperationException("invalid_request_shape");
            string? line = Console.ReadLine();
            if (line is null) return 0;
            if (line.Length > 2048)
                throw new InvalidOperationException("invalid_request_size");
            using JsonDocument document = JsonDocument.Parse(line);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 4)
                throw new InvalidOperationException("invalid_request_shape");
            int pid = root.GetProperty("pid").GetInt32();
            long hwndValue = root.GetProperty("hwnd").GetInt64();
            long nonce = root.GetProperty("window_nonce").GetInt64();
            string created = root.GetProperty("process_created").GetString() ?? "";
            if (pid <= 0 || hwndValue <= 0 || nonce <= 0 || created.Length is < 15 or > 64)
                throw new InvalidOperationException("invalid_request_identity");
            // pywin32's CreationTime ISO value is rounded to milliseconds.
            long createdMilliseconds = DateTimeOffset.Parse(created, CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind).UtcTicks / 10_000;
            nint hwnd = (nint)hwndValue;
            TargetSnapshot snapshot = ValidateTarget(hwnd, pid, nonce, createdMilliseconds);
            if (args.Length == 1)
                return await RunCaptureSession(hwnd, pid, nonce, createdMilliseconds, snapshot);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            byte[] bmp = await CaptureBmp(hwnd, deadline.Token);
            if (ValidateTarget(hwnd, pid, nonce, createdMilliseconds) != snapshot)
                throw new InvalidOperationException("target_geometry_changed");
            await Console.OpenStandardOutput().WriteAsync(bmp);
            return 0;
        }
        catch (Exception error)
        {
            // Exception messages may contain target content or system paths.
            string code = error is InvalidOperationException && SafeErrors.Contains(error.Message)
                ? error.Message : "wgc_error";
            if (args.Length == 1) Diagnostic("error", code: code);
            else Console.Error.WriteLine(code);
            return 3;
        }
    }

    // Internal F1 mode: fixed target, resources reused for at most eight seconds.
    // No production MCP entry selects this mode until its live probe is verified.
    private static async Task<int> RunCaptureSession(nint hwnd, int pid, long nonce,
                                                    long created, TargetSnapshot snapshot)
    {
        using var lifetime = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var capture = new PersistentCapture(hwnd);
        Diagnostic("session_ready", qpc_frequency: Stopwatch.Frequency);
        Stream output = Console.OpenStandardOutput();
        int requestId = 0;
        while (true)
        {
            string? line;
            try { line = await Console.In.ReadLineAsync(lifetime.Token); }
            catch (OperationCanceledException) { return 0; }
            if (line is null) return 0;
            if (line.Length > 256) throw new InvalidOperationException("invalid_request_size");
            using JsonDocument request = JsonDocument.Parse(line);
            JsonElement root = request.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 2 ||
                root.GetProperty("op").GetString() != "frame" ||
                root.GetProperty("request_id").GetInt32() != ++requestId || requestId > 16)
                throw new InvalidOperationException("invalid_request_shape");
            if (ValidateTarget(hwnd, pid, nonce, created) != snapshot)
                throw new InvalidOperationException("target_geometry_changed");
            Diagnostic("request_received", requestId);
            var timer = Stopwatch.StartNew();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            deadline.CancelAfter(TimeSpan.FromSeconds(3));
            var frame = await capture.NextBmp(requestId, deadline.Token);
            if (ValidateTarget(hwnd, pid, nonce, created) != snapshot)
                throw new InvalidOperationException("target_geometry_changed");
            Marshal.ThrowExceptionForHR(DwmGetWindowAttribute(hwnd, 9, out Rect visible, Marshal.SizeOf<Rect>()));
            int width = BitConverter.ToInt32(frame.Bmp, 18), height = -BitConverter.ToInt32(frame.Bmp, 22);
            if (visible.Right - visible.Left != width || visible.Bottom - visible.Top != height)
                throw new InvalidOperationException("frame_format_or_size_invalid");
            byte[] header = JsonSerializer.SerializeToUtf8Bytes(new {
                request_id = requestId, frame_id = frame.Id, captured_ticks = frame.Ticks,
                capture_mode = "request_started_snapshot", snapshot_id = requestId,
                requested_ticks = frame.Requested, acquired_ticks = frame.Acquired,
                source_rendered_after_request = frame.Ticks > frame.Requested,
                timestamp_frequency = TimeSpan.TicksPerSecond, bmp_bytes = frame.Bmp.Length,
                width, height, source_bounds = new[] { visible.Left, visible.Top, visible.Right, visible.Bottom },
                elapsed_ms = timer.Elapsed.TotalMilliseconds, content_verified = false
            });
            await output.WriteAsync(BitConverter.GetBytes(header.Length), deadline.Token);
            await output.WriteAsync(header, deadline.Token);
            await output.WriteAsync(frame.Bmp, deadline.Token);
            await output.FlushAsync(deadline.Token);
            Diagnostic("frame_written", requestId, frame.Id, frame.Ticks);
        }
    }

    private sealed class PersistentCapture : IDisposable
    {
        private IDirect3DDevice? device;
        private Direct3D11CaptureFramePool? pool;
        private GraphicsCaptureSession? session;
        private GraphicsCaptureItem? item;
        private readonly object gate = new();
        private TaskCompletionSource<(Direct3D11CaptureFrame Frame, long Id, long Ticks, long Acquired)>? pending;
        private long frameId;
        private long requestedRelativeTicks;
        private long idleFrames, lastCompositorTicks;
        private bool disposed;

        public PersistentCapture(nint hwnd)
        {
            try {
                if (!GraphicsCaptureSession.IsSupported())
                    throw new InvalidOperationException("wgc_unsupported");
                item = CreateItemForWindow(hwnd);
                device = CreateDevice();
            }
            catch { Dispose(); throw; }
        }

        private void OnFrame(Direct3D11CaptureFramePool sender,
                            TaskCompletionSource<(Direct3D11CaptureFrame Frame, long Id, long Ticks, long Acquired)> request,
                            int requestId)
        {
            lock (gate) {
                if (disposed) return;
                try {
                    Direct3D11CaptureFrame? frame = sender.TryGetNextFrame();
                    if (frame is null) return;
                    long id = ++frameId;
                    // Idle frames are drained and disposed, never queued or retained.
                    long captured = frame.SystemRelativeTime.Ticks;
                    lastCompositorTicks = captured;
                    if (!ReferenceEquals(pending, request)) { idleFrames++; frame.Dispose(); }
                    // This pool was created and this snapshot session started
                    // for the pending request. A static source can keep its
                    // old render timestamp; never replace it with receipt time.
                    else if (!pending.TrySetResult((frame, id, captured, RelativeTicks())))
                        frame.Dispose();
                }
                catch (Exception error) {
                    DiagnosticError("frame_read", requestId, error);
                    request.TrySetException(error);
                }
            }
        }

        public async Task<(byte[] Bmp, long Id, long Ticks, long Requested, long Acquired)> NextBmp(int requestId, CancellationToken token)
        {
            var ready = new TaskCompletionSource<(Direct3D11CaptureFrame Frame, long Id, long Ticks, long Acquired)>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            lock (gate) {
                ObjectDisposedException.ThrowIf(disposed, this);
                if (pending is not null) throw new InvalidOperationException("invalid_request_shape");
            }
            // Match the single-snapshot lifecycle: retain device/item/process,
            // create a new pool and session per request, close both afterwards.
            // A previously closed snapshot session is not reused via Recreate.
            TypedEventHandler<Direct3D11CaptureFramePool, object> callback =
                (sender, _) => OnFrame(sender, ready, requestId);
            using var cancel = token.Register(() => ready.TrySetCanceled(token));
            try {
                pool = CapturePhase("pool_create", requestId, () =>
                    Direct3D11CaptureFramePool.CreateFreeThreaded(device!,
                        DirectXPixelFormat.B8G8R8A8UIntNormalized, 1, item!.Size));
                pool.FrameArrived += callback;
                session = CapturePhase("session_create", requestId, () => pool.CreateCaptureSession(item!));
                lock (gate) {
                    requestedRelativeTicks = RelativeTicks();
                    pending = ready;
                }
                CapturePhase("capture_start", requestId, () => {
                    session.StartCapture(); return true; // Preserve the ordinary capture border.
                });
                Diagnostic("snapshot_started", requestId, requested_ticks: requestedRelativeTicks);
                while (!ready.Task.IsCompleted) {
                    await Task.WhenAny(ready.Task, Task.Delay(500, token));
                    lock (gate) {
                        Diagnostic("frame_wait", requestId, frameId, lastCompositorTicks,
                            requestedRelativeTicks, idleFrames, 0);
                    }
                }
                var arrived = await ready.Task;
                using (arrived.Frame) {
                    byte[] bmp;
                    try { bmp = await EncodeFrame(arrived.Frame, token); }
                    catch (Exception error) { DiagnosticError("frame_encode", requestId, error); throw; }
                    return (bmp, arrived.Id, arrived.Ticks, requestedRelativeTicks, arrived.Acquired);
                }
            }
            catch (OperationCanceledException) {
                lock (gate) {
                    Diagnostic("fresh_frame_timeout", requestId, frameId, lastCompositorTicks,
                        requestedRelativeTicks, idleFrames, 0, "fresh_frame_timeout");
                }
                throw new InvalidOperationException("fresh_frame_timeout");
            }
            finally {
                lock (gate) { pending = null; }
                if (pool is not null) pool.FrameArrived -= callback;
                try {
                    CapturePhase("session_close", requestId, () => { session?.Dispose(); return true; });
                }
                finally {
                    session = null;
                    try { CapturePhase("pool_close", requestId, () => { pool?.Dispose(); return true; }); }
                    finally { pool = null; }
                }
            }
        }

        public void Dispose()
        {
            lock (gate) {
                if (disposed) return;
                disposed = true;
                pending?.TrySetCanceled();
            }
            session?.Dispose(); pool?.Dispose(); device?.Dispose();
        }
    }

    private static T CapturePhase<T>(string stage, int requestId, Func<T> operation)
    {
        Diagnostic(stage, requestId);
        try { return operation(); }
        catch (Exception error) { DiagnosticError(stage, requestId, error); throw; }
    }

    private static void DiagnosticError(string stage, int requestId, Exception error)
    {
        string kind = error switch {
            COMException => "COMException",
            ObjectDisposedException => "ObjectDisposedException",
            InvalidOperationException => "InvalidOperationException",
            OperationCanceledException => "OperationCanceledException",
            ArgumentException => "ArgumentException",
            _ => "OtherException"
        };
        Diagnostic(stage, requestId, code: "wgc_error", hresult: unchecked((uint)error.HResult), error_type: kind);
    }

    private static long RelativeTicks() => (long)(Stopwatch.GetTimestamp() *
        ((double)TimeSpan.TicksPerSecond / Stopwatch.Frequency));

    // Bounded diagnostic metadata only: no HWND, title, pixels, paths or exception text.
    private static void Diagnostic(string stage, int request_id = 0, long frame_id = 0,
                                   long compositor_ticks = 0, long requested_ticks = 0,
                                   long idle_frames = 0, long stale_frames = 0,
                                   string? code = null, long qpc_frequency = 0,
                                   uint? hresult = null, string? error_type = null)
    {
        Console.Error.WriteLine(JsonSerializer.Serialize(new {
            origin = "wgc", stage, request_id, frame_id, compositor_ticks, requested_ticks,
            idle_frames, stale_frames, code, qpc_frequency, hresult, error_type
        }));
    }

    private static async Task<byte[]> EncodeFrame(Direct3D11CaptureFrame frame, CancellationToken token)
    {
        using SoftwareBitmap bitmap = await SoftwareBitmap.CreateCopyFromSurfaceAsync(frame.Surface).AsTask(token);
        int width = bitmap.PixelWidth, height = bitmap.PixelHeight;
        if (width <= 0 || height <= 0 || width > 3840 || height > 3840 ||
            (long)width * height > MaxPixels || frame.ContentSize.Width != width ||
            frame.ContentSize.Height != height || bitmap.BitmapPixelFormat != BitmapPixelFormat.Bgra8)
            throw new InvalidOperationException("frame_format_or_size_invalid");
        BitmapPlaneDescription plane;
        using (BitmapBuffer locked = bitmap.LockBuffer(BitmapBufferAccessMode.Read))
            plane = locked.GetPlaneDescription(0);
        int rowBytes = checked(width * 4);
        if (plane.StartIndex < 0 || plane.Stride < rowBytes || plane.Height != height || plane.Width != width ||
            (long)plane.StartIndex + (long)plane.Stride * height > MaxPixels * 8L)
            throw new InvalidOperationException("frame_stride_invalid");
        var buffer = new Windows.Storage.Streams.Buffer(checked((uint)(plane.StartIndex + plane.Stride * height)));
        bitmap.CopyToBuffer(buffer);
        if (buffer.Length < plane.StartIndex + (height - 1) * plane.Stride + rowBytes)
            throw new InvalidOperationException("frame_buffer_incomplete");
        byte[] source = new byte[buffer.Length];
        using (var reader = DataReader.FromBuffer(buffer)) reader.ReadBytes(source);
        byte[] bmp = new byte[checked(54 + rowBytes * height)];
        using (var writer = new BinaryWriter(new MemoryStream(bmp, writable: true))) {
            writer.Write((byte)'B'); writer.Write((byte)'M'); writer.Write(bmp.Length);
            writer.Write((ushort)0); writer.Write((ushort)0); writer.Write(54); writer.Write(40);
            writer.Write(width); writer.Write(-height); writer.Write((ushort)1); writer.Write((ushort)32);
            writer.Write(0); writer.Write(rowBytes * height); writer.Write(2835); writer.Write(2835);
            writer.Write(0); writer.Write(0);
        }
        for (int row = 0; row < height; row++)
            System.Buffer.BlockCopy(source, plane.StartIndex + row * plane.Stride, bmp, 54 + row * rowBytes, rowBytes);
        return bmp;
    }

    private static TargetSnapshot ValidateTarget(nint hwnd, int pid, long nonce, long createdMilliseconds)
    {
        if (!IsWindow(hwnd) || !IsWindowVisible(hwnd) || IsIconic(hwnd) ||
            GetWindowThreadProcessId(hwnd, out uint actualPid) == 0 || actualPid != pid ||
            GetPropW(hwnd, NonceProperty) != (nint)nonce)
            throw new InvalidOperationException("target_identity_changed");
        using Process process = Process.GetProcessById(pid);
        if (process.StartTime.ToUniversalTime().Ticks / 10_000 != createdMilliseconds)
            throw new InvalidOperationException("target_process_changed");
        if (!GetWindowRect(hwnd, out Rect rect) || rect.Right <= rect.Left || rect.Bottom <= rect.Top ||
            (long)(rect.Right - rect.Left) * (rect.Bottom - rect.Top) > MaxPixels)
            throw new InvalidOperationException("target_geometry_invalid");
        return new TargetSnapshot(rect.Left, rect.Top, rect.Right, rect.Bottom);
    }

    private static async Task<byte[]> CaptureBmp(nint hwnd, CancellationToken token)
    {
        if (!GraphicsCaptureSession.IsSupported())
            throw new InvalidOperationException("wgc_unsupported");
        GraphicsCaptureItem item = CreateItemForWindow(hwnd);
        using IDirect3DDevice device = CreateDevice();
        using Direct3D11CaptureFramePool pool = Direct3D11CaptureFramePool.CreateFreeThreaded(
            device, DirectXPixelFormat.B8G8R8A8UIntNormalized, 2, item.Size);
        using GraphicsCaptureSession session = pool.CreateCaptureSession(item);
        var ready = new TaskCompletionSource<Direct3D11CaptureFrame>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnFrame(Direct3D11CaptureFramePool sender, object _) {
            try {
                Direct3D11CaptureFrame next = sender.TryGetNextFrame();
                if (next is null) return;
                if (!ready.TrySetResult(next)) next.Dispose();
            }
            catch (Exception error) { ready.TrySetException(error); }
        }
        pool.FrameArrived += OnFrame;
        try
        {
            // Preserve the system capture border and its ordinary consent behavior.
            session.StartCapture();
            using Direct3D11CaptureFrame frame = await ready.Task.WaitAsync(token);
            return await EncodeFrame(frame, token);
        }
        finally { pool.FrameArrived -= OnFrame; }
    }

    private static GraphicsCaptureItem CreateItemForWindow(nint hwnd)
    {
        const string name = "Windows.Graphics.Capture.GraphicsCaptureItem";
        Marshal.ThrowExceptionForHR(WindowsCreateString(name, name.Length, out nint hstring));
        try
        {
            Marshal.ThrowExceptionForHR(RoGetActivationFactory(hstring, in CaptureInteropIid, out nint factory));
            try
            {
                nint method = Marshal.ReadIntPtr(Marshal.ReadIntPtr(factory), 3 * IntPtr.Size);
                var create = Marshal.GetDelegateForFunctionPointer<CreateForWindowDelegate>(method);
                Marshal.ThrowExceptionForHR(create(factory, hwnd, in CaptureItemIid, out nint abi));
                try { return MarshalInterface<GraphicsCaptureItem>.FromAbi(abi); }
                finally { Marshal.Release(abi); }
            }
            finally { Marshal.Release(factory); }
        }
        finally { WindowsDeleteString(hstring); }
    }

    private static IDirect3DDevice CreateDevice()
    {
        Marshal.ThrowExceptionForHR(D3D11CreateDevice(0, 1, 0, 0x20, 0, 0, 7,
            out nint native, out _, out nint context));
        try
        {
            Marshal.ThrowExceptionForHR(Marshal.QueryInterface(native, in DxgiDeviceIid, out nint dxgi));
            try
            {
                Marshal.ThrowExceptionForHR(CreateDirect3D11DeviceFromDXGIDevice(dxgi, out nint abi));
                try { return MarshalInterface<IDirect3DDevice>.FromAbi(abi); }
                finally { Marshal.Release(abi); }
            }
            finally { Marshal.Release(dxgi); }
        }
        finally { Marshal.Release(context); Marshal.Release(native); }
    }

    private readonly record struct TargetSnapshot(int Left, int Top, int Right, int Bottom);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(nint hwnd, uint attribute, out Rect value, int size);
    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int CreateForWindowDelegate(nint self, nint hwnd, in Guid iid, out nint result);
    [DllImport("combase.dll", ExactSpelling = true)] private static extern int RoGetActivationFactory(nint classId, in Guid iid, out nint factory);
    [DllImport("combase.dll", ExactSpelling = true)] private static extern int WindowsCreateString([MarshalAs(UnmanagedType.LPWStr)] string source, int length, out nint hstring);
    [DllImport("combase.dll", ExactSpelling = true)] private static extern int WindowsDeleteString(nint hstring);
    [DllImport("d3d11.dll", ExactSpelling = true)] private static extern int D3D11CreateDevice(nint adapter, int driverType, nint software, uint flags, nint featureLevels, uint featureLevelCount, uint sdkVersion, out nint device, out int featureLevel, out nint immediateContext);
    [DllImport("d3d11.dll", ExactSpelling = true)] private static extern int CreateDirect3D11DeviceFromDXGIDevice(nint dxgiDevice, out nint graphicsDevice);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern bool SetProcessDpiAwarenessContext(nint context);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern bool IsWindow(nint hwnd);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern bool IsWindowVisible(nint hwnd);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern bool IsIconic(nint hwnd);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern uint GetWindowThreadProcessId(nint hwnd, out uint pid);
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)] private static extern nint GetPropW(nint hwnd, string name);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern bool GetWindowRect(nint hwnd, out Rect rect);
}
