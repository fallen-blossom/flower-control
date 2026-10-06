using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Windows.Security.Credentials.UI;

// This one-shot helper owns the HWND passed to the official desktop interop.
// It never receives a PIN, page content, browser profile, or database path.
internal sealed record HelloRequest(int Version, string RequestId, string Challenge);
internal sealed record HelloResponse(int Version, string RequestId, string Challenge,
                                     string Result);

internal static class Program
{
    private const string WindowMarker = "FlowerControlAuthorizationVerifier";

    [DllImport("user32.dll", EntryPoint = "SetPropW", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern bool SetProp(nint hwnd, string name, nint value);

    [DllImport("user32.dll", EntryPoint = "RemovePropW", CharSet = CharSet.Unicode)]
    private static extern nint RemoveProp(nint hwnd, string name);

    [STAThread]
    private static int Main(string[] args)
    {
        // This diagnostic mode can only return Canceled and never calls Hello.
        var markerProbe = args.Length == 1 && args[0] == "--marker-probe";
        if (args.Length != 0 && !markerProbe)
            return 2;
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;
        HelloRequest? request;
        try
        {
            var line = Console.ReadLine();
            request = JsonSerializer.Deserialize<HelloRequest>(line ?? "");
            if (request is null || request.Version != 1 ||
                string.IsNullOrWhiteSpace(request.RequestId) ||
                string.IsNullOrWhiteSpace(request.Challenge) ||
                request.RequestId.Length > 128 || request.Challenge.Length > 128)
                return 2;
        }
        catch (JsonException)
        {
            return 2;
        }

        string result = "Canceled";
        var closedByUser = false;
        var closingAfterVerification = false;
        ApplicationConfiguration.Initialize();
        using var window = new Form
        {
            Text = "Flower Control · Windows Hello 验证",
            Width = 450,
            Height = 150,
            MaximizeBox = false,
            MinimizeBox = false,
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            ShowInTaskbar = true
        };
        window.Controls.Add(new Label
        {
            Text = markerProbe
                ? "授权窗口标识检查；关闭此窗口即结束，不会启动 Windows Hello。"
                : "请在 Windows 系统提示中完成身份验证。取消或关闭此窗口将拒绝授权。",
            Dock = DockStyle.Fill,
            TextAlign = System.Drawing.ContentAlignment.MiddleCenter
        });
        window.FormClosing += (_, _) =>
        {
            if (!closingAfterVerification)
                closedByUser = true;
        };
        // Mark the actual top-level HWND before it can become visible.
        if (!SetProp(window.Handle, WindowMarker, 1))
            return 3;
        if (!markerProbe)
            window.Shown += async (_, _) =>
        {
            try
            {
                var availability = await UserConsentVerifier.CheckAvailabilityAsync();
                if (availability == UserConsentVerifierAvailability.Available)
                {
                    var verification = await UserConsentVerifierInterop
                        .RequestVerificationForWindowAsync(
                            window.Handle, "Flower Control：确认本聊天使用落花登录态");
                    result = verification.ToString();
                }
                else
                {
                    result = "Unavailable";
                }
            }
            catch (Exception)
            {
                result = "Error";
            }
            finally
            {
                if (closedByUser)
                    result = "Canceled";
                closingAfterVerification = true;
                if (!window.IsDisposed)
                    window.Close();
                if (window.IsHandleCreated)
                    RemoveProp(window.Handle, WindowMarker);
            }
        };
        Application.Run(window);
        Console.WriteLine(JsonSerializer.Serialize(
            new HelloResponse(1, request.RequestId, request.Challenge, result)));
        return 0;
    }
}
