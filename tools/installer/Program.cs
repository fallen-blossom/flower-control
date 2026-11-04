using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FlowerControl.Setup;

internal static class Program
{
    internal static string DisplayVersion => typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "unknown";
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.SequenceEqual(new[] { "--selftest" }))
        {
            foreach (string bad in new[] { "../outside", "C:/absolute", "/absolute", "a\\b", "a//b", "x/./y", "x./y", "a/CON", "a:file" })
                if (SafeName(bad)) return 2;
            return SafeName("Python/Lib/encodings/__init__.py") ? 0 : 3;
        }
        bool uninstall = args.SequenceEqual(new[] { "--uninstall" });
        if (uninstall && Environment.ProcessPath is { } own && own.Contains(Path.DirectorySeparatorChar + "Packages" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            string copy = Path.Combine(Path.GetTempPath(), "flower-uninstall-" + Guid.NewGuid().ToString("N") + ".exe");
            File.Copy(own, copy, false);
            using var first = File.OpenRead(own); using var second = File.OpenRead(copy);
            if (!SHA256.HashData(first).SequenceEqual(SHA256.HashData(second))) return 4;
            var child = new ProcessStartInfo(copy) { UseShellExecute = true };
            child.ArgumentList.Add("--uninstall"); Process.Start(child); return 0;
        }
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        if (args.Length == 2 && args[0] is "--snapshot" or "--snapshot-uninstall")
        {
            using var preview = new SetupWindow(uninstall: args[0] == "--snapshot-uninstall", preview: true);
            preview.StartPosition = FormStartPosition.Manual; preview.Location = new(-32000, -32000);
            preview.ShowInTaskbar = false; preview.Show(); Application.DoEvents(); preview.PerformLayout();
            using var bitmap = new Bitmap(preview.Width, preview.Height);
            preview.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
            bitmap.Save(Path.GetFullPath(args[1]), System.Drawing.Imaging.ImageFormat.Png);
            return 0;
        }
        string? initialRoot = args.Length == 2 && args[0] == "--install-root" ? Path.GetFullPath(args[1]) : null;
        Application.Run(new SetupWindow(uninstall, initialRoot: initialRoot));
        return 0;
    }

    internal static bool SafeName(string name)
    {
        if (name.Length is < 1 or > 512 || name.Contains('\\') || name.Contains(':') || name.StartsWith('/')) return false;
        return name.Split('/').All(part => part.Length > 0 && part is not "." and not ".."
            && !part.EndsWith('.') && !part.EndsWith(' ') && !part.Any(char.IsControl)
            && !new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }.Contains(part.Split('.')[0], StringComparer.OrdinalIgnoreCase));
    }

    internal static string Extract(CancellationToken stop, Action<string> progress)
    {
        using Stream source = Assembly.GetExecutingAssembly().GetManifestResourceStream("Flower.OfflinePayload.zip")
            ?? throw new InvalidOperationException("当前程序不含离线载荷。请使用正式构建产物，不能直接运行开发版安装器。");
        using var zip = new ZipArchive(source, ZipArchiveMode.Read);
        if (zip.Entries.Count is < 1 or > 60001) throw new IOException("安装包文件数量异常。");
        string stage = Path.Combine(Path.GetTempPath(), "flower-setup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(stage);
        long size = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in zip.Entries)
        {
            stop.ThrowIfCancellationRequested();
            if (!SafeName(entry.FullName) || !names.Add(entry.FullName) || entry.Length > 512L * 1024 * 1024
                || (size += entry.Length) > 3L * 1024 * 1024 * 1024 || ((entry.ExternalAttributes >> 16) & 0xf000) == 0xa000)
                throw new IOException("安装包含不安全路径或超出容量限制。");
            string path = Path.Combine(stage, entry.FullName.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var input = entry.Open();
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
            if (output.Length != entry.Length) throw new IOException("安装包解压长度不符。");
        }
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(stage, "payload.json")));
        var root = manifest.RootElement;
        if (root.GetProperty("schema").GetInt32() != 1 || !root.GetProperty("generic").GetBoolean()
            || root.GetProperty("platform").GetString() != "win-x64") throw new IOException("离线载荷类型不符。");
        int files = 0;
        foreach (var file in root.GetProperty("files").EnumerateObject())
        {
            stop.ThrowIfCancellationRequested();
            if (!SafeName(file.Name) || !names.Contains(file.Name)) throw new IOException("离线载荷清单不符。");
            using var input = File.OpenRead(Path.Combine(stage, file.Name.Replace('/', Path.DirectorySeparatorChar)));
            if (!Convert.ToHexString(SHA256.HashData(input)).Equals(file.Value.GetString(), StringComparison.OrdinalIgnoreCase))
                throw new IOException("离线载荷校验失败。");
            ++files;
        }
        if (files + 1 != names.Count) throw new IOException("安装包存在未登记文件。");
        progress("离线载荷校验通过。正在识别已有安装位置…");
        return stage;
    }
}

internal sealed class SetupWindow : Form
{
    private readonly TextBox location = new() { Dock = DockStyle.Fill, Text = DefaultLocation(), AccessibleName = "安装根目录" };
    private readonly TextBox dshImage = new() { Dock = DockStyle.Fill, AccessibleName = "DSH 程序路径" };
    private readonly TextBox details = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, TabStop = true };
    private readonly Button install = new() { Text = "安装 / 升级", AutoSize = true, Enabled = false };
    private readonly Button browse = new() { Text = "浏览…", AutoSize = true };
    private readonly Button cancel = new() { Text = "取消", AutoSize = true };
    private readonly CheckBox codex = new() { Text = "接入 Codex（安装、信任与启用在宿主中确认）", AutoSize = true, Checked = true };
    private readonly CheckBox dsh = new() { Text = "接入 DSH（选择已安装的 DeepSeek Harness.exe）", AutoSize = true };
    private readonly ProgressBar progress = new() { Width = 170, Height = 20, Style = ProgressBarStyle.Marquee, MarqueeAnimationSpeed = 30, AccessibleName = "安装维护进度" };
    private readonly Button help = new() { Text = "使用说明与 AI 提示词", AutoSize = true, Enabled = false };
    private readonly Button cleanup = new() { Text = "回收本次安装临时材料", AutoSize = true, Enabled = false };
    private readonly Button personalData = new() { Text = "审阅保留的个人资料…", AutoSize = true, Enabled = false, Visible = false };
    private readonly CancellationTokenSource cancellation = new();
    private string? payload;
    private bool deploying, busy;
    private readonly bool uninstallMode;
    private JsonElement? pendingInstall;
    private string? pendingWork;
    private JsonElement? pendingUninstall;
    private bool pendingInstallDispatched;
    private bool personalCleanupActive, closeAfterPersonalCleanup;
    private string? personalCleanupCancelFile, personalCleanupReviewSha;

    internal SetupWindow(bool uninstall = false, bool preview = false, string? initialRoot = null)
    {
        uninstallMode = uninstall;
        if (initialRoot is not null) location.Text = initialRoot;
        Text = "Flower Control " + Program.DisplayVersion + " 安装与维护";
        Size = new(820, 620); MinimumSize = new(680, 540); StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(24), ColumnCount = 2, RowCount = 9 };
        grid.ColumnStyles.Add(new(SizeType.Percent, 100)); grid.ColumnStyles.Add(new(SizeType.AutoSize));
        var title = new Label { Text = "安装 Flower Control " + Program.DisplayVersion, Font = new Font(SystemFonts.MessageBoxFont?.FontFamily ?? FontFamily.GenericSansSerif, 18, FontStyle.Bold), AutoSize = true };
        grid.Controls.Add(title, 0, 0); grid.SetColumnSpan(title, 2);
        var description = new Label { Text = "无需 Python、.NET SDK 或编译器。程序、运行时、资料和缓存统一放在所选根目录。\n安装期间会请求一次 Windows 管理员授权；默认使用 02 普通控制，后续权限由你选择。", AutoSize = true, MaximumSize = new(730, 0), Margin = new(0, 12, 0, 18) };
        grid.Controls.Add(description, 0, 1); grid.SetColumnSpan(description, 2);
        grid.Controls.Add(new Label { Text = "安装根目录（可选其他本地磁盘）", AutoSize = true }, 0, 2);
        grid.Controls.Add(location, 0, 3); grid.Controls.Add(browse, 1, 3);
        grid.Controls.Add(codex, 0, 4); grid.SetColumnSpan(codex, 2);
        grid.Controls.Add(dsh, 0, 5); grid.SetColumnSpan(dsh, 2);
        grid.Controls.Add(dshImage, 0, 6);
        var dshBrowse = new Button { Text = "选择 DSH…", AutoSize = true };
        grid.Controls.Add(dshBrowse, 1, 6);
        grid.Controls.Add(details, 0, 7); grid.SetColumnSpan(details, 2); grid.RowStyles.Add(new(SizeType.AutoSize));
        for (int i = 1; i < 7; ++i) grid.RowStyles.Add(new(SizeType.AutoSize));
        grid.RowStyles.Add(new(SizeType.Percent, 100)); grid.RowStyles.Add(new(SizeType.AutoSize));
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        buttons.Controls.Add(cancel); buttons.Controls.Add(install); buttons.Controls.Add(help); buttons.Controls.Add(cleanup); buttons.Controls.Add(personalData); buttons.Controls.Add(progress); grid.Controls.Add(buttons, 0, 8); grid.SetColumnSpan(buttons, 2);
        Controls.Add(grid); AcceptButton = install; CancelButton = cancel;
        if (uninstallMode)
        {
            title.Text = "卸载 Flower Control " + Program.DisplayVersion; install.Text = "审阅并卸载";
            description.Text = "核对本机登记、进程、启动任务和宿主配置后，将准确属于 Flower 的程序文件移入回收站。\n默认保留个人资料、缓存与恢复记录；未知结果和正在使用的文件不会被强行删除。";
            codex.Enabled = dsh.Enabled = dshImage.Enabled = dshBrowse.Enabled = false;
            cleanup.Visible = false; personalData.Visible = true;
        }
        browse.Click += (_, _) => { using var picker = new FolderBrowserDialog { Description = "选择安装位置的父目录，将自动建立 FlowerControl 专用根目录。安装后请用维护入口迁移。", UseDescriptionForTitle = true }; if (picker.ShowDialog(this) == DialogResult.OK) location.Text = Path.Combine(picker.SelectedPath, "FlowerControl"); };
        dshBrowse.Click += (_, _) => { using var picker = new OpenFileDialog { Title = "选择已安装的 DeepSeek Harness.exe", Filter = "DeepSeek Harness|DeepSeek Harness.exe", CheckFileExists = true }; if (picker.ShowDialog(this) == DialogResult.OK) { dshImage.Text = picker.FileName; dsh.Checked = true; } };
        cancel.Click += (_, _) => { if (personalCleanupActive) RequestPersonalCleanupStop(); else if (!deploying) { cancellation.Cancel(); if (!busy) Close(); } };
        help.Click += (_, _) => OpenGuide();
        cleanup.Click += async (_, _) => await RecycleTemporary();
        personalData.Click += async (_, _) => await RecyclePersonalData();
        FormClosing += (_, e) => { if (personalCleanupActive) { closeAfterPersonalCleanup = true; RequestPersonalCleanupStop(); e.Cancel = true; } else if (deploying) { e.Cancel = true; Log("安装维护正在执行，请等待结果后关闭；不会强杀正在写入的安装进程。"); } else if (busy) { cancellation.Cancel(); e.Cancel = true; } };
        if (!preview) Shown += async (_, _) => await LoadPayload();
        else details.Text = "离线校验后将在这里显示真实检查结果。\r\n\r\n程序和依赖：<Root>\\Program\r\n浏览器资料与设置：<Root>\\Data\r\n大文件缓存：<Root>\\Cache\r\n安装维护：<Root>\\Packages\r\n\r\n宿主中的信任和启用由你确认；安装成功与聊天已加载分别显示。";
        install.Click += async (_, _) => { if (uninstallMode) await Uninstall(); else await Install(); };
    }

    private static string DefaultLocation()
    {
        var drive = DriveInfo.GetDrives().FirstOrDefault(d => d.IsReady && d.DriveType == DriveType.Fixed
            && !d.RootDirectory.FullName.Equals(Path.GetPathRoot(Environment.SystemDirectory), StringComparison.OrdinalIgnoreCase));
        return Path.Combine(drive?.RootDirectory.FullName ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl");
    }
    private void Log(string text)
    {
        if (InvokeRequired) { BeginInvoke(new Action(() => Log(text))); return; }
        details.AppendText(text + Environment.NewLine);
    }
    private void BindPlannedHosts(JsonElement plan)
    {
        var adapters = plan.GetProperty("adapters").EnumerateArray().ToArray();
        codex.Checked = adapters.Any(x => x.GetProperty("host").GetString() == "codex");
        dsh.Checked = adapters.Any(x => x.GetProperty("host").GetString() == "dsh");
        location.ReadOnly = true; browse.Enabled = codex.Enabled = dsh.Enabled = dshImage.Enabled = false;
        if (dsh.Checked && string.IsNullOrEmpty(dshImage.Text)) dshImage.Text = "沿用原安装计划中已封存的 DSH 身份";
    }
    private void DescribeOriginalPlan(JsonElement plan)
    {
        string? release = plan.TryGetProperty("release_version", out var value) ? value.GetString() : null;
        Log("当前安装器 " + Program.DisplayVersion + "；原计划发行版本：" + (release ?? "未知（旧计划未记录）")
            + "；运行时指纹：" + plan.GetProperty("version").GetString());
        if (release != Program.DisplayVersion) Log("先完成这个原计划；若要安装当前发行版本，再重新打开本版安装器进行升级。不会把原计划改写为新版。");
    }
    private void OpenGuide()
    {
        if (payload is null) return;
        string path = Path.Combine(payload, "Guides/START_HERE.zh-CN.txt");
        if (pendingInstall is { } plan && plan.TryGetProperty("maintenance_sha256", out var sha))
        {
            string installed = Path.Combine(plan.GetProperty("packages_root").GetString()!, plan.GetProperty("version").GetString()! + "-" + sha.GetString()![..12], "Help/Guides/START_HERE.zh-CN.txt");
            if (File.Exists(installed)) path = installed;
        }
        if (!File.Exists(path)) { Log("本地说明文件未找到，请保留安装材料并查看回执。"); return; }
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe")) { UseShellExecute = false };
        start.ArgumentList.Add(path); Process.Start(start);
    }
    private async Task RecycleTemporary()
    {
        if (busy || payload is null || pendingWork is null) return;
        try
        {
            var trees = new[] { payload, pendingWork }.Where(Directory.Exists).Select(TemporaryMaterials.Inspect).ToArray();
            string summary = string.Join("\n", trees.Select(x => x.Path + "\n" + x.Files + " 个文件，" + (x.Bytes / 1048576.0).ToString("F1") + " MiB"));
            if (MessageBox.Show(this, "文件安装和执行器连接已核实，以下本次临时材料可回收；安装目录与个人资料不在此清单中。\n\n" + summary
                + "\n\n移入 Windows 回收站？需要保留原始排查材料时请选择取消。", "回收本次临时材料", MessageBoxButtons.OKCancel, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
            busy = true; cleanup.Enabled = help.Enabled = false; progress.Visible = true;
            // COM shell recycling runs on this STA thread after all installer
            // children ended. No elevated process or permanent delete is used.
            await Task.Yield();
            foreach (var tree in trees)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                TemporaryMaterials.Recycle(tree);
            }
            Log("本次临时材料已移入回收站。程序、资料、缓存与维护入口保留在所选根目录。");
        }
        catch (OperationCanceledException) { Log("已取消后续临时材料回收；已完成的回收保留实际结果。"); }
        catch (Exception error) { Log(error.Message); cleanup.Enabled = true; }
        finally { busy = false; progress.Visible = false; help.Enabled = true; if (cancellation.IsCancellationRequested) Close(); }
    }
    private void RequestPersonalCleanupStop()
    {
        if (!personalCleanupActive || personalCleanupCancelFile is null || personalCleanupReviewSha is null) return;
        try
        {
            if (!File.Exists(personalCleanupCancelFile))
            {
                string publication = personalCleanupCancelFile + ".publish-" + Guid.NewGuid().ToString("N") + ".tmp";
                using (var output = new FileStream(publication, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    output.Write(Encoding.ASCII.GetBytes(personalCleanupReviewSha)); output.Flush(true);
                }
                File.Move(publication, personalCleanupCancelFile, overwrite: false);
            }
            else if (File.ReadAllText(personalCleanupCancelFile) != personalCleanupReviewSha) throw new IOException("取消标记发生变化，未覆盖未知文件。");
            cancel.Enabled = false;
            Log("已请求停止后续回收，正在等待当前一项结束。已回收的文件和结果未知项会按实际回执保留，不会强杀或重放。");
        }
        catch (Exception error) { Log("停止请求未确认：" + error.Message); }
    }
    private async Task RecyclePersonalData()
    {
        if (busy || pendingUninstall is null) return;
        busy = true; personalData.Enabled = false; progress.Visible = true;
        try
        {
            var plan = pendingUninstall.Value;
            string work = Path.GetDirectoryName(plan.GetProperty("plan").GetString()!)!;
            string review = Path.Combine(work, "personal-review-" + Guid.NewGuid().ToString("N") + ".json");
            Log("只读盘点此安装保留的 Data/Cache。关闭本窗口会保留资料，Program 的安全与恢复记录不会进入清理。");
            using var inspected = await Python("inspect-uninstall-data", "--plan", plan.GetProperty("plan").GetString()!,
                "--expected-sha256", plan.GetProperty("plan_sha256").GetString()!, "--output", review);
            var value = inspected.RootElement;
            string summary = "以下个人资料和缓存将移入 Windows 回收站，包括其中的浏览器登录资料和本地设置：\n\n"
                + string.Join("\n", value.GetProperty("selected_roots").EnumerateArray().Select(x => x.GetString())) + "\n\n"
                + value.GetProperty("file_count").GetInt32() + " 个文件，" + (value.GetProperty("bytes").GetInt64() / 1048576.0).ToString("F1") + " MiB"
                + "\n\nProgram 中的权限、Stop、未知动作、审计和恢复记录继续保留。此操作不是安全擦除；回收站失败不改永久删除。\n取消将保留全部尚未处理的个人资料。";
            if (MessageBox.Show(this, summary + "\n\n确认回收本清单？", "另行确认个人资料清理", MessageBoxButtons.OKCancel,
                MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
            cancellation.Token.ThrowIfCancellationRequested();
            // Medium-only exact-data recycling has its own durable receipt.
            // Once dispatched, wait for it rather than killing a partial batch.
            personalCleanupCancelFile = review + ".cancel";
            personalCleanupReviewSha = value.GetProperty("review_sha256").GetString()!;
            personalCleanupActive = deploying = true; cancel.Enabled = true; cancel.Text = "停止后续回收";
            using var result = await Python("recycle-uninstall-data", "--review", value.GetProperty("review_path").GetString()!,
                "--expected-sha256", personalCleanupReviewSha, "--receipt", review + ".receipt.json",
                "--cancel-file", personalCleanupCancelFile, "--confirmed");
            Log("个人资料处理结果：" + result.RootElement.GetProperty("state").GetString() + "\n回执：" + review + ".receipt.json");
        }
        catch (OperationCanceledException) { Log("已取消资料盘点，未派发回收。"); }
        catch (Exception error) { Log(error.Message); }
        finally
        {
            personalCleanupActive = deploying = busy = false; cancel.Enabled = personalData.Enabled = true; cancel.Text = "关闭"; progress.Visible = false;
            if (cancellation.IsCancellationRequested || closeAfterPersonalCleanup) Close();
        }
    }
    private static string PinnedBootstrap(string script, string hash, string arguments = "")
    {
        string quote(string value) => "'" + value.Replace("'", "''") + "'";
        string code = "$ErrorActionPreference='Stop';$s=[IO.File]::Open(" + quote(script)
            + ",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{"
            + "$h=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"
            + "if($v -cne " + quote(hash) + "){throw 'setup_script_changed'};$s.Position=0;"
            + "$r=[IO.StreamReader]::new($s,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};"
            + "& ([scriptblock]::Create($text)) " + arguments + "}finally{$s.Dispose()}";
        return Convert.ToBase64String(Encoding.Unicode.GetBytes(code));
    }
    private async Task<JsonDocument> Python(params string[] args)
    {
        if (payload is null) throw new InvalidOperationException("离线载荷尚未就绪。");
        var start = new ProcessStartInfo(Path.Combine(payload, "Python/python.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("-B"); start.ArgumentList.Add(Path.Combine(payload, "Source/tools/offline_install.py"));
        foreach (string arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new IOException("无法启动内置运行时。");
        Task<string> output = process.StandardOutput.ReadToEndAsync(), error = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(deploying ? CancellationToken.None : cancellation.Token); }
        catch (OperationCanceledException)
        {
            // This process only prepares/read-checks local material. An
            // elevated deployment is owned separately and is never killed.
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(output, error);
            throw;
        }
        if (process.ExitCode != 0)
        {
            string message = await error;
            string reason = message.Contains("installation_unprotected") || message.Contains("installation_parent_")
                ? "此目录或它的上级允许普通用户修改，不能放管理员组件。请选择盘根下尚未创建的新目录，例如 D:\\FlowerControl；无需提前建文件夹。"
                : message.Contains("offline_existing_root_requires_explicit_migration")
                ? "已发现其他位置的现有安装。升级会保留原资料目录；迁移需通过单独的明确迁移流程。"
                : "本地检查或准备未完成，请保留回执与恢复材料。";
            throw new IOException(reason + "\n" + message[..Math.Min(message.Length, 4000)]);
        }
        return JsonDocument.Parse(await output);
    }
    private async Task LoadPayload()
    {
        busy = true;
        try
        {
            Log("正在解包并校验内置运行依赖；此步骤不联网、不安装。临时解包目录使用 Windows TEMP。");
            payload = await Task.Run(() => Program.Extract(cancellation.Token, Log));
            help.Enabled = true;
            using var status = await Python("status");
            bool installed = status.RootElement.GetProperty("installed").GetBoolean();
            if (installed)
            {
                location.Text = status.RootElement.GetProperty("root").GetString(); location.ReadOnly = true; browse.Enabled = false;
                Log("已发现现有安装：" + location.Text + "。升级保留实际数据目录，不自动迁盘。");
            }
            Log("可开始安装。Codex/DSH 的信任和新聊天实际加载由宿主确认，安装成功不代表已控制窗口。");
            install.Enabled = !uninstallMode || installed;
            var operations = status.RootElement.GetProperty("resumable_operations").EnumerateArray().ToArray();
            if (operations.Length > 0)
            {
                string kind = uninstallMode ? "uninstall" : "setup";
                var matching = operations.Where(x => x.GetProperty("kind").GetString() == kind).ToArray();
                if (matching.Length != 1 || !matching[0].GetProperty("materials_verified").GetBoolean())
                {
                    install.Enabled = false;
                    Log("发现未完成的已确认操作。请保留并核对原材料；不会生成新计划覆盖它。\n" + string.Join("\n", operations.Select(x => x.GetProperty("anchor").GetString())));
                }
                else
                {
                    using var original = await Python("resume", "--kind", kind, "--operation", matching[0].GetProperty("operation_id").GetString()!);
                    if (uninstallMode) pendingUninstall = original.RootElement.Clone();
                    else
                    {
                        pendingInstall = original.RootElement.Clone(); pendingInstallDispatched = true;
                        pendingWork = Path.GetDirectoryName(original.RootElement.GetProperty("setup_plan_path").GetString()!);
                        BindPlannedHosts(original.RootElement);
                        DescribeOriginalPlan(original.RootElement);
                    }
                    install.Text = uninstallMode ? "继续原卸载" : "继续原安装"; install.Enabled = true;
                    Log("已从受保护回执接回原操作。原计划与脚本字节均已核实，点击继续后核实并补完原阶段。");
                }
            }
            if (uninstallMode && !installed) Log("没有发现可核实的 Flower 安装；不会猜测或删除其他目录。");
        }
        catch (OperationCanceledException) { Log("已取消解包；没有安装或更改现有 Flower。"); }
        catch (Exception error) { Log(error.Message); }
        finally { busy = false; progress.Visible = false; if (cancellation.IsCancellationRequested) Close(); }
    }
    private async Task Uninstall()
    {
        if (payload is null || busy) return;
        busy = true; install.Enabled = false; progress.Visible = true;
        bool dispatched = false, hostStageAttempted = false, completed = false;
        try
        {
            string work = Path.Combine(Path.GetTempPath(), "flower-uninstall-plan-" + Guid.NewGuid().ToString("N"));
            Log("正在只读核对文件、准确进程身份及宿主注册…");
            if (pendingUninstall is null)
            {
                using var prepared = await Python("prepare-uninstall", "--work", work);
                pendingUninstall = prepared.RootElement.Clone();
            }
            else Log("接回原卸载计划和回执，核对已经回收的准确文件，不生成新的删除范围。");
            using var plan = JsonDocument.Parse(pendingUninstall.Value.GetRawText());
            var root = plan.RootElement;
            work = Path.GetDirectoryName(root.GetProperty("plan").GetString()!)!;
            string summary = "安装目录：" + root.GetProperty("root").GetString()
                + "\n程序文件：" + root.GetProperty("files").GetInt32() + " 个，" + (root.GetProperty("bytes").GetInt64() / 1048576.0).ToString("F1") + " MiB"
                + "\n将停止并移除准确匹配的 Flower 自启动项与宿主入口，然后回收程序文件。\n保留：\n"
                + string.Join("\n", root.GetProperty("preserve").EnumerateArray().Select(x => x.GetString()))
                + "\n\n计划：" + root.GetProperty("plan").GetString();
            Log(summary);
            if (root.GetProperty("blockers").GetArrayLength() > 0)
            {
                Log("发现需要人工核对的项目：" + root.GetProperty("blockers").GetRawText() + "\n未执行卸载，请先解决这些项目，再重新核对。");
                pendingUninstall = null;
                return;
            }
            if (MessageBox.Show(this, summary + "\n\n确认执行此卸载计划？", "确认卸载", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.OK) { pendingUninstall = null; return; }
            Log("先以普通权限清理已核实的宿主注册，再请求管理员处理 Flower 程序。此阶段不会提权运行宿主 CLI。");
            hostStageAttempted = true;
            using var hostStage = await Python("complete-uninstall-hosts", "--plan", root.GetProperty("plan").GetString()!, "--expected-sha256", root.GetProperty("plan_sha256").GetString()!);
            var merged = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(pendingUninstall.Value.GetRawText())!;
            foreach (var property in hostStage.RootElement.EnumerateObject()) merged[property.Name] = property.Value.Clone();
            pendingUninstall = JsonSerializer.SerializeToElement(merged);
            var current = pendingUninstall.Value;
            Log("普通权限宿主收尾阶段已核实。取消接下来的 UAC 会保留 Flower 程序，可继续本计划；不会自动重新注册宿主。");
            string script = current.GetProperty("elevated_script").GetString()!;
            using (var input = File.OpenRead(script))
                if (!Convert.ToHexString(SHA256.HashData(input)).Equals(current.GetProperty("elevated_script_sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new IOException("卸载脚本已改变，请重新核对。");
            deploying = true; cancel.Enabled = false;
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell/v1.0/powershell.exe")) { UseShellExecute = true, Verb = "runas", WorkingDirectory = work };
            string parameters = "-Apply -ReviewedPlanSha256 '" + current.GetProperty("plan_sha256").GetString()!
                + "' -ExpectedScriptSha256 '" + current.GetProperty("elevated_script_sha256").GetString()!
                + "' -ResultPath '" + current.GetProperty("result_path").GetString()!.Replace("'", "''") + "' -Confirm:$false";
            foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-STA", "-EncodedCommand", PinnedBootstrap(script, current.GetProperty("elevated_script_sha256").GetString()!, parameters) }) start.ArgumentList.Add(arg);
            using var process = Process.Start(start) ?? throw new IOException("卸载进程未启动。");
            dispatched = true;
            await process.WaitForExitAsync();
            string receipt = root.GetProperty("result_path").GetString()!;
            if (!File.Exists(receipt)) throw new IOException("卸载回执尚未确认，请保留计划并核对：" + work);
            using var result = JsonDocument.Parse(File.ReadAllBytes(receipt));
            completed = process.ExitCode == 0 && result.RootElement.GetProperty("complete").GetBoolean();
            Log(completed
                ? "卸载完成。个人资料和恢复记录已保留；准确程序文件已移入回收站。"
                : "卸载未完全完成；不会强杀或改为永久删除。请查看回执：" + receipt);
            personalData.Enabled = completed;
            cancel.Text = "关闭";
        }
        catch (Exception error) { if (!dispatched && !hostStageAttempted) pendingUninstall = null; Log(error.Message); }
        finally { deploying = busy = false; cancel.Enabled = true; install.Enabled = !completed; progress.Visible = false; if (cancellation.IsCancellationRequested) Close(); }
    }
    private async Task Install()
    {
        if (payload is null || busy) return;
        busy = true; install.Enabled = false; browse.Enabled = false; progress.Visible = true;
        try
        {
            string root = Path.GetFullPath(location.Text.Trim());
            if (!Path.IsPathFullyQualified(root) || root.StartsWith("\\\\") || root == Path.GetPathRoot(root)) throw new IOException("请选择本地磁盘下的专用根目录，例如 D:\\FlowerControl。");
            if (pendingInstall is null && dsh.Checked && (!File.Exists(dshImage.Text) || !Path.GetFileName(dshImage.Text).Equals("DeepSeek Harness.exe", StringComparison.OrdinalIgnoreCase))) throw new IOException("请先选择准确的 DSH 程序。");
            string work = pendingWork ?? Path.Combine(Path.GetDirectoryName(payload)!, "flower-install-" + Guid.NewGuid().ToString("N"));
            bool resume = pendingInstallDispatched;
            if (pendingInstall is null)
            {
                using var inspected = await Python("inspect-root", "--root", root);
                var previous = inspected.RootElement.GetProperty("resumable_operations").EnumerateArray().ToArray();
                if (previous.Length > 0)
                {
                    if (previous.Length != 1 || previous[0].GetProperty("kind").GetString() != "setup" || !previous[0].GetProperty("materials_verified").GetBoolean())
                        throw new IOException("此根目录存在未完成操作，请保留原材料并核对准确回执，不能生成新计划覆盖。");
                    using var recovered = await Python("resume", "--kind", "setup", "--operation", previous[0].GetProperty("operation_id").GetString()!, "--root", root);
                    pendingInstall = recovered.RootElement.Clone(); pendingInstallDispatched = true; resume = true;
                    pendingWork = Path.GetDirectoryName(recovered.RootElement.GetProperty("setup_plan_path").GetString()!); work = pendingWork!;
                    Log("已从所选原目录的受保护回执找到登记前的未完成安装，将继续原计划。");
                }
            }
            if (pendingInstall is null)
            {
                Log("准备安装计划和本机身份绑定，保留已有设置、Stop 与未知动作记录…");
                var args = new List<string> { "prepare", "--payload", payload, "--root", root, "--work", work };
                args.Add("--installer"); args.Add(Environment.ProcessPath!);
                if (!codex.Checked) args.Add("--without-codex");
                if (dsh.Checked) { args.Add("--dsh-image"); args.Add(dshImage.Text); }
                using var prepared = await Python(args.ToArray());
                pendingInstall = prepared.RootElement.Clone(); pendingWork = work;
                location.ReadOnly = true; codex.Enabled = dsh.Enabled = dshImage.Enabled = false;
            }
            else
            {
                Log("接回同一安装计划；只核实并补完准确阶段，不重新准备或重放未知动作。\n恢复材料：" + work);
                DescribeOriginalPlan(pendingInstall.Value);
            }
            using var plan = JsonDocument.Parse(pendingInstall.Value.GetRawText());
            BindPlannedHosts(plan.RootElement);
            var adapters = plan.RootElement.GetProperty("adapters").EnumerateArray().ToArray();
            bool codexPlanned = adapters.Any(x => x.GetProperty("host").GetString() == "codex");
            string script = plan.RootElement.GetProperty("elevated_script").GetString()!;
            using (var input = File.OpenRead(script))
                if (!Convert.ToHexString(SHA256.HashData(input)).Equals(plan.RootElement.GetProperty("elevated_script_sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new IOException("安装计划已改变，请重新准备。");
            cancellation.Token.ThrowIfCancellationRequested();
            Log("即将请求 Windows 管理员授权。取消 UAC 会保留准备材料，不覆盖现有安装。");
            deploying = true; cancel.Enabled = false;
            var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell/v1.0/powershell.exe")) { UseShellExecute = true, Verb = "runas", WorkingDirectory = work };
            string parameters = (resume ? "-Resume " : "")
                + "-SetupOperationId '" + plan.RootElement.GetProperty("operation_id").GetString()!
                + "' -SetupPlanPath '" + plan.RootElement.GetProperty("setup_plan_path").GetString()!.Replace("'", "''")
                + "' -SetupPlanSha256 '" + plan.RootElement.GetProperty("setup_plan_sha256").GetString()!
                + "' -SetupScriptPath '" + script.Replace("'", "''")
                + "' -ExpectedScriptSha256 '" + plan.RootElement.GetProperty("elevated_script_sha256").GetString()! + "'";
            foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-STA", "-EncodedCommand", PinnedBootstrap(script, plan.RootElement.GetProperty("elevated_script_sha256").GetString()!, parameters) }) start.ArgumentList.Add(arg);
            using var process = Process.Start(start) ?? throw new IOException("安装维护进程未启动。");
            pendingInstallDispatched = true;
            await process.WaitForExitAsync();
            if (process.ExitCode != 0) throw new IOException("安装维护未完成。请保留此目录用于诊断/恢复：" + work);
            Log("正在核实安装文件、执行器与宿主本地市场…");
            using var launched = await Python("finish-install", "--plan", Path.Combine(work, "setup-plan.json"));
            string registrationState = launched.RootElement.GetProperty("registration").GetProperty("state").GetString()!;
            if (codexPlanned)
            {
                Log(registrationState switch
                {
                    "marketplace_registered" => "已核实 Codex 本地市场注册。请在 Codex 插件设置中安装并启用 Flower Control，确认宿主要求的信任。",
                    "previous_source_restored" => "新版市场登记失败，已读回并恢复原版本市场。新版接入尚未完成，请保留回执核对。",
                    "restoration_unconfirmed" => "新版市场登记失败，原市场恢复也未确认。请保留回执，只读核对实际登记后再处理。",
                    "removal_unconfirmed" => "原市场移除未确认，未继续登记新版。请保留回执核对。",
                    _ => "Flower 插件已生成；Codex 的市场注册仍需核对。请保留回执，不覆盖来源不明的登记，也未替你确认信任。"
                });
                if (launched.RootElement.GetProperty("registration").TryGetProperty("receipt_path", out var receipt)) Log("宿主登记回执：" + receipt.GetString());
            }
            foreach (var adapter in adapters)
            {
                string host = adapter.GetProperty("host").GetString()!, source = adapter.GetProperty("source").GetString()!;
                Log(host + " 本地接入包：" + source);
                if (host == "codex" && registrationState == "marketplace_registered") Log("在 Codex 插件设置安装并启用 Flower Control，由你确认这次 Hook 信任。");
                else if (host == "codex") Log("核对实际市场与上述回执后使用本地来源：codex plugin marketplace add \"" + source + "\"");
                else if (host == "dsh") Log("在 DSH 中选择此本地接入包，确认宿主要求的信任与启用。");
            }
            Log(launched.RootElement.GetProperty("runtime_started").GetBoolean()
                ? "安装已完成，已核实执行器连接。" : "文件安装已完成；执行器启动尚未确认，请查看安装回执，不要反复重装。");
            Log(launched.RootElement.GetProperty("settings_open_requested").GetBoolean()
                ? "已向实际执行器请求打开设置。请先核实权限档位，再在新聊天中检查三个 flower_status。"
                : "设置打开请求尚未确认；可通过 Flower 托盘打开设置并查看诊断。");
            Log("安装回执与恢复材料：" + work);
            if (launched.RootElement.GetProperty("runtime_started").GetBoolean() && (!codexPlanned || registrationState == "marketplace_registered"))
            {
                cleanup.Enabled = true;
                Log("可点击“使用说明与 AI 提示词”开始使用；确认无需排查后，可回收本次 Windows TEMP 材料。");
            }
            cancel.Text = "关闭";
        }
        catch (OperationCanceledException) { Log("已取消，尚未派发新的管理员安装。"); }
        catch (Exception error) { Log(error.Message); install.Enabled = true; }
        finally { deploying = false; busy = false; cancel.Enabled = true; progress.Visible = false; if (cancellation.IsCancellationRequested) Close(); }
    }
}
