using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace IPSwitcher
{
    #region New Classes for Added Features

    /// <summary>
    /// 管理应用程序设置，从JSON文件加载和保存。
    /// </summary>
    public static class SettingsManager
    {
        private static readonly string FilePath;
        public static AppSettings Current { get; private set; }

        static SettingsManager()
        {
            // 在 %APPDATA% 中构建路径
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string settingsDir = Path.Combine(appDataPath, "ipTools");
            FilePath = Path.Combine(settingsDir, "settings.json");
            Current = new AppSettings();
        }

        public static void Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    string json = File.ReadAllText(FilePath);
                    Current = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[yellow]警告: 无法加载配置文件。将使用默认设置。 ({Markup.Escape(ex.Message)})[/]");
                Current = new AppSettings();
            }
        }

        public static void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(Current, options);
                File.WriteAllText(FilePath, json);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]错误: 无法保存配置文件。 ({Markup.Escape(ex.Message)})[/]");
            }
        }
    }

    /// <summary>
    /// 定义应用程序的可配置设置。
    /// </summary>
    public class AppSettings
    {
        public int PingConcurrency { get; set; } = 100;
        public int ResolveConcurrency { get; set; } = 50;
    }

    /// <summary>
    /// 跟踪网络接口的流量统计信息。
    /// </summary>
    public static class NetworkTrafficMonitor
    {
        private static Timer? _timer;
        private static long _lastTotalSent = 0;
        private static long _lastTotalReceived = 0;

        public static string CurrentUpSpeed { get; private set; } = "0 B/s".PadLeft(12);
        public static string CurrentDownSpeed { get; private set; } = "0 B/s".PadLeft(12);
        public static string TotalDataTransferred { get; private set; } = "0 B";

        public static void Initialize()
        {
            if (!NetworkInterface.GetIsNetworkAvailable()) return;

            _lastTotalSent = GetTotalBytesSent();
            _lastTotalReceived = GetTotalBytesReceived();

            _timer = new Timer(UpdateGlobalStats, null, 1000, 1000);
        }

        private static void UpdateGlobalStats(object? state)
        {
            long currentTotalSent = GetTotalBytesSent();
            long currentTotalReceived = GetTotalBytesReceived();

            long sentSinceLast = currentTotalSent - _lastTotalSent;
            long receivedSinceLast = currentTotalReceived - _lastTotalReceived;

            CurrentUpSpeed = $"{FormatBytes(sentSinceLast)}/s".PadLeft(12);
            CurrentDownSpeed = $"{FormatBytes(receivedSinceLast)}/s".PadLeft(12);
            TotalDataTransferred = FormatBytes(currentTotalSent + currentTotalReceived);

            _lastTotalSent = currentTotalSent;
            _lastTotalReceived = currentTotalReceived;
        }

        public static long GetTotalBytesSent()
        {
            if (!NetworkInterface.GetIsNetworkAvailable()) return 0;
            return NetworkInterface.GetAllNetworkInterfaces().Sum(ni =>
            {
                try { return ni.GetIPv4Statistics().BytesSent; }
                catch { return 0L; }
            });
        }

        public static long GetTotalBytesReceived()
        {
            if (!NetworkInterface.GetIsNetworkAvailable()) return 0;
            return NetworkInterface.GetAllNetworkInterfaces().Sum(ni =>
            {
                try { return ni.GetIPv4Statistics().BytesReceived; }
                catch { return 0L; }
            });
        }

        /// <summary>
        /// 将字节计数格式化为人类可读的字符串（B, KB, MB, GB 等）。
        /// </summary>
        public static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB", "PB" };
            int i = 0;
            double dblSByte = bytes;
            while (dblSByte >= 1024 && i < suffixes.Length - 1)
            {
                dblSByte /= 1024;
                i++;
            }
            return $"{dblSByte:0.##} {suffixes[i]}";
        }
    }

    #endregion

    /// <summary>
    /// 用于存储局域网扫描结果的辅助类。
    /// </summary>
    public class ScanResult
    {
        public string IpAddress { get; set; } = "";
        public string MacAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
    }

    /// <summary>
    /// 用于存储从 API 获取的公网 IP 信息 (ipinfo.io)。
    /// </summary>
    public class PublicIpInfo
    {
        [JsonPropertyName("ip")]
        public string? Ip { get; set; }

        [JsonPropertyName("city")]
        public string? City { get; set; }

        [JsonPropertyName("region")]
        public string? Region { get; set; }

        [JsonPropertyName("country")]
        public string? Country { get; set; }

        [JsonPropertyName("org")]
        public string? Org { get; set; } // ISP
    }


    class Program
    {
        private static PublicIpInfo? _publicIpInfo;
        private static string _publicIpStatus = "正在获取...";

        static async Task Main(string[] args)
        {
            // 注册代码页提供程序以支持GBK等编码
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // 设置控制台编码为UTF-8以正确显示中文
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            // 从文件加载设置
            SettingsManager.Load();

            // 初始化网络流量监视器
            NetworkTrafficMonitor.Initialize();

            // 异步获取公网IP信息，不阻塞UI
            _ = GetPublicIpInfoAsync();

            while (true)
            {
                // 清除任何残留的按键输入
                while (Console.KeyAvailable)
                {
                    Console.ReadKey(true);
                }

                if (!await MainMenu())
                {
                    break; // 如果MainMenu返回false则退出程序
                }
            }

            AnsiConsole.MarkupLine("[green]程序已退出。[/]");
        }

        /// <summary>
        /// 异步获取公网IP信息。
        /// </summary>
        static async Task GetPublicIpInfoAsync()
        {
            try
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                // 使用更稳定的 ipinfo.io API
                var response = await client.GetStringAsync("https://ipinfo.io/json");
                _publicIpInfo = JsonSerializer.Deserialize<PublicIpInfo>(response);
                if (string.IsNullOrWhiteSpace(_publicIpInfo?.Ip))
                {
                    _publicIpStatus = "[red]获取失败[/]";
                    _publicIpInfo = null;
                }
            }
            catch (Exception)
            {
                _publicIpStatus = "[red]获取失败 (网络错误)[/]";
                _publicIpInfo = null;
            }
        }

        /// <summary>
        /// 主菜单循环, 返回 false 以退出应用程序。
        /// </summary>
        static async Task<bool> MainMenu()
        {
            var options = new List<string>
            {
                "配置网络适配器 IP",
                "扫描局域网设备",
                "网络诊断工具",
                "流量监控",
                "设置",
                "退出程序"
            };

            AnsiConsole.Clear();
            AnsiConsole.Write(new FigletText("ipTools").Centered().Color(Color.Blue));

            var chosenIndex = await ShowMainMenuWithOptions(options);


            // 根据用户的选择执行操作
            switch (chosenIndex)
            {
                case 0:
                    await ConfigureIpMenu();
                    break;
                case 1:
                    await StartLanScan();
                    break;
                case 2:
                    await NetworkDiagnosticsMenu();
                    break;
                case 3:
                    await ShowTrafficMonitor();
                    break;
                case 4:
                    await ShowSettingsMenu();
                    break;
                case 5:
                case -1: // ESC in main menu means exit
                    return false; // 发出退出主循环的信号
            }

            return true; // 继续主循环
        }

        /// <summary>
        /// [已修改] 使用传入的适配器信息构建本地信息网格，以展示更丰富的信息。
        /// </summary>
        private static Grid GetLocalInfoGrid(AdapterInfo? activeAdapter)
        {
            var grid = new Grid();
            grid.AddColumn(new GridColumn().Width(12).NoWrap()); // 固定宽度的标签列
            grid.AddColumn(new GridColumn());
            grid.AddRow("[bold]当前时间:[/]", $"[yellow]{DateTime.Now:yyyy-MM-dd HH:mm:ss}[/]");

            if (activeAdapter != null)
            {
                grid.AddRow("[bold]活动连接:[/]", $"[yellow]{Markup.Escape(activeAdapter.Name)}[/]");
                grid.AddRow("[bold]网卡描述:[/]", $"[yellow]{Markup.Escape(activeAdapter.Description)}[/]");
                grid.AddRow("[bold]本地 IP:[/]", $"[yellow]{activeAdapter.IpAddress}[/]");

                string ipType = activeAdapter.IsDhcpEnabled ? "[green]动态 (DHCP)[/]" : "[cyan]静态[/]";
                grid.AddRow("[bold]IP 分配:[/]", ipType);

                string connectionType = activeAdapter.IsVirtual ? $"[grey]虚拟 ({activeAdapter.AdapterType})[/]" : $"[aqua]物理 ({activeAdapter.AdapterType})[/]";
                grid.AddRow("[bold]连接类型:[/]", connectionType);
            }
            else
            {
                grid.AddRow("[bold]活动连接:[/]", "[red]无活动连接[/]");
                grid.AddRow("[bold]本地 IP:[/]", "[red]N/A[/]");
            }

            // 新增流量统计信息
            grid.AddRow("[bold]实时速率:[/]", $"[red]↑{NetworkTrafficMonitor.CurrentUpSpeed}[/]  [green]↓{NetworkTrafficMonitor.CurrentDownSpeed}[/]");
            grid.AddRow("[bold]已用流量:[/]", $"[cyan](开机) {NetworkTrafficMonitor.TotalDataTransferred}[/]");

            return grid;
        }

        /// <summary>
        /// 为标签列设置固定宽度以确保对齐
        /// </summary>
        static Grid GetPublicInfoGrid()
        {
            var grid = new Grid();
            grid.AddColumn(new GridColumn().Width(12).NoWrap()); // 固定宽度的标签列
            grid.AddColumn(new GridColumn());
            if (_publicIpInfo != null)
            {
                grid.AddRow("[bold]公网 IP:[/]", $"[aqua]{_publicIpInfo.Ip ?? "N/A"}[/]");
                grid.AddRow("[bold]地理位置:[/]", $"[aqua]{Markup.Escape($"{_publicIpInfo.Country ?? ""}, {_publicIpInfo.Region ?? ""}, {_publicIpInfo.City ?? ""}")}[/]");
                grid.AddRow("[bold]运营商:[/]", $"[aqua]{Markup.Escape(_publicIpInfo.Org ?? "N/A")}[/]");
            }
            else
            {
                grid.AddRow("[bold]公网 IP:[/]", _publicIpStatus);
                grid.AddRow("[bold]地理位置:[/]", _publicIpStatus);
                grid.AddRow("[bold]运营商:[/]", _publicIpStatus);
            }
            return grid;
        }

        /// <summary>
        /// 启动局域网扫描，优先使用活动适配器。
        /// </summary>
        static async Task StartLanScan()
        {
            AnsiConsole.Clear();
            var activeAdapter = AdapterInfo.GetActiveAdapter();
            string? adapterToScan;

            if (activeAdapter != null)
            {
                adapterToScan = activeAdapter.Name;
            }
            else
            {
                adapterToScan = await SelectAdapter("未找到活动网络，请选择要扫描的适配器");
            }

            if (!string.IsNullOrEmpty(adapterToScan))
            {
                await ScanLanDevices(adapterToScan);
                AnsiConsole.Prompt(new TextPrompt<string>("[grey]操作完成。按任意键返回主菜单...[/]").AllowEmpty());
            }
        }

        /// <summary>
        /// 用于IP配置的二级菜单。
        /// </summary>
        static async Task ConfigureIpMenu()
        {
            while (true)
            {
                AnsiConsole.Clear();
                string? selectedAdapterName = await SelectAdapter("请选择要配置的网络适配器");
                if (string.IsNullOrEmpty(selectedAdapterName))
                {
                    return; // 用户按 ESC 或选择返回
                }

                while (true)
                {
                    AnsiConsole.Clear();
                    var panel = new Panel($"[bold]已选定适配器:[/] [yellow]\"{Markup.Escape(selectedAdapterName)}\"[/]")
                        .Border(BoxBorder.Rounded);
                    AnsiConsole.Write(panel);

                    var options = new List<string>
                    {
                        "设置静态 IP 地址",
                        "设置为自动获取 (DHCP)",
                        "返回上一级 (选择其他适配器)"
                    };

                    var choiceIndex = await ShowMenuAsync(options, "[bold]请选择要执行的操作:[/]");


                    if (choiceIndex == -1 || choiceIndex == 2) break; // -1 is ESC, 2 is "返回"

                    bool operationCancelled = false;
                    switch (choiceIndex)
                    {
                        case 0:
                            operationCancelled = !SetStaticIP(selectedAdapterName);
                            break;
                        case 1:
                            SetDhcpIP(selectedAdapterName);
                            break;
                    }

                    if (!operationCancelled && choiceIndex < 2)
                    {
                        AnsiConsole.Prompt(new TextPrompt<string>("[grey]操作完成。按任意键返回...[/]").AllowEmpty());
                    }
                }
            }
        }

        /// <summary>
        /// 扫描本地网络上的设备，并解析主机名，同时确保本机信息准确无误。
        /// </summary>
        static async Task ScanLanDevices(string adapterName)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine($"[bold blue]================ 局域网设备扫描 ==================[/]");

            var adapter = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase));

            if (adapter == null)
            {
                AnsiConsole.MarkupLine($"[red]错误: 找不到名为 \"{Markup.Escape(adapterName)}\" 的适配器。[/]");
                return;
            }

            var ipInfo = adapter.GetIPProperties().UnicastAddresses
                .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            if (ipInfo == null)
            {
                AnsiConsole.MarkupLine($"[red]错误: 适配器 \"{Markup.Escape(adapterName)}\" 未配置IPv4地址。[/]");
                return;
            }

            var ipAddress = ipInfo.Address;
            var subnetMask = ipInfo.IPv4Mask;
            var networkAddress = new IPAddress(ipAddress.GetAddressBytes().Zip(subnetMask.GetAddressBytes(), (a, b) => (byte)(a & b)).ToArray());

            var ipRange = GetIpRange(networkAddress, subnetMask).ToList();
            if (!ipRange.Any())
            {
                AnsiConsole.MarkupLine("[red]错误: 无法确定有效的IP扫描范围。[/]");
                return;
            }

            AnsiConsole.MarkupLine($"[bold]本机IP:[/] [yellow]{ipAddress}[/], [bold]正在扫描网段:[/] [yellow]{networkAddress} / {subnetMask}[/]");
            AnsiConsole.MarkupLine($"[bold]扫描范围:[/] [yellow]{ipRange.First()} - {ipRange.Last()}[/]");
            AnsiConsole.MarkupLine("[grey](按 Esc 键可随时中断)[/]");


            var onlineHosts = new ConcurrentBag<IPAddress>();
            var results = new ConcurrentBag<ScanResult>();
            bool wasCancelled = false;

            using var cts = new CancellationTokenSource();
            var cancellationToken = cts.Token;

            var keyListenerTask = Task.Run(() =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                    {
                        cts.Cancel();
                    }
                    Task.Delay(50, cancellationToken).ContinueWith(_ => { });
                }
            }, cancellationToken);

            try
            {
                await AnsiConsole.Progress()
                    .Columns(new ProgressColumn[]
                    {
                        new TaskDescriptionColumn(),
                        new ProgressBarColumn(),
                        new PercentageColumn(),
                        new SpinnerColumn(),
                    })
                    .StartAsync(async ctx =>
                    {
                        var pingProgressTask = ctx.AddTask("[green]Ping 扫描[/]", new ProgressTaskSettings { MaxValue = ipRange.Count });
                        var pingSemaphore = new SemaphoreSlim(SettingsManager.Current.PingConcurrency);
                        var pingTasks = ipRange.Select(async ip =>
                        {
                            if (cancellationToken.IsCancellationRequested) return;
                            await pingSemaphore.WaitAsync(cancellationToken);
                            try
                            {
                                if (cancellationToken.IsCancellationRequested) return;
                                using (var ping = new Ping())
                                {
                                    var reply = await ping.SendPingAsync(ip, 1000);
                                    if (reply.Status == IPStatus.Success)
                                    {
                                        onlineHosts.Add(ip);
                                    }
                                }
                            }
                            finally
                            {
                                pingProgressTask.Increment(1);
                                pingSemaphore.Release();
                            }
                        });
                        await Task.WhenAll(pingTasks);

                        if (cancellationToken.IsCancellationRequested)
                        {
                            wasCancelled = true;
                            return;
                        }

                        var resolveProgressTask = ctx.AddTask("[aqua]解析主机[/]", new ProgressTaskSettings { MaxValue = onlineHosts.Count });
                        var arpCache = GetArpCache();
                        var resolveSemaphore = new SemaphoreSlim(SettingsManager.Current.ResolveConcurrency);
                        var resolveTasks = onlineHosts.Select(async host =>
                        {
                            if (cancellationToken.IsCancellationRequested) return;
                            await resolveSemaphore.WaitAsync(cancellationToken);
                            try
                            {
                                if (cancellationToken.IsCancellationRequested) return;
                                string ipStr = host.ToString();
                                string macAddress = arpCache.TryGetValue(ipStr, out var mac) ? mac : "(无法获取)";
                                string hostname = "(无法解析)";
                                try
                                {
                                    var resolveHostTask = Dns.GetHostEntryAsync(host);
                                    if (await Task.WhenAny(resolveHostTask, Task.Delay(1500, cancellationToken)) == resolveHostTask && !resolveHostTask.IsFaulted)
                                    {
                                        hostname = resolveHostTask.Result.HostName;
                                    }
                                }
                                catch (SocketException) { }
                                catch (TaskCanceledException) { }

                                results.Add(new ScanResult { IpAddress = ipStr, MacAddress = macAddress, Hostname = hostname });
                            }
                            finally
                            {
                                resolveProgressTask.Increment(1);
                                resolveSemaphore.Release();
                            }
                        });
                        await Task.WhenAll(resolveTasks);
                    });
            }
            catch (TaskCanceledException)
            {
                wasCancelled = true;
            }
            finally
            {
                if (!cts.IsCancellationRequested)
                {
                    cts.Cancel();
                }
                await keyListenerTask;
                while (Console.KeyAvailable)
                {
                    Console.ReadKey(true);
                }
            }


            string localIp = ipAddress.ToString();
            string localMac = FormatMacAddress(adapter.GetPhysicalAddress());
            string localHostname = Dns.GetHostName();

            var finalResults = results.ToList();
            var localMachineResult = finalResults.FirstOrDefault(r => r.IpAddress == localIp);
            if (localMachineResult != null)
            {
                localMachineResult.MacAddress = localMac;
                localMachineResult.Hostname = localHostname;
            }
            else
            {
                if (!wasCancelled)
                {
                    finalResults.Add(new ScanResult { IpAddress = localIp, MacAddress = localMac, Hostname = localHostname });
                }
            }

            var tableCaption = wasCancelled ? "[bold yellow]扫描已被用户中断[/]" : "[bold blue]局域网扫描结果[/]";
            PrintResultsTable(finalResults, localIp, tableCaption);
        }

        /// <summary>
        /// 将适配器设置为使用 DHCP。
        /// </summary>
        static void SetDhcpIP(string adapterName)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine($"[yellow]正在设置 \"{Markup.Escape(adapterName)}\" 为自动获取 IP 地址 (DHCP)...[/]");
            if (!ExecuteNetsh($"interface ipv4 set address name=\"{adapterName}\" source=dhcp")) return;

            AnsiConsole.MarkupLine($"[yellow]正在设置 \"{Markup.Escape(adapterName)}\" 为自动获取 DNS 服务器 (DHCP)...[/]");
            if (!ExecuteNetsh($"interface ipv4 set dns name=\"{adapterName}\" source=dhcp")) return;

            ShowSuccess(adapterName);
        }

        /// <summary>
        /// 为适配器设置静态IP，包含输入验证和ESC取消功能。
        /// </summary>
        /// <returns>如果操作成功完成则返回 true, 如果被用户取消则返回 false。</returns>
        static bool SetStaticIP(string adapterName)
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine($"[bold]正在为 \"{Markup.Escape(adapterName)}\" 配置静态 IP[/]");
            AnsiConsole.MarkupLine("[grey](在任何提示下按 ESC 键可取消操作)[/]");
            AnsiConsole.WriteLine();

            string? staticIP;
            while (true)
            {
                staticIP = GetInputWithCancel("[green]请输入静态 IP 地址: [/]");
                if (staticIP is null) return false; // User cancelled
                if (IsValidIpOrHostname(staticIP)) break;
                AnsiConsole.MarkupLine("[red]IP 地址格式不正确，请重试。[/]");
            }

            var ipParts = staticIP.Split('.');
            string defaultGatewayValue = ipParts.Length == 4 ? $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.1" : "";

            string? subnetMask;
            while (true)
            {
                subnetMask = GetInputWithCancel($"[green]请输入子网掩码 [/][grey](默认: 255.255.255.0)[/][green]: [/]");
                if (subnetMask is null) return false;
                if (string.IsNullOrEmpty(subnetMask)) subnetMask = "255.255.255.0";
                if (IsValidIp(subnetMask)) break;
                AnsiConsole.MarkupLine("[red]子网掩码格式不正确，请重试。[/]");
            }

            string? gateway;
            while (true)
            {
                gateway = GetInputWithCancel($"[green]请输入网关 [/][grey](默认: {defaultGatewayValue}, 可留空)[/][green]: [/]");
                if (gateway is null) return false;
                if (string.IsNullOrEmpty(gateway)) gateway = defaultGatewayValue;
                if (string.IsNullOrEmpty(gateway) || IsValidIp(gateway)) break;
                AnsiConsole.MarkupLine("[red]网关地址格式不正确，请重试。[/]");
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]正在应用 IP 配置...[/]");
            string command = string.IsNullOrWhiteSpace(gateway)
                ? $"interface ipv4 set address name=\"{adapterName}\" static {staticIP} {subnetMask}"
                : $"interface ipv4 set address name=\"{adapterName}\" static {staticIP} {subnetMask} {gateway}";
            if (!ExecuteNetsh(command)) return false;

            AnsiConsole.WriteLine();
            string? dns1;
            while (true)
            {
                dns1 = GetInputWithCancel("[green]请输入主 DNS 服务器 [/][grey](默认: 114.114.114.114)[/][green]: [/]");
                if (dns1 is null) return false;
                if (string.IsNullOrEmpty(dns1)) dns1 = "114.114.114.114";
                if (IsValidIpOrHostname(dns1)) break;
                AnsiConsole.MarkupLine("[red]DNS 服务器地址格式不正确，请重试。[/]");
            }

            string? dns2;
            while (true)
            {
                dns2 = GetInputWithCancel("[green]请输入备用 DNS 服务器 [/][grey](默认: 8.8.8.8, 可留空)[/][green]: [/]");
                if (dns2 is null) return false;
                if (string.IsNullOrEmpty(dns2)) dns2 = "8.8.8.8";
                if (string.IsNullOrEmpty(dns2) || IsValidIpOrHostname(dns2)) break;
                AnsiConsole.MarkupLine("[red]DNS 服务器地址格式不正确，请重试。[/]");
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]正在应用 DNS 配置...[/]");
            if (!ExecuteNetsh($"interface ipv4 set dns name=\"{adapterName}\" static {dns1}")) return false;

            if (!string.IsNullOrWhiteSpace(dns2))
            {
                ExecuteNetsh($"interface ipv4 add dns name=\"{adapterName}\" {dns2} index=2");
            }

            ShowSuccess(adapterName);
            return true;
        }

        /// <summary>
        /// 显示成功信息和当前配置。
        /// </summary>
        static void ShowSuccess(string adapterName)
        {
            AnsiConsole.Clear();
            var panel = new Panel($"[bold green]操作成功[/]\n\"{Markup.Escape(adapterName)}\" 的网络配置已更新。")
                .Header("成功")
                .Border(BoxBorder.Rounded)
                .Expand();
            AnsiConsole.Write(panel);

            var table = new Table().Title("[bold]当前配置[/]").Border(TableBorder.Simple);
            table.AddColumn("项目");
            table.AddColumn("值");

            try
            {
                Thread.Sleep(500);
                var ni = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase));

                if (ni == null)
                {
                    AnsiConsole.MarkupLine("[red]无法获取该适配器的详细信息。[/]");
                    return;
                }

                var ipProps = ni.GetIPProperties();
                var ipv4AddressInfo = ipProps.UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                if (ipv4AddressInfo != null)
                {
                    table.AddRow("IPv4 地址", ipv4AddressInfo.Address.ToString());
                    table.AddRow("子网掩码", ipv4AddressInfo.IPv4Mask.ToString());
                }
                else
                {
                    table.AddRow("IPv4 地址", "[grey](未分配)[/]");
                }

                var gateway = ipProps.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                table.AddRow("默认网关", gateway != null ? gateway.Address.ToString() : "[grey](无)[/]");

                var dnsServers = ipProps.DnsAddresses.Where(d => d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToList();
                if (dnsServers.Any())
                {
                    table.AddRow("DNS 服务器", string.Join("\n", dnsServers.Select(d => d.ToString())));
                }
                else
                {
                    table.AddRow("DNS 服务器", "[grey](无)[/]");
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]获取配置时出错: {Markup.Escape(ex.Message)}[/]");
            }
            AnsiConsole.Write(table);
        }

        #region 新增功能方法

        /// <summary>
        /// 显示流量监控页面。
        /// </summary>
        static async Task ShowTrafficMonitor()
        {
            AnsiConsole.Clear();

            var sessionStartStats = new ConcurrentDictionary<string, (long Sent, long Received)>();
            var lastCycleStats = new ConcurrentDictionary<string, (long Sent, long Received, DateTime Time)>();
            bool isFirstRun = true;

            using var cts = new CancellationTokenSource();
            var token = cts.Token;

            // 监听 Esc 键以退出
            var keyListenerTask = Task.Run(() =>
            {
                while (!token.IsCancellationRequested)
                {
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                    {
                        cts.Cancel();
                    }
                    Task.Delay(50, token).ContinueWith(_ => { });
                }
            }, token);

            try
            {
                await AnsiConsole.Live(new Table())
                .StartAsync(async ctx =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                            .Where(ni => ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback && ni.Supports(NetworkInterfaceComponent.IPv4))
                            .ToList();

                        var table = new Table().Expand().Border(TableBorder.Rounded);
                        table.Title = new TableTitle($"[bold blue]实时流量监控[/] [grey](每秒刷新, 按 Esc 退出)[/]");
                        table.AddColumn(new TableColumn("[bold]适配器[/]").Centered());
                        table.AddColumn(new TableColumn("[bold]实时速率 (↑/↓)[/]").Centered());
                        table.AddColumn(new TableColumn("[bold]已上传 (开机)[/]").Centered());
                        table.AddColumn(new TableColumn("[bold]已下载 (开机)[/]").Centered());
                        table.AddColumn(new TableColumn("[bold]已上传 (会话)[/]").Centered());
                        table.AddColumn(new TableColumn("[bold]已下载 (会话)[/]").Centered());


                        foreach (var ni in interfaces)
                        {
                            IPv4InterfaceStatistics stats;
                            try
                            {
                                stats = ni.GetIPv4Statistics();
                            }
                            catch { continue; }

                            long currentSent = stats.BytesSent;
                            long currentReceived = stats.BytesReceived;
                            var currentTime = DateTime.UtcNow;

                            // 初始化会话和速率计算的基准值
                            if (isFirstRun)
                            {
                                sessionStartStats[ni.Id] = (currentSent, currentReceived);
                                lastCycleStats[ni.Id] = (currentSent, currentReceived, currentTime);
                            }

                            sessionStartStats.TryAdd(ni.Id, (currentSent, currentReceived));
                            lastCycleStats.TryAdd(ni.Id, (currentSent, currentReceived, currentTime));


                            // 计算速率
                            var lastStats = lastCycleStats[ni.Id];
                            var timeDiff = (currentTime - lastStats.Time).TotalSeconds;
                            string upSpeed = "0 B/s";
                            string downSpeed = "0 B/s";

                            if (timeDiff > 0)
                            {
                                upSpeed = $"{NetworkTrafficMonitor.FormatBytes((long)((currentSent - lastStats.Sent) / timeDiff))}/s";
                                downSpeed = $"{NetworkTrafficMonitor.FormatBytes((long)((currentReceived - lastStats.Received) / timeDiff))}/s";
                            }

                            string formattedRate = $"[red]↑ {upSpeed.PadLeft(10)}[/]  [green]↓ {downSpeed.PadLeft(10)}[/]";

                            // 更新上一周期的数据
                            lastCycleStats[ni.Id] = (currentSent, currentReceived, currentTime);

                            // 计算会话流量
                            var sessionStats = sessionStartStats[ni.Id];
                            long sessionSentBytes = currentSent - sessionStats.Sent;
                            long sessionReceivedBytes = currentReceived - sessionStats.Received;
                            string sessionSent = NetworkTrafficMonitor.FormatBytes(sessionSentBytes);
                            string sessionReceived = NetworkTrafficMonitor.FormatBytes(sessionReceivedBytes);

                            // 开机总流量
                            string bootSent = NetworkTrafficMonitor.FormatBytes(currentSent);
                            string bootReceived = NetworkTrafficMonitor.FormatBytes(currentReceived);

                            table.AddRow(
                                new Markup($"[yellow]{Markup.Escape(ni.Name)}[/]"),
                                new Markup(formattedRate),
                                new Markup($"[cyan]{bootSent.PadLeft(10)}[/]"),
                                new Markup($"[cyan]{bootReceived.PadLeft(10)}[/]"),
                                new Markup($"[magenta]{sessionSent.PadLeft(10)}[/]"),
                                new Markup($"[magenta]{sessionReceived.PadLeft(10)}[/]")
                            );
                        }

                        ctx.UpdateTarget(table);
                        ctx.Refresh();
                        isFirstRun = false;
                        await Task.Delay(1000, token);
                    }
                });
            }
            catch (TaskCanceledException) { /* 正常退出 */ }
            finally
            {
                if (!cts.IsCancellationRequested) cts.Cancel();
                await keyListenerTask;
            }
        }

        /// <summary>
        /// 显示设置菜单。
        /// </summary>
        static async Task ShowSettingsMenu()
        {
            while (true)
            {
                AnsiConsole.Clear();
                var options = new List<string>
                {
                    $"修改 Ping 并发数 (当前: {SettingsManager.Current.PingConcurrency})",
                    $"修改主机解析并发数 (当前: {SettingsManager.Current.ResolveConcurrency})",
                    "返回主菜单"
                };

                var choiceIndex = await ShowMenuAsync(options, "[bold]设置[/]");

                if (choiceIndex == -1 || choiceIndex == 2)
                {
                    SettingsManager.Save(); // 在退出时保存
                    return;
                }

                switch (choiceIndex)
                {
                    case 0:
                        var newPing = AnsiConsole.Prompt(
                            new TextPrompt<int>($"输入新的 [green]Ping 并发数[/] (推荐 50-200):")
                                .DefaultValue(SettingsManager.Current.PingConcurrency)
                                .ValidationErrorMessage("[red]请输入一个有效的正整数[/]")
                                .Validate(p => p > 0)
                        );
                        SettingsManager.Current.PingConcurrency = newPing;
                        break;
                    case 1:
                        var newResolve = AnsiConsole.Prompt(
                            new TextPrompt<int>($"输入新的 [green]主机解析并发数[/] (推荐 25-100):")
                                .DefaultValue(SettingsManager.Current.ResolveConcurrency)
                                .ValidationErrorMessage("[red]请输入一个有效的正整数[/]")
                                .Validate(r => r > 0)
                        );
                        SettingsManager.Current.ResolveConcurrency = newResolve;
                        break;
                }
            }
        }

        #endregion

        #region 网络诊断工具

        /// <summary>
        /// 网络诊断工具的主菜单。
        /// </summary>
        static async Task NetworkDiagnosticsMenu()
        {
            while (true)
            {
                AnsiConsole.Clear();
                var options = new List<string>
                {
                    "持续 Ping 监控",
                    "路由跟踪",
                    "端口扫描",
                    "返回主菜单"
                };

                var choiceIndex = await ShowMenuAsync(options, "[bold]网络诊断工具[/]");

                if (choiceIndex == -1 || choiceIndex == 3) return;

                bool operationCompleted = false;
                switch (choiceIndex)
                {
                    case 0:
                        operationCompleted = await StartPingMonitor();
                        break;
                    case 1:
                        operationCompleted = await StartTraceroute();
                        break;
                    case 2:
                        operationCompleted = await StartPortScan();
                        break;
                }
                if (operationCompleted)
                {
                    AnsiConsole.Prompt(new TextPrompt<string>("[grey]诊断完成。按任意键返回诊断菜单...[/]").AllowEmpty());
                }
            }
        }

        /// <summary>
        /// 启动持续 Ping 监控。
        /// </summary>
        static async Task<bool> StartPingMonitor()
        {
            AnsiConsole.Clear();
            string? target;
            while (true)
            {
                target = GetInputWithCancel("[green]请输入目标 IP 地址或域名: [/]");
                if (target is null) return false; // User cancelled
                if (!string.IsNullOrWhiteSpace(target)) break;
                AnsiConsole.MarkupLine("[red]目标不能为空，请重试。[/]");
            }

            AnsiConsole.MarkupLine($"\n正在持续 Ping [yellow]{Markup.Escape(target)}[/] ([grey]按 Esc 键停止[/])...");

            using var cts = new CancellationTokenSource();
            var token = cts.Token;

            long packetsSent = 0;
            long packetsReceived = 0;
            var latencies = new List<long>();

            var pingLoop = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        using var ping = new Ping();
                        var reply = await ping.SendPingAsync(target, 2000);
                        packetsSent++;

                        if (reply.Status == IPStatus.Success)
                        {
                            packetsReceived++;
                            latencies.Add(reply.RoundtripTime);
                            var ttl = reply.Options?.Ttl;
                            AnsiConsole.MarkupLine($"来自 [green]{reply.Address}[/]: 字节=32 时间=[yellow]{reply.RoundtripTime}ms[/] TTL=[blue]{ttl}[/]");
                        }
                        else
                        {
                            AnsiConsole.MarkupLine($"[yellow]请求超时或错误: {reply.Status}[/]");
                        }
                    }
                    catch (PingException ex)
                    {
                        AnsiConsole.MarkupLine($"[red]Ping 错误: {Markup.Escape(ex.InnerException?.Message ?? ex.Message)}[/]");
                        cts.Cancel();
                    }
                    catch (OperationCanceledException) { }

                    if (!token.IsCancellationRequested)
                    {
                        try
                        {
                            await Task.Delay(1000, token);
                        }
                        catch (TaskCanceledException) { }
                    }
                }
            }, token);

            while (!pingLoop.IsCompleted && !pingLoop.IsCanceled)
            {
                if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                {
                    cts.Cancel();
                }
                await Task.Delay(100);
            }

            long packetsLost = packetsSent - packetsReceived;
            double lossPercentage = packetsSent > 0 ? (double)packetsLost / packetsSent * 100 : 0;

            var statsGrid = new Grid()
                .AddColumn().AddColumn().AddColumn().AddColumn()
                .AddRow(
                    "[bold]已发送:[/] " + packetsSent,
                    "[bold]已接收:[/] " + packetsReceived,
                    "[bold]已丢失:[/] " + packetsLost,
                    $"([bold red]{lossPercentage:F2}% 丢失[/])"
                );

            Panel panel;
            if (latencies.Any())
            {
                var latencyGrid = new Grid()
                    .AddColumn().AddColumn().AddColumn()
                    .AddRow(
                        $"[bold]最短:[/] {latencies.Min()}ms",
                        $"[bold]最长:[/] {latencies.Max()}ms",
                        $"[bold]平均:[/] {latencies.Average():F0}ms"
                    );
                var rows = new Rows(statsGrid, new Text("往返行程的估计时间(以毫秒为单位):"), latencyGrid);
                panel = new Panel(rows).Header("[bold]Ping 统计信息[/]").Border(BoxBorder.Rounded);
            }
            else
            {
                panel = new Panel(statsGrid).Header("[bold]Ping 统计信息[/]").Border(BoxBorder.Rounded);
            }
            AnsiConsole.Write(panel);
            return true;
        }

        /// <summary>
        /// 启动路由跟踪，并允许用户随时中断。
        /// </summary>
        static async Task<bool> StartTraceroute()
        {
            AnsiConsole.Clear();
            string? target;
            while (true)
            {
                target = GetInputWithCancel("[green]请输入目标 IP 地址或域名: [/]");
                if (target is null) return false; // User cancelled
                if (!string.IsNullOrWhiteSpace(target)) break;
                AnsiConsole.MarkupLine("[red]目标不能为空，请重试。[/]");
            }

            IPAddress targetIp;
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(target);
                targetIp = addresses.First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]无法解析目标: {Markup.Escape(ex.Message)}[/]");
                return true;
            }

            AnsiConsole.MarkupLine($"\n通过最多 30 个跃点跟踪到 [yellow]{Markup.Escape(target)}[/] [[[yellow]{targetIp}[/]]] 的路由:");
            AnsiConsole.MarkupLine("[grey](按 Esc 键可随时中断)[/]");

            var table = new Table().Border(TableBorder.Simple);
            table.AddColumn("跃点");
            table.AddColumn("延迟");
            table.AddColumn("IP 地址");
            table.AddColumn("主机名");

            // --- 修改开始: 引入CancellationToken实现立即中断 ---

            // 使用CancellationTokenSource来从键盘发出中断信号。
            using var cts = new CancellationTokenSource();
            var cancellationToken = cts.Token;
            bool wasCancelled = false;

            // 此任务在后台运行以侦听Esc键。
            // 当按下Esc时，它会取消CancellationTokenSource。
            var keyListenerTask = Task.Run(() =>
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                    {
                        // 向主循环发送取消信号。
                        cts.Cancel();
                    }
                    // 短暂等待以防止此循环消耗100%的CPU。
                    Task.Delay(50, cancellationToken).ContinueWith(_ => { });
                }
            }, cancellationToken);

            try
            {
                await AnsiConsole.Live(table)
                    .StartAsync(async ctx =>
                    {
                        const int maxHops = 30;
                        const int timeout = 4000; // 每次ping尝试的超时时间。

                        for (int ttl = 1; ttl <= maxHops && !cancellationToken.IsCancellationRequested; ttl++)
                        {
                            using var ping = new Ping();
                            var pingOptions = new PingOptions(ttl, true);
                            var stopwatch = new Stopwatch();

                            try
                            {
                                var pingTask = ping.SendPingAsync(targetIp, timeout, new byte[32], pingOptions);
                                stopwatch.Start();

                                // 创建一个仅在请求取消时才会完成的任务。
                                var cancellationDelayTask = Task.Delay(Timeout.Infinite, cancellationToken);

                                // 等待ping完成或触发取消。
                                var completedTask = await Task.WhenAny(pingTask, cancellationDelayTask);
                                stopwatch.Stop();

                                // 如果完成的任务是我们的取消任务，则中断循环。
                                if (completedTask == cancellationDelayTask)
                                {
                                    wasCancelled = true;
                                    break;
                                }

                                // 否则，ping任务已完成。等待它以获取结果。
                                var reply = await pingTask;

                                if (reply.Status == IPStatus.Success || reply.Status == IPStatus.TtlExpired)
                                {
                                    string hostname = "[grey]N/A[/]";
                                    try
                                    {
                                        // 同时使DNS查找也可被取消。
                                        var resolveHostTask = Dns.GetHostEntryAsync(reply.Address);
                                        var dnsCancellationTask = Task.Delay(1500, cancellationToken); // DNS的1.5秒超时
                                        var completedDnsTask = await Task.WhenAny(resolveHostTask, dnsCancellationTask);

                                        if (completedDnsTask == resolveHostTask && !resolveHostTask.IsFaulted)
                                        {
                                            hostname = Markup.Escape(resolveHostTask.Result.HostName);
                                        }
                                    }
                                    catch
                                    {
                                        // 忽略DNS解析错误。
                                    }

                                    table.AddRow(ttl.ToString(), $"[yellow]{stopwatch.ElapsedMilliseconds}ms[/]", $"[green]{reply.Address}[/]", hostname);
                                    ctx.Refresh();

                                    if (reply.Status == IPStatus.Success)
                                    {
                                        table.Caption = new TableTitle("[bold green]跟踪完成[/]");
                                        ctx.Refresh();
                                        return; // 跟踪成功完成。
                                    }
                                }
                                else
                                {
                                    table.AddRow(ttl.ToString(), "*", "[grey]请求超时[/]", "");
                                    ctx.Refresh();
                                }
                            }
                            catch (PingException)
                            {
                                table.AddRow(ttl.ToString(), "*", "[red]错误[/]", "");
                                ctx.Refresh();
                            }
                        }

                        // 根据循环结束的方式设置最终的表格标题。
                        if (wasCancelled)
                        {
                            table.Caption = new TableTitle("[bold yellow]跟踪已被用户中断[/]");
                        }
                        else
                        {
                            table.Caption = new TableTitle("[bold yellow]跟踪已达到最大跃点数[/]");
                        }
                        ctx.Refresh();
                    });
            }
            finally
            {
                // 确保后台的按键监听器被停止和清理。
                if (!cts.IsCancellationRequested)
                {
                    cts.Cancel();
                }
                await keyListenerTask;

                // 清理任何残留的按键输入。
                while (Console.KeyAvailable)
                {
                    Console.ReadKey(true);
                }
            }
            // --- 修改结束 ---

            return true;
        }

        /// <summary>
        /// 启动端口扫描。
        /// </summary>
        static async Task<bool> StartPortScan()
        {
            AnsiConsole.Clear();
            string? target;
            while (true)
            {
                target = GetInputWithCancel("[green]请输入目标 IP 地址: [/]");
                if (target is null) return false; // User cancelled
                if (IsValidIp(target)) break;
                AnsiConsole.MarkupLine("[red]无效的 IP 地址，请重试。[/]");
            }

            string? portString;
            while (true)
            {
                portString = GetInputWithCancel("[green]请输入要扫描的端口 (例如: 80, 443, 8000-8080): [/]");
                if (portString is null) return false; // User cancelled
                if (!string.IsNullOrWhiteSpace(portString)) break;
                AnsiConsole.MarkupLine("[red]端口不能为空，请重试。[/]");
            }

            var portsToScan = ParsePorts(portString);

            if (!portsToScan.Any())
            {
                AnsiConsole.MarkupLine("[yellow]没有要扫描的有效端口。[/]");
                return true;
            }

            AnsiConsole.MarkupLine($"\n正在扫描 [yellow]{Markup.Escape(target)}[/] 上的端口...");

            var openPorts = new ConcurrentBag<int>();

            await AnsiConsole.Progress()
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(),
                })
                .StartAsync(async ctx =>
                {
                    var task = ctx.AddTask("[green]扫描进度[/]", new ProgressTaskSettings { MaxValue = portsToScan.Count });
                    var semaphore = new SemaphoreSlim(100);

                    var scanTasks = portsToScan.Select(async port =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            using (var client = new TcpClient())
                            {
                                var connectTask = client.ConnectAsync(target!, port);
                                if (await Task.WhenAny(connectTask, Task.Delay(1000)) == connectTask && !connectTask.IsFaulted)
                                {
                                    openPorts.Add(port);
                                }
                            }
                        }
                        catch { }
                        finally
                        {
                            task.Increment(1);
                            semaphore.Release();
                        }
                    });
                    await Task.WhenAll(scanTasks);
                });

            AnsiConsole.WriteLine();
            var table = new Table().Title("[bold]扫描结果[/]").Border(TableBorder.Simple);
            table.AddColumn(new TableColumn("开放的端口").Centered());

            if (openPorts.Any())
            {
                foreach (var port in openPorts.OrderBy(p => p))
                {
                    table.AddRow($"[green]{port}[/]");
                }
            }
            else
            {
                table.AddRow("[grey]未发现开放端口[/]");
            }
            AnsiConsole.Write(table);
            return true;
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 优化: 实现一个可被 ESC 键取消的自定义文本输入方法。
        /// </summary>
        private static string? GetInputWithCancel(string promptMarkup)
        {
            AnsiConsole.Markup(promptMarkup);
            Console.CursorVisible = true;
            var input = new StringBuilder();

            while (true)
            {
                var key = Console.ReadKey(true);

                if (key.Key == ConsoleKey.Escape)
                {
                    Console.CursorVisible = false;
                    AnsiConsole.WriteLine();
                    return null;
                }

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.CursorVisible = false;
                    AnsiConsole.WriteLine();
                    return input.ToString();
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (input.Length > 0)
                    {
                        input.Length--;
                        Console.Write("\b \b");
                    }
                }
                else if (!char.IsControl(key.KeyChar))
                {
                    input.Append(key.KeyChar);
                    Console.Write(key.KeyChar);
                }
            }
        }

        /// <summary>
        /// 创建一个通用的、无闪烁的、响应迅速的菜单渲染方法，支持ESC退出。
        /// </summary>
        static Task<int> ShowMenuAsync(List<string> options, string title)
        {
            int selectedIndex = 0;
            var chosenIndex = -1;

            AnsiConsole.Live(new Grid())
                .Start(ctx =>
                {
                    IRenderable BuildMenuRenderable()
                    {
                        var menuItems = new List<IRenderable>
                        {
                            new Markup(title),
                            new Markup("[grey](使用 ↑/↓ 或数字键选择)[/]"),
                            new Markup("[grey](Enter 确认, Esc 返回)[/]"),
                            Text.Empty
                        };

                        for (int i = 0; i < options.Count; i++)
                        {
                            // 直接使用选项字符串，不再错误地转义它
                            var text = options[i];
                            if (i == selectedIndex)
                            {
                                menuItems.Add(new Markup($"[cyan]>[/] [underline blue]{i + 1}. {text}[/]"));
                            }
                            else
                            {
                                menuItems.Add(new Markup($"  {i + 1}. {text}"));
                            }
                        }
                        var menuRenderable = new Padder(new Rows(menuItems), new Padding(1, 1, 1, 1));
                        return new Grid().AddColumn().AddRow(menuRenderable);
                    }

                    ctx.UpdateTarget(BuildMenuRenderable());
                    ctx.Refresh();

                    while (true)
                    {
                        var keyInfo = Console.ReadKey(true);
                        bool selectionMade = false;

                        switch (keyInfo.Key)
                        {
                            case ConsoleKey.UpArrow:
                                selectedIndex = (selectedIndex - 1 + options.Count) % options.Count;
                                break;
                            case ConsoleKey.DownArrow:
                                selectedIndex = (selectedIndex + 1) % options.Count;
                                break;
                            case ConsoleKey.Enter:
                                chosenIndex = selectedIndex;
                                selectionMade = true;
                                break;
                            case ConsoleKey.Escape:
                                chosenIndex = -1;
                                selectionMade = true;
                                break;
                            default:
                                if (char.IsDigit(keyInfo.KeyChar))
                                {
                                    if (int.TryParse(keyInfo.KeyChar.ToString(), out int numChoice) && numChoice > 0 && numChoice <= options.Count)
                                    {
                                        chosenIndex = numChoice - 1;
                                        selectionMade = true;
                                    }
                                }
                                break;
                        }

                        if (selectionMade)
                        {
                            break;
                        }

                        ctx.UpdateTarget(BuildMenuRenderable());
                        ctx.Refresh();
                    }
                });

            return Task.FromResult(chosenIndex);
        }

        /// <summary>
        /// [已修复] 主菜单显示逻辑，通过缓存昂贵的系统调用结果来解决UI迟滞问题。
        /// </summary>
        static async Task<int> ShowMainMenuWithOptions(List<string> options)
        {
            int selectedIndex = 0;
            int chosenIndex = -1;

            // [修复] 在进入实时显示循环之前，一次性获取耗时的适配器信息。
            var activeAdapter = AdapterInfo.GetActiveAdapter();

            await AnsiConsole.Live(new Grid())
                .StartAsync(async ctx =>
                {
                    // 辅助方法，用于构建完整的UI布局。它现在使用从父作用域捕获的、缓存的'activeAdapter'。
                    IRenderable BuildLayout()
                    {
                        var menuItems = new List<IRenderable>
                        {
                            new Markup("[bold]您希望执行什么操作?[/]"),
                            new Markup("[grey](使用 ↑/↓ 或数字键选择)[/]"),
                            new Markup("[grey](Enter 确认, Esc 退出)[/]"),
                            Text.Empty
                        };

                        for (int i = 0; i < options.Count; i++)
                        {
                            var text = Markup.Escape(options[i]);
                            if (i == selectedIndex)
                            {
                                menuItems.Add(new Markup($"[cyan]>[/] [underline blue]{i + 1}. {text}[/]"));
                            }
                            else
                            {
                                menuItems.Add(new Markup($"  {i + 1}. {text}"));
                            }
                        }
                        var menuRenderable = new Padder(new Rows(menuItems), new Padding(1, 1, 1, 1));

                        // [修复] 使用新的 GetLocalInfoGrid(AdapterInfo) 方法，传入缓存的数据。
                        var localPanel = new Panel(GetLocalInfoGrid(activeAdapter)).Header("[bold blue]本地网络信息[/]").Border(BoxBorder.Rounded);
                        var publicPanel = new Panel(GetPublicInfoGrid()).Header("[bold green]公网信息[/]").Border(BoxBorder.Rounded);
                        var infoGrid = new Grid().AddColumn().AddColumn().AddRow(localPanel, publicPanel);

                        return new Rows(infoGrid, menuRenderable);
                    }

                    var stopwatch = Stopwatch.StartNew();
                    var refreshInterval = TimeSpan.FromMilliseconds(500); // 动态数据刷新间隔

                    // 首次渲染
                    ctx.UpdateTarget(BuildLayout());
                    ctx.Refresh();

                    bool exitLoop = false;
                    while (!exitLoop)
                    {
                        // 优先处理所有待处理的按键输入，以实现即时响应
                        while (Console.KeyAvailable)
                        {
                            var keyInfo = Console.ReadKey(true);
                            switch (keyInfo.Key)
                            {
                                case ConsoleKey.UpArrow:
                                    selectedIndex = (selectedIndex - 1 + options.Count) % options.Count;
                                    break;
                                case ConsoleKey.DownArrow:
                                    selectedIndex = (selectedIndex + 1) % options.Count;
                                    break;
                                case ConsoleKey.Enter:
                                    chosenIndex = selectedIndex;
                                    exitLoop = true;
                                    break;
                                case ConsoleKey.Escape:
                                    chosenIndex = -1;
                                    exitLoop = true;
                                    break;
                                default:
                                    if (char.IsDigit(keyInfo.KeyChar))
                                    {
                                        if (int.TryParse(keyInfo.KeyChar.ToString(), out int numChoice) && numChoice > 0 && numChoice <= options.Count)
                                        {
                                            chosenIndex = numChoice - 1;
                                            exitLoop = true;
                                        }
                                    }
                                    break;
                            }

                            if (exitLoop) break;

                            // 每次按键后立即重新渲染，以提供快速的视觉反馈
                            ctx.UpdateTarget(BuildLayout());
                            ctx.Refresh();
                            stopwatch.Restart(); // 按键后重置定时器
                        }

                        if (exitLoop) break;

                        // 如果没有按键，检查是否到了为动态数据（时钟等）进行定期刷新的时间
                        if (stopwatch.Elapsed > refreshInterval)
                        {
                            ctx.UpdateTarget(BuildLayout());
                            ctx.Refresh();
                            stopwatch.Restart();
                        }

                        // 在主循环中进行短暂的等待，以防止在空闲时占用100%的CPU
                        await Task.Delay(10);
                    }
                });

            return chosenIndex;
        }


        /// <summary>
        /// 提示用户选择一个网络适配器。
        /// </summary>
        static async Task<string?> SelectAdapter(string prompt)
        {
            var adapters = AdapterInfo.GetAvailableAdapters();
            if (!adapters.Any())
            {
                AnsiConsole.Clear();
                AnsiConsole.MarkupLine("[red]未找到已连接的网络适配器。[/]");
                AnsiConsole.MarkupLine("[yellow]请确保网络已连接，或以管理员权限运行本程序。[/]");
                AnsiConsole.Prompt(new TextPrompt<string>("[grey]按任意键继续...[/]").AllowEmpty());
                return null;
            }

            var displayList = adapters.Select(a => a.Display).ToList();
            displayList.Add("  返回主菜单");

            var choiceIndex = await ShowMenuAsync(displayList, $"[bold]{prompt}[/]");

            if (choiceIndex == -1 || choiceIndex >= adapters.Count)
            {
                return null;
            }

            return adapters[choiceIndex].Name;
        }

        /// <summary>
        /// 执行 netsh 命令并对常见错误进行友好提示。
        /// </summary>
        static bool ExecuteNetsh(string arguments)
        {
            try
            {
                using (Process p = new Process())
                {
                    p.StartInfo.FileName = "netsh.exe";
                    p.StartInfo.Arguments = arguments;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.StartInfo.CreateNoWindow = true;
                    p.StartInfo.StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
                    p.StartInfo.StandardErrorEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);

                    p.Start();
                    string output = p.StandardOutput.ReadToEnd();
                    string error = p.StandardError.ReadToEnd();
                    p.WaitForExit();

                    if (p.ExitCode != 0)
                    {
                        AnsiConsole.WriteLine();
                        var panel = new Panel(GetErrorMessage(error, output))
                            .Header("[bold red]NETSH 命令执行失败[/]")
                            .Border(BoxBorder.Rounded);
                        AnsiConsole.Write(panel);
                        return false;
                    }
                    return true;
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]执行 netsh 时发生意外错误: {Markup.Escape(ex.Message)}[/]");
                return false;
            }
        }

        static string GetErrorMessage(string error, string output)
        {
            string errorMessage = string.IsNullOrWhiteSpace(error) ? output.Trim() : error.Trim();
            if (errorMessage.Contains("requires elevation") || errorMessage.Contains("请求的操作需要提升"))
                return "[red]错误: 权限不足。\n请尝试以管理员身份运行此程序。[/]";
            if (errorMessage.Contains("Element not found") || errorMessage.Contains("找不到元素"))
                return "[red]错误: 网络适配器名称无效或不存在。[/]";
            if (errorMessage.Contains("syntax of the command is incorrect") || errorMessage.Contains("命令的语法不正确"))
                return "[red]错误: 命令语法不正确。请检查输入的值是否有效。[/]";
            if (errorMessage.Contains("object with this name already exists") || errorMessage.Contains("同名的对象已存在"))
                return "[red]错误: 对象已存在。\n例如，您可能尝试添加一个已经存在的 DNS 服务器地址。[/]";
            return $"[red]未知错误:\n{Markup.Escape(errorMessage)}[/]";
        }


        /// <summary>
        /// 验证字符串是否为有效的IPv4地址。
        /// </summary>
        static bool IsValidIp(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            return IPAddress.TryParse(ip, out _);
        }

        /// <summary>
        /// 验证字符串是否为有效的IPv4地址或主机名。
        /// </summary>
        static bool IsValidIpOrHostname(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            return Uri.CheckHostName(host) != UriHostNameType.Unknown;
        }

        #endregion

        #region 扫描器与UI辅助方法

        /// <summary>
        /// 打印包含主机名的对齐扫描结果表格。
        /// </summary>
        private static void PrintResultsTable(List<ScanResult> results, string localIp, string tableTitle = "[bold blue]局域网扫描结果[/]")
        {
            var table = new Table().Expand().Border(TableBorder.Rounded);
            table.Title = new TableTitle(tableTitle);
            table.AddColumn("[bold]IP 地址[/]");
            table.AddColumn("[bold]MAC 地址[/]");
            table.AddColumn("[bold]主机名[/]");

            if (results.Any())
            {
                var sortedResults = results.OrderBy(r => IPAddress.Parse(r.IpAddress).GetAddressBytes(), new IPAddressComparer());
                foreach (var entry in sortedResults)
                {
                    var rowStyle = entry.IpAddress == localIp ? new Style(Color.Cyan1, decoration: Decoration.Bold) : Style.Plain;
                    table.AddRow(
                        new Markup(entry.IpAddress, rowStyle),
                        new Markup(entry.MacAddress, rowStyle),
                        new Markup(Markup.Escape(entry.Hostname), rowStyle)
                    );
                }
            }
            else
            {
                table.AddRow("[grey]未发现任何在线设备。[/]", "", "");
            }
            AnsiConsole.Write(table);
        }

        /// <summary>
        /// 根据网段地址和子网掩码计算出所有可用的主机IP地址范围。
        /// </summary>
        private static IEnumerable<IPAddress> GetIpRange(IPAddress networkAddress, IPAddress subnetMask)
        {
            var networkBytes = networkAddress.GetAddressBytes();
            var maskBytes = subnetMask.GetAddressBytes();

            var broadcastBytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                broadcastBytes[i] = (byte)(networkBytes[i] | (byte)~maskBytes[i]);
            }

            uint startIp = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);
            uint endIp = BitConverter.ToUInt32(broadcastBytes.Reverse().ToArray(), 0);

            // 确保我们不会扫描网络和广播地址
            if (endIp > startIp + 1)
            {
                for (uint i = startIp + 1; i < endIp; i++)
                {
                    yield return new IPAddress(BitConverter.GetBytes(i).Reverse().ToArray());
                }
            }
        }

        /// <summary>
        /// 执行 arp -a 命令并解析结果，返回IP到MAC地址的映射字典。
        /// </summary>
        private static Dictionary<string, string> GetArpCache()
        {
            var cache = new Dictionary<string, string>();
            try
            {
                using (var p = new Process())
                {
                    p.StartInfo.FileName = "arp.exe";
                    p.StartInfo.Arguments = "-a";
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();

                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();

                    var matches = Regex.Matches(output, @"\s+([0-9\.]+)\s+([0-9a-fA-F\-]+)\s+");
                    foreach (Match match in matches.Cast<Match>())
                    {
                        if (match.Groups.Count == 3)
                        {
                            cache[match.Groups[1].Value.Trim()] = match.Groups[2].Value.Trim().ToUpper();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]获取ARP缓存失败: {Markup.Escape(ex.Message)}[/]");
            }
            return cache;
        }

        /// <summary>
        /// 将 PhysicalAddress 对象格式化为 XX-XX-XX-XX-XX-XX 格式的字符串。
        /// </summary>
        private static string FormatMacAddress(PhysicalAddress address)
        {
            if (address == null) return "(N/A)";
            var bytes = address.GetAddressBytes();
            if (bytes == null || bytes.Length == 0) return "(N/A)";
            return string.Join("-", bytes.Select(b => b.ToString("X2")));
        }

        /// <summary>
        /// 解析端口字符串 (例如 "80,443,8000-8080") 为一个整数列表。
        /// </summary>
        private static List<int> ParsePorts(string? portString)
        {
            var ports = new HashSet<int>();
            if (string.IsNullOrWhiteSpace(portString)) return new List<int>();

            foreach (var part in portString.Split(','))
            {
                var trimmedPart = part.Trim();
                if (trimmedPart.Contains('-'))
                {
                    var rangeParts = trimmedPart.Split('-');
                    if (rangeParts.Length == 2 && int.TryParse(rangeParts[0], out int start) && int.TryParse(rangeParts[1], out int end) && start <= end)
                    {
                        for (int i = start; i <= end; i++)
                        {
                            if (i > 0 && i < 65536) ports.Add(i);
                        }
                    }
                }
                else
                {
                    if (int.TryParse(trimmedPart, out int port))
                    {
                        if (port > 0 && port < 65536) ports.Add(port);
                    }
                }
            }
            return ports.ToList();
        }

        /// <summary>
        /// 用于IP地址排序的比较器。
        /// </summary>
        private class IPAddressComparer : IComparer<byte[]?>
        {
            public int Compare(byte[]? x, byte[]? y)
            {
                if (x == null && y == null) return 0;
                if (x == null) return -1;
                if (y == null) return 1;

                for (int i = 0; i < x.Length; i++)
                {
                    if (i >= y.Length) return 1;
                    if (x[i] != y[i])
                    {
                        return x[i].CompareTo(y[i]);
                    }
                }
                return x.Length.CompareTo(y.Length);
            }
        }

        #endregion
    }

    /// <summary>
    /// 用于存储和格式化网络适配器信息的辅助类。
    /// </summary>
    public class AdapterInfo
    {
        public string Name { get; }
        public string Description { get; }
        public bool IsActive { get; }
        public bool IsVirtual { get; }
        public string Display { get; private set; }
        public string IpAddress { get; }
        public bool IsDhcpEnabled { get; }
        public string AdapterType { get; }

        public AdapterInfo(NetworkInterface ni, int activeInterfaceIndex)
        {
            Name = ni.Name;
            Description = ni.Description;
            AdapterType = ni.NetworkInterfaceType.ToString();

            // 添加平台检查来安全地访问特定于Windows的属性
            if (OperatingSystem.IsWindows())
            {
                var ipv4Props = ni.GetIPProperties().GetIPv4Properties();
                if (ipv4Props != null)
                {
                    IsActive = ipv4Props.Index == activeInterfaceIndex;
                    IsDhcpEnabled = ipv4Props.IsDhcpEnabled;
                }
                else
                {
                    IsActive = false;
                    IsDhcpEnabled = false;
                }
            }
            else // 对于非Windows平台，提供默认值
            {
                IsActive = ni.OperationalStatus == OperationalStatus.Up;
                IsDhcpEnabled = false; // 非Windows平台下，我们无法轻易判断，先默认为false
            }


            string desc = ni.Description.ToLower();
            IsVirtual = desc.Contains("virtual") || desc.Contains("vpn") || desc.Contains("tap") || desc.Contains("tun") || desc.Contains("clash");

            IpAddress = ni.GetIPProperties().UnicastAddresses
                .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address.ToString() ?? "N/A";

            Display = string.Empty;
            SetDisplay();
        }

        /// <summary>
        /// 优化后的方法：设置包含详细描述的显示名称
        /// </summary>
        public void SetDisplay()
        {
            string prefix = IsActive ? "[green]*[/]" : " ";
            var markers = new List<string>();
            if (IsActive) markers.Add("[green](活动)[/]");
            if (IsVirtual) markers.Add("[grey](虚拟)[/]");

            string markerString = string.Join(" ", markers);

            // 使用 Markup.Escape 防止网卡描述中的特殊字符（如'['）破坏 Spectre.Console 的格式
            // 使用 [dim]...[/] 样式让描述文字颜色变暗，突出重点
            Display = $"{prefix} {Markup.Escape(Name)} {markerString} - [dim]{Markup.Escape(Description)}[/]";
        }

        /// <summary>
        /// 获取所有可用的网络适配器。
        /// </summary>
        public static List<AdapterInfo> GetAvailableAdapters()
        {
            var adapterInfos = new List<AdapterInfo>();
            try
            {
                var allInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                var activeInterfaceIndex = allInterfaces
                    .FirstOrDefault(ni => ni.OperationalStatus == OperationalStatus.Up && ni.GetIPProperties().GatewayAddresses
                    .Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))?.GetIPProperties().GetIPv4Properties()?.Index ?? -1;

                foreach (NetworkInterface ni in allInterfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        var info = new AdapterInfo(ni, activeInterfaceIndex);
                        adapterInfos.Add(info);
                    }
                }
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]扫描网络适配器时出错: {Markup.Escape(ex.Message)}[/]");
            }

            return adapterInfos
                .OrderBy(a => a.IsVirtual)
                .ThenByDescending(a => a.IsActive)
                .ToList();
        }

        /// <summary>
        /// 获取当前活动的适配器。
        /// </summary>
        public static AdapterInfo? GetActiveAdapter()
        {
            return GetAvailableAdapters().FirstOrDefault(a => a.IsActive);
        }
    }
}
