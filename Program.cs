using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace IPSwitcher
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // 注册代码页提供程序以支持GBK等编码
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // 设置控制台编码为UTF-8以正确显示中文
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                if (!await MainMenu())
                {
                    break; // 如果MainMenu返回false则退出程序
                }
            }

            Console.WriteLine("程序已退出。");
        }

        /// <summary>
        /// 主菜单循环, 返回 false 以退出应用程序。
        /// </summary>
        static async Task<bool> MainMenu()
        {
            var options = new List<string>
            {
                "[1] 配置网络适配器 IP",
                "[2] 扫描局域网设备",
                "[3] 退出程序"
            };

            int actionChoice = GetInteractiveMenuChoice(DrawDashboard, options, 1);

            switch (actionChoice)
            {
                case -1: // 用户在顶层菜单按下了 Esc
                    return false;
                case 1:
                    ConfigureIpMenu();
                    break;
                case 2:
                    await StartLanScan();
                    break;
                case 3:
                    return false; // 发出退出主循环的信号
            }

            if (actionChoice != 2)
            {
                Console.WriteLine("操作完成。按任意键返回主菜单...");
                Console.ReadKey(true);
            }
            return true; // 继续主循环
        }

        /// <summary>
        /// 绘制实时信息仪表盘的静态框架。
        /// </summary>
        static void DrawDashboard()
        {
            Console.WriteLine("┌───────────────────────────────────────────────────────┐");
            Console.WriteLine("│                                                       │"); // 时间行
            Console.WriteLine("│                                                       │"); // IP 行
            Console.WriteLine("└───────────────────────────────────────────────────────┘");
            Console.WriteLine("\n 您希望执行什么操作?");
            UpdateDashboard(); // 首次填充数据
        }

        /// <summary>
        /// 仅更新仪表盘中的动态数据，避免闪烁。
        /// </summary>
        static void UpdateDashboard()
        {
            var originalLeft = Console.CursorLeft;
            var originalTop = Console.CursorTop;

            var activeAdapter = AdapterInfo.GetActiveAdapter();
            string time = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string activeIp = activeAdapter?.IpAddress ?? "N/A";
            string adapterName = activeAdapter?.Name ?? "无活动连接";

            string timeLine = $"当前时间: {time}";
            string ipLine = $"活动连接: {adapterName} ({activeIp})";

            Console.SetCursorPosition(2, 1); // 定位到第一行数据区
            Console.Write(PadRightForMixedChars(timeLine, 53));

            Console.SetCursorPosition(2, 2); // 定位到第二行数据区
            Console.Write(PadRightForMixedChars(ipLine, 53));

            Console.SetCursorPosition(originalLeft, originalTop); // 恢复光标位置
        }

        /// <summary>
        /// 启动局域网扫描，优先使用活动适配器。
        /// </summary>
        static async Task StartLanScan()
        {
            var activeAdapter = AdapterInfo.GetActiveAdapter();
            string? adapterToScan;

            if (activeAdapter != null)
            {
                // 如果找到活动适配器，直接使用
                adapterToScan = activeAdapter.Name;
            }
            else
            {
                // 否则，让用户选择
                adapterToScan = SelectAdapter("未找到活动网络，请选择要扫描的适配器");
            }

            if (!string.IsNullOrEmpty(adapterToScan))
            {
                await ScanLanDevices(adapterToScan);
                Console.WriteLine("\n扫描完成。按任意键返回主菜单...");
                Console.ReadKey(true);
            }
        }

        /// <summary>
        /// 用于IP配置的二级菜单。
        /// </summary>
        static void ConfigureIpMenu()
        {
            string? selectedAdapter = SelectAdapter("请选择要配置的网络适配器");
            if (string.IsNullOrEmpty(selectedAdapter)) return;

            var prompt = $" 已选定适配器: \"{selectedAdapter}\"\n" +
                         "---------------------------------------------------------\n\n" +
                         "请选择要执行的操作:";
            var options = new List<string>
            {
                "[1] 设置静态 IP 地址",
                "[2] 设置为自动获取 (DHCP)"
            };

            int choice = GetInteractiveMenuChoice(() => Console.WriteLine(prompt), options, 1);

            if (choice == -1) return; // 用户按下了 Esc

            if (choice == 1)
            {
                SetStaticIP(selectedAdapter);
            }
            else
            {
                SetDhcpIP(selectedAdapter);
            }
        }

        /// <summary>
        /// 扫描本地网络上的设备。
        /// </summary>
        static async Task ScanLanDevices(string adapterName)
        {
            Console.Clear();
            Console.WriteLine("================ 局域网设备扫描 ==================");

            var adapter = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => n.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase));

            if (adapter == null)
            {
                Console.WriteLine($"错误: 找不到名为 \"{adapterName}\" 的适配器。");
                return;
            }

            var ipInfo = adapter.GetIPProperties().UnicastAddresses
                .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            if (ipInfo == null)
            {
                Console.WriteLine($"错误: 适配器 \"{adapterName}\" 未配置IPv4地址。");
                return;
            }

            var ipAddress = ipInfo.Address;
            var subnetMask = ipInfo.IPv4Mask;
            var networkAddress = new IPAddress(ipAddress.GetAddressBytes().Zip(subnetMask.GetAddressBytes(), (a, b) => (byte)(a & b)).ToArray());

            var ipRange = GetIpRange(networkAddress, subnetMask).ToList();
            if (!ipRange.Any())
            {
                Console.WriteLine("错误: 无法确定有效的IP扫描范围。");
                return;
            }

            Console.WriteLine($"本机IP: {ipAddress}, 正在扫描网段: {networkAddress} / {subnetMask}");
            Console.WriteLine($"扫描范围: {ipRange.First()} - {ipRange.Last()}");
            Console.WriteLine("正在并行扫描，请稍候...");

            var onlineHosts = new List<IPAddress>();
            var pingTasks = new List<Task>();
            var semaphore = new SemaphoreSlim(100);

            foreach (var ip in ipRange)
            {
                await semaphore.WaitAsync();
                pingTasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        using (var ping = new Ping())
                        {
                            var reply = await ping.SendPingAsync(ip, 1000);
                            if (reply.Status == IPStatus.Success)
                            {
                                lock (onlineHosts)
                                {
                                    onlineHosts.Add(ip);
                                }
                            }
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(pingTasks);

            Console.WriteLine("\n扫描完成，正在获取MAC地址...");

            var arpCache = GetArpCache();
            var results = new Dictionary<string, string>();

            foreach (var host in onlineHosts.OrderBy(h => h.GetAddressBytes(), new IPAddressComparer()))
            {
                string ipStr = host.ToString();
                if (arpCache.TryGetValue(ipStr, out string? macAddress))
                {
                    results[ipStr] = macAddress;
                }
                else
                {
                    results[ipStr] = "(无法获取)";
                }
            }

            PrintResultsTable(results);
        }


        /// <summary>
        /// 将适配器设置为使用 DHCP。
        /// </summary>
        static void SetDhcpIP(string adapterName)
        {
            Console.Clear();
            Console.WriteLine();
            Console.WriteLine($" 正在设置 \"{adapterName}\" 为自动获取 IP 地址 (DHCP)...");
            if (!ExecuteNetsh($"interface ipv4 set address name=\"{adapterName}\" source=dhcp")) return;

            Console.WriteLine($" 正在设置 \"{adapterName}\" 为自动获取 DNS 服务器 (DHCP)...");
            if (!ExecuteNetsh($"interface ipv4 set dns name=\"{adapterName}\" source=dhcp")) return;

            ShowSuccess(adapterName);
        }

        /// <summary>
        /// 为适配器设置静态IP。
        /// </summary>
        static void SetStaticIP(string adapterName)
        {
            Console.Clear();
            Console.WriteLine();
            Console.WriteLine($" 正在为 \"{adapterName}\" 配置静态 IP");
            Console.WriteLine(" (直接按回车键即可使用中括号 [] 内的默认值)");
            Console.WriteLine();
            Console.WriteLine("---------------------------------------------------------");
            Console.WriteLine();

            string staticIP;
            while (true)
            {
                Console.Write("请输入静态 IP 地址: ");
                staticIP = Console.ReadLine() ?? "";
                if (!string.IsNullOrWhiteSpace(staticIP) && IsValidIp(staticIP)) break;
                Console.WriteLine(" IP 地址不能为空或格式不正确。");
            }

            string defaultSubnet = "255.255.255.0";
            var ipParts = staticIP.Split('.');
            string defaultGateway = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.1";

            Console.Write($"请输入子网掩码 [默认: {defaultSubnet}]: ");
            string subnetMask = Console.ReadLine() ?? "";
            if (string.IsNullOrWhiteSpace(subnetMask)) subnetMask = defaultSubnet;

            Console.Write($"请输入网关 (如果不需要请留空) [默认: {defaultGateway}]: ");
            string gateway = Console.ReadLine() ?? "";
            if (string.IsNullOrWhiteSpace(gateway)) gateway = defaultGateway;

            Console.WriteLine();
            Console.WriteLine(" 正在应用 IP 配置...");
            string command = string.IsNullOrWhiteSpace(gateway)
                ? $"interface ipv4 set address name=\"{adapterName}\" static {staticIP} {subnetMask}"
                : $"interface ipv4 set address name=\"{adapterName}\" static {staticIP} {subnetMask} {gateway}";
            if (!ExecuteNetsh(command)) return;

            Console.WriteLine();
            string defaultDns1 = "114.114.114.114";
            string defaultDns2 = "8.8.8.8";

            Console.Write($"请输入主 DNS 服务器 [默认: {defaultDns1}]: ");
            string dns1 = Console.ReadLine() ?? "";
            if (string.IsNullOrWhiteSpace(dns1)) dns1 = defaultDns1;

            Console.Write($"请输入备用 DNS 服务器 (可选) [默认: {defaultDns2}]: ");
            string dns2 = Console.ReadLine() ?? "";
            if (string.IsNullOrWhiteSpace(dns2)) dns2 = defaultDns2;

            Console.WriteLine();
            Console.WriteLine(" 正在应用 DNS 配置...");
            if (!ExecuteNetsh($"interface ipv4 set dns name=\"{adapterName}\" static {dns1}")) return;

            if (!string.IsNullOrWhiteSpace(dns2))
            {
                ExecuteNetsh($"interface ipv4 add dns name=\"{adapterName}\" {dns2} index=2");
            }

            ShowSuccess(adapterName);
        }

        /// <summary>
        /// 显示成功信息和当前配置。
        /// </summary>
        static void ShowSuccess(string adapterName)
        {
            Console.Clear();
            Console.WriteLine("===================== 操作成功 =====================");
            Console.WriteLine();
            Console.WriteLine($" \"{adapterName}\" 的网络配置已更新。");
            Console.WriteLine(" 以下为当前配置:");
            Console.WriteLine("---------------------------------------------------------");

            try
            {
                Thread.Sleep(500);
                var ni = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase));

                if (ni == null)
                {
                    Console.WriteLine(" 无法获取该适配器的详细信息。");
                    return;
                }

                var ipProps = ni.GetIPProperties();
                var ipv4AddressInfo = ipProps.UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                if (ipv4AddressInfo != null)
                {
                    Console.WriteLine($"   IPv4 地址 . . . . . . . . . . . : {ipv4AddressInfo.Address}");
                    Console.WriteLine($"   子网掩码  . . . . . . . . . . . : {ipv4AddressInfo.IPv4Mask}");
                }
                else
                {
                    Console.WriteLine("   IPv4 地址 . . . . . . . . . . . : (未分配)");
                }

                var gateway = ipProps.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                Console.WriteLine($"   默认网关. . . . . . . . . . . : {(gateway != null ? gateway.Address.ToString() : "(无)")}");

                Console.WriteLine("   DNS 服务器. . . . . . . . . . . : ");
                var dnsServers = ipProps.DnsAddresses.Where(d => d.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                if (dnsServers.Any())
                {
                    foreach (var dns in dnsServers)
                    {
                        Console.WriteLine($"                                     {dns}");
                    }
                }
                else
                {
                    Console.WriteLine("                                     (无)");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" 获取配置时出错: {ex.Message}");
            }
            Console.WriteLine();
        }

        #region 辅助方法

        /// <summary>
        /// 提示用户选择一个网络适配器。
        /// </summary>
        static string? SelectAdapter(string prompt)
        {
            var adapters = AdapterInfo.GetAvailableAdapters();
            if (!adapters.Any())
            {
                Console.Clear();
                Console.WriteLine("未找到已连接的网络适配器。");
                Console.WriteLine("请确保网络已连接，或以管理员权限运行本程序。");
                Console.ReadKey();
                return null;
            }

            var adapterDisplayList = adapters.Select(a => a.Display).ToList();

            int defaultChoice = adapters.FindIndex(a => a.IsActive);
            if (defaultChoice == -1) defaultChoice = 0;

            var title = $"===== {prompt} =====";
            int selectedIndex = GetInteractiveMenuChoice(() => Console.WriteLine(title), adapterDisplayList, defaultChoice + 1);

            if (selectedIndex == -1) return null; // 用户按下了 Esc
            return adapters[selectedIndex - 1].Name;
        }

        /// <summary>
        /// 提供一个可通过箭头和Enter键选择的交互式菜单。
        /// </summary>
        /// <returns>返回选中项从1开始的索引，如果按下Esc则返回-1。</returns>
        static int GetInteractiveMenuChoice(Action drawPrompt, List<string> options, int defaultChoice)
        {
            int selectedIndex = defaultChoice - 1;
            ConsoleKeyInfo key;
            var timer = new System.Timers.Timer(1000);

            Console.CursorVisible = false;

            // 绘制静态框架
            Console.Clear();
            drawPrompt();
            Console.WriteLine();

            // 预留选项的位置
            int menuTop = Console.CursorTop;
            for (int i = 0; i < options.Count; i++)
            {
                Console.WriteLine(new string(' ', Console.WindowWidth));
            }
            Console.WriteLine("\n(使用 ↑/↓ 箭头选择, Enter 确认, Esc 返回/退出)");

            Action<int> drawOption = (index) =>
            {
                Console.SetCursorPosition(0, menuTop + index);
                if (index == selectedIndex)
                {
                    Console.BackgroundColor = ConsoleColor.DarkCyan;
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($" > {options[index]}");
                    Console.ResetColor();
                }
                else
                {
                    Console.Write($"   {options[index]}");
                }
                // 清除行尾可能存在的旧字符
                Console.Write(new string(' ', Console.WindowWidth - Console.CursorLeft));
            };

            for (int i = 0; i < options.Count; i++)
            {
                drawOption(i);
            }

            timer.Elapsed += (sender, e) => UpdateDashboard();
            if (drawPrompt.Method.Name.Contains("Dashboard"))
            {
                timer.Start();
            }

            while (true)
            {
                key = Console.ReadKey(true);

                int previousIndex = selectedIndex;

                switch (key.Key)
                {
                    case ConsoleKey.UpArrow:
                        selectedIndex = (selectedIndex > 0) ? selectedIndex - 1 : options.Count - 1;
                        break;
                    case ConsoleKey.DownArrow:
                        selectedIndex = (selectedIndex < options.Count - 1) ? selectedIndex + 1 : 0;
                        break;
                    case ConsoleKey.Enter:
                        timer.Stop();
                        Console.CursorVisible = true;
                        Console.Clear();
                        return selectedIndex + 1;
                    case ConsoleKey.Escape:
                        timer.Stop();
                        Console.CursorVisible = true;
                        Console.Clear();
                        return -1;
                    default:
                        if (char.IsDigit(key.KeyChar))
                        {
                            if (int.TryParse(key.KeyChar.ToString(), out int numChoice) && numChoice > 0 && numChoice <= options.Count)
                            {
                                timer.Stop();
                                Console.CursorVisible = true;
                                Console.Clear();
                                return numChoice;
                            }
                        }
                        break;
                }

                if (previousIndex != selectedIndex)
                {
                    drawOption(previousIndex);
                    drawOption(selectedIndex);
                }
            }
        }

        /// <summary>
        /// 执行 netsh 命令并捕获错误。
        /// </summary>
        static bool ExecuteNetsh(string arguments)
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
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n--- NETSH 命令执行失败 ---");
                    Console.WriteLine($"错误代码: {p.ExitCode}");
                    if (!string.IsNullOrWhiteSpace(output)) Console.WriteLine($"输出信息: {output.Trim()}");
                    if (!string.IsNullOrWhiteSpace(error)) Console.WriteLine($"错误详情: {error.Trim()}");
                    Console.WriteLine("--------------------------");
                    Console.ResetColor();
                    Console.WriteLine("请检查命令或确保以管理员权限运行。按任意键继续...");
                    Console.ReadKey();
                    return false;
                }
                return true;
            }
        }

        /// <summary>
        /// 验证IP地址格式是否正确。
        /// </summary>
        static bool IsValidIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            var parts = ip.Split('.');
            if (parts.Length != 4) return false;
            return parts.All(part => byte.TryParse(part, out _));
        }

        #endregion

        #region 扫描器与UI辅助方法

        /// <summary>
        /// 打印对齐的扫描结果表格。
        /// </summary>
        private static void PrintResultsTable(Dictionary<string, string> results)
        {
            const int ipWidth = 20;
            const int macWidth = 22;

            string ipHeader = "IP 地址";
            string macHeader = "MAC 地址";

            string header = $"│ {PadRightForMixedChars(ipHeader, ipWidth)} │ {PadRightForMixedChars(macHeader, macWidth)} │";
            string separator = $"├{new string('─', ipWidth + 2)}┼{new string('─', macWidth + 2)}┤";

            Console.WriteLine("\n┌" + new string('─', ipWidth + 2) + "┬" + new string('─', macWidth + 2) + "┐");
            Console.WriteLine(header);
            Console.WriteLine(separator);

            if (results.Any())
            {
                foreach (var entry in results)
                {
                    Console.WriteLine($"│ {entry.Key,-ipWidth} │ {entry.Value,-macWidth} │");
                }
            }
            else
            {
                string noDeviceMsg = "未发现任何在线设备。";
                Console.WriteLine($"│ {PadRightForMixedChars(noDeviceMsg, ipWidth + macWidth + 3)} │");
            }
            Console.WriteLine("└" + new string('─', ipWidth + 2) + "┴" + new string('─', macWidth + 2) + "┘\n");
        }

        /// <summary>
        /// 计算字符串在控制台的显示宽度 (一个中文字符宽度为2)。
        /// </summary>
        private static int GetVisibleLength(string str)
        {
            return str.Sum(c => Regex.IsMatch(c.ToString(), @"[\u4e00-\u9fa5]") ? 2 : 1);
        }

        /// <summary>
        /// 填充字符串以使其在混合中/英文字符时对齐。
        /// </summary>
        private static string PadRightForMixedChars(string str, int totalWidth)
        {
            int currentWidth = GetVisibleLength(str);
            int padding = totalWidth - currentWidth;
            return str + new string(' ', padding > 0 ? padding : 0);
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

            if (startIp + 1 <= endIp - 1)
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

                    var matches = Regex.Matches(output, @"\s*([0-9\.]+)\s+([0-9a-fA-F\-]+)\s+");
                    foreach (Match match in matches)
                    {
                        cache[match.Groups[1].Value] = match.Groups[2].Value.ToUpper();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"获取ARP缓存失败: {ex.Message}");
            }
            return cache;
        }

        /// <summary>
        /// 初始化性能计数器。
        /// </summary>
        private static void InitializePerformanceCounters()
        {
#if NETFRAMEWORK || WINDOWS
            try
            {
                _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                _ramCounter = new PerformanceCounter("Memory", "% Committed Bytes In Use");
                // 首次调用以获取初始值
                _cpuCounter.NextValue();
                _ramCounter.NextValue();
            }
            catch (Exception ex)
            {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("警告: 性能计数器初始化失败。");
                Console.WriteLine("CPU和RAM使用率将不可用。");
                Console.WriteLine("\n可能的原因及解决方案:");
                Console.WriteLine(" 1. 权限不足: 请确保以管理员权限运行本程序。");
                Console.WriteLine(" 2. 缺少依赖: (如果使用.NET Core/5+) 请确保已为项目添加 System.Diagnostics.PerformanceCounter NuGet包。");
                Console.WriteLine(" 3. 系统计数器损坏: 可以尝试在管理员CMD或PowerShell中运行 'lodctr /r' 命令来重建系统性能计数器。");
                Console.WriteLine($"\n错误详情: {ex.Message}");
                Console.ResetColor();
                Console.WriteLine("\n按任意键继续...");
                Console.ReadKey();

                _cpuCounter = null;
                _ramCounter = null;
            }
#endif
        }

        /// <summary>
        /// 释放性能计数器资源。
        /// </summary>
        private static void DisposePerformanceCounters()
        {
#if NETFRAMEWORK || WINDOWS
            _cpuCounter?.Dispose();
            _ramCounter?.Dispose();
#endif
        }

        /// <summary>
        /// 用于IP地址排序的比较器。
        /// </summary>
        private class IPAddressComparer : IComparer<byte[]?>
        {
            // 修复警告 CS8767: 允许参数为可空类型
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
        public bool IsActive { get; }
        public bool IsVirtual { get; }
        public string Display { get; private set; }
        public string IpAddress { get; }

        public AdapterInfo(NetworkInterface ni, int activeInterfaceIndex)
        {
            Name = ni.Name;
            IsActive = ni.GetIPProperties().GetIPv4Properties()?.Index == activeInterfaceIndex;

            string desc = ni.Description.ToLower();
            IsVirtual = desc.Contains("virtual") || desc.Contains("vpn") || desc.Contains("tap") || desc.Contains("tun") || desc.Contains("clash");

            IpAddress = ni.GetIPProperties().UnicastAddresses
                .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address.ToString() ?? "N/A";

            // 修复警告: 在构造函数中初始化 Display 属性
            Display = string.Empty;
        }

        /// <summary>
        /// 在排序后设置正确的显示编号。
        /// </summary>
        public void SetDisplayIndex(int index)
        {
            string prefix = IsActive ? "* [活动]" : "  [普通]";
            if (IsVirtual) prefix = "  [虚拟]";
            if (IsActive && IsVirtual) prefix = "* [虚拟]";

            Display = $"{prefix} [{index}] {Name}";
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
                    .FirstOrDefault(ni => ni.GetIPProperties().GatewayAddresses
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
                Console.WriteLine($" 扫描网络适配器时出错: {ex.Message}");
            }

            var sortedAdapters = adapterInfos
                .OrderBy(a => a.IsVirtual)
                .ThenByDescending(a => a.IsActive)
                .ToList();

            for (int i = 0; i < sortedAdapters.Count; i++)
            {
                sortedAdapters[i].SetDisplayIndex(i + 1);
            }
            return sortedAdapters;
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
