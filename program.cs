using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;

namespace IPSwitcher
{
    class Program
    {
        static void Main(string[] args)
        {
            // 注册代码页提供程序以支持GBK等编码
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // 设置控制台编码为UTF-8以正确显示中文
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                MainMenu();
                Console.WriteLine("操作完成。按任意键退出，或按 'R' 键返回主菜单...");
                var key = Console.ReadKey(true);
                if (key.KeyChar != 'r' && key.KeyChar != 'R')
                {
                    break;
                }
            }
        }

        static void MainMenu()
        {
            Console.Clear();
            Console.WriteLine("=========================================================");
            Console.WriteLine("               IP 地址快速切换器 v3.4 (C#)");
            Console.WriteLine("=========================================================");
            Console.WriteLine();
            Console.WriteLine(" 正在扫描可用的网络适配器...");
            Console.WriteLine();

            // 步骤 1: 检测并列出可用的网络适配器
            var adapters = GetAvailableAdapters();
            if (adapters.Count == 0)
            {
                Console.WriteLine(" 未找到已连接的网络适配器。");
                Console.WriteLine(" 请确保网络已连接，或以管理员权限运行本程序。");
                return;
            }

            for (int i = 0; i < adapters.Count; i++)
            {
                Console.WriteLine($" [{i + 1}] {adapters[i]}");
            }
            Console.WriteLine();

            // 步骤 2: 让用户选择一个适配器
            int adapterChoice = GetUserChoice("请输入要配置的适配器编号", 1, adapters.Count, 1) - 1;
            string selectedAdapter = adapters[adapterChoice];

            // 步骤 3: 让用户选择要执行的操作
            Console.Clear();
            Console.WriteLine($" 已选定适配器: \"{selectedAdapter}\"");
            Console.WriteLine();
            Console.WriteLine("---------------------------------------------------------");
            Console.WriteLine();
            Console.WriteLine(" 您希望执行什么操作?");
            Console.WriteLine();
            Console.WriteLine("   [1] 设置静态 IP 地址");
            Console.WriteLine("   [2] 设置为自动获取 (DHCP)");
            Console.WriteLine();

            int actionChoice = GetUserChoice("请输入您的选择", 1, 2, 1);

            if (actionChoice == 1)
            {
                SetStaticIP(selectedAdapter);
            }
            else
            {
                SetDhcpIP(selectedAdapter);
            }
        }

        /// <summary>
        /// 设置为自动获取 (DHCP)
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
        /// 设置静态IP
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

            // 获取 IP 地址
            string staticIP;
            while (true)
            {
                Console.Write("请输入静态 IP 地址: ");
                staticIP = Console.ReadLine();
                if (!string.IsNullOrWhiteSpace(staticIP) && IsValidIp(staticIP)) break;
                Console.WriteLine(" IP 地址不能为空或格式不正确。");
            }

            // 生成默认子网掩码和网关
            string defaultSubnet = "255.255.255.0";
            var ipParts = staticIP.Split('.');
            string defaultGateway = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.1";

            // 获取子网掩码
            Console.Write($"请输入子网掩码 [默认: {defaultSubnet}]: ");
            string subnetMask = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(subnetMask)) subnetMask = defaultSubnet;

            // 获取网关
            Console.Write($"请输入网关 (如果不需要请留空) [默认: {defaultGateway}]: ");
            string gateway = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(gateway)) gateway = defaultGateway;

            // 应用静态 IP 配置
            Console.WriteLine();
            Console.WriteLine(" 正在应用 IP 配置...");
            string command = string.IsNullOrWhiteSpace(gateway)
                ? $"interface ipv4 set address name=\"{adapterName}\" static {staticIP} {subnetMask}"
                : $"interface ipv4 set address name=\"{adapterName}\" static {staticIP} {subnetMask} {gateway}";
            if (!ExecuteNetsh(command)) return;

            // 设置静态DNS
            Console.WriteLine();
            string defaultDns1 = "114.114.114.114";
            string defaultDns2 = "8.8.8.8";

            Console.Write($"请输入主 DNS 服务器 [默认: {defaultDns1}]: ");
            string dns1 = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(dns1)) dns1 = defaultDns1;

            Console.Write($"请输入备用 DNS 服务器 (可选) [默认: {defaultDns2}]: ");
            string dns2 = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(dns2)) dns2 = defaultDns2;

            Console.WriteLine();
            Console.WriteLine(" 正在应用 DNS 配置...");
            if (!ExecuteNetsh($"interface ipv4 set dns name=\"{adapterName}\" static {dns1}")) return;

            if (!string.IsNullOrWhiteSpace(dns2))
            {
                // 备用DNS设置失败通常不影响主要连接，因此不中断流程
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
                // 短暂等待，以确保API能读取到最新的状态
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

        /// <summary>
        /// 获取已连接的网络适配器列表。
        /// </summary>
        static List<string> GetAvailableAdapters()
        {
            var adapters = new List<string>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.Supports(NetworkInterfaceComponent.IPv4))
                    {
                        adapters.Add(ni.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" 扫描网络适配器时出错: {ex.Message}");
            }
            return adapters;
        }

        /// <summary>
        /// 获取用户输入并提供默认值
        /// </summary>
        static int GetUserChoice(string prompt, int min, int max, int defaultValue)
        {
            while (true)
            {
                Console.Write($"{prompt} [默认: {defaultValue}]: ");
                string input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input))
                {
                    return defaultValue;
                }
                if (int.TryParse(input, out int choice) && choice >= min && choice <= max)
                {
                    return choice;
                }
                Console.WriteLine($"无效输入，请输入 {min} 到 {max} 之间的数字。");
            }
        }

        /// <summary>
        /// 执行 netsh 命令并捕获错误
        /// </summary>
        /// <returns>如果命令成功执行则返回 true，否则返回 false。</returns>
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
                // 设置编码以正确读取中文系统下的netsh输出
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
        /// 简单的IP地址格式验证
        /// </summary>
        static bool IsValidIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            var parts = ip.Split('.');
            if (parts.Length != 4) return false;
            return parts.All(part => byte.TryParse(part, out _));
        }
    }
}
