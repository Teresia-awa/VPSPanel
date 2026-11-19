using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using VPSPanel.Core;

namespace VPSPanel.Tests;

// A loopback-only TCP entrance to the same private network namespace as the alias fixtures.
internal sealed class LoopbackSshEndpoint : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource closing = new();
    private readonly Task loop;
    private readonly string distro, nsId;
    internal int DestinationPort = 26442;
    internal int RotateAfter = int.MaxValue;
    internal string KeyFile { get; }
    internal SshTarget Target { get; }
    internal string Secret { get; }

    internal LoopbackSshEndpoint()
    {
        var config = Environment.GetEnvironmentVariable("VPSPANEL_LOOPBACK_CONFIG")!;
        var bridge = Regex.Match(File.ReadAllText(config), @"wsl\.exe -d ([\w.-]+) -u root -- nsenter -t ([0-9]+) -m -n nc 127\.0\.0\.1 26442");
        Assert.True(bridge.Success);
        distro = bridge.Groups[1].Value;
        nsId = bridge.Groups[2].Value;
        KeyFile = Path.Combine(Path.GetDirectoryName(config)!, "client");
        using var key = File.OpenRead(KeyFile);
        Secret = Convert.ToHexStringLower(SHA256.HashData(key));
        listener.Start();
        Target = new("127.0.0.1", "root", ((IPEndPoint)listener.LocalEndpoint).Port, "phase2-lab");
        loop = Forward(closing.Token);
    }

    private async Task Forward(CancellationToken token)
    {
        try
        {
            int accepted = 0;
            while (!token.IsCancellationRequested)
            {
                using var socket = await listener.AcceptTcpClientAsync(token);
                int port = ++accepted > RotateAfter ? 26443 : Volatile.Read(ref DestinationPort);
                var start = new ProcessStartInfo("wsl.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true
                };
                foreach (var arg in new[] {"-d",distro,"-u","root","--","nsenter","-t",nsId,
                    "-m","-n","nc","127.0.0.1",port.ToString()}) start.ArgumentList.Add(arg);
                using var process = Process.Start(start)!;
                using var stream = socket.GetStream();
                using var session = CancellationTokenSource.CreateLinkedTokenSource(token);
                var toServer = stream.CopyToAsync(process.StandardInput.BaseStream, session.Token);
                var toClient = process.StandardOutput.BaseStream.CopyToAsync(stream, session.Token);
                await Task.WhenAny(toServer, toClient);
                session.Cancel();
                if (!process.HasExited) process.Kill(true);
                try { await Task.WhenAll(toServer, toClient); }
                catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException) { }
            }
        }
        catch (Exception ex) when (token.IsCancellationRequested && ex is OperationCanceledException or SocketException) { }
    }

    public async ValueTask DisposeAsync()
    {
        closing.Cancel();
        listener.Stop();
        await loop;
        closing.Dispose();
    }
}
