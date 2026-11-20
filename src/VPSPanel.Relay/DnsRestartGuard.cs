using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal static class DnsRestartGuard
{
    internal static string Service(string value)
    {
        if (value.Length is < 1 or > 64 || !char.IsAsciiLetterOrDigit(value[0]) ||
            value is "vpspanel-relay" or "vpspanel-restored-relay" || value.EndsWith(".service", StringComparison.Ordinal) ||
            !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '@'))
            throw new PanelException("Xray 服务名无效。");
        return value + ".service";
    }

    internal static async Task<FileStream> Lock(string directory, CancellationToken token)
    {
        string path = Path.Combine(directory, "dns-restart.lock");
        for (int attempt = 0; ; attempt++)
        {
            try { return File.Open(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (attempt < 60) { await Task.Delay(1000, token); }
        }
    }

    internal static Task Arm(string directory, string id, CancellationToken token) =>
        Run("systemd-run",
            ["--quiet", "--collect", "--on-active=90s", "--timer-property=AccuracySec=1s", "--unit=vpspanel-dns-" + id,
             Environment.ProcessPath!, "recover-dns", directory, id], token);

    internal static Task Restart(string service, CancellationToken token) =>
        Run("systemctl", ["restart", Service(service)], token);

    internal static async Task WaitForApi(int port, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(12));
        while (true)
        {
            using var socket = new TcpClient();
            try
            {
                await socket.ConnectAsync(IPAddress.Loopback, port, deadline.Token);
                return;
            }
            catch (SocketException) { await Task.Delay(200, deadline.Token); }
        }
    }

    internal static void RestoreFiles(string directory, Journal journal)
    {
        string asset = BootstrapGeneration.AssetPath(directory);
        if (journal.PreviousBootstrapAsset is { } data) BootstrapGeneration.WriteAsset(directory, data);
        else if (File.Exists(asset)) Disk.Remove(asset);
        Disk.Restore(Path.Combine(directory, "xray.json"), journal.PreviousXray);
        Disk.Restore(Path.Combine(directory, "committed.json"), System.Text.Json.JsonSerializer.Serialize(journal.PreviousState));
    }

    internal static async Task Recover(string directory, string id, CancellationToken token)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new PanelException("DNS 事务编号无效。");
        await using var held = await Lock(directory, token);
        string journalPath = Path.Combine(directory, "transaction.json");
        if (!File.Exists(journalPath)) return;
        var journal = Disk.Read<Journal>(journalPath);
        if (journal.RestartId != id || journal.XrayService is null) return;
        await Rollback(directory, journal, token);
    }

    internal static async Task Rollback(string directory, Journal journal, CancellationToken token)
    {
        RestoreFiles(directory, journal);
        await Restart(journal.XrayService!, token);
        await WaitForApi(Disk.Read<RelayOptions>(Path.Combine(directory, "relay.json")).ApiPort, token);
        string request = Path.Combine(directory, "request.json");
        if (File.Exists(request) && Disk.Read<Submission>(request).Id == journal.RestartId) Disk.Remove(request);
        if (journal.RestartId is string id)
        {
            string receipts = Path.Combine(directory, "receipts");
            Directory.CreateDirectory(receipts);
            Disk.Write(Path.Combine(receipts, id + ".json"),
                System.Text.Json.JsonSerializer.Serialize(new { Id = id, Success = false, Error = "DNS 变更未完成，已恢复上一版。" }));
        }
        Disk.Remove(Path.Combine(directory, "transaction.json"));
    }

    private static async Task Run(string binary, string[] args, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        var info = new ProcessStartInfo(binary)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in args) info.ArgumentList.Add(argument);
        using var process = Process.Start(info)!;
        try
        {
            await Task.WhenAll(process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, deadline.Token),
                process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token), process.WaitForExitAsync(deadline.Token));
            if (process.ExitCode != 0) throw new PanelException("Xray 重启或回滚定时器启动失败。");
        }
        finally { if (!process.HasExited) process.Kill(true); }
    }
}
