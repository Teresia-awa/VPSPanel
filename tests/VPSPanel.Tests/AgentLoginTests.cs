using System.Diagnostics;
using System.IO.Pipes;
using System.Text.RegularExpressions;
using VPSPanel.Core;

namespace VPSPanel.Tests;

public sealed class AgentLoginTests
{
    [IsolatedSshFact]
    public async Task SystemSftpAuthenticatesWithNamedPipeAgent()
    {
        string config = Environment.GetEnvironmentVariable("VPSPANEL_LOOPBACK_CONFIG")!;
        string text = File.ReadAllText(config);
        var pipeName = Regex.Match(text, @"IdentityAgent //\./pipe/(vpspanel-[a-f0-9]{32})").Groups[1].Value;
        var bridge = Regex.Match(text, @"wsl\.exe -d ([\w.-]+) -u root -- nsenter -t ([0-9]+) -m -n nc 127\.0\.0\.1");
        Assert.NotEmpty(pipeName);
        Assert.True(bridge.Success);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var pipe = new NamedPipeServerStream(pipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var auth = new OpenSsh(new("phase2-agent"),config).CheckSftp(timeout.Token);
        await pipe.WaitForConnectionAsync(timeout.Token);
        // This private agent holds the only copy of the key, inside WSL's isolated tmpfs.
        var start = new ProcessStartInfo("wsl.exe") { UseShellExecute=false, CreateNoWindow=true,
            RedirectStandardInput=true, RedirectStandardOutput=true };
        foreach (var arg in new[] {"-d",bridge.Groups[1].Value,"-u","root","--","nsenter","-t",bridge.Groups[2].Value,
            "-m","-n","nc","-U","/run/panel-lab/agent.sock"}) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var send = pipe.CopyToAsync(process.StandardInput.BaseStream,timeout.Token);
        var receive = process.StandardOutput.BaseStream.CopyToAsync(pipe,timeout.Token);
        try { await auth; }
        finally
        {
            await timeout.CancelAsync();
            pipe.Disconnect();
            if (!process.HasExited) process.Kill(true);
            try { await Task.WhenAll(send,receive); }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidOperationException) { }
        }
    }
}
