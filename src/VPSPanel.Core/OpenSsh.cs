using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace VPSPanel.Core;

public sealed record SshTarget(string Host, string User = "", int? Port = null, string Service = "xray-relay")
{
    public void Validate()
    {
        bool address = Host.Length is > 0 and <= 253 &&
            (Regex.IsMatch(Host, @"\A[A-Za-z0-9][A-Za-z0-9._-]*\z") ||
             (Host.All(c => Uri.IsHexDigit(c) || c is ':' or '.') && IPAddress.TryParse(Host, out _)));
        if (!address || (User != "" && !Regex.IsMatch(User, @"\A[A-Za-z_][A-Za-z0-9_.-]*\z"))
            || Port is < 1 or > 65535 || !Regex.IsMatch(Service, @"\A[A-Za-z0-9][A-Za-z0-9@_.-]{0,100}\z"))
            throw new PanelException("请检查 SSH 别名或 IP、用户、端口及服务名。");
    }
}

public interface IFileUpload
{
    Task Upload(string localFile, string remoteFile, CancellationToken token);
    Task<byte[]> ReadAsset(string remoteFile,CancellationToken token);
}

public interface ISshTransport
{
    Task<string> Command(string command, string input, CancellationToken token);
    Task<(string Json, bool Sftp)> ReadConfiguration(string path, CancellationToken token);
}

public sealed class OpenSsh(SshTarget target, string? configFile = null) : ISshTransport, IFileUpload
{
    private ProcessStartInfo StartInfo(bool transfer, string command)
    {
        var name = transfer ? "sftp.exe" : "ssh.exe";
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "OpenSSH", name))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = Encoding.UTF8
        };
        var args = info.ArgumentList;
        if (configFile is not null) { args.Add("-F"); args.Add(configFile); }
        foreach (var setting in new[] { "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
            "ClearAllForwardings=yes", "ForwardAgent=no", "PermitLocalCommand=no", "ControlPath=none",
            "ControlMaster=no", "ConnectTimeout=8" })
        {
            args.Add("-o");
            args.Add(setting);
        }
        if (target.Port is int port) { args.Add(transfer ? "-P" : "-p"); args.Add(port.ToString()); }
        if (transfer) { args.Add("-q"); args.Add("-b"); args.Add("-"); }
        else args.Add("-T");
        var host = transfer && target.Host.Contains(':') ? "[" + target.Host + "]" : target.Host;
        args.Add(target.User.Length == 0 ? host : target.User + "@" + host);
        if (!transfer) args.Add(command);
        return info;
    }

    private async Task<string> RunAsync(bool transfer, string command, string input, CancellationToken token)
    {
        target.Validate();
        token.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(transfer ? TimeSpan.FromMinutes(25) : TimeSpan.FromSeconds(90));
        using var process = Process.Start(StartInfo(transfer, command))!;
        void Stop()
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { /* already exited */ }
        }
        using var cleanup = deadline.Token.Register(Stop);
        var output = ReadLimited(process.StandardOutput, Stop, deadline.Token);
        var error = ReadLimited(process.StandardError, Stop, deadline.Token);
        try
        {
            // A refused SSH connection can close stdin before the client prints its diagnostic.
            try { await process.StandardInput.WriteAsync(input.AsMemory(), deadline.Token); process.StandardInput.Close(); }
            catch (IOException) { }
            await Task.WhenAll(output, error, process.WaitForExitAsync(deadline.Token));
            deadline.Token.ThrowIfCancellationRequested();
            if (process.ExitCode == 0) return await output;
            var diagnostic = await error;
            if (diagnostic.Contains("Host key verification", StringComparison.OrdinalIgnoreCase) || diagnostic.Contains("IDENTIFICATION HAS CHANGED"))
                throw new PanelException("SSH 主机指纹未受信任或已变化。请先在系统 OpenSSH 核对指纹。");
            if (diagnostic.Contains("Permission denied", StringComparison.OrdinalIgnoreCase))
                throw new PanelException("SSH 认证或读取权限不足，请检查别名、Agent 和服务文件权限。");
            throw new PanelException(transfer ? "SFTP 子系统不可用。" : "SSH 操作失败，请检查连接、活动服务及读取权限。");
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { throw new PanelException("SSH 操作超时。"); }
        finally { Stop(); }
    }

    private static async Task<string> ReadLimited(StreamReader reader, Action stop, CancellationToken token)
    {
        var text = new StringBuilder();
        var buffer = new char[8192];
        int count;
        while ((count = await reader.ReadAsync(buffer, token)) > 0)
        {
            if (text.Length + count > 8 * 1024 * 1024)
            {
                stop();
                throw new PanelException("远端输出超过大小限制，已停止读取。");
            }
            text.Append(buffer, 0, count);
        }
        return text.ToString();
    }

    Task<string> ISshTransport.Command(string command, string input, CancellationToken token) =>
        RunAsync(false, command, input, token);
    async Task<(string, bool)> ISshTransport.ReadConfiguration(string path, CancellationToken token)
    {
        string json = await RunAsync(false, "cat -- " + Quote(path), "", token);
        try { await CheckSftp(token); }
        catch (PanelException) { return (json, false); }
        return (json, true);
    }
    public Task CheckSftp(CancellationToken token) => RunAsync(true, "", "pwd\nquit\n", token);
    public async Task<byte[]> ReadAsset(string remoteFile,CancellationToken token)
    {
        if(remoteFile.Any(char.IsControl)||!remoteFile.StartsWith('/'))throw new PanelException("安装材料路径无效。");
        var tmp=Directory.CreateTempSubdirectory("panel-public-asset-");var local=Path.Combine(tmp.FullName,"asset");
        try{
            var size=await RunAsync(false,"stat -Lc %s -- "+Quote(remoteFile),"",token);
            if(!long.TryParse(size.Trim(),out long count)||count is <1 or >268435456)throw new PanelException("安装材料大小无效。");
            await RunAsync(true,"","get "+SftpArg(remoteFile)+" "+SftpArg(local.Replace('\\','/'))+"\nquit\n",token);
            return await File.ReadAllBytesAsync(local,token);
        }finally{tmp.Delete(true);}
    }
    private static string SftpArg(string s)=>"\""+s.Replace("\\","\\\\").Replace("\"","\\\"").Replace("*","\\*").Replace("?","\\?").Replace("[","\\[")+"\"";
    public async Task Upload(string localFile,string remoteFile,CancellationToken token)
    {
        string path=Path.GetFullPath(localFile).Replace('\\','/');
        if(path.Any(char.IsControl) || remoteFile.Any(char.IsControl) || !remoteFile.StartsWith('/'))throw new PanelException("SFTP 路径无效。");
        await RunAsync(true,"","put "+SftpArg(path)+" "+SftpArg(remoteFile)+"\nquit\n",token);
    }
    internal static string Quote(string value) => "'" + value.Replace("'", "'\\''") + "'";
}
