using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace VPSPanel.Core;

internal sealed class DirectSsh(SshTarget target, DirectLogin login, DirectAccess access,
    Func<HostFingerprint, bool>? confirm) : ISshTransport, IFileUpload
{
    private const int MaxBytes = 8 * 1024 * 1024;

    private PrivateKeyFile? OpenKey()
    {
        if (login.Profile.KeyFile is not { } path) return null;
        if (!Path.IsPathFullyQualified(path) || new Uri(path).IsUnc || new DriveInfo(Path.GetPathRoot(path)!).DriveType == DriveType.Network)
            throw new PanelException("请选择本机磁盘上的私钥文件。");
        try { return new PrivateKeyFile(path, login.Secret.Length == 0 ? null : login.Secret); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { throw new PanelException("无法打开私钥，请检查文件、密钥格式和私钥口令。"); }
    }

    private async Task<T> Run<T>(bool transfer, Func<BaseClient, CancellationToken, Task<T>> operation, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        // Unknown keys are rejected before authentication. Prompt with the connection closed,
        // then reconnect and verify the approved key on a fresh handshake.
        using var key = OpenKey();
        using AuthenticationMethod auth = key is null
            ? new PasswordAuthenticationMethod(target.User, login.Secret)
            : new PrivateKeyAuthenticationMethod(target.User, key);
        for (int attempt = 0; attempt < 2; attempt++)
        {
            var expected = access.Pin(target);
            HostFingerprint? untrusted = null;
            var info = new ConnectionInfo(target.Host, target.Port ?? 22, target.User, auth) { Timeout = TimeSpan.FromSeconds(12) };
            using BaseClient client = transfer ? new SftpClient(info) : new SshClient(info);
            client.HostKeyReceived += (_, e) =>
            {
                string fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
                e.CanTrust = fingerprint == expected;
                if (!e.CanTrust) untrusted = new(target.Host, target.Port ?? 22, e.HostKeyName, fingerprint);
            };
            using var limit = CancellationTokenSource.CreateLinkedTokenSource(token);
            limit.CancelAfter(transfer ? TimeSpan.FromMinutes(25) : TimeSpan.FromSeconds(90));
            try
            {
                await client.ConnectAsync(limit.Token).ConfigureAwait(false);
                return await operation(client, limit.Token).ConfigureAwait(false);
            }
            catch (Exception) when (untrusted is not null)
            {
                if (expected != null || attempt != 0) throw DirectAccess.ChangedKey();
            }
            catch (SshAuthenticationException)
            { throw new PanelException(key == null ? "密码认证失败，请核对用户名、密码及服务端是否允许密码登录。" : "私钥认证失败，请核对用户名和服务器授权的公钥。"); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            { throw new PanelException("直连 SSH 操作超时。"); }
            catch (SftpPermissionDeniedException) { throw new PanelException("SFTP 读取权限不足，请核对配置文件权限。"); }
            catch (SshOperationTimeoutException) { throw new PanelException("直连 SSH 操作超时。"); }
            catch (Exception ex) when (ex is SshException or SocketException or IOException)
            { throw new PanelException(transfer ? "SFTP 读取失败，请检查子系统与文件读取权限。" : "SSH 连接或执行失败，请检查主机地址、端口与服务。"); }

            token.ThrowIfCancellationRequested();
            if (confirm?.Invoke(untrusted!) != true) throw new PanelException("未信任主机指纹，连接已取消。");
            token.ThrowIfCancellationRequested();
            access.Trust(target, untrusted!.Sha256);
        }
        throw DirectAccess.ChangedKey();
    }

    public Task<string> Command(string command, string input, CancellationToken token) =>
        Run(false, async (client, ct) =>
        {
            using var request = ((SshClient)client).CreateCommand(command);
            request.CommandTimeout = TimeSpan.FromSeconds(90);
            var running = request.ExecuteAsync(ct);
            using (var stdin = request.CreateInputStream())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(input);
                try { await stdin.WriteAsync(bytes, ct).ConfigureAwait(false); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            await running.ConfigureAwait(false);
            if (request.ExitStatus != 0) throw new PanelException("远端只读检查或探测未完成，请检查服务名、权限与网络。");
            if (request.OutputStream.Length > MaxBytes) throw new PanelException("远端输出超过大小限制。");
            return request.Result;
        }, token);

    public Task<byte[]> ReadAsset(string remoteFile,CancellationToken token)=>
        Run(true,async (client,ct)=>{
            await using var source=await ((SftpClient)client).OpenAsync(remoteFile,FileMode.Open,FileAccess.Read,ct);
            if(source.Length is <1 or >268435456)throw new PanelException("安装材料大小无效。");
            var data=new byte[(int)source.Length];await source.ReadExactlyAsync(data,ct);return data;
        },token);
    public Task Upload(string localFile,string remoteFile,CancellationToken token)=>
        Run(true,async (client,ct)=>{
            await using var input=File.OpenRead(localFile);
            await ((SftpClient)client).UploadFileAsync(input,remoteFile,false,null,ct);return true;
        },token);

    public Task<(string Json, bool Sftp)> ReadConfiguration(string path, CancellationToken token) =>
        Run(true, async (client, ct) =>
        {
            using var stream = await ((SftpClient)client).OpenAsync(path, FileMode.Open, FileAccess.Read, ct).ConfigureAwait(false);
            if (stream.Length > MaxBytes) throw new PanelException("活动配置超出 8 MiB 大小限制。");
            using var file = new MemoryStream();
            byte[] buffer = new byte[32768];
            try
            {
                int count;
                while ((count = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) != 0)
                {
                    if (file.Length + count > MaxBytes) throw new PanelException("活动配置超出 8 MiB 大小限制。");
                    file.Write(buffer, 0, count);
                }
                return (Encoding.UTF8.GetString(file.GetBuffer(), 0, (int)file.Length).TrimStart('\uFEFF'), true);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                CryptographicOperations.ZeroMemory(file.GetBuffer());
            }
        }, token);
}
