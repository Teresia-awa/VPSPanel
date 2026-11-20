using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using ProtoBuf;
using VPSPanel.Core;

namespace VPSPanel.Relay;

// Xray RoutingService.TestRoute evaluates the live matcher without opening an outbound connection.
internal static class BootstrapGeneration
{
    // A service with a separate Unix identity can mount this directory read-only.
    // The parent remains private. Xray only sees the child in its systemd mount namespace.
    internal static string AssetDirectory(string work)
    {
        var separate = Path.Combine(work, "dns-assets");
        return Directory.Exists(separate) ? separate : work;
    }

    internal static string AssetPath(string work) => Path.Combine(AssetDirectory(work), EncryptedDnsRoute.Asset);

    internal static void WriteAsset(string work, byte[] data)
    {
        var directory = AssetDirectory(work);
        var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if (directory != work && !OperatingSystem.IsWindows())
        {
            if (File.GetUnixFileMode(work).HasFlag(UnixFileMode.OtherExecute))
                throw new PanelException("独立 DNS 资料目录需要位于私有 Relay 工作目录内。");
            mode |= UnixFileMode.GroupRead | UnixFileMode.OtherRead;
        }
        Disk.Write(Path.Combine(directory, EncryptedDnsRoute.Asset), data, unixMode: mode);
    }

    [ProtoContract]
    private sealed class Context
    {
        [ProtoMember(1)] public string? Inbound { get; set; }
        [ProtoMember(7)] public string? Domain { get; set; }
        [ProtoMember(12)] public string? Outbound { get; set; }
    }

    [ProtoContract]
    private sealed class RouteRequest
    {
        [ProtoMember(1)] public Context? Context { get; set; }
        [ProtoMember(2)] public string? Selector { get; set; }
    }

    internal static async Task Wait(int port, string generation, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(75));
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        try
        {
            while (!await Matches(client, port, generation, deadline.Token))
                await Task.Delay(350, deadline.Token);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { throw new PanelException("运行中的 Xray 未在限时内载入新的引导域名。"); }
    }

    private static async Task<bool> Matches(HttpClient client, int port, string generation, CancellationToken ct)
    {
        using var body = new MemoryStream();
        body.Write(new byte[5]);
        Serializer.Serialize(body, new RouteRequest { Context = new Context {
            Inbound = EncryptedDnsRoute.VerificationTag, Domain = generation }, Selector = "outbound" });
        var payload = body.ToArray();
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(1), payload.Length - 5);
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"http://127.0.0.1:{port}/xray.app.router.command.RoutingService/TestRoute")
        {
            Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new ByteArrayContent(payload)
        };
        request.Headers.TE.Add(new TransferCodingWithQualityHeaderValue("trailers"));
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        using var response = await client.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        var data = await response.Content.ReadAsByteArrayAsync(ct);
        if (!response.TrailingHeaders.TryGetValues("grpc-status", out var status) || status.Single() != "0" ||
            data.Length < 5 || data[0] != 0 || BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(1)) != data.Length - 5)
            throw new PanelException("无法核对 Xray 运行中的引导域名版本。");
        using var result = new MemoryStream(data, 5, data.Length - 5);
        return Serializer.Deserialize<Context>(result).Outbound == EncryptedDnsRoute.Tag;
    }
}
