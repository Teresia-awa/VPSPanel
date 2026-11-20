using System.Net;
using System.Net.Sockets;
using System.Net.Http.Headers;
using System.Text;

namespace VPSPanel.Relay;

internal readonly record struct Destination(string Host, int Port)
{
    public byte[] Encode()
    {
        byte[] host;
        byte type;
        if (IPAddress.TryParse(Host, out var ip)) { host = ip.GetAddressBytes(); type = host.Length == 4 ? (byte)1 : (byte)4; }
        else { var raw = Encoding.ASCII.GetBytes(Host); if (raw.Length is 0 or > 255) throw new InvalidDataException(); host = [(byte)raw.Length, .. raw]; type = 3; }
        return [type, .. host, (byte)(Port >> 8), (byte)Port];
    }
    public static Destination Decode(ReadOnlySpan<byte> packet, out int size)
    {
        if (packet.Length < 1) throw new InvalidDataException();
        int offset = packet[0] == 3 ? 2 : 1;
        int length = packet[0] switch { 1 => 4, 4 => 16, 3 when packet.Length >= 2 => packet[1], _ => throw new InvalidDataException() };
        size = offset + length + 2;
        if (packet.Length < size || length == 0) throw new InvalidDataException();
        var addr = packet.Slice(offset, length);
        return new(packet[0] == 3 ? Encoding.ASCII.GetString(addr) : new IPAddress(addr).ToString(), packet[size - 2] * 256 + packet[size - 1]);
    }
}
internal static class Socks
{
    internal static async Task<byte[]> Read(Stream stream, int length, CancellationToken token)
    { var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, token); return bytes; }
    internal static async Task<Destination> Address(Stream stream, CancellationToken ct)
    {
        byte type = (await Read(stream, 1, ct))[0];
        byte[] prefix = type == 3 ? [type, (await Read(stream, 1, ct))[0]] : [type];
        int len = type switch { 1 => 4, 4 => 16, 3 => prefix[1], _ => throw new InvalidDataException() };
        return Destination.Decode([.. prefix, .. await Read(stream, len + 2, ct)], out _);
    }
    internal static async Task<(TcpClient Client, Destination Bound)> Connect(int port, byte op, Destination dest, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(8)); var ct = deadline.Token;
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(IPAddress.Loopback, port, ct);
            var s = tcp.GetStream();
            await s.WriteAsync(new byte[] { 5, 1, 0 }, ct);
            if (!(await Read(s, 2, ct)).SequenceEqual(new byte[] { 5, 0 })) throw new IOException("SOCKS5 认证失败。");
            await s.WriteAsync(new byte[] { 5, op, 0 }.Concat(dest.Encode()).ToArray(), ct);
            if (!(await Read(s, 3, ct)).SequenceEqual(new byte[] { 5, 0, 0 })) throw new IOException("出口建连失败。");
            return (tcp, await Address(s, ct));
        }
        catch { tcp.Dispose(); throw; }
    }

    internal static async Task<byte[]> ExchangeDoh(int port, Uri resolver, byte[] query, CancellationToken ct, bool requireHttp2 = false)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false, AllowAutoRedirect = false,
            ConnectCallback = async (context, token) =>
            {
                var ep = context.DnsEndPoint;
                var (socket, _) = await Connect(port, 1, new(ep.Host, ep.Port), token);
                return socket.GetStream();
            }
        };
        using var http = new HttpClient(handler) { MaxResponseContentBufferSize = ushort.MaxValue };
        using var request = new HttpRequestMessage(HttpMethod.Post, resolver)
        {
            Content = new ByteArrayContent(query), Version = HttpVersion.Version20,
            VersionPolicy = requireHttp2 ? HttpVersionPolicy.RequestVersionExact : HttpVersionPolicy.RequestVersionOrLower
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        request.Headers.Accept.ParseAdd("application/dns-message");
        using var reply = await http.SendAsync(request, ct);
        if (!reply.IsSuccessStatusCode || reply.Content.Headers.ContentType?.MediaType != "application/dns-message") throw new IOException("DoH 响应无效。");
        byte[] answer = await reply.Content.ReadAsByteArrayAsync(ct);
        if (answer.Length < 12 || answer[0] != query[0] || answer[1] != query[1] || (answer[2] & 0x80) == 0) throw new IOException("DoH 响应无效。");
        return answer;
    }

    internal static async Task<double> Check(int port, Uri url, CancellationToken ct, string[]? bootstrap = null)
    {
        long start = System.Diagnostics.Stopwatch.GetTimestamp();
        using var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectCallback = async (request, token) =>
            {
                var host = request.DnsEndPoint.Host;
                if (bootstrap != null) host = (await BootstrapDns.Resolve(host, bootstrap, token)).ToString();
                var (tcp, _) = await Connect(port, 1, new(host, request.DnsEndPoint.Port), token);
                return tcp.GetStream(); // NetworkStream owns the socket.
            }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(bootstrap == null ? 6 : 8 + bootstrap.Length * 3) };
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode != HttpStatusCode.NoContent) throw new IOException("探测目标未返回 204。");
        return System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalMilliseconds;
    }
}
