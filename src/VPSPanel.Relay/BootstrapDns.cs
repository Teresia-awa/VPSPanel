using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal static class BootstrapDns
{
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(2),
        PooledConnectionLifetime = TimeSpan.FromMinutes(2)
    }) { MaxResponseContentBufferSize = ushort.MaxValue };

    internal static async Task<IPAddress> Resolve(string host, string[] resolvers, CancellationToken token)
    {
        if (IPAddress.TryParse(host, out var literal)) return literal;
        if (!ExitProfile.ValidHost(host)) throw new PanelException("预检域名无效。");
        host = host.TrimEnd('.');
        foreach (var address in DohResolvers.Validate(resolvers, true))
        {
            var endpoint = new Uri("https" + address["https+local".Length..]);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                foreach (ushort type in new ushort[] { 1, 28 })
                {
                    var query = Query(host, type);
                    using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
                    {
                        Content = new ByteArrayContent(query), Version = HttpVersion.Version20,
                        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                    };
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
                    request.Headers.Accept.ParseAdd("application/dns-message");
                    using var reply = await Client.SendAsync(request, timeout.Token);
                    if (!reply.IsSuccessStatusCode || reply.Content.Headers.ContentType?.MediaType != "application/dns-message")
                        throw new InvalidDataException();
                    var packet = await reply.Content.ReadAsByteArrayAsync(timeout.Token);
                    var result = Answer(packet, query, host, type);
                    if (result != null) return result;
                }
            }
            catch (Exception e) when (!token.IsCancellationRequested &&
                e is IOException or HttpRequestException or OperationCanceledException or InvalidDataException) { }
        }
        token.ThrowIfCancellationRequested();
        throw new PanelException("直连与节点引导 DoH 解析失败。");
    }

    private static byte[] Query(string name, ushort type)
    {
        using var stream = new MemoryStream();
        stream.Write(RandomNumberGenerator.GetBytes(2));
        stream.Write(new byte[] { 1,0,0,1,0,0,0,0,0,0 });
        foreach (var label in name.Split('.'))
        {
            stream.WriteByte((byte)label.Length);
            stream.Write(Encoding.ASCII.GetBytes(label));
        }
        stream.Write(new byte[] { 0,0,(byte)type,0,1 });
        return stream.ToArray();
    }

    private static ushort Word(byte[] packet, ref int pos)
    {
        if (pos + 2 > packet.Length) throw new InvalidDataException();
        var word = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(pos));
        pos += 2;
        return word;
    }

    private static string Name(byte[] packet, ref int pos)
    {
        var labels = new List<string>();
        int cursor = pos, end = -1, size = 0;
        for (int hops = 0; hops < 256 && cursor < packet.Length; hops++)
        {
            int length = packet[cursor++];
            if (length == 0)
            {
                pos = end < 0 ? cursor : end;
                return string.Join('.', labels);
            }
            if ((length & 192) == 192 && cursor < packet.Length)
            {
                int pointer = ((length & 63) << 8) | packet[cursor++];
                if (pointer >= cursor - 2) throw new InvalidDataException();
                if (end < 0) end = cursor;
                cursor = pointer;
                continue;
            }
            size += length + 1;
            if (length > 63 || size > 254 || cursor + length > packet.Length) throw new InvalidDataException();
            labels.Add(Encoding.ASCII.GetString(packet, cursor, length));
            cursor += length;
        }
        throw new InvalidDataException();
    }

    internal static IPAddress? Answer(byte[] packet, byte[] query, string host, ushort type)
    {
        if (packet.Length < 12 || !packet.AsSpan(0,2).SequenceEqual(query.AsSpan(0,2)) ||
            (packet[2] & 0xfa) != 0x80 || (packet[3] & 15) != 0) throw new InvalidDataException();
        int pos = 4;
        if (Word(packet, ref pos) != 1) throw new InvalidDataException();
        int answers = Word(packet, ref pos);
        pos = 12;
        if (!Name(packet, ref pos).Equals(host, StringComparison.OrdinalIgnoreCase) ||
            Word(packet, ref pos) != type || Word(packet, ref pos) != 1) throw new InvalidDataException();
        var cnames = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        var ips = new Dictionary<string,IPAddress>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < answers; i++)
        {
            string owner = Name(packet, ref pos);
            int rrType = Word(packet, ref pos), rrClass = Word(packet, ref pos);
            pos += 4;
            int length = Word(packet, ref pos), end = pos + length;
            if (end > packet.Length) throw new InvalidDataException();
            if (rrClass == 1 && rrType == type && length == (type == 1 ? 4 : 16))
                ips.TryAdd(owner, new IPAddress(packet.AsSpan(pos,length)));
            if (rrClass == 1 && rrType == 5)
            {
                cnames[owner] = Name(packet, ref pos);
                if (pos != end) throw new InvalidDataException();
            }
            pos = end;
        }
        for (int depth = 0; depth < 32; depth++)
        {
            if (ips.TryGetValue(host, out var ip)) return ip;
            if (!cnames.TryGetValue(host, out var next)) return null;
            host = next;
        }
        throw new InvalidDataException();
    }
}
