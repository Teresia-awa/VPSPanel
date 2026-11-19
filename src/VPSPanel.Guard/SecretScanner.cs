using System.Text;
using System.Text.RegularExpressions;

namespace VPSPanel.Guard;

public sealed class SecretScanner(IReadOnlyList<string> registered)
{
    private static readonly RegexOptions Flags = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;
    private static readonly (string Category, Regex Pattern)[] Rules =
    [
        ("私钥", new(@"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----", Flags)),
        ("节点分享链接", new(@"\b(?:hy2|hysteria2|vless|vmess|trojan|ss|ssr)://[^\s""'<>]+", Flags)),
        ("订阅链接", new(@"https?://[^\s<>""']*(?:[?&](?:token|access_token|authkey|api_key|apikey|subscription_key|key)=|/(?:client/subscribe|subscription|subscribe|sub)/)[^&\s<>""']+", Flags)),
        ("链接内凭据", new(@"\b(?:ssh|sftp|https?|socks5)://[^/\s:@]+:[^/\s@]+@", Flags)),
        ("私钥文件", new(@"PuTTY-User-Key-File-[0-9]+:", Flags))
    ];
    private static readonly Regex Field = new(
        """(?:^|[\s{"',])(?:["']?)(?<key>(?:(?:vps|ssh|proxy|node|server)[_-]?)?(?:password|passwd|pwd)|private[_-]?key|api[_-]?key|access[_-]?token|subscription[_-]?(?:url|link|token)|(?:vps|ssh)[_-]?(?:host|address))["']?\s*[:=]\s*["']?(?<value>[^"'\s,;{}#<>]+)""", Flags);
    private static bool Placeholder(Match field)
    {
        string value = field.Groups["value"].Value;
        string key = field.Groups["key"].Value;
        if (value is "null" or "REDACTED") return true;
        return (key.EndsWith("host", StringComparison.OrdinalIgnoreCase) ||
                key.EndsWith("address", StringComparison.OrdinalIgnoreCase)) &&
               value.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase);
    }

    public string? Match(string line)
    {
        if (registered.Any(value => line.Contains(value, StringComparison.OrdinalIgnoreCase)))
            return "本机登记的敏感信息";
        foreach (var (category, pattern) in Rules)
            if (pattern.IsMatch(line)) return category;
        foreach (Match match in Field.Matches(line))
            if (!Placeholder(match)) return "明文连接信息或凭据";
        return null;
    }

    internal void Check(byte[] bytes, string label)
    {
        // StreamReader also recognizes UTF-16/32 files written by Windows tools with a BOM.
        var encoding = bytes.Length > 3 && bytes[1] == 0 && bytes[3] == 0 ? Encoding.Unicode : Encoding.UTF8;
        using var reader = new StreamReader(new MemoryStream(bytes), encoding, true);
        int number = 0;
        while (reader.ReadLine() is { } line)
        {
            number++;
            if (Match(line) is { } type) throw new Finding(label, number, type);
        }
    }
}

internal sealed class Finding(string file, int line, string type) : Exception
{
    public string Report => $"已拦截 · {file} · 第 {line} 行 · {type}";
}
