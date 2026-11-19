using System.Net;
using System.Text.RegularExpressions;
using ProtoBuf;

namespace VPSPanel.Core;

// Wire fields from Xray common/geodata/geodat.proto. Read one category at a time.
public sealed class GeoCatalog(string directory)
{
    [ProtoContract] private sealed class Attribute { [ProtoMember(1)] public string Key { get; set; } = ""; }
    [ProtoContract]
    private sealed class DomainEntry
    {
        [ProtoMember(1)] public int Type { get; set; }
        [ProtoMember(2)] public string Value { get; set; } = "";
        [ProtoMember(3)] public List<Attribute> Attributes { get; } = [];
    }
    [ProtoContract]
    private sealed class Site
    {
        [ProtoMember(1)] public string Code { get; set; } = "";
        [ProtoMember(2)] public List<DomainEntry> Entries { get; } = [];
    }
    [ProtoContract]
    private sealed class Cidr
    {
        [ProtoMember(1)] public byte[] Ip { get; set; } = [];
        [ProtoMember(2)] public int Prefix { get; set; }
    }
    [ProtoContract]
    private sealed class Region
    {
        [ProtoMember(1)] public string Code { get; set; } = "";
        [ProtoMember(2)] public List<Cidr> Entries { get; } = [];
        [ProtoMember(3)] public bool Reverse { get; set; }
    }
    private readonly Dictionary<string, Func<string, bool>> siteCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Func<IPAddress, bool>> ipCache = new(StringComparer.OrdinalIgnoreCase);
    private T Load<T>(string file, Func<T, bool> match) where T : class
    {
        try
        {
            using var stream = File.OpenRead(Path.Combine(directory, file));
            return Serializer.DeserializeItems<T>(stream, PrefixStyle.Base128, 1).FirstOrDefault(match)
                ?? throw new PanelException(file + " 中找不到所选分类。");
        }
        catch (Exception ex) when (ex is IOException or ProtoException or UnauthorizedAccessException)
        { throw new PanelException("请导入与分类匹配的 " + file + " 数据文件。"); }
    }
    internal Func<string, bool> Sites(string key)
    {
        if (siteCache.TryGetValue(key, out var cached)) return cached;
        var parts = key.Split('@');
        var group = Load<Site>("geosite.dat", s => s.Code.Equals(parts[0], StringComparison.OrdinalIgnoreCase));
        HashSet<string> full = [], suffix = []; List<string> contains = []; List<Regex> regex = [];
        foreach (var d in group.Entries.Where(d => parts.Skip(1).All(attr => d.Attributes.Any(a => a.Key.Equals(attr, StringComparison.OrdinalIgnoreCase)))))
        {
            var value = d.Value.ToLowerInvariant();
            switch (d.Type)
            {
                case 0: contains.Add(value); break;
                case 1: regex.Add(new(d.Value, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50))); break;
                case 2: suffix.Add(value); break;
                case 3: full.Add(value); break;
                default: throw new PanelException("GeoSite 含未知域名类型。");
            }
        }
        return siteCache[key] = host =>
        {
            if (full.Contains(host)) return true;
            for (var s = host; ;) { if (suffix.Contains(s)) return true; int i = s.IndexOf('.'); if (i < 0) break; s = s[(i + 1)..]; }
            return contains.Any(host.Contains) || regex.Any(r => r.IsMatch(host));
        };
    }
    internal Func<IPAddress, bool> Networks(string key)
    {
        if (ipCache.TryGetValue(key, out var cached)) return cached;
        bool invert = key.StartsWith('!');
        var region = Load<Region>("geoip.dat", r => r.Code.Equals(key.TrimStart('!'), StringComparison.OrdinalIgnoreCase));
        var nets = region.Entries.Select(c => new IPNetwork(new IPAddress(c.Ip), c.Prefix)).ToArray();
        return ipCache[key] = ip => nets.Any(n => n.Contains(ip)) ^ region.Reverse ^ invert;
    }
}
