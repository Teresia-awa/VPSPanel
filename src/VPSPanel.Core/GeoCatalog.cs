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
        HashSet<string> full = [], suffix = []; List<string> contains = []; List<Regex> regex = [];
        foreach (var d in SiteEntries(key))
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
    private IEnumerable<DomainEntry> SiteEntries(string key)
    {
        var parts = key.Split('@');
        var group = Load<Site>("geosite.dat", s => s.Code.Equals(parts[0], StringComparison.OrdinalIgnoreCase));
        return group.Entries.Where(d => parts.Skip(1).All(attr => d.Attributes.Any(a => a.Key.Equals(attr, StringComparison.OrdinalIgnoreCase))));
    }

    public (byte[] Data, string Generation) BootstrapAsset(RelayPlan plan)
    {
        var site = new Site { Code = "BINDINGS" };
        foreach (var rule in plan.BootstrapDomains())
        {
            var pair = rule.Split(':', 2);
            if (pair[0] == "geosite") site.Entries.AddRange(SiteEntries(pair[1]));
            else site.Entries.Add(new DomainEntry { Type = pair[0] == "full" ? 3 : 2, Value = pair[1] });
        }
        using var data = new MemoryStream();
        Serializer.SerializeWithLengthPrefix(data, site, PrefixStyle.Base128, 1);
        var digest = System.Security.Cryptography.SHA256.HashData(data.GetBuffer().AsSpan(0, (int)data.Length));
        var generation = Convert.ToHexStringLower(digest.AsSpan(0, 24)) + ".invalid";
        var proof = new Site { Code = "GENERATION" };
        proof.Entries.Add(new DomainEntry { Type = 3, Value = generation });
        Serializer.SerializeWithLengthPrefix(data, proof, PrefixStyle.Base128, 1);
        return (data.ToArray(), generation);
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
