using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace VPSPanel.Core;

[JsonConverter(typeof(JsonStringEnumConverter<RouteAction>))]
public enum RouteAction { Auto, Direct, Fixed }
[JsonConverter(typeof(JsonStringEnumConverter<DnsFailureAction>))]
public enum DnsFailureAction { Reject, Direct, Plaintext }

public static class DohResolvers
{
    public static string[] Domestic => ["https+local://223.5.5.5/dns-query", "https+local://1.12.12.12/dns-query"];
    public static string[] Overseas => ["https+local://1.1.1.1/dns-query", "https+local://8.8.8.8/dns-query"];
    public static string[] Parse(string text, bool local = false) =>
        Validate(text.Split(['\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), local);

    public static string[] Validate(string[] urls, bool local = false)
    {
        if (urls.Length is < 1 or > 4)
            throw new PanelException("请配置 1–4 个 DoH 地址，每行一个。");
        var normalized = urls.Select(url =>
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != (local ? "https+local" : "https") ||
                uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
                !IPAddress.TryParse(uri.IdnHost.Trim('[', ']'), out var ip) || IPAddress.IsLoopback(ip))
                throw new PanelException("DoH 地址须使用 IP 形式的 HTTPS URL，且不含账号、参数或片段。");
            return uri.AbsoluteUri;
        }).ToArray();
        if (normalized.Distinct(StringComparer.Ordinal).Count() != normalized.Length)
            throw new PanelException("DoH 地址重复。");
        return normalized;
    }
}
public enum FailureAction { Reject, Direct, Fixed, Auto, UseDefault }
public readonly record struct ExitFailurePolicy(FailureAction Action, string? Exit = null)
{
    public string Label => Action switch {
        FailureAction.Reject => "拒绝连接", FailureAction.Direct => "中转 VPS 直连",
        FailureAction.Fixed => "指定出口 "+Exit, FailureAction.Auto => "自动分摊",
        FailureAction.UseDefault => "跟随默认分流", _ => throw new PanelException("未知故障策略。")
    };
}
public sealed record RuleSet(string Id, string Name, bool Enabled, string[] Entries);
public sealed record SiteRule(string Id, string Name, bool Enabled, string? Group, string[] Entries, RouteAction Action, string? Exit);
public sealed record RoutingPolicy(RuleSet[] Groups, SiteRule[] Rules)
{
    public static RoutingPolicy Empty => new([], []);
    // A final, explicit condition keeps the existing plan/backup format. Older Relays
    // reject this unknown condition during validation instead of silently using Auto.
    internal const string DefaultId = "vpspanel:default";
    private const string Unmatched = "unmatched:*";
    private const string FailureId = "vpspanel:unavailable";
    private const string OnFailure = "unavailable:*", FollowDefault = "unavailable:default";
    [JsonIgnore] public SiteRule? DefaultRule => Rules.LastOrDefault() is { Id: DefaultId } rule ? rule : null;
    [JsonIgnore] public IEnumerable<SiteRule> WebsiteRules => Rules.Where(rule => rule.Id is not (DefaultId or FailureId));
    private SiteRule? FailureRule => Rules.FirstOrDefault(r => r.Id == FailureId);
    [JsonIgnore] public ExitFailurePolicy OnUnavailable => FailureRule switch {
        null => new(FailureAction.Reject),
        { Entries: [FollowDefault] } => new(FailureAction.UseDefault),
        { Action: RouteAction.Fixed } rule => new(FailureAction.Fixed,rule.Exit),
        { Action: RouteAction.Direct } => new(FailureAction.Direct),
        _ => new(FailureAction.Auto)
    };

    public RoutingPolicy WithFailurePolicy(ExitFailurePolicy choice)
    {
        var rules = WebsiteRules.ToList();
        if (choice.Action != FailureAction.Reject) {
            var action = choice.Action switch {
                FailureAction.Direct => RouteAction.Direct, FailureAction.Fixed => RouteAction.Fixed,
                FailureAction.Auto or FailureAction.UseDefault => RouteAction.Auto, _ => throw new PanelException("未知故障策略。")
            };
            rules.Add(new(FailureId,"出口不可用时",true,null,[choice.Action==FailureAction.UseDefault?FollowDefault:OnFailure],action,choice.Exit));
        }
        if (DefaultRule is {} last) rules.Add(last);
        return this with { Rules=rules.ToArray() };
    }

    public RoutingPolicy WithDefault(RouteAction action, string? exit = null)
    {
        var sites = Rules.Where(r=>r.Id!=DefaultId);
        if (action != RouteAction.Auto)
            sites = sites.Append(new(DefaultId, "默认规则", true, null, [Unmatched], action, exit));
        return this with { Rules = sites.ToArray() };
    }

    public RoutingPolicy WithWebsiteRules(IEnumerable<SiteRule> sites) =>
        this with { Rules = sites.Concat(Rules.Where(r=>r.Id is DefaultId or FailureId)).ToArray() };

    internal bool IsPolicyRule(SiteRule rule)
    {
        if (rule.Id == FailureId) {
            int index=Rules.Length-(DefaultRule==null?1:2);
            if (index<0 || rule!=Rules[index] || !rule.Enabled || rule.Group!=null ||
                !(rule.Entries is [OnFailure] || rule.Entries is [FollowDefault] && rule.Action==RouteAction.Auto) ||
                rule.Action!=RouteAction.Fixed && rule.Exit!=null)
                throw new PanelException("出口故障策略的格式或顺序无效。");
            return true;
        }
        if (rule.Id != DefaultId) return false;
        if (rule != DefaultRule || !rule.Enabled || rule.Group != null || rule.Entries is not [Unmatched] ||
            rule.Action is not (RouteAction.Direct or RouteAction.Fixed) || rule.Action == RouteAction.Direct && rule.Exit != null)
            throw new PanelException("默认动作必须位于全部网站规则之后，并绑定有效的分流动作。");
        return true;
    }

    public RoutingPolicy RemoveGroup(string id, bool keepRules)
    {
        var group = Groups.Single(g => g.Id == id);
        var rules = keepRules
            ? Rules.Select(r => r.Group == id ? r with { Group = null, Entries = [.. group.Entries], Enabled = r.Enabled && group.Enabled } : r)
            : Rules.Where(r => r.Group != id);
        return new(Groups.Where(g => g.Id != id).ToArray(), rules.ToArray());
    }
}
public sealed record Bandwidth(bool Enabled = false, double Upload = 0, double Download = 0)
{
    public void Validate()
    {
        if (Enabled && (!double.IsFinite(Upload) || !double.IsFinite(Download) || Upload <= 0 || Download <= 0))
            throw new PanelException("开启限速需要正数上传和下载 Mbps。");
    }
}
public sealed record RelayExit(string Id, string Name, bool Direct, bool Enabled, Bandwidth Limit, JsonObject Outbound)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? Aliases { get; init; }
}
public sealed record ExitSetting(string Id, bool Enabled, Bandwidth Limit);
public sealed record PolicyUpdate(RoutingPolicy Policy, Bandwidth Total, ExitSetting[] Settings)
{
    public RelayPlan Apply(RelayPlan plan)
    {
        var changes = Settings.ToDictionary(s => s.Id);
        if (changes.Keys.Except(plan.Exits.Select(e => e.Id)).Any()) throw new PanelException("规则方案含未部署的出口。");
        return plan with { Policy = Policy, Total = Total,
            Exits = plan.Exits.Select(e => changes.TryGetValue(e.Id, out var c) ? e with { Enabled = c.Enabled, Limit = c.Limit } : e).ToArray() };
    }
}
public sealed record RelayPlan(RoutingPolicy Policy, RelayExit[] Exits, Bandwidth Total)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool FollowHealthyDns { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public DnsFailureAction DnsOnFailure { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? ManagedDohResolvers { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string[]? BootstrapDohResolvers { get; init; }

    public string[] BootstrapDomains()
    {
        var domains = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var exit in Exits.Where(e => !e.Direct))
        {
            var settings = exit.Outbound["settings"];
            var servers = settings?["vnext"] as JsonArray;
            var hosts = servers?.Select(node => node?["address"]?.ToString()) ?? [settings?["address"]?.ToString()];
            foreach (var host in hosts.Concat(exit.Aliases ?? []))
                if (!string.IsNullOrEmpty(host) && !IPAddress.TryParse(host, out _))
                    domains.Add("full:" + RuleEngine.Domain(host));
        }
        foreach (var rule in Policy.WebsiteRules.Where(r => r.Enabled && r.Action == RouteAction.Direct))
        {
            var group = rule.Group is null ? null : Policy.Groups.Single(g => g.Id == rule.Group);
            if (group?.Enabled == false) continue;
            foreach (var entry in group?.Entries ?? rule.Entries)
            {
                var pair = entry.Trim().Split(':', 2);
                var kind = pair[0].ToLowerInvariant();
                if (pair.Length == 2 && kind is "domain" or "full" or "geosite")
                    domains.Add(kind + ":" + (kind == "geosite" ? pair[1].Trim().ToLowerInvariant() : RuleEngine.Domain(pair[1].Trim())));
            }
        }
        return domains.ToArray();
    }

    public string[]? HealthResolvers(string exitId) =>
        ManagedDohResolvers != null && Exits.Any(e => e.Id == exitId && e.Direct)
            ? BootstrapDohResolvers ?? DohResolvers.Domestic : null;

    public bool SameDns(RelayPlan other) =>
        (ManagedDohResolvers == null && other.ManagedDohResolvers == null) ||
        ManagedDohResolvers != null && other.ManagedDohResolvers != null &&
        ManagedDohResolvers.SequenceEqual(other.ManagedDohResolvers) &&
        (BootstrapDohResolvers ?? DohResolvers.Domestic).SequenceEqual(other.BootstrapDohResolvers ?? DohResolvers.Domestic);
}
public sealed record LinkSample(string Id, bool Direct, bool Healthy, double BaselineMs, double LatencyMs,
    double FailureRate, double BytesPerSecond, int Active, double Recovery, long Assigned,
    double? UploadBytesPerSecond = null, double? DownloadBytesPerSecond = null)
{
    [JsonIgnore]
    public double Weight => Math.Max(.01, Recovery) /
        (1 + 5 * Math.Max(0, LatencyMs / Math.Max(1, BaselineMs) - 1) + 9 * FailureRate
           + .12 * Math.Log2(1 + Active) + .08 * Math.Log2(1 + BytesPerSecond / 131072));
}
public sealed record RelaySnapshot(DateTimeOffset Time, long Sequence, LinkSample[] Links)
{
    public bool SupportsDefaultRoute { get; init; }
    public bool SupportsExitFailover { get; init; }
    public bool SupportsEncryptedDnsRouting { get; init; }
    public bool SupportsDnsFailurePolicy { get; init; }
    public bool SupportsManagedDoh { get; init; }
    public bool SupportsSplitDoh { get; init; }
    public string? AutoError => Links.Any(l => !l.Direct && l.Healthy) ? null : "自动分摊没有健康上游。";
}
public sealed record Decision(string Rule, string Group, RouteAction Action, string? Exit, string[] Candidates, string? Error)
{
    public string? FailoverReason { get; init; }
}

public sealed class RuleEngine
{
    private sealed record Entry(SiteRule Rule, string Group, Func<string, IPAddress?, bool>[] Tests);
    private readonly Entry[] entries;
    private readonly SiteRule? defaultRule;
    private readonly ExitFailurePolicy onUnavailable;
    public RuleEngine(RoutingPolicy policy, GeoCatalog geo, bool syntaxOnly = false)
    {
        if (policy.Rules.GroupBy(r => r.Id).Any(g => g.Count() != 1) || policy.Groups.GroupBy(g => g.Id).Any(g => g.Count() != 1))
            throw new PanelException("规则或规则集 ID 重复。");
        var groups = policy.Groups.ToDictionary(g => g.Id);
        defaultRule = policy.DefaultRule;
        onUnavailable = policy.OnUnavailable;
        var compiled = new List<Entry>();
        foreach (var rule in policy.Rules)
        {
            if (string.IsNullOrWhiteSpace(rule.Id) || string.IsNullOrWhiteSpace(rule.Name) ||
                !Enum.IsDefined(rule.Action) || rule.Action == RouteAction.Fixed && string.IsNullOrWhiteSpace(rule.Exit))
                throw new PanelException("规则名称、标识或动作无效。");
            if (policy.IsPolicyRule(rule)) continue;
            RuleSet? group = null;
            if (rule.Group != null && !groups.TryGetValue(rule.Group, out group)) throw new PanelException("规则引用了不存在的规则集。");
            if ((!rule.Enabled || group?.Enabled == false) && !syntaxOnly) continue;
            if (group != null && rule.Entries.Length > 0) throw new PanelException("规则请选择直接填写条件或引用规则集。");
            var tests = (group?.Entries ?? rule.Entries).Select(s => Compile(s, geo, syntaxOnly)).ToArray();
            if (tests.Length == 0) throw new PanelException("启用的规则需要至少一个匹配条件。");
            compiled.Add(new(rule, group?.Name ?? "—", tests));
        }
        entries = compiled.ToArray();
    }

    internal static string Domain(string text)
    {
        var value = new IdnMapping().GetAscii(text.TrimEnd('.')).ToLowerInvariant();
        if (!ExitProfile.ValidHost(value) || IPAddress.TryParse(value, out _)) throw new PanelException("域名无效。");
        return value;
    }

    private static Func<string, IPAddress?, bool> Compile(string raw, GeoCatalog geo, bool syntaxOnly)
    {
        var pair = raw.Trim().Split(':', 2);
        if (pair.Length != 2 || string.IsNullOrWhiteSpace(pair[1])) throw new PanelException("条件使用 full:、domain:、ip:、geosite: 或 geoip: 前缀。");
        var value = pair[1].Trim();
        switch (pair[0].ToLowerInvariant())
        {
            case "full": var full = Domain(value); return (s, ip) => ip == null && s == full;
            case "domain": var suffix = Domain(value); return (s, ip) => ip == null && (s == suffix || s.EndsWith("." + suffix, StringComparison.Ordinal));
            case "ip":
                if (IPAddress.TryParse(value, out var exact)) return (_, ip) => exact.Equals(ip);
                if (!IPNetwork.TryParse(value, out var network)) throw new PanelException("IP 网段格式无效。");
                return (_, ip) => ip != null && network.Contains(ip);
            case "geosite" when syntaxOnly: case "geoip" when syntaxOnly: return (_, _) => false;
            case "geosite": var sites = geo.Sites(value); return (s, ip) => ip == null && sites(s);
            case "geoip": var networks = geo.Networks(value); return (_, ip) => ip != null && networks(ip);
            default: throw new PanelException("不支持此匹配条件。");
        }
    }

    public Decision Select(string target, RelaySnapshot snapshot, bool healthyDns = false)
    {
        target = target.Trim();
        if (!IPAddress.TryParse(target, out var ip)) target = Domain(target);
        else target = ip.ToString();
        var entry = healthyDns ? null : entries.FirstOrDefault(e => e.Tests.Any(match => match(target, ip)));
        var rule = healthyDns ? null : entry?.Rule ?? defaultRule;
        var action = rule?.Action ?? RouteAction.Auto;
        string name = healthyDns ? "加密 DNS" : entry?.Rule.Name ?? "默认规则", group = entry?.Group ?? "—";
        Decision Resolve(RouteAction via, string? exit)
        {
            if (via==RouteAction.Auto) {
                var candidates=snapshot.Links.Where(l=>l.Healthy && !l.Direct).ToArray();
                var chosen=candidates.MaxBy(l=>Rank(snapshot.Sequence,target,l))?.Id;
                return new(name,group,via,chosen,candidates.Select(l=>l.Id).ToArray(),chosen==null?"自动分摊没有健康上游。":null);
            }
            var bound=via==RouteAction.Direct ? snapshot.Links.FirstOrDefault(l=>l.Direct)?.Id : exit;
            return new(name,group,via,bound,[],snapshot.Links.Any(l=>l.Id==bound && l.Healthy)?null:"绑定出口不可用或尚无健康记录。");
        }
        var primary=Resolve(action,rule?.Exit);
        if (primary.Error==null || action==RouteAction.Auto || onUnavailable.Action==FailureAction.Reject || snapshot.Time==default)
            return primary;
        // Resolve exactly once against the same snapshot. An unavailable fallback never re-enters the policy.
        var backup=onUnavailable.Action switch {
            FailureAction.Direct => Resolve(RouteAction.Direct,null),
            FailureAction.Fixed => Resolve(RouteAction.Fixed,onUnavailable.Exit),
            FailureAction.Auto => Resolve(RouteAction.Auto,null),
            FailureAction.UseDefault => Resolve(defaultRule?.Action??RouteAction.Auto,defaultRule?.Exit),
            _ => throw new PanelException("未知故障策略。")
        };
        return backup with { FailoverReason=$"原出口 {primary.Exit??"中转直连"} 不可用，故障策略：{onUnavailable.Label}",
            Error=backup.Error==null?null:"故障策略无可用出口，连接已拒绝。"+backup.Error };
    }
    private static double Rank(long sequence, string target, LinkSample link)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{sequence}|{target}|{link.Id}"));
        double uniform = ((System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes) >> 11) + .5) / 9007199254740992d;
        return Math.Log(uniform) / link.Weight;
    }
}
