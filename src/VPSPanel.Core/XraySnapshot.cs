using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VPSPanel.Core;

public sealed record PortSummary(string Tag, string Protocol, string Security, string Port);
public sealed record ExitSummary(string Tag, string Protocol, string Kind);
public sealed record RouteGroup(int Order, string Target, string Match, bool Fixed, string RuleTag = "")
{
    public string DisplayTag => string.IsNullOrWhiteSpace(RuleTag) ? "—" : RuleTag;
    public string DisplayMatch => string.IsNullOrWhiteSpace(Match) ? "—" : Match;
    public string Action => Fixed ? "指定出口" : "均衡组";
}
public sealed record XraySnapshot(string Digest, PortSummary[] Inbounds, ExitSummary[] Outbounds, RouteGroup[] Rules, ExitProfile[] Editable, RoutingPolicy? ImportedPolicy = null, int[]? ReviewOrders = null, JsonObject? DirectOutbound = null)
{
    internal static string S(JsonNode? node, string name, string fallback = "") => node?[name]?.ToString() ?? fallback;
    private static JsonObject[] Rows(JsonNode? n) => n is null ? [] : n.AsArray().Select(x => x!.AsObject()).ToArray();

    public static XraySnapshot Parse(string json)
    {
        try
        {
            var root = JsonNode.Parse(json, documentOptions: new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })!.AsObject();
            if (root["inbounds"] is null || root["outbounds"] is null) throw new PanelException("配置缺少入口或出口。");
            var ins = Rows(root["inbounds"]).Select(i => new PortSummary(S(i, "tag", "未命名"), S(i, "protocol"), S(i["streamSettings"], "security", "无"), S(i, "port", "本地套接字"))).ToArray();
            var summaries = new List<ExitSummary>(); var editable = new List<ExitProfile>();
            var rawOut = Rows(root["outbounds"]);
            var tags = rawOut.Select(x => S(x, "tag")).Where(t => t != "").ToHashSet(StringComparer.Ordinal);
            var assigned = new HashSet<string>();
            foreach (var o in rawOut)
            {
                string tag = S(o, "tag");
                if (tag.Length == 0) { tag = "outbound-" + (summaries.Count + 1); while (tags.Contains(tag) || assigned.Contains(tag)) tag += "-"; }
                if (!assigned.Add(tag)) throw new PanelException("配置存在重复出口标识，请先核对配置。");
                string protocol = S(o, "protocol"); var item = ReadExit(o, tag);
                if (item is not null) editable.Add(item);
                summaries.Add(new(tag, protocol, protocol == "freedom" ? "中转直连" : item?.Protocol ?? "只读出口"));
            }
            var rules = Rows(root["routing"]?["rules"]).Select((r, i) =>
            {
                var fixedTarget = S(r, "outboundTag");
                var match = string.Join("；", r.Where(p => p.Key is not ("type" or "outboundTag" or "balancerTag" or "ruleTag"))
                    .Select(p => p.Key + " " + (p.Value is JsonArray a ? string.Join("、", a.Select(v => v?.ToString())) : p.Value?.ToString())));
                return new RouteGroup(i + 1, fixedTarget.Length > 0 ? fixedTarget : S(r, "balancerTag", "默认"), match, fixedTarget.Length > 0, S(r, "ruleTag"));
            }).ToArray();
            var (policy,review) = ImportRules(Rows(root["routing"]?["rules"]),summaries,editable);
            return new(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))), ins, summaries.ToArray(), rules, editable.ToArray(),
                policy,review,rawOut.FirstOrDefault(o=>S(o,"protocol")=="freedom"));
        }
        catch (Exception e) when (e is not PanelException && e is not OutOfMemoryException)
        { throw new PanelException("无法解析单文件 Xray JSON 配置，原有本地草稿已保留。"); }
    }

    // Phase 2 stored formatted criteria. Upgrade only the unambiguous single-field cases.
    public XraySnapshot Upgrade()
    {
        if(ImportedPolicy!=null)return this;
        var rows = Rules.Select(r=>{
            var raw=new JsonObject{["ruleTag"]=r.RuleTag,["outboundTag"]=r.Target};
            var pair=r.Match.Split(' ',2);
            if(r.Fixed && pair.Length==2 && pair[0] is "domain" or "ip" && !pair[1].Contains('；'))
                raw[pair[0]]=new JsonArray(pair[1].Split('、').Select(v=>(JsonNode?)JsonValue.Create(v)).ToArray());
            return raw;
        });
        var (policy,review)=ImportRules(rows,Outbounds,Editable);
        return this with{ImportedPolicy=policy,ReviewOrders=review};
    }

    private static (RoutingPolicy,int[]) ImportRules(IEnumerable<JsonObject> rows,IEnumerable<ExitSummary> summaries,IEnumerable<ExitProfile> editable)
    {
        var groups = new List<RuleSet>();
        var imported = new List<SiteRule>();
        var review = new List<int>();
        var direct = summaries.FirstOrDefault(o => o.Kind == "中转直连")?.Tag;
        foreach (var (raw, index) in rows.Select((r,i) => (r,i)))
        {
            var target = S(raw,"outboundTag");
            bool domain = raw["domain"] is JsonArray;
            if (domain == (raw["ip"] is JsonArray) || raw.Any(p => p.Key is not ("type" or "ruleTag" or "domain" or "ip" or "outboundTag")) ||
                (target != direct && !editable.Any(e => e.Id == target)))
            { review.Add(index+1); continue; }
            var entries = raw[domain ? "domain" : "ip"]!.AsArray().Select(n => n!.ToString())
                .Select(v => !domain && !v.StartsWith("geoip:") ? "ip:"+v : v).ToArray();
            if (entries.Length == 0 || domain && entries.Any(v => !(v.StartsWith("domain:") || v.StartsWith("full:") || v.StartsWith("geosite:"))))
            { review.Add(index+1); continue; }
            var id = "source-"+(index+1);
            var label = S(raw,"ruleTag");
            if (string.IsNullOrWhiteSpace(label)) label = "原规则 "+(index+1);
            groups.Add(new(id,label,true,entries));
            imported.Add(new(id,label,true,id,[],target==direct?RouteAction.Direct:RouteAction.Fixed,target==direct?null:target));
        }
        return (new(groups.ToArray(),imported.ToArray()),review.ToArray());
    }

    internal static ExitProfile? ReadExit(JsonObject o, string id)
    {
        var stream = o["streamSettings"]; var settings = o["settings"];
        var p = new ExitProfile { Id = id, Name = id, Original = o };
        if (S(o, "protocol") == "hysteria" && S(settings, "version") == "2")
            return p with { Host = S(settings, "address"), Port = int.Parse(S(settings, "port", "443")), Sni = S(stream?["tlsSettings"], "serverName"), Secret = S(stream?["hysteriaSettings"], "auth") };
        if (S(o, "protocol") != "vless" || S(stream, "security") != "reality") return null;
        if (settings?["vnext"] is JsonArray { Count: not 1 }) return null;
        var server = settings?["vnext"] is JsonArray v ? v[0] : settings;
        if (server?["users"] is JsonArray { Count: not 1 }) return null;
        var user = server?["users"] is JsonArray u ? u[0] : server;
        var tls = stream?["realitySettings"];
        return p with
        {
            Protocol = "VLESS REALITY",
            Host = S(server, "address"),
            Port = int.Parse(S(server, "port", "443")),
            Secret = S(user, "id"),
            Sni = S(tls, "serverName"),
            PublicKey = S(tls, "password", S(tls, "publicKey")),
            ShortId = S(tls, "shortId"),
            Flow = S(user, "flow"),
            Fingerprint = S(tls, "fingerprint", "chrome")
        };
    }
}

public sealed record ExitWorkspace(XraySnapshot? Snapshot, List<ExitProfile> Drafts, List<string> Deleted)
{
    public static ExitWorkspace Empty => new(null, [], []);
    [System.Text.Json.Serialization.JsonIgnore]
    public IEnumerable<ExitProfile> Items => (Snapshot?.Editable ?? []).Where(x => !Deleted.Contains(x.Id))
        .Select(x => Drafts.FirstOrDefault(d => d.Id == x.Id) ?? x)
        .Concat(Drafts.Where(d => Snapshot?.Editable.Any(x => x.Id == d.Id) != true));
    public ExitWorkspace Refresh(XraySnapshot snapshot) => this with { Snapshot = snapshot };
    public ExitWorkspace Save(ExitProfile item, bool create)
    {
        item.Validate();
        if (create && !System.Text.RegularExpressions.Regex.IsMatch(item.Id, @"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$"))
            throw new PanelException("新出口 ID 使用 1–64 个英文字母、数字、点、横线或下划线，并以字母或数字开头。");
        if (create && (Items.Any(x => x.Id == item.Id) || Snapshot?.Outbounds.Any(x => x.Tag == item.Id) == true || Deleted.Contains(item.Id)))
            throw new PanelException("稳定 ID 已存在，请使用其他 ID。");
        if (!create && !Items.Any(x => x.Id == item.Id)) throw new PanelException("出口已不存在，请刷新。");
        return this with { Drafts = [.. Drafts.Where(x => x.Id != item.Id), item] };
    }
    public int[] References(string id) => Snapshot?.Rules.Where(r => r.Fixed && r.Target == id).Select(r => r.Order).ToArray() ?? [];
    public ExitWorkspace Delete(string id, bool managed = false)
    {
        if (!managed && References(id).Length != 0) throw new PanelException("此出口仍被固定规则引用，请先修改规则绑定。");
        var deleted = Deleted.Where(x => x != id).ToList();
        if (Snapshot?.Editable.Any(x => x.Id == id) == true) deleted.Add(id);
        return this with { Drafts = [.. Drafts.Where(x => x.Id != id)], Deleted = deleted };
    }
}
