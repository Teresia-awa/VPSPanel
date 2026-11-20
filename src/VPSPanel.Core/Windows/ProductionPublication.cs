using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VPSPanel.Core;

public sealed record PublicationTicket(string Id, string Before, string Desired, string[] Changes);
public sealed class PublicationPreview
{
    internal PublicationPreview(ManagedHost host,string revision,string basePlanDigest,RelayPlan plan,string[] changes,bool requiresXrayRestart)
    {
        Host=host; Revision=revision; BasePlanDigest=basePlanDigest; Plan=plan; Changes=Array.AsReadOnly(changes); RequiresXrayRestart=requiresXrayRestart;
    }
    internal ManagedHost Host { get; }
    internal string Revision { get; }
    internal string BasePlanDigest { get; }
    internal RelayPlan Plan { get; }
    public IReadOnlyList<string> Changes { get; }
    public bool RequiresXrayRestart { get; }
}
internal sealed record PublishedState(string Revision, RelayPlan Plan, string Source, string CheckUrl, bool SupportsDefaultRoute = false, bool SupportsExitFailover = false, bool SupportsEncryptedDnsRouting = false, bool SupportsDnsFailurePolicy = false, bool XrayDnsFallbackReady = false, bool SupportsManagedDoh = false, string? ServerDnsMode = null, JsonObject? OriginalDns = null, bool SupportsSplitDoh = false, bool? UsesBootstrapAsset = null, JsonObject? OriginalGeodata = null)
{
    internal ExitWorkspace Rebase(XraySnapshot original, ExitWorkspace? local, ExitWorkspace? backup)
    {
        var profiles = Plan.Exits.Where(e => !e.Direct).Select(e =>
        {
            var p = XraySnapshot.ReadExit(e.Outbound, e.Id) ?? throw new PanelException("已部署出口协议不受支持。");
            var previous = local?.Items.FirstOrDefault(i => i.Id == e.Id)??backup?.Items.FirstOrDefault(i=>i.Id==e.Id);
            return p with { Name=e.Name, Enabled=e.Enabled, Limited=e.Limit.Enabled, Up=(decimal)e.Limit.Upload,
                Down=(decimal)e.Limit.Download, Aliases=(e.Aliases ?? previous?.Aliases)?.Where(a=>!a.Equals(p.Host,StringComparison.OrdinalIgnoreCase)).ToArray()??[],
                LastProbe=previous!=null && JsonNode.DeepEquals(previous.ToOutbound(),p.ToOutbound()) ? previous.LastProbe : null };
        }).ToArray();
        var direct=Plan.Exits.SingleOrDefault(e=>e.Direct);
        var outbounds=Plan.Exits.Select(e=>new ExitSummary(e.Id,e.Outbound["protocol"]!.ToString(),e.Direct?"中转直连":profiles.Single(p=>p.Id==e.Id).Protocol));
        var snapshot=original with { Editable=profiles, Outbounds=outbounds.ToArray(), DirectOutbound=direct?.Outbound, ImportedPolicy=Plan.Policy };
        bool Matches(ExitProfile a,ExitProfile? b)=>b!=null && a.Name==b.Name && a.Enabled==b.Enabled && a.Limited==b.Limited &&
            a.Up==b.Up && a.Down==b.Down && a.Aliases.SequenceEqual(b.Aliases) && JsonNode.DeepEquals(a.ToOutbound(),b.ToOutbound());
        var drafts=local?.Drafts.Where(d=>!Matches(d,profiles.FirstOrDefault(x=>x.Id==d.Id)) &&
            !Matches(d,local.Snapshot?.Editable.FirstOrDefault(x=>x.Id==d.Id))).ToList()??[];
        return new(snapshot,drafts,local?.Deleted.Where(id=>profiles.Any(p=>p.Id==id)).ToList()??[]);
    }
}

internal static class PublicationRemote
{
    internal sealed record Reply(string Status, PublishedState? Current, string? Reason);
    private static readonly string Command=LoadCommand();
    private static string LoadCommand()
    {
        using var stream=typeof(PanelSession).Assembly.GetManifestResourceStream("VPSPanel.publication.py")!;
        using var reader=new StreamReader(stream);
        return "python3 -c "+OpenSsh.Quote(reader.ReadToEnd().ReplaceLineEndings("\n"));
    }
    internal static async Task<Reply> Call(ISshTransport io, object data, CancellationToken ct)
    {
        var json=await io.Command(Command,JsonSerializer.Serialize(data),ct);
        var reply=JsonSerializer.Deserialize<Reply>(json)??throw new PanelException("发布回执格式错误。");
        if(reply.Status=="unavailable")throw new PanelException(reply.Reason switch {
            "inactive"=>"入口或 Relay 服务尚未运行。","relay identity"=>"Relay 进程与接管目录不匹配。",
            "kernel identity"=>"入口内核与 Relay 管理的内核不匹配。","config binding"=>"正式入口的持久配置绑定与接管目录不匹配。",
            "config identity"=>"已部署配置与 Relay 管理端口不匹配，或缺少接管源配置。","stale status"=>"Relay 实时快照已过期。",
            _=>"无法读取接管服务状态或管理文件，请检查 SSH 权限及目标服务。"});
        return reply;
    }
    internal static async Task<PublishedState> Inspect(ISshTransport io,SshTarget target,CancellationToken ct,bool includeDnsSource=false)
    {
        var reply=await Call(io,new {Op="inspect",target.Service,IncludeDnsSource=includeDnsSource},ct);
        return reply.Current??throw new PanelException("Relay 正在处理其他事务，请稍后重新预览。");
    }
}

internal static class PlanChanges
{
    internal static bool Equal<T>(T a,T b)=>JsonNode.DeepEquals(JsonSerializer.SerializeToNode(a),JsonSerializer.SerializeToNode(b));
    internal static string Digest(RelayPlan plan) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(plan)));
    private static string Rate(Bandwidth b)=>b.Enabled?$"上传 {b.Upload:g} / 下载 {b.Download:g} Mbps":"关闭";
    private static string On(bool b)=>b?"启用":"停用";
    private static string Target(SiteRule r)=>r.Action switch {RouteAction.Auto=>"自动分摊",RouteAction.Direct=>"中转直连",_=>"出口 "+r.Exit};
    internal static string[] Compare(RelayPlan old,RelayPlan next)
    {
        var lines=new List<string>();
        void Conditions(string label,string[] before,string[] after)
        {
            foreach(var s in before.Except(after))lines.Add($"{label}　移除条件 {s}");
            foreach(var s in after.Except(before))lines.Add($"{label}　添加条件 {s}");
        }
        void Diff<T>(string kind,T[] before,T[] after,Func<T,string> id,Func<T,string> name,Action<T,T,string> change)
        {
            var prior=before.ToDictionary(id);var remaining=after.Select(id).ToHashSet();
            foreach(var x in before.Where(x=>!remaining.Contains(id(x))))lines.Add($"删除{kind}「{name(x)}」");
            foreach(var x in after)
            {
                string label=$"{kind}「{name(x)}」";
                if(!prior.TryGetValue(id(x),out var prev))lines.Add("新增"+label);
                else if(!Equal(prev,x))change(prev,x,label);
            }
        }
        Diff("出口",old.Exits,next.Exits,e=>e.Id,e=>e.Name,(a,b,label)=>{
            if(!Equal(a.Aliases,b.Aliases))lines.Add($"{label}　更新备用域名");
            if(a.Name!=b.Name)lines.Add($"{label}　名称 {a.Name} → {b.Name}");
            if(a.Enabled!=b.Enabled)lines.Add($"{label}　{On(a.Enabled)} → {On(b.Enabled)}");
            if(a.Limit!=b.Limit)lines.Add($"{label}　限速 {Rate(a.Limit)} → {Rate(b.Limit)}");
            if(!JsonNode.DeepEquals(a.Outbound,b.Outbound)){
                var before=XraySnapshot.ReadExit(a.Outbound,a.Id);
                var after=XraySnapshot.ReadExit(b.Outbound,b.Id);
                if(before==null || after==null){lines.Add($"{label}　更新协议配置");return;}
                if(before.Host!=after.Host)lines.Add($"{label}　连接域名 {before.Host} → {after.Host}");
                if(before.Port!=after.Port)lines.Add($"{label}　连接端口 {before.Port} → {after.Port}");
                if(before.Sni!=after.Sni)lines.Add($"{label}　TLS 名称 {before.Sni} → {after.Sni}");
                if(before.Secret!=after.Secret)lines.Add($"{label}　更新认证凭据（内容隐藏）");
                var projected=before with { Host=after.Host, Port=after.Port, Sni=after.Sni, Secret=after.Secret };
                if(!JsonNode.DeepEquals(projected.ToOutbound(),after.ToOutbound()))lines.Add($"{label}　更新协议或高级参数");
            }
        });
        Diff("规则集",old.Policy.Groups,next.Policy.Groups,g=>g.Id,g=>g.Name,(a,b,l)=>{
            if(a.Name!=b.Name)lines.Add($"{l}　名称 {a.Name} → {b.Name}");
            if(a.Enabled!=b.Enabled)lines.Add($"{l}　{On(a.Enabled)} → {On(b.Enabled)}");
            Conditions(l,a.Entries,b.Entries);
        });
        var oldRules=old.Policy.WebsiteRules.ToArray();
        var newRules=next.Policy.WebsiteRules.ToArray();
        Diff("网站规则",oldRules,newRules,r=>r.Id,r=>r.Name,(a,b,l)=>{
            lines.Add($"{l}　{On(b.Enabled)} · {Target(a)} → {Target(b)} · "+(b.Group==null?"独立条件 "+b.Entries.Length+" 条":"规则集 "+next.Policy.Groups.Single(g=>g.Id==b.Group).Name));
            Conditions(l,a.Entries,b.Entries);
        });
        foreach(var e in next.Exits.Where(e=>old.Exits.All(a=>a.Id!=e.Id)))lines.Add($"出口「{e.Name}」　{On(e.Enabled)} · 限速 {Rate(e.Limit)}");
        foreach(var g in next.Policy.Groups.Where(g=>old.Policy.Groups.All(a=>a.Id!=g.Id)))Conditions($"规则集「{g.Name}」　{On(g.Enabled)}",[],g.Entries);
        foreach(var r in newRules.Where(r=>oldRules.All(a=>a.Id!=r.Id)))
            lines.Add($"网站规则「{r.Name}」　{On(r.Enabled)} · {Target(r)} · "+(r.Group==null?string.Join("、",r.Entries):"规则集 "+next.Policy.Groups.Single(g=>g.Id==r.Group).Name));
        string fallback=next.Policy.DefaultRule is {} rule?Target(rule):"自动分摊";
        if(!Equal(old.Policy.DefaultRule,next.Policy.DefaultRule))
            lines.Add($"未命中规则的默认动作　{(old.Policy.DefaultRule is {} prior?Target(prior):"自动分摊")} → {fallback}");
        if(old.Policy.OnUnavailable!=next.Policy.OnUnavailable)
            lines.Add($"出口不可用时　{old.Policy.OnUnavailable.Label} → {next.Policy.OnUnavailable.Label}");
        if(!oldRules.Select(r=>r.Id).SequenceEqual(newRules.Select(r=>r.Id)))
            lines.Add("匹配顺序　"+string.Join(" → ",newRules.Select(r=>r.Name).Append("默认："+fallback)));
        if(old.Total!=next.Total)lines.Add($"整体限速　{Rate(old.Total)} → {Rate(next.Total)}");
        if(!Equal(old.ManagedDohResolvers,next.ManagedDohResolvers))
            lines.Add(next.ManagedDohResolvers is { } resolvers
                ? $"Xray DNS 解析器　应用面板中的 {resolvers.Length} 个 DoH 地址"
                : "Xray DNS 解析器　恢复服务器原有配置");
        if(old.FollowHealthyDns!=next.FollowHealthyDns)
            lines.Add(next.FollowHealthyDns?"加密 DNS　跟随健康上游":"加密 DNS　恢复服务器原有出站");
        if (!Equal(old.BootstrapDohResolvers, next.BootstrapDohResolvers))
            lines.Add("更新直连与节点引导 DoH");
        if (next.ManagedDohResolvers != null && !old.BootstrapDomains().SequenceEqual(next.BootstrapDomains()))
            lines.Add("同步直连规则与节点域名绑定");
        return lines.ToArray();
    }
}

public sealed partial class PanelSession
{
    public async Task<PublicationPreview> PreviewProduction(CancellationToken ct)
    {
        var host=Current;
        if(IsDemo || host?.ManagedRevision==null)throw new PanelException("请在正式面板首页只读读取已接管 VPS，再预览变更。");
        var remote=await PublicationRemote.Inspect(RelayTransport(host),host.Target,ct);
        if(Current!=host || remote.Revision!=host.ManagedRevision)throw new PanelException("主机或已部署配置已变化，请重新只读读取并预览。");
        var draft=BuildRelayPlan();
        if(draft.FollowHealthyDns!=remote.Plan.FollowHealthyDns && !remote.SupportsEncryptedDnsRouting)
            throw new PanelException("当前 VPS 的 Relay 尚未支持加密 DNS 路由。请升级 Relay，DNS 草稿已保留。");
        bool requiresRestart = !draft.SameDns(remote.Plan) || draft.ManagedDohResolvers != null && remote.UsesBootstrapAsset == false;
        if((requiresRestart || draft.ManagedDohResolvers!=null) && !remote.SupportsSplitDoh)
            throw new PanelException("请升级 Relay 后再应用双栏 DoH 配置。");
        if(draft.Policy.OnUnavailable.Action!=FailureAction.Reject && !remote.SupportsExitFailover)
            throw new PanelException("当前 VPS 的 Relay 尚未支持出口故障策略。请升级后再应用，草稿已保留。");
        if(draft.Policy.DefaultRule!=null && !remote.SupportsDefaultRoute)
            throw new PanelException("当前 VPS 的 Relay 仅支持默认自动分摊。草稿已保留，请升级 Relay 后再应用直连或固定出口。");
        // Keep the exact accepted wire configuration for untouched transports (older plans can omit default fields).
        var exits=draft.Exits.Select(e=>{
            var old=remote.Plan.Exits.FirstOrDefault(x=>x.Id==e.Id);
            if(old==null)return e;
            if(e.Direct)return old;
            if(old.Aliases!=null && e.Aliases==null)e=e with {Aliases=[]};
            var p=XraySnapshot.ReadExit(old.Outbound,old.Id);
            return p!=null && JsonNode.DeepEquals(p.ToOutbound(),e.Outbound)?e with{Outbound=old.Outbound}:e;
        }).ToArray();
        var next=draft with{Exits=exits};
        var changes=PlanChanges.Compare(remote.Plan,next);
        if(requiresRestart) changes=[.. changes,"重启 Xray 并校验解析器，失败时自动恢复"];
        return new(host,remote.Revision,PlanChanges.Digest(remote.Plan),next,changes,requiresRestart);
    }

    public async Task<string> ApplyProduction(PublicationPreview preview,CancellationToken ct)
    {
        var host=Current;
        if(IsDemo || host==null || !ReferenceEquals(host,preview.Host) || host.ManagedRevision!=preview.Revision || book.Revision!=ReadBook().Revision)
            throw new PanelException("本机草稿或主机已变化，请重新预览。");
        if(preview.Changes.Count==0)return "已保存的草稿与 VPS 一致。";
        var io=RelayTransport(host);
        var ticket=new PublicationTicket(Guid.NewGuid().ToString("N"),preview.BasePlanDigest,PlanChanges.Digest(preview.Plan),preview.Changes.ToArray());
        Write(book.Selected!,host with{Publication=ticket});
        var reply=await PublicationRemote.Call(io,new {Op="submit",host.Target.Service,ticket.Id,preview.Revision,preview.Plan,RestartXray=preview.RequiresXrayRestart},ct);
        if(reply.Status!="submitted")throw new PanelException(reply.Status switch {
            "stale"=>"VPS 配置在预览后有变更，本次未提交。请重新读取并预览。",
            "needs-restart"=>"重新预览并确认 Xray 重启后才能应用 DNS 变更。",
            _=>"其他事务正在处理，本次未提交。"});
        for(int i=0;i<90;i++){
            await Task.Delay(1000,ct);
            PublicationRemote.Reply result;
            try { result=await PublicationRemote.Call(io,new {Op="result",host.Target.Service,ticket.Id},ct); }
            catch(PanelException) when (preview.RequiresXrayRestart && !ct.IsCancellationRequested) { continue; }
            if(result.Status is "applied" or "rejected")return FinishPublication(host.Target,ticket,result);
        }
        return "已提交，回执尚未返回。可用「核对上次应用」继续查询。";
    }

    public async Task<string> CheckPublication(CancellationToken ct)
    {
        var host=Current;
        if(IsDemo || host?.Publication is not {} ticket)throw new PanelException("当前主机没有生产发布记录。");
        var reply=await PublicationRemote.Call(RelayTransport(host),new {Op="result",host.Target.Service,ticket.Id},ct);
        return FinishPublication(host.Target,ticket,reply);
    }
    private string FinishPublication(SshTarget target,PublicationTicket ticket,PublicationRemote.Reply reply)
    {
        if(Current is not {} host || host.Target!=target || host.Publication?.Id!=ticket.Id)throw new PanelException("主机或事务已切换，请回到原主机核对回执。");
        if(reply.Status=="rejected")return reply.Current!=null && PlanChanges.Digest(reply.Current.Plan)==ticket.Before
            ?"发布失败，Relay 拒绝或已回滚本次变更。已核对 VPS 保留上一版；本机草稿可继续修改。"
            :"发布失败。VPS 当前版本已有其他变更，请重新读取。";
        if(reply.Status!="applied" || reply.Current==null)return reply.Status=="pending"?"Relay 正在处理此事务。":"尚无此事务的回执。请重新预览，核对当前部署状态。";
        if(PlanChanges.Digest(reply.Current.Plan)!=ticket.Desired)return "本次有成功回执，当前部署已变化。请重新读取并预览。";
        if(host.ManagedRevision!=reply.Current.Revision){
            var deployed=reply.Current;
            var workspace=deployed.Rebase(host.Workspace.Snapshot!,host.Workspace,null);
            Write(book.Selected!,host with{ManagedRevision=deployed.Revision,Workspace=workspace,
                Rules=PlanChanges.Equal(host.Policy,deployed.Plan.Policy)?null:host.Rules,DeployedTotal=deployed.Plan.Total,
                FollowHealthyDnsDraft=host.FollowHealthyDns==deployed.Plan.FollowHealthyDns?null:host.FollowHealthyDnsDraft,
                DeployedFollowHealthyDns=deployed.Plan.FollowHealthyDns,
                DnsOnFailureDraft=host.DnsOnFailure==deployed.Plan.DnsOnFailure?null:host.DnsOnFailureDraft,
                DeployedDnsOnFailure=deployed.Plan.DnsOnFailure,
                DnsResolversDraft=PlanChanges.Equal(host.ManagedDohResolvers,deployed.Plan.ManagedDohResolvers)?null:host.DnsResolversDraft,
                DeployedBootstrap=deployed.Plan.BootstrapDohResolvers,DeployedDohResolvers=deployed.Plan.ManagedDohResolvers,ServerDnsMode=deployed.ServerDnsMode});
            Changed?.Invoke();
        }
        return "已生效（Relay 回执与 VPS 持久方案一致）\n"+string.Join("\n",ticket.Changes.Select(c=>"✓ "+c));
    }
}
