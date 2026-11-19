using System.Security.Cryptography;
using System.Text.Json;

namespace VPSPanel.Core;

public sealed record ObservedTopology(PortSummary[] Inbounds,ExitSummary[] Outbounds,RouteGroup[] Rules);
public sealed record ManagedHost(SshTarget Target, string Version, string Binary, string ConfigPath,
    DateTimeOffset ReadAt, bool Sftp, ExitWorkspace Workspace, string WorkingDirectory, DirectProfile? Direct = null, RoutingPolicy? Rules = null, Bandwidth? Total = null, Guid? GeoSet = null,
    string? ManagedRevision = null, string? CheckUrl = null, PublicationTicket? Publication = null, Bandwidth? DeployedTotal = null,
    ObservedTopology? LastReadTopology = null)
{
    [System.Text.Json.Serialization.JsonIgnore] public RoutingPolicy Policy => Rules ?? Workspace.Snapshot?.ImportedPolicy ?? RoutingPolicy.Empty;
}
public sealed record ConnectionBook(int Revision, string? Selected, Dictionary<string, ManagedHost> Hosts);

public sealed partial class PanelSession(string directory, Func<SshTarget, OpenSsh>? sshFactory = null)
{
    private string FileName => Path.Combine(directory, "connections.dpapi");
    private ConnectionBook book = new(0, null, []);
    public ManagedHost? Current => book.Selected == null ? null : book.Hosts[book.Selected];
    public event Action? Changed;
    public string GeoDirectory => Current?.GeoSet is Guid id ? Path.Combine(directory,"geo",id.ToString("N")) : Path.Combine(directory,"geo");
    public Func<HostFingerprint, bool>? ConfirmFingerprint { get; set; }
    private readonly DirectAccess access = new(directory);
    private (SshTarget Target, DirectLogin Credentials)? activeLogin;
    public void ClearSessionCredentials() => activeLogin = null;
    public bool HasSavedPassword(SshTarget target) => access.SavedSecret(target) != null;
    public void ForgetPassword(SshTarget target) => access.SetSecret(target, null);

    private ConnectionBook ReadBook()
    {
        byte[] encrypted;
        try { encrypted = File.ReadAllBytes(FileName); }
        catch (FileNotFoundException) { return new(0, null, []); }
        catch (DirectoryNotFoundException) { return new(0, null, []); }
        var plain = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        try { return JsonSerializer.Deserialize<ConnectionBook>(plain) ?? throw new InvalidDataException(); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public void Load()
    {
        book = ReadBook();
        foreach(var (key, host) in book.Hosts.ToArray()){
            if(host.Workspace.Snapshot is {ImportedPolicy:null} snapshot)
                book.Hosts[key]=host with{Workspace=host.Workspace with{Snapshot=snapshot.Upgrade()}};
        }
        activeLogin = null; Changed?.Invoke();
    }
    private RemoteInspection Remote(SshTarget target, DirectLogin? direct) => new(direct == null
        ? sshFactory?.Invoke(target) ?? new OpenSsh(target) : new DirectSsh(target, direct, access, ConfirmFingerprint));

    public async Task ReadOnly(SshTarget target, CancellationToken token, DirectLogin? direct = null)
    {
        if(IsDemo)throw new PanelException("当前为离线演示，请查看下方虚构快照。");
        var currentRevision = book.Revision;
        if (direct != null)
        {
            target.Validate();
            if (target.User.Length == 0 || !ExitProfile.ValidHost(target.Host))
                throw new PanelException("主机直连需要有效的主机 IP 或域名和 SSH 用户名。");
            target = target with { Port = target.Port ?? 22 };
            new ProtectedTerms(Path.Combine(directory, "guard")).Register(target.Host);
            if (!direct.Remember && direct.Profile.KeyFile == null) ForgetPassword(target);
            if (direct.Profile.KeyFile == null && direct.Secret.Length == 0)
            {
                var saved = direct.Remember ? access.SavedSecret(target) : null;
                if (saved == null) throw new PanelException("请输入 SSH 登录密码。");
                direct = new DirectLogin(direct.Profile, saved, true);
            }
        }
        var remote = Remote(target, direct);
        var read = direct == null ? await remote.Read(target, token) :
            await Task.Run(() => remote.Read(target, token), token);
        token.ThrowIfCancellationRequested();
        if (book.Revision != currentRevision) throw new PanelException("读取期间本机草稿已更改，请重新读取。");
        string key = JsonSerializer.Serialize(target);
        if (direct != null) key = "direct:" + key;
        var previous = book.Hosts.GetValueOrDefault(key);
        MigrationProfile? packageProfile=null;
        if(target.Service=="vpspanel-restored-xray" && read.ConfigPath=="/var/lib/vpspanel/xray.json"){
            var io=direct==null?(ISshTransport)(sshFactory?.Invoke(target)??new OpenSsh(target)):new DirectSsh(target,direct,access,ConfirmFingerprint);
            var (json,_)=await io.ReadConfiguration("/var/lib/vpspanel/panel.json",token);
            packageProfile=JsonSerializer.Deserialize<MigrationProfile>(json)??throw new PanelException("迁移配置档案无效。");
        }
        var workspace = previous?.Workspace ?? packageProfile?.Workspace ?? ExitWorkspace.Empty;
        var logicalSnapshot=packageProfile?.Workspace.Snapshot??read.Snapshot;
        var rules=previous?.Rules??packageProfile?.Policy;
        var total=previous?.Total??packageProfile?.Total;
        PublishedState? managed=null;
        if (RecoveryLayout.Parse(read.RawJson)["api"]?["tag"]?.ToString()==RecoveryLayout.ApiTag)
        {
            var io=direct==null?(ISshTransport)(sshFactory?.Invoke(target)??new OpenSsh(target)):new DirectSsh(target,direct,access,ConfirmFingerprint);
            managed=await PublicationRemote.Inspect(io,target,token);
            var source=(await io.ReadConfiguration(managed.Source,token)).Json;
            var original=XraySnapshot.Parse(source);
            workspace=managed.Rebase(original,previous?.Workspace,packageProfile?.Workspace);
            logicalSnapshot=workspace.Snapshot!;
            if(previous?.Rules==null || PlanChanges.Equal(previous.Rules,previous.Workspace.Snapshot?.ImportedPolicy)) rules=null;
            if(previous?.Total==null || previous.Total==previous.DeployedTotal) total=managed.Plan.Total;
        }
        if(book.Revision!=currentRevision)throw new PanelException("读取期间本机草稿已更改，请重新读取。");
        if (direct?.Remember == true) access.SetSecret(target, direct.Secret);
        Write(key, new(target, read.Version, read.Binary, read.ConfigPath, DateTimeOffset.Now,
            read.Sftp, workspace.Refresh(logicalSnapshot), read.WorkingDirectory, direct?.Profile,rules,total,previous?.GeoSet,managed?.Revision,managed?.CheckUrl,previous?.Publication,managed?.Plan.Total,
            managed==null?null:new(read.Snapshot.Inbounds,read.Snapshot.Outbounds,read.Snapshot.Rules)));
        activeLogin = direct == null ? null : (target, direct);
        Changed?.Invoke();
    }

    public async Task<CheckedExit> Probe(ExitProfile candidate, CancellationToken token, Uri? checkUrl = null)
    {
        if(IsDemo)throw new PanelException("离线演示使用虚构出口。");
        var host = Current ?? throw new PanelException("请先在首页只读读取目标主机。");
        if (host.Version != "26.10.31") throw new PanelException("当前 Xray 与已验证版本 26.10.31 不同。只读快照可用，预检需先复核内核兼容性。");
        var login = activeLogin is { } active && active.Target == host.Target && active.Credentials.Profile == host.Direct
            ? active.Credentials : null;
        if (host.Direct != null && login == null)
        {
            var secret = host.Direct.KeyFile == null ? access.SavedSecret(host.Target) : "";
            if (secret == null) throw new PanelException("请回到首页输入本次登录密码，再只读读取配置。");
            login = new DirectLogin(host.Direct, secret);
        }
        var remote = Remote(host.Target, host.Direct == null ? null : login);
        if(checkUrl==null && host.CheckUrl!=null)checkUrl=new Uri(host.CheckUrl);
        var result = host.Direct == null ? await remote.Probe(host.Binary, host.WorkingDirectory, candidate, token, checkUrl) :
            await Task.Run(() => remote.Probe(host.Binary, host.WorkingDirectory, candidate, token, checkUrl), token);
        return new CheckedExit(host, candidate, result);
    }

    public sealed class CheckedExit
    {
        internal readonly ManagedHost Host;
        internal readonly string Transport;
        public ProbeResult Result { get; }
        internal CheckedExit(ManagedHost host, ExitProfile candidate, ProbeResult result)
        {
            Host = host;
            Transport = candidate.ToOutbound().ToJsonString();
            Result = result;
        }
    }

    public void SaveExit(ExitProfile candidate, bool create, CheckedExit? check)
    {
        var host = Current ?? throw new PanelException("请先读取目标主机。");
        var next = host.Workspace.Save(candidate, create);
        var previous = host.Workspace.Items.FirstOrDefault(x => x.Id == candidate.Id);
        string transport = candidate.ToOutbound().ToJsonString();
        bool checkedHere = check?.Host == host && check.Transport == transport;
        if ((create || previous?.ToOutbound().ToJsonString() != transport) && !(checkedHere && check!.Result.Passed))
            throw new PanelException("请先对这组连接参数完成三项预检，原地址仍保留。");
        var result = checkedHere ? check!.Result : previous?.LastProbe;
        next = next.Save(candidate with { LastProbe = result }, false);
        Write(book.Selected!, host with { Workspace = next });
        Changed?.Invoke();
    }

    public void SaveRules(RoutingPolicy policy, Bandwidth total)
    {
        var host=Current ?? throw new PanelException("请先读取主机快照。");
        _ = new RuleEngine(policy,new(GeoDirectory),syntaxOnly:true);
        foreach(var group in policy.Groups)
            _ = new RuleEngine(new([group with {Enabled=true}],[new("check","校验",true,group.Id,[],RouteAction.Auto,null)]),new(GeoDirectory),true);
        if(policy.Rules.Any(r=>r.Action==RouteAction.Fixed && !host.Workspace.Items.Any(e=>e.Id==r.Exit)))
            throw new PanelException("指定出口已不存在。");
        total.Validate();
        Write(book.Selected!,host with {Rules=policy,Total=total});
        Changed?.Invoke();
    }

    public PolicyUpdate RuleUpdate()
    {
        var h=Current ?? throw new PanelException("请先读取主机快照。");
        return new(h.Policy,h.Total??new(),h.Workspace.Items.Select(e=>new ExitSetting(e.Id,e.Enabled,new(e.Limited,(double)e.Up,(double)e.Down))).ToArray());
    }

    private ISshTransport RelayTransport(ManagedHost h)
    {
        var login=activeLogin is { } active && active.Target==h.Target && active.Credentials.Profile==h.Direct ? active.Credentials : null;
        if(h.Direct!=null && login==null){
            var secret=h.Direct.KeyFile==null?access.SavedSecret(h.Target):"";
            if(secret==null)throw new PanelException("请先在首页完成本次登录。");
            login=new(h.Direct,secret);
        }
        return h.Direct==null?sshFactory?.Invoke(h.Target)??new OpenSsh(h.Target):new DirectSsh(h.Target,login!,access,ConfirmFingerprint);
    }

    public async Task<RelaySnapshot> ReadRelayStatus(CancellationToken ct)
    {
        if(IsDemo)return ExampleStatus();
        var transport=RelayTransport(Current??throw new PanelException("请先选择主机。"));
        var (json,_)=await Task.Run(()=>transport.ReadConfiguration("/var/lib/vpspanel/status.json",ct),ct);
        return JsonSerializer.Deserialize<RelaySnapshot>(json)??throw new PanelException("Relay 快照无效。");
    }

    public RelayPlan BuildRelayPlan()
    {
        var h=Current??throw new PanelException("先读取主机快照。");
        var snapshot=h.Workspace.Snapshot??throw new PanelException("缺少入口快照。");
        var exits=h.Workspace.Items.Select(e=>new RelayExit(e.Id,e.Name,false,e.Enabled,
            new(e.Limited,(double)e.Up,(double)e.Down),e.ToOutbound())).ToList();
        var direct=snapshot.Outbounds.Where(e=>e.Kind=="中转直连").ToArray();
        if(direct.Length>1)throw new PanelException("有多个直连出口，须先在接管时明确直连绑定。");
        if(direct.Length==1)exits.Add(new(direct[0].Tag,direct[0].Tag,true,true,new(),
            snapshot.DirectOutbound??throw new PanelException("上次快照缺少完整直连参数，请重新只读读取。")));
        return new(h.Policy,exits.ToArray(),h.Total??new());
    }

    public async Task ApplyToLabRelay(CancellationToken ct)
    {
        var h=Current??throw new PanelException("请先选择隔离主机。");
        if(IsDemo || !System.Net.IPAddress.TryParse(h.Target.Host,out var ip) || !System.Net.IPAddress.IsLoopback(ip))
            throw new PanelException("阶段三仅允许通过回环 IP 同步到本机隔离 SSH 环境。");
        var plan=BuildRelayPlan();
        if(plan.Policy.DefaultRule!=null || plan.Policy.OnUnavailable.Action!=FailureAction.Reject){
            var status=await ReadRelayStatus(ct);
            if(plan.Policy.DefaultRule!=null && !status.SupportsDefaultRoute || plan.Policy.OnUnavailable.Action!=FailureAction.Reject && !status.SupportsExitFailover)
                throw new PanelException("请升级隔离 Relay 后再应用所选分流策略。");
        }
        var transport=RelayTransport(h);
        const string folder="/var/lib/vpspanel";
        string relay=h.Target.Service=="vpspanel-restored-xray"?folder+"/relay":"/usr/local/bin/vpspanel-relay";
        string id=(await Task.Run(()=>transport.Command(relay+" submit-existing "+folder+" -",JsonSerializer.Serialize(plan),ct),ct)).Trim();
        if(!Guid.TryParseExact(id,"N",out _))throw new PanelException("隔离 Relay 未返回有效事务编号。");
        for(int i=0;i<90;i++){
            await Task.Delay(1000,ct);
            var json=await transport.Command("cat "+folder+"/receipts/"+id+".json 2>/dev/null || true","",ct);
            if(string.IsNullOrWhiteSpace(json))continue;
            using var result=JsonDocument.Parse(json);
            var root=result.RootElement;
            if(root.GetProperty("Id").GetString()!=id)continue;
            if(!root.GetProperty("Success").GetBoolean())throw new PanelException("隔离 Relay 拒绝方案，请核对分类数据、静态配置和出口健康。");
            return;
        }
        throw new PanelException("已提交，尚未收到完成回执。请核对隔离环境的事务结果。");
    }

    public void DeleteExit(string id)
    {
        var host = Current ?? throw new PanelException("请先读取目标主机。");
        if(host.Policy.DefaultRule is {Action: RouteAction.Fixed} fallback && fallback.Exit==id)
            throw new PanelException("此出口是未命中规则时的默认出口，请先修改默认动作。");
        if(host.Policy.OnUnavailable is {Action: FailureAction.Fixed} failure && failure.Exit==id)
            throw new PanelException("此出口被故障策略引用，请先在设置中修改备用出口。");
        if(host.Policy.WebsiteRules.Any(r=>r.Action==RouteAction.Fixed && r.Exit==id))throw new PanelException("此出口仍被网站规则引用，请先修改绑定。");
        Write(book.Selected!, host with { Workspace = host.Workspace.Delete(id, host.ManagedRevision!=null) });
        Changed?.Invoke();
    }

    private void Write(string key, ManagedHost host)
    {
        Directory.CreateDirectory(directory);
        using (File.Open(Path.Combine(directory, "connections.lock"), FileMode.OpenOrCreate, FileAccess.Write, FileShare.None))
        {
            if (ReadBook().Revision != book.Revision)
                throw new PanelException("另一个窗口已更新本机配置，请重新打开面板。");
            var next = new ConnectionBook(book.Revision + 1, key, new(book.Hosts) { [key] = host });
            var terms = host.Workspace.Items.SelectMany(e => e.Aliases.Append(e.Host).Append(e.Sni)
                .Concat(e.Secret.Length >= 8 ? [e.Secret] : Array.Empty<string>())).Append(host.Target.Host);
            new ProtectedTerms(Path.Combine(directory, "guard")).RegisterMany(terms);
            var plain = JsonSerializer.SerializeToUtf8Bytes(next);
            var temporary = FileName + "." + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllBytes(temporary, ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser));
                File.Move(temporary, FileName, overwrite: true);
                book = next;
            }
            finally { CryptographicOperations.ZeroMemory(plain); File.Delete(temporary); }
        }
    }
}
