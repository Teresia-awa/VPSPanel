using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPSPanel.Core;

namespace VPSPanel.Tests;

public sealed class MigrationTests
{
    [Fact]
    public void TruncatedAndWrongKeyNeverReachPayload()
    {
        var temp=Directory.CreateTempSubdirectory();
        try{
            var elf=new byte[64];new byte[]{127,69,76,70,2,1}.CopyTo(elf,0);elf[18]=62;
            var files=RecoveryPackage.Required.ToDictionary(s=>s,s=>s is "xray" or "relay"?elf:Encoding.UTF8.GetBytes("private-fixture-content"));
            string path=Path.Combine(temp.FullName,"sample.vpspack");string pass=Guid.NewGuid().ToString();
            Assert.Throws<PanelException>(()=>RecoveryPackage.Export(path,pass,pass+"x",files));Assert.False(File.Exists(path));
            var manifest=RecoveryPackage.Export(path,pass,pass,files);
            Assert.Equal(RecoveryPackage.Required.Count,manifest.Files.Length);
            Assert.Throws<PanelException>(()=>RecoveryPackage.Read(path,pass+"x",(_,_)=>Assert.Fail("unauthenticated data")));
            var bytes=File.ReadAllBytes(path);Assert.DoesNotContain("private-fixture-content",Encoding.UTF8.GetString(bytes));
            bytes[^2]^=32;File.WriteAllBytes(path,bytes);
            Assert.Throws<PanelException>(()=>RecoveryPackage.Open(path,pass));
            File.WriteAllBytes(path,bytes[..^20]);Assert.Throws<PanelException>(()=>RecoveryPackage.Open(path,pass));
        }finally{temp.Delete(true);}
    }

    [MigrationFact] public async Task RestoreCleanSystemThenRejectBrokenReplacement()
    {
        string cfg=Environment.GetEnvironmentVariable("VPSPANEL_LOOPBACK_CONFIG")!;
        string assets=Environment.GetEnvironmentVariable("VPSPANEL_MIGRATION_ASSETS")!;
        var folder=Directory.CreateTempSubdirectory("panel-recovery-");
        string secret=Guid.NewGuid().ToString("N");
        try{
            var source=new PanelSession(Path.Combine(folder.FullName,"old"),t=>new OpenSsh(t,cfg));
            var src=new SshTarget("phase2-lab",Service:"migration-source");
            await source.ReadOnly(src,default);
            var host=source.Current!;
            var route=host.Policy.Rules.Reverse().ToArray();
            route[0]=route[0] with{Enabled=false};
            var groups=host.Policy.Groups.Append(new RuleSet("paused-group","暂停组",false,["domain:paused.example"])).ToArray();
            source.SaveRules((host.Policy with{Groups=groups,Rules=route}).WithDefault(RouteAction.Direct).WithFailurePolicy(new(FailureAction.UseDefault)),new(true,9,12));
            var original=source.Current!.Workspace.Items.First();
            source.SaveExit(original with{Aliases=["spare.test"],Limited=true,Up=3,Down=4},false,null);
            string pack=Path.Combine(folder.FullName,"migration.vpspack");
            await source.ExportRecovery(pack,secret,secret,assets,"192.0.2.10",default,"https://check.test:24443/ok");
            var bundle=RecoveryPackage.Open(pack,secret,"source.json","portable.json","plan.json","panel.json");
            var profile=bundle.Json<MigrationProfile>("panel.json");
            var plan=bundle.Json<RelayPlan>("plan.json");
            Assert.Equal(new Bandwidth(true,9,12),profile.Total);
            Assert.Equal(FailureAction.UseDefault,profile.Policy.OnUnavailable.Action);
            Assert.Equal(3,plan.Exits.Length);Assert.Single(profile.Workspace.Items.First().Aliases);
            var raw=RecoveryLayout.Parse(Encoding.UTF8.GetString(bundle.Files["source.json"]));
            var portable=RecoveryLayout.Parse(Encoding.UTF8.GetString(bundle.Files["portable.json"]));
            var srcClient=Assert.Single(RecoveryLayout.Clients(raw));
            var dns=RestoreResult.ForClients("entry.example","192.0.2.20",[srcClient]);Assert.Equal("entry.example",dns.DnsName);Assert.Empty(dns.Links);
            var link=new Uri(srcClient.Link("2001:db8::1"));
            Assert.Equal("vless",link.Scheme);Assert.Equal("2001:db8::1",link.IdnHost);
            Assert.Equal(srcClient.User,link.UserInfo);Assert.Equal(srcClient.Port,link.Port);
            Assert.Contains("pbk="+srcClient.PublicKey,link.Query);
            var mapped=RecoveryLayout.RouteUsers(portable,30001,30002);
            Assert.True(JsonNode.DeepEquals(raw["routing"]!["rules"]![0],mapped["routing"]!["rules"]![0]));
            Assert.True(JsonNode.DeepEquals(raw["inbounds"]![1],mapped["inbounds"]![1]));
            Assert.Equal(RecoveryLayout.ProxyTag,mapped["routing"]!["rules"]![1]!["outboundTag"]!.ToString());

            // Only the synthetic source service is stopped. Its upstream peers stay available.
            ISshTransport sourceSsh=new OpenSsh(src,cfg);
            await sourceSsh.Command("kill \"$(systemctl show --property=MainPID --value migration-source)\"","",default);
            var targetAlias=new SshTarget("phase4-target",Service:"vpspanel-restored-xray");
            ISshTransport targetSsh=new OpenSsh(targetAlias,cfg);
            Assert.Equal("clean",(await targetSsh.Command("test ! -e /var/lib/vpspanel && test ! -e /var/lib/vpspanel-releases && printf clean","",default)).Trim());
            var freshDir=Path.Combine(folder.FullName,"new");
            var targetSession=new PanelSession(freshDir,t=>new OpenSsh(t,cfg));
            await Assert.ThrowsAsync<PanelException>(()=>targetSession.RestoreRecovery(pack,secret+"x",targetAlias,null,"192.0.2.20",default));
            var corrupt=Path.Combine(folder.FullName,"corrupt.vpspack");
            File.Copy(pack,corrupt);
            using(var file=new FileStream(corrupt,FileMode.Open,FileAccess.Write)){file.SetLength(file.Length-1);}
            await Assert.ThrowsAsync<PanelException>(()=>targetSession.RestoreRecovery(corrupt,secret,targetAlias,null,"192.0.2.20",default));
            File.Delete(corrupt);
            Assert.False(File.Exists(Path.Combine(freshDir,"connections.dpapi")));
            Assert.Contains(targetSession.History(),h=>h.Status.Contains("校验失败"));
            Assert.Equal("clean",await targetSsh.Command("test ! -e /var/lib/vpspanel-releases && test -z \"$(find /var/tmp -maxdepth 1 -name 'vpspanel-restore.*' -print -quit)\" && printf clean","",default));

            await using var endpoint=new LoopbackSshEndpoint{DestinationPort=26444};
            int prompts=0;targetSession.ConfirmFingerprint=_=>{prompts++;return true;};
            var result=await targetSession.RestoreRecovery(pack,secret,endpoint.Target,new DirectLogin(new(),endpoint.Secret),"192.0.2.20",default);
            Assert.Equal(1,prompts);Assert.Equal(srcClient.Link("192.0.2.20"),Assert.Single(result.Links));
            var after=targetSession.Current!;
            Assert.Equal(profile.Policy.Rules.Select(r=>(r.Id,r.Enabled)),after.Policy.Rules.Select(r=>(r.Id,r.Enabled)));
            Assert.Equal(original.Secret,after.Workspace.Items.First().Secret);Assert.Equal(profile.Total,after.Total);
            var state=JsonNode.Parse((await targetSsh.ReadConfiguration("/var/lib/vpspanel/committed.json",default)).Json)!;
            Assert.True(JsonNode.DeepEquals(JsonSerializer.SerializeToNode(plan.Policy),state["Plan"]!["Policy"]));
            Assert.True(JsonNode.DeepEquals(JsonSerializer.SerializeToNode(plan.Exits),state["Plan"]!["Exits"]));
            var active=RecoveryLayout.Parse((await targetSsh.ReadConfiguration("/var/lib/vpspanel/xray.json",default)).Json);
            Assert.Equal(srcClient,Assert.Single(RecoveryLayout.Clients(active)));
            Assert.False(after.Policy.Groups.Single(g=>g.Id=="paused-group").Enabled);
            foreach(var member in bundle.Manifest.Files.Where(f=>f.Name=="xray" || f.Name=="relay" || f.Name.EndsWith(".dat"))){
                string name=member.Name.Replace("relay-","rules-geo/");
                string hash=await targetSsh.Command("cd /var/lib/vpspanel && sha256sum -- "+name,"",default);
                Assert.StartsWith(member.Sha256.ToLowerInvariant(),hash);
            }
            var reopened=new PanelSession(freshDir);reopened.Load();
            Assert.Equal(profile.Total,reopened.Current!.Total);
            Assert.True(File.Exists(Path.Combine(reopened.GeoDirectory,"geosite.dat")));
            // Re-open the restored host from a second desk without its previous drafts or Geo cache.
            var otherDesk=new PanelSession(Path.Combine(folder.FullName,"other"),t=>new OpenSsh(t,cfg));
            await otherDesk.ReadOnly(targetAlias,default);
            string again=Path.Combine(folder.FullName,"reexport.vpspack");
            await otherDesk.ExportRecovery(again,secret,secret,assets,"entry.example",default,"https://check.test:24443/ok");
            var second=RecoveryPackage.Open(again,secret);
            foreach(var name in new[]{"source.json","plan.json","geoip.dat","geosite.dat","relay-geoip.dat","relay-geosite.dat","xray","relay"})
                Assert.Equal(bundle.Manifest.Files.Single(f=>f.Name==name).Sha256,second.Manifest.Files.Single(f=>f.Name==name).Sha256);
            string previous=await targetSsh.Command("readlink -f /var/lib/vpspanel","",default);

            var all=RecoveryPackage.Open(pack,secret,RecoveryPackage.Required.ToArray()).Files;
            all["panel.json"]=JsonSerializer.SerializeToUtf8Bytes(profile with{CheckUrl="https://check.test:24443/bad"});
            string bad=Path.Combine(folder.FullName,"failed.vpspack");RecoveryPackage.Export(bad,secret,secret,all);
            var failure=await Assert.ThrowsAsync<PanelException>(()=>targetSession.RestoreRecovery(bad,secret,targetAlias,null,"192.0.2.20",default));
            Assert.Contains("出口健康",failure.Message);
            Assert.Equal(previous,await targetSsh.Command("readlink -f /var/lib/vpspanel","",default));
            await targetSsh.Command("systemctl is-active --quiet vpspanel-restored-xray vpspanel-restored-relay && /var/lib/vpspanel/relay restore-check /var/lib/vpspanel","",default);
            await ExercisePublication(targetSsh,cfg,folder.FullName);
            var activeTarget = new SshTarget("phase4-target",Service:"xray-relay");
            var dnsDesk = new PanelSession(Path.Combine(folder.FullName,"split-source"),t=>new OpenSsh(t,cfg));
            await dnsDesk.ReadOnly(activeTarget,default);
            string[] proxy = ["https://192.0.2.53:24453/dns-query"];
            string[] direct = ["https+local://192.0.2.53:24453/dns-query"];
            dnsDesk.SaveDohResolvers(proxy,direct);
            var splitPack = Path.Combine(folder.FullName,"split.vpspack");
            await dnsDesk.ExportRecovery(splitPack,secret,secret,assets,"entry.example",default);
            var split = RecoveryPackage.Open(splitPack,secret,"plan.json");
            Assert.Equal(direct,split.Json<RelayPlan>("plan.json").BootstrapDohResolvers);
            // This SSH alias is internal to the disposable systemd fixture. Preserve its prior generation.
            await targetSsh.Command("sh -se","""
                test "$(cat /etc/hostname)" = migration-fixture
                systemctl stop vpspanel-relay xray-relay
                mkdir /tmp/prior-panel
                mv /var/lib/vpspanel /var/lib/vpspanel-releases /tmp/prior-panel/
                mv /etc/systemd/system/vpspanel-restored-xray.service /etc/systemd/system/vpspanel-restored-relay.service /tmp/prior-panel/
                systemctl daemon-reload
                test ! -e /var/lib/vpspanel
                test ! -e /var/lib/vpspanel-releases
                """.ReplaceLineEndings("\n")+"\n",default);
            var fresh = new PanelSession(Path.Combine(folder.FullName,"split-clean"),t=>new OpenSsh(t,cfg));
            await fresh.RestoreRecovery(splitPack,secret,targetAlias,null,"192.0.2.20",default);
            await fresh.ReadOnly(targetAlias,default);
            Assert.Equal(proxy,fresh.Current!.ManagedDohResolvers);
            Assert.Equal(direct,fresh.Current.Bootstrap);
            Assert.Empty((await fresh.PreviewProduction(default)).Changes);
            var checkedNode = await fresh.Probe(fresh.Current.Workspace.Items.First(),default);
            Assert.True(checkedNode.Result.Passed,checkedNode.Result.Detail);
            const string relayPid = "systemctl show vpspanel-restored-relay -p MainPID --value";
            var pid = await targetSsh.Command(relayPid,"",default);
            fresh.SaveDohResolvers(null,null);
            var disable = await fresh.PreviewProduction(default);
            Assert.True(disable.RequiresXrayRestart);
            Assert.Contains("已生效",await fresh.ApplyProduction(disable,default));
            await fresh.ReadOnly(targetAlias,default);
            Assert.Null(fresh.Current!.ManagedDohResolvers);
            await targetSsh.Command("sh -se","""
                test "$(cat /etc/hostname)" = migration-fixture
                install -d -m 0755 /var/lib/vpspanel/dns-assets /etc/systemd/system/vpspanel-restored-xray.service.d
                cp /var/lib/vpspanel/geoip.dat /var/lib/vpspanel/geosite.dat /var/lib/vpspanel/dns-assets/
                printf '\170\001' >> /var/lib/vpspanel/dns-assets/geoip.dat
                printf '%s\n' '[Service]' 'BindReadOnlyPaths=/var/lib/vpspanel/dns-assets:/run/vpspanel-dns' 'Environment=XRAY_LOCATION_ASSET=/run/vpspanel-dns' > /etc/systemd/system/vpspanel-restored-xray.service.d/80-dns.conf
                systemctl daemon-reload
                """.ReplaceLineEndings("\n")+"\n",default);
            fresh.SaveDohResolvers(proxy,direct);
            var enable = await fresh.PreviewProduction(default);
            Assert.True(enable.RequiresXrayRestart);
            Assert.Contains("已生效",await fresh.ApplyProduction(enable,default));
            Assert.Equal(pid,await targetSsh.Command(relayPid,"",default));
            var reexport=Path.Combine(folder.FullName,"mounted-geo.vpspack");
            await fresh.ExportRecovery(reexport,secret,secret,assets,"entry.example",default);
            var recovered=RecoveryPackage.Open(reexport,secret,"geoip.dat");
            var actual=await targetSsh.Command("sha256sum /var/lib/vpspanel/dns-assets/geoip.dat","",default);
            Assert.Equal(actual.Split(' ')[0],Convert.ToHexStringLower(SHA256.HashData(recovered.Files["geoip.dat"])));
            var accessCheck=await targetSsh.Command("sh -se","""
                mkdir -p /run/systemd/system
                cat > /run/systemd/system/vpspanel-asset-check.service <<'UNIT'
                [Service]
                Type=oneshot
                RemainAfterExit=yes
                DynamicUser=yes
                BindReadOnlyPaths=/var/lib/vpspanel/dns-assets:/run/vpspanel-dns
                ExecStart=/bin/sh -ec 'test "$$(id -u)" != 0 || exit 81; test -r /run/vpspanel-dns/vpspanel-bootstrap.dat || exit 82; test ! -r /var/lib/vpspanel/committed.json || exit 83'
                UNIT
                systemctl daemon-reload
                if systemctl start vpspanel-asset-check; then echo verified; else systemctl show vpspanel-asset-check -p ExecMainStatus -p Result; fi
                """.ReplaceLineEndings("\n")+"\n",default);
            Assert.Equal("verified",accessCheck.Trim());
        }finally{folder.Delete(true);}
    }

    private static async Task ExercisePublication(ISshTransport ssh,string cfg,string local)
    {
        // Reproduce the takeover unit and its credential drop-in inside the disposable systemd target.
        await ssh.Command("sh -se", """
            systemctl stop vpspanel-restored-relay vpspanel-restored-xray
            mkdir -p /etc/xray-relay /etc/systemd/system/xray-relay.service.d
            cp /var/lib/vpspanel/portable.json /etc/xray-relay/config.json
            cat >/etc/systemd/system/xray-relay.service <<'UNIT'
            [Service]
            LoadCredential=config.json:/etc/xray-relay/config.json
            ExecStart=/var/lib/vpspanel/xray run -c %d/config.json
            UNIT
            cat >/etc/systemd/system/xray-relay.service.d/panel.conf <<'UNIT'
            [Service]
            LoadCredential=
            LoadCredential=config.json:/var/lib/vpspanel/xray.json
            UNIT
            sed 's/vpspanel-restored-xray/xray-relay/g' /etc/systemd/system/vpspanel-restored-relay.service >/etc/systemd/system/vpspanel-relay.service
            systemctl daemon-reload
            systemctl start xray-relay vpspanel-relay
            """.ReplaceLineEndings("\n")+"\n",default);
        var target=new SshTarget("phase4-target",Service:"xray-relay");
        PanelSession Desk(string name)=>new(Path.Combine(local,name),t=>new OpenSsh(t,cfg));
        var panel=Desk("production");await panel.ReadOnly(target,default);
        Assert.Empty((await panel.PreviewProduction(default)).Changes);
        Assert.DoesNotContain(panel.Current!.Workspace.Items,e=>e.Id.StartsWith("vp3-"));
        string unitBefore=await ssh.Command("systemctl show xray-relay -p InvocationID --value","",default);
        string originalHash=await ssh.Command("sha256sum /etc/xray-relay/config.json","",default);
        var old=panel.Current.Workspace.Items.First(e=>e.Protocol=="HY2");
        var candidate=old with{Host="spare.test",Aliases=[old.Host],Limited=true,Up=7,Down=8};
        var check=await panel.Probe(candidate,default);Assert.True(check.Result.Passed,check.Result.Detail);
        panel.SaveExit(candidate,false,check);
        var additional=candidate with{Id="extra",Name="额外出口"};
        panel.SaveExit(additional,true,await panel.Probe(additional,default));
        var group=new RuleSet("extra-set","测试集",true,["full:isolated.example"]);
        var rule=new SiteRule("extra-rule","测试绑定",true,group.Id,[],RouteAction.Fixed,additional.Id);
        var policy=panel.Current.Policy;panel.SaveRules(new([..policy.Groups,group],[rule,..policy.Rules]),new(true,5,6));
        var preview=await panel.PreviewProduction(default);
        Assert.Contains(preview.Changes,c=>c.Contains("连接域名")&&c.Contains("spare.test"));
        Assert.DoesNotContain(preview.Changes,c=>c.Contains(old.Secret));
        var competitor=Desk("second");await competitor.ReadOnly(target,default);
        competitor.SaveRules(competitor.Current!.Policy,new(true,10,11));
        var obsolete=await competitor.PreviewProduction(default);
        // The candidate passed the desktop probe. Force it to fail the Relay-side probe during publication.
        await ssh.Command("cp /etc/hosts /tmp/publication-hosts && sed 's/ spare.test//g' /tmp/publication-hosts >/etc/hosts && echo '127.0.0.8 spare.test' >>/etc/hosts","",default);
        try{
            Assert.Contains("上一版",await panel.ApplyProduction(preview,default));
        }finally{await ssh.Command("cat /tmp/publication-hosts >/etc/hosts","",default);}
        await panel.ReadOnly(target,default);
        Assert.Contains("已生效",await panel.ApplyProduction(await panel.PreviewProduction(default),default));
        var stale=await Assert.ThrowsAsync<PanelException>(()=>competitor.ApplyProduction(obsolete,default));Assert.Contains("预览",stale.Message);
        var reopened=Desk("production");reopened.Load();
        Assert.Contains("已生效",await reopened.CheckPublication(default));
        await reopened.ReadOnly(target,default);Assert.Empty((await reopened.PreviewProduction(default)).Changes);
        Assert.Equal(candidate.Host,reopened.Current!.Workspace.Items.Single(e=>e.Id==old.Id).Host);
        Assert.Equal(new Bandwidth(true,5,6),reopened.Current.Total);
        Assert.Equal(rule.Id,reopened.Current.Policy.Rules[0].Id);
        Assert.Throws<PanelException>(()=>reopened.DeleteExit(additional.Id));
        reopened.SaveRules(reopened.Current.Policy.RemoveGroup(group.Id,false).WithDefault(RouteAction.Fixed,additional.Id)
            .WithFailurePolicy(new(FailureAction.Fixed,additional.Id)),new());
        Assert.Contains("默认出口",Assert.Throws<PanelException>(()=>reopened.DeleteExit(additional.Id)).Message);
        var changedDefault=await reopened.PreviewProduction(default);
        Assert.Contains(changedDefault.Changes,c=>c.Contains("出口不可用时") && c.Contains(additional.Id));
        Assert.Contains(changedDefault.Changes,c=>c.Contains("默认动作") && c.Contains(additional.Id));
        Assert.Contains("已生效",await reopened.ApplyProduction(changedDefault,default));
        await reopened.ReadOnly(target,default);
        Assert.Equal(additional.Id,reopened.Current!.Policy.DefaultRule!.Exit);
        reopened.SaveRules(reopened.Current.Policy.WithDefault(RouteAction.Auto),new());
        Assert.Contains("故障策略",Assert.Throws<PanelException>(()=>reopened.DeleteExit(additional.Id)).Message);
        reopened.SaveRules(reopened.Current.Policy.WithFailurePolicy(new(FailureAction.Reject)),new());
        reopened.DeleteExit(additional.Id);
        Assert.Contains("删除出口",await reopened.ApplyProduction(await reopened.PreviewProduction(default),default));
        await reopened.ReadOnly(target,default);Assert.DoesNotContain(reopened.Current!.Workspace.Items,e=>e.Id==additional.Id);
        Assert.Equal(unitBefore,await ssh.Command("systemctl show xray-relay -p InvocationID --value","",default));
        Assert.Equal(originalHash,await ssh.Command("sha256sum /etc/xray-relay/config.json","",default));
    }
}
public sealed class MigrationFactAttribute:FactAttribute
{
    public MigrationFactAttribute(){if(string.IsNullOrEmpty(Environment.GetEnvironmentVariable("VPSPANEL_MIGRATION_ASSETS")))Skip="需要隔离的 systemd 迁移目标。";}
}
