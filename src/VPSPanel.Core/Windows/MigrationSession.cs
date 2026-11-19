using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;

namespace VPSPanel.Core;

public sealed record MigrationEvent(DateTimeOffset Time,string Operation,string Status);
public sealed record RestoreResult(string? DnsName,string[] Links)
{
    public static RestoreResult ForClients(string original,string destination,IEnumerable<RecoveryClient> users)=>
        IPAddress.TryParse(original,out _)?new(null,users.Select(c=>c.Link(destination)).ToArray()):new(original,[]);
}
public sealed partial class PanelSession
{
    public string BackupDirectory=>Path.Combine(directory,"backups");
    private static readonly string[] InstallationFiles=["xray","relay","geoip.dat","geosite.dat"];
    public string AssetDirectory
    {
        get
        {
            string bundled=Path.Combine(AppContext.BaseDirectory,"recovery-assets");
            return File.Exists(Path.Combine(bundled,"assets.json")) && InstallationFiles.All(n=>File.Exists(Path.Combine(bundled,n)))
                ? bundled : Path.Combine(LocalSettings.DataDirectory,"recovery-assets");
        }
    }

    private sealed class MaterialException(string message):PanelException(message);
    private static async Task<byte[]> ReadInstallationFile(string folder,string name,CancellationToken token)
    {
        try{return await File.ReadAllBytesAsync(Path.Combine(folder,name),token);}
        catch(Exception ex) when(ex is FileNotFoundException or DirectoryNotFoundException){
            throw new MaterialException($"离线安装材料目录缺少 {name}。请选择包含清单和安装文件的目录。");
        }
        catch(UnauthorizedAccessException){throw new MaterialException($"无法读取离线安装材料 {name}，请检查目录权限。");}
    }
    private string HistoryFile=>Path.Combine(directory,"migration-history.json");
    public MigrationEvent[] History()=>File.Exists(HistoryFile)?JsonSerializer.Deserialize<MigrationEvent[]>(File.ReadAllText(HistoryFile))??[]:[];
    private void Record(string action,string status){
        Directory.CreateDirectory(directory);
        string temp=HistoryFile+"."+Guid.NewGuid().ToString("N");
        try{File.WriteAllText(temp,JsonSerializer.Serialize(History().Prepend(new(DateTimeOffset.Now,action,status)).Take(30)));
            File.Move(temp,HistoryFile,true);}finally{File.Delete(temp);}
    }
    private static byte[] JsonBytes<T>(T value)=>JsonSerializer.SerializeToUtf8Bytes(value);
    private static async Task EmbedCertificates(JsonNode? node,ISshTransport? transport,string cwd,CancellationToken ct)
    {
        if(node is JsonArray a){foreach(var child in a)await EmbedCertificates(child,transport,cwd,ct);return;}
        if(node is not JsonObject o)return;
        foreach(var (key,child) in o.ToList()){
            if(key is "certificateFile" or "keyFile" && child is JsonValue){
                if(transport==null)throw new PanelException("缺少源主机上的 TLS 文件。");
                string path=child.ToString();
                if(!path.StartsWith('/'))path=cwd.TrimEnd('/')+"/"+path;
                if(path.Any(char.IsControl))throw new PanelException("源 TLS 文件路径无效。");
                var (pem,_)=await transport.ReadConfiguration(path,ct);
                string type=key=="certificateFile"?"CERTIFICATE":"PRIVATE KEY";
                if(!pem.Contains(type+"-----") || pem.Contains("OPENSSH PRIVATE KEY"))throw new PanelException("引用文件不是受支持的 Xray TLS PEM。");
                o.Remove(key);o[key=="certificateFile"?"certificate":"key"]=JsonSerializer.SerializeToNode(pem.Trim().Split('\n').Select(l=>l.TrimEnd('\r')));
            }else await EmbedCertificates(child,transport,cwd,ct);
        }
    }
    private string DemoSource(ManagedHost host)
    {
        string file=Path.Combine(directory,"demo-ingress.dpapi");
        if(File.Exists(file))return Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(file),null,DataProtectionScope.CurrentUser));
        var key=new X25519PrivateKeyParameters(RandomNumberGenerator.GetBytes(32),0);
        var id=Guid.NewGuid().ToString();
        var realitySettings=new JsonObject{
            ["privateKey"]=Convert.ToBase64String(key.GetEncoded()).TrimEnd('=').Replace('+','-').Replace('/','_'),
            ["target"]="demo.invalid:443",["serverNames"]=new JsonArray("demo.invalid"),["shortIds"]=new JsonArray("1234")};
        var json=JsonSerializer.Serialize(new{
            inbounds=new[]{new{tag="demo-user",listen="127.0.0.1",port=24690,protocol="vless",settings=new{decryption="none",clients=new[]{new{id}}},
                streamSettings=new{network="raw",security="reality",realitySettings}}},
            outbounds=host.Workspace.Items.Select(e=>e.ToOutbound()).Append(new JsonObject{["protocol"]="freedom",["tag"]="D"}),
            routing=new{rules=Array.Empty<object>()}
        });
        string temp=file+"."+Guid.NewGuid().ToString("N");
        try{File.WriteAllBytes(temp,ProtectedData.Protect(Encoding.UTF8.GetBytes(json),null,DataProtectionScope.CurrentUser));File.Move(temp,file,false);}
        catch(IOException) when(File.Exists(file)){return DemoSource(host);}finally{File.Delete(temp);}
        return json;
    }
    private static async Task<Dictionary<string,string>> SourceAssets(ISshTransport transport,ManagedHost host,CancellationToken ct)
    {
        const string lookup="""
            import os,sys,json,subprocess
            pid=int(subprocess.check_output(["systemctl","show","--property=MainPID","--value",sys.argv[1]]))
            env=dict(x.split(b"=",1) for x in open("/proc/%d/environ"%pid,"rb").read().split(b"\0") if b"=" in x)
            binary=os.readlink("/proc/%d/exe"%pid)
            first=os.fsdecode(env.get(b"xray.location.asset",env.get(b"XRAY_LOCATION_ASSET",os.fsencode(os.path.dirname(binary)))))
            paths={"xray":binary}
            for name in ("geoip.dat","geosite.dat"):
                for parent in (first,"/usr/local/share/xray","/usr/share/xray","/opt/share/xray"):
                    path=os.path.join(os.readlink("/proc/%d/cwd"%pid),parent,name)
                    if os.path.isfile(path): paths[name]=path;break
            if sys.argv[1]=="vpspanel-restored-xray":
                for name in ("geoip.dat","geosite.dat"):
                    path="/var/lib/vpspanel/rules-geo/"+name
                    if os.path.isfile(path):paths["relay-"+name]=path
            print(json.dumps(paths))
            """;
        return JsonSerializer.Deserialize<Dictionary<string,string>>(await transport.Command("python3 - "+OpenSsh.Quote(host.Target.Service),lookup.ReplaceLineEndings("\n"),ct))??throw new InvalidDataException();
    }
    public async Task<PackageManifest> ExportRecovery(string path,string password,string confirmation,string assets,string clientHost,CancellationToken ct,
        string? checkUrl=null,IProgress<string>? progress=null)
    {
        if(password!=confirmation || string.IsNullOrEmpty(password))throw new PanelException("请输入相同的备份口令并再次确认。");
        if(!ExitProfile.ValidHost(clientHost))throw new PanelException("请填写客户端实际使用的入口 IP 或自有域名。");
        var h=Current??throw new PanelException("先在首页读取源主机。");
        var plan=BuildRelayPlan();string geoDirectory=GeoDirectory;
        progress?.Report("正在读取源配置和入口身份…");
        var transport=IsDemo?null:RelayTransport(h);
        try{
            string raw,portableRaw;
            if(transport==null)raw=portableRaw=DemoSource(h);
            else if(h.Target.Service=="vpspanel-restored-xray" && h.ConfigPath=="/var/lib/vpspanel/xray.json"){
                raw=(await transport.ReadConfiguration("/var/lib/vpspanel/source.json",ct)).Json;
                portableRaw=(await transport.ReadConfiguration("/var/lib/vpspanel/portable.json",ct)).Json;
            }else if(h.ManagedRevision!=null){
                var state=await PublicationRemote.Inspect(transport,h.Target,ct);
                if(state.Revision!=h.ManagedRevision)throw new PanelException("部署方案已变化，请重新读取主机再导出。");
                raw=portableRaw=(await transport.ReadConfiguration(state.Source,ct)).Json;
            }else{
                var live=await new RemoteInspection(transport).Read(h.Target,ct);
                if(live.Version!=RecoveryPackage.KernelVersion || live.Snapshot.Digest!=h.Workspace.Snapshot?.Digest)
                    throw new PanelException("活动配置或内核已变化，请先刷新只读快照再导出。");
                raw=portableRaw=live.RawJson;
            }
            var portable=RecoveryLayout.Parse(portableRaw);
            _=RecoveryLayout.Clients(portable);
            var profileNode=JsonSerializer.SerializeToNode(new MigrationProfile(h.Workspace,h.Policy,h.Total??new(),clientHost,checkUrl??h.CheckUrl??"https://www.gstatic.com/generate_204"))!;
            var planNode=JsonSerializer.SerializeToNode(plan)!;
            foreach(var node in new[]{portable,profileNode,planNode})await EmbedCertificates(node,transport,h.WorkingDirectory,ct);
            var items=new Dictionary<string,byte[]>{
                ["source.json"]=Encoding.UTF8.GetBytes(raw),["portable.json"]=JsonBytes(portable),["panel.json"]=JsonBytes(profileNode),["plan.json"]=JsonBytes(planNode)};
            progress?.Report("正在核对内核、出口凭据和地理规则数据…");
            Dictionary<string,string> hashes;
            var manifestBytes=await ReadInstallationFile(assets,"assets.json",ct);
            try{hashes=JsonSerializer.Deserialize<Dictionary<string,string>>(manifestBytes)??throw new JsonException();}
            catch(JsonException){throw new MaterialException("离线安装材料清单 assets.json 格式无效，请重新准备材料。");}
            if(plan.Policy.DefaultRule!=null && (!hashes.TryGetValue("relay-configurable-default",out var capable) ||
                !hashes.TryGetValue("relay",out var relayHash) || !string.Equals(capable,relayHash,StringComparison.OrdinalIgnoreCase)))
                throw new MaterialException("此默认动作需要支持自定义默认分流的 Relay，请选择新版离线安装材料。");
            if(plan.Policy.OnUnavailable.Action!=FailureAction.Reject && (!hashes.TryGetValue("relay-exit-failover",out var failoverHash) ||
                !hashes.TryGetValue("relay",out var bundledHash) || !string.Equals(failoverHash,bundledHash,StringComparison.OrdinalIgnoreCase)))
                throw new MaterialException("此故障策略需要支持出口故障切换的 Relay，请选择新版离线安装材料。");
            var sourceFiles=transport==null?new Dictionary<string,string>():await SourceAssets(transport,h,ct);
            if(portableRaw.Contains("\"ext:",StringComparison.OrdinalIgnoreCase)||portableRaw.Contains("\"ext-ip:",StringComparison.OrdinalIgnoreCase))
                throw new PanelException("源配置引用了自定义外部 Geo 文件，请先将该依赖纳入迁移清单。");
            foreach(var name in InstallationFiles){
                byte[] data=await ReadInstallationFile(assets,name,ct);
                if(!hashes.TryGetValue(name,out var expected)||!Convert.ToHexString(SHA256.HashData(data)).Equals(expected,StringComparison.OrdinalIgnoreCase))
                    throw new MaterialException($"离线安装材料 {name} 的 SHA-256 与清单不一致，请重新准备材料。");
                if(sourceFiles.TryGetValue(name,out var remotePath)){
                    string digest=(await transport!.Command("sha256sum -- "+OpenSsh.Quote(remotePath),"",ct)).Split(' ')[0];
                    if(!digest.Equals(expected,StringComparison.OrdinalIgnoreCase)){
                        data=await ((IFileUpload)transport).ReadAsset(remotePath,ct);
                        if(!Convert.ToHexString(SHA256.HashData(data)).Equals(digest,StringComparison.OrdinalIgnoreCase))
                            throw new PanelException("读取期间源安装材料发生变化，请重新导出。");
                    }
                }else if(transport!=null && name.EndsWith(".dat") && portableRaw.Contains(name[..^4]+":",StringComparison.OrdinalIgnoreCase))
                    throw new PanelException("源配置引用的地理规则数据无法定位。");
                if(name.EndsWith(".dat")){
                    byte[] relayGeo=data;
                    var localGeo=Path.Combine(geoDirectory,name);
                    if(File.Exists(localGeo))relayGeo=await File.ReadAllBytesAsync(localGeo,ct);
                    else if(sourceFiles.TryGetValue("relay-"+name,out string? remoteGeo)){
                        var digest=(await transport!.Command("sha256sum -- "+OpenSsh.Quote(remoteGeo),"",ct)).Split(' ')[0];
                        if(!Convert.ToHexString(SHA256.HashData(data)).Equals(digest,StringComparison.OrdinalIgnoreCase))
                            relayGeo=await ((IFileUpload)transport).ReadAsset(remoteGeo,ct);
                        if(!Convert.ToHexString(SHA256.HashData(relayGeo)).Equals(digest,StringComparison.OrdinalIgnoreCase))
                            throw new PanelException("读取期间 Relay 地理数据发生变化，请重新导出。");
                    }
                    items.Add("relay-"+name,relayGeo);
                }
                items.Add(name,data);
            }
            if(h.Version!=RecoveryPackage.KernelVersion)throw new PanelException("源主机 Xray 版本与恢复工具不兼容。");
            ct.ThrowIfCancellationRequested();
            progress?.Report("正在加密并重新打开恢复包，逐项核对摘要…");
            var result=await Task.Run(()=>RecoveryPackage.Export(path,password,confirmation,items),ct);
            Record("导出","认证及全部文件摘要通过");return result;
        }catch(MaterialException ex){Record("导出",ex.Message);throw;}
        catch{Record("导出","未完成");throw;}
    }

    public async Task<RestoreResult> RestoreRecovery(string package,string password,SshTarget target,DirectLogin? direct,string newAddress,CancellationToken token,IProgress<string>? progress=null)
    {
        if(IsDemo)throw new PanelException("离线演示支持导出和校验；恢复请在独立的目标环境中操作。");
        // Authentication and the complete member hash pass happen before creating any SSH connection.
        using var locked=File.Open(package,FileMode.Open,FileAccess.Read,FileShare.Read);
        OpenPackage restored;
        try{restored=await Task.Run(()=>RecoveryPackage.Open(package,password,"relay","panel.json","portable.json","relay-geoip.dat","relay-geosite.dat"),token);}
        catch(PanelException){Record("恢复","恢复包认证或完整性校验失败");throw;}
        var profile=restored.Json<MigrationProfile>("panel.json");
        var clients=RecoveryLayout.Clients(RecoveryLayout.Parse(Encoding.UTF8.GetString(restored.Files["portable.json"])));
        if(!ExitProfile.ValidHost(newAddress))throw new PanelException("请填写新主机对客户端公开的地址。");
        target.Validate();
        if(direct!=null && (target.User.Length==0||!ExitProfile.ValidHost(target.Host)))throw new PanelException("请填写直连用户名和主机地址。");
        new ProtectedTerms(Path.Combine(directory,"guard")).Register(target.Host);
        ISshTransport transport=direct==null?sshFactory?.Invoke(target)??new OpenSsh(target):new DirectSsh(target,direct,access,ConfirmFingerprint);
        string? stage=null;bool dispatched=false;string receipt="";
        var local=Directory.CreateTempSubdirectory("vpspanel-installer-");
        try{
            string arch=(await transport.Command("set -eu; test \"$(uname -s)\" = Linux; test \"$(id -u)\" = 0; test -d /run/systemd/system; for t in systemctl systemd-run sha256sum python3 flock timeout; do command -v \"$t\" >/dev/null; done; uname -m","",token)).Trim();
            if(arch!=restored.Manifest.Architecture)throw new PanelException("目标架构与恢复包不匹配。");
            var payloadLength=restored.Manifest.Files.Sum(f=>f.Length);
            var scratchSize=locked.Length+restored.Files["relay"].LongLength+payloadLength+64L*1024*1024;
            var capacity=await transport.Command("command -v ss >/dev/null && python3 -","""
                import os,sys
                for path,required in (("/var/tmp",SCRATCH),("/var/lib",RELEASE)):
                    disk=os.statvfs(path)
                    if disk.f_frsize*disk.f_bavail<required:
                        print("full");sys.exit(0)
                print("ready")
                """.Replace("SCRATCH",scratchSize.ToString(System.Globalization.CultureInfo.InvariantCulture)).Replace("RELEASE",payloadLength.ToString(System.Globalization.CultureInfo.InvariantCulture)).ReplaceLineEndings("\n"),token);
            if(capacity.Trim()!="ready")throw new PanelException("目标暂存区或服务目录的可用空间不足。");
            progress?.Report("环境检查通过，正在通过 SFTP 上传加密包及安装件…");
            string candidate=(await transport.Command("umask 077; mktemp -d /var/tmp/vpspanel-restore.XXXXXXXXXX","",token)).Trim();
            if(!Regex.IsMatch(candidate,@"\A/var/tmp/vpspanel-restore\.[a-zA-Z0-9]{10}\z"))throw new PanelException("目标暂存目录无效。");
            stage=candidate;
            string bootstrap=Path.Combine(local.FullName,"relay");
            await File.WriteAllBytesAsync(bootstrap,restored.Files["relay"],token);
            var uploader=(IFileUpload)transport;
            await uploader.Upload(package,stage+"/backup",token);
            await uploader.Upload(bootstrap,stage+"/relay",token);
            var relayHash=restored.Manifest.Files.Single(f=>f.Name=="relay").Sha256.ToLowerInvariant();
            string cmd=$"cd {stage} && umask 077 && echo '{relayHash}  relay' | sha256sum -c --status && chmod 700 relay && test \"$(./relay version)\" = 'VPSPanel.Relay {RecoveryPackage.RelayVersion}' && mkdir -m 700 release && ./relay restore-unpack backup release";
            progress?.Report("传输完成，正在校验、解包和静态检查候选配置…");
            await transport.Command(cmd,password,token);
            await using var resource=typeof(PanelSession).Assembly.GetManifestResourceStream("VPSPanel.install.sh")!;
            using var reader=new StreamReader(resource);string script=(await reader.ReadToEndAsync(token)).ReplaceLineEndings("\n");
            await transport.Command("umask 077; cat > "+stage+"/install.sh",script,token);
            string unit=Path.GetFileName(stage).Replace('.','-');
            dispatched=true;
            await transport.Command($"systemd-run --quiet --collect --unit={unit} /bin/sh {stage}/install.sh {stage}","",token);
            progress?.Report("目标机独立执行启动、出口健康和真实入口请求检查…");
            string result="";
            for(int i=0;i<210;i++){
                await Task.Delay(1000,token);
                result=(await transport.Command($"cat {stage}/result 2>/dev/null || true","",token)).Trim();
                if(result!="")break;
            }
            receipt=result;
            if(result!="verified")throw new PanelException(result switch{
                "rejected-prepare"=>"目标已有非面板服务或目录冲突，恢复已终止。","rejected-static"=>"候选配置静态校验失败。",
                "rejected-activation"=>"服务启动失败，已恢复之前的目标状态。","rejected-exits"=>"候选出口健康验证失败，已恢复之前的目标状态。",
                "rejected-ingress"=>"候选入口代理请求失败，已恢复之前的目标状态。","busy"=>"目标机正在执行其他恢复。",
                "rollback-error"=>"目标机恢复旧服务时报告故障，请检查原服务。",
                _=>"尚未收到目标机完成回执，请核对恢复历史和目标服务。"});
            var dst=target with{Service="vpspanel-restored-xray"};
            string key=(direct==null?"":"direct:")+JsonSerializer.Serialize(dst);
            var geoSet=Guid.NewGuid();string geo=Path.Combine(directory,"geo",geoSet.ToString("N"));Directory.CreateDirectory(geo);
            foreach(var name in new[]{"geoip.dat","geosite.dat"})File.WriteAllBytes(Path.Combine(geo,name),restored.Files["relay-"+name]);
            Write(key,new(dst,restored.Manifest.XrayVersion,"/var/lib/vpspanel/xray","/var/lib/vpspanel/xray.json",DateTimeOffset.Now,true,
                profile.Workspace,"/var/lib/vpspanel",direct?.Profile,profile.Policy,profile.Total,geoSet));
            activeLogin=direct==null?null:(dst,direct);
            Changed?.Invoke();
            Record("恢复","入口、启用出口及服务已验证");
            return RestoreResult.ForClients(profile.ClientHost,newAddress,clients);
        }catch{
            var status=receipt switch{
                "verified"=>"目标已验证；本机资料保存未完成","rollback-error"=>"目标回滚异常",
                "rejected-activation" or "rejected-exits" or "rejected-ingress"=>"候选验证失败，目标已还原",
                "busy"=>"目标已有恢复任务","rejected-prepare" or "rejected-static"=>"目标准备或静态检查未通过",
                _ when dispatched=>"待核对目标回执 "+Path.GetFileName(stage)+"/result",_=>"校验或准备未完成"};
            Record("恢复",status);throw;
        }
        finally{
            local.Delete(true);
            if(stage!=null && !dispatched){
                try{await transport.Command("rm -rf -- "+stage,"",CancellationToken.None);}catch(PanelException){}
            }
        }
    }
}
