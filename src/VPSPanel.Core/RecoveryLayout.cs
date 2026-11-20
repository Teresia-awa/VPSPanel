using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Parameters;

namespace VPSPanel.Core;

public sealed record MigrationProfile(ExitWorkspace Workspace, RoutingPolicy Policy, Bandwidth Total, string ClientHost, string CheckUrl)
{
    public int? SourceRelayPort { get; init; }
}
public sealed record RecoveryClient(string Tag, string User, int Port, string Flow, string Sni, string PublicKey, string ShortId, string Listen)
{
    public string Link(string host)
    {
        if(!ExitProfile.ValidHost(host))throw new PanelException("请填写新入口对客户端公开的 IP 或域名。");
        var endpoint=new UriBuilder("vless",host,Port){
            UserName=User,Query=$"encryption=none&security=reality&type=tcp&fp=chrome&sni={Uri.EscapeDataString(Sni)}&pbk={PublicKey}&sid={ShortId}&flow={Uri.EscapeDataString(Flow)}",
            Fragment=Uri.EscapeDataString(Tag)};
        return endpoint.Uri.AbsoluteUri;
    }
    public JsonObject ProbeOutbound() => new ExitProfile{Id="verify",Protocol="VLESS REALITY",Host=Listen,Port=Port,Secret=User,
        Sni=Sni,PublicKey=PublicKey,ShortId=ShortId,Flow=Flow,Fingerprint="chrome"}.ToOutbound();
}
public static class RecoveryLayout
{
    public const string ProxyTag="vpspanel-user-relay";
    public const string ApiTag="vpspanel-control";
    public const string EncryptedDnsTag="vpspanel-encrypted-dns";
    public const string DnsGenerationTag=EncryptedDnsTag+"-generation";
    public const string DnsUnmatchedTag=EncryptedDnsTag+"-unmatched";
    public static JsonObject Parse(string text) => JsonNode.Parse(text,documentOptions:new(){CommentHandling=JsonCommentHandling.Skip,AllowTrailingCommas=true})!.AsObject();
    public static List<RecoveryClient> Clients(JsonObject config)
    {
        var clients=new List<RecoveryClient>();
        foreach(var node in config["inbounds"]!.AsArray()){
            var stream=node?["streamSettings"];
            if(node?["protocol"]?.ToString()!="vless" || stream?["security"]?.ToString()!="reality")continue;
            var reality=stream["realitySettings"];
            var tag=node["tag"]?.ToString();
            if(string.IsNullOrEmpty(tag) || stream["network"]?.ToString() is not (null or "raw" or "tcp") ||
                reality?["mldsa65Seed"]!=null || node["settings"]?["decryption"]?.ToString() is not (null or "none"))
                throw new PanelException("当前自动恢复支持有标签的 TCP VLESS REALITY 常规身份。请核对传输与认证参数。");
            string key=reality?["privateKey"]?.ToString()??"";
            var bytes=Convert.FromBase64String(key.Replace('-','+').Replace('_','/').PadRight(44,'='));
            var pub=Convert.ToBase64String(new X25519PrivateKeyParameters(bytes,0).GeneratePublicKey().GetEncoded()).TrimEnd('=').Replace('+','-').Replace('/','_');
            var sni=reality!["serverNames"]?.AsArray().FirstOrDefault()?.ToString();
            string? sid=reality["shortIds"]?.AsArray().FirstOrDefault()?.ToString();
            var users=node["settings"]?["clients"]?.AsArray()??node["settings"]?["users"]?.AsArray();
            if(!int.TryParse(node["port"]?.ToString(),out int port)||port is <1 or >65535||string.IsNullOrEmpty(sni)||sid==null||users==null||users.Count==0)
                throw new PanelException("入口缺少可恢复的用户、端口、SNI 或 Short ID。");
            string listen=node["listen"]?.ToString() switch {null or "" or "0.0.0.0"=>"127.0.0.1","::"=>"::1",var v=>v};
            foreach(var u in users){
                string id=u?["id"]?.ToString()??"";
                if(!Guid.TryParse(id,out _))throw new PanelException("当前入口用户标识需要进一步核对。");
                clients.Add(new(tag,id,port,u?["flow"]?.ToString()??"",sni,pub,sid,listen));
            }
        }
        if(clients.Count==0)throw new PanelException("未找到可验证的 VLESS REALITY 用户入口。");
        return clients;
    }
    private static JsonNode[] RelayServers(JsonObject root,int relayPort)
    {
        var servers=new List<JsonNode>();
        foreach(var outbound in root["outbounds"]!.AsArray()){
            if(outbound?["protocol"]?.ToString()!="socks")continue;
            var settings=outbound["settings"];
            IEnumerable<JsonNode?> endpoints=settings?["servers"] is JsonArray list ? list : [settings];
            foreach(var endpoint in endpoints){
                if(endpoint?["address"]?.ToString() is "127.0.0.1" or "localhost" &&
                    int.TryParse(endpoint["port"]?.ToString(),out int port) && port==relayPort)
                    servers.Add(endpoint);
            }
        }
        if(relayPort is <1 or >65535 || servers.Count==0)
            throw new PanelException("无法确认托管配置中的 Relay 调度出口。");
        return servers.ToArray();
    }

    public static JsonObject ExportManaged(JsonObject managed, IReadOnlySet<string> lanes, bool followHealthyDns,int relayPort)
    {
        var root=managed.DeepClone().AsObject();
        if(root["api"]?["tag"]?.ToString()!=ApiTag)throw new PanelException("无法确认托管配置的管理 API。");
        // Strip regenerated handlers by committed identity. All other entries keep their order and settings.
        void RemoveGenerated(JsonArray entries,string key,params string[] dnsTags)
        {
            foreach(var entry in entries.ToArray()){
                string tag=entry?[key]?.ToString()??"";
                if(lanes.Contains(tag) || followHealthyDns && dnsTags.Contains(tag))entries.Remove(entry);
            }
        }
        RemoveGenerated(root["inbounds"]!.AsArray(),"tag");
        RemoveGenerated(root["outbounds"]!.AsArray(),"tag",EncryptedDnsTag);
        RemoveGenerated(root["routing"]!["rules"]!.AsArray(),"ruleTag",EncryptedDnsTag,DnsGenerationTag,DnsUnmatchedTag);
        _=RelayServers(root,relayPort);
        return root;
    }

    public static JsonObject RouteUsers(JsonObject source,int apiPort,int relayPort,int? sourceRelayPort=null)
    {
        var root=source.DeepClone().AsObject();
        if(sourceRelayPort is int previousPort){
            if(root["api"]?["tag"]?.ToString()!=ApiTag)throw new PanelException("恢复包中的托管入口元数据无效。");
            root["api"]!["listen"]="127.0.0.1:"+apiPort;
            foreach(var server in RelayServers(root,previousPort))server["port"]=relayPort;
            return root;
        }
        var tags=Clients(root).Select(c=>c.Tag).Distinct().ToHashSet();
        var outs=root["outbounds"]!.AsArray();
        if(root["api"]!=null || outs.Any(o=>o?["tag"]?.ToString()==ProxyTag))
            throw new PanelException("源配置已包含管理 API 或保留标签，请使用原始接管备份。");
        foreach(var i in root["inbounds"]!.AsArray().Where(i=>tags.Contains(i?["tag"]?.ToString()??""))){
            var sniff=(JsonObject?)i!["sniffing"]??new JsonObject();
            i["sniffing"]=sniff;sniff["enabled"]=true;sniff["routeOnly"]=false;
            if(sniff["destOverride"]==null)sniff["destOverride"]=new JsonArray("http","tls","quic");
        }
        root["api"]=new JsonObject{["listen"]="127.0.0.1:"+apiPort,["tag"]=ApiTag,["services"]=new JsonArray("HandlerService","RoutingService")};
        outs.Add(new JsonObject{["tag"]=ProxyTag,["protocol"]="socks",["settings"]=new JsonObject{["servers"]=new JsonArray(new JsonObject{["address"]="127.0.0.1",["port"]=relayPort})}});
        root["routing"]??=new JsonObject();root["routing"]!["rules"]??=new JsonArray();
        var rules=root["routing"]!["rules"]!.AsArray();
        int at=0;
        while(at<rules.Count && rules[at]?["inboundTag"] is JsonArray sources && sources.Count>0 &&
              sources.All(t=>!tags.Contains(t!.ToString())))at++;
        rules.Insert(at,new JsonObject{["type"]="field",["ruleTag"]=ProxyTag,["inboundTag"]=JsonSerializer.SerializeToNode(tags),["outboundTag"]=ProxyTag});
        return root;
    }
}
