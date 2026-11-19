using System.Text.Json;

namespace VPSPanel.Core;

public sealed record UnitInspection(string Fragment,string DropIns,string Kind,string? Source,bool? ContentMatches,
    int UserInputs,int InfrastructureInputs,int FirstRuleBoundInputs,bool FirstRuleTargetsExistingOutbound,
    bool FirstRuleExcludesUserInputs,bool FirstRuleUsesTunnel, bool ExpectedForwarding);

public sealed partial class PanelSession
{
    public async Task<UnitInspection> InspectService(CancellationToken token,string tunnelTag="",int tunnelPort=0,string companionTag="")
    {
        var host=Current??throw new PanelException("请先选择已读取的主机。");
        if(IsDemo)throw new PanelException("离线演示没有活动的 systemd 单元。");
        host.Target.Validate();
        // Never request SetCredential, Environment or the full unit text: they may contain inline secrets.
        const string script="""
            import os,sys,subprocess,json
            unit,path,tunnel,port,companion=sys.argv[1:]
            def prop(key):
                return subprocess.check_output(["systemctl","show","-p",key,"--value",unit],text=True).strip()
            pid=int(prop("MainPID"))
            args=open("/proc/%d/cmdline"%pid,"rb").read().decode().split("\0")
            if path not in args and not any(x.endswith("="+path) for x in args):raise ValueError()
            live="/proc/%d/root"%pid+path
            raw=open(live,"rb").read()
            cfg=json.loads(raw)
            source=None;equal=None;kind="普通文件"
            if path.startswith("/run/credentials/"):
                kind="需核对凭据提供方"
                for key in ("LoadCredential","LoadCredentialEncrypted"):
                    for item in prop(key).split():
                        name,_,value=item.partition(":")
                        if name==os.path.basename(path) and value.startswith("/"):
                            source=value;kind=key
                            if key=="LoadCredential" and os.path.isfile(value):
                                equal=raw==open(value,"rb").read()
                if source is None:
                    # Parse only directive names, IDs and file-source paths on the host.
                    # The text of inline credentials never leaves this process.
                    import shlex
                    chosen=None; section=""; origin=prop("FragmentPath")
                    text=subprocess.check_output(["systemctl","cat","--no-pager",unit],text=True)
                    for line in text.replace("\\\n"," ").splitlines():
                        if line.startswith("# /"): origin=line[2:];continue
                        line=line.strip()
                        if line.startswith("["):section=line;continue
                        if section!="[Service]":continue
                        directive,sep,val=line.partition("="); directive=directive.strip()
                        if directive not in ("LoadCredential","LoadCredentialEncrypted","SetCredential","SetCredentialEncrypted","ImportCredential"):continue
                        if not val.strip():
                            if chosen and chosen[0]==directive:chosen=None
                            continue
                        if directive.startswith("Set"):
                            if val.strip().lstrip('"').partition(":")[0]==os.path.basename(path):chosen=(directive,origin)
                        else:
                            args=shlex.split(val)
                            if len(args)!=1:continue
                            key,_,loc=args[0].partition(":")
                            if key==os.path.basename(path):chosen=(directive,loc or key)
                    if chosen:
                        kind,loc=chosen
                        if os.path.isabs(loc):source=loc
                        elif kind.startswith("Load"):
                            suffix=".encrypted" if kind.endswith("Encrypted") else ""
                            candidates=[d+"/credstore"+suffix+"/"+loc for d in ("/etc","/run","/usr/lib")]
                            source=next((f for f in candidates if os.path.isfile(f)),None)
                        if kind=="LoadCredential" and source and os.path.isfile(source):equal=raw==open(source,"rb").read()
            else:source=os.path.realpath(path);equal=True
            ins=cfg.get("inbounds",[]); rules=cfg.get("routing",{}).get("rules",[])
            first=rules[0] if rules else {}
            print(json.dumps(dict(Fragment=prop("FragmentPath"),DropIns=prop("DropInPaths"),Kind=kind,Source=source,
                ContentMatches=equal,UserInputs=sum(i.get("protocol")=="vless" for i in ins),
                InfrastructureInputs=sum(i.get("protocol") in ("dokodemo-door","tunnel") for i in ins),
                FirstRuleBoundInputs=len(first.get("inboundTag",[])),FirstRuleTargetsExistingOutbound=first.get("outboundTag") in
                [o.get("tag") for o in cfg.get("outbounds",[])],
                FirstRuleExcludesUserInputs=bool(first.get("inboundTag")) and not any(i.get("tag") in first["inboundTag"] for i in ins if i.get("protocol")=="vless"),
                FirstRuleUsesTunnel=any(i.get("tag") in first.get("inboundTag",[]) for i in ins if i.get("protocol") in ("dokodemo-door","tunnel")),
                ExpectedForwarding=bool(tunnel) and set(first.get("inboundTag",[]))=={tunnel,companion} and any(i.get("tag")==tunnel and str(i.get("port"))==port and i.get("protocol") in ("dokodemo-door","tunnel") for i in ins))))
            """;
        var transport=RelayTransport(host);
        var result=await Task.Run(()=>transport.Command("python3 - "+string.Join(" ",new[]{host.Target.Service,host.ConfigPath,tunnelTag,tunnelPort.ToString(),companionTag}.Select(OpenSsh.Quote)),
            script.ReplaceLineEndings("\n"),token),token);
        return JsonSerializer.Deserialize<UnitInspection>(result)??throw new PanelException("只读核查返回无效。");
    }
}
