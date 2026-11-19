using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal static class RestoreRuntime
{
    private static int Port(HashSet<int> used)
    {
        while(true){using var s=new TcpListener(IPAddress.Loopback,0);s.Start();int p=((IPEndPoint)s.LocalEndpoint).Port;if(used.Add(p))return p;}
    }
    private static Process Start(string dir,params string[] args)
    {
        var info=new ProcessStartInfo(Path.Combine(dir,"xray")){WorkingDirectory=dir,UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
        info.Environment["XRAY_LOCATION_ASSET"]=dir;
        foreach(string s in args)info.ArgumentList.Add(s);
        return Process.Start(info)!;
    }
    internal static async Task Unpack(string package,string destination)
    {
        string dir=Path.GetFullPath(destination);
        if(!OperatingSystem.IsLinux()||Directory.EnumerateFileSystemEntries(dir).Any())throw new PanelException("需要全新的私有恢复目录。");
        var passphrase=await Console.In.ReadToEndAsync();
        var manifest=RecoveryPackage.Read(package,passphrase,(f,data)=>{
            string name=Path.Combine(dir,f.Name);
            var mode=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write};
            if(OperatingSystem.IsLinux())mode.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
            using var output=new FileStream(name,mode);
            output.Write(data.Span);output.Flush(true);
        });
        foreach(var name in new[]{"xray","relay"})File.SetUnixFileMode(Path.Combine(dir,name),UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        using(var version=Start(dir,"version")){
            string first=await version.StandardOutput.ReadToEndAsync();await version.WaitForExitAsync();
            if(version.ExitCode!=0 || !first.StartsWith("Xray "+manifest.XrayVersion+" "))throw new PanelException("Xray 版本与清单不符。");
        }
        var profile=Disk.Read<MigrationProfile>(Path.Combine(dir,"panel.json"));
        var plan=Disk.Read<RelayPlan>(Path.Combine(dir,"plan.json"));
        var rulesDir=Directory.CreateDirectory(Path.Combine(dir,"rules-geo")).FullName;
        foreach(string name in new[]{"geoip.dat","geosite.dat"})File.Move(Path.Combine(dir,"relay-"+name),Path.Combine(rulesDir,name));
        _=new RuleEngine(plan.Policy,new(rulesDir));plan.Total.Validate();
        foreach(var exit in plan.Exits)exit.Limit.Validate();
        var raw=RecoveryLayout.Parse(File.ReadAllText(Path.Combine(dir,"portable.json")));
        var used=raw["inbounds"]!.AsArray().Select(i=>int.TryParse(i?["port"]?.ToString(),out int p)?p:0).ToHashSet();
        var options=new RelayOptions("/var/lib/vpspanel/xray",Port(used),Port(used),profile.CheckUrl);
        var root=RecoveryLayout.RouteUsers(raw,options.ApiPort,options.ListenPort);
        var state=new RuntimeState(plan,plan.Exits.Where(e=>e.Enabled).Select(e=>new Lane(e.Id,"vp3-"+Guid.NewGuid().ToString("N"),Port(used))).ToArray());
        Disk.Write(Path.Combine(dir,"xray.json"),XrayManager.Compose(root.ToJsonString(),state,[]).ToJsonString());
        Disk.Write(Path.Combine(dir,"committed.json"),JsonSerializer.Serialize(state));
        Disk.Write(Path.Combine(dir,"relay.json"),JsonSerializer.Serialize(options));
        Disk.Write(Path.Combine(dir,"manifest.json"),JsonSerializer.Serialize(manifest));
        using var check=Start(dir,"run","-test","-c","xray.json");
        await Task.WhenAll(check.StandardOutput.ReadToEndAsync(),check.StandardError.ReadToEndAsync(),check.WaitForExitAsync());
        if(check.ExitCode!=0)throw new PanelException("恢复候选未通过 Xray 静态校验。");
    }
    internal static async Task Check(string destination)
    {
        string dir=Path.GetFullPath(destination);
        var state=Disk.Read<RuntimeState>(Path.Combine(dir,"committed.json"));
        var settings=Disk.Read<RelayOptions>(Path.Combine(dir,"relay.json"));
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(100));
        var token=deadline.Token;
        var url=new Uri(settings.CheckUrl);
        // Test each generation, including direct, through the pinned protocol transport.
        foreach(var lane in state.Lanes)await Socks.Check(lane.Port,url,token);
        var users=RecoveryLayout.Clients(RecoveryLayout.Parse(File.ReadAllText(Path.Combine(dir,"portable.json"))));
        foreach(var user in users){
            int port=Port([]);
            string file=Path.Combine(dir,"verify-"+Guid.NewGuid().ToString("N")+".json");
            var cfg=new JsonObject{["inbounds"]=new JsonArray(new JsonObject{["listen"]="127.0.0.1",["port"]=port,["protocol"]="socks"}),["outbounds"]=new JsonArray(user.ProbeOutbound())};
            Disk.Write(file,cfg.ToJsonString());
            try{
                using var client=Start(dir,"run","-c",file);
                var stdout=client.StandardOutput.BaseStream.CopyToAsync(Stream.Null);var stderr=client.StandardError.BaseStream.CopyToAsync(Stream.Null);
                try{
                    while(!client.HasExited){
                        try{await Socks.Check(port,url,token);break;}
                        catch(Exception ex) when(ex is IOException or SocketException or HttpRequestException or TaskCanceledException){
                            await Task.Delay(350,token);
                        }
                    }
                    if(client.HasExited)throw new PanelException("客户端入口验证失败。");
                }finally{if(!client.HasExited)client.Kill(true);await client.WaitForExitAsync();await Task.WhenAll(stdout,stderr);}
            }finally{File.Delete(file);}
        }
    }
}
