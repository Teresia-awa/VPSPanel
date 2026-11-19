using System.Text.Json;
using System.Text.Json.Nodes;

namespace VPSPanel.Core;

public sealed partial class PanelSession
{
    public bool IsDemo { get; private init; }
    public static PanelSession Demo(string directory)
    {
        var session = new PanelSession(directory) { IsDemo = true };
        session.Load();
        if (session.Current != null) return session;
        var exits = new[] { "A", "B" }.Select(id => new ExitProfile { Id = id, Name = "演示出口 " + id, Host = id.ToLowerInvariant() + ".example.invalid", Sni = "example.invalid", Secret = Guid.NewGuid().ToString("N") }).ToArray();
        var json = JsonSerializer.Serialize(new
        {
            inbounds = new[] { new { tag = "demo-in", protocol = "vless", port = 8443, streamSettings = new { security = "reality" } } },
            outbounds = new JsonArray(exits[0].ToOutbound(), exits[1].ToOutbound(), new JsonObject { ["protocol"] = "freedom", ["tag"] = "D" }),
            routing = new
            {
                rules = new object[]{
                new {domain=new[]{"domain:media.example","full:stream.example"},outboundTag="A",ruleTag="媒体网站"},
                new {domain=new[]{"full:work.example"},outboundTag="B",ruleTag="工作站点"},
                new {ip=new[]{"192.0.2.0/24"},outboundTag="D",ruleTag="示例网段"}
            }
            }
        });
        var workspace = ExitWorkspace.Empty.Refresh(XraySnapshot.Parse(json)) with { Drafts = exits.ToList() };
        session.Write("demo", new(new("demo.invalid","demo",22), "26.10.31", "xray", "/demo/xray.json", DateTimeOffset.Now, true, workspace, "/demo",new DirectProfile()));
        return session;
    }

    public static RelaySnapshot ExampleStatus() => new(DateTimeOffset.Now, 24, [
        new("A",false,true,32,38,.01,50000,3,1,12),new("B",false,true,53,58,0,80000,4,1,10),
        new("D",true,true,6,7,0,0,0,1,2)]);
}
