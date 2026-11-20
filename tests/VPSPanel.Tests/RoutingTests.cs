using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using VPSPanel.Core;
using VPSPanel.Relay;

namespace VPSPanel.Tests;

public sealed class RoutingTests
{
    private static SiteRule Bind(string id, string condition, string exit) => new(id, id, true, null, [condition], RouteAction.Fixed, exit);
    private static LinkSample Link(string id, bool healthy = true, bool direct = false) => new(id, direct, healthy, 20, 20, 0, 0, 0, 1, 0);
    private static RelaySnapshot Sample(params LinkSample[] links) => new(DateTimeOffset.UtcNow, 123, links);

    [Theory]
    [InlineData(FailureAction.Reject, null, true, "B")]
    [InlineData(FailureAction.Fixed, "A", false, "A")]
    [InlineData(FailureAction.Fixed, "B", true, "B")]
    [InlineData(FailureAction.Direct, null, false, "D")]
    [InlineData(FailureAction.Auto, null, false, "A")]
    [InlineData(FailureAction.UseDefault, null, false, "D")]
    public void UnavailableBindingUsesOneConfiguredAlternative(FailureAction action,string? spare,bool fails,string expected)
    {
        var policy=new RoutingPolicy([], [Bind("pinned","full:site.example","B")]).WithFailurePolicy(new(action,spare)).WithDefault(RouteAction.Direct);
        var saved=System.Text.Json.JsonSerializer.Serialize(policy);
        var restored=System.Text.Json.JsonSerializer.Deserialize<RoutingPolicy>(saved)!;
        var engine=new RuleEngine(restored,new("."));
        var state=Sample(Link("A"),Link("D",direct:true),Link("B",false));
        var decision=engine.Select("site.example",state);
        Assert.Equal(expected,decision.Exit);Assert.Equal(fails,decision.Error!=null);Assert.Equal("pinned",decision.Rule);
        Assert.Equal(action!=FailureAction.Reject,decision.FailoverReason!=null);
        Assert.Equal("B",engine.Select("site.example",Sample(Link("A"),Link("B"),Link("D",direct:true))).Exit);
        Assert.Equal("D",engine.Select("other.example",state).Exit);
        Assert.Single(restored.WebsiteRules);Assert.Equal(new ExitFailurePolicy(action,spare),restored.OnUnavailable);
        Assert.Equal(restored.OnUnavailable,restored.WithDefault(RouteAction.Auto).WithWebsiteRules([]).OnUnavailable);
    }

    [Fact]
    public void FollowingDefaultDoesNotRecurseOrLeakWhenAllAutomaticExitsFail()
    {
        var policy=RoutingPolicy.Empty.WithFailurePolicy(new(FailureAction.UseDefault)).WithDefault(RouteAction.Fixed,"B");
        var state=Sample(Link("D",direct:true),Link("B",false));
        Assert.NotNull(new RuleEngine(policy,new(".")).Select("site.example",state).Error);
        var auto=policy.WithDefault(RouteAction.Auto).WithFailurePolicy(new(FailureAction.Direct));
        var noCandidates=new RuleEngine(auto,new(".")).Select("site.example",state);
        Assert.NotNull(noCandidates.Error);Assert.Null(noCandidates.Exit);Assert.Null(noCandidates.FailoverReason);
    }

    [Fact]
    public void UnmatchedActionRoundTripsAndAlwaysRunsAfterWebsiteRules()
    {
        var sites = new[] { Bind("pinned","full:site.example","A") };
        var state = Sample(Link("D",direct:true), Link("A"), Link("new-exit"));
        var original = new RoutingPolicy([],sites);
        var old = System.Text.Json.JsonSerializer.Deserialize<RoutingPolicy>("""{"Groups":[],"Rules":[]}""")!;
        Assert.Equal(RouteAction.Auto,new RuleEngine(old,new(".")).Select("example.net",state).Action);
        foreach(var action in new[]{RouteAction.Direct,RouteAction.Fixed}){
            var policy=original.WithDefault(action,action==RouteAction.Fixed?"new-exit":null);
            var saved=System.Text.Json.JsonSerializer.Serialize(policy);
            var restored=System.Text.Json.JsonSerializer.Deserialize<RoutingPolicy>(saved)!;
            var engine=new RuleEngine(restored,new("."));
            Assert.Equal("A",engine.Select("site.example",state).Exit);
            foreach(var target in new[]{"other.example","192.0.2.2","2001:db8::1"}){
                var decision=engine.Select(target,state);
                Assert.Equal(action,decision.Action);
                Assert.Equal(action==RouteAction.Fixed?"new-exit":"D",decision.Exit);
                Assert.Null(decision.Error);
                Assert.NotNull(engine.Select(target,state with{Links=[Link("A")]}).Error);
            }
            Assert.Single(restored.WebsiteRules);
            Assert.Null(restored.WithDefault(RouteAction.Auto).DefaultRule);
            Assert.Throws<PanelException>(()=>new RuleEngine(restored with{Rules=restored.Rules.Reverse().ToArray()},new(".")));
        }
    }

    [Fact]
    public void FirstMatchGroupsDisableAndFixedFailures()
    {
        RuleSet group = new("work", "办公", true, ["domain:bücher.example", "ip:2001:db8::/32"]);
        SiteRule first = new("g", "分组", true, "work", [], RouteAction.Direct, null);
        var rules = new[] { first, Bind("fixed", "full:x.xn--bcher-kva.example", "A") };
        var snap = Sample(Link("D", true, true), Link("A", false), Link("B"));
        var engine = new RuleEngine(new([group], rules), new("."));
        Assert.Equal("D", engine.Select("x.bücher.example.", snap).Exit);
        Assert.Equal("D", engine.Select("2001:db8::12", snap).Exit);
        Assert.Equal("B", engine.Select("notbücher.example", snap).Exit);
        foreach (var policy in new[] { new RoutingPolicy([group with { Enabled = false }], rules), new([group], [first with { Enabled = false }, rules[1]]), new([group], [rules[1], first]) })
        {
            var fixedRoute = new RuleEngine(policy, new(".")).Select("x.bücher.example", snap);
            Assert.Equal("A", fixedRoute.Exit); Assert.NotNull(fixedRoute.Error);
        }
        var fail = engine.Select("other.invalid", Sample(Link("D", true, true), Link("A", false)));
        Assert.NotNull(fail.Error); Assert.Null(fail.Exit); Assert.Empty(fail.Candidates);
    }

    [Fact]
    public void RemovingGroupCanAlsoDeleteAllReferencingRulesInOrder()
    {
        var shared=new RuleSet("g","组",true,["domain:lab.example"]);
        var first=Bind("keep","full:solo.example","A");
        var grouped=first with{Id="grouped",Group="g",Entries=[]};
        var p=new RoutingPolicy([shared],[grouped,first,grouped with{Id="other",Enabled=false}]);
        var next=p.RemoveGroup("g",false);
        Assert.Empty(next.Groups);Assert.Equal(first,Assert.Single(next.Rules));
        Assert.Equal(3,p.Rules.Length);
    }

    [Fact]
    public void ProtobufCategoriesMatchRealWireFormat()
    {
        // protobuf length-delimited fields; tiny independent Xray-compatible fixtures.
        static byte[] Field(int n, byte[] v) => [(byte)(n * 8 + 2), (byte)v.Length, .. v];
        static byte[] Str(int n, string s) => Field(n, Encoding.UTF8.GetBytes(s));
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            byte[] entry = [8, 2, .. Str(2, "example.test"), .. Field(3, Str(1, "test"))];
            File.WriteAllBytes(Path.Combine(directory.FullName, "geosite.dat"), Field(1, [.. Str(1, "LAB"), .. Field(2, entry)]));
            File.WriteAllBytes(Path.Combine(directory.FullName, "geoip.dat"), Field(1, [.. Str(1, "LAB"), .. Field(2, [.. Field(1, IPAddress.Parse("192.0.2.0").GetAddressBytes()), 16, 24])]));
            var engine = new RuleEngine(new([], [Bind("geo", "geosite:lab@test", "A"), Bind("cidr", "geoip:LAB", "B")]), new(directory.FullName));
            var snap = Sample(Link("A"), Link("B"));
            Assert.Equal("geo", engine.Select("www.example.test", snap).Rule); Assert.Equal("cidr", engine.Select("192.0.2.21", snap).Rule);
            Assert.Equal("默认规则", engine.Select("192.0.3.21", snap).Rule);
            Assert.Throws<PanelException>(() => new RuleEngine(new([], [Bind("missing", "geoip:none", "A")]), new(directory.FullName)));
        }
        finally { directory.Delete(true); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void RetiredSessionExpiresOnlyAtItsOwnDeadline(bool udp, bool hard)
    {
        var runtime = new RoutingRuntime(); var policy = new RoutingPolicy([], []);
        var plan = new RelayPlan(policy, [new("A", "A", false, true, new(), new JsonObject())], new());
        var engine = new RuleEngine(policy, new("."));
        runtime.Publish(new(plan, [new("A", "old", 123)]), engine, new HashSet<string> { "old" });
        using var lease = runtime.Open("site.invalid", udp, default);
        runtime.Publish(new(plan, [new("A", "new", 124)]), engine, new HashSet<string> { "new" });
        long now = System.Diagnostics.Stopwatch.GetTimestamp();
        lease.LastActivity = now - (long)((udp ? 119 : 299) * System.Diagnostics.Stopwatch.Frequency);
        runtime.Tick(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(30));
        Assert.False(lease.Stop.IsCancellationRequested);
        if (hard) lease.Line.Retired = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(31);
        else lease.LastActivity -= 2 * System.Diagnostics.Stopwatch.Frequency;
        runtime.Tick(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(30));
        Assert.True(lease.Stop.IsCancellationRequested);
        using var fresh = runtime.Open("site.invalid", udp, default); Assert.Equal("new", fresh.Line.Lane.Tag);
    }

    [Fact]
    public void DirectionalRatesAddToCombinedRateAndOldSnapshotsRemainReadable()
    {
        var runtime=new RoutingRuntime();
        var policy=RoutingPolicy.Empty;
        var plan=new RelayPlan(policy,[new("A","A",false,true,new(),new JsonObject())],new());
        runtime.Publish(new(plan,[new("A","a",1)]),new(policy,new(".")),new HashSet<string>{"a"});
        using var lease=runtime.Open("example.test",false,default);
        lease.Bytes(1000,true);lease.Bytes(4000,false);
        runtime.Tick(TimeSpan.FromMinutes(5),TimeSpan.FromMinutes(2),TimeSpan.FromMinutes(30));
        var sample=Assert.Single(runtime.Snapshot().Links);
        Assert.True(sample.UploadBytesPerSecond>0);
        Assert.Equal(4*sample.UploadBytesPerSecond!.Value,sample.DownloadBytesPerSecond!.Value,6);
        Assert.Equal(sample.BytesPerSecond,sample.UploadBytesPerSecond.Value+sample.DownloadBytesPerSecond.Value,6);
        var old=System.Text.Json.JsonSerializer.Deserialize<LinkSample>("""{"Id":"A","BytesPerSecond":123}""")!;
        Assert.Null(old.UploadBytesPerSecond);Assert.Null(old.DownloadBytesPerSecond);
        Assert.Equal(123,old.BytesPerSecond);
    }

    [Fact]
    public void EncryptedDnsUsesOnlyHealthyProxiesAndReconnectsOnFailure()
    {
        var policy = RoutingPolicy.Empty.WithDefault(RouteAction.Direct).WithFailurePolicy(new(FailureAction.Direct));
        var plan = new RelayPlan(policy,
            [new("A", "A", false, true, new(), new()), new("B", "B", false, true, new(), new()),
             new("D", "D", true, true, new(), new())], new()) { FollowHealthyDns = true };
        plan = new PolicyUpdate(policy, new(), []).Apply(plan);
        var runtime = new RoutingRuntime();
        var state = new RuntimeState(plan, [new("A", "a", 1), new("B", "b", 2), new("D", "d", 3)]);
        var engine = new RuleEngine(policy, new("."));
        runtime.Publish(state, engine, new HashSet<string> { "a", "d" });
        using var dns = runtime.Open("192.0.2.53", false, default, healthyDns: true);
        using var ordinary = runtime.Open("192.0.2.53", false, default);
        Assert.Equal("A", dns.Line.Lane.Id);
        Assert.Equal("D", ordinary.Line.Lane.Id);
        runtime.Observe("b", true, 20); runtime.Observe("b", true, 20);
        runtime.Observe("a", false, null); runtime.Observe("a", false, null);
        Assert.True(dns.Stop.IsCancellationRequested);
        Assert.False(ordinary.Stop.IsCancellationRequested);
        using var next = runtime.Open("192.0.2.53", false, default, healthyDns: true);
        Assert.Equal("B", next.Line.Lane.Id);
        runtime.Observe("b", false, null); runtime.Observe("b", false, null);
        Assert.True(next.Stop.IsCancellationRequested);
        Assert.Throws<PanelException>(() => runtime.Open("192.0.2.53", false, default, healthyDns: true));
    }

    [Fact]
    public void EncryptedDnsRuleOverridesLegacyRouteAndCanBeRemoved()
    {
        const string baseline = """
            {"inbounds":[],"dns":{"tag":"doh","servers":["https://192.0.2.53/dns-query"]},
             "routing":{"rules":[{"ruleTag":"legacy","inboundTag":["doh"],"outboundTag":"upstream"}]},
             "outbounds":[{"tag":"upstream","protocol":"blackhole"}]}
            """;
        var plan = new RelayPlan(RoutingPolicy.Empty, [], new()) { FollowHealthyDns = true };
        var enabled = XrayManager.Compose(baseline, new(plan, []), [], 9000);
        Assert.Equal(EncryptedDnsRoute.Tag, enabled["routing"]!["rules"]![0]!["outboundTag"]!.ToString());
        Assert.Equal("legacy", enabled["routing"]!["rules"]![1]!["ruleTag"]!.ToString());
        Assert.True(JsonNode.DeepEquals(enabled, XrayManager.Compose(enabled.ToJsonString(), new(plan, []), [], 9000)));
        var disabled = XrayManager.Compose(enabled.ToJsonString(), new(plan with { FollowHealthyDns = false }, []), [], 9000);
        Assert.Single(disabled["routing"]!["rules"]!.AsArray());
        Assert.Single(disabled["outbounds"]!.AsArray());
        Assert.True(JsonNode.DeepEquals(disabled["dns"], JsonNode.Parse(baseline)!["dns"]));
        foreach (var bad in new[] { System.Text.Json.JsonSerializer.Serialize("192.0.2.53"), System.Text.Json.JsonSerializer.Serialize("https+local://192.0.2.53/dns-query"),
            """{"address":"https://192.0.2.53/dns-query","tag":"other"}""" })
        {
            var invalid = baseline.Replace(System.Text.Json.JsonSerializer.Serialize("https://192.0.2.53/dns-query"), bad);
            Assert.Throws<PanelException>(() => XrayManager.Compose(invalid, new(plan, []), [], 9000));
        }
    }

    [Fact]
    public void PanelDohIsolatesStaticHostsAndPreservesOriginal()
    {
        var original = JsonNode.Parse("""
            {"tag":"host-dns","servers":["192.0.2.53"],"hosts":{"fixture.invalid":"192.0.2.25"},"disableFallback":true}
            """)!.AsObject();
        const string address = "https://192.0.2.40/dns-query";
        var plan = new RelayPlan(RoutingPolicy.Empty, [], new())
        {
            FollowHealthyDns = true, ManagedDohResolvers = DohResolvers.Parse(address)
        };
        var state = new RuntimeState(plan, []) { PreviousDns = original };
        var config = XrayManager.Compose("{}", state, [], 9000);
        Assert.Equal(address, config["dns"]!["servers"]![0]!.ToString());
        Assert.Null(config["dns"]!["hosts"]);
        Assert.Equal("192.0.2.25", original["hosts"]!["fixture.invalid"]!.ToString());
        Assert.Equal("192.0.2.53", original["servers"]![0]!.ToString());
        Assert.Null(config["dns"]!["disableFallback"]);
        Assert.Throws<PanelException>(() => DohResolvers.Parse("https://fixture.invalid/dns-query"));
        Assert.Throws<PanelException>(() => DohResolvers.Parse("https://127.0.0.1/dns-query"));
        Assert.Throws<PanelException>(() => DohResolvers.Parse("https://192.0.2.40/dns-query?variant=fixture"));
    }

    [Fact]
    public void SplitDohBindsOnlyNodeNamesAndEnabledDirectDomainRules()
    {
        var exits = new RelayExit[] { new("p","p",false,true,new(), JsonNode.Parse("""
            {"protocol":"hysteria","settings":{"address":"NODE.example"}}
            """)!.AsObject()) { Aliases=["spare.example","192.0.2.4"] } };
        var policy = new RoutingPolicy([new("g","group",true,["domain:example.cn","geosite:cn","ip:192.0.2.1"])],
            [new("r","direct",true,"g",[],RouteAction.Direct,null),new("off","off",false,null,["full:off.example"],RouteAction.Direct,null)]);
        var plan = new RelayPlan(policy,exits,new()) { FollowHealthyDns=true,
            ManagedDohResolvers=["https://192.0.2.53/dns-query"],BootstrapDohResolvers=["https+local://192.0.2.54/dns-query"] };
        Assert.Equal(new[]{"domain:example.cn","full:node.example","full:spare.example","geosite:cn"},plan.BootstrapDomains());
        var dns = EncryptedDnsRoute.ManagedConfiguration(plan);
        Assert.True(dns["servers"]![1]!["skipFallback"]!.GetValue<bool>());
        Assert.True(dns["disableFallbackIfMatch"]!.GetValue<bool>());
        var changed = plan with { Exits=[exits[0] with { Aliases=["extra.example"] }] };
        Assert.True(plan.SameDns(changed));
        Assert.NotEqual(plan.BootstrapDomains(),changed.BootstrapDomains());
        Assert.Throws<PanelException>(()=>DohResolvers.Validate(plan.ManagedDohResolvers,true));
        Assert.Throws<PanelException>(()=>DohResolvers.Validate(plan.BootstrapDohResolvers));
    }

    [Fact]
    public void PreviewAndNextAdmissionUseSameWeightsAndSequence()
    {
        var policy = RoutingPolicy.Empty; var engine = new RuleEngine(policy, new("."));
        var plan = new RelayPlan(policy, new[] { "A", "B" }.Select(id => new RelayExit(id, id, false, true, new(), new())).ToArray(), new());
        var rt = new RoutingRuntime(); rt.Publish(new(plan, [new("A", "a", 1), new("B", "b", 2)]), engine, new HashSet<string> { "a", "b" });
        for (int i = 0; i < 30; i++)
        {
            var snap = rt.Snapshot(); var preview = engine.Select("site.invalid", snap);
            using var lease = rt.Open("site.invalid", false, default);
            Assert.Equal(preview.Exit, lease.Line.Lane.Id);
        }
    }
}
