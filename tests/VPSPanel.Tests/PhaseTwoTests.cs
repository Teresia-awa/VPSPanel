using System.Security.Cryptography;
using System.Text;
using VPSPanel.Core;

namespace VPSPanel.Tests;

public sealed class PhaseTwoTests
{
    [Theory]
    [InlineData("hy2")]
    [InlineData("hysteria2")]
    public void ImportsEscapedAuthSniAndObfuscation(string scheme)
    {
        var p = ShareLink.Parse(scheme + "://a%3Ab@one.invalid:7000?sni=tls.invalid&obfs=salamander&obfs-password=fixture#%E5%87%BA%E5%8F%A3");
        Assert.Equal(("a:b", "tls.invalid", 7000, "出口"), (p.Secret, p.Sni, p.Port, p.Name));
        Assert.Equal("salamander", p.ToOutbound()["streamSettings"]!["finalmask"]!["udp"]![0]!["type"]!.ToString());
        Assert.False(p.Limited);
    }

    [Fact]
    public void RealityImportAndSnapshotKeepIdentityAndAdvancedFields()
    {
        var id = Guid.NewGuid();
        var p = ShareLink.Parse("vless" + "://" + id + "@alt.invalid?security=reality&pbk=public-fixture&sid=aa&fp=firefox&flow=xtls-rprx-vision&spx=%2Fdemo");
        string json = """{"inbounds":[{"protocol":"vless","port":443,"streamSettings":{"security":"reality"}}],"outbounds":["""
            + p.ToOutbound().ToJsonString() + """,{"tag":"local","protocol":"freedom"}],"routing":{"rules":[{"outboundTag":"local","ip":["geoip:private"]},{"balancerTag":"pool","network":"udp"}]}}""";
        var snapshot = XraySnapshot.Parse(json);
        Assert.Equal("reality", Assert.Single(snapshot.Inbounds).Security);
        Assert.Equal("中转直连", snapshot.Outbounds[1].Kind);
        Assert.Equal(["local", "pool"], snapshot.Rules.Select(r => r.Target));
        var read = Assert.Single(snapshot.Editable);
        Assert.Equal((id.ToString(), "aa", "firefox", "xtls-rprx-vision"), (read.Secret, read.ShortId, read.Fingerprint, read.Flow));
        Assert.Equal("/demo", read.ToOutbound()["streamSettings"]!["realitySettings"]!["spiderX"]!.ToString());
    }

    [Fact]
    public void RejectsAmbiguousInputs()
    {
        Assert.Throws<PanelException>(() => ShareLink.Parse("hy2" + "://a@node.invalid?sni=x&sni=y"));
        Assert.Throws<PanelException>(() => ShareLink.Parse("hy2" + "://a@node.invalid?unknown=value"));
        Assert.Throws<PanelException>(() => RemoteInspection.ConfigurationPath(["xray", "-confdir", "/etc"], "/tmp"));
        Assert.Throws<PanelException>(() => RemoteInspection.ConfigurationPath(["xray", "-c", "a", "-c", "b"], "/tmp"));
        Assert.Equal("/tmp/two words.json", RemoteInspection.ConfigurationPath(["xray", "run", "-config=two words.json"], "/tmp"));
        Assert.Throws<PanelException>(() => new SshTarget("-option").Validate());
    }

    [Fact]
    public void ExitEditsProtectBindingsAndValidateLimits()
    {
        var p = ShareLink.Parse("hy2" + "://fixture@a.invalid") with { Id = "source" };
        var space = new ExitWorkspace(new("", [], [new(p.Id, "hysteria", "HY2")], [new(1, p.Id, "domain", true)], [p]), [], []);
        Assert.Throws<PanelException>(() => space.Delete(p.Id));
        Assert.Throws<PanelException>(() => space.Save(p, true));
        Assert.Throws<PanelException>(() => space.Save(p with { Limited = true, Up = 2 }, false));
        var changed = space.Save(p with { Name = "改名", Enabled = false, Aliases = ["backup.invalid"], Limited = true, Up = 2, Down = 3 }, false);
        Assert.Equal([1], changed.References(p.Id));
        Assert.False(Assert.Single(changed.Items).Enabled);
        Assert.Throws<PanelException>(() => changed.Save(p with { Aliases = ["A.INVALID"] }, false));
        var added = changed.Save(p with { Id = "other" }, true);
        Assert.Single(added.Delete("other").Items);
    }

    [IsolatedSshFact]
    public async Task RealSshAndXrayRoundTrip()
    {
        string config = Environment.GetEnvironmentVariable("VPSPANEL_LOOPBACK_CONFIG")!;
        Assert.Contains("HostName 127.0.0.1", File.ReadAllText(config), StringComparison.OrdinalIgnoreCase);
        var target = new SshTarget("phase2-lab", Service: "phase2-lab");
        var folder = Directory.CreateTempSubdirectory("panel-integration-");
        try
        {
            PanelSession Session() => new(folder.FullName, t => new OpenSsh(t, config));
            var app = Session();
            await app.ReadOnly(target, default);
            var live = app.Current!;
            Assert.True(live.Sftp);
            Assert.Equal("26.10.31", live.Version);
            Assert.Equal("lab-direct", live.Workspace.Snapshot!.Outbounds[1].Tag);
            Assert.Equal(4, live.Workspace.Snapshot.Rules.Length);
            Assert.Equal("reality", Assert.Single(live.Workspace.Snapshot.Inbounds).Security);
            var p = live.Workspace.Items.Single(x => x.Protocol == "HY2");
            var candidate = p with { Host = "spare.test", Aliases = [p.Host] };
            var ok = new Uri("https://check.test:24443/ok");
            var reality = live.Workspace.Items.Single(x => x.Protocol == "VLESS REALITY") with { Host = "spare.test" };
            var realityResult = await app.Probe(reality, default, ok);
            Assert.True(realityResult.Result.Passed, realityResult.Result.Detail);
            var good = await app.Probe(candidate, default, ok);
            Assert.True(good.Result.Passed, good.Result.Detail);
            var bad = await app.Probe(candidate with { Host = "no-such.invalid" }, default, ok);
            Assert.False(bad.Result.Dns);
            var denied = await app.Probe(candidate with { Secret = Guid.NewGuid().ToString("N") }, default, ok);
            Assert.True(denied.Result.Dns);
            Assert.False(denied.Result.Handshake);
            var wrongPath = await app.Probe(candidate, default, new("https://check.test:24443/missing"));
            Assert.True(wrongPath.Result.Handshake);
            Assert.False(wrongPath.Result.Request);
            var closedTarget = await app.Probe(candidate, default, new("https://check.test:24444/ok"));
            Assert.True(closedTarget.Result.Handshake, closedTarget.Result.Detail);
            Assert.False(closedTarget.Result.Request);
            Assert.Throws<PanelException>(() => app.SaveExit(candidate, false, wrongPath));
            Assert.Throws<PanelException>(() => app.SaveExit(candidate with { Port = 1234 }, false, good));
            Assert.Equal(p.Host, app.Current!.Workspace.Items.Single(x => x.Id == p.Id).Host);
            app.SaveExit(candidate with { Limited = true, Up = 2, Down = 4 }, false, good);
            var another = Session(); another.Load();
            var after = another.Current!.Workspace.Items.Single(x => x.Id == p.Id);
            Assert.Equal(candidate.Host, after.Host);
            Assert.True(after.Limited);
            Assert.Contains(p.Host, after.Aliases);
            Assert.DoesNotContain(p.Secret, Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(folder.FullName, "connections.dpapi"))));
            Assert.Throws<PanelException>(() => app.DeleteExit(p.Id));
            await another.ReadOnly(target, default);
            Assert.Equal(live.Workspace.Snapshot.Digest, another.Current!.Workspace.Snapshot!.Digest);
            Assert.Equal(p.Host, another.Current.Workspace.Snapshot.Editable.Single(x => x.Id == p.Id).Host);
            var extra = candidate with { Id = "extra", Name = "临时测试出口" };
            var extraCheck = await another.Probe(extra, default, ok);
            another.SaveExit(extra, true, extraCheck);
            Assert.Contains(another.Current.Workspace.Items, x => x.Id == extra.Id);
            another.DeleteExit(extra.Id);
            Assert.DoesNotContain(another.Current.Workspace.Items, x => x.Id == extra.Id);
            Assert.Throws<PanelException>(() => app.SaveExit(after, false, null));
            File.WriteAllBytes(Path.Combine(folder.FullName, "connections.dpapi"), [0, 1, 2]);
            Assert.ThrowsAny<CryptographicException>(() => Session().Load());
        }
        finally { folder.Delete(true); }
    }
}

public sealed class IsolatedSshFactAttribute : FactAttribute
{
    public IsolatedSshFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("VPSPANEL_LOOPBACK_CONFIG")))
            Skip = "需显式提供隔离 SSH 配置和回环 Xray 测试站。";
    }
}
