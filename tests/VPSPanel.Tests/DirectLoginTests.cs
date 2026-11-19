using System.Security.Cryptography;
using System.Text;
using VPSPanel.Core;
using VPSPanel.Guard;

namespace VPSPanel.Tests;

public sealed class DirectLoginTests : IDisposable
{
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("panel-direct-tests-");
    private PanelSession Session() => new(directory.FullName);
    public void Dispose() => directory.Delete(true);

    [RelayFixtureFact]
    public async Task DirectSessionAppliesPolicyAndReadsRealRelaySnapshot()
    {
        await using var lab=new LoopbackSshEndpoint();
        var session=Session();session.ConfirmFingerprint=_=>true;
        await session.ReadOnly(lab.Target,default,new DirectLogin(new(),lab.Secret));
        var h=session.Current!;
        Assert.Equal(3,h.Policy.Rules.Length);
        var plan=session.BuildRelayPlan();
        Assert.Contains(plan.Exits,e=>e.Direct && e.Outbound["settings"]?["finalRules"]!=null);
        session.SaveRules(h.Policy with {Rules=[..h.Policy.Rules.Reverse()]},new(true,8,12));
        await session.ApplyToLabRelay(default);
        RelaySnapshot? status=null;
        for(int i=0;i<10;i++){
            status=await session.ReadRelayStatus(default);
            if(status.Links.Count(l=>l.Healthy)==3)break;
            await Task.Delay(300);
        }
        Assert.Equal(3,status!.Links.Count(l=>l.Healthy));Assert.Null(status.AutoError);
        var engine=new RuleEngine(session.Current!.Policy,new(session.GeoDirectory));
        Assert.Equal("lab-reality",engine.Select("media.invalid",status).Exit);
        var reopened=Session();reopened.Load();
        Assert.Equal(session.Current!.Policy.Rules.Select(r=>r.Id),reopened.Current!.Policy.Rules.Select(r=>r.Id));
        Assert.Equal(new Bandwidth(true,8,12),reopened.Current.Total);
    }

    [Fact]
    public async Task DirectFormRequiresAUserBeforeNetworkAccess()
    {
        var session = Session();
        await Assert.ThrowsAsync<PanelException>(() => session.ReadOnly(new("test.invalid"), default, new(new(), "")));
        Assert.Empty(directory.GetFiles());
    }

    [IsolatedSshFact]
    public async Task PasswordTrustAndSftpUseTheSameServerIdentity()
    {
        await using var lab = new LoopbackSshEndpoint();
        var app = Session();
        var auth = new DirectLogin(new(), lab.Secret);
        int prompts = 0;
        app.ConfirmFingerprint = key =>
        {
            prompts++;
            Assert.StartsWith("SHA256:", key.Sha256);
            Assert.Equal(lab.Target.Port, key.Port);
            return false;
        };
        var refused = await Assert.ThrowsAsync<PanelException>(() => app.ReadOnly(lab.Target, default, auth));
        Assert.Contains("未信任", refused.Message);
        Assert.Null(app.Current);
        app.ConfirmFingerprint = key => { prompts++; return true; };
        var denied = await Assert.ThrowsAsync<PanelException>(() =>
            app.ReadOnly(lab.Target, default, new(new(), Guid.NewGuid().ToString(), true)));
        Assert.Contains("密码认证失败", denied.Message);
        Assert.False(app.HasSavedPassword(lab.Target));
        await app.ReadOnly(lab.Target, default, auth);
        Assert.True(app.Current!.Sftp);
        Assert.Equal("26.10.31", app.Current.Version);
        Assert.Equal(4, app.Current.Workspace.Snapshot!.Rules.Length);
        var fixtureExit = app.Current.Workspace.Items.Single(x => x.Protocol == "HY2");
        var probe = await app.Probe(fixtureExit, default, new("https://check.test:24443/ok"));
        Assert.True(probe.Result.Passed, probe.Result.Detail);
        Assert.Equal(2, prompts);
        var terms = new ProtectedTerms(Path.Combine(directory.FullName, "guard")).Read();
        Assert.NotNull(new SecretScanner(terms).Match("example " + lab.Target.Host));
        AssertSecretAbsent(lab.Secret);
        var restarted = Session();
        restarted.Load();
        Assert.False(restarted.HasSavedPassword(lab.Target));
        await Assert.ThrowsAsync<PanelException>(() => restarted.Probe(fixtureExit, default));
        // The same address now presents the second fixture daemon's key.
        Volatile.Write(ref lab.DestinationPort, 26443);
        restarted.ConfirmFingerprint = _ => throw new InvalidOperationException("A changed key must never prompt for replacement.");
        var changed = await Assert.ThrowsAsync<PanelException>(() => restarted.ReadOnly(lab.Target, default, auth));
        Assert.Contains("指纹已变化", changed.Message);
    }

    [IsolatedSshFact]
    public async Task SftpRejectsKeyChangedAfterSshDiscovery()
    {
        await using var lab = new LoopbackSshEndpoint { RotateAfter = 2 };
        var app = Session();
        int prompts = 0;
        app.ConfirmFingerprint = _ => { prompts++; return true; };
        var changed = await Assert.ThrowsAsync<PanelException>(() =>
            app.ReadOnly(lab.Target, default, new(new(), lab.Secret, true)));
        Assert.Contains("指纹已变化", changed.Message);
        Assert.Equal(1, prompts);
        Assert.Null(app.Current);
        Assert.False(app.HasSavedPassword(lab.Target));
    }

    [IsolatedSshFact]
    public async Task RememberedPasswordSurvivesRestartAndCanBeRemoved()
    {
        await using var lab = new LoopbackSshEndpoint();
        var app = Session();
        app.ConfirmFingerprint = _ => true;
        await app.ReadOnly(lab.Target, default, new(new(), lab.Secret, true));
        Assert.True(app.HasSavedPassword(lab.Target));
        Assert.False(app.HasSavedPassword(lab.Target with { User = "different" }));
        var vault = File.ReadAllBytes(Path.Combine(directory.FullName, "direct-access.dpapi"));
        Assert.False(ContainsSecret(vault, lab.Secret));
        var plain = ProtectedData.Unprotect(vault, null, DataProtectionScope.CurrentUser);
        try { Assert.True(ContainsSecret(plain, lab.Secret)); }
        finally { CryptographicOperations.ZeroMemory(plain); }
        var reopened = Session();
        reopened.Load();
        await reopened.ReadOnly(lab.Target, default, new(new(), "", true));
        reopened.ForgetPassword(lab.Target);
        Assert.False(Session().HasSavedPassword(lab.Target));
        AssertSecretAbsent(lab.Secret);
    }

    [IsolatedSshFact]
    public async Task PrivateKeySupportsOptionalPassphrase()
    {
        await using var lab = new LoopbackSshEndpoint();
        var app = Session();
        app.ConfirmFingerprint = _ => true;
        await app.ReadOnly(lab.Target, default, new(new(lab.KeyFile), ""));
        Assert.True(app.Current!.Sftp);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(lab.KeyFile));
        var phrase = Guid.NewGuid().ToString("N");
        var path = Path.Combine(directory.FullName, "fixture-encrypted.pem");
        File.WriteAllText(path, rsa.ExportEncryptedPkcs8PrivateKeyPem(phrase, new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10000)));
        var invalid = await Assert.ThrowsAsync<PanelException>(() => app.ReadOnly(lab.Target, default, new(new(path), "incorrect")));
        Assert.Contains("私钥", invalid.Message);
        await app.ReadOnly(lab.Target, default, new(new(path), phrase, true));
        Assert.True(app.Current!.Sftp);
        Assert.False(app.HasSavedPassword(lab.Target));
        var check = await app.Probe(app.Current.Workspace.Items.Single(x => x.Protocol == "VLESS REALITY"), default, new("https://check.test:24443/ok"));
        Assert.True(check.Result.Passed, check.Result.Detail);
        AssertSecretAbsent(phrase);
    }

    private void AssertSecretAbsent(string secret)
    {
        foreach (var file in directory.EnumerateFiles("*.dpapi", SearchOption.AllDirectories))
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(file.FullName), null, DataProtectionScope.CurrentUser);
            try { Assert.False(ContainsSecret(bytes, secret)); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    // A failed assertion must not print credentials or the decrypted vault.
    private static bool ContainsSecret(byte[] bytes, string value) => Encoding.UTF8.GetString(bytes).Contains(value, StringComparison.Ordinal);
}
public sealed class RelayFixtureFactAttribute:FactAttribute
{
    public RelayFixtureFactAttribute()
    {
        if(Environment.GetEnvironmentVariable("VPSPANEL_LAB_RELAY")!="1")Skip="需要带 Relay 的回环 SSH 夹具。";
    }
}
