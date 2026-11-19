using System.Security.Cryptography;
using System.Text;
using VPSPanel.Core;
using VPSPanel.Guard;

namespace VPSPanel.Tests;

public sealed class LocalBehaviorTests : IDisposable
{
    private readonly DirectoryInfo folder = Directory.CreateTempSubdirectory("VPSPanel-tests-");

    [Theory]
    [InlineData(Appearance.System)]
    [InlineData(Appearance.Light)]
    [InlineData(Appearance.Dark)]
    public void AppearanceRoundTrips(Appearance theme)
    {
        string file = Path.Combine(folder.FullName, "appearance.json");
        Assert.Equal(Appearance.System, LocalSettings.Load(file).Theme);
        new LocalSettings(theme).Save(file);
        Assert.Equal(theme, LocalSettings.Load(file).Theme);
        File.WriteAllText(file, "broken");
        Assert.Equal(Appearance.System, LocalSettings.Load(file).Theme);
    }

    [Fact]
    public void RegisteredTermsAreEncryptedAndRecognized()
    {
        var store = new ProtectedTerms(folder.FullName);
        var example = Guid.NewGuid().ToString("N") + ".example.invalid";
        store.Register(example);
        var file = Path.Combine(folder.FullName, "registered.dpapi");
        Assert.DoesNotContain(example, Encoding.UTF8.GetString(File.ReadAllBytes(file)));
        Assert.NotNull(new SecretScanner(store.Read()).Match("see " + example + "/info"));
        File.WriteAllBytes(file, [1, 2, 3]);
        Assert.ThrowsAny<CryptographicException>(() => store.Read());
    }

    [Theory]
    [InlineData("-----BEGIN ", "OPENSSH PRIVATE KEY-----")]
    [InlineData("vless", "://example@node.invalid")]
    [InlineData("hy2", "://example@node.invalid")]
    [InlineData("hysteria2", "://example@node.invalid")]
    [InlineData("ssh_pass", "word: \"fixture-only\"")]
    [InlineData("VPS_", "HOST=fixture.example.org")]
    [InlineData("https://example.invalid/", "sub/fixture-token")]
    public void RecognizesSensitiveFormats(string prefix, string suffix)
        => Assert.NotNull(new SecretScanner([]).Match(prefix + suffix));

    public void Dispose() => folder.Delete(recursive: true);
}
