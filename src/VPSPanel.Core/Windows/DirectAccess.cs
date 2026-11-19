using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace VPSPanel.Core;

// Only these non-secret options belong in the encrypted connection book.
public sealed record DirectProfile(string? KeyFile = null);

// This type is intentionally never serialized or formatted as a record.
public sealed class DirectLogin(DirectProfile profile, string secret, bool remember = false)
{
    public DirectProfile Profile { get; } = profile;
    internal string Secret { get; } = secret;
    internal bool Remember { get; } = remember && profile.KeyFile == null;
}

public sealed record HostFingerprint(string Host, int Port, string Algorithm, string Sha256);

internal sealed class DirectAccess(string directory)
{
    internal static string Endpoint(SshTarget target)
    {
        string host = IPAddress.TryParse(target.Host, out var ip) ? ip.ToString() : target.Host.TrimEnd('.').ToLowerInvariant();
        return $"[{host}]:{target.Port ?? 22}";
    }
    private static string Account(SshTarget target) => Endpoint(target) + "/" + target.User;
    private string VaultPath => Path.Combine(directory, "direct-access.dpapi");
    private sealed record Vault(Dictionary<string, string> Pins, Dictionary<string, string> Logins);
    private Vault Read()
    {
        byte[] encrypted;
        try { encrypted = File.ReadAllBytes(VaultPath); }
        catch (FileNotFoundException) { return new([], []); }
        catch (DirectoryNotFoundException) { return new([], []); }
        byte[] bytes = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        try { return JsonSerializer.Deserialize<Vault>(bytes) ?? throw new InvalidDataException(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Update(Func<Vault, bool> change)
    {
        Directory.CreateDirectory(directory);
        using var writer = File.Open(VaultPath + ".lock", FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
        var vault = Read();
        if (!change(vault)) return;
        var plain = JsonSerializer.SerializeToUtf8Bytes(vault);
        string temp = VaultPath + "." + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllBytes(temp, ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser));
            File.Move(temp, VaultPath, true);
        }
        finally { CryptographicOperations.ZeroMemory(plain); File.Delete(temp); }
    }

    internal string? Pin(SshTarget target) => Read().Pins.GetValueOrDefault(Endpoint(target));
    internal void Trust(SshTarget target, string fingerprint) => Update(vault =>
    {
        if (vault.Pins.TryGetValue(Endpoint(target), out var existing))
        {
            if (existing != fingerprint) throw ChangedKey();
            return false;
        }
        vault.Pins.Add(Endpoint(target), fingerprint);
        return true;
    });

    internal string? SavedSecret(SshTarget target) => Read().Logins.GetValueOrDefault(Account(target));
    internal void SetSecret(SshTarget target, string? value) => Update(vault =>
    {
        string key = Account(target);
        if (value == null) return vault.Logins.Remove(key);
        if (vault.Logins.GetValueOrDefault(key) == value) return false;
        vault.Logins[key] = value;
        return true;
    });
    internal static PanelException ChangedKey() => new("主机指纹已变化，连接已阻止。请通过 VPS 控制台核对主机身份。");
}
