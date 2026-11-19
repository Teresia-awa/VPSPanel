using System.Security.Cryptography;
using System.Text.Json;

namespace VPSPanel.Core;

public sealed class ProtectedTerms(string directory)
{
    public static ProtectedTerms Local => new(Path.Combine(LocalSettings.DataDirectory, "guard"));
    private string FileName => Path.Combine(directory, "registered.dpapi");

    public string[] Read()
    {
        byte[] encrypted;
        try { encrypted = File.ReadAllBytes(FileName); }
        catch (FileNotFoundException) { return []; }
        catch (DirectoryNotFoundException) { return []; }
        byte[] plain = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
        try
        {
            var values = JsonSerializer.Deserialize<string[]>(plain);
            if (values is null || values.Any(string.IsNullOrWhiteSpace)) throw new InvalidDataException();
            return values;
        }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public void Register(string value) => RegisterMany([value]);

    public void RegisterMany(IEnumerable<string> entries)
    {
        Directory.CreateDirectory(directory);
        using var writerLock = File.Open(Path.Combine(directory, "write.lock"), FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
        var existing = Read();
        var values = existing.Concat(entries.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (values.Length == existing.Length) return;
        var plain = JsonSerializer.SerializeToUtf8Bytes(values);
        var temporary = FileName + "." + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllBytes(temporary, ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser));
            File.Move(temporary, FileName, overwrite: true);
        }
        finally { CryptographicOperations.ZeroMemory(plain); File.Delete(temporary); }
    }
}
