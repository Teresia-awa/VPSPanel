using System.Text.Json;
using System.Text.Json.Serialization;

namespace VPSPanel.Core;

public enum Appearance { System, Light, Dark }

public sealed record LocalSettings(Appearance Theme = Appearance.System)
{
    public static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPSPanel");

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter<Appearance>(allowIntegerValues: false) }
    };

    public static LocalSettings Load(string file)
    {
        try { return JsonSerializer.Deserialize<LocalSettings>(File.ReadAllText(file), Options) ?? new(); }
        catch (FileNotFoundException) { return new(); }
        catch (DirectoryNotFoundException) { return new(); }
        catch (JsonException) { return new(); }
    }

    public void Save(string file)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        var temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(this, Options));
            File.Move(temp, file, overwrite: true);
        }
        finally { File.Delete(temp); }
    }
}
