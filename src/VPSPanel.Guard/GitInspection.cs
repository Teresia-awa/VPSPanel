using System.Diagnostics;
using System.Text;

namespace VPSPanel.Guard;

internal sealed class GitInspection(string directory, SecretScanner scanner)
{
    private readonly HashSet<string> checkedBlobs = [];
    private readonly HashSet<string> checkedCommits = [];

    private static bool ObjectId(string id) => id.Length is 40 or 64 && id.All(Uri.IsHexDigit);
    private static bool Zero(string id) => id.All(c => c == '0');

    private (byte[] Output, int Code) Git(params string[] args)
    {
        var start = new ProcessStartInfo("git")
        {
            WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true
        };
        start.Environment["GIT_NO_REPLACE_OBJECTS"] = "1";
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var child = Process.Start(start) ?? throw new IOException();
        var error = child.StandardError.BaseStream.CopyToAsync(Stream.Null);
        using var result = new MemoryStream();
        child.StandardOutput.BaseStream.CopyTo(result);
        child.WaitForExit();
        error.GetAwaiter().GetResult();
        return (result.ToArray(), child.ExitCode);
    }

    private byte[] Read(params string[] args)
    {
        var (data, code) = Git(args);
        if (code != 0) throw new InvalidDataException();
        return data;
    }

    private string Text(params string[] args) => Encoding.UTF8.GetString(Read(args));

    public void Staged() => Entries(Text("ls-files", "--stage", "-z"), index: true);

    private void Entries(string records, bool index)
    {
        foreach (var record in records.Split('\0', StringSplitOptions.RemoveEmptyEntries))
        {
            int tab = record.IndexOf('\t');
            var fields = record[..tab].Split(' ');
            string path = record[(tab + 1)..];
            if (scanner.Match(path) is { } type) throw new Finding("文件名已隐藏", 1, type);
            if (path.Any(char.IsControl)) throw new Finding("文件名已隐藏", 1, "含控制符的路径");
            if (index && fields[2] != "0") throw new InvalidDataException();
            if (fields[0] == "160000") continue; // Submodule contents belong to the child repository.
            string id = index ? fields[1] : fields[2];
            if (checkedBlobs.Add(id)) scanner.Check(Read("cat-file", "blob", id), path);
        }
    }

    public void Outgoing(TextReader updates)
    {
        while (updates.ReadLine() is { } line)
        {
            if (line.Length == 0) continue;
            var parts = line.Split(' ');
            if (parts.Length != 4 || !ObjectId(parts[1]) || !ObjectId(parts[3])) throw new InvalidDataException();
            if (Zero(parts[1])) continue; // Deleted ref.
            if (scanner.Match(parts[2]) is { } issue) throw new Finding("目标引用名已隐藏", 1, issue);
            string tip = parts[1];
            while (Text("cat-file", "-t", tip).Trim() == "tag")
            {
                byte[] tag = Read("cat-file", "tag", tip);
                scanner.Check(tag, "标签说明");
                tip = Encoding.UTF8.GetString(tag).Split('\n', 2)[0].Split(' ')[1];
                if (!ObjectId(tip)) throw new InvalidDataException();
            }
            var kind = Text("cat-file", "-t", tip).Trim();
            if (kind == "blob") { scanner.Check(Read("cat-file", "blob", tip), "标签对象"); continue; }
            if (kind == "tree") { Entries(Text("ls-tree", "-r", "-z", tip), false); continue; }
            if (kind != "commit") throw new InvalidDataException();
            // A shallow clone can hide ancestors in a still-unpublished history.
            if (Text("rev-parse", "--is-shallow-repository").Trim() == "true") throw new InvalidDataException();
            string prior = parts[3] + "^{commit}";
            var revArgs = new List<string> { "rev-list", tip };
            if (!Zero(parts[3]) && Git("cat-file", "-e", prior).Code == 0)
                revArgs.Add("^" + prior);
            foreach (var id in Text(revArgs.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!checkedCommits.Add(id)) continue;
                scanner.Check(Read("cat-file", "commit", id), "提交信息 " + id[..8]);
                Entries(Text("ls-tree", "-r", "-z", id), index: false);
            }
        }
    }
}
