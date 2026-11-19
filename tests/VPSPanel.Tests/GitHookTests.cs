using System.Diagnostics;
using System.Text;

namespace VPSPanel.Tests;

public sealed class GitHookTests : IDisposable
{
    private readonly DirectoryInfo sandbox = Directory.CreateTempSubdirectory("VPSPanel-git-");
    private readonly string work;

    public GitHookTests()
    {
        work = Directory.CreateDirectory(Path.Combine(sandbox.FullName, "work")).FullName;
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "VPSPanel.slnx"))) root = root.Parent;
        Assert.NotNull(root);
        File.Copy(Path.Combine(root.FullName, ".gitignore"), Path.Combine(work, ".gitignore"));
        File.Copy(Path.Combine(root.FullName, ".env.example"), Path.Combine(work, ".env.example"));
        Good("init", "-b", "main");
        Good("config", "core.hooksPath", Path.Combine(root.FullName, ".githooks").Replace('\\', '/'));
        Good("config", "user.name", "Local Fixture");
        Good("config", "user.email", "fixture@example.invalid");
        Good("config", "commit.gpgSign", "false");
    }

    private (int Exit, string Output) Git(params string[] arguments)
    {
        var info = new ProcessStartInfo("git")
        {
            WorkingDirectory = work, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
            UseShellExecute = false, CreateNoWindow = true
        };
        // Keep fixtures independent of the outer repository and personal URL rewrites.
        foreach (var key in info.Environment.Keys.Where(k => k.StartsWith("GIT_", StringComparison.OrdinalIgnoreCase)).ToArray())
            info.Environment.Remove(key);
        info.Environment["GIT_CONFIG_NOSYSTEM"] = "1";
        info.Environment["GIT_CONFIG_GLOBAL"] = Path.Combine(sandbox.FullName, "empty.gitconfig");
        info.Environment["GIT_ALLOW_PROTOCOL"] = "file";
        info.Environment["GIT_TERMINAL_PROMPT"] = "0";
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(90000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("本地 Git 演练超时");
        }
        return (process.ExitCode, output.Result + error.Result);
    }

    private string Good(params string[] arguments)
    {
        var result = Git(arguments);
        Assert.True(result.Exit == 0, "本地 Git 演练未完成：" + result.Output);
        return result.Output;
    }

    private static string FakeLink => "https://example.invalid/" + "subscribe?token=" + Guid.NewGuid().ToString("N");

    [Fact]
    public void OrdinaryAddIgnoresPrivateFilesAndCommitInspectsTheIndex()
    {
        foreach (string name in new[] { ".env", ".env.local", ".ssh/config", "private/host.json", "demo.key", "exports/test.vpspack", "bin/output.dll" })
        {
            var path = Path.Combine(work, name);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "synthetic");
        }
        var readme = Path.Combine(work, "README.md");
        var value = FakeLink;
        File.WriteAllText(readme, value);
        Good("add", ".");
        var files = Good("ls-files").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        Assert.Equal(new[] { ".env.example", ".gitignore", "README.md" }, files);
        File.WriteAllText(readme, "clean working file");
        var rejected = Git("commit", "-m", "fixture");
        Assert.NotEqual(0, rejected.Exit);
        Assert.Contains("README.md", rejected.Output);
        Assert.Contains("已拦截", rejected.Output);
        Assert.DoesNotContain(value, rejected.Output);
        Good("add", "README.md");
        File.WriteAllText(readme, value); // Only the index will enter the commit.
        Good("commit", "-m", "clean");
    }

    [Fact]
    public void PushDryRunRejectsDeletedHistoricalSecret()
    {
        var bare = Path.Combine(sandbox.FullName, "destination.git");
        Good("init", "--bare", bare);
        Good("add", ".");
        Good("commit", "-m", "clean base");
        Good("push", "--dry-run", bare, "HEAD:refs/heads/main");
        string value = FakeLink;
        File.WriteAllText(Path.Combine(work, "README.md"), value);
        Good("add", "README.md");
        // Construct the historical mistake only inside this disposable repository.
        Good("-c", "core.hooksPath=" + Path.Combine(sandbox.FullName, "no-hooks"), "commit", "-m", "historical fixture");
        Good("rm", "README.md");
        Good("commit", "-m", "remove fixture");
        var rejected = Git("push", "--dry-run", bare, "HEAD:refs/heads/main");
        Assert.NotEqual(0, rejected.Exit);
        Assert.Contains("README.md", rejected.Output);
        Assert.Contains("已拦截", rejected.Output);
        Assert.DoesNotContain(value, rejected.Output);
        Assert.Empty(Good("--git-dir", bare, "for-each-ref"));
    }

    public void Dispose()
    {
        foreach (var file in sandbox.EnumerateFiles("*", SearchOption.AllDirectories)) file.IsReadOnly = false;
        sandbox.Delete(recursive: true);
    }
}
