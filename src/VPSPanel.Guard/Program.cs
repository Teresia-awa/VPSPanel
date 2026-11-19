using System.Text;
using VPSPanel.Guard;
using VPSPanel.Core;

try
{
    if (args is ["register"])
    {
        if (Console.IsInputRedirected) throw new InvalidOperationException();
        Console.Write("输入要保护的完整地址或链接（输入隐藏），按回车保存：");
        var value = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Escape) return 0;
            if (key.Key == ConsoleKey.Backspace && value.Length > 0) value.Length--;
            else if (!char.IsControl(key.KeyChar)) value.Append(key.KeyChar);
        }
        ProtectedTerms.Local.Register(value.ToString());
        Console.WriteLine("\n已加密登记。");
        return 0;
    }
    if (args.Length != 2) throw new ArgumentException();
    var audit = new GitInspection(args[1], new SecretScanner(ProtectedTerms.Local.Read()));
    switch (args[0])
    {
        case "pre-commit": audit.Staged(); break;
        case "pre-push": audit.Outgoing(Console.In); break;
        default: throw new ArgumentException();
    }
    return 0;
}
catch (Finding finding) { Console.Error.WriteLine(finding.Report); return 1; }
catch (Exception) { Console.Error.WriteLine("检查未完成，操作已停止。请检查 Git 对象、本机凭据库及 .NET 环境。"); return 2; }
