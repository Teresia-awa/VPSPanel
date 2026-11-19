using System.IO;
using System.Windows;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class App : Application
{
    private static string SettingsFile => Path.Combine(LocalSettings.DataDirectory, "appearance.json");
    internal LocalSettings Preferences { get; private set; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        try { Preferences = LocalSettings.Load(SettingsFile); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show("外观设置读取失败，本次跟随系统。", "VPS 代理管理面板");
        }
        ApplyTheme(Preferences.Theme);
        MainWindow = e.Args.Contains("--demo") ? new MainWindow(PanelSession.Demo(Path.Combine(LocalSettings.DataDirectory,"demo"))) {Title="VPS 代理管理面板 · 离线演示"} : new MainWindow();
        MainWindow.Show();
    }

    internal void ChangeTheme(Appearance theme)
    {
        var next = Preferences with { Theme = theme };
        next.Save(SettingsFile);
        Preferences = next;
        ApplyTheme(theme);
    }

    private void ApplyTheme(Appearance theme)
    {
#pragma warning disable WPF0001
        ThemeMode = theme switch
        {
            Appearance.Light => ThemeMode.Light,
            Appearance.Dark => ThemeMode.Dark,
            _ => ThemeMode.System
        };
#pragma warning restore WPF0001
    }
}
