using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class MainWindow : Window
{
    private App Panel => (App)Application.Current;
    private readonly CancellationTokenSource lifetime = new();
    private string? overviewTheme;
    private readonly PanelSession session;
    private bool loadingFailureChoices;
    private sealed record FailureChoice(ExitFailurePolicy Policy,string Label);

    internal static string Message(Exception ex) => ex switch
    {
        PanelException => ex.Message,
        OperationCanceledException => "操作已取消。",
        System.ComponentModel.Win32Exception => "系统 OpenSSH 未能启动，请检查 Windows 的 OpenSSH 客户端。",
        System.Security.Cryptography.CryptographicException => "当前 Windows 用户无法解密本机配置。请核对账户或恢复本机备份。",
        IOException or UnauthorizedAccessException => "读取或保存失败，请检查文件权限和其他面板窗口。",
        _ => "数据格式或操作异常。请核对配置再重试。"
    };

    public MainWindow() : this(new PanelSession(LocalSettings.DataDirectory)) { }

    internal MainWindow(PanelSession session)
    {
        this.session=session;
        InitializeComponent();
        UpdateOverviewTheme();
        ThemePicker.SelectedValue = Panel.Preferences.Theme.ToString();
        try { session.Load(); }
        catch (Exception ex) { MessageBox.Show(Message(ex), Title); }
        HomePage.Attach(session, lifetime.Token);
        Overview.FooterChanged+=(status,brush)=>{
            SideStatus.Text=status;SideDot.SetResourceReference(System.Windows.Shapes.Shape.FillProperty,brush);
        };
        Overview.ConnectionRequested+=()=>ShowPage(true);
        Overview.LimitsRequested+=()=>{
            Nav.SelectedIndex=2;RulesPage.OverallLimit.IsExpanded=true;RulesPage.OverallLimit.BringIntoView();
        };
        Overview.Attach(session,lifetime.Token);
        HomePage.ConfigurationRead+=async ()=>{
            if(Nav.SelectedIndex==0 && session.Current?.ManagedRevision!=null){
                ShowPage(false);await Overview.StartMonitoring();
            }
        };
        ExitsPage.Attach(session, lifetime.Token);
        RulesPage.Attach(session,lifetime.Token);
        MigrationPage.Attach(session,lifetime.Token);
        FailurePublisher.Attach(session,lifetime.Token);
        session.Changed+=RefreshFailureChoices;
        RefreshFailureChoices();
        Closed += (_, _) => { lifetime.Cancel(); session.ClearSessionCredentials(); };
    }

    private void RefreshFailureChoices()
    {
        loadingFailureChoices=true;
        try {
            var host=session.Current;
            FailurePicker.IsEnabled=host!=null;
            FailureNotice.Text=host==null?"请先在首页读取主机快照。":"";
            if(host==null){FailurePicker.ItemsSource=null;return;}
            var policy=host.Policy.OnUnavailable;
            var choices=new List<FailureChoice>();
            foreach(var action in new[]{FailureAction.Reject,FailureAction.Direct,FailureAction.Auto,FailureAction.UseDefault}){
                var item=new ExitFailurePolicy(action);
                choices.Add(new(item,item.Label));
            }
            foreach(var exit in ExitChoices.ForHost(host,policy.Exit))
                choices.Add(new(new(FailureAction.Fixed,exit.Id),exit.Label));
            FailurePicker.ItemsSource=choices;
            FailurePicker.SelectedValue=policy;
        } finally { loadingFailureChoices=false; }
    }
    private void FailureChanged(object sender,SelectionChangedEventArgs e)
    {
        if(loadingFailureChoices || FailurePicker.SelectedItem is not FailureChoice choice || session.Current is not {} host)return;
        try {
            session.SaveRules(host.Policy.WithFailurePolicy(choice.Policy),host.Total??new());
            FailureNotice.Text="已保存到本地主机草稿。应用到 VPS 后对新连接生效。";
        } catch(Exception ex){RefreshFailureChoices();FailureNotice.Text=Message(ex);}
    }

    protected override void OnPropertyChanged(DependencyPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if(e.Property==ForegroundProperty && IsInitialized)UpdateOverviewTheme();
    }

    private void UpdateOverviewTheme()
    {
        // The inherited Fluent text brush also changes when Windows changes the system theme.
        if(Foreground is not SolidColorBrush text || Resources.MergedDictionaries.Count==0)return;
        string theme=SystemParameters.HighContrast?"Contrast":text.Color.R>140?"Dark":"Light";
        if(overviewTheme==theme)return;
        overviewTheme=theme;
        if(theme=="Contrast"){
            var palette=new ResourceDictionary();
            foreach(var key in new[]{"OverviewBackdrop","OverviewCard","OverviewNavSelected","OverviewTrack"})
                palette[key]=SystemColors.WindowBrush;
            foreach(var key in new[]{"OverviewEdge","OverviewGridLine","OverviewUp"})
                palette[key]=SystemColors.WindowTextBrush;
            palette["OverviewDown"]=SystemColors.HighlightBrush;
            Resources.MergedDictionaries[0]=palette;
        }else Resources.MergedDictionaries[0]=new ResourceDictionary{
            Source=new Uri($"/VPSPanel.Desktop;component/Themes/Overview{theme}.xaml",UriKind.Relative)};
    }

    private void OnNavigation(object sender, SelectionChangedEventArgs e)
    {
        if (HomePage is null || SettingsPage is null) return;
        ShowPage(false);
    }
    private void BackToOverview(object sender,RoutedEventArgs e)=>ShowPage(false);
    private void ShowPage(bool connection)
    {
        RulesPage.Visibility = Nav.SelectedIndex==2?Visibility.Visible:Visibility.Collapsed;
        MigrationPage.Visibility = Nav.SelectedIndex == 3 ? Visibility.Visible : Visibility.Collapsed;
        SettingsPage.Visibility = Nav.SelectedIndex == 4 ? Visibility.Visible : Visibility.Collapsed;
        ExitsPage.Visibility = Nav.SelectedIndex == 1 ? Visibility.Visible : Visibility.Collapsed;
        HomePage.Visibility = connection ? Visibility.Visible : Visibility.Collapsed;
        Overview.Visibility = Nav.SelectedIndex==0 && !connection?Visibility.Visible:Visibility.Collapsed;
        BackButton.Visibility=connection?Visibility.Visible:Visibility.Collapsed;
        PageHeader.Visibility=Overview.Visibility==Visibility.Visible?Visibility.Collapsed:Visibility.Visible;
        PageTitle.Text = Nav.SelectedIndex switch { 1 => "出口管理", 2 => "规则与测试", 3 => "备份与迁移",4 => "设置", _ => "连接与快照" };
    }

    private void OnThemeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!Enum.TryParse<Appearance>(ThemePicker.SelectedValue as string, out var theme)
            || theme == Panel.Preferences.Theme) return;
        try { Panel.ChangeTheme(theme); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ThemePicker.SelectedValue = Panel.Preferences.Theme.ToString();
            MessageBox.Show(this, "外观设置未能保存，请检查本机配置目录的写入权限。", Title);
        }
    }
}
