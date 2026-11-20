using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using VPSPanel.Core;
using VPSPanel.Desktop;

namespace VPSPanel.Tests;

public sealed class DesktopFlowTests
{
    private static void Capture(Window window, string page, bool dark)
    {
        var output = Environment.GetEnvironmentVariable("VPSPANEL_VISUAL_DIR");
        if (string.IsNullOrWhiteSpace(output)) return;
        Directory.CreateDirectory(output);
        var content = (FrameworkElement)window.Content;
        var bitmap = new System.Windows.Media.Imaging.RenderTargetBitmap(
            (int)content.ActualWidth, (int)content.ActualHeight, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
        bitmap.Render(content);
        var png = new System.Windows.Media.Imaging.PngBitmapEncoder();
        png.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(output, page + (dark ? "-dark.png" : "-light.png")));
        png.Save(file);
    }

    [IsolatedSshFact]
    public async Task WindowReadsFixtureAndEditsLocalDraft()
    {
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));
            dispatcher.InvokeAsync(async () =>
            {
                var directory = Directory.CreateTempSubdirectory("panel-ui-test-");
                try
                {
                    var app = new App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
                    app.InitializeComponent();
                    string config = Environment.GetEnvironmentVariable("VPSPANEL_LOOPBACK_CONFIG")!;
                    var session = new PanelSession(directory.FullName, t => new OpenSsh(t, config));
                    var window = new MainWindow(session);
                    window.ApplyTemplate();
                    var home = window.HomePage;
                    Click(window.Overview.ConnectButton);
                    Assert.Equal(Visibility.Visible,home.Visibility);
                    home.HostBox.Text = "phase2-lab";
                    home.Service.Text = "phase2-lab";
                    var loaded = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    session.Changed += () => loaded.TrySetResult();
                    Click(home.ReadButton);
                    await loaded.Task.WaitAsync(TimeSpan.FromSeconds(40));
                    Assert.Equal(4, home.Routes.Items.Count);
                    Assert.Equal(3, home.Outbounds.Items.Count);
                    window.Nav.SelectedIndex = 1;
                    var page = window.ExitsPage;
                    Assert.Equal(Visibility.Visible, page.Visibility);
                    Assert.Equal(2, page.List.Items.Count);
                    Assert.True(page.StableId.IsReadOnly);
                    page.ExitName.Text = "桌面测试出口";
                    page.Limit.IsChecked = true;
                    page.Upload.Text = "2.5";
                    page.Download.Text = "8";
                    page.EnabledBox.IsChecked = false;
                    Click(page.SaveButton);
                    Assert.Contains(session.Current!.Workspace.Items, x =>
                        x.Name == "桌面测试出口" && !x.Enabled && x.Limited && x.Up == 2.5m && x.Down == 8m);
                    Click(page.AddButton);
                    Assert.False(page.StableId.IsReadOnly);
                    page.Link.Password = "hy2" + "://fixture@draft.invalid";
                    Click(page.ImportButton);
                    Assert.Equal("draft.invalid", page.Host.Text);
                    page.Aliases.Text = "spare.invalid";
                    Click(page.AliasButton);
                    Assert.Equal("spare.invalid", page.Host.Text);
                    Assert.Equal("draft.invalid", page.Aliases.Text);
                    Click(page.SaveButton);
                    Assert.Contains("预检", page.ProbeText.Text);
                    Assert.Equal(2, page.List.Items.Count);
                    window.Nav.SelectedIndex = 0;
                    await using var loopback = new LoopbackSshEndpoint();
                    home.DirectMode.IsChecked = true;
                    Assert.Equal("22", home.DirectPort.Text);
                    Assert.Equal(Visibility.Collapsed, home.AliasFields.Visibility);
                    home.KeyMode.IsChecked = true;
                    Assert.Equal(Visibility.Visible, home.KeyFields.Visibility);
                    home.PasswordMode.IsChecked = true;
                    home.Address.Text = loopback.Target.Host;
                    home.DirectPort.Text = loopback.Target.Port.ToString();
                    home.DirectUser.Text = loopback.Target.User;
                    home.DirectService.Text = loopback.Target.Service;
                    home.LoginSecret.Password = loopback.Secret;
                    home.Remember.IsChecked = true;
                    session.ConfirmFingerprint = _ => true;
                    var directRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    session.Changed += () => directRead.TrySetResult();
                    Click(home.ReadButton);
                    await directRead.Task.WaitAsync(TimeSpan.FromSeconds(25));
                    Assert.NotNull(session.Current!.Direct);
                    Assert.Equal(4, home.Routes.Items.Count);
                    Assert.Equal(Visibility.Visible, home.SavedHint.Visibility);
                    home.Remember.IsChecked = false;
                    Assert.False(session.HasSavedPassword(loopback.Target));
                    home.AliasMode.IsChecked = true;
                    Assert.Equal("phase2-lab", home.HostBox.Text);
                    window.Close();
                    var demoSession=PanelSession.Demo(Path.Combine(directory.FullName,"demo"));
                    var demo=new MainWindow(demoSession){Left=-20000,Top=-20000,WindowStartupLocation=WindowStartupLocation.Manual,ShowActivated=false};
                    demo.Show();
                    demo.HomePage.SnapshotTabs.SelectedIndex=2;
                    demo.RulesPage.Target.Text="unlisted.example";
                    Assert.Contains("健康候选：A、B",demo.RulesPage.Preview.Text);
                    var dnsDirectory = Directory.CreateDirectory(Path.Combine(directory.FullName,"dns-fixture"));
                    var dnsHost = demoSession.Current! with { Target=new SshTarget("phase2-lab",Service:"phase2-lab"), Direct=null, ManagedRevision="fixture" };
                    var fixtureBook = new ConnectionBook(1,"fixture",new() { ["fixture"]=dnsHost });
                    File.WriteAllBytes(Path.Combine(dnsDirectory.FullName,"connections.dpapi"),System.Security.Cryptography.ProtectedData.Protect(
                        System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(fixtureBook),null,System.Security.Cryptography.DataProtectionScope.CurrentUser));
                    var dnsSession = new PanelSession(dnsDirectory.FullName,t=>new OpenSsh(t,config));
                    var dns = new MainWindow(dnsSession){Left=-20000,Top=-20000,WindowStartupLocation=WindowStartupLocation.Manual,ShowActivated=false};
                    dns.Show();
                    dns.Nav.SelectedIndex=4;
                    foreach(var dark in new[]{false,true}){
#pragma warning disable WPF0001
                        app.ThemeMode=dark?ThemeMode.Dark:ThemeMode.Light;
#pragma warning restore WPF0001
                        dns.DnsResolverMode.SelectedValue="Existing";
                        Assert.Equal(Visibility.Collapsed,dns.DohEditor.Visibility);
                        dns.DnsResolverMode.SelectedValue="Managed";
                        Assert.Equal(Visibility.Visible,dns.DohEditor.Visibility);
                        dns.SettingsPage.ScrollToEnd();
                        await dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
                        dns.UpdateLayout();
                        Assert.True(dns.DohAddresses.ActualWidth>120 && dns.BootstrapAddresses.ActualWidth>120);
                        Click(Descendants<Button>(dns.DohEditor).Single(b=>Equals(b.Content,"海外中转")));
                        Assert.Equal(string.Join(Environment.NewLine,DohResolvers.Overseas),dns.BootstrapAddresses.Text);
                        Capture(dns, "dns", dark);
                        for(int pageIndex=0;pageIndex<=2;pageIndex+=2){
                            demo.Nav.SelectedIndex=pageIndex;
                            await dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
                            demo.UpdateLayout();
                            var grid=pageIndex==0?demo.Overview.ExitTable:demo.RulesPage.Rules;
                            if(pageIndex==0){
                                Assert.Equal(Visibility.Collapsed,demo.HomePage.Visibility);
                                Assert.Contains("演示",demo.Overview.Status.Text);
                                Assert.NotEqual("—",demo.Overview.ActiveCount.Text);
                                Assert.Equal(3,demo.Overview.ShareLabels.Children.Count);
                                Assert.Contains("下行",demo.Overview.PrimaryRate.Text);
                            }
                            Assert.True(grid.ActualHeight>40);
                            var header=Descendants<System.Windows.Controls.Primitives.DataGridColumnHeader>(grid).First(h=>h.Column!=null);
                            var row=Descendants<DataGridRow>(grid).First();
                            var foreground=(System.Windows.Media.SolidColorBrush)header.Foreground;
                            Assert.True(dark?foreground.Color.R>180:foreground.Color.R<100);
                            Assert.NotNull(header.Background);Assert.NotNull(row.Background);
                            Assert.Equal(new Thickness(9,7,9,7),header.Padding);
                            grid.SelectedIndex=pageIndex==0?1:0;
                            demo.UpdateLayout();
                            Assert.True(((DataGridRow)grid.ItemContainerGenerator.ContainerFromIndex(grid.SelectedIndex)).IsSelected);
                            grid.UnselectAll();demo.UpdateLayout();
                            Capture(demo, pageIndex == 0 ? "home" : "rules", dark);
                        }
                        foreach (var (index, name) in new[] { (1, "exits"), (3, "migration") })
                        {
                            demo.Nav.SelectedIndex = index;
                            await dispatcher.InvokeAsync(() => {}, DispatcherPriority.ApplicationIdle);
                            demo.UpdateLayout();
                            Capture(demo, name, dark);
                        }
                    }
                    demo.Nav.SelectedIndex=2;
                    demo.UpdateLayout();
                    dns.Close();
                    var rulesPage=demo.RulesPage;
                    var choices=rulesPage.DefaultRoute;
                    Assert.Equal(2+demoSession.Current!.Workspace.Items.Count(),choices.Items.Count);
                    choices.SelectedIndex=1;
                    Assert.Contains("绑定出口：D",rulesPage.Preview.Text);
                    choices.SelectedIndex=3;
                    string selected=demoSession.Current!.Policy.DefaultRule!.Exit!;
                    Assert.Contains("绑定出口："+selected,rulesPage.Preview.Text);
                    Assert.Throws<PanelException>(()=>demoSession.DeleteExit(selected));
                    var existing=demoSession.Current.Workspace.Items.Single(x=>x.Id==selected);
                    demo.Nav.SelectedIndex=4;
                    Assert.Equal(4+demoSession.Current.Workspace.Items.Count(),demo.FailurePicker.Items.Count);
                    demo.FailurePicker.SelectedValue=new ExitFailurePolicy(FailureAction.Fixed,"A");
                    demoSession.SaveExit(existing with{Enabled=false},false,null);
                    Assert.Contains("备用出口：A",rulesPage.Preview.Text);
                    Assert.Contains("原出口 "+selected,rulesPage.Preview.Text);
                    Assert.Equal(new ExitFailurePolicy(FailureAction.Fixed,"A"),PanelSession.Demo(Path.Combine(directory.FullName,"demo")).Current!.Policy.OnUnavailable);
                    demo.FailurePicker.SelectedValue=new ExitFailurePolicy(FailureAction.Reject);
                    demo.Nav.SelectedIndex=2;
                    demoSession.SaveExit(existing with{Name="重命名测试"},false,null);
                    Assert.Contains("重命名测试",choices.Text);
                    Assert.Equal(selected,PanelSession.Demo(Path.Combine(directory.FullName,"demo")).Current!.Policy.DefaultRule!.Exit);
                    void EditDialog(bool group,Action<RuleEditor> fill)
                    {
                        var editor=new RuleEditor(demoSession,group,null){Owner=demo};
                        editor.ContentRendered+=(_,_)=>{
                            fill(editor);
                            Click(Descendants<Button>(editor).Single(b=>b.IsDefault));
                            if(editor.IsVisible)editor.Close();
                        };
                        Assert.True(editor.ShowDialog(),editor.ErrorText.Text);
                    }
                    EditDialog(true,editor=>{editor.TitleBox.Text="本地测试组";editor.Lines.Text="full:sample.example\n198.51.100.0/24";});
                    string groupId=demoSession.Current!.Policy.Groups.Last().Id;
                    EditDialog(false,editor=>{
                        editor.TitleBox.Text="本地测试规则";editor.Group.SelectedValue=groupId;
                        editor.ActionBox.SelectedIndex=(int)RouteAction.Fixed;editor.Exit.SelectedValue="B";
                    });
                    Assert.Equal(selected,demoSession.Current!.Policy.Rules.Last().Exit);
                    choices.SelectedIndex=0;
                    rulesPage.Target.Text="sample.example";
                    Assert.Contains("绑定出口：B",rulesPage.Preview.Text);
                    rulesPage.Rules.SelectedIndex=rulesPage.Rules.Items.Count-1;
                    int before=rulesPage.Rules.SelectedIndex;
                    Click(Descendants<Button>(rulesPage).Single(b=>Equals(b.Content,"上移")));
                    Assert.Equal(before-1,rulesPage.Rules.SelectedIndex);
                    rulesPage.Tabs.SelectedIndex=1;demo.UpdateLayout();rulesPage.Groups.ScrollIntoView(rulesPage.Groups.Items[^1]);demo.UpdateLayout();
                    var last=(DataGridRow)rulesPage.Groups.ItemContainerGenerator.ContainerFromIndex(rulesPage.Groups.Items.Count-1);
                    Descendants<CheckBox>(last).Single().RaiseEvent(new RoutedEventArgs(CheckBox.ClickEvent));
                    Assert.False(demoSession.Current.Policy.Groups.Last().Enabled);
                    Assert.Contains("默认规则",rulesPage.Preview.Text);
                    rulesPage.Groups.SelectedIndex=rulesPage.Groups.Items.Count-1;
                    _=dispatcher.BeginInvoke(new Action(()=>{
                        var confirm=app.Windows.OfType<ChangeDialog>().Single();
                        Click(confirm.Accept);
                    }),DispatcherPriority.ApplicationIdle);
                    Click(Descendants<Button>(rulesPage).Single(b=>b.IsVisible && Equals(b.Content,"删除")));
                    Assert.DoesNotContain(demoSession.Current.Policy.Groups,g=>g.Id==groupId);
                    var kept=demoSession.Current.Policy.Rules.Single(r=>r.Name=="本地测试规则");
                    Assert.Null(kept.Group);Assert.False(kept.Enabled);Assert.Contains("full:sample.example",kept.Entries);
                    if(Environment.GetEnvironmentVariable("VPSPANEL_MIGRATION_ASSETS") is string assets){
                        demo.Nav.SelectedIndex=3;demo.UpdateLayout();
                        var migration=demo.MigrationPage;
                        migration.Direct.IsChecked=true;migration.KeyMode.IsChecked=true;
                        Assert.Equal(Visibility.Visible,migration.KeyPanel.Visibility);Assert.Equal("22",migration.Port.Text);
                        migration.Alias.IsChecked=true;Assert.Equal(Visibility.Collapsed,migration.AuthPanel.Visibility);
                        migration.Assets.Text=assets;
                        migration.SavePath.Text=Path.Combine(directory.FullName,"ui.vpspack");
                        migration.Password.Password=Guid.NewGuid().ToString("N");
                        Click(migration.ExportButton);
                        Assert.Contains("确认",migration.ExportNotice.Text);Assert.False(File.Exists(migration.SavePath.Text));
                        string pass=migration.Password.Password;migration.Confirm.Password=pass;
                        async Task WaitForCompletion(){
                            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(45));
                            while(!migration.IsEnabled)await Task.Delay(70,deadline.Token);
                            await dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
                        }
                        migration.Assets.Text=directory.FullName;
                        Click(migration.ExportButton);await WaitForCompletion();
                        Assert.Contains("缺少 assets.json",migration.ExportNotice.Text);
                        Assert.Contains("缺少 assets.json",demoSession.History().First().Status);
                        Assert.False(File.Exists(migration.SavePath.Text));
                        migration.Assets.Text=assets;
                        Click(migration.ExportButton);await WaitForCompletion();
                        Assert.Contains("已验证 10 项文件",migration.ExportNotice.Text);Assert.True(File.Exists(migration.SavePath.Text));
                        migration.RestorePassword.Password=pass;Click(migration.VerifyButton);await WaitForCompletion();
                        Assert.Contains("SHA-256 通过",migration.Notice.Text);Assert.NotEmpty(migration.Events.Items);
                    }
                    demo.Close();
                    finished.SetResult();
                }
                catch (Exception error) { finished.SetException(error); }
                finally { directory.Delete(true); dispatcher.BeginInvokeShutdown(DispatcherPriority.Background); }
            });
            Dispatcher.Run();
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        await finished.Task.WaitAsync(TimeSpan.FromSeconds(100));
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject obj) where T:DependencyObject
    {
        for(int i=0;i<System.Windows.Media.VisualTreeHelper.GetChildrenCount(obj);i++){
            var child=System.Windows.Media.VisualTreeHelper.GetChild(obj,i);
            if(child is T found)yield return found;
            foreach(var next in Descendants<T>(child))yield return next;
        }
    }
    private static void Click(Button button) => button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
}
