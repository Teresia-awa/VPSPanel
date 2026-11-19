using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class MigrationView : UserControl
{
    private PanelSession session=null!;
    private CancellationToken lifetime;
    public MigrationView()=>InitializeComponent();
    internal void Attach(PanelSession value,CancellationToken token){
        session=value;lifetime=token;Assets.Text=value.AssetDirectory;
        SavePath.Text=Path.Combine(value.BackupDirectory,$"VPSPanel-{DateTime.Now:yyyyMMdd-HHmmss}.vpspack");
        if(value.IsDemo){ClientHost.Text="192.0.2.42";InspectButton.Visibility=Visibility.Collapsed;}
        Events.ItemsSource=value.History();
    }
    private void Mode(object s,RoutedEventArgs e){
        if(CredentialLabel==null)return;
        bool direct=Direct.IsChecked==true,key=KeyMode.IsChecked==true;
        AuthPanel.Visibility=UserPanel.Visibility=PortPanel.Visibility=direct?Visibility.Visible:Visibility.Collapsed;
        KeyPanel.Visibility=key?Visibility.Visible:Visibility.Collapsed;
        HostLabel.Content=direct?"主机 IP 或域名":"SSH 别名";CredentialLabel.Content=key?"私钥口令（可选）":"SSH 密码";Credential.Clear();
    }
    private void ChooseAssets(object s,RoutedEventArgs e){var d=new OpenFolderDialog();if(d.ShowDialog()==true)Assets.Text=d.FolderName;}
    private void ChooseSave(object s,RoutedEventArgs e){Directory.CreateDirectory(session.BackupDirectory);var d=new SaveFileDialog{Filter="加密恢复包|*.vpspack",InitialDirectory=session.BackupDirectory,FileName=Path.GetFileName(SavePath.Text)};if(d.ShowDialog()==true)SavePath.Text=d.FileName;}
    private void ChooseOpen(object s,RoutedEventArgs e){var d=new OpenFileDialog{Filter="加密恢复包|*.vpspack"};if(d.ShowDialog()==true)OpenPath.Text=d.FileName;}
    private void ChooseKey(object s,RoutedEventArgs e){var d=new OpenFileDialog();if(d.ShowDialog()==true)KeyFile.Text=d.FileName;}
    // Apply each update before Report returns so queued progress cannot replace a terminal result.
    private sealed class StatusProgress(TextBlock status):IProgress<string>{
        public void Report(string message)=>status.Dispatcher.Invoke(()=>{status.Text=message;});
    }
    private async Task Run(TextBlock status,string progress,Func<Task> action){
        IsEnabled=false;status.Text=progress;Result.Clear();Result.Visibility=Visibility.Collapsed;
        try{await action();}catch(Exception ex){status.Text=MainWindow.Message(ex);}
        finally{IsEnabled=true;Events.ItemsSource=session.History();}
    }
    private async void Inspect(object s,RoutedEventArgs e)=>await Run(ExportNotice,"正在只读核对服务和配置来源…",async()=>{
        Inspection.Visibility=Visibility.Collapsed;
        var item=await session.InspectService(lifetime);
        string match=item.ContentMatches switch{true=>"源文件与运行副本一致",false=>"源文件与运行副本有差异",_=>"需人工核对来源"};
        Inspection.Text=string.Join(Environment.NewLine,item.Fragment,
            string.IsNullOrEmpty(item.DropIns)?"无附加 unit 配置":item.DropIns,
            item.Kind+" · "+(item.Source??"待核对"),match);
        Inspection.Visibility=Visibility.Visible;ExportNotice.Text="只读核查完成。";
    });
    private async void Export(object s,RoutedEventArgs e){
        if(File.Exists(SavePath.Text) && MessageBox.Show(Window.GetWindow(this),"替换已有加密包？新包验证通过后才会替换。","导出备份",MessageBoxButton.YesNo)!=MessageBoxResult.Yes)return;
        await Run(ExportNotice,"正在准备材料、加密并重新读取验证…",async()=>{
            var m=await session.ExportRecovery(SavePath.Text,Password.Password,Confirm.Password,Assets.Text,ClientHost.Text.Trim(),lifetime,progress:new StatusProgress(ExportNotice));
            ExportNotice.Text=$"已验证 {m.Files.Length} 项文件 · Xray {m.XrayVersion} · Relay {m.RelayVersion}";OpenPath.Text=SavePath.Text;Password.Clear();Confirm.Clear();
        });
    }
    private async void Verify(object s,RoutedEventArgs e)=>await Run(Notice,"正在验证恢复包…",async()=>{
        var file=OpenPath.Text;var pass=RestorePassword.Password;
        var pack=await Task.Run(()=>RecoveryPackage.Open(file,pass),lifetime);
        Notice.Text=$"认证及全部 SHA-256 通过 · {pack.Manifest.Architecture} · {pack.Manifest.Files.Length} 项文件";
    });
    private async void Restore(object s,RoutedEventArgs e){
        if(session.IsDemo){Notice.Text="离线演示可导出和校验备份。";return;}
        if(MessageBox.Show(Window.GetWindow(this),$"将向目标「{Host.Text}」安装备份中的服务。目标已有面板服务时，验证期间会短暂中断。确认这是要恢复的新主机？","确认目标主机",MessageBoxButton.YesNo,MessageBoxImage.Warning,MessageBoxResult.No)!=MessageBoxResult.Yes)return;
        await Run(Notice,"正在校验恢复包、检查目标环境并验证线路…",async()=>{
            bool direct=Direct.IsChecked==true;int port=22;
            if(direct && !int.TryParse(Port.Text,out port))throw new PanelException("SSH 端口无效。");
            if(direct && KeyMode.IsChecked==true && string.IsNullOrWhiteSpace(KeyFile.Text))throw new PanelException("请选择本地私钥。");
            var target=new SshTarget(Host.Text.Trim(),direct?User.Text.Trim():"",direct?port:null,"vpspanel-restored-xray");
            var auth=direct?new DirectLogin(new(KeyMode.IsChecked==true?KeyFile.Text:null),Credential.Password):null;
            var done=await session.RestoreRecovery(OpenPath.Text,RestorePassword.Password,target,auth,PublicHost.Text.Trim(),lifetime,new StatusProgress(Notice));
            Result.Text=done.DnsName==null?string.Join(Environment.NewLine,done.Links):$"请将 {done.DnsName} 的 DNS A / AAAA 记录指向新 VPS 地址。";
            Result.Visibility=Visibility.Visible;Notice.Text="恢复完成，入口和出口已验证。";Credential.Clear();RestorePassword.Clear();
            var content=new StackPanel{Margin=new Thickness(20)};
            content.Children.Add(new TextBlock{Text=done.DnsName==null?"使用新地址的客户端链接":"入口域名",FontSize=18});
            content.Children.Add(new TextBox{Text=Result.Text,IsReadOnly=true,TextWrapping=TextWrapping.Wrap,MaxHeight=240,
                VerticalScrollBarVisibility=ScrollBarVisibility.Auto,Margin=new Thickness(0,12,0,12)});
            var close=new Button{Content="完成",IsDefault=true,HorizontalAlignment=HorizontalAlignment.Right};
            content.Children.Add(close);
            var dialog=new Window{Owner=Window.GetWindow(this),Title="恢复结果",Width=520,SizeToContent=SizeToContent.Height,
                WindowStartupLocation=WindowStartupLocation.CenterOwner,Content=content};
            close.Click+=(_,_)=>dialog.Close();dialog.ShowDialog();
        });
    }
}
