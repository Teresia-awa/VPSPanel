using System.Windows;
using System.Windows.Controls;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class PublishView : UserControl
{
    private PanelSession session=null!;
    private CancellationToken lifetime;
    private SshTarget? shown;
    internal Func<bool>? HasUnsavedForm { get; set; }
    public PublishView()=>InitializeComponent();
    internal void Attach(PanelSession value,CancellationToken ct)
    {
        session=value; lifetime=ct;
        session.Changed+=()=>{if(shown!=session.Current?.Target){Result.Text="";shown=session.Current?.Target;}};
    }
    private async void Preview(object sender,RoutedEventArgs e)
    {
        var host=session.Current;shown=host?.Target;IsEnabled=false;
        try {
            if(HasUnsavedForm?.Invoke()==true){Result.Text="当前表单有未保存的修改，请先保存本地草稿。";return;}
            Result.Text="正在读取 VPS 已部署方案…";
            var preview=await session.PreviewProduction(lifetime);
            if(preview.Changes.Count==0){Result.Text="运行参数与 VPS 一致，没有待发布变更。";return;}
            var scope=preview.RequiresXrayRestart
                ? "将备份配置并重启 Xray。当前代理连接会中断，校验失败或超时将自动恢复上一版。"
                : "将发布以下已保存的草稿。修改出口后，已有连接继续使用原线路排空，新连接采用新方案。";
            var confirm=new ChangeDialog("确认应用到生产 VPS", $"目标 {host!.Target.Host} · {host.Target.Service}\n{scope}",
                preview.Changes,preview.RequiresXrayRestart?"确认重启并应用":"确认应用"){Owner=Window.GetWindow(this)};
            if(confirm.ShowDialog()!=true){Result.Text="已取消发布，草稿仍在本机。";return;}
            Result.Text="正在等待 Relay 校验与提交…";
            var result=await session.ApplyProduction(preview,lifetime);
            if(shown==host.Target)Result.Text=result;
        } catch(Exception ex){if(shown==host?.Target)Result.Text=MainWindow.Message(ex)+" 可用「核对上次应用」查询已提交的事务。";}
        finally {IsEnabled=true;}
    }
    private async void Check(object sender,RoutedEventArgs e)
    {
        var host=session.Current; shown=host?.Target;IsEnabled=false;
        try {var result=await session.CheckPublication(lifetime);if(shown==host?.Target)Result.Text=result;}
        catch(Exception ex){if(shown==host?.Target)Result.Text=MainWindow.Message(ex);}
        finally{IsEnabled=true;}
    }
}
