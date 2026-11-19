using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class DashboardView : UserControl
{
    private sealed record ExitRow(string Id,string Name,string Protocol,string Aliases,string Delay,string Health)
    {
        public string Icon=>Health switch { "健康"=>"\uE930","不可用"=>"\uE7BA",_=>"\uECCA" };
    }
    private readonly List<RelaySnapshot> history=[];
    private readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromSeconds(5)};
    private PanelSession session=null!;
    private CancellationToken lifetime;
    private CancellationTokenSource? reading;
    private (SshTarget Target,bool Direct)? identity;
    private bool monitoring;
    private string? error;
    internal event Action? ConnectionRequested, LimitsRequested;
    internal event Action<string,string>? FooterChanged;

    public DashboardView()
    {
        InitializeComponent();
        timer.Tick+=async (_,_)=>await RefreshAsync();
        IsVisibleChanged+=async (_,_)=>{
            UpdateTimer();
            if(IsVisible && session!=null){
                Render();
                if(monitoring && (history.Count==0 || DateTimeOffset.UtcNow-history[^1].Time>=timer.Interval))await RefreshAsync();
            }
        };
        Unloaded+=(_,_)=>{timer.Stop();reading?.Cancel();};
    }

    internal void Attach(PanelSession model,CancellationToken token)
    {
        session=model;lifetime=token;
        session.Changed+=OnSessionChanged;
        OnSessionChanged();
    }
    private void OnSessionChanged()
    {
        var host=session.Current;
        (SshTarget,bool)? next=host==null?null:(host.Target,host.Direct!=null);
        if(next!=identity){
            reading?.Cancel(); identity=next; history.Clear(); error=null; monitoring=false;
            if(session.IsDemo){
                SeedDemo(DateTimeOffset.UtcNow);
                monitoring=true;
            }
        }
        Render(); UpdateTimer();
    }
    private void SeedDemo(DateTimeOffset end)
    {
        history.Clear();
        for(int s=60;s>=0;s--)history.Add(DemoSample(end.AddSeconds(-s)));
    }
    private void UpdateTimer()
    {
        if(IsVisible && monitoring && !lifetime.IsCancellationRequested)timer.Start();
        else{timer.Stop();reading?.Cancel();}
    }
    private static RelaySnapshot DemoSample(DateTimeOffset time)
    {
        // Fixed fictional series for the offline dashboard only.
        long t=time.ToUnixTimeSeconds();
        double Wave(double period)=>Math.Sin(t*2*Math.PI/period);
        double down=9+1.8*Wave(26)+1.4*Wave(11)+1.1*Wave(5.5)+.8*Wave(4);
        double up=1.2+.29*Wave(15)+.22*Wave(6);
        int active=142+(int)(9*Wave(20)+6*Wave(7));
        var demo=PanelSession.ExampleStatus();
        var links=demo.Links.Select((l,i)=>{
            double part=i==0?.68:i==1?.22:.1;
            double d=down*125000*part,u=up*125000*part;
            int count=i==0?active*7/10:i==1?active*2/10:active-active*7/10-active*2/10;
            return l with {Assigned=(long)Math.Floor(t*5*part),Active=count,BytesPerSecond=d+u,
                UploadBytesPerSecond=u,DownloadBytesPerSecond=d,LatencyMs=l.LatencyMs+2*Wave(29+i)};
        }).ToArray();
        return new(time,t*5,links);
    }

    private async void RefreshClicked(object sender,RoutedEventArgs e)
    {
        if(session.Current==null){ConnectionRequested?.Invoke();return;}
        monitoring=true;await RefreshAsync();UpdateTimer();
    }
    private void ConnectClicked(object sender,RoutedEventArgs e)=>ConnectionRequested?.Invoke();
    private void LimitsClicked(object sender,RoutedEventArgs e)=>LimitsRequested?.Invoke();
    internal async Task StartMonitoring()
    {
        monitoring=true; await RefreshAsync();UpdateTimer();
    }
    private async Task RefreshAsync()
    {
        if(reading!=null || session.Current==null || lifetime.IsCancellationRequested)return;
        var key=identity;
        using var request=CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        reading=request;RefreshButton.IsEnabled=false;
        try{
            var sample=session.IsDemo?DemoSample(DateTimeOffset.UtcNow):await session.ReadRelayStatus(request.Token);
            if(request.IsCancellationRequested || key!=identity)return;
            var age=DateTimeOffset.UtcNow-sample.Time;
            if(sample.Links==null || age>TimeSpan.FromSeconds(30) || age<TimeSpan.FromSeconds(-30))
                throw new PanelException("Relay 快照时间异常或已过期，请检查服务和系统时间。");
            if(history.Count>0 && (sample.Time<history[^1].Time || sample.Time-history[^1].Time>TimeSpan.FromSeconds(18) ||
                sample.Sequence<history[^1].Sequence))history.Clear();
            if(session.IsDemo)SeedDemo(sample.Time);
            else if(history.Count==0 || history[^1].Time!=sample.Time)history.Add(sample);
            history.RemoveAll(s=>s.Time<sample.Time.AddSeconds(-60));
            error=null;
        }catch(OperationCanceledException) when(request.IsCancellationRequested){}
        catch(Exception ex){if(key==identity){error=MainWindow.Message(ex);monitoring=false;}}
        finally{
            reading=null;RefreshButton.IsEnabled=true;
            if(!lifetime.IsCancellationRequested){Render();UpdateTimer();}
        }
    }
    private void Render()
    {
        var host=session.Current;
        var last=history.LastOrDefault();
        bool fresh=last!=null && error==null && DateTimeOffset.UtcNow-last.Time<=TimeSpan.FromSeconds(30);
        string tone=fresh?"SystemFillColorSuccessBrush":error!=null?"SystemFillColorCautionBrush":"TextFillColorSecondaryBrush";
        Status.Text=session.IsDemo?"离线演示 · 运行中":host==null?"尚未连接 VPS":fresh?"已接管 VPS · 运行中":error!=null?"VPS 状态读取失败":"中转 VPS · 待刷新";
        Stamp.Text=last==null?"":$"采样于 {last.Time.LocalDateTime:HH:mm:ss}";
        StateDot.SetResourceReference(Shape.FillProperty,tone);
        FooterChanged?.Invoke(host==null?"尚未选择中转机":$"{(session.IsDemo?"演示中转":host.Target.Host)} · {(fresh?"运行中":"待刷新")}",tone);
        ReadError.Text=error;ReadError.Visibility=error==null?Visibility.Collapsed:Visibility.Visible;
        var sample=fresh?last:null;
        var seen=sample==null?Array.Empty<RelaySnapshot>():history.ToArray();
        ActiveCount.Text=sample?.Links.Sum(l=>l.Active).ToString("N0")??"—";
        ActiveNote.Text=sample==null?"等待运行快照":"当前 TCP 连接与 UDP 会话";
        var active=seen.Select(s=>new TrendPoint(s.Time,s.Links.Sum(l=>l.Active))).ToArray();
        ActiveTrend.Plot(active,active.Select(p=>p.First).DefaultIfEmpty(1).Max()*1.08,true);
        var total=session.IsDemo?new Bandwidth():host?.DeployedTotal;
        LimitState.Text=total==null?"整体限速 · 待核对":total.Enabled?"整体限速 · 已开启":"整体限速 · 已关闭";
        LimitState.ToolTip=total?.Enabled==true?$"上传 {total.Upload:g} / 下载 {total.Download:g} Mbps":"查看最近读取的已部署限速设置";
        SchedulerState.Text=sample==null?"拥堵调度 · 待采样":sample.AutoError==null?"拥堵调度 · 正常运行":"拥堵调度 · 无健康上游";
        var profiles=host?.Workspace.Snapshot?.Editable??[];
        var direct=host?.Workspace.Snapshot?.Outbounds.FirstOrDefault(e=>e.Kind=="中转直连")?.Tag;
        var ids=(sample?.Links.Select(l=>l.Id)??profiles.Select(p=>p.Id).Concat(direct==null?[]:[direct])).Distinct();
        var rows=ids.Select(id=>{
            var link=sample?.Links.FirstOrDefault(l=>l.Id==id);
            var profile=profiles.FirstOrDefault(p=>p.Id==id);
            bool isDirect=link?.Direct??(id==direct);
            var local=host?.Workspace.Items.FirstOrDefault(e=>e.Id==id);
            var aliases=local?.Aliases??profile?.Aliases;
            var name=(session.IsDemo?local?.Name:null)??profile?.Name??id;
            return new ExitRow(id,isDirect?"中转直连":name,isDirect?"直连":profile?.Protocol??"—",
                isDirect?"—":aliases==null?"—":$"{aliases.Length} 个",link?.LatencyMs>0?$"{link.LatencyMs:F0} ms":"—",
                link==null?"待采样":profile?.Enabled==false?"已停用":link.Healthy?"健康":"不可用");
        }).ToArray();
        ExitTable.ItemsSource=rows;HealthLines.ItemsSource=rows.Take(3);
        HealthEmpty.Visibility=TableEmpty.Visibility=rows.Length==0?Visibility.Visible:Visibility.Collapsed;
        bool split=sample?.Links.Length>0 && sample.Links.All(l=>l.DownloadBytesPerSecond.HasValue && l.UploadBytesPerSecond.HasValue);
        var traffic=seen.Where(s=>!split||s.Links.All(l=>l.DownloadBytesPerSecond.HasValue && l.UploadBytesPerSecond.HasValue))
            .Select(s=>new TrendPoint(s.Time,s.Links.Sum(l=>split?l.DownloadBytesPerSecond!.Value:l.BytesPerSecond)/125000,
                              split?s.Links.Sum(l=>l.UploadBytesPerSecond!.Value)/125000:null)).ToArray();
        PrimaryRate.Text=sample==null?"等待采样":$"{(split?"下行":"合计")} {traffic[^1].First:0.##}";
        UpRate.Text=split?$"上行 {traffic[^1].Second:0.##}":"";
        UpDot.Visibility=split?Visibility.Visible:Visibility.Collapsed;
        TrafficPlot.Plot(traffic,traffic.Select(p=>Math.Max(p.First,p.Second??0)).DefaultIfEmpty(1).Max()*1.12);
        PlotEmpty.Text=traffic.Length==0?"刷新后显示速率趋势":traffic.Length==1?"正在累积采样…":"";
        ShowShares(rows,seen);
    }
    private void ShowShares(ExitRow[] rows,RelaySnapshot[] samples)
    {
        ShareBar.Children.Clear();ShareBar.ColumnDefinitions.Clear();ShareLabels.Children.Clear();
        var counts=rows.ToDictionary(r=>r.Id,_=>0L);
        for(int i=1;i<samples.Length;i++){
            var before=samples[i-1].Links.ToDictionary(l=>l.Id,l=>l.Assigned);
            foreach(var link in samples[i].Links){
                if(!counts.ContainsKey(link.Id)||!before.TryGetValue(link.Id,out long old))continue;
                counts[link.Id]+=link.Assigned>=old?link.Assigned-old:link.Assigned;
            }
        }
        long total=counts.Values.Sum();
        ShareEmpty.Text=total>0?"":samples.Length<2?"等待新连接采样":"采样窗口内暂无新连接";
        var nonzero=rows.Where(r=>counts[r.Id]>0).ToArray();
        foreach(var (row,index) in rows.Select((r,i)=>(r,i))){
            if(total==0)break;
            double share=(double)counts[row.Id]/total;
            string color=row.Protocol=="直连"?"TextFillColorSecondaryBrush":index%2==0?"OverviewDown":"OverviewUp";
            double left=row==nonzero[0]?8:0,right=row==nonzero[^1]?8:0;
            var segment=new Border{CornerRadius=new CornerRadius(left,right,right,left)};
            segment.SetResourceReference(Border.BackgroundProperty,color);
            ShareBar.ColumnDefinitions.Add(new(){Width=new GridLength(share,GridUnitType.Star)});
            Grid.SetColumn(segment,index);ShareBar.Children.Add(segment);
            var legend=new DockPanel{Margin=new(0,2,0,0)};
            var percent=new TextBlock{Text=share.ToString("P0"),FontSize=12};DockPanel.SetDock(percent,Dock.Right);legend.Children.Add(percent);
            var dot=new Ellipse{Width=8,Height=8,Margin=new(0,0,7,0)};dot.SetResourceReference(Shape.FillProperty,color);legend.Children.Add(dot);
            legend.Children.Add(new TextBlock{Text=row.Name,FontSize=12,TextTrimming=TextTrimming.CharacterEllipsis,ToolTip=row.Name});
            ShareLabels.Children.Add(legend);
        }
    }
}
