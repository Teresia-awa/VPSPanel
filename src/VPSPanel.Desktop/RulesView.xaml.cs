using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class RulesView : UserControl
{
    private sealed record Row(string Id, string Name, bool Enabled, string Conditions, string Action, string Exit);
    private sealed record DefaultChoice(RouteAction Action, string? Exit, string Label);
    private bool loadingChoices;
    private PanelSession session = null!;
    private CancellationToken lifetime;
    private ManagedHost Host => session.Current ?? throw new PanelException("请先在首页读取主机快照。");
    private RoutingPolicy Policy => Host.Policy;
    private RelaySnapshot? snapshot;
    private ManagedHost? previous;
    private RuleEngine? engine;
    private Point dragOrigin;
    private string? dragId;
    private bool offline;

    public RulesView() => InitializeComponent();
    internal void Attach(PanelSession value, CancellationToken ct)
    {
        session=value; lifetime=ct; Publisher.Attach(session,ct);
        Publisher.HasUnsavedForm=()=>session.Current is {} h &&
            (!double.TryParse(Up.Text,out var up) || !double.TryParse(Down.Text,out var down) ||
             new Bandwidth(Limited.IsChecked==true,up,down)!=(h.Total??new Bandwidth()));
        session.Changed+=Refresh; Refresh();
    }
    private static string Label(RouteAction a) => a switch { RouteAction.Direct => "中转机直连", RouteAction.Fixed => "指定出口", _ => "自动分摊" };
    private void Refresh()
    {
        engine = null;
        if (session.Current is not { } host) { DefaultRoute.IsEnabled=false; DefaultRoute.ItemsSource=null; DefaultNotice.Text=""; Review.Text = "请先在首页读取主机快照。"; return; }
        if (previous?.Target != host.Target || previous?.Direct != host.Direct) snapshot = null;
        if (session.IsDemo && snapshot == null) { snapshot = PanelSession.ExampleStatus(); offline = true; }
        bool reloadLimit = previous?.Target != host.Target || previous?.Direct != host.Direct || previous?.Total != host.Total;
        previous = host;
        var p = host.Policy;
        var ruleId=(Rules.SelectedItem as Row)?.Id;
        var groupId=(Groups.SelectedItem as Row)?.Id;
        Rules.ItemsSource = p.WebsiteRules.Select(r => new Row(r.Id, r.Name, r.Enabled, r.Group == null ? string.Join("、", r.Entries) : p.Groups.FirstOrDefault(g => g.Id == r.Group)?.Name ?? "—", Label(r.Action), r.Exit ?? "—")).ToArray();
        Groups.ItemsSource = p.Groups.Select(g => new Row(g.Id, g.Name, g.Enabled, string.Join("、", g.Entries), "—", "—")).ToArray();
        Rules.SelectedItem=Rules.Items.Cast<Row>().FirstOrDefault(r=>r.Id==ruleId);
        Groups.SelectedItem=Groups.Items.Cast<Row>().FirstOrDefault(r=>r.Id==groupId);
        if(reloadLimit){
            var limits = host.Total ?? new(); Limited.IsChecked = limits.Enabled; Up.Text = limits.Upload.ToString(); Down.Text = limits.Download.ToString();
        }
        LoadDefaultChoices(host);
        var review = host.Workspace.Snapshot?.ReviewOrders ?? [];
        Review.Text = review.Length == 0 ? "" : $"原配置第 {string.Join("、", review)} 条含其他匹配条件，保留在首页快照中，接管前需人工核对。";
        Evaluate();
    }
    private void LoadDefaultChoices(ManagedHost host)
    {
        loadingChoices=true;
        try {
            var current=host.Policy.DefaultRule;
            var choices=new List<DefaultChoice>{new(RouteAction.Auto,null,"自动分摊"),new(RouteAction.Direct,null,"中转机直连")};
            foreach(var exit in ExitChoices.ForHost(host,current?.Exit))
                choices.Add(new(RouteAction.Fixed,exit.Id,exit.Label));
            DefaultRoute.IsEnabled=true;
            DefaultRoute.ItemsSource=choices;
            DefaultRoute.SelectedItem=choices.Single(c=>c.Action==(current?.Action??RouteAction.Auto) && c.Exit==current?.Exit);
            DefaultNotice.Text="";
        } finally {loadingChoices=false;}
    }
    private void DefaultRouteChanged(object sender,SelectionChangedEventArgs e)
    {
        if(loadingChoices || session?.Current is not {} host || DefaultRoute.SelectedItem is not DefaultChoice choice)return;
        try {
            Persist(host.Policy.WithDefault(choice.Action,choice.Exit));
            DefaultNotice.Text="已保存到本地草稿";
        } catch(Exception ex){
            LoadDefaultChoices(host);
            DefaultNotice.Text=MainWindow.Message(ex);
        }
    }
    private void Run(Action action) { try { action(); Notice.Text = ""; } catch (Exception ex) { Notice.Text = MainWindow.Message(ex); } }
    private void Persist(RoutingPolicy policy) => session.SaveRules(policy, Host.Total ?? new());
    private static Row Selected(DataGrid grid) => grid.SelectedItem as Row ?? throw new PanelException("请先选择一行。");
    private void Editor(bool group, bool create) => Run(() => { _ = Host; new RuleEditor(session, group, create ? null : Selected(group ? Groups : Rules).Id) { Owner = Window.GetWindow(this) }.ShowDialog(); });
    private void NewRule(object s, RoutedEventArgs e) => Editor(false, true);
    private void EditRule(object s, RoutedEventArgs e) => Editor(false, false);
    private void NewGroup(object s, RoutedEventArgs e) => Editor(true, true);
    private void EditGroup(object s, RoutedEventArgs e) => Editor(true, false);
    private bool Confirm(string name) => MessageBox.Show(Window.GetWindow(this), "删除「" + name + "」？", "确认删除", MessageBoxButton.YesNo) == MessageBoxResult.Yes;
    private void RemoveRule(object s, RoutedEventArgs e) => Run(() => { var r = Selected(Rules); if (Confirm(r.Name)) Persist(Policy with { Rules = Policy.Rules.Where(x => x.Id != r.Id).ToArray() }); });
    private void RemoveGroup(object s, RoutedEventArgs e) => Run(() =>
    {
        var g = Selected(Groups);
        var refs = Policy.Rules.Where(r => r.Group == g.Id).Select(r => r.Name).ToArray();
        if (refs.Length == 0) { if (Confirm(g.Name)) Persist(Policy.RemoveGroup(g.Id, true)); return; }
        var dialog = new ChangeDialog("删除规则集「" + g.Name + "」", "下列网站规则使用此规则集。保留规则会将匹配条件复制到各规则，并保留当前启停效果。", refs, "保留网站规则", "一并删除这些规则") { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() == true) Persist(Policy.RemoveGroup(g.Id, !dialog.SecondChoice));
    });
    private void ToggleRule(object s, RoutedEventArgs e) => Run(() => { var r = (Row)((CheckBox)s).DataContext; Persist(Policy with { Rules = Policy.Rules.Select(x => x.Id == r.Id ? x with { Enabled = !r.Enabled } : x).ToArray() }); });
    private void ToggleGroup(object s, RoutedEventArgs e) => Run(() => { var g = (Row)((CheckBox)s).DataContext; Persist(Policy with { Groups = Policy.Groups.Select(x => x.Id == g.Id ? x with { Enabled = !g.Enabled } : x).ToArray() }); });
    private void Move(string id, int index)
    {
        var rules = Policy.WebsiteRules.ToList(); var r = rules.Single(x => x.Id == id); rules.Remove(r);
        int dest = Math.Clamp(index, 0, rules.Count); rules.Insert(dest, r); Persist(Policy.WithWebsiteRules(rules)); Rules.SelectedIndex = dest;
    }
    private void MoveUp(object s, RoutedEventArgs e) => Run(() => Move(Selected(Rules).Id, Rules.SelectedIndex - 1));
    private void MoveDown(object s, RoutedEventArgs e) => Run(() => Move(Selected(Rules).Id, Rules.SelectedIndex + 1));
    private Row? Under(object? source) => source is DependencyObject d && ItemsControl.ContainerFromElement(Rules, d) is DataGridRow row ? row.Item as Row : null;
    private void DragStart(object s, MouseButtonEventArgs e) { dragOrigin = e.GetPosition(Rules); dragId = Under(e.OriginalSource)?.Id; }
    private void DragMove(object s, MouseEventArgs e)
    {
        if (e.LeftButton != MouseButtonState.Pressed || dragId == null) return;
        var delta = e.GetPosition(Rules) - dragOrigin;
        if (Math.Abs(delta.Y) < SystemParameters.MinimumVerticalDragDistance) return;
        var id = dragId; dragId = null; DragDrop.DoDragDrop(Rules, new DataObject("PanelRule", id), DragDropEffects.Move);
    }
    private void Dropped(object s, DragEventArgs e) => Run(() => { if (e.Data.GetData("PanelRule") is string id && Under(e.OriginalSource) is Row row && Policy.Rules.Any(r => r.Id == id)) Move(id, Array.FindIndex(Policy.Rules, r => r.Id == row.Id)); });
    private void ImportGeo(object s, RoutedEventArgs e) => Run(() =>
    {
        var picker = new OpenFileDialog { Filter = "Xray Geo 数据|geosite.dat;geoip.dat", Multiselect = true };
        if (picker.ShowDialog() != true) return;
        Directory.CreateDirectory(session.GeoDirectory);
        foreach (var path in picker.FileNames)
        {
            var file = Path.GetFileName(path).ToLowerInvariant();
            if (file is not ("geoip.dat" or "geosite.dat")) throw new PanelException("请选择 geoip.dat 或 geosite.dat。");
            string dest = Path.Combine(session.GeoDirectory, file), temp = dest + Guid.NewGuid().ToString("N");
            try { File.Copy(path, temp); File.Move(temp, dest, true); } finally { File.Delete(temp); }
        }
        engine = null; Evaluate();
    });
    private void SaveLimit(object s, RoutedEventArgs e) => Run(() =>
    {
        bool on = Limited.IsChecked == true;
        if (!double.TryParse(Up.Text, out var up) || !double.TryParse(Down.Text, out var down)) throw new PanelException("请输入数值 Mbps。");
        session.SaveRules(Policy, new(on, up, down));
    });
    private void Export(object s, RoutedEventArgs e) => Run(() =>
    {
        var update = session.RuleUpdate();
        var picker = new SaveFileDialog { Filter = "规则方案|*.json", FileName = "rules.json", InitialDirectory = LocalSettings.DataDirectory };
        if (picker.ShowDialog() == true) File.WriteAllText(picker.FileName, JsonSerializer.Serialize(update, new JsonSerializerOptions { WriteIndented = true }));
    });
    private async void ApplyLab(object sender, RoutedEventArgs e)
    {
        if (session.Current is not { } h || session.IsDemo || !System.Net.IPAddress.TryParse(h.Target.Host, out var ip) || !System.Net.IPAddress.IsLoopback(ip))
        {
            Notice.Text = "此操作仅供本机回环 IP 的隔离 Relay 使用。"; return;
        }
        if (MessageBox.Show(Window.GetWindow(this), "将当前出口、规则和限速同步到本机隔离 Relay。新连接按新方案分配。继续？", "同步隔离环境", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        IsEnabled = false;
        try { await session.ApplyToLabRelay(lifetime); snapshot = await session.ReadRelayStatus(lifetime); offline = false; Evaluate(); Notice.Text = "隔离 Relay 已校验并保存配置。"; }
        catch (Exception ex) { Notice.Text = MainWindow.Message(ex); }
        finally { IsEnabled = true; }
    }
    private async void ReadStatus(object s, RoutedEventArgs e)
    {
        var before = session.Current;
        try { var result = await session.ReadRelayStatus(lifetime); if (session.Current != before) return; snapshot = result; offline = false; Notice.Text = ""; Evaluate(); }
        catch (Exception ex) { Notice.Text = MainWindow.Message(ex); snapshot = null; Evaluate(); }
    }
    private void OpenStatus(object s, RoutedEventArgs e) => Run(() =>
    {
        var picker = new OpenFileDialog { Filter = "Relay 状态快照|*.json" };
        if (picker.ShowDialog() != true) return;
        var result = JsonSerializer.Deserialize<RelaySnapshot>(File.ReadAllBytes(picker.FileName));
        if (result?.Links == null || result.Time == default || result.Links.Any(l => l == null || string.IsNullOrWhiteSpace(l.Id))) throw new PanelException("Relay 状态快照无效。");
        snapshot = result; offline = true; Evaluate();
    });
    private void TargetChanged(object s, TextChangedEventArgs e) => Evaluate();
    private void Evaluate()
    {
        if (Preview == null || session?.Current == null) return;
        if (string.IsNullOrWhiteSpace(Target.Text)) { Preview.Text = "输入目标以查看命中规则、规则集与预计出口。"; return; }
        try
        {
            engine ??= new RuleEngine(Policy, new(session.GeoDirectory));
            var direct = Host.Workspace.Snapshot?.Outbounds.FirstOrDefault(o => o.Kind == "中转直连")?.Tag;
            var enabled = Host.Workspace.Items.Where(x => x.Enabled).Select(x => x.Id).Append(direct).ToHashSet();
            var state = snapshot ?? new RelaySnapshot(default, 0, []);
            var links = state.Links.Where(l => enabled.Contains(l.Id)).ToList();
            if (direct != null && links.All(l => l.Id != direct)) links.Add(new(direct, true, false, 0, 0, 0, 0, 0, 0, 0));
            var d = engine.Select(Target.Text, state with { Links = links.ToArray() });
            string status = snapshot == null ? "尚未读取 Relay 健康快照" : (session.IsDemo ? "演示快照" : offline ? "离线快照" : "Relay 快照") + " · " + state.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            if (snapshot != null && !offline && DateTimeOffset.UtcNow - state.Time > TimeSpan.FromSeconds(30)) status += "（历史采样，请刷新）";
            Preview.Text = $"{d.Rule}  →  {d.Group}  →  {Label(d.Action)}\n{status}\n" +
                (d.FailoverReason==null?"":d.FailoverReason+"\n") +
                (d.Action == RouteAction.Auto ? $"健康候选：{(d.Candidates.Length > 0 ? string.Join("、", d.Candidates) : "无")}　预计出口：{d.Exit ?? "—"}" : $"{(d.FailoverReason==null?"绑定出口":"备用出口")}：{d.Exit ?? "—"}　状态：{(d.Error == null ? "健康" : "不可用或未知")}") +
                (d.Error == null ? "" : "\n" + d.Error);
        }
        catch (Exception ex) { Preview.Text = MainWindow.Message(ex); }
    }
}
