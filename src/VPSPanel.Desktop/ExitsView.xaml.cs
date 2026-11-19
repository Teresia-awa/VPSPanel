using System.Windows;
using System.Windows.Controls;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class ExitsView : UserControl
{
    private PanelSession session = null!;
    private CancellationToken lifetime;
    private ExitProfile model = new();
    private bool creating, loading, dirty;
    private PanelSession.CheckedExit? checkedExit;

    public ExitsView()
    {
        InitializeComponent();
        Editor.AddHandler(TextBox.TextChangedEvent, new TextChangedEventHandler(Edited));
        Auth.PasswordChanged += (_, _) => { if(!loading)dirty=true; InvalidateCheck(); };
        EnabledBox.Click+=(_,_)=>dirty=true;
        Limit.Click+=(_,_)=>dirty=true;
        Publisher.HasUnsavedForm=()=>dirty;
    }

    internal void Attach(PanelSession value, CancellationToken token)
    {
        session = value;
        lifetime = token;
        Publisher.Attach(session,token);
        session.Changed += Refresh;
        Refresh();
    }

    private void Refresh()
    {
        var host = session.Current;
        var items = host?.Workspace.Items.ToArray() ?? [];
        loading = true;
        List.ItemsSource = items;
        var selected = items.FirstOrDefault(x => x.Id == StableId.Text) ?? items.FirstOrDefault();
        List.SelectedItem = selected;
        loading = false;
        Editor.IsEnabled = AddButton.IsEnabled = host != null;
        ContextText.Text = host == null ? "请先在首页只读读取中转 VPS。" :
            $"{host.Target.Host} · {items.Length} 个上游。启停、地址和限速修改保存到本机草稿。";
        Fill(selected ?? NewExit(), selected == null);
    }

    private static ExitProfile NewExit() => new() { Id = "exit-" + Guid.NewGuid().ToString("N")[..8] };
    private void Fill(ExitProfile item, bool isNew)
    {
        loading = true;
        model = item;
        creating = isNew;
        checkedExit = null;
        EditTitle.Text = isNew ? "添加出口" : "编辑出口";
        ExitName.Text = item.Name;
        StableId.Text = item.Id;
        StableId.IsReadOnly = !isNew;
        Protocol.SelectedIndex = item.Protocol == "HY2" ? 0 : 1;
        Protocol.IsEnabled = isNew;
        Host.Text = item.Host;
        Sni.Text = item.Sni;
        Port.Text = item.Port.ToString();
        Auth.Password = item.Secret;
        Public.Text = item.PublicKey;
        Short.Text = item.ShortId;
        Flow.Text = item.Flow;
        Fingerprint.Text = item.Fingerprint;
        Aliases.Text = string.Join(Environment.NewLine, item.Aliases);
        EnabledBox.IsChecked = item.Enabled;
        Limit.IsChecked = item.Limited;
        Upload.Text = item.Up.ToString();
        Download.Text = item.Down.ToString();
        Link.Clear();
        ImportPane.IsExpanded = false;
        DeleteButton.IsEnabled = !isNew;
        ProbeText.Text = item.LastProbe is { } probe ? Feedback(probe) : "待预检 · DNS 解析、协议握手、代理请求";
        loading = false;
        dirty = false;
        ShowProtocol();
    }

    private static string Feedback(ProbeResult p)
    {
        string verdict(bool ok) => ok ? "通过" : "未通过";
        return $"DNS {verdict(p.Dns)}　握手 {(p.Dns ? verdict(p.Handshake) : "未执行")}　代理请求 {(p.Handshake ? verdict(p.Request) : "未执行")}\n{p.Detail}　{p.Milliseconds} ms　{p.At.LocalDateTime:t}";
    }

    private void SelectExit(object sender, SelectionChangedEventArgs e)
    {
        if (!loading && List.SelectedItem is ExitProfile selected) Fill(selected, false);
    }
    private void Add(object sender, RoutedEventArgs e) { List.SelectedIndex = -1; Fill(NewExit(), true); }
    private void Import(object sender, RoutedEventArgs e)
    {
        try
        {
            var imported = ShareLink.Parse(Link.Password);
            if (!creating)
            {
                var aliases = AliasList().Append(Host.Text.Trim()).Where(h => h.Length > 0 && !h.Equals(imported.Host, StringComparison.OrdinalIgnoreCase));
                imported = imported with
                {
                    Id = model.Id,
                    Name = ExitName.Text,
                    Aliases = aliases.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                    Enabled = EnabledBox.IsChecked == true,
                    Limited = Limit.IsChecked == true,
                    Up = decimal.TryParse(Upload.Text, out var up) ? up : 0,
                    Down = decimal.TryParse(Download.Text, out var down) ? down : 0
                };
            }
            Fill(imported, creating);
            dirty=true;
        }
        catch (Exception ex) { ProbeText.Text = MainWindow.Message(ex); }
    }
    private void ShowProtocol()
    {
        bool reality = Protocol.SelectedIndex == 1;
        Advanced.Visibility = reality ? Visibility.Visible : Visibility.Collapsed;
        AuthLabel.Text = reality ? "VLESS 用户 ID" : "认证口令";
    }
    private void ProtocolChanged(object sender, SelectionChangedEventArgs e)
    {
        if (loading || Advanced == null) return;
        dirty=true;
        ShowProtocol();
        InvalidateCheck();
    }
    private void Edited(object sender, TextChangedEventArgs e)
    {
        if(!loading)dirty=true;
        if (e.OriginalSource == ExitName || e.OriginalSource == Aliases || e.OriginalSource == Upload || e.OriginalSource == Download) return;
        InvalidateCheck();
    }
    private void InvalidateCheck()
    {
        if (loading || ProbeText == null) return;
        checkedExit = null;
        ProbeText.Text = "请按当前连接参数预检。";
    }
    private string[] AliasList() => Aliases.Text.Split(['\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    private void AliasesChanged(object sender, TextChangedEventArgs e)
    {
        if (Candidates == null) return;
        Candidates.ItemsSource = AliasList();
        Candidates.SelectedIndex = 0;
    }
    private void ChooseAlias(object sender, RoutedEventArgs e)
    {
        if (Candidates.SelectedItem is not string next) return;
        var previous = Host.Text.Trim();
        Aliases.Text = string.Join(Environment.NewLine, AliasList().Where(h => !h.Equals(next, StringComparison.OrdinalIgnoreCase)).Append(previous).Where(h => h.Length > 0));
        Host.Text = next;
    }

    private ExitProfile Candidate()
    {
        if (!int.TryParse(Port.Text, out var port)) throw new PanelException("请填写有效出口端口。");
        bool limited = Limit.IsChecked == true;
        bool validUp = decimal.TryParse(Upload.Text, out var up);
        bool validDown = decimal.TryParse(Download.Text, out var down);
        if (limited && (!validUp || !validDown)) throw new PanelException("请填写有效的上传及下载 Mbps。");
        string protocol = Protocol.SelectedIndex == 1 ? "VLESS REALITY" : "HY2";
        var item = model with
        {
            Id = StableId.Text.Trim(),
            Name = ExitName.Text.Trim(),
            Protocol = protocol,
            Host = Host.Text.Trim(),
            Sni = Sni.Text.Trim(),
            Port = port,
            Secret = Auth.Password,
            PublicKey = Public.Text.Trim(),
            ShortId = Short.Text.Trim(),
            Flow = Flow.Text.Trim(),
            Fingerprint = Fingerprint.Text.Trim(),
            Aliases = AliasList(),
            Enabled = EnabledBox.IsChecked == true,
            Limited = limited,
            Up = up,
            Down = down,
            Original = protocol == model.Protocol ? model.Original : new()
        };
        item.Validate();
        return item;
    }

    private async void Probe(object sender, RoutedEventArgs e)
    {
        try
        {
            var candidate = Candidate();
            if (MessageBox.Show(Window.GetWindow(this),
                $"将通过 SSH 在 {session.Current!.Target.Host} 启动短时候选进程，并通过候选出口请求 HTTPS 测试站。结束后清理临时套接字。继续预检？",
                "预检候选出口", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
            var host = session.Current;
            IsEnabled = false;
            checkedExit = null;
            ProbeText.Text = "正在检查 DNS、握手和代理请求…";
            var result = await session.Probe(candidate, lifetime);
            if (host == session.Current)
            {
                checkedExit = result;
                ProbeText.Text = Feedback(result.Result);
            }
        }
        catch (Exception ex) { ProbeText.Text = MainWindow.Message(ex); }
        finally { IsEnabled = true; }
    }
    private void Save(object sender, RoutedEventArgs e)
    {
        try
        {
            session.SaveExit(Candidate(), creating, checkedExit);
            ProbeText.Text = "本机草稿已加密保存。" + (model.LastProbe is null ? "" : "\n" + Feedback(model.LastProbe));
        }
        catch (Exception ex) { ProbeText.Text = MainWindow.Message(ex); }
    }
    private void Delete(object sender, RoutedEventArgs e)
    {
        try
        {
            var refs = session.Current!.ManagedRevision == null ? session.Current.Workspace.References(model.Id) : [];
            var bindings=session.Current.Policy.Rules.Where(r=>r.Action==RouteAction.Fixed && r.Exit==model.Id).Select(r=>r.Name).ToArray();
            if(bindings.Length>0){MessageBox.Show(Window.GetWindow(this),"请先修改以下分流绑定："+string.Join("、",bindings),"删除出口");return;}
            if (refs.Length > 0)
            {
                MessageBox.Show(Window.GetWindow(this), "固定规则 " + string.Join("、", refs) + " 仍引用此出口。请先调整绑定。", "删除出口");
                return;
            }
            if (MessageBox.Show(Window.GetWindow(this), $"没有固定规则引用「{model.Name}」。从本机草稿中删除？", "删除出口",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes) session.DeleteExit(model.Id);
        }
        catch (Exception ex) { ProbeText.Text = MainWindow.Message(ex); }
    }
}
