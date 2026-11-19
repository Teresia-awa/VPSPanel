using System.IO;
using System.Net;
using System.Windows;
using Microsoft.Win32;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class RuleEditor : Window
{
    private readonly bool groupMode;
    private readonly ManagedHost host;
    private readonly PanelSession session;
    private readonly string id;
    private readonly bool enabled;
    internal RuleEditor(PanelSession session, bool groupMode, string? selected)
    {
        InitializeComponent();
        this.session = session; this.groupMode = groupMode; host = session.Current ?? throw new PanelException("请先读取主机快照。");
        var rule = host.Policy.Rules.FirstOrDefault(r => !groupMode && r.Id == selected);
        var group = host.Policy.Groups.FirstOrDefault(g => groupMode && g.Id == selected);
        id = selected ?? Guid.NewGuid().ToString("N"); enabled = rule?.Enabled ?? group?.Enabled ?? true;
        Title = groupMode ? "编辑规则集" : "编辑网站规则"; TitleBox.Text = rule?.Name ?? group?.Name ?? "";
        Lines.Text = string.Join(Environment.NewLine, rule?.Entries ?? group?.Entries ?? []);
        RuleFields.Visibility = groupMode ? Visibility.Collapsed : Visibility.Visible;
        Group.ItemsSource = new[] { new RuleSet("", "直接填写", true, []) }.Concat(host.Policy.Groups);
        Group.SelectedValue = rule?.Group ?? ""; ActionBox.SelectedIndex = (int)(rule?.Action ?? RouteAction.Auto);
        Exit.ItemsSource = host.Workspace.Items.ToArray(); Exit.SelectedValue = rule?.Exit;
        ChoiceChanged(this, new RoutedEventArgs());
    }
    private void ChoiceChanged(object sender, RoutedEventArgs e)
    {
        if (Manual == null) return;
        Manual.Visibility = groupMode || string.IsNullOrEmpty(Group.SelectedValue as string) ? Visibility.Visible : Visibility.Collapsed;
        Bound.Visibility = ActionBox.SelectedIndex == 2 ? Visibility.Visible : Visibility.Collapsed;
    }
    private void Import(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Filter = "文本文件|*.txt;*.list;*.conf|所有文件|*.*" };
        if (picker.ShowDialog(this) != true) return;
        try { Lines.AppendText(Environment.NewLine + File.ReadAllText(picker.FileName)); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { ErrorText.Text = MainWindow.Message(ex); }
    }
    private void Save(object sender, RoutedEventArgs e)
    {
        try
        {
            string name = TitleBox.Text.Trim();
            if (name.Length == 0) throw new PanelException("请填写名称。");
            var entries = Lines.Text.Split(['\n', '\r'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Where(s => !s.StartsWith('#')).Select(s => IPAddress.TryParse(s, out _) || System.Net.IPNetwork.TryParse(s, out _) ? "ip:" + s : s.Contains(':') ? s : "domain:" + s).Distinct().ToArray();
            var policy = host.Policy;
            if (groupMode)
            {
                var next = new RuleSet(id, name, enabled, entries);
                policy = policy with { Groups = Replace(policy.Groups, g => g.Id == id, next) };
            }
            else
            {
                var group = Group.SelectedValue as string;
                var action = (RouteAction)ActionBox.SelectedIndex;
                var next = new SiteRule(id, name, enabled, string.IsNullOrEmpty(group) ? null : group, string.IsNullOrEmpty(group) ? entries : [], action, action == RouteAction.Fixed ? Exit.SelectedValue as string : null);
                policy = policy.WithWebsiteRules(Replace(policy.WebsiteRules.ToArray(), r => r.Id == id, next));
            }
            session.SaveRules(policy, host.Total ?? new()); DialogResult = true;
        }
        catch (Exception ex) { ErrorText.Text = MainWindow.Message(ex); }
    }
    private static T[] Replace<T>(T[] items, Func<T, bool> match, T value) => items.Any(match) ? items.Select(x => match(x) ? value : x).ToArray() : [.. items, value];
}
