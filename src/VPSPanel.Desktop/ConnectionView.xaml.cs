using System.Windows;
using System.Windows.Controls;
using VPSPanel.Core;

namespace VPSPanel.Desktop;

public partial class ConnectionView : UserControl
{
    private PanelSession session = null!;
    private CancellationToken lifetime;
    private CancellationTokenSource? operation;
    private bool updating;
    public ConnectionView() => InitializeComponent();
    internal event Action? ConfigurationRead;

    internal void Attach(PanelSession model, CancellationToken token)
    {
        session = model;
        lifetime = token;
        session.ConfirmFingerprint ??= fingerprint => Dispatcher.Invoke(() =>
            !lifetime.IsCancellationRequested && MessageBox.Show(Window.GetWindow(this),
                $"首次直连 {fingerprint.Host}（端口 {fingerprint.Port}）\n算法　{fingerprint.Algorithm}\n{fingerprint.Sha256}\n\n请与 VPS 控制台提供的 SSH 主机指纹核对。是否信任并继续登录？",
                "确认 SSH 主机指纹", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes);
        ShowSnapshot();
        if (session.Current is { Direct: { } profile } direct)
        {
            DirectMode.IsChecked = true;
            Address.Text = direct.Target.Host;
            DirectPort.Text = (direct.Target.Port ?? 22).ToString();
            DirectUser.Text = direct.Target.User;
            DirectService.Text = direct.Target.Service;
            KeyMode.IsChecked = profile.KeyFile != null;
            KeyPath.Text = profile.KeyFile ?? "";
        }
        else if (session.Current is { } host)
        {
            HostBox.Text = host.Target.Host;
            Account.Text = host.Target.User;
            PortBox.Text = host.Target.Port?.ToString() ?? "";
            Service.Text = host.Target.Service;
        }
        UpdateMode();
    }

    private void ModeChanged(object sender, RoutedEventArgs e)
    {
        if (session != null) UpdateMode();
    }
    private void UpdateMode()
    {
        bool direct = DirectMode.IsChecked == true;
        bool key = KeyMode.IsChecked == true;
        AliasFields.Visibility = direct ? Visibility.Collapsed : Visibility.Visible;
        DirectFields.Visibility = direct ? Visibility.Visible : Visibility.Collapsed;
        KeyFields.Visibility = key ? Visibility.Visible : Visibility.Collapsed;
        PasswordFields.Visibility = key ? Visibility.Collapsed : Visibility.Visible;
        Notice.Text = direct ? "首次直连时请核对 SSH 主机指纹。" : "使用本机 OpenSSH 与已信任的主机指纹。用户和端口可留空。";
        AlignActions(direct && !key && operation==null);
        RefreshCredentials();
    }
    private void IdentityChanged(object sender, TextChangedEventArgs e)
    {
        if (session != null) RefreshCredentials();
    }
    private SshTarget? FormAccount() => !string.IsNullOrWhiteSpace(Address.Text) && !string.IsNullOrWhiteSpace(DirectUser.Text)
        && int.TryParse(DirectPort.Text.Trim(), out var port) && port is > 0 and <= 65535
        ? new(Address.Text.Trim(), DirectUser.Text.Trim(), port, DirectService.Text.Trim()) : null;

    private void RefreshCredentials()
    {
        updating = true;
        LoginSecret.Clear();
        KeySecret.Clear();
        try
        {
            bool saved = DirectMode.IsChecked == true && KeyMode.IsChecked != true &&
                FormAccount() is { } account && session.HasSavedPassword(account);
            Remember.IsChecked = saved;
            SavedHint.Visibility = saved ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex) { Notice.Text = MainWindow.Message(ex); }
        finally { updating = false; }
    }
    private void Forget(object sender, RoutedEventArgs e)
    {
        if (updating || session == null || FormAccount() is not { } target) return;
        try { session.ForgetPassword(target); SavedHint.Visibility = Visibility.Collapsed; }
        catch (Exception ex) { Remember.IsChecked = true; Notice.Text = MainWindow.Message(ex); }
    }
    private void AlignActions(bool besidePassword)
    {
        var target=besidePassword?PasswordActions:DefaultActions;
        if(ReferenceEquals(target.Content,ActionButtons))return;
        if(ActionButtons.Parent is ContentControl previous)previous.Content=null;
        ActionButtons.HorizontalAlignment=besidePassword?HorizontalAlignment.Stretch:HorizontalAlignment.Left;
        target.Content=ActionButtons;
    }

    private void ChooseKey(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "选择 SSH 私钥文件", CheckFileExists = true };
        if (dialog.ShowDialog(Window.GetWindow(this)) == true) { KeyPath.Text = dialog.FileName; KeySecret.Clear(); }
    }

    private void ShowSnapshot()
    {
        if (session.Current is not { Workspace.Snapshot: { } snapshot } host) return;
        Details.Visibility = Visibility.Visible;
        HostLabel.Text = host.Target.Host;
        VersionLabel.Text = "Xray " + host.Version;
        SftpLabel.Text = host.Sftp ? "✓ SFTP 可用" : "SFTP 不可用";
        SftpBadge.SetResourceReference(Border.BackgroundProperty, host.Sftp ? "SystemFillColorSuccessBackgroundBrush" : "SystemFillColorCautionBackgroundBrush");
        ReadTime.Text = host.ReadAt.LocalDateTime.ToString("g");
        Summary.Text = host.ConfigPath;
        Ingress.ItemsSource = host.LastReadTopology?.Inbounds ?? snapshot.Inbounds;
        Outbounds.ItemsSource = host.LastReadTopology?.Outbounds ?? snapshot.Outbounds;
        Routes.ItemsSource = host.LastReadTopology?.Rules ?? snapshot.Rules;
    }

    private async void Read(object sender, RoutedEventArgs e)
    {
        using var source = CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        operation = source;
        AlignActions(false);
        ReadButton.IsEnabled = false;
        LoginFields.IsEnabled = false;
        CancelButton.Visibility = Visibility.Visible;
        Notice.Text = "正在核对运行进程、内核版本和配置…";
        try
        {
            bool direct = DirectMode.IsChecked == true;
            string portText = (direct ? DirectPort : PortBox).Text.Trim();
            if (portText.Length > 0 && !int.TryParse(portText, out _)) throw new PanelException("SSH 端口须为整数。");
            var target = direct ? FormAccount() ?? throw new PanelException("请填写主机、有效端口和 SSH 用户名。") : new SshTarget(HostBox.Text.Trim(), Account.Text.Trim(),
                portText.Length == 0 ? null : int.Parse(portText), Service.Text.Trim());
            DirectLogin? login = null;
            if (direct && KeyMode.IsChecked == true)
            {
                if (string.IsNullOrWhiteSpace(KeyPath.Text)) throw new PanelException("请选择本地私钥文件。");
                login = new(new(KeyPath.Text.Trim()), KeySecret.Password);
            }
            else if (direct) login = new(new(), LoginSecret.Password, Remember.IsChecked == true);
            await session.ReadOnly(target, source.Token, login);
            ShowSnapshot();
            if (direct && Remember.IsChecked == true && KeyMode.IsChecked != true)
            {
                LoginSecret.Clear();
                SavedHint.Visibility = Visibility.Visible;
            }
            Notice.Text = "读取完成，快照已在本机加密保存。可到「出口管理」编辑。";
            ConfigurationRead?.Invoke();
        }
        catch (Exception ex) { Notice.Text = MainWindow.Message(ex); }
        finally { operation = null; LoginFields.IsEnabled = ReadButton.IsEnabled = true; CancelButton.Visibility = Visibility.Collapsed; AlignActions(DirectMode.IsChecked==true && KeyMode.IsChecked!=true); }
    }
    private void Cancel(object sender, RoutedEventArgs e) => operation?.Cancel();
}
