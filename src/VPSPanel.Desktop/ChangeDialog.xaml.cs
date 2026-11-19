using System.Windows;

namespace VPSPanel.Desktop;

public partial class ChangeDialog : Window
{
    internal bool SecondChoice { get; private set; }
    internal ChangeDialog(string title,string description,IReadOnlyList<string> lines,string accept,string? alternate=null)
    {
        InitializeComponent();
        Title=title; Description.Text=description; Lines.ItemsSource=lines; Accept.Content=accept;
        Alternate.Content=alternate; Alternate.Visibility=alternate==null?Visibility.Collapsed:Visibility.Visible;
    }
    private void Choose(object sender,RoutedEventArgs e) { SecondChoice=sender==Alternate; DialogResult=true; }
}
