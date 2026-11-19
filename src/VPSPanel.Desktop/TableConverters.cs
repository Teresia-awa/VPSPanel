using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace VPSPanel.Desktop;

public sealed class EmptyField : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        string.IsNullOrWhiteSpace(value?.ToString()) ? "—" : value!;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}

// Windows permits custom accent colors. Choose between the current theme's two text brushes.
public sealed class AccentText : IValueConverter
{
    private static double Luminance(Color color)
    {
        double Linear(byte channel) { double c = channel / 255d; return c <= .04045 ? c / 12.92 : Math.Pow((c + .055) / 1.055, 2.4); }
        return .2126 * Linear(color.R) + .7152 * Linear(color.G) + .0722 * Linear(color.B);
    }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not SolidColorBrush background) return DependencyProperty.UnsetValue;
        var brushes = new[] { "TextFillColorPrimaryBrush", "TextOnAccentFillColorPrimaryBrush" }
            .Select(key => Application.Current.TryFindResource(key)).OfType<SolidColorBrush>();
        double surface = Luminance(background.Color);
        return brushes.MaxBy(b => (Math.Max(surface, Luminance(b.Color)) + .05) / (Math.Min(surface, Luminance(b.Color)) + .05)) as object ?? DependencyProperty.UnsetValue;
    }
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => Binding.DoNothing;
}
