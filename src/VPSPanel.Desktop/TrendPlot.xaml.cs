using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace VPSPanel.Desktop;

internal readonly record struct TrendPoint(DateTimeOffset Time, double First, double? Second = null);

public partial class TrendPlot : UserControl
{
    private IReadOnlyList<TrendPoint> samples=[];
    private double ceiling=1;
    private bool spark;
    public TrendPlot()=>InitializeComponent();
    internal void Plot(IReadOnlyList<TrendPoint> points,double maximum,bool sparkline=false)
    {
        samples=points; ceiling=Math.Max(maximum,.001); spark=sparkline; Draw();
    }
    private void Resized(object sender,SizeChangedEventArgs e)=>Draw();
    private void Draw()
    {
        if(Surface==null)return;
        Guides.Visibility=spark?Visibility.Collapsed:Visibility.Visible;
        var primary=new PointCollection();var secondary=new PointCollection();
        double w=Math.Max(0,ActualWidth-6),h=Math.Max(0,ActualHeight-6);
        if(samples.Count>0){
            var end=samples[^1].Time;
            double floor=spark?samples.Min(p=>p.First)*.97:0;
            foreach(var sample in samples){
                double x=3+w*Math.Clamp(1-(end-sample.Time).TotalSeconds/60,0,1);
                double Y(double v)=>3+h*(1-Math.Clamp((v-floor)/Math.Max(.001,ceiling-floor),0,1));
                primary.Add(new(x,Y(sample.First)));
                if(sample.Second is double value)secondary.Add(new(x,Y(value)));
            }
        }
        First.Data=Curve(primary);Second.Data=Curve(secondary);Area.Data=Curve(primary,h+3);
        Tip.Visibility=primary.Count>0?Visibility.Visible:Visibility.Collapsed;
        if(primary.Count>0){Canvas.SetLeft(Tip,primary[^1].X-2.5);Canvas.SetTop(Tip,primary[^1].Y-2.5);}
    }
    private static Geometry? Curve(PointCollection points,double? fillTo=null)
    {
        if(points.Count<2)return null;
        var curve=new StreamGeometry();
        using(var pen=curve.Open()){
            pen.BeginFigure(points[0],fillTo.HasValue,fillTo.HasValue);
            for(int i=1;i<points.Count;i++){
                var a=points[i-1];var b=points[i];double mid=(a.X+b.X)/2;
                pen.BezierTo(new(mid,a.Y),new(mid,b.Y),b,true,true);
            }
            if(fillTo is double y){pen.LineTo(new(points[^1].X,y),false,false);pen.LineTo(new(points[0].X,y),false,false);}
        }
        curve.Freeze();return curve;
    }
}
