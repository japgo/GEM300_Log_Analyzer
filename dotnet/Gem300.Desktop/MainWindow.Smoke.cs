using Avalonia;
using Avalonia.Controls;
using Avalonia.Media.Imaging;
using Gem300.Core;

namespace Gem300.Desktop;

public partial class MainWindow
{
    internal async Task SmokeAsync(string? screenshot)
    {
        static void Require(bool value,string label) {if(!value) throw new InvalidOperationException("UI check failed: "+label);}
        string fixture=Path.Combine(LogText.DefaultCache,"smoke-input");Directory.CreateDirectory(fixture);
        string path=Path.Combine(fixture,"2026_09_16.log");
        await File.WriteAllLinesAsync(path,Enumerable.Range(0,750).Select(i=>$"2026-09-16 08:00:00:{i:D3}|21|{i}|Carrier CST{i:D4} LoadPort=1 State=RUN"));
        await LoadPathsAsync([path]);
        Require(session?.Count==750,"load count");
        IncludeBox.Text="CST0701";
        Require(results.Length==750,"editing must not apply filter");
        await ApplyAsync();Require(results.Length==1,"apply exact filter");
        ResultGrid.SelectedItem=ResultGrid.ItemsSource.Cast<LogRow>().Single();
        for(int i=0;i<100 && DetailBox.Text?.Contains("CST0701")!=true;i++) await Task.Delay(20);
        Require(AllGrid.SelectedItem is LogRow row&&row.Position==701,"right click selects left across pages");
        Require(DetailBox.Text?.Contains("CST0701")==true,"right detail");
        Require(ResultGrid.SelectedItem is LogRow,"left paging preserves right selection");
        IncludeBox.Text="";await ApplyAsync();
        FindBox.Text="CST0702";await FindAsync(1);
        Require(results.Length==750&&selected==702,"find keeps filtered result and selects row");
        Require(AllGrid.SelectedItem is LogRow found&&found.Position==702,"find synchronizes left");
        FindBox.Text="CST0701";await FindAsync(-1);Require(selected==701,"previous find");
        AllGrid.SelectedItem=AllGrid.ItemsSource.Cast<LogRow>().First(r=>r.Position==700);
        for(int i=0;i<100 && DetailBox.Text?.Contains("CST0700")!=true;i++) await Task.Delay(20);
        Require(DetailBox.Text?.Contains("CST0700")==true,"left click detail");
        bool rightVisible=ResultGrid.Columns[4].IsVisible;
        AllGrid.Columns[4].IsVisible=!rightVisible;Require(ResultGrid.Columns[4].IsVisible==rightVisible,"independent columns");
        AllGrid.Columns[4].IsVisible=false;
        await Task.Delay(150);UpdateLayout();
        if(screenshot is not null)
        {
            using var image=new RenderTargetBitmap(new PixelSize((int)Bounds.Width,(int)Bounds.Height),new Vector(96,96));
            image.Render(this);image.Save(screenshot);
        }
    }
}
