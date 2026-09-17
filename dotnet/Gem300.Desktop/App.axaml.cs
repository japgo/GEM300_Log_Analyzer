using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace Gem300.Desktop;
public partial class App : Application
{
    public override void Initialize()=>AvaloniaXamlLoader.Load(this);
    public override void OnFrameworkInitializationCompleted()
    {
        if(ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window=new MainWindow();desktop.MainWindow=window;
            window.Opened+=async (_,_)=>
            {
                var args=desktop.Args??[];
                if(args.Contains("--smoke"))
                {
                    try
                    {
                        await window.SmokeAsync(args.LastOrDefault(a=>a.EndsWith(".png",StringComparison.OrdinalIgnoreCase)));
                        Console.WriteLine("PASS Avalonia window / analysis / filtering / selection sync / F3-F4 / column independence");
                        desktop.Shutdown(0);
                    }
                    catch(Exception ex) {Console.Error.WriteLine(ex);desktop.Shutdown(1);}
                }
                else if(args.Length>0) await window.LoadPathsAsync(args.Where(File.Exists).ToArray());
            };
        }
        base.OnFrameworkInitializationCompleted();
    }
}
