using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Gem300.Core;
using Microsoft.Data.SqlClient;

namespace Gem300.Desktop;

public partial class MainWindow : Window
{
    private const int PageSize=500;
    private readonly List<string> paths=[];
    private readonly SemaphoreSlim workGate=new(1,1);
    private CancellationTokenSource workCancel=new(),detailCancel=new();
    private int generation,detailGeneration;
    private LogSession? session;
    private int[] results=[];
    private int leftStart,rightStart;
    private int? selected;
    private DataGrid? activeGrid;
    private bool synchronizing,closed;
    private readonly HashSet<int> bookmarks=[];
    private readonly HashSet<string> bookmarkKeys=[];
    private AnnotationService? annotation;
    private string annotationConnection="";
    private readonly string bookmarkPath=Path.Combine(LogText.DefaultCache,"bookmarks.json");
    private readonly string settingsPath=Path.Combine(LogText.DefaultCache,"ui-settings.json");
    private readonly int[] timeWindows=[1,5,30,60,300,600,1800,3600];

    public MainWindow()
    {
        InitializeComponent();
        Title=$"GEM300 Log Analyzer · {typeof(MainWindow).Assembly.GetName().Version} · C# Preview";
        TimeWindowBox.ItemsSource=new[]{"앞뒤 1초","앞뒤 5초","앞뒤 30초","앞뒤 1분","앞뒤 5분","앞뒤 10분","앞뒤 30분","앞뒤 1시간"};
        TimeWindowBox.SelectedIndex=0;SxfyBox.ItemsSource=new[]{"전체 SxFy"};SxfyBox.SelectedIndex=0;
        OpenButton.Click+=async (_,_)=>await OpenFilesAsync();
        AnalyzeButton.Click+=async (_,_)=>await AnalyzeAsync();
        CancelButton.Click+=(_,_)=>{workCancel.Cancel();detailCancel.Cancel();};
        FilesButton.Click+=(_,_)=>ShowFiles();
        ApplyButton.Click+=async (_,_)=>await ApplyAsync();
        AllGrid.SelectionChanged+=async (_,_)=>await SelectionAsync(AllGrid);
        ResultGrid.SelectionChanged+=async (_,_)=>await SelectionAsync(ResultGrid);
        LeftPrev.Click+=(_,_)=>Page(false,-1);LeftNext.Click+=(_,_)=>Page(false,1);
        RightPrev.Click+=(_,_)=>Page(true,-1);RightNext.Click+=(_,_)=>Page(true,1);
        FindPrev.Click+=async (_,_)=>await FindAsync(-1);FindNext.Click+=async (_,_)=>await FindAsync(1);
        BookmarkButton.Click+=(_,_)=>ToggleBookmark();BookmarksButton.Click+=(_,_)=>ShowBookmarks();
        CopyRawButton.Click+=async (_,_)=>await CopyAsync(false);CopyAnnotatedButton.Click+=async (_,_)=>await CopyAsync(true);
        TimeWindowButton.Click+=(_,_)=>SetTimeWindow();
        FullDateCheck.IsCheckedChanged+=(_,_)=>Render();
        LeftColumnsButton.Click+=(_,_)=>Columns(AllGrid,LeftColumnsButton);
        RightColumnsButton.Click+=(_,_)=>Columns(ResultGrid,RightColumnsButton);
        AddHandler(KeyDownEvent,OnKeyDown,RoutingStrategies.Tunnel);
        DragDrop.SetAllowDrop(this,true);AddHandler(DragDrop.DropEvent,OnDrop);
        foreach(var box in new[]{ServerBox,DatabaseBox,UserBox,PasswordBox}) box.TextChanged+=(_,_)=>InvalidateDb();
        IntegratedCheck.IsCheckedChanged+=(_,_)=>InvalidateDb();TrustCheck.IsCheckedChanged+=(_,_)=>InvalidateDb();
        DbCheck.IsCheckedChanged+=async (_,_)=>{InvalidateDb();if(selected is {} p) await DetailsAsync(p);};
        try { foreach(var key in JsonSerializer.Deserialize<string[]>(File.ReadAllText(bookmarkPath))??[]) bookmarkKeys.Add(key); } catch(IOException){} catch(JsonException){}
        ReadSettings();
        Closed+=(_,_)=>
        {
            closed=true;workCancel.Cancel();detailCancel.Cancel();SaveSettings();
            // Work retains its session until cancellation has completed.
            _=Task.Run(async ()=>{await workGate.WaitAsync();try {session?.Dispose();}finally {workGate.Release();}});
        };
    }
    private void InvalidateDb() {detailCancel.Cancel();detailGeneration++;annotation=null;annotationConnection="";}
    private static string[] Lines(TextBox box)=>(box.Text??"").Split(['\r','\n'],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries);
    private void Status(string text) {if(!closed) StatusText.Text=text;}
    private async Task WorkAsync(Func<CancellationToken,Task> action)
    {
        workCancel.Cancel();var cts=new CancellationTokenSource();workCancel=cts;
        int version=++generation;
        bool entered=false;
        try
        {
            await workGate.WaitAsync(cts.Token);entered=true;
            WorkProgress.IsIndeterminate=true;
            await action(cts.Token);
        }
        catch(OperationCanceledException) {if(version==generation) Status("작업을 취소했습니다.");}
        catch(Exception ex) {if(version==generation) Status($"처리 실패: {ex.GetBaseException().Message}");}
        finally {if(entered) workGate.Release();if(version==generation) {WorkProgress.IsIndeterminate=false;WorkProgress.Value=0;}}
    }
    private async Task OpenFilesAsync()
    {
        var files=await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions {Title="MMI / SECS 로그 선택",AllowMultiple=true,
            FileTypeFilter=[new("로그 파일") {Patterns=["*.log","*.txt","*.tslog"]}]});
        foreach(var file in files) if(file.TryGetLocalPath() is {} path&&!paths.Contains(path)) paths.Add(path);
        Status($"{paths.Count}개 파일 선택됨. 분석 시작을 누르세요.");
    }
    public async Task LoadPathsAsync(string[] selectedPaths)
    { paths.Clear();paths.AddRange(selectedPaths);await AnalyzeAsync(); }
    private async void OnDrop(object? sender,DragEventArgs e)
    {
#pragma warning disable CS0618
        var files=e.Data.GetFiles();
#pragma warning restore CS0618
        if(files is null) return;
        foreach(var file in files) if(file.TryGetLocalPath() is {} p && new[]{".log",".txt",".tslog"}.Contains(Path.GetExtension(p).ToLowerInvariant())&&!paths.Contains(p)) paths.Add(p);
        Status($"{paths.Count}개 파일 선택됨. 분석 시작을 누르세요.");
        await Task.CompletedTask;
    }
    private async Task AnalyzeAsync()
    {
        if(paths.Count==0) {Status("먼저 로그 파일을 추가하세요.");return;}
        var snapshot=paths.ToArray();bool skip=SetupCheck.IsChecked==true;
        await WorkAsync(async ct=>
        {
            detailCancel.Cancel();detailGeneration++;Status("분석 준비 중...");
            var timer=Stopwatch.StartNew();int version=generation;
            var progress=new ThrottledProgress(p=>Dispatcher.UIThread.Post(()=>
            {
                if(version!=generation||ct.IsCancellationRequested||closed) return;
                Status($"{p.Stage} · {p.File} · {(p.Total>0?100*p.Done/p.Total:0)}%");
            }));
            var loaded=await Task.Run(()=>LogSession.LoadAsync(snapshot,LogText.DefaultCache,new(skip,Math.Clamp(Environment.ProcessorCount,1,4)),progress,ct),ct);
            if(ct.IsCancellationRequested) {loaded.Dispose();ct.ThrowIfCancellationRequested();}
            detailCancel.Cancel();detailGeneration++;
            var prior=session;session=loaded;prior?.Dispose();
            results=Enumerable.Range(0,loaded.Count).ToArray();leftStart=rightStart=0;selected=null;
            bookmarks.Clear();
            if(bookmarkKeys.Count>0)
                for(int i=0;i<loaded.Count;i++) if(bookmarkKeys.Contains(loaded.StableKey(i))) bookmarks.Add(i);
            BookmarkOnlyCheck.IsChecked=false;
            SxfyBox.ItemsSource=new[]{"전체 SxFy"}.Concat(loaded.Shards.SelectMany(s=>s.Entries).Select(e=>e.Sxfy).Where(sf=>sf!=0).Distinct().Order().Select(LogText.SxfyLabel)).ToArray();
            SxfyBox.SelectedIndex=0;
            DetailBox.Text="";Render();
            Status($"분석·검색 색인 준비 완료: {loaded.Count:N0}건 · {timer.Elapsed.TotalSeconds:F2}초 · 캐시 {loaded.ReusedShards}/{loaded.Shards.Length}구간 재사용 · DB 조회 없음");
        });
    }
    private FilterOptions Options()
    {
        long? ParseTime(TextBox box)
        {
            if(string.IsNullOrWhiteSpace(box.Text)) return null;
            if(DateTime.TryParseExact(box.Text.Trim(),new[]{"yyyy-MM-dd HH:mm:ss:fff","yyyy-MM-dd HH:mm:ss.fff","yyyy-MM-dd HH:mm:ss","yyyy-MM-dd"},CultureInfo.InvariantCulture,DateTimeStyles.None,out var value)) return value.Ticks;
            throw new FormatException("시간은 yyyy-MM-dd HH:mm:ss 또는 yyyy-MM-dd HH:mm:ss:fff 형식으로 입력하세요.");
        }
        long? start=ParseTime(StartBox),end=ParseTime(EndBox);
        if(start>end) throw new FormatException("시작 시간이 종료 시간보다 늦습니다.");
        int? sf=null;
        if(SxfyBox.SelectedItem is string label && label.StartsWith('S'))
        {var parts=label[1..].Split('F');sf=int.Parse(parts[0])*10000+int.Parse(parts[1]);}
        return new(Lines(IncludeBox).Select(s=>new Keyword(s)).Concat(Lines(OrBox).Select(s=>new Keyword(s,true))).ToArray(),Lines(ExcludeBox),
            CaseCheck.IsChecked==true,RegexCheck.IsChecked==true,MmiCheck.IsChecked==true,SecsCheck.IsChecked==true,start,end,
            new HashSet<int>(bookmarks),BookmarkOnlyCheck.IsChecked==true,AlwaysBookmarkCheck.IsChecked==true,sf);
    }
    private async Task ApplyAsync()
    {
        if(session is null) return;
        FilterOptions options;try{options=Options();}catch(Exception ex){Status(ex.Message);return;}
        await WorkAsync(async ct=>
        {
            var current=session!;Status("원문 키워드 검색 중...");var timer=Stopwatch.StartNew();
            var found=await Task.Run(()=>current.Filter(options,ct),ct);ct.ThrowIfCancellationRequested();
            results=found;rightStart=0;RenderRight();SaveSettings();
            Status($"필터 결과 {found.Length:N0} / {current.Count:N0}건 · {timer.Elapsed.TotalSeconds:F3}초 · 조건 수정은 F5로 적용");
        });
    }
    private void Render()
    { RenderLeft();RenderRight(); }
    private void RenderLeft()
    {
        if(session is null) return;
        bool old=synchronizing;synchronizing=true;
        try
        {
            leftStart=Math.Clamp(leftStart,0,Math.Max(0,session.Count-1));
            AllGrid.ItemsSource=Enumerable.Range(leftStart,Math.Min(PageSize,session.Count-leftStart)).Select(p=>session.Row(p,FullDateCheck.IsChecked==true,bookmarks)).ToArray();
            LeftPage.Text=$"{(session.Count==0?0:leftStart+1):N0}–{Math.Min(session.Count,leftStart+PageSize):N0} / {session.Count:N0}";
        }
        finally{synchronizing=old;}
    }
    private void RenderRight()
    {
        if(session is null) return;
        bool old=synchronizing;synchronizing=true;
        try
        {
            rightStart=Math.Clamp(rightStart,0,Math.Max(0,results.Length-1));
            ResultGrid.ItemsSource=results.Skip(rightStart).Take(PageSize).Select(p=>session.Row(p,FullDateCheck.IsChecked==true,bookmarks)).ToArray();
            RightPage.Text=$"{(results.Length==0?0:rightStart+1):N0}–{Math.Min(results.Length,rightStart+PageSize):N0} / {results.Length:N0}";
        }
        finally{synchronizing=old;}
    }
    private void Page(bool right,int delta)
    {
        if(session is null) return;
        if(right) {rightStart=Math.Clamp(rightStart+delta*PageSize,0,Math.Max(0,(results.Length-1)/PageSize*PageSize));RenderRight();}
        else {leftStart=Math.Clamp(leftStart+delta*PageSize,0,Math.Max(0,(session.Count-1)/PageSize*PageSize));RenderLeft();}
    }
    private async Task SelectionAsync(DataGrid grid)
    {
        if(synchronizing||grid.SelectedItem is not LogRow row||session is null) return;
        activeGrid=grid;selected=row.Position;
        if(grid==ResultGrid) SelectLeft(row.Position);
        await DetailsAsync(row.Position);
    }
    private void SelectLeft(int position)
    {
        synchronizing=true;
        try
        {
            if(position<leftStart||position>=leftStart+PageSize) {leftStart=position/PageSize*PageSize;RenderLeft();}
            var row=AllGrid.ItemsSource.Cast<LogRow>().FirstOrDefault(r=>r.Position==position);
            AllGrid.UpdateLayout();AllGrid.SelectedItem=row;if(row is not null) AllGrid.ScrollIntoView(row,null);
        }
        finally{synchronizing=false;}
    }
    private AnnotationService Annotations()
    {
        var builder=new SqlConnectionStringBuilder { DataSource=ServerBox.Text??"localhost",InitialCatalog=DatabaseBox.Text??"BOCCOB_BONDER",
            IntegratedSecurity=IntegratedCheck.IsChecked==true,ConnectTimeout=3,TrustServerCertificate=TrustCheck.IsChecked==true };
        if(!builder.IntegratedSecurity) {builder.UserID=UserBox.Text??"";builder.Password=PasswordBox.Text??"";}
        string key=builder.ConnectionString;
        if(annotation is null||annotationConnection!=key) {annotation=new(new SqlReferenceLookup(key));annotationConnection=key;}
        return annotation;
    }
    private async Task DetailsAsync(int position)
    {
        if(session is not {} current) return;
        detailCancel.Cancel();detailCancel=new();var ct=detailCancel.Token;int version=++detailGeneration;
        try
        {
            string raw=await Task.Run(()=>current.Raw(position),ct);
            if(version!=detailGeneration||ct.IsCancellationRequested) return;
            DetailBox.Text=raw;DetailTitle.Text=$"선택 로그 상세 · #{position+1:N0}";
            if(DbCheck.IsChecked!=true) return;
            var service=Annotations();DetailTitle.Text+=" · DB 주석 조회 중...";
            string[] annotated=await Task.Run(()=>service.AnnotateAsync([raw],ct),ct);
            if(version!=detailGeneration||ct.IsCancellationRequested) return;
            DetailBox.Text=annotated[0];DetailTitle.Text=$"선택 로그 상세 · #{position+1:N0} · 주석 적용";
        }
        catch(OperationCanceledException){}
        catch(Exception ex) {if(version==detailGeneration) {DetailTitle.Text="선택 로그 상세 · 원문 유지";Status($"주석/상세 조회 실패: {ex.GetBaseException().Message}");}}
    }
    private async Task CopyAsync(bool annotated)
    {
        if(session is not {} current) return;
        int[] positions=activeGrid?.SelectedItems.Cast<LogRow>().Select(r=>r.Position).Order().ToArray()??[];
        if(positions.Length==0&&selected is {} p) positions=[p];
        if(positions.Length==0) return;
        AnnotationService? service=null;
        if(annotated) {try{service=Annotations();}catch(Exception ex){Status(ex.Message);return;}}
        await WorkAsync(async ct=>
        {
            Status($"{positions.Length:N0}건 복사 준비 중...");
            var raw=await Task.Run(()=>positions.Select(p=>{ct.ThrowIfCancellationRequested();return current.Raw(p);}).ToArray(),ct);
            var text=service is null?raw:await Task.Run(()=>service.AnnotateAsync(raw,ct),ct);
            ct.ThrowIfCancellationRequested();
            if(Clipboard is not null) {await Clipboard.SetTextAsync(string.Join(Environment.NewLine,text));Status($"{positions.Length:N0}건 {(annotated?"주석 포함":"원문")} 복사 완료");}
        });
    }
    private async Task FindAsync(int direction)
    {
        if(session is null||results.Length==0||string.IsNullOrWhiteSpace(FindBox.Text)) return;
        string word=FindBox.Text;bool sensitive=CaseCheck.IsChecked==true,regex=RegexCheck.IsChecked==true;
        await WorkAsync(async ct=>
        {
            var mask=await Task.Run(()=>session.Match(word,sensitive,regex,ct),ct);
            int index=selected is {} p?Array.BinarySearch(results,p):-1;
            if(index<0) index=direction>0?-1:0;
            for(int n=1;n<=results.Length;n++)
            {
                if((n&4095)==0) ct.ThrowIfCancellationRequested();
                int next=((index+direction*n)%results.Length+results.Length)%results.Length;
                if(!LogSession.IsMatch(mask,results[next])) continue;
                rightStart=next/PageSize*PageSize;RenderRight();
                var row=ResultGrid.ItemsSource.Cast<LogRow>().First(r=>r.Position==results[next]);
                synchronizing=true;
                try {ResultGrid.UpdateLayout();ResultGrid.SelectedItem=row;ResultGrid.ScrollIntoView(row,null);}
                finally {synchronizing=false;}
                selected=row.Position;activeGrid=ResultGrid;SelectLeft(row.Position);
                await DetailsAsync(row.Position);
                Status($"결과 내 찾기: {next+1:N0} / {results.Length:N0}");return;
            }
            Status("현재 필터 결과에서 찾는 단어가 없습니다.");
        });
    }
    private void ToggleBookmark()
    {
        if(session is null||selected is not {} p) return;
        string key=session.StableKey(p);
        if(!bookmarks.Add(p)) {bookmarks.Remove(p);bookmarkKeys.Remove(key);}else bookmarkKeys.Add(key);
        try{Directory.CreateDirectory(LogText.DefaultCache);File.WriteAllText(bookmarkPath,JsonSerializer.Serialize(bookmarkKeys));}catch(IOException ex){Status(ex.Message);}
        Render();Status("북마크 변경됨. 검색 조건 반영은 F5를 누르세요.");
    }
    private void SetTimeWindow()
    {
        if(session is null||selected is not {} p) return;
        int seconds=timeWindows[Math.Clamp(TimeWindowBox.SelectedIndex,0,timeWindows.Length-1)];
        var time=new DateTime(session.Timeline[p].Ticks);
        StartBox.Text=time.AddSeconds(-seconds).ToString("yyyy-MM-dd HH:mm:ss:fff");EndBox.Text=time.AddSeconds(seconds).ToString("yyyy-MM-dd HH:mm:ss:fff");
        Status("시간 조건 설정됨. 검색 / 필터 적용 또는 F5를 누르세요.");
    }
    private void ShowBookmarks()
    {
        if(session is not {} originalSession) return;
        var list=new ListBox {ItemsSource=bookmarks.Order().Select(p=>session.Row(p)).Select(r=>$"#{r.Position+1}  {r.Time}  {r.Preview}").ToArray()};
        int[] positions=bookmarks.Order().ToArray();
        var window=new Window {Title="북마크 보기",Width=900,Height=450,MinWidth=350,CanResize=true,Content=list};
        list.DoubleTapped+=async (_,_)=>
        {
            if(!ReferenceEquals(session,originalSession)) {Status("분석 대상이 변경되었습니다. 북마크 창을 다시 여세요.");return;}
            if(list.SelectedIndex>=0){selected=positions[list.SelectedIndex];SelectLeft(selected.Value);await DetailsAsync(selected.Value);}
        };
        window.Show(this);
    }
    private void ShowFiles()
    {
        var analyzed=session?.Shards.Select(s=>s.SourcePath).Distinct().ToArray()??[];
        var box=new TextBox {IsReadOnly=true,AcceptsReturn=true,Text="분석 완료 파일\n"+string.Join('\n',analyzed)+"\n\n다음 분석 선택 파일\n"+string.Join('\n',paths),Margin=new Thickness(12)};
        var clear=new Button {Content="다음 분석 파일 선택 초기화",Margin=new Thickness(12)};
        clear.Click+=(_,_)=>{paths.Clear();box.Text="분석 완료 파일\n"+string.Join('\n',analyzed)+"\n\n다음 분석 선택 파일 없음";};
        var panel=new DockPanel();DockPanel.SetDock(clear,Dock.Bottom);panel.Children.Add(clear);panel.Children.Add(box);
        new Window {Title="분석 파일 목록",Width=800,Height=420,Content=panel}.Show(this);
    }
    private static void Columns(DataGrid grid,Button button)
    {
        var menu=new ContextMenu();
        menu.ItemsSource=grid.Columns.Select(c=>
        {
            var item=new MenuItem {Header=(c.IsVisible?"✓ ":"   ")+c.Header};
            item.Click+=(_,_)=>c.IsVisible=!c.IsVisible;return item;
        }).ToArray();
        button.ContextMenu=menu;menu.Open(button);
    }
    private async void OnKeyDown(object? sender,KeyEventArgs e)
    {
        if(e.Key==Key.F5) {e.Handled=true;await ApplyAsync();}
        else if(e.Key==Key.F3||e.Key==Key.F4) {e.Handled=true;await FindAsync(e.Key==Key.F3?-1:1);}
        else if(e.Key==Key.Escape) {AllGrid.SelectedItem=null;ResultGrid.SelectedItem=null;}
        else if(e.Key==Key.Enter&&FindBox.IsFocused) {e.Handled=true;await FindAsync(1);}
        else if(e.Key==Key.C&&(e.KeyModifiers.HasFlag(KeyModifiers.Control)||e.KeyModifiers.HasFlag(KeyModifiers.Meta))&&(AllGrid.IsKeyboardFocusWithin||ResultGrid.IsKeyboardFocusWithin))
        {e.Handled=true;await CopyAsync(false);}
    }
    private sealed record Settings(string Include,string Or,string Exclude,bool Case,bool Regex,bool FullDate,string Server,string Database,bool Integrated,bool Trust,int[] LeftColumns,int[] RightColumns);
    private void ReadSettings()
    {
        try
        {
            var s=JsonSerializer.Deserialize<Settings>(File.ReadAllText(settingsPath));if(s is null) return;
            IncludeBox.Text=s.Include;OrBox.Text=s.Or;ExcludeBox.Text=s.Exclude;CaseCheck.IsChecked=s.Case;RegexCheck.IsChecked=s.Regex;FullDateCheck.IsChecked=s.FullDate;
            ServerBox.Text=s.Server;DatabaseBox.Text=s.Database;IntegratedCheck.IsChecked=s.Integrated;TrustCheck.IsChecked=s.Trust;
            for(int i=0;i<AllGrid.Columns.Count;i++) AllGrid.Columns[i].IsVisible=s.LeftColumns.Contains(i);
            for(int i=0;i<ResultGrid.Columns.Count;i++) ResultGrid.Columns[i].IsVisible=s.RightColumns.Contains(i);
        }catch(IOException){}catch(JsonException){}
    }
    private void SaveSettings()
    {
        try
        {
            Directory.CreateDirectory(LogText.DefaultCache);
            File.WriteAllText(settingsPath,JsonSerializer.Serialize(new Settings(IncludeBox.Text??"",OrBox.Text??"",ExcludeBox.Text??"",CaseCheck.IsChecked==true,RegexCheck.IsChecked==true,FullDateCheck.IsChecked==true,
                ServerBox.Text??"",DatabaseBox.Text??"",IntegratedCheck.IsChecked==true,TrustCheck.IsChecked==true,
                AllGrid.Columns.Select((c,i)=>(c,i)).Where(p=>p.c.IsVisible).Select(p=>p.i).ToArray(),ResultGrid.Columns.Select((c,i)=>(c,i)).Where(p=>p.c.IsVisible).Select(p=>p.i).ToArray())));
        }catch(IOException){}
    }
    private sealed class ThrottledProgress(Action<LoadProgress> report) : IProgress<LoadProgress>
    {
        private long last;
        public void Report(LoadProgress value)
        {
            long now=Environment.TickCount64,previous=Interlocked.Read(ref last);
            if(now-previous<120) return;
            if(Interlocked.CompareExchange(ref last,now,previous)==previous) report(value);
        }
    }
}
