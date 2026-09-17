using System.Text.RegularExpressions;

namespace Gem300.Core;

public sealed record ReportVariable(int Rptid,int Index,int Vid,string Name);
public sealed record ReferenceData(IReadOnlyDictionary<int,string> Events,IReadOnlyDictionary<int,ReportVariable[]> Reports);
public interface IReferenceLookup
{
    Task<ReferenceData> FetchAsync(IReadOnlyCollection<int> ceids,IReadOnlyCollection<int> rptids,CancellationToken token);
}

public sealed partial class AnnotationService(IReferenceLookup lookup)
{
    private readonly SemaphoreSlim gate=new(1,1);
    private readonly Dictionary<int,string> events=new();
    private readonly Dictionary<int,ReportVariable[]> reports=new();
    private sealed record Node(int Line,int Indent,string Type,string Value)
    { public List<Node> Children { get; }=[]; public int? Id=>int.TryParse(Value.Trim().Trim('>'),out int value)?value:null; }
    private sealed record Parsed(string[] Lines,Node? Body,int? InlineCeid);
    [GeneratedRegex(@"^(?<indent>\s*)<(?<type>[A-Z0-9]+)\s+\[\d+\](?:\s+(?<value>.*?))?\s*>")]
    private static partial Regex Item();
    [GeneratedRegex(@"\bCEID\s*=\s*(\d+)",RegexOptions.IgnoreCase)]
    private static partial Regex Ceid();
    private static Parsed Parse(string raw)
    {
        string[] lines=raw.Replace("\r\n","\n").Split('\n');
        if(!raw.Contains("S6F11",StringComparison.OrdinalIgnoreCase)) return new(lines,null,null);
        var nodes=new List<Node>();var stack=new Stack<Node>();
        for(int i=0;i<lines.Length;i++)
        {
            var m=Item().Match(lines[i]); if(!m.Success) continue;
            var n=new Node(i,m.Groups["indent"].Length,m.Groups["type"].Value,m.Groups["value"].Value.Trim());
            while(stack.Count>0&&stack.Peek().Indent>=n.Indent) stack.Pop();
            if(stack.Count>0) stack.Peek().Children.Add(n);
            stack.Push(n);nodes.Add(n);
        }
        var ceid=Ceid().Match(raw);
        return new(lines,nodes.FirstOrDefault(n=>n.Type=="L"&&n.Children.Count>=3),
            ceid.Success&&int.TryParse(ceid.Groups[1].Value,out int id)?id:null);
    }
    private static IEnumerable<Node> ReportNodes(Parsed p)=>p.Body is {} b
        ?b.Children[2].Children.Where(n=>n.Type=="L"&&n.Children.Count>=2):[];

    // This is the only entry point that reaches the database. Loading/searching never calls it.
    public async Task<string[]> AnnotateAsync(IReadOnlyList<string> rawLogs,CancellationToken token=default)
    {
        var parsed=rawLogs.Select(Parse).ToArray();
        var ceids=parsed.Select(p=>p.Body?.Children[1].Id??p.InlineCeid).OfType<int>().Distinct().ToArray();
        var rptids=parsed.SelectMany(ReportNodes).Select(n=>n.Children[0].Id).OfType<int>().Distinct().ToArray();
        await gate.WaitAsync(token);
        try
        {
            if(events.Count+reports.Count>50_000) {events.Clear();reports.Clear();}
            var missingCeids=ceids.Where(id=>!events.ContainsKey(id)).ToArray();
            var missingReports=rptids.Where(id=>!reports.ContainsKey(id)).ToArray();
            if(missingCeids.Length+missingReports.Length>0)
            {
                var data=await lookup.FetchAsync(missingCeids,missingReports,token);
                token.ThrowIfCancellationRequested();
                foreach(int id in missingCeids) events[id]=data.Events.GetValueOrDefault(id,"");
                foreach(int id in missingReports) reports[id]=data.Reports.GetValueOrDefault(id,[]).OrderBy(v=>v.Index).ToArray();
            }
            var output=new string[parsed.Length];
            for(int i=0;i<parsed.Length;i++)
            {
                token.ThrowIfCancellationRequested();
                var p=parsed[i];var lines=(string[])p.Lines.Clone();
                int? ceid=p.Body?.Children[1].Id??p.InlineCeid;
                if(ceid is {} id&&events.TryGetValue(id,out var name)&&name.Length>0)
                    lines[p.Body?.Children[1].Line??0]+=$" // (CEID {id}) {name}";
                foreach(var n in ReportNodes(p))
                {
                    if(n.Children[0].Id is not {} rpt) continue;
                    lines[n.Children[0].Line]+=$" // (RPTID {rpt})";
                    var vars=reports.GetValueOrDefault(rpt,[]);var values=n.Children[1].Children;
                    for(int v=0;v<Math.Min(vars.Length,values.Count);v++)
                        lines[values[v].Line]+=$" // (VID {vars[v].Vid}) {vars[v].Name}";
                }
                output[i]=string.Join('\n',lines);
            }
            return output;
        }
        finally {gate.Release();}
    }
}
