using System.Collections.Concurrent;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace Gem300.Core;

public sealed record LogRow(int Position, string Time, string Kind, string File, int Line, string Sxfy, string Preview, string Bookmark);

public sealed class LogSession : IDisposable
{
    public LogShard[] Shards { get; }
    public TimelineEntry[] Timeline { get; }
    public int Count => Timeline.Length;
    public int ReusedShards => Shards.Count(s=>s.CacheHit);
    public long LastScannedBytes { get; private set; }
    public bool LastKeywordCacheHit { get; private set; }
    private readonly SafeFileHandle[] texts;
    private readonly object cacheLock=new();
    private readonly Dictionary<(string,bool,bool), (long[] Bits, LinkedListNode<(string,bool,bool)> Node)> masks=new();
    private readonly LinkedList<(string,bool,bool)> lru=new();
    private long cacheBytes;
    private const long CacheBudget=128L*1024*1024;

    private LogSession(LogShard[] shards, CancellationToken token)
    {
        Shards=shards;
        Timeline=new TimelineEntry[shards.Sum(s=>s.Entries.Length)];
        int next=0;
        for(int s=0;s<shards.Length;s++)
        {
            shards[s].Positions=new int[shards[s].Entries.Length];
            for(int i=0;i<shards[s].Entries.Length;i++) Timeline[next++]=new(shards[s].Entries[i].Ticks,s,i);
        }
        token.ThrowIfCancellationRequested();
        Array.Sort(Timeline, (a,b)=>
        {
            int cmp=a.Ticks.CompareTo(b.Ticks);
            if(cmp!=0) return cmp;
            cmp=shards[a.Shard].Kind.CompareTo(shards[b.Shard].Kind);
            if(cmp!=0) return cmp;
            cmp=StringComparer.Ordinal.Compare(shards[a.Shard].SourcePath,shards[b.Shard].SourcePath);
            return cmp!=0?cmp:shards[a.Shard].Entries[a.Local].Line.CompareTo(shards[b.Shard].Entries[b.Local].Line);
        });
        for(int i=0;i<Timeline.Length;i++) shards[Timeline[i].Shard].Positions[Timeline[i].Local]=i;
        token.ThrowIfCancellationRequested();
        // Cache generations are immutable; recovery publishes a different directory.
        // Delete sharing also permits individual-file cache maintenance on Windows.
        texts=shards.Select(s=>File.OpenHandle(s.TextPath,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete,FileOptions.RandomAccess)).ToArray();
    }
    public static async Task<LogSession> LoadAsync(IEnumerable<string> paths,string cacheRoot,ParseOptions options,
        IProgress<LoadProgress>? progress=null,CancellationToken token=default)
    {
        Directory.CreateDirectory(cacheRoot);
        var shards=new List<LogShard>();
        foreach(var path in paths.Select(Path.GetFullPath).Distinct())
        {
            token.ThrowIfCancellationRequested();
            shards.AddRange(await LogParser.LoadFileAsync(path,cacheRoot,options,progress,token));
        }
        progress?.Report(new("시간순 정렬","",0,1));
        return new(shards.ToArray(),token);
    }
    private static byte[] Read(SafeFileHandle handle,long offset,int length)
    {
        byte[] data=GC.AllocateUninitializedArray<byte>(length);
        int read=0;
        while(read<length)
        {
            int n=RandomAccess.Read(handle,data.AsSpan(read),offset+read);
            if(n==0) throw new EndOfStreamException("캐시 원문을 읽을 수 없습니다. 다시 분석하세요.");
            read+=n;
        }
        return data;
    }
    public string Message(int position)
    {
        var t=Timeline[position]; var e=Shards[t.Shard].Entries[t.Local];
        return Encoding.UTF8.GetString(Read(texts[t.Shard],e.MessageOffset,e.MessageLength));
    }
    public string Raw(int position)
    {
        var t=Timeline[position]; var shard=Shards[t.Shard]; var e=shard.Entries[t.Local];
        var info=new FileInfo(shard.SourcePath);
        if(info.Length!=shard.SourceLength||info.LastWriteTimeUtc.Ticks!=shard.SourceModifiedTicks)
            throw new IOException("분석 이후 원본 파일이 변경되었습니다. 다시 분석한 뒤 상세 보기 / 복사를 사용하세요.");
        using var handle=File.OpenHandle(shard.SourcePath,FileMode.Open,FileAccess.Read,FileShare.Read);
        return Encoding.UTF8.GetString(Read(handle,e.SourceOffset,e.SourceLength)).TrimEnd('\n','\r');
    }
    public LogRow Row(int position,bool fullDate=true,IReadOnlySet<int>? bookmarks=null)
    {
        var t=Timeline[position]; var shard=Shards[t.Shard]; var e=shard.Entries[t.Local];
        // Read only the visible preview, never a giant FDC body for a table cell.
        var preview=Encoding.UTF8.GetString(Read(texts[t.Shard],e.MessageOffset,Math.Min(512,e.MessageLength))).Replace('\n',' ');
        return new(position,new DateTime(t.Ticks).ToString(fullDate?"yyyy-MM-dd HH:mm:ss:fff":"HH:mm:ss:fff"),
            shard.Kind==LogKind.Mmi?"MMI":"SECS",Path.GetFileName(shard.SourcePath),e.Line,LogText.SxfyLabel(e.Sxfy),preview,bookmarks?.Contains(position)==true?"★":"");
    }
    public string StableKey(int position)
    { var t=Timeline[position]; var s=Shards[t.Shard]; var e=s.Entries[t.Local]; return $"{s.SourcePath}|{e.Ticks}|{e.Line}"; }

    public long[] Match(string keyword,bool caseSensitive=false,bool regex=false,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();
        keyword=LogText.Normalize(keyword.Trim());
        var key=(keyword,caseSensitive,regex);
        lock(cacheLock)
        {
            if(masks.TryGetValue(key,out var cached))
            { lru.Remove(cached.Node);lru.AddLast(cached.Node);LastScannedBytes=0;LastKeywordCacheHit=true; return cached.Bits; }
        }
        var result=new long[(Count+63)/64];
        Regex? pattern=regex?new Regex(keyword,RegexOptions.CultureInvariant|(caseSensitive?RegexOptions.None:RegexOptions.IgnoreCase),TimeSpan.FromMilliseconds(100)):null;
        var comparison=caseSensitive?StringComparison.Ordinal:StringComparison.OrdinalIgnoreCase;
        long scanned=0;
        if(keyword.Length>0)
        {
            var work=Shards.SelectMany((s,index)=>s.Blocks.Select(b=>(Shard:index,Block:b)));
            Parallel.ForEach(work,new ParallelOptions { MaxDegreeOfParallelism=Math.Clamp(Environment.ProcessorCount,1,4),CancellationToken=token },job=>
            {
                if(!regex && !job.Block.MayContain(keyword)) return;
                var shard=Shards[job.Shard]; var b=job.Block;
                var bytes=Read(texts[job.Shard],b.Offset,b.Length);
                Interlocked.Add(ref scanned,bytes.Length);
                for(int local=b.First;local<b.First+b.Count;local++)
                {
                    if((local&63)==0) token.ThrowIfCancellationRequested();
                    var e=shard.Entries[local];
                    string message=Encoding.UTF8.GetString(bytes,checked((int)(e.MessageOffset-b.Offset)),e.MessageLength);
                    bool matched=pattern?.IsMatch(message)??message.Contains(keyword,comparison);
                    if(matched)
                    { int p=shard.Positions[local]; Interlocked.Or(ref result[p>>6],1L<<(p&63)); }
                }
            });
        }
        token.ThrowIfCancellationRequested();
        LastScannedBytes=scanned; LastKeywordCacheHit=false;
        lock(cacheLock)
        {
            if(masks.TryGetValue(key,out var existing)) return existing.Bits;
            long size=result.LongLength*8;
            while(cacheBytes+size>CacheBudget && lru.First is {} first)
            { cacheBytes-=masks[first.Value].Bits.LongLength*8;masks.Remove(first.Value);lru.RemoveFirst(); }
            if(size<=CacheBudget) { masks[key]=(result,lru.AddLast(key));cacheBytes+=size; }
        }
        return result;
    }
    public int[] Filter(FilterOptions options,CancellationToken token=default)
    {
        var and=options.Include.Where(k=>!k.Or && !string.IsNullOrWhiteSpace(k.Text)).ToArray();
        var or=options.Include.Where(k=>k.Or && !string.IsNullOrWhiteSpace(k.Text)).ToArray();
        var included=new long[(Count+63)/64];
        if(and.Length>0 || or.Length==0) Array.Fill(included,-1L);
        foreach(var k in and) { var m=Match(k.Text,options.CaseSensitive,options.Regex,token);for(int i=0;i<m.Length;i++) included[i]&=m[i]; }
        foreach(var k in or) { var m=Match(k.Text,options.CaseSensitive,options.Regex,token);for(int i=0;i<m.Length;i++) included[i]|=m[i]; }
        foreach(var k in options.Exclude.Where(k=>!string.IsNullOrWhiteSpace(k)))
        { var m=Match(k,options.CaseSensitive,options.Regex,token);for(int i=0;i<m.Length;i++) included[i]&=~m[i]; }
        if(options.AlwaysBookmarks && options.Bookmarks is {} bookmarks)
            foreach(int p in bookmarks) if(p>=0 && p<Count) included[p>>6]|=1L<<(p&63);
        var results=new List<int>();
        for(int w=0;w<included.Length;w++)
        {
            if((w&1023)==0) token.ThrowIfCancellationRequested();
            ulong bits=(ulong)included[w];
            while(bits!=0)
            {
                int bit=BitOperations.TrailingZeroCount(bits); bits&=bits-1;
                int position=w*64+bit; if(position>=Count) break;
                var t=Timeline[position];var s=Shards[t.Shard];var e=s.Entries[t.Local];
                if((s.Kind==LogKind.Mmi&&!options.Mmi)||(s.Kind==LogKind.Secs&&!options.Secs)) continue;
                if(options.StartTicks is {} start&&t.Ticks<start || options.EndTicks is {} end&&t.Ticks>end) continue;
                if(options.Sxfy is {} sf && s.Kind==LogKind.Secs && e.Sxfy!=sf) continue;
                if(options.BookmarkOnly&&options.Bookmarks?.Contains(position)!=true) continue;
                results.Add(position);
            }
        }
        return results.ToArray();
    }
    public static bool IsMatch(long[] mask,int position)=>position>=0 && position/64<mask.Length && (mask[position>>6]&(1L<<(position&63)))!=0;
    public void Dispose() { foreach(var handle in texts) handle.Dispose(); }
}
