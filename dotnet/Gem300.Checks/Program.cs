using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gem300.Core;

int assertions=0;
void Check(bool value,string label) {assertions++;if(!value) throw new Exception("FAILED: "+label);}
string root=Path.Combine(Path.GetTempPath(),"gem300-csharp-checks-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);

if(args.Length>0 && (args[0]=="--benchmark" || args[0]=="--digest"))
{
    var paths=args.Skip(1).ToArray();
    var watch=Stopwatch.StartNew();
    using var session=await LogSession.LoadAsync(paths,Path.Combine(root,"cache"),new());
    double cold=watch.Elapsed.TotalSeconds;
    if(args[0]=="--digest")
    {
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for(int i=0;i<session.Count;i++)
        {
            var t=session.Timeline[i];var s=session.Shards[t.Shard];var e=s.Entries[t.Local];
            string value=$"{new DateTime(e.Ticks):yyyy-MM-dd HH:mm:ss:fff}|{s.Kind}|{Path.GetFileName(s.SourcePath)}|{e.Line}|{session.Message(i)}\n";
            hash.AppendData(Encoding.UTF8.GetBytes(value));
        }
        Console.WriteLine($"count={session.Count} sha256={Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant()}");
        return;
    }
    Console.WriteLine($"cold_analysis_and_index_s={cold:F3} count={session.Count} shards={session.Shards.Length}");
    foreach(string word in new[]{"S6F11","CST0027","State=RUN","PM","1","없는키워드","S6F11"})
    {
        watch.Restart();var found=session.Filter(new([new(word)],[]));
        Console.WriteLine($"keyword={word} results={found.Length} elapsed_s={watch.Elapsed.TotalSeconds:F3} scanned_MB={session.LastScannedBytes/1048576.0:F1} mask_cache={session.LastKeywordCacheHit}");
    }
    watch.Restart();var combined=session.Filter(new([new("S6F11"),new("CST0027",true)],["State=RUN"]));
    Console.WriteLine($"combine_cached_s={watch.Elapsed.TotalSeconds:F3} results={combined.Length}");
    watch.Restart();var regex=session.Filter(new([new(@"CST00(27|28)")],[],Regex:true));
    Console.WriteLine($"regex_s={watch.Elapsed.TotalSeconds:F3} results={regex.Length}");
    watch.Restart();using var reused=await LogSession.LoadAsync(paths,Path.Combine(root,"cache"),new());
    Console.WriteLine($"warm_analysis_s={watch.Elapsed.TotalSeconds:F3} reused={reused.ReusedShards}/{reused.Shards.Length}");
    Console.WriteLine($"managed_heap_MB={GC.GetTotalMemory(false)/1048576.0:F1} cache={root}");
    return;
}

try
{
    string mmi=Path.Combine(root,"2026_09_01.log"),secs=Path.Combine(root,"2026-09-01 08.tslog");
    File.WriteAllText(mmi,"2026-09-01 08:00:00:000|1|1|Carrier ABC 한글\r\ncontinued\r\n"+
        "2026-09-01 08:00:01:000|1|2|[Setup.ini] LOGGING\r\n"+
        "2026-09-01 08:00:02:000|1|3|hidden\r\n"+
        "2026-09-01 08:00:03:000|1|4|[Setup.ini] FINISH\r\n"+
        "2026-09-01 08:00:04:000|31|5|Alarm AB -->[Count:3]\r\n"+
        "2026-09-01 08:00:05:000|1|6|carrier abc");
    string s6="08:00:00:000: [1] SEND S6F11W\n  <L [3]>\n    <U4 [1] 0>\n    <U4 [1] 777>\n    <L [1]>\n      <L [2]>\n        <U4 [1] 10>\n        <L [2]>\n          <A [3] ABC>\n          <L [1]>\n            <U4 [1] 9>\n";
    File.WriteAllText(secs,s6+"08:00:06:000: [2] RECV S6F12\n");
    string cache=Path.Combine(root,"cache");
    using var log=await LogSession.LoadAsync([mmi,secs],cache,new());
    Check(log.Count==5,"MMI setup excluded and SECS multiline preserved");
    Check(log.Shards[log.Timeline[0].Shard].Kind==LogKind.Mmi,"MMI wins equal timestamp");
    Check(log.Message(0)=="Carrier ABC 한글\ncontinued","continuation and CRLF");
    Check(log.Raw(1)==s6.TrimEnd(),"raw source range preserves W and full body");
    Check(log.Message(2)=="Alarm AB","count suffix removed");
    Check(log.Filter(new([new("AB")],[])).Length==4,"two-character substring index");
    Check(log.Filter(new([new("A")],[])).Length==4,"one-character substring index");
    Check(log.Filter(new([new("Carrier")],[],CaseSensitive:true)).SequenceEqual([0]),"case sensitive");
    Check(log.Filter(new([new("carrier")],[])).SequenceEqual([0,3]),"case insensitive");
    Check(log.Filter(new([new("S6F11")],[])).SequenceEqual([1]),"optional W normalization");
    Check(log.Filter(new([new("한글")],[])).SequenceEqual([0]),"unicode search");
    Check(log.Filter(new([new("[가-힣]+")],[],Regex:true)).SequenceEqual([0]),"unicode regex");
    Check(log.Filter(new([new("Carrier"),new("ABC")],["한글"])).SequenceEqual([3]),"AND exclude");
    Check(log.Filter(new([new("Carrier"),new("S6F12",true)],[])).SequenceEqual([0,3,4]),"AND OR union");
    Check(log.Filter(new([new("S6F11")],[],Bookmarks:new HashSet<int>{4},AlwaysBookmarks:true)).SequenceEqual([1,4]),"bookmark keyword bypass");
    Check(log.Filter(new([new("S6F11")],[],Secs:false,Bookmarks:new HashSet<int>{4},AlwaysBookmarks:true)).Length==0,"bookmark respects type");
    Check(log.Filter(new([],[],StartTicks:new DateTime(2026,9,1,8,0,4).Ticks)).SequenceEqual([2,3,4]),"time filtering");
    var mask=log.Match("Carrier");var again=log.Match("Carrier");
    Check(ReferenceEquals(mask,again)&&log.LastKeywordCacheHit,"keyword mask reused");
    using var warm=await LogSession.LoadAsync([mmi,secs],cache,new());
    Check(warm.ReusedShards==warm.Shards.Length,"persistent metadata and index reuse");
    Check(warm.Filter(new([new("AB")],[])).SequenceEqual(log.Filter(new([new("AB")],[]))),"warm index equivalent");
    using var setup=await LogSession.LoadAsync([mmi],cache,new(SkipSetup:false));
    Check(setup.Count==6&&setup.ReusedShards==0,"option invalidation");
    File.AppendAllText(mmi,"\n2026-09-01 09:00:00:000|1|7|new log");
    try{log.Raw(0);Check(false,"changed source rejected");}catch(IOException){Check(true,"changed source rejected");}
    using var changed=await LogSession.LoadAsync([mmi,secs],cache,new());
    Check(changed.Count==6&&changed.ReusedShards==1,"per-file cache invalidation");
    // Corrupt the active generation deterministically; leave its reader open during repair.
    string damaged=Path.ChangeExtension(changed.Shards[0].TextPath,".meta");
    string beforeRepair=changed.Message(0);
    File.WriteAllText(damaged,"broken");
    using var repaired=await LogSession.LoadAsync([mmi,secs],cache,new());
    Check(repaired.Count==6,"corrupt cache recovered");
    Check(Directory.GetDirectories(cache,"*.invalid-*").Length==1,"active damaged cache quarantined");
    Check(changed.Message(0)==beforeRepair,"existing reader survives cache quarantine");
    Check(changed.Filter(new([new("new log")],[])).SequenceEqual(repaired.Filter(new([new("new log")],[]))),"old and repaired readers search independently");
    using var repairedWarm=await LogSession.LoadAsync([mmi,secs],cache,new());
    Check(repairedWarm.ReusedShards==repairedWarm.Shards.Length,"repaired generation reused");
    using var cancelled=new CancellationTokenSource();cancelled.Cancel();
    try{log.Filter(new([new("unknown")],[]),cancelled.Token);Check(false,"cancel requested");}catch(OperationCanceledException){Check(true,"cancel search");}
    try{log.Match("[",regex:true);Check(false,"invalid regex");}catch(ArgumentException){Check(true,"invalid regex reported");}

    var fake=new FakeLookup();var service=new AnnotationService(fake);
    Check(fake.Calls==0,"analysis and keyword search made no DB calls");
    var annotated=await service.AnnotateAsync([s6]);
    Check(fake.Calls==1&&fake.Ceids.SequenceEqual([777])&&fake.Rptids.SequenceEqual([10]),"only selected identifiers queried");
    Check(annotated[0].Contains("(CEID 777) Arrived")&&annotated[0].Contains("(RPTID 10)")&&annotated[0].Contains("(VID 1001) CarrierID")&&annotated[0].Contains("(VID 1002) Values"),"CEID RPTID VID annotation");
    await service.AnnotateAsync([s6,s6]);Check(fake.Calls==1,"copy reuses reference cache");
    await service.AnnotateAsync(["plain MMI"]);Check(fake.Calls==1,"MMI no DB calls");
    var failed=new AnnotationService(new FailingLookup());
    try{await failed.AnnotateAsync([s6]);Check(false,"DB failure");}catch(IOException){Check(true,"DB failure propagated for raw copy fallback");}

    // A large single file forces real intra-file parallel ranges, including a boundary in S6F11.
    string big=Path.Combine(root,"2026-09-02 08.log");
    using(var writer=new StreamWriter(big))
        for(int i=0;i<100_000;i++) writer.Write(s6+"08:00:07:000: [1] tail "+i+"\n");
    using var parallel=await LogSession.LoadAsync([big],Path.Combine(root,"parallel"),new(Workers:4));
    using var sequential=await LogSession.LoadAsync([big],Path.Combine(root,"sequential"),new(Workers:1));
    Check(parallel.Shards.Length>1&&parallel.Count==sequential.Count,"single-file parallel parsing");
    for(int i=0;i<parallel.Count;i+=197)
    {
        Check(parallel.Message(i)==sequential.Message(i),"parallel message equality");
        Check(parallel.Raw(i)==sequential.Raw(i),"parallel offsets equality");
    }
    Check(parallel.Filter(new([new("99999")],[])).Length==1,"boundary index exact match");
    Check(parallel.Filter(new([new("S6F11")],[])).Length==100_000,"no split or lost S6F11");
    Console.WriteLine($"PASS {assertions} assertions · cache/search/parallel/cancellation/lazy DB");
}
finally {Directory.Delete(root,true);}

sealed class FakeLookup : IReferenceLookup
{
    public int Calls;public int[] Ceids=[],Rptids=[];
    public Task<ReferenceData> FetchAsync(IReadOnlyCollection<int> ceids,IReadOnlyCollection<int> rptids,CancellationToken token)
    {Calls++;Ceids=ceids.ToArray();Rptids=rptids.ToArray();return Task.FromResult(new ReferenceData(new Dictionary<int,string>{{777,"Arrived"}},new Dictionary<int,ReportVariable[]>{{10,[new(10,1,1001,"CarrierID"),new(10,2,1002,"Values")]}}));}
}
sealed class FailingLookup : IReferenceLookup
{
    public Task<ReferenceData> FetchAsync(IReadOnlyCollection<int> ceids,IReadOnlyCollection<int> rptids,CancellationToken token)=>throw new IOException("DB unavailable");
}
