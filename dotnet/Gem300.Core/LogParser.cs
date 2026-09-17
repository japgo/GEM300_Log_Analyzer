using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Gem300.Core;

public static partial class LogParser
{
    private const int Schema = 1;
    private readonly record struct Segment(long Start, long End, int FirstLine);
    [GeneratedRegex(@"(?<y>\d{4})[-_](?<m>\d{2})[-_](?<d>\d{2})")]
    private static partial Regex FileDate();
    [GeneratedRegex(@"\bS(?<s>\d+)F(?<f>\d+)W?\b", RegexOptions.IgnoreCase)]
    private static partial Regex MessageType();
    [GeneratedRegex(@"\[.+?\.ini\] LOGGING", RegexOptions.IgnoreCase)]
    private static partial Regex SetupStart();
    [GeneratedRegex(@"\[.+?\.ini\] FINISH", RegexOptions.IgnoreCase)]
    private static partial Regex SetupFinish();
    [GeneratedRegex(@"-->\[Count:\d+\]\s*$")]
    private static partial Regex CountSuffix();

    private static bool Header(ReadOnlySpan<byte> line, out LogKind kind)
    {
        kind = LogKind.Mmi;
        if (line.Length > 26 && line[4] == '-' && line[7] == '-' && line[10] == ' '
            && line[13] == ':' && line[16] == ':' && line[19] == ':' && line[23] == '|'
            && line[0] >= '0' && line[0] <= '9') return true;
        kind = LogKind.Secs;
        if (line.Length < 17 || line[2] != ':' || line[5] != ':' || line[8] != ':'
            || line[12] != ':' || line[0] < '0' || line[0] > '9') return false;
        int pos = 13;
        while (pos < line.Length && (line[pos] == ' ' || line[pos] == '\t')) pos++;
        return pos > 13 && pos < line.Length && line[pos] == '[' && line[pos..].IndexOf((byte)']') > 1;
    }
    private static DateTime BaseDate(string path)
    {
        var match = FileDate().Match(Path.GetFileName(path));
        return match.Success ? new DateTime(int.Parse(match.Groups["y"].Value), int.Parse(match.Groups["m"].Value), int.Parse(match.Groups["d"].Value)) : DateTime.Today;
    }
    private static int Number(ReadOnlySpan<char> s) => int.Parse(s, CultureInfo.InvariantCulture);
    private static (long Ticks, int Level, string Message) ParseHeader(string line, LogKind kind, DateTime date)
    {
        var s = line.AsSpan();
        if (kind == LogKind.Mmi)
        {
            var timestamp = new DateTime(Number(s[..4]), Number(s.Slice(5,2)), Number(s.Slice(8,2)),
                Number(s.Slice(11,2)), Number(s.Slice(14,2)), Number(s.Slice(17,2)), Number(s.Slice(20,3)));
            int colorEnd = line.IndexOf('|', 24), sequenceEnd = line.IndexOf('|', colorEnd + 1);
            if (colorEnd < 0 || sequenceEnd < 0) throw new FormatException("MMI 헤더 형식 오류");
            string message=line[(sequenceEnd+1)..];
            if(CountSuffix().IsMatch(message)) message=CountSuffix().Replace(message, "").TrimEnd();
            return (timestamp.Ticks, Number(s[24..colorEnd]), message);
        }
        int open = line.IndexOf('['), close = line.IndexOf(']', open);
        var ticks = date.Ticks + new TimeSpan(0, Number(s[..2]), Number(s.Slice(3,2)), Number(s.Slice(6,2)), Number(s.Slice(9,3))).Ticks;
        return (ticks, Number(s[(open+1)..close]), line[(close+1)..].Trim());
    }

    public static async Task<LogShard[]> LoadFileAsync(string input, string cacheRoot, ParseOptions options,
        IProgress<LoadProgress>? progress, CancellationToken token)
    {
        string path = Path.GetFullPath(input);
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("로그 파일이 없습니다.", path);
        var fingerprint = $"{Schema}|{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}|{options.SkipSetup}|{BaseDate(path):yyyy-MM-dd}";
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint)));
        string destination = Path.Combine(cacheRoot, key);
        if (Directory.Exists(destination))
        {
            try
            {
                var cached = Directory.GetFiles(destination, "*.meta").Order().Select(p => ReadCache(p, path)).ToArray();
                if (cached.Length != 0)
                {
                    token.ThrowIfCancellationRequested();
                    progress?.Report(new("캐시 재사용", Path.GetFileName(path), info.Length, info.Length));
                    return cached;
                }
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException) { }
        }
        string staging = destination + ".building-" + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(staging);
        try
        {
            // Scan offsets once; no strings, DB calls, or tree parsing for continuation lines.
            var segments = new List<Segment>();
            var starts = new List<(long Offset, int Line)> { (0, 1) };
            LogKind? kind = null;
            bool setup = false;
            long interval = Math.Max(16 * 1024 * 1024, info.Length / Math.Clamp(options.Workers, 1, 4));
            long target = interval;
            int lineNo = 0;
            using (var lines = new Utf8Lines(path))
            {
                while (lines.MoveNext())
                {
                    if ((++lineNo & 8191) == 0)
                    {
                        token.ThrowIfCancellationRequested();
                        progress?.Report(new("로그 경계 확인", Path.GetFileName(path), lines.NextOffset, info.Length));
                    }
                    var bytes = lines.Bytes;
                    if (Header(bytes, out var found))
                    {
                        kind ??= found;
                        if (found != kind) throw new InvalidDataException("한 파일에 MMI와 SECS 형식이 혼합되어 있습니다.");
                        if (lines.Offset >= target && starts.Count < options.Workers)
                        { starts.Add((lines.Offset, lineNo)); target = lines.Offset + interval; }
                    }
                    if (kind == LogKind.Mmi && !setup && bytes.IndexOf(".ini]"u8) >= 0) setup = true;
                    // Case-insensitive marker detection only on rare '[' lines.
                    if (kind == LogKind.Mmi && !setup && bytes.IndexOf((byte)'[') >= 0)
                        setup = lines.Text.Contains(".ini]", StringComparison.OrdinalIgnoreCase);
                }
            }
            if (kind is null) throw new InvalidDataException($"지원하는 MMI/SECS 로그가 아닙니다: {Path.GetFileName(path)}");
            if (setup) starts.RemoveRange(1, starts.Count - 1);
            for (int i = 0; i < starts.Count; i++) segments.Add(new(starts[i].Offset, i+1 < starts.Count ? starts[i+1].Offset : info.Length, starts[i].Line));
            var outputs = new LogShard[segments.Count];
            var completedBytes=new long[segments.Count];
            await Parallel.ForEachAsync(Enumerable.Range(0, segments.Count), new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(options.Workers,1,4), CancellationToken = token }, (i, ct) =>
            {
                var partProgress=new CallbackProgress(p=>
                {
                    Interlocked.Exchange(ref completedBytes[i],Math.Clamp(p.Done-segments[i].Start,0,segments[i].End-segments[i].Start));
                    progress?.Report(new(p.Stage,p.File,completedBytes.Sum(),info.Length));
                });
                outputs[i] = ParseSegment(path, Path.Combine(staging, $"{i:D3}.meta"), kind.Value, BaseDate(path), segments[i], options.SkipSetup, partProgress, info.Length, ct);
                partProgress.Report(new("분석 및 검색 색인",Path.GetFileName(path),segments[i].End,info.Length));
                return ValueTask.CompletedTask;
            });
            info.Refresh();
            if (fingerprint != $"{Schema}|{path}|{info.Length}|{info.LastWriteTimeUtc.Ticks}|{options.SkipSetup}|{BaseDate(path):yyyy-MM-dd}")
                throw new IOException("분석 중 파일이 변경되었습니다. 기록이 끝난 파일을 다시 분석하세요.");
            token.ThrowIfCancellationRequested();
            // Immutable cache directories are only visible after every segment succeeds.
            if (Directory.Exists(destination))
            {
                try
                {
                    var winner=Directory.GetFiles(destination,"*.meta").Order().Select(p=>ReadCache(p,path)).ToArray();
                    if(winner.Length==outputs.Length) return winner;
                }
                catch(Exception ex) when(ex is IOException or InvalidDataException or ArgumentException) { }
                Directory.Move(destination, destination + ".invalid-" + Guid.NewGuid().ToString("N"));
            }
            Directory.Move(staging, destination);
            return outputs.Select(s => new LogShard { SourcePath=path, TextPath=Path.Combine(destination, Path.GetFileName(s.TextPath)), Kind=s.Kind, Entries=s.Entries, Blocks=s.Blocks,
                SourceLength=info.Length,SourceModifiedTicks=info.LastWriteTimeUtc.Ticks }).ToArray();
        }
        finally { if (Directory.Exists(staging)) Directory.Delete(staging, true); }
    }

    private static LogShard ParseSegment(string path, string metaPath, LogKind kind, DateTime date,
        Segment segment, bool skipSetup, IProgress<LoadProgress>? progress, long total, CancellationToken token)
    {
        var entries = new List<EntryMeta>();
        var blocks = new List<SearchBlock>();
        using var text = new FileStream(Path.ChangeExtension(metaPath, ".text"), FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024*1024);
        SearchBlock block = new();
        StringBuilder message = new();
        long currentOffset = -1, currentEnd = 0, ticks = 0;
        int currentLine = 0, level = 0;
        bool inSetup = false;
        void Finish()
        {
            if (currentOffset < 0) return;
            string original = message.ToString();
            if (kind == LogKind.Mmi)
            {
                if (SetupStart().IsMatch(original)) inSetup = true;
                else if (SetupFinish().IsMatch(original)) inSetup = false;
                if (skipSetup && (inSetup || SetupStart().IsMatch(original) || SetupFinish().IsMatch(original))) { currentOffset=-1; return; }
            }
            string normalized = LogText.Normalize(original);
            byte[] data = Encoding.UTF8.GetBytes(normalized);
            if (block.Count > 0 && (block.Count >= 256 || block.Length + data.Length > 4*1024*1024))
            { blocks.Add(block); block = new() { First=entries.Count, Offset=text.Position }; }
            var match = MessageType().Match(original);
            int sf = match.Success && int.TryParse(match.Groups["s"].Value, out int stream) && int.TryParse(match.Groups["f"].Value, out int func)
                && stream < 10000 && func < 10000 ? stream*10000+func : 0;
            entries.Add(new(ticks, currentOffset, checked((int)(currentEnd-currentOffset)), text.Position, data.Length, currentLine, level, sf));
            text.Write(data);
            block.Count++; block.Length += data.Length; block.Index(normalized);
            currentOffset=-1;
        }
        int lineNo = segment.FirstLine - 1;
        using var lines = new Utf8Lines(path, segment.Start);
        while (lines.MoveNext() && lines.Offset < segment.End)
        {
            if ((++lineNo & 8191) == 0)
            { token.ThrowIfCancellationRequested(); progress?.Report(new("분석 및 검색 색인",Path.GetFileName(path),lines.NextOffset,total)); }
            if (Header(lines.Bytes, out var lineKind) && lineKind == kind)
            {
                Finish();
                var header = ParseHeader(lines.Text, kind, date);
                ticks=header.Ticks; level=header.Level;
                message.Clear().Append(header.Message);
                if (kind == LogKind.Mmi)
                {
                    if (SetupStart().IsMatch(header.Message)) inSetup=true;
                    else if (SetupFinish().IsMatch(header.Message) || level != 1) inSetup=false;
                    if (skipSetup && (inSetup || SetupStart().IsMatch(header.Message) || SetupFinish().IsMatch(header.Message))) continue;
                }
                currentOffset=lines.Offset; currentEnd=lines.NextOffset; currentLine=lineNo;
            }
            else if (currentOffset >= 0)
            {
                string line = lines.Text;
                if (string.IsNullOrWhiteSpace(line)) { currentEnd=lines.NextOffset; continue; }
                if (kind == LogKind.Secs && line[0] != ' ' && line[0] != '\t') { Finish(); continue; }
                message.Append('\n').Append(kind == LogKind.Secs ? line.TrimEnd() : line);
                currentEnd=lines.NextOffset;
                if (kind == LogKind.Mmi)
                { if (SetupStart().IsMatch(line)) inSetup=true; else if (SetupFinish().IsMatch(line)) inSetup=false; }
            }
        }
        Finish();
        token.ThrowIfCancellationRequested();
        if (block.Count>0) blocks.Add(block);
        text.Flush();
        var shard = new LogShard { SourcePath=path, TextPath=Path.ChangeExtension(metaPath,".text"), Kind=kind, Entries=entries.ToArray(), Blocks=blocks.ToArray() };
        using var writer = new BinaryWriter(File.Create(metaPath));
        writer.Write(Schema); writer.Write((byte)kind); writer.Write(text.Length); writer.Write(shard.Entries.Length);
        foreach (var e in shard.Entries)
        { writer.Write(e.Ticks); writer.Write(e.SourceOffset); writer.Write(e.SourceLength); writer.Write(e.MessageOffset); writer.Write(e.MessageLength); writer.Write(e.Line); writer.Write(e.Level); writer.Write(e.Sxfy); }
        writer.Write(blocks.Count);
        foreach(var b in blocks)
        { writer.Write(b.First); writer.Write(b.Count); writer.Write(b.Offset); writer.Write(b.Length); foreach(var bits in b.Bits) writer.Write(bits); }
        return shard;
    }
    private static LogShard ReadCache(string metaPath, string source)
    {
        using var reader = new BinaryReader(File.OpenRead(metaPath));
        if (reader.ReadInt32()!=Schema) throw new InvalidDataException("캐시 버전 불일치");
        var kind=(LogKind)reader.ReadByte(); long textLength=reader.ReadInt64();
        string textPath=Path.ChangeExtension(metaPath,".text");
        if (new FileInfo(textPath).Length!=textLength) throw new InvalidDataException("검색 원문 캐시 불일치");
        int count=reader.ReadInt32();
        if (count < 0 || count > reader.BaseStream.Length/44) throw new InvalidDataException("메타데이터 크기 오류");
        var entries=new EntryMeta[count];
        for(int i=0;i<count;i++) entries[i]=new(reader.ReadInt64(),reader.ReadInt64(),reader.ReadInt32(),reader.ReadInt64(),reader.ReadInt32(),reader.ReadInt32(),reader.ReadInt32(),reader.ReadInt32());
        int blockCount=reader.ReadInt32();
        if(blockCount<0 || blockCount>count) throw new InvalidDataException("색인 크기 오류");
        var blocks=new SearchBlock[blockCount];
        int covered=0;
        for(int i=0;i<blockCount;i++)
        {
            var b=new SearchBlock { First=reader.ReadInt32(),Count=reader.ReadInt32(),Offset=reader.ReadInt64(),Length=reader.ReadInt32() };
            if(b.First!=covered || b.Count<=0 || b.First+b.Count>count || b.Offset<0 || b.Length<0 || b.Offset+b.Length>textLength) throw new InvalidDataException("색인 범위 오류");
            for(int j=0;j<b.Bits.Length;j++) b.Bits[j]=reader.ReadUInt64();
            blocks[i]=b; covered+=b.Count;
        }
        if(covered!=count) throw new InvalidDataException("불완전 색인");
        var sourceInfo=new FileInfo(source);
        return new LogShard { SourcePath=source,TextPath=textPath,Kind=kind,Entries=entries,Blocks=blocks,CacheHit=true,
            SourceLength=sourceInfo.Length,SourceModifiedTicks=sourceInfo.LastWriteTimeUtc.Ticks };
    }
    private sealed class CallbackProgress(Action<LoadProgress> report) : IProgress<LoadProgress>
    { public void Report(LoadProgress value)=>report(value); }
}
