using System.Text.RegularExpressions;

namespace Gem300.Core;

public enum LogKind : byte { Mmi, Secs }
public readonly record struct EntryMeta(long Ticks, long SourceOffset, int SourceLength,
    long MessageOffset, int MessageLength, int Line, int Level, int Sxfy);
public readonly record struct TimelineEntry(long Ticks, int Shard, int Local);
public sealed record LoadProgress(string Stage, string File, long Done, long Total);
public sealed record ParseOptions(bool SkipSetup = true, int Workers = 4);
public sealed record Keyword(string Text, bool Or = false);
public sealed record FilterOptions(
    IReadOnlyList<Keyword> Include, IReadOnlyList<string> Exclude,
    bool CaseSensitive = false, bool Regex = false,
    bool Mmi = true, bool Secs = true, long? StartTicks = null, long? EndTicks = null,
    IReadOnlySet<int>? Bookmarks = null, bool BookmarkOnly = false,
    bool AlwaysBookmarks = false, int? Sxfy = null);

public static partial class LogText
{
    [GeneratedRegex(@"\b(S\d+F\d+)W\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OptionalW();
    public static string Normalize(string text) => OptionalW().Replace(text, "$1");
    public static string SxfyLabel(int value) => value == 0 ? "" : $"S{value / 10000}F{value % 10000}";
    public static readonly string DefaultCache = Environment.GetEnvironmentVariable("GEM300_CACHE_DIR") ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GEM300LogAnalyzer", "dotnet-cache");
}
