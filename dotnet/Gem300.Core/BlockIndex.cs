namespace Gem300.Core;

// A conservative block index: false positives are verified; matches are never skipped.
// Unigrams/bigrams are included, so one- and two-character searches are also indexed.
public sealed class SearchBlock
{
    public const int WordCount = 256;
    public int First { get; set; }
    public int Count { get; set; }
    public long Offset { get; set; }
    public int Length { get; set; }
    public ulong[] Bits { get; } = new ulong[WordCount];
    private static uint Hash(uint value) { value ^= value >> 16; value *= 0x7feb352d; value ^= value >> 15; return value; }
    private static uint Gram(char a, char b = '\0', char c = '\0', int n = 1) =>
        Hash(((uint)a * 16777619 ^ (uint)b * 65599 ^ c) + (uint)n * 0x9e3779b9);
    private void Add(uint hash) { var bit = hash & (WordCount * 64 - 1); Bits[bit >> 6] |= 1UL << (int)(bit & 63); }
    private bool Has(uint hash) { var bit = hash & (WordCount * 64 - 1); return (Bits[bit >> 6] & (1UL << (int)(bit & 63))) != 0; }
    public void Index(string text)
    {
        var folded = text.ToUpperInvariant();
        for (int i = 0; i < folded.Length; i++)
        {
            Add(Gram(folded[i]));
            if (i + 1 < folded.Length) Add(Gram(folded[i], folded[i + 1], n: 2));
            if (i + 2 < folded.Length) Add(Gram(folded[i], folded[i + 1], folded[i + 2], 3));
        }
    }
    public bool MayContain(string keyword)
    {
        // Keep Unicode case-folding differences out of the pruning decision.
        if (keyword.Any(c => c > 127)) return true;
        var folded = keyword.ToUpperInvariant();
        if (folded.Length == 1) return Has(Gram(folded[0]));
        if (folded.Length == 2) return Has(Gram(folded[0], folded[1], n: 2));
        for (int i = 0; i + 2 < folded.Length; i++)
            if (!Has(Gram(folded[i], folded[i + 1], folded[i + 2], 3))) return false;
        return true;
    }
}

public sealed class LogShard
{
    public required string SourcePath { get; init; }
    public required string TextPath { get; init; }
    public required LogKind Kind { get; init; }
    public required EntryMeta[] Entries { get; init; }
    public required SearchBlock[] Blocks { get; init; }
    public int[] Positions { get; set; } = [];
    public bool CacheHit { get; init; }
    public long SourceLength { get; init; }
    public long SourceModifiedTicks { get; init; }
}
