using System.Text;

namespace Gem300.Core;

// One buffered sequential read, no seek/stat or stream allocation per physical line.
internal sealed class Utf8Lines : IDisposable
{
    private readonly FileStream stream;
    private byte[] buffer = new byte[1024 * 1024];
    private int start, end, length;
    private long baseOffset;
    private bool eof;
    public long Offset { get; private set; }
    public long NextOffset { get; private set; }
    public ReadOnlySpan<byte> Bytes => buffer.AsSpan(start, length).TrimEnd((byte)'\r');
    public Utf8Lines(string path, long offset = 0)
    {
        stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1,
            FileOptions.SequentialScan);
        stream.Position = offset;
        baseOffset = offset;
    }
    public bool MoveNext()
    {
        start = checked((int)(NextOffset == 0 ? 0 : NextOffset - baseOffset));
        while (true)
        {
            var newline = buffer.AsSpan(start, end - start).IndexOf((byte)'\n');
            if (newline >= 0 || eof)
            {
                length = newline >= 0 ? newline : end - start;
                if (eof && length == 0) return false;
                Offset = baseOffset + start;
                NextOffset = Offset + length + (newline >= 0 ? 1 : 0);
                return true;
            }
            var remaining = end - start;
            if (start > 0) Buffer.BlockCopy(buffer, start, buffer, 0, remaining);
            baseOffset += start;
            start = 0;
            end = remaining;
            if (end == buffer.Length) Array.Resize(ref buffer, checked(buffer.Length * 2));
            var read = stream.Read(buffer, end, buffer.Length - end);
            end += read;
            eof = read == 0;
        }
    }
    public string Text => Encoding.UTF8.GetString(Bytes);
    public void Dispose() => stream.Dispose();
}
