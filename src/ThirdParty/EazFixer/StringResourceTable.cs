using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;

namespace EazFixer
{
    internal sealed class StringResourceTable
    {
        internal const int MaxTextBytes = 1024 * 1024;
        private const int UnusedFlag = 0x10000000;
        private static readonly Encoding StrictUnicode = new UnicodeEncoding(false, false, true);

        internal readonly EmbeddedResource Resource;
        internal readonly int FileOffset;
        internal readonly byte[] Data;
        private readonly StringResourceLayout _layout;
        private readonly byte[] _token;
        private readonly byte[] _globalSeed;
        private readonly int _seedSize, _first;
        private readonly Dictionary<int, Entry> _entries;
        private int _state;

        internal sealed class Entry
        {
            internal int Offset, Header, Start, Size, Flags;
            internal int? Alias;
            internal string Text;
        }

        internal StringResourceTable(EmbeddedResource resource, StringResourceLayout layout, HashSet<int> callIds, byte[] token)
        {
            Resource = resource;
            _layout = layout;
            _token = token?.Length == 8 ? token : null;
            var reader = resource.CreateReader();
            if (reader.Length < 8 || reader.Length > 128 * 1024 * 1024) throw Invalid();
            FileOffset = checked((int)reader.StartOffset);
            Data = reader.ToArray();

            int globalSize = (short)(Read16(0) ^ layout.GlobalSeedMask);
            if (globalSize == 0)
            {
                _seedSize = (short)(Read16(2) ^ layout.SeedModeMask);
                if (_seedSize != -1 && (_seedSize < 3 || _seedSize > 256)) throw Invalid();
                _first = 4;
            }
            else
            {
                if (globalSize < 3 || globalSize > 256 || globalSize > Data.Length - 2) throw Invalid();
                _globalSeed = Data.Skip(2).Take(globalSize).ToArray();
                _first = 2 + globalSize;
            }

            // An ID is the entry offset XORed with two decoder constants. Use
            // calls as anchors and accept the state only when the entire table
            // partitions into valid records and the anchors agree.
            foreach (int id in callIds)
            {
                int state = id ^ _first ^ layout.PositionMask;
                if (!TryReadTable(state, callIds, out var candidate)) continue;
                if (_entries != null) throw Invalid();
                _entries = candidate;
                _state = state;
            }
            if (_entries == null) throw Invalid();
        }

        internal int Id(Entry entry) => entry.Offset ^ _layout.PositionMask ^ _state;
        internal IEnumerable<Entry> Entries => _entries.Values.Where(entry => !entry.Alias.HasValue).OrderBy(entry => entry.Offset);
        internal Entry Find(int id) => _entries.TryGetValue(id ^ _layout.PositionMask ^ _state, out var e) && !e.Alias.HasValue ? e : null;

        private bool TryReadTable(int state, HashSet<int> callIds, out Dictionary<int, Entry> entries)
        {
            entries = new Dictionary<int, Entry>();
            int matches = 0;
            for (int offset = _first; offset < Data.Length;)
            {
                if (entries.Count >= 250000) return false;
                int header = offset;
                if (_globalSeed == null)
                {
                    int seedLength = _seedSize;
                    if (seedLength == -1)
                    {
                        if (header > Data.Length - 2) return false;
                        seedLength = (short)(Read16(header) ^ _layout.EntrySeedMask ^ offset);
                        header += 2;
                    }
                    if (seedLength < 0 || seedLength > 256 || header > Data.Length - seedLength) return false;
                    header += seedLength;
                }
                if (header > Data.Length - 4) return false;
                int flags = Read32(header) ^ offset ^ _layout.FrameMask ^ state;
                int start = header + 4;
                bool alias = flags == _layout.RedirectMarker;
                int size = alias ? 4 : flags & _layout.LengthMask;
                bool compressed = (flags & _layout.CompressedFlag) != 0;
                bool bytes = (flags & _layout.ByteTextFlag) != 0;
                int seedStart = offset + (_globalSeed == null && _seedSize == -1 ? 2 : 0);
                if (size > MaxTextBytes || size > Data.Length - start ||
                    !alias && ((flags & UnusedFlag) != 0 || _globalSeed == null && header - seedStart < 3 ||
                        (compressed ? size < 4 : !bytes && (size & 1) != 0))) return false;
                var entry = new Entry { Offset = offset, Header = header, Start = start, Size = size, Flags = flags };
                if (alias) entry.Alias = (Data[start + 2] | (Data[start + 3] << 16) |
                    (Data[start] << 8) | (Data[start + 1] << 24)) ^
                    unchecked(-(_layout.RedirectMask ^ state)) ^ _layout.PositionMask ^ state;
                entries.Add(offset, entry);
                if (callIds.Contains(offset ^ _layout.PositionMask ^ state)) matches++;
                offset = start + size;
            }
            if (matches < Math.Min(2, callIds.Count)) return false;
            var known = new HashSet<int>(entries.Values.Where(e => !e.Alias.HasValue).Select(e => e.Offset));
            foreach (var entry in entries.Values.Where(e => e.Alias.HasValue))
            {
                int offset = entry.Offset, steps = 0;
                while (!known.Contains(offset))
                {
                    if (++steps > 256 || !entries.TryGetValue(offset, out var next) || !next.Alias.HasValue) return false;
                    offset = next.Alias.Value;
                }
                known.Add(entry.Offset);
            }

            long textBytes = 0;
            foreach (var entry in entries.Values.Where(e => !e.Alias.HasValue))
            {
                var plain = Transform(Data, entry.Start, entry.Size, ReadSeed(entry, state), _token, false);
                if ((entry.Flags & _layout.CompressedFlag) != 0)
                {
                    plain = Decompress(plain);
                    if (plain == null) return false;
                }
                textBytes += plain.Length;
                if (textBytes > 128 * 1024 * 1024) return false;
                if ((entry.Flags & _layout.ByteTextFlag) != 0)
                    entry.Text = new string(Array.ConvertAll(plain, value => (char)value));
                else
                {
                    if ((plain.Length & 1) != 0) return false;
                    entry.Text = Encoding.Unicode.GetString(plain);
                }
            }
            return true;
        }

        internal void Replace(byte[] output, Entry entry, string text)
        {
            if (text.Length > MaxTextBytes) throw new StringResourceException("替换文本超过大小限制。");
            byte[] unicode;
            try { unicode = StrictUnicode.GetBytes(text); }
            catch (EncoderFallbackException) { throw new StringResourceException("替换文本包含无效的 UTF-16 字符。"); }
            byte[] narrow = text.All(ch => ch <= 255) ? Array.ConvertAll(text.ToCharArray(), ch => (byte)ch) : null;
            var choices = (narrow != null
                    ? new[] { (Bytes: narrow, Flag: _layout.ByteTextFlag), (Bytes: unicode, Flag: 0) }
                    : new[] { (Bytes: unicode, Flag: 0) })
                .Where(choice => choice.Bytes.Length <= MaxTextBytes).ToArray();
            foreach (var choice in choices)
                if (choice.Bytes.Length == entry.Size)
                {
                    WriteFrame(output, entry, choice.Bytes, choice.Flag);
                    return;
                }
            foreach (var choice in choices.OrderBy(choice => choice.Bytes.Length))
            {
                var packed = Compress(choice.Bytes, entry.Size);
                if (packed == null) continue;
                WriteFrame(output, entry, packed, choice.Flag | _layout.CompressedFlag);
                return;
            }
            throw new StringResourceException("条目 " + unchecked((uint)Id(entry)).ToString("X8") +
                " 的替换文本无法装入原密文槽位（容量 " + entry.Size + " 字节）。");
        }

        private void WriteFrame(byte[] output, Entry entry, byte[] payload, int flags)
        {
            byte[] encrypted = Transform(payload, 0, payload.Length, ReadSeed(entry, _state), _token, true);
            int header = (entry.Flags & ~(_layout.ByteTextFlag | _layout.CompressedFlag)) | flags;
            Write32(output, FileOffset + entry.Header, header ^ entry.Offset ^ _layout.FrameMask ^ _state);
            Buffer.BlockCopy(encrypted, 0, output, FileOffset + entry.Start, encrypted.Length);
        }

        private byte[] ReadSeed(Entry entry, int state)
        {
            if (_globalSeed != null) return _globalSeed;
            int start = entry.Offset + (_seedSize == -1 ? 2 : 0);
            return new[] { (byte)(Data[start] ^ state), (byte)(Data[start + 1] ^ (state >> 8)),
                (byte)(Data[start + 2] ^ (state >> 16)) };
        }

        private static byte[] Transform(byte[] source, int offset, int length, byte[] seed, byte[] token, bool encrypt)
        {
            var result = new byte[length];
            int middle = seed[1];
            byte previous = (byte)((length + 11) ^ (middle + 7));
            uint state = (uint)((seed[0] | (seed[2] << 8)) + (previous << 3));
            for (int i = 0; i < length; i++)
            {
                if ((i & 1) == 0) state = unchecked(state * 214013 + 2531011);
                byte mask = (byte)(middle ^ (previous + 3) ^ (state >> (16 + ((i & 1) << 3))));
                if (token != null)
                {
                    int key = token[i & 7];
                    mask ^= (byte)((key << 3) | (key >> 5));
                }
                byte input = source[offset + i];
                result[i] = (byte)(input ^ mask);
                previous = encrypt ? result[i] : input;
            }
            return result;
        }

        private static byte[] Decompress(byte[] input)
        {
            int size = input[2] | (input[3] << 8) | (input[0] << 16) | (input[1] << 24);
            if (size < 0 || size > MaxTextBytes) return null;
            var output = new byte[size];
            int src = 4, dst = 0;
            while (dst < size)
            {
                if (src >= input.Length) return null;
                int mask = input[src++];
                for (int bit = 0; bit < 8 && dst < size; bit++)
                {
                    if (src >= input.Length) return null;
                    if ((mask & (1 << bit)) == 0)
                    {
                        output[dst++] = input[src++];
                        continue;
                    }
                    if (src > input.Length - 2) return null;
                    int pair = (input[src] << 8) | input[src + 1];
                    src += 2;
                    int distance = pair & 1023;
                    if (distance == 0 || distance > dst) return null;
                    for (int count = (pair >> 10) + 3; count > 0 && dst < size; count--)
                    {
                        output[dst] = output[dst - distance];
                        dst++;
                    }
                }
            }
            return output;
        }

        // LZ records use a low-bit-first control byte and 10-bit lookback.
        // The original decoder stops at the stored plaintext length, so bytes
        // after the last token may pad the encrypted slot without changing text.
        private static byte[] Compress(byte[] input, int capacity)
        {
            if (capacity < 4 || input.Length > (capacity - 4L) * 33) return null;
            var output = new byte[capacity];
            int length = input.Length;
            output[0] = (byte)(length >> 16); output[1] = (byte)(length >> 24);
            output[2] = (byte)length; output[3] = (byte)(length >> 8);
            var previous = new int[length];
            var last = new Dictionary<int, int>();
            int src = 0, dst = 4;
            while (src < length)
            {
                if (dst >= capacity) return null;
                int control = dst++;
                for (int bit = 0; bit < 8 && src < length; bit++)
                {
                    int best = 2, distance = 0;
                    if (src + 2 < length && last.TryGetValue(Triplet(input, src), out int pos))
                    {
                        int max = Math.Min(66, length - src);
                        for (int steps = 0; pos >= 0 && src - pos <= 1023 && steps < 64; steps++, pos = previous[pos])
                        {
                            int match = 3;
                            while (match < max && input[src + match] == input[pos + match]) match++;
                            if (match <= best) continue;
                            best = match; distance = src - pos;
                            if (match == max) break;
                        }
                    }
                    int take = distance == 0 ? 1 : best;
                    if (distance == 0)
                    {
                        if (dst == capacity) return null;
                        output[dst++] = input[src];
                    }
                    else
                    {
                        if (dst > capacity - 2) return null;
                        int pair = ((best - 3) << 10) | distance;
                        output[control] |= (byte)(1 << bit);
                        output[dst++] = (byte)(pair >> 8);
                        output[dst++] = (byte)pair;
                    }
                    for (int end = src + take; src < end; src++)
                    {
                        if (src + 2 >= length) continue;
                        int key = Triplet(input, src);
                        previous[src] = last.TryGetValue(key, out int old) ? old : -1;
                        last[key] = src;
                    }
                }
            }
            return output;
        }

        private static int Triplet(byte[] input, int i) => input[i] | (input[i + 1] << 8) | (input[i + 2] << 16);
        private int Read16(int i) => Data[i] | (Data[i + 1] << 8);
        private int Read32(int i) => Read16(i) | (Read16(i + 2) << 16);
        private static void Write32(byte[] output, int i, int value)
        {
            for (int b = 0; b < 4; b++) output[i + b] = (byte)(value >> (8 * b));
        }

        private static StringResourceException Invalid() => new StringResourceException("无法验证 Eaz 字符串资源的记录边界或解码参数。");
    }
}
