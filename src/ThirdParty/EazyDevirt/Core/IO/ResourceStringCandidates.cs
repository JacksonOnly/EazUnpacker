using System.Resources;
using System.Text;
using AsmResolver.DotNet;
using EazyDevirt.Devirtualization;

namespace EazyDevirt.Core.IO;

/// <summary>Reads bounded resource candidates as data, without loading asset assemblies.</summary>
internal sealed class ResourceStringCandidates(DevirtualizationContext context)
{
    private const int MaxCandidates = 8192;
    private const int MaxFiles = 64;
    private const int MaxFileBytes = 32 * 1024 * 1024;
    private const int MaxResourceBytes = 4 * 1024 * 1024;
    private const int MaxTotalBytes = 64 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private string[]? local, external;
    private long bytesRead;
    private int skipped;

    internal IEnumerable<string> Local()
    {
        if (local != null) return local;
        var values = new HashSet<string>(StringComparer.Ordinal);
        var codes = typeof(ResourceReader).Assembly.GetType("System.Resources.ResourceTypeCode");
        if (codes?.IsEnum == true)
            foreach (string name in Enum.GetNames(codes)) Add(values, "ResourceTypeCode." + name);
        ReadModule(context.Module, values);
        return local = values.ToArray();
    }

    internal IEnumerable<string> External()
    {
        if (external != null) return external;
        var values = new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { context.Options.Assembly.FullName };
        int files = 0;
        bool limited = false;
        foreach (string path in AssetPaths())
        {
            if (files >= MaxFiles || values.Count >= MaxCandidates || bytesRead >= MaxTotalBytes) { limited = true; break; }
            if (!seen.Add(path)) continue;
            try
            {
                long size = new FileInfo(path).Length;
                if (size <= 0 || size > MaxFileBytes || size > MaxTotalBytes - bytesRead) { skipped++; continue; }
                bytesRead += size;
                files++;
                string extension = Path.GetExtension(path);
                if (extension.Equals(".resources", StringComparison.OrdinalIgnoreCase))
                    ReadResources(File.ReadAllBytes(path), values);
                else if (extension.Equals(".baml", StringComparison.OrdinalIgnoreCase))
                    ReadLengthPrefixedStrings(File.ReadAllBytes(path), values);
                else
                    ReadModule(ModuleDefinition.FromFile(path), values);
            }
            catch (Exception ex) when (IsInvalidAsset(ex)) { skipped++; }
        }
        external = values.ToArray();
        string message = $"[密钥] 外部资源候选：读取 {files} 个文件，提取 {external.Length} 项，跳过 {skipped} 项" +
            (limited ? "；达到扫描上限" : "") + "；仍须通过原校验。";
        context.Console.Summary(message);
        context.Progress?.Invoke(message, 0, 0);
        return external;
    }

    private IEnumerable<string> AssetPaths()
    {
        // Explicit assets take precedence over flat, declared probing directories.
        // Never search the disk recursively or consult an implicit key cache.
        var paths = (Environment.GetEnvironmentVariable("UNPACKER_VM_KEY_ASSET_PATHS") ?? "")
            .Split(Path.PathSeparator).Where(p => !string.IsNullOrWhiteSpace(p))
            .Concat(Enumerable.Reverse(context.Options.DependencyDirectories))
            .Concat(new[] { Path.GetDirectoryName(context.Options.Assembly.FullName)! });
        foreach (string value in paths)
        {
            string path;
            try { path = Path.GetFullPath(value.Trim()); }
            catch (Exception ex) when (IsInvalidAsset(ex)) { skipped++; continue; }
            if (File.Exists(path))
            {
                if (Supported(path)) yield return path;
                else skipped++;
                continue;
            }
            string[] files;
            try
            {
                if (!Directory.Exists(path)) { skipped++; continue; }
                files = Directory.GetFiles(path);
            }
            catch (Exception ex) when (IsInvalidAsset(ex)) { skipped++; continue; }
            foreach (string file in files.Where(Supported).OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
                yield return file;
        }
    }

    private static bool Supported(string path) => Path.GetExtension(path).ToLowerInvariant() is ".dll" or ".exe" or ".resources" or ".baml";

    private void ReadModule(ModuleDefinition module, HashSet<string> values)
    {
        foreach (var resource in module.Resources.Where(r => r.IsEmbedded))
        {
            if (values.Count >= MaxCandidates) break;
            try
            {
                byte[]? data = resource.GetData();
                if (data == null || data.Length > MaxFileBytes) { skipped++; continue; }
                if (data.Length >= 4 && BitConverter.ToUInt32(data, 0) == 0xBEEFCACE)
                    ReadResources(data, values);
                else if (resource.Name?.ToString().EndsWith(".baml", StringComparison.OrdinalIgnoreCase) == true)
                    ReadLengthPrefixedStrings(data, values);
            }
            catch (Exception ex) when (IsInvalidAsset(ex)) { skipped++; }
        }
    }

    private void ReadResources(byte[] data, HashSet<string> values)
    {
        if (data.Length > MaxFileBytes) { skipped++; return; }
        using var reader = new ResourceReader(new MemoryStream(data, false));
        var entries = reader.GetEnumerator();
        while (values.Count < MaxCandidates && entries.MoveNext())
        {
            // Accessing Key/GetResourceData does not deserialize resource objects.
            string name = (string)entries.Key;
            reader.GetResourceData(name, out string type, out byte[] raw);
            Add(values, name);
            Add(values, type);
            Add(values, type.Split(',')[0]);
            if (type == "ResourceTypeCode.String")
            {
                if (TryString(raw, 0, out string? text)) Add(values, text!);
            }
            else if ((type is "ResourceTypeCode.Stream" or "ResourceTypeCode.ByteArray") &&
                     name.EndsWith(".baml", StringComparison.OrdinalIgnoreCase) && raw.Length >= 4 &&
                     BitConverter.ToInt32(raw, 0) == raw.Length - 4)
                ReadLengthPrefixedStrings(raw, values, 4);
        }
    }

    private static void ReadLengthPrefixedStrings(byte[] data, HashSet<string> values, int start = 0)
    {
        // BAML records contain seven-bit-length-prefixed UTF-8 strings. These
        // are candidates, not a claim that every matching span is a Text record.
        // Acceptance always uses the protected method's original verifier.
        if (data.Length > MaxResourceBytes) return;
        for (int offset = start; offset < data.Length && values.Count < MaxCandidates; offset++)
            if (TryString(data, offset, out string? text)) Add(values, text!);
    }

    private static bool TryString(byte[] data, int offset, out string? text)
    {
        text = null;
        int length = 0, shift = 0, prefix = 0;
        bool complete = false;
        while (offset < data.Length && shift < 21)
        {
            int value = data[offset++];
            prefix++;
            length |= (value & 127) << shift;
            if ((value & 128) == 0) { complete = true; break; }
            shift += 7;
        }
        if (!complete || length <= 0 || length > 2048 || length > data.Length - offset ||
            (prefix > 1 && length < (1 << (7 * (prefix - 1))))) return false;
        for (int i = offset; i < offset + length; i++)
            if (data[i] < 32 && data[i] != 9 && data[i] != 10 && data[i] != 13) return false;
        try { text = StrictUtf8.GetString(data, offset, length); }
        catch (DecoderFallbackException) { return false; }
        return text.Length <= 512 && text.All(c => !char.IsControl(c) || c is '\r' or '\n' or '\t');
    }

    private static void Add(HashSet<string> values, string value)
    {
        if (values.Count < MaxCandidates && value.Length is > 0 and <= 512) values.Add(value);
    }

    private static bool IsInvalidAsset(Exception ex) => ex is IOException or UnauthorizedAccessException or
        ArgumentException or BadImageFormatException or FormatException or InvalidOperationException or
        NotSupportedException or OverflowException or IndexOutOfRangeException;
}
