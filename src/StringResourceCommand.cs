using System.Security;
using System.Security.Cryptography;
using System.Text;
using EazFixer;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Unpacker;

internal static class StringResourceCommand
{
    internal const string Usage = "用法：Unpacker strings [export] <输入EXE/DLL> [清单.strings.json]\n" +
        "      Unpacker strings apply <输入EXE/DLL> [清单.strings.json] [输出EXE/DLL|--in-place]";
    private const int CatalogVersion = 1;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static int Run(string[] args)
    {
        try
        {
            bool export = args.Length < 2 || args[1] != "apply";
            int first = args.Length >= 2 && (args[1] == "export" || args[1] == "apply") ? 2 : 1;
            if (args.Length <= first || args.Length > first + (export ? 2 : 3))
                throw new CommandException(Usage);
            string input = BinaryPath(args[first]);
            string[] trailing = args.Skip(first + 1).ToArray();
            bool hasCatalog = trailing.Length != 0 && (export || trailing.Length == 2 ||
                !IsBinary(trailing[0]) && trailing[0] != "--in-place");
            if (hasCatalog && trailing[0].StartsWith("--", StringComparison.Ordinal))
                throw new CommandException(Usage);
            string catalog = hasCatalog ? Path.GetFullPath(trailing[0]) : input + ".strings.json";
            if (SamePath(input, catalog)) throw new CommandException("输入程序和字符串清单必须使用不同文件。");
            string? destination = export ? null : trailing.Skip(hasCatalog ? 1 : 0).SingleOrDefault();
            bool inPlace = destination == "--in-place";
            string output = export ? catalog : inPlace ? input : destination == null ?
                Path.ChangeExtension(input, ".edited" + Path.GetExtension(input)) : BinaryPath(destination);
            if (!export && !inPlace && (SamePath(input, output) || SamePath(catalog, output)))
                throw new CommandException("输出路径必须不同；覆盖输入请显式使用 --in-place。");
            if (!File.Exists(input)) throw new CommandException("输入程序不存在。");
            if (!export && !File.Exists(catalog)) throw new CommandException("字符串清单不存在。");
            if (!inPlace && (File.Exists(output) || Directory.Exists(output)))
                throw new CommandException("输出已存在，请选择新路径。");

            byte[] image = File.ReadAllBytes(input);
            string fingerprint = Fingerprint(image);
            if (export)
            {
                var entries = new EncryptedStringEditor(image).GetEntries().ToArray();
                Publish(output, null, stream =>
                {
                    using var writer = new StreamWriter(stream, Utf8, 4096, leaveOpen: true);
                    JsonSerializer.CreateDefault(new JsonSerializerSettings { Formatting = Formatting.Indented })
                        .Serialize(writer, new
                        {
                            version = CatalogVersion, sha256 = fingerprint,
                            entries = entries.Select(e => new { resource = e.Resource, id = e.Id, text = e.Text })
                        });
                });
                Console.WriteLine($"[strings] 已导出 {entries.Length} 项。");
                return 0;
            }

            var edits = ReadCatalog(catalog, fingerprint);
            var editor = new EncryptedStringEditor(image);
            byte[] patched = editor.Apply(edits, out int changes);
            if (changes == 0)
            {
                Console.WriteLine("[strings] 无改动，未写入文件。");
                return 0;
            }

            string? backup = inPlace ? input + ".bak" : null;
            if (backup != null && (File.Exists(backup) || Directory.Exists(backup)))
                throw new CommandException("备份文件已存在；请先移走备份或使用独立输出。");
            Publish(output, backup, stream => stream.Write(patched, 0, patched.Length), inPlace ? fingerprint : null);
            string backupNote = inPlace ? "；已备份原件" : "";
            string signatureNote = editor.HasSignature ? "；原数字签名不再有效" : "";
            Console.WriteLine($"[strings] 已替换 {changes} 项{backupNote}{signatureNote}。");
            return 0;
        }
        catch (JsonException) { return Error("字符串清单不是有效 JSON，或包含重复字段。"); }
        catch (DecoderFallbackException) { return Error("字符串清单编码无效。"); }
        catch (BadImageFormatException) { return Error("输入不是可直接编辑的托管 PE 文件。"); }
        catch (StringResourceException e) { return Error(e.Message); }
        catch (CommandException e) { return Error(e.Message); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException)
        { return Error("无法读取或写入文件，请检查路径、占用和权限。"); }
        catch (Exception e) { return Error("处理失败（" + e.GetType().Name + "）。"); }
    }

    private static List<EncryptedStringEditor.StringEntry> ReadCatalog(string path, string fingerprint)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > 256 * 1024 * 1024) throw new CommandException("字符串清单超过大小限制。");
        using var text = new StreamReader(stream, Utf8, detectEncodingFromByteOrderMarks: true);
        using var reader = new JsonTextReader(text) { MaxDepth = 8, DateParseHandling = DateParseHandling.None };
        var root = JObject.Load(reader, new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
        if (reader.Read() || root["version"] is not JValue { Type: JTokenType.Integer } version ||
            version.ToString() != CatalogVersion.ToString() || root["sha256"] is not JValue { Type: JTokenType.String } sha ||
            root["entries"] is not JArray entries || entries.Count > 250000)
            throw new CommandException("字符串清单格式或版本无效。");
        if (!string.Equals(sha.Value<string>(), fingerprint, StringComparison.OrdinalIgnoreCase))
            throw new CommandException("字符串清单与输入程序不匹配，请重新导出。");

        var edits = new List<EncryptedStringEditor.StringEntry>(entries.Count);
        foreach (var item in entries)
        {
            if (item is not JObject obj || obj["resource"] is not JValue { Type: JTokenType.String } resource ||
                obj["id"] is not JValue { Type: JTokenType.String } id || obj["text"] is not JValue { Type: JTokenType.String } value)
                throw new CommandException("清单条目必须包含 resource、id 和 text 字符串字段。");
            edits.Add(new EncryptedStringEditor.StringEntry
            {
                Resource = resource.Value<string>(), Id = id.Value<string>(), Text = value.Value<string>()
            });
        }
        return edits;
    }

    private static string BinaryPath(string path)
    {
        string full = Path.GetFullPath(path);
        if (!IsBinary(full))
            throw new CommandException("程序文件必须使用 EXE 或 DLL 扩展名。");
        return full;
    }

    private static bool IsBinary(string path) =>
        Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
        Path.GetExtension(path).Equals(".dll", StringComparison.OrdinalIgnoreCase);

    private static bool SamePath(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static string Fingerprint(byte[] image)
    {
        using var sha = SHA256.Create();
        return BitConverter.ToString(sha.ComputeHash(image)).Replace("-", "").ToLowerInvariant();
    }

    private static void Publish(string output, string? backup, Action<FileStream> write, string? expected = null)
    {
        string directory = Path.GetDirectoryName(output)!;
        Directory.CreateDirectory(directory);
        string temp = Path.Combine(directory, ".strings-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                write(stream);
                stream.Flush(flushToDisk: true);
            }
            if (backup == null) File.Move(temp, output);
            else
            {
                if (!string.Equals(expected, Fingerprint(File.ReadAllBytes(output)), StringComparison.Ordinal))
                    throw new CommandException("输入程序在处理期间发生变化，未覆盖原件。");
                if (File.Exists(backup) || Directory.Exists(backup))
                    throw new CommandException("备份文件已存在，未覆盖原件。");
                File.Replace(temp, output, backup);
            }
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    private sealed class CommandException(string message) : Exception(message);

    private static int Error(string message)
    {
        Console.Error.WriteLine("[strings] 错误：" + message);
        return 1;
    }
}
