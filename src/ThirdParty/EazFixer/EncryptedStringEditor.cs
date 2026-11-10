using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using EazFixer.Processors;

namespace EazFixer
{
    /// <summary>Edits verified embedded string tables without loading the target into the CLR.</summary>
    public sealed class EncryptedStringEditor
    {
        private readonly byte[] _image;
        private readonly Dictionary<string, StringResourceTable> _tables;
        public bool HasSignature { get; }

        public sealed class StringEntry
        {
            public string Resource { get; set; }
            public string Id { get; set; }
            public string Text { get; set; }
        }

        public EncryptedStringEditor(byte[] image)
        {
            _image = image ?? throw new ArgumentNullException(nameof(image));
            using (var module = ModuleDefMD.Load(image))
            {
                HasSignature = module.IsStrongNameSigned ||
                    module.Metadata.PEImage.ImageNTHeaders.OptionalHeader.DataDirectories[4].Size != 0;
                var wrappers = new Dictionary<MethodDef, MethodDef>();
                foreach (var wrapper in StringFixUtils.FindStringDecryptMethods(module))
                {
                    var core = StringFixUtils.FindDecoderCore(wrapper, true);
                    if (core != null) wrappers.Add(wrapper, core);
                }
                if (wrappers.Count == 0) throw new StringResourceException("未发现受支持的 Eaz 字符串资源解码器。");

                var ids = wrappers.Values.Distinct().ToDictionary(m => m, m => new HashSet<int>());
                CollectIds(module, wrappers, ids);
                var token = module.Assembly?.PublicKeyToken?.Data;
                _tables = new Dictionary<string, StringResourceTable>(StringComparer.Ordinal);
                foreach (var pair in ids)
                {
                    var layout = StringResourceLayout.Detect(pair.Key);
                    var resources = module.Resources.OfType<EmbeddedResource>().Where(r => r.Name == layout.ResourceName).ToArray();
                    if (resources.Length != 1) throw new StringResourceException("解码器没有唯一的嵌入字符串资源。");
                    var resource = resources[0];
                    var table = new StringResourceTable(resource, layout, pair.Value, token, pair.Key);
                    string key = Hex(checked((int)resource.Rid));
                    if (_tables.ContainsKey(key)) throw new StringResourceException("同一资源关联多个解码器。");
                    if (table.FileOffset < 4 || table.Data.Length > image.Length - table.FileOffset ||
                        BitConverter.ToInt32(image, table.FileOffset - 4) != table.Data.Length)
                        throw new BadImageFormatException("资源不在可直接写入的 PE 文件范围内。");
                    for (int i = 0; i < table.Data.Length; i++)
                        if (table.Data[i] != image[table.FileOffset + i]) throw new BadImageFormatException("资源文件映射不一致。");
                    _tables.Add(key, table);
                }
                foreach (var table in _tables.Values)
                    foreach (var other in module.Resources.OfType<EmbeddedResource>())
                    {
                        if (other == table.Resource) continue;
                        var reader = other.CreateReader();
                        if (reader.StartOffset < 4) continue;
                        if (table.FileOffset - 4 < reader.EndOffset && reader.StartOffset - 4 < table.FileOffset + table.Data.Length)
                            throw new BadImageFormatException("Eaz 字符串资源文件范围重叠。");
                    }
            }
        }

        public IEnumerable<StringEntry> GetEntries() => _tables.OrderBy(p => p.Key, StringComparer.Ordinal)
            .SelectMany(p => p.Value.Entries.Select(e => new StringEntry { Resource = p.Key, Id = Hex(p.Value.Id(e)), Text = e.Text }));

        public byte[] Apply(IEnumerable<StringEntry> edits, out int changes)
        {
            var pending = new List<(StringResourceTable Table, StringResourceTable.Entry Entry, string Text)>();
            var unique = new HashSet<(string Resource, int Id)>();
            foreach (var edit in edits)
            {
                if (edit?.Resource == null || edit.Id == null || edit.Text == null || edit.Id.Length != 8 ||
                    !uint.TryParse(edit.Id, System.Globalization.NumberStyles.AllowHexSpecifier, System.Globalization.CultureInfo.InvariantCulture, out uint id) ||
                    !_tables.TryGetValue(edit.Resource, out var table) || !unique.Add((edit.Resource, unchecked((int)id))) ||
                    table.Find(unchecked((int)id)) is not StringResourceTable.Entry entry)
                    throw new StringResourceException("编辑清单包含无效、重复或未知的资源条目。");
                if (!string.Equals(edit.Text, entry.Text, StringComparison.Ordinal))
                    pending.Add((table, entry, edit.Text));
            }
            changes = pending.Count;
            if (changes == 0) return _image;

            var output = (byte[])_image.Clone();
            var resized = new List<(StringResourceTable Table, Dictionary<StringResourceTable.Entry, string> Edits)>();
            foreach (var group in pending.GroupBy(e => e.Table))
            {
                if (group.Any(edit => !edit.Table.TryReplace(output, edit.Entry, edit.Text)))
                    resized.Add((group.Key, group.ToDictionary(edit => edit.Entry, edit => edit.Text)));
            }
            if (resized.Count != 0) output = RewriteResources(output, resized);

            var reread = new EncryptedStringEditor(output);
            var expected = pending.ToDictionary(e => (e.Table, e.Entry), e => e.Text);
            if (reread._tables.Count != _tables.Count) throw VerificationFailed();
            foreach (var pair in _tables)
            {
                if (!reread._tables.TryGetValue(pair.Key, out var verified) ||
                    !pair.Value.HasSameLayoutIds(verified)) throw VerificationFailed();
                foreach (var entry in pair.Value.Entries)
                    if (verified.Find(pair.Value.Id(entry))?.Text !=
                        (expected.TryGetValue((pair.Value, entry), out var text) ? text : entry.Text))
                        throw VerificationFailed();
            }
            return output;
        }

        private static byte[] RewriteResources(byte[] image,
            List<(StringResourceTable Table, Dictionary<StringResourceTable.Entry, string> Edits)> changes)
        {
            using (var module = ModuleDefMD.Load(image))
            using (var output = new MemoryStream())
            {
                if (!module.IsILOnly || module.Metadata.ImageCor20Header.ManagedNativeHeader.VirtualAddress != 0)
                    throw new StringResourceException("此 PE 含本机代码，无法扩容字符串资源。");
                EazContext.PreserveSerializedMaxStack(module);
                foreach (var (table, edits) in changes)
                {
                    if (!(module.ResolveToken(table.DecoderToken) is MethodDef decoder)) throw VerificationFailed();
                    int index = module.Resources.ToList().FindIndex(resource => resource.Rid == table.Resource.Rid &&
                        resource.Name == table.Resource.Name && resource is EmbeddedResource);
                    if (index < 0) throw VerificationFailed();
                    var resource = module.Resources[index];
                    var rebuilt = table.Rebuild(edits);
                    module.Resources[index] = new EmbeddedResource(resource.Name, rebuilt.Data, resource.Attributes) { Rid = resource.Rid };
                    StringResourceOffsets.Install(module, decoder, rebuilt.Offsets);
                }
                module.Write(output, new ModuleWriterOptions(module) { MetadataOptions = { Flags = MetadataFlags.PreserveAll } });
                return output.ToArray();
            }
        }

        private static void CollectIds(ModuleDefMD module, Dictionary<MethodDef, MethodDef> wrappers,
            Dictionary<MethodDef, HashSet<int>> ids)
        {
            var names = wrappers.ToDictionary(p => p.Key.FullName, p => p.Value, StringComparer.Ordinal);
            foreach (var method in module.GetTypes().SelectMany(t => t.Methods).Where(m => m.HasBody && m.Body.HasInstructions))
            {
                var body = method.Body;
                if (!body.Instructions.Any(i => i.OpCode.Code == Code.Call && i.Operand is IMethod m &&
                    (m is MethodDef def ? wrappers.ContainsKey(def) : names.ContainsKey(m.FullName)))) continue;
                var boundaries = StringFixer.GetBoundaries(body);
                var tracker = new ConstantArgumentTracker(body);
                foreach (var instruction in body.Instructions)
                {
                    if (boundaries.Contains(instruction)) tracker.Reset();
                    if (instruction.OpCode.Code == Code.Call && tracker.Top is int id && instruction.Operand is IMethod callee)
                    {
                        MethodDef core = null;
                        bool found = callee is MethodDef definition ? wrappers.TryGetValue(definition, out core) :
                            callee.DeclaringType.DefinitionAssembly?.FullName == module.Assembly?.FullName &&
                            names.TryGetValue(callee.FullName, out core);
                        if (found) ids[core].Add(id);
                    }
                    tracker.Step(instruction, body);
                }
            }
        }

        private static string Hex(int value) => unchecked((uint)value).ToString("X8");
        private static StringResourceException VerificationFailed() => new StringResourceException("回写后的 Eaz 字符串校验失败。");
    }
}
