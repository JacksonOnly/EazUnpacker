using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
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
                    var candidates = wrapper.Body.Instructions.Where(i => i.OpCode.Code == Code.Call)
                        .Select(i => (i.Operand as IMethod)?.ResolveMethodDef())
                        .Where(m => m != null && m.DeclaringType == wrapper.DeclaringType && m.IsStatic && m.HasBody &&
                            m.MethodSig?.RetType.ElementType == ElementType.String && m.MethodSig.Params.Count == 2 &&
                            m.MethodSig.Params[0].ElementType == ElementType.I4 && m.MethodSig.Params[1].ElementType == ElementType.Boolean &&
                            m.Body.Instructions.Any(i => i.Operand is IMethod op && op.Name == "GetManifestResourceStream" &&
                                op.DeclaringType.FullName == "System.Reflection.Assembly"))
                        .Distinct().ToArray();
                    if (candidates.Length > 1) throw new StringResourceException("Eaz 字符串解码入口不唯一。");
                    if (candidates.Length == 1) wrappers.Add(wrapper, candidates[0]);
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
                    var table = new StringResourceTable(resource, layout, pair.Value, token);
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
            foreach (var edit in pending) edit.Table.Replace(output, edit.Entry, edit.Text);
            var reread = new EncryptedStringEditor(output);
            var expected = pending.ToDictionary(e => (e.Table, e.Entry), e => e.Text);
            foreach (var pair in _tables)
            {
                if (!reread._tables.TryGetValue(pair.Key, out var verified)) throw VerificationFailed();
                foreach (var entry in pair.Value.Entries)
                    if (verified.Find(pair.Value.Id(entry))?.Text !=
                        (expected.TryGetValue((pair.Value, entry), out var text) ? text : entry.Text))
                        throw VerificationFailed();
            }
            return output;
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
