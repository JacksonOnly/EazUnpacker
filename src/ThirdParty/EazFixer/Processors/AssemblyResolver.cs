using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer.Processors
{
    internal class AssemblyResolver : ProcessorBase
    {
        private TypeDef _assemblyResolver;
        private List<MethodDef> _manifestMethods;
        internal List<EmbeddedAssemblyExport> Exports { get; } = new List<EmbeddedAssemblyExport>();
        private List<EmbeddedAssemblyInfo> _assemblies;
        private MethodInfo _decrypter;
        private MethodInfo _decompressor;
        public int ExtractedCount { get; private set; }

        internal Dictionary<string,byte[]> RepackResources(ModuleDef source,ModuleDef edited,IEnumerable<Assembly> assemblies,
            IEnumerable<string> requested,out HashSet<string> handled)=>
            ResourceRepacker.Pack(source,edited,assemblies,requested,_decrypter,_decompressor,out handled);

        protected override void InitializeInternal()
        {
            //try to find the embedded assemblies string, which is located in 
            //the iterator in the EnumerateEmbeddedAssemblies function
            if (!Flags.AsmResTypeTok.IsNull)
                _assemblyResolver = Ctx.Module.ResolveToken(Flags.AsmResTypeTok) as TypeDef
                                    ?? throw new Exception("AssemblyResolver token set but type not found");
            else
                _assemblyResolver = Ctx.Module.GetTypes().SingleOrDefault(CanBeAssemblyResolver)
                                    ?? throw new ProtectionNotFoundException("No assembly resolver event registration found");

            if (!Flags.AsmResMoveNextTok.IsNull)
                _manifestMethods = new List<MethodDef> { Ctx.Module.ResolveToken(Flags.AsmResMoveNextTok) as MethodDef
                    ?? throw new Exception("MoveNext token set but method not found") };
            else
            {
                _manifestMethods = Utils.GetMethodsRecursive(_assemblyResolver).Where(method => method.HasBody && CanBeMoveNext(method)).ToList();
                if (_manifestMethods.Count == 0)
                    _manifestMethods = Utils.GetMethodsRecursive(_assemblyResolver).Where(method => method.HasBody).ToList();
            }
            //find the decryption methods

            MethodDef dec1;
            if (!Flags.AsmResDecryptTok.IsNull)
                dec1 = Ctx.Module.ResolveToken(Flags.AsmResDecryptTok) as MethodDef
                       ?? throw new Exception("Decrypter token set but method not found");
            else
                dec1 = _assemblyResolver.Methods.SingleOrDefault(CanBeDecryptionMethod);

            if (dec1 != null) _decrypter = Utils.FindMethod(Ctx.Assembly, dec1, new[] { typeof(byte[]) });

            MethodDef dec2;
            if (!Flags.AsmResDecompressTok.IsNull)
                dec2 = Ctx.Module.ResolveToken(Flags.AsmResDecompressTok) as MethodDef
                        ?? throw new Exception("Decompressor token set but method not found");
            else
                dec2 = _assemblyResolver.Methods.SingleOrDefault(CanBeDecompressionMethod);

            //this one may be null
            if (dec2 != null)
                _decompressor = Utils.FindMethod(Ctx.Assembly, dec2, new[] {typeof(byte[])})
                                ?? throw new Exception("Couldn't find prefix remover through reflection");
        }

        protected override void ProcessInternal()
        {
            var path = Path.GetDirectoryName(Path.GetFullPath(Flags.OutFile));
            Directory.CreateDirectory(path);
            var manifests = new List<EmbeddedAssemblyInfo>();
            foreach (var method in _manifestMethods)
                foreach (var literal in method.Body.Instructions.Where(instruction => instruction.OpCode.Code == Code.Ldstr))
                    if (TryParseManifest(literal.Operand as string, out var entries)) manifests.AddRange(entries);
            if (manifests.Count == 0) throw new Exception("Could not find a valid embedded assembly manifest");
            manifests = manifests.GroupBy(item => item.Fullname + "\n" + item.ResourceName + "\n" + item.Filename).Select(group => group.First()).ToList();
            int aliases = manifests.Count(item => item.Fullname.StartsWith("#A,A,", StringComparison.Ordinal));
            _assemblies = manifests.Where(item => !item.Fullname.StartsWith("#A,A,", StringComparison.Ordinal)).ToList();
            var resourceResolver = Ctx.Processors.OfType<ResourceResolver>().FirstOrDefault();
            var resourceNames = new HashSet<string>((resourceResolver?.ResourceAssemblies ?? new List<Assembly>())
                .Select(assembly => assembly.GetName().Name), StringComparer.OrdinalIgnoreCase);
            int skippedResources = 0, extracted = 0;
            var report = new List<string>();
            foreach (var assembly in _assemblies)
            {
                try
                {
                    if (resourceNames.Contains(new AssemblyName(assembly.Fullname).Name)) { skippedResources++; continue; }
                    byte[] buffer;
                    using (var stream = Ctx.Assembly.GetManifestResourceStream(assembly.ResourceName))
                    {
                        if (stream == null) throw new InvalidDataException("Embedded resource not found: " + assembly.ResourceName);
                        using (var data = new MemoryStream()) { stream.CopyTo(data); buffer = data.ToArray(); }
                    }
                    if (assembly.Encrypted)
                    {
                        if (_decrypter == null) throw new Exception("No unambiguous assembly decrypter found");
                        buffer = _decrypter.Invoke(null, new object[] { buffer }) as byte[] ?? throw new InvalidDataException("Assembly decrypter returned no bytes");
                    }
                    if (assembly.Compressed)
                    {
                        if (_decompressor == null) throw new Exception("No unambiguous assembly decompressor found");
                        buffer = _decompressor.Invoke(null, new object[] { buffer }) as byte[] ?? throw new InvalidDataException("Assembly decompressor returned no bytes");
                    }
                    string filename, identity;
                    using (var module = ModuleDefMD.Load(buffer))
                    {
                        if (module.Assembly == null) throw new InvalidDataException("Embedded image is not an assembly");
                        var expected = new AssemblyName(assembly.Fullname);
                        var actual = new AssemblyName(module.Assembly.FullName);
                        if (!string.Equals(actual.Name, expected.Name, StringComparison.OrdinalIgnoreCase)
                            || expected.Version != null && actual.Version != expected.Version
                            || !string.Equals(actual.CultureName ?? "", expected.CultureName ?? "", StringComparison.OrdinalIgnoreCase)
                            || !(actual.GetPublicKeyToken() ?? new byte[0]).SequenceEqual(expected.GetPublicKeyToken() ?? new byte[0]))
                            throw new InvalidDataException("Extracted assembly identity mismatch: expected " + assembly.Fullname + "; actual " + module.Assembly.FullName);
                        filename = actual.Name + (module.EntryPoint == null ? ".dll" : ".exe");
                        identity = actual.FullName;
                    }
                    if (filename != Path.GetFileName(filename) || filename.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                        throw new InvalidDataException("Embedded assembly filename is not a simple filename");
                    var destination = Path.Combine(path, filename);
                    // An embedded alias must never overwrite the main recovered assembly.
                    if (string.Equals(Path.GetFullPath(destination), Path.GetFullPath(Flags.OutFile), StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("Embedded assembly destination collides with the recovered output");
                    if (File.Exists(destination) && !File.ReadAllBytes(destination).SequenceEqual(buffer))
                        throw new InvalidDataException("Conflicting embedded assembly filename.");
                    if (!File.Exists(destination)) File.WriteAllBytes(destination, buffer);
                    Exports.Add(new EmbeddedAssemblyExport { File=destination, Identity=identity, Resource=assembly.ResourceName,
                        Format=aliases==0 ? "eaz" : "eaz-aliased" });
                    extracted++; ExtractedCount++;
                    report.Add("Extracted: " + assembly.Fullname + " -> " + destination);
                }
                catch (Exception error)
                {
                    var message = assembly.Fullname + ": " + error.GetBaseException().Message;
                    Warn(message); report.Add("Failed: " + message);
                }
            }
            Summary = "ManifestItems=" + manifests.Count + "; AliasesSkipped=" + aliases + "; ResourceAssembliesSkipped=" + skippedResources +
                "; Extracted=" + extracted + "; Failures=" + WarningCount + ". Runtime resolver dependencies preserved.";
            report.Insert(0, Summary);
            File.WriteAllLines(Path.Combine(path, "embedded-assemblies.txt"), report, Encoding.UTF8);
        }

        internal static bool TryParseManifest(string text, out List<EmbeddedAssemblyInfo> entries)
        {
            entries = null;
            if (string.IsNullOrEmpty(text) || text.IndexOf(',') < 0) return false;
            try
            {
                var parsed = EnumerateEmbeddedAssemblies(text).ToList();
                if (parsed.Count == 0) return false;
                foreach (var item in parsed)
                {
                    if (string.IsNullOrEmpty(item.ResourceName) || string.IsNullOrEmpty(item.Filename)) return false;
                    if (!item.Fullname.StartsWith("#A,A,", StringComparison.Ordinal))
                        if (string.IsNullOrWhiteSpace(new AssemblyName(item.Fullname).Name)) return false;
                }
                entries = parsed; return true;
            }
            catch (FormatException) { return false; }
            catch (ArgumentException) { return false; }
            catch (FileLoadException) { return false; }
        }
        // The pipeline removes a resolver only after proving its payloads
        // are publishable and that no live IL still uses the resolver.
        protected override void CleanupInternal() { }

        private bool CanBeAssemblyResolver(TypeDef t)
        {
            // Registering AssemblyResolve is not sufficient evidence of an Eaz
            // embedded-assembly runtime (ordinary applications do so too).
            // Eaz extraction APIs contain an enumerable MoveNext manifest reader.
            if(!Utils.GetMethodsRecursive(t).Any(CanBeMoveNext))return false;
            foreach (MethodDef m in t.Methods.Where(a => a.HasBody && a.Body.HasInstructions)) {
                //adds AssemblyResolver
                bool addsResolver = m.Body.Instructions.Any(i => (i.OpCode.Code == Code.Callvirt || i.OpCode.Code == Code.Call) && i.Operand is IMethod mr && mr.Name == "add_AssemblyResolve");
                if (addsResolver)
                    return true;
            }

            return false;
        }

        private bool CanBeExtractionApi(TypeDef t) => t.HasNestedTypes && t.IsAbstract && t.IsSealed && t.NestedTypes.Any(CanBeEnumerable);
        private bool CanBeEnumerable(TypeDef t) => t.HasInterfaces && t.Interfaces.Any(a => a.Interface.Name == "IEnumerable");
        private bool CanBeMoveNext(MethodDef m) => m.Overrides.Any(a => a.MethodDeclaration.FullName == "System.Boolean System.Collections.IEnumerator::MoveNext()");

        private bool CanBeDecryptionMethod(MethodDef m) => m.MethodSig.ToString() == "System.Byte[] (System.Byte[])" && m.IsNoInlining;
        private bool CanBeDecompressionMethod(MethodDef m) => m.MethodSig.ToString() == "System.Byte[] (System.Byte[])" && !m.IsNoInlining;

        private static IEnumerable<EmbeddedAssemblyInfo> EnumerateEmbeddedAssemblies(string text)
        {
            var split = text.Split(',');

            // newer versions of eaz have an extra entry at the start, so skip that
            var firstIndex = split.Length % 4;
            for (int i = firstIndex; i < split.Length; i += 4)
            {
                string b64 = split[i];
                string resName = split[i + 1];
                var asm = new EmbeddedAssemblyInfo { FullnameBase64 = b64 };

                //check flags
                int posPipe = resName.IndexOf('|');
                if (posPipe >= 0)
                {
                    string flags = resName.Substring(0, posPipe);
                    resName = resName.Substring(posPipe + 1);

                    asm.Encrypted = flags.IndexOf('a') != -1;
                    asm.Compressed = flags.IndexOf('b') != -1;
                    asm.MustLoadfromDisk = flags.IndexOf('c') != -1;
                    asm.AlternateDirectory = flags.IndexOf('f') != -1;
                }
                asm.ResourceName = resName;
                asm.FilenameBase64 = split[i + 2];

                yield return asm;
            }
        }

        [DebuggerDisplay("{" + nameof(Fullname) + "}")]
        internal class EmbeddedAssemblyInfo
        {
            public string Fullname {
                get {
                    if (_fullname != null) return _fullname;
                    byte[] array = Convert.FromBase64String(FullnameBase64);
                    return _fullname = Encoding.UTF8.GetString(array, 0, array.Length);
                }
            }

            public string Filename {
                get {
                    if (_filename != null) return _filename;
                    byte[] array = Convert.FromBase64String(FilenameBase64);
                    return _filename = Encoding.UTF8.GetString(array, 0, array.Length);
                }
            }

            public string FullnameBase64;
            public string ResourceName;
            public bool Encrypted;
            public bool Compressed;
            public bool MustLoadfromDisk;
            public bool AlternateDirectory;
            public string FilenameBase64;
            private string _fullname;
            private string _filename;
        }
    }
}
