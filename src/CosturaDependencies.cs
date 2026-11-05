using System.IO.Compression;
using System.Security.Cryptography;
using dnlib.DotNet;
using EazFixer;
using Newtonsoft.Json;

namespace Unpacker;

/// <summary>Materializes managed Costura resources for static resolution and isolated validation.</summary>
internal static class CosturaDependencies
{
    internal static int ExtractRawManaged(string input,string directory,List<EmbeddedAssemblyExport> exports)
    {
        using var module=ModuleDefMD.Load(input);
        var images=new Dictionary<string,(string Name,byte[] Bytes,string[] References,List<string> Resources)>(StringComparer.OrdinalIgnoreCase);
        long total=0;
        foreach(var resource in module.Resources.OfType<EmbeddedResource>())
        {
            var reader=resource.CreateReader();
            if(reader.Length<512 || reader.Length>64*1024*1024 || reader.ReadUInt16()!=0x5a4d)continue;
            try
            {
                reader.Position=0;
                var bytes=reader.ToArray();
                using var dependency=ModuleDefMD.Load(bytes);
                if(dependency.Assembly==null)continue;
                string name=dependency.Assembly.Name.String, identity=dependency.Assembly.FullName;
                if(name.Length==0 || name.IndexOfAny(Path.GetInvalidFileNameChars())>=0 ||
                    name!=Path.GetFileName(name) || name.EndsWith(".") || name.EndsWith(" "))continue;
                if(images.TryGetValue(identity,out var previous))
                {
                    if(!Enumerable.SequenceEqual(previous.Bytes,bytes))throw new InvalidDataException("Conflicting raw embedded dependency identity.");
                    previous.Resources.Add(resource.Name.String);
                    continue;
                }
                total+=bytes.Length;
                if(images.Count>=512 || total>256*1024*1024)throw new InvalidDataException("Raw embedded dependency limit exceeded.");
                images.Add(identity,(name+(dependency.EntryPoint==null?".dll":".exe"),bytes,
                    dependency.GetAssemblyRefs().Select(r=>r.FullName).ToArray(),new List<string>{resource.Name.String}));
            }
            catch(BadImageFormatException){ } // A native PE is not a managed reference.
        }
        var pending=new Queue<string>(module.GetAssemblyRefs().Select(r=>r.FullName).Concat(images.Keys));
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int count=0;
        while(pending.Count!=0)
        {
            string identity=pending.Dequeue();
            if(!seen.Add(identity) || !images.TryGetValue(identity,out var dependency))continue;
            string output=Path.Combine(directory,dependency.Name);
            if(string.Equals(Path.GetFullPath(output),Path.GetFullPath(input),StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Raw embedded dependency would overwrite its input.");
            if(File.Exists(output) && !Enumerable.SequenceEqual(File.ReadAllBytes(output),dependency.Bytes))
                throw new InvalidDataException("Conflicting raw embedded dependency filename.");
            File.WriteAllBytes(output,dependency.Bytes);count++;
            foreach(string resource in dependency.Resources)
                exports.Add(new EmbeddedAssemblyExport{File=output,Identity=identity,Resource=resource,Format="raw"});
            foreach(string reference in dependency.References)pending.Enqueue(reference);
        }
        return count;
    }

    internal static int Extract(string input, string directory,List<EmbeddedAssemblyExport> exports)
    {
        using var module = ModuleDefMD.Load(input);
        var evidence = new List<object>();
        long total = 0;
        foreach (var resource in module.Resources.OfType<EmbeddedResource>().Where(r =>
            r.Name.String.StartsWith("costura.", StringComparison.OrdinalIgnoreCase) &&
            (r.Name.String.EndsWith(".dll.compressed", StringComparison.OrdinalIgnoreCase) ||
             r.Name.String.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))))
        {
            if (evidence.Count >= 512) throw new InvalidDataException("Too many embedded Costura dependencies.");
            byte[] payload = resource.CreateReader().ToArray();
            if (resource.Name.String.EndsWith(".compressed", StringComparison.OrdinalIgnoreCase))
            {
                using var source = new MemoryStream(payload);
                using var inflater = new DeflateStream(source, CompressionMode.Decompress);
                using var output = new MemoryStream();
                byte[] buffer = new byte[65536]; int count;
                while ((count = inflater.Read(buffer, 0, buffer.Length)) != 0)
                {
                    if (output.Length + count > 64 * 1024 * 1024) throw new InvalidDataException("Embedded dependency exceeds size limit.");
                    output.Write(buffer, 0, count);
                }
                payload = output.ToArray();
            }
            total += payload.Length;
            if (total > 256 * 1024 * 1024) throw new InvalidDataException("Embedded dependencies exceed total size limit.");
            using var dependency = ModuleDefMD.Load(payload);
            string name = dependency.Assembly?.Name.String ?? throw new InvalidDataException("Embedded Costura DLL has no assembly identity.");
            if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name != Path.GetFileName(name))
                throw new InvalidDataException("Unsafe embedded dependency name.");
            string outputPath = Path.Combine(directory, name + ".dll");
            if (string.Equals(Path.GetFullPath(outputPath), Path.GetFullPath(input), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Embedded dependency would overwrite its input.");
            if (File.Exists(outputPath) && !Enumerable.SequenceEqual(File.ReadAllBytes(outputPath), payload))
                throw new InvalidDataException("Conflicting embedded dependency: " + name);
            File.WriteAllBytes(outputPath, payload);
            exports.Add(new EmbeddedAssemblyExport{File=outputPath,Identity=dependency.Assembly!.FullName,
                Resource=resource.Name.String,Format="costura"});
            using var hash = SHA256.Create();
            evidence.Add(new { Resource = resource.Name.String, Assembly = dependency.Assembly!.FullName,
                Output = outputPath, Sha256 = BitConverter.ToString(hash.ComputeHash(payload)).Replace("-", "").ToLowerInvariant() });
        }
        if (evidence.Count != 0) File.WriteAllText(Path.Combine(directory, "costura-dependencies.json"), JsonConvert.SerializeObject(evidence, Formatting.Indented));
        return evidence.Count;
    }
}
