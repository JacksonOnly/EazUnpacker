using dnlib.DotNet;
using EazFixer;
using Newtonsoft.Json.Linq;

namespace Unpacker;

internal static class ResourcePackingWorker
{
    internal static int Run(string requestFile)
    {
        var request=JObject.Parse(File.ReadAllText(requestFile));
        string input=(string)request["input"]!,edited=(string)request["edited"]!,output=(string)request["output"]!;
        using var dependencies=new DependencyLoadScope((string)request["original"]!,input);
        string staged=Path.Combine(Path.GetDirectoryName(output)!,"staged.dll");File.Copy(input,staged);
        StartupBodyRestore.Process(staged);
        ModuleResourceRestore.Process(staged,out var carrier,true);
        using var changed=ModuleDefMD.Load(edited);
        var replacements=changed.Resources.OfType<EmbeddedResource>().ToDictionary(r=>r.Name.String,StringComparer.Ordinal);
        var pending=new HashSet<string>(request["names"]!.Values<string>()!,StringComparer.Ordinal);
        using var updates=new ModuleDefUser("ResourceUpdates.dll");
        new AssemblyDefUser("ResourceUpdates",new Version(1,0)).Modules.Add(updates);
        if(carrier!=null)
        {
            var inner=new ResourceFileEditor(carrier.Image,false);
            var edits=new Dictionary<string,byte[]>(StringComparer.Ordinal);
            foreach(var asset in inner.Assets.Where(a=>pending.Contains(a.Name)))
            {
                if(!replacements.TryGetValue(asset.Name,out var replacement))throw new InvalidDataException("Missing edited carrier resource.");
                edits.Add(asset.Id,replacement.CreateReader().ToArray());pending.Remove(asset.Name);
            }
            if(edits.Count!=0)
            {
                byte[] encoded=carrier.Encode(inner.Apply(edits,out _));
                using var original=ModuleDefMD.Load(input);
                var resource=original.Resources.OfType<EmbeddedResource>().Single(r=>r.Name==carrier.Resource);
                updates.Resources.Add(new EmbeddedResource(resource.Name,encoded,resource.Attributes));
            }
        }
        using var module=ModuleDefMD.Load(File.ReadAllBytes(staged));
        if(pending.Count!=0 && FixerBridge.HasResourceResolver(module))
        {
            string additional=Path.Combine(Path.GetDirectoryName(output)!,"encoded.dll");
            foreach(string name in FixerBridge.RepackResources(staged,edited,additional,pending))pending.Remove(name);
            using var payload=ModuleDefMD.Load(additional);
            foreach(var resource in payload.Resources.OfType<EmbeddedResource>())
                updates.Resources.Add(new EmbeddedResource(resource.Name,resource.CreateReader().ToArray(),resource.Attributes));
        }
        if(pending.Count!=0)throw new InvalidDataException("Edited protected resources have no verified original-format encoder.");
        updates.Write(output);return 0;
    }
}
