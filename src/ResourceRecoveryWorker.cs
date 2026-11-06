using dnlib.DotNet;
using dnlib.DotNet.Writer;
using EazFixer;

namespace Unpacker;

// Only this short-lived worker invokes the supported resource decoder, using
// the existing initializer-suppressed runtime copy and dependency scope.
internal static class ResourceRecoveryWorker
{
    internal static int Run(string input,string output,string original)
    {
        using var dependencies=new DependencyLoadScope(original,input);
        using var source=ModuleDefMD.Load(input);
        int originalCount=source.Resources.Count;
        string staged=Path.Combine(Path.GetDirectoryName(output)!,"staged"+Path.GetExtension(input));
        File.Copy(input,staged);
        StartupBodyRestore.Process(staged);
        ModuleResourceRestore.Process(staged,out _,true);
        using var module=ModuleDefMD.Load(File.ReadAllBytes(staged));
        if(FixerBridge.HasResourceResolver(module))
        {
            string payload=Path.Combine(Path.GetDirectoryName(output)!,"recovered-resources.dll");
            FixerBridge.RecoverResources(staged,payload);
            using var recovered=ModuleDefMD.Load(File.ReadAllBytes(payload));
            var names=new HashSet<string>(module.Resources.Select(r=>r.Name.String),StringComparer.Ordinal);
            foreach(var resource in recovered.Resources.OfType<EmbeddedResource>())
                if(names.Add(resource.Name.String))module.Resources.Add(new EmbeddedResource(resource.Name,resource.CreateReader().ToArray(),resource.Attributes));
        }
        if(module.Resources.Count==originalCount){File.Copy(input,output);return 0;}
        // Deterministic IDs across export/apply, even if the decoder's runtime
        // dictionary enumeration order differs between processes.
        var appended=module.Resources.Skip(originalCount).OrderBy(r=>r.Name.String,StringComparer.Ordinal).ToArray();
        while(module.Resources.Count>originalCount)module.Resources.RemoveAt(module.Resources.Count-1);
        foreach(var resource in appended)module.Resources.Add(resource);
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody))method.Body.KeepOldMaxStack=true;
        module.Write(output,new ModuleWriterOptions(module) {MetadataOptions={Flags=MetadataFlags.PreserveAll}});
        return 0;
    }
}
