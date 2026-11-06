using dnlib.DotNet;
using Newtonsoft.Json.Linq;

namespace Unpacker;

internal static class ResourcePacking
{
    internal static byte[] Restore(byte[] original,byte[] prepared,byte[] edited,string input)
    {
        if(ReferenceEquals(original,prepared))return edited;
        var source=new ResourceFileEditor(original,false);
        var before=new ResourceFileEditor(prepared,false).Assets.ToDictionary(a=>a.Name,StringComparer.Ordinal);
        var after=new ResourceFileEditor(edited,false).Assets.ToDictionary(a=>a.Name,StringComparer.Ordinal);
        var direct=new Dictionary<string,byte[]>(StringComparer.Ordinal);
        var names=source.Assets.ToDictionary(a=>a.Name,StringComparer.Ordinal);
        foreach(var asset in source.Assets)
        {
            if(!after.TryGetValue(asset.Name,out var replacement) || replacement.Type!=asset.Type)
                throw ResourceFileEditor.Invalid("原始资源身份发生变化，未写入文件。");
            if(!Enumerable.SequenceEqual(asset.Data,replacement.Data))direct.Add(asset.Id,replacement.Data);
        }
        var requested=after.Values.Where(a=>!names.ContainsKey(a.Name) && before.TryGetValue(a.Name,out var baseline) &&
            !Enumerable.SequenceEqual(a.Data,baseline.Data)).Select(a=>a.Name).ToArray();
        if(requested.Length!=0)
        {
            WorkCache.Initialize();string directory=WorkCache.CreateTemporary("resource-pack");bool success=false;
            try
            {
                string sourcePath=Path.Combine(directory,"source.dll"),editedPath=Path.Combine(directory,"edited.dll"),updates=Path.Combine(directory,"updates.dll");
                File.WriteAllBytes(sourcePath,original);File.WriteAllBytes(editedPath,edited);
                string request=Path.Combine(directory,"request.json");
                File.WriteAllText(request,new JObject {["input"]=sourcePath,["edited"]=editedPath,["output"]=updates,["original"]=input,["names"]=new JArray(requested)}.ToString());
                bool modern=AssemblyInspector.Inspect(input).ModernRuntime;
                string worker=modern?Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","modern","Unpacker.ModernWorker.exe"):
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","Unpacker.Worker.exe");
                Console.WriteLine("[resources] 正在按原格式重新封装保护层资源。");
                if(!File.Exists(worker) || ProcessRunner.Run(worker,new[]{"--resources-pack",request},Path.Combine(directory,"packing.log"),180)!=0 || !File.Exists(updates))
                    throw ResourceFileEditor.Invalid("无法验证原资源格式的重新压缩或加密；未写入明文或部分结果，诊断保存在 temp 内。");
                if(new FileInfo(updates).Length>ResourceFileEditor.MaxFileBytes)throw ResourceFileEditor.Invalid("重新封装的资源超过限制。");
                using var payload=ModuleDefMD.Load(updates);
                foreach(var resource in payload.Resources.OfType<EmbeddedResource>())
                {
                    if(!names.TryGetValue(resource.Name.String,out var asset) || direct.ContainsKey(asset.Id))
                        throw ResourceFileEditor.Invalid("不能同时修改密文载体及其解密内容，或资源映射存在冲突。");
                    byte[] data=resource.CreateReader().ToArray();
                    if(data.Length>ResourceFileEditor.MaxAssetBytes)throw ResourceFileEditor.Invalid("重新封装的资源超过限制。");
                    direct.Add(asset.Id,data);
                }
                if(payload.Resources.Count==0)throw ResourceFileEditor.Invalid("保护资源回写未产生可验证的原格式载体。");
                success=true;
            }
            finally
            {
                if(success)
                    try {Directory.Delete(directory,true);}
                    catch(IOException) { }
                    catch(UnauthorizedAccessException) { }
            }
        }
        // Patch the original PE, not the temporary recovered module: retain its
        // exact resource names, attributes, code and original protection layout.
        byte[] result=source.Apply(direct,out _);
        if(requested.Length!=0)
        {
            // Verify the final PE through the original decoder again. This also
            // checks metadata-dependent startup protection after resource growth.
            var verified=new ResourceFileEditor(ResourceRecovery.Prepare(result,input,false),false).Assets.ToDictionary(a=>a.Name,StringComparer.Ordinal);
            foreach(var asset in after.Values.Where(a=>!names.ContainsKey(a.Name)))
                if(!verified.TryGetValue(asset.Name,out var check) || check.Type!=asset.Type || !Enumerable.SequenceEqual(asset.Data,check.Data))
                    throw ResourceFileEditor.Invalid("原格式回写后的解码校验失败，未写入程序或明文资源。");
        }
        return result;
    }

}
