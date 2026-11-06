using dnlib.DotNet;
using Newtonsoft.Json.Linq;

namespace Unpacker;

// Temporary source/XAML files never enter the public five-field catalog.
internal sealed class BamlResources : IDisposable
{
    private readonly string directory,owner,original;
    private bool retainDiagnostics;
    private readonly Dictionary<string,(byte[] Baml,byte[] Xaml,string Stem)> files=new(StringComparer.Ordinal);
    internal static bool IsBaml(byte[] data)=>data.Length>=28 && BitConverter.ToInt32(data,0)==12 &&
        System.Text.Encoding.Unicode.GetString(data,4,12)=="MSBAML";

    internal BamlResources(byte[] image,bool container,string original,IEnumerable<ResourceFileEditor.Asset> assets)
    {
        this.original=original;
        WorkCache.Initialize();directory=WorkCache.CreateTemporary("baml");
        if(container)
        {
            string stem=Path.ChangeExtension(original,null);
            if(stem.EndsWith(".g",StringComparison.OrdinalIgnoreCase))stem=Path.ChangeExtension(stem,null);
            string? found=new[]{stem+".dll",stem+".exe"}.FirstOrDefault(File.Exists);
            if(found!=null)
            {
                if(new FileInfo(found).Length>ResourceFileEditor.MaxFileBytes)throw ResourceFileEditor.Invalid("BAML 所属程序集超过大小限制。");
                image=File.ReadAllBytes(found);
            }
            else
            {
                using var stub=new ModuleDefUser("ResourceOwner.dll") {Kind=ModuleKind.Dll};
                new AssemblyDefUser("ResourceOwner",new Version(1,0)).Modules.Add(stub);
                using var stream=new MemoryStream();stub.Write(stream);image=stream.ToArray();
            }
        }
        using(var module=ModuleDefMD.Load(image))
        {
            string name=module.Assembly?.Name.String??"owner";
            if(name.Length==0 || name.IndexOfAny(Path.GetInvalidFileNameChars())>=0 || Path.GetFileName(name)!=name)name="owner";
            owner=Path.Combine(directory,name+".dll");
        }
        File.WriteAllBytes(owner,image);
        var items=new JArray();int index=0;
        foreach(var asset in assets.Where(a=>a.Format=="binary" && IsBaml(a.Data)))
        {
            string stem=Path.Combine(directory,(index++).ToString(System.Globalization.CultureInfo.InvariantCulture));
            File.WriteAllBytes(stem+".baml",asset.Data);
            files.Add(asset.Id,(asset.Data,Array.Empty<byte>(),stem));
            items.Add(new JObject {["baml"]=stem+".baml",["xaml"]=stem+".xaml"});
        }
        string request=Path.Combine(directory,"decompile.json");
        File.WriteAllText(request,new JObject {["owner"]=owner,["directories"]=new JArray(DependencyLoadScope.DependencyDirectories(owner,original)),["items"]=items}.ToString());
        string worker=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","baml","Unpacker.BamlWorker.exe");
        if(!File.Exists(worker) || ProcessRunner.Run(worker,new[]{request},Path.Combine(directory,"decompile.log"),180)!=0)
            throw ResourceFileEditor.Invalid("BAML 转 XAML 失败；请保留完整后端和所需的 .NET 运行时，诊断保存在 temp 内。");
        foreach(string id in files.Keys.ToArray())
        {
            var file=files[id];var info=new FileInfo(file.Stem+".xaml");
            if(!info.Exists || info.Length>ResourceFileEditor.MaxAssetBytes)throw ResourceFileEditor.Invalid("BAML 转换结果无效或超过限制。");
            files[id]=(file.Baml,File.ReadAllBytes(info.FullName),file.Stem);
        }
    }

    internal byte[]? Xaml(string id)=>files.TryGetValue(id,out var file)?file.Xaml:null;

    internal Dictionary<string,byte[]> Compile(IReadOnlyDictionary<string,byte[]> edits)
    {
        var result=new Dictionary<string,byte[]>(StringComparer.Ordinal);
        var items=new JArray();
        foreach(var edit in edits)
        {
            if(!files.TryGetValue(edit.Key,out var file)) {result.Add(edit.Key,edit.Value);continue;}
            // Older binary catalogs remain usable without recompiling their BAML.
            if(IsBaml(edit.Value)) {result.Add(edit.Key,edit.Value);continue;}
            if(Enumerable.SequenceEqual(edit.Value,file.Xaml)) {result.Add(edit.Key,file.Baml);continue;}
            File.WriteAllBytes(file.Stem+".edited.xaml",edit.Value);
            items.Add(new JObject {["baseline"]=file.Stem+".xaml",["baml"]=file.Stem+".baml",["xaml"]=file.Stem+".edited.xaml",["output"]=file.Stem+".compiled.baml",["id"]=edit.Key});
        }
        if(items.Count==0)return result;
        string request=Path.Combine(directory,"compile.json");
        File.WriteAllText(request,new JObject {["owner"]=owner,["original"]=original,["items"]=items}.ToString());
        bool modern=AssemblyInspector.Inspect(owner).ModernRuntime;
        string worker=modern?Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","modern","Unpacker.ModernWorker.exe"):
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","Unpacker.Worker.exe");
        retainDiagnostics=true;
        if(!File.Exists(worker) || ProcessRunner.Run(worker,new[]{"--baml-compile",request},Path.Combine(directory,"compile.log"),180)!=0)
            throw ResourceFileEditor.Invalid("XAML 编译失败；请检查 XML、类型、属性及依赖，保留原有 ub 标记、x:Class 和事件处理器。诊断保存在 temp 内，未写入部分资源。");
        foreach(var item in items)
        {
            string path=(string)item["output"]!;var info=new FileInfo(path);
            if(!info.Exists || info.Length>ResourceFileEditor.MaxAssetBytes)throw ResourceFileEditor.Invalid("XAML 编译结果无效或超过限制。");
            byte[] baml=File.ReadAllBytes(path);
            if(!IsBaml(baml))throw ResourceFileEditor.Invalid("XAML 编译结果不是 BAML。");
            result.Add((string)item["id"]!,baml);
        }
        retainDiagnostics=false;
        return result;
    }

    public void Dispose()
    {
        if(retainDiagnostics)return;
        try {Directory.Delete(directory,true);}
        catch(IOException) { }
        catch(UnauthorizedAccessException) { }
    }
}
