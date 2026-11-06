using System.Security;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Unpacker;

internal static class ResourceFileCommand
{
    internal const string Usage="用法：Unpacker resources [export] <输入EXE/DLL/resources> [清单.resources.json]\n"+
        "      Unpacker resources apply <输入EXE/DLL/resources> [清单.resources.json] [输出文件|--in-place]";

    internal static int Run(string[] args)
    {
        try
        {
            bool export=args.Length<2 || args[1]!="apply";
            int first=args.Length>=2 && args[1] is "export" or "apply"?2:1;
            if(args.Length<=first || args.Length>first+(export?2:3))throw Invalid(Usage);
            string input=InputPath(args[first]);
            var trailing=args.Skip(first+1).ToArray();
            bool hasCatalog=trailing.Length!=0 && (export || trailing.Length==2 ||
                !IsInput(trailing[0]) && trailing[0]!="--in-place");
            if(hasCatalog && trailing[0].StartsWith("--",StringComparison.Ordinal))throw Invalid(Usage);
            string catalog=hasCatalog?Path.GetFullPath(trailing[0]):input+".resources.json";
            string files=catalog+".files";
            string? destination=export?null:trailing.Skip(hasCatalog?1:0).SingleOrDefault();
            bool inPlace=destination=="--in-place";
            string output=export?catalog:inPlace?input:destination==null?
                Path.ChangeExtension(input,".edited"+Path.GetExtension(input)):InputPath(destination);
            if(Same(input,catalog) || !export && (Same(output,catalog) || !inPlace && Same(output,input)))
                throw Invalid("输入、清单与输出必须使用不同文件；覆盖原件请使用 --in-place。");
            if(!export && !string.Equals(Path.GetExtension(input),Path.GetExtension(output),StringComparison.OrdinalIgnoreCase))
                throw Invalid("输出扩展名必须与输入一致。");
            if(!File.Exists(input))throw Invalid("输入文件不存在。");
            if(!inPlace && (File.Exists(output) || Directory.Exists(output)))throw Invalid("输出已存在，请选择新路径。");
            byte[] image=ReadBounded(input,ResourceFileEditor.MaxFileBytes);
            string fingerprint=Hash(image);
            bool container=Path.GetExtension(input).Equals(".resources",StringComparison.OrdinalIgnoreCase);
            var editCatalog=export?null:ReadCatalog(catalog,container,fingerprint);
            byte[] prepared=container?image:ResourceRecovery.Prepare(image,input);
            using var editor=new ResourceEditSession(prepared,container,input);
            if(export)
            {
                Export(editor,catalog,files);
                Console.WriteLine($"[resources] 已导出 {editor.Assets.Count} 项；文件位于清单同名 .files 目录。");
                return 0;
            }
            var edits=ReadEdits(editor,editCatalog!,files);
            byte[] patched=editor.Apply(edits,out int changes);
            if(changes==0){Console.WriteLine("[resources] 无改动，未写入文件。");return 0;}
            string? backup=inPlace?input+".bak":null;
            if(backup!=null && (File.Exists(backup) || Directory.Exists(backup)))throw Invalid("备份已存在，请先移走备份或选择独立输出。");
            Publish(output,backup,stream=>stream.Write(patched,0,patched.Length),inPlace?fingerprint:null);
            Console.WriteLine($"[resources] 已替换 {changes} 项"+(inPlace?"；已备份原件":"")+
                (editor.HasSignature?"；原数字签名不再有效":"")+"。");
            return 0;
        }
        catch(JsonException){return Error("资源清单不是有效 JSON，或包含重复字段。");}
        catch(DecoderFallbackException){return Error("文本资源或清单不是有效 UTF-8。");}
        catch(BadImageFormatException){return Error("输入不是受支持的托管 PE 或资源容器。");}
        catch(InvalidDataException e){return Error(e.Message);}
        catch(Exception e) when(e is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException or OverflowException)
        {return Error("无法处理资源，请检查文件格式、路径、体积、占用和权限。");}
        catch(Exception e){return Error("处理失败（"+e.GetType().Name+"）。");}
    }

    private static void Export(ResourceEditSession editor,string catalog,string files)
    {
        if(File.Exists(files) || Directory.Exists(files))throw Invalid("资源导出目录已存在，请选择新清单路径。");
        string directory=Path.GetDirectoryName(catalog)!;Directory.CreateDirectory(directory);
        string temporary=Path.Combine(directory,".resources-"+Guid.NewGuid().ToString("N")+".tmp");
        bool installed=false,complete=false;
        try
        {
            Directory.CreateDirectory(temporary);
            var entries=new JArray();
            var paths=ResourceExportPaths.Create(editor,files.Length>=temporary.Length?files:temporary);
            foreach(var asset in editor.Assets)
            {
                string file=paths[asset.Id];
                string destination=Path.Combine(temporary,file.Replace('/',Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.WriteAllBytes(destination,asset.Data);
                entries.Add(new JObject { ["id"]=asset.Id,["name"]=asset.Name,["type"]=asset.Type,["format"]=asset.Format,
                    ["file"]=file });
            }
            InstallDirectory(temporary,files);installed=true;
            Publish(catalog,null,stream=>
            {
                using var text=new StreamWriter(stream,ResourceFileEditor.Utf8,4096,true);
                using var json=new JsonTextWriter(text) {Formatting=Formatting.Indented};entries.WriteTo(json);json.Flush();
            });
            complete=true;
        }
        finally
        {
            if(Directory.Exists(temporary))Directory.Delete(temporary,true);
            if(installed && !complete)Directory.Delete(files,true);
        }
    }

    private static JArray ReadCatalog(string catalog,bool container,string fingerprint)
    {
        using var stream=new FileStream(catalog,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length>128*1024*1024)throw Invalid("资源清单超过大小限制。");
        using var text=new StreamReader(stream,ResourceFileEditor.Utf8,true);
        using var reader=new JsonTextReader(text) {MaxDepth=8,DateParseHandling=DateParseHandling.None};
        var root=JToken.Load(reader,new JsonLoadSettings {DuplicatePropertyNameHandling=DuplicatePropertyNameHandling.Error});
        if(reader.Read())throw Invalid("资源清单包含尾随数据。");
        // Read previous catalogs as well, but new exports contain only the
        // five user-requested mapping fields, with no size/hash settings.
        if(root is JObject legacy)
        {
            if(legacy["sha256"]!=null && (legacy["sha256"]!.Type!=JTokenType.String ||
                !string.Equals((string?)legacy["sha256"],fingerprint,StringComparison.OrdinalIgnoreCase)))
                throw Invalid("旧资源清单与输入不匹配，请重新导出。");
            if(legacy["kind"]!=null && (string?)legacy["kind"]!=(container?"resources":"assembly"))
                throw Invalid("资源清单类型与输入不匹配。");
            root=legacy["entries"]??throw Invalid("资源清单缺少条目。");
        }
        if(root is not JArray entries || entries.Count>ResourceFileEditor.MaxEntries)throw Invalid("资源清单格式或数量无效。");
        return entries;
    }

    private static void InstallDirectory(string source,string destination)
    {
        // Indexers/antivirus can briefly hold newly-created resource files open
        // on Windows. Retry only the same atomic rename, never overwrite a
        // destination that appeared concurrently.
        for(int attempt=0;;attempt++)
        {
            try {Directory.Move(source,destination);return;}
            catch(IOException e) when(attempt<9 && (e.HResult&0xffff) is 5 or 32 or 33 &&
                Directory.Exists(source) && !Directory.Exists(destination) && !File.Exists(destination))
            {System.Threading.Thread.Sleep(50*(attempt+1));}
        }
    }

    private static Dictionary<string,byte[]> ReadEdits(ResourceEditSession editor,JArray entries,string files)
    {
        var originals=editor.Assets.ToDictionary(a=>a.Id,StringComparer.Ordinal);
        var edits=new Dictionary<string,byte[]>(StringComparer.Ordinal);long total=0;
        foreach(var item in entries)
        {
            if(item is not JObject entry || entry["id"]?.Type!=JTokenType.String || entry["name"]?.Type!=JTokenType.String ||
                entry["type"]?.Type!=JTokenType.String || entry["format"]?.Type!=JTokenType.String ||
                entry["file"]?.Type!=JTokenType.String ||
                !originals.TryGetValue((string)entry["id"]!,out var asset) || edits.ContainsKey(asset.Id) ||
                ((string?)entry["name"]!=asset.Name && (editor.ContainerName(asset.Id) is not string parent || (string?)entry["name"]!=parent+"::"+asset.Name)) ||
                (string?)entry["type"]!=asset.Type ||
                ((string?)entry["format"]!=asset.Format && !(asset.Format=="xaml" && (string?)entry["format"]=="binary")))
                throw Invalid("资源条目身份无效、重复或被修改；只修改导出的文件，或删除不需要回写的条目。");
            string path=SafeFile(files,(string)entry["file"]!);
            byte[] replacement=ReadBounded(path,ResourceFileEditor.MaxAssetBytes);
            total+=replacement.Length;if(total>ResourceFileEditor.MaxFileBytes)throw Invalid("替换资源的总体积超过限制。");
            edits.Add(asset.Id,replacement);
        }
        return edits;
    }

    private static string SafeFile(string directory,string relative)
    {
        if(string.IsNullOrWhiteSpace(relative) || Path.IsPathRooted(relative) || relative.IndexOf(':')>=0 ||
            relative.Split('\\','/').Any(p=>p is "" or "." or ".." || p.EndsWith(".",StringComparison.Ordinal) || p.EndsWith(" ",StringComparison.Ordinal)))
            throw Invalid("资源文件必须使用导出目录内的相对路径。");
        string root=Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);
        string file=Path.GetFullPath(Path.Combine(root,relative));
        if(!file.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw Invalid("资源文件超出导出目录。");
        for(string? path=file;path!=null;path=Path.GetDirectoryName(path))
        {
            if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw Invalid("资源文件路径不能经过符号链接或重解析点。");
        }
        if(!File.Exists(file))throw Invalid("替换资源文件不存在。");
        return file;
    }

    private static byte[] ReadBounded(string path,int maximum)
    {
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(stream.Length>maximum)throw Invalid("文件超过大小限制。");
        byte[] bytes=new byte[checked((int)stream.Length)];int position=0;
        while(position<bytes.Length)
        {
            int read=stream.Read(bytes,position,bytes.Length-position);if(read==0)throw Invalid("文件在读取期间被截断。");position+=read;
        }
        return bytes;
    }

    private static void Publish(string output,string? backup,Action<FileStream> write,string? expected=null)
    {
        string directory=Path.GetDirectoryName(output)!;Directory.CreateDirectory(directory);
        string temporary=Path.Combine(directory,".resources-"+Guid.NewGuid().ToString("N")+".tmp");
        try
        {
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            {write(stream);stream.Flush(true);}
            if(backup==null)File.Move(temporary,output);
            else
            {
                if(!string.Equals(expected,Hash(ReadBounded(output,ResourceFileEditor.MaxFileBytes)),StringComparison.Ordinal))
                    throw Invalid("输入在处理期间发生变化，未覆盖原件。");
                if(File.Exists(backup) || Directory.Exists(backup))throw Invalid("备份已存在，未覆盖原件。");
                File.Replace(temporary,output,backup);
            }
        }
        finally {if(File.Exists(temporary))File.Delete(temporary);}
    }

    private static string InputPath(string path)
    {
        string full=Path.GetFullPath(path);
        if(!IsInput(full))throw Invalid("输入和输出必须使用 EXE、DLL 或 resources 扩展名。");
        return full;
    }
    private static bool IsInput(string path)=>new[]{".exe",".dll",".resources"}.Contains(Path.GetExtension(path),StringComparer.OrdinalIgnoreCase);
    private static bool Same(string left,string right)=>string.Equals(left,right,StringComparison.OrdinalIgnoreCase);
    private static string Hash(byte[] bytes)
    {
        using var sha=SHA256.Create();return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant();
    }
    private static InvalidDataException Invalid(string message)=>ResourceFileEditor.Invalid(message);
    private static int Error(string message){Console.Error.WriteLine("[resources] 错误："+message);return 1;}
}
