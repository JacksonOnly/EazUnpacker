using System.Collections;
using System.Resources;
using System.Text;
using dnlib.DotNet;

namespace Unpacker;

// Resource data is handled as bytes, never as deserialized user objects.
// PE edits preserve method bodies and metadata identities, including opaque IL.
internal sealed class ResourceFileEditor
{
    internal const int MaxFileBytes=512*1024*1024, MaxAssetBytes=256*1024*1024, MaxEntries=250000;
    internal static readonly UTF8Encoding Utf8=new(false,true);
    internal sealed class Asset(string id,string name,string type,string format,byte[] data,byte[] stored)
    {
        internal string Id {get;}=id;
        internal string Name {get;}=name;
        internal string Type {get;}=type;
        internal string Format {get;}=format;
        internal byte[] Data {get;}=data;
        internal byte[] Stored {get;}=stored;
    }

    private readonly byte[] image;
    internal bool IsContainer {get;}
    internal bool HasSignature {get;}
    internal List<Asset> Assets {get;}=new();

    internal ResourceFileEditor(byte[] bytes,bool container)
    {
        image=bytes;IsContainer=container;
        if(image.Length>MaxFileBytes)throw Invalid("输入文件超过大小限制。");
        long total=0;
        void Add(Asset asset)
        {
            total+=asset.Data.Length;
            if(Assets.Count>=MaxEntries || asset.Data.Length>MaxAssetBytes || total>MaxFileBytes)
                throw Invalid("资源数量或体积超过限制。");
            Assets.Add(asset);
        }
        if(container)
        {
            using var stream=new MemoryStream(image,false);
            using var reader=new ResourceReader(stream);
            IDictionaryEnumerator iterator=reader.GetEnumerator();
            var names=new List<string>();
            while(iterator.MoveNext())
            {
                if(names.Count>=MaxEntries || iterator.Key is not string name)throw Invalid("资源容器键无效或数量过多。");
                names.Add(name);
            }
            names.Sort(StringComparer.Ordinal);
            if(names.Distinct(StringComparer.Ordinal).Count()!=names.Count)throw Invalid("资源容器包含重复键。");
            foreach(string name in names)
            {
                reader.GetResourceData(name,out string type,out byte[] raw);
                if(raw.Length>MaxAssetBytes)throw Invalid("单个资源超过大小限制。");
                string format="raw";byte[] data=raw;
                if(type is "ResourceTypeCode.ByteArray" or "ResourceTypeCode.Stream")
                {
                    if(raw.Length<4 || BitConverter.ToInt32(raw,0)!=raw.Length-4)throw Invalid("字节或流资源的长度无效。");
                    data=new byte[raw.Length-4];Buffer.BlockCopy(raw,4,data,0,data.Length);format="binary";
                }
                else if(type=="ResourceTypeCode.String")
                {
                    using var text=new MemoryStream(raw,false);
                    using var binary=new BinaryReader(text,Utf8);
                    data=Utf8.GetBytes(binary.ReadString());
                    if(text.Position!=text.Length)throw Invalid("字符串资源包含尾随数据。");
                    format="utf8";
                }
                Add(new Asset((Assets.Count+1).ToString("X8"),name,type,format,data,raw));
            }
        }
        else
        {
            using var module=ModuleDefMD.Load(image);
            HasSignature=module.IsStrongNameSigned || module.Metadata.PEImage.ImageNTHeaders.OptionalHeader.DataDirectories[4].Size!=0;
            foreach(var resource in module.Resources.OfType<EmbeddedResource>())
            {
                var reader=resource.CreateReader();
                if(reader.Length>MaxAssetBytes || total+reader.Length>MaxFileBytes)throw Invalid("资源体积超过限制。");
                byte[] data=reader.ToArray();
                Add(new Asset(resource.Rid.ToString("X8"),resource.Name.String,
                    "embedded:"+((uint)resource.Attributes).ToString("X8"),"binary",data,data));
            }
        }
    }

    internal byte[] Apply(IReadOnlyDictionary<string,byte[]> edits,out int changes)
    {
        var known=Assets.ToDictionary(a=>a.Id,StringComparer.Ordinal);
        foreach(var edit in edits)
            if(!known.ContainsKey(edit.Key) || edit.Value.Length>MaxAssetBytes)throw Invalid("替换资源条目无效。");
        var changed=edits.Where(e=>!Enumerable.SequenceEqual(e.Value,known[e.Key].Data)).ToDictionary(e=>e.Key,e=>e.Value,StringComparer.Ordinal);
        changes=changed.Count;
        if(changes==0)return image;
        long total=Assets.Sum(a=>(long)(changed.TryGetValue(a.Id,out var data)?data.Length:a.Data.Length));
        if(total>MaxFileBytes)throw Invalid("替换后的资源总体积超过限制。");
        byte[] result;
        if(IsContainer)
        {
            using var output=new MemoryStream();
            using(var writer=new ResourceWriter(output))
            {
                foreach(var asset in Assets)
                {
                    byte[] raw=asset.Stored;
                    if(changed.TryGetValue(asset.Id,out var data))
                    {
                        if(asset.Type=="ResourceTypeCode.String")
                        {
                            using var text=new MemoryStream();
                            using(var binary=new BinaryWriter(text,Utf8,true))binary.Write(Utf8.GetString(data));
                            raw=text.ToArray();
                        }
                        else if(asset.Type is "ResourceTypeCode.ByteArray" or "ResourceTypeCode.Stream")
                        {
                            raw=new byte[checked(data.Length+4)];
                            Buffer.BlockCopy(BitConverter.GetBytes(data.Length),0,raw,0,4);
                            Buffer.BlockCopy(data,0,raw,4,data.Length);
                        }
                        else {ValidatePrimitive(asset.Type,data);raw=data;}
                    }
                    writer.AddResourceData(asset.Name,asset.Type,raw);
                }
                writer.Generate();result=output.ToArray();
            }
        }
        else result=PatchAssembly(changed);
        if(result.Length>MaxFileBytes)throw Invalid("生成文件超过大小限制。");
        var verified=new ResourceFileEditor(result,IsContainer);
        if(verified.Assets.Count!=Assets.Count)throw Invalid("回写后的资源数量校验失败。");
        for(int i=0;i<Assets.Count;i++)
        {
            var expected=Assets[i];var actual=verified.Assets[i];
            if(expected.Id!=actual.Id || expected.Name!=actual.Name || expected.Type!=actual.Type || expected.Format!=actual.Format ||
                !Enumerable.SequenceEqual(actual.Data,changed.TryGetValue(expected.Id,out var data)?data:expected.Data))
                throw Invalid("回写后的资源内容或身份校验失败。");
        }
        return result;
    }

    private byte[] PatchAssembly(Dictionary<string,byte[]> changed)
    {
        using var module=ModuleDefMD.Load(image);
        var resources=module.Resources.OfType<EmbeddedResource>().ToArray();
        var output=(byte[])image.Clone();
        var spans=new List<(int Start,int End)>();
        var starts=new Dictionary<uint,int>();
        int cor=checked((int)module.Metadata.ImageCor20Header.StartOffset);
        Require(cor,72,image.Length);
        uint oldRva=BitConverter.ToUInt32(image,cor+24),oldSize=BitConverter.ToUInt32(image,cor+28);
        foreach(var resource in resources)
        {
            var reader=resource.CreateReader();uint offset=resource.Offset??throw Invalid("嵌入资源缺少清单偏移。");
            if((ulong)offset+4+reader.Length>oldSize)throw Invalid("嵌入资源超出目录范围。");
            // dnlib represents a zero-length resource with an empty reader at
            // file offset zero; the manifest offset remains authoritative.
            int start=checked((int)module.Metadata.PEImage.ToFileOffset((dnlib.PE.RVA)checked(oldRva+offset)));
            Require(start,checked((int)reader.Length+4),image.Length);
            if(BitConverter.ToUInt32(image,start)!=reader.Length || reader.Length!=0 && reader.StartOffset!=start+4)
                throw Invalid("嵌入资源范围无效。");
            starts.Add(resource.Rid,start);
            spans.Add((start,checked(start+4+(int)reader.Length)));
        }
        spans.Sort((a,b)=>a.Start.CompareTo(b.Start));
        for(int i=1;i<spans.Count;i++)if(spans[i].Start<spans[i-1].End)throw Invalid("嵌入资源范围重叠。");
        var assetIndex=Assets.ToDictionary(a=>a.Id,StringComparer.Ordinal);
        if(changed.All(p=>p.Value.Length<=assetIndex[p.Key].Data.Length))
        {
            foreach(var resource in resources)
            {
                if(!changed.TryGetValue(resource.Rid.ToString("X8"),out var data))continue;
                var reader=resource.CreateReader();int start=starts[resource.Rid];
                Array.Clear(output,start+4,checked((int)reader.Length));
                Write32(output,start,(uint)data.Length);Buffer.BlockCopy(data,0,output,start+4,data.Length);
            }
            return output;
        }
        // Rebuild only the managed resource directory. No dnlib module writer is
        // used: it could normalize protected IL or relocate unrelated metadata.
        using var blob=new MemoryStream();
        var offsets=new Dictionary<uint,uint>();
        foreach(var resource in resources)
        {
            while((blob.Length&7)!=0)blob.WriteByte(0);
            offsets.Add(resource.Rid,checked((uint)blob.Length));
            byte[] data=changed.TryGetValue(resource.Rid.ToString("X8"),out var replacement)?replacement:resource.CreateReader().ToArray();
            byte[] size=BitConverter.GetBytes(data.Length);blob.Write(size,0,4);blob.Write(data,0,data.Length);
        }
        if(blob.Length>MaxFileBytes)throw Invalid("资源目录超过大小限制。");
        byte[] payload=blob.ToArray();
        var pe=module.Metadata.PEImage;
        uint Raw(uint rva,int length)
        {
            foreach(var section in pe.ImageSectionHeaders)
            {
                uint first=(uint)section.VirtualAddress;
                if(rva<first || (ulong)(rva-first)+(uint)length>section.SizeOfRawData)continue;
                uint raw=checked((uint)section.PointerToRawData+rva-first);Require(checked((int)raw),length,image.Length);return raw;
            }
            throw Invalid("资源目录不在可直接编辑的文件范围内。");
        }
        uint newRva;
        if(payload.Length<=oldSize)
        {
            int raw=checked((int)Raw(oldRva,checked((int)oldSize)));
            Array.Clear(output,raw,checked((int)oldSize));Buffer.BlockCopy(payload,0,output,raw,payload.Length);newRva=oldRva;
        }
        else
        {
            int nt=checked((int)BitConverter.ToUInt32(image,60)),optional=checked(nt+24);
            Require(nt,24,image.Length);int sections=BitConverter.ToUInt16(image,nt+6);
            int table=checked(optional+BitConverter.ToUInt16(image,nt+20)),header=checked(table+sections*40);
            Require(optional,68,image.Length);Require(header,40,image.Length);
            uint firstRaw=pe.ImageSectionHeaders.Where(s=>s.SizeOfRawData!=0).Min(s=>(uint)s.PointerToRawData);
            bool extraHeader=sections>=1 && sections<96 && header+40<=firstRaw && header+40<=BitConverter.ToUInt32(image,optional+60) &&
                image.Skip(header).Take(40).All(b=>b==0);
            uint fileAlignment=BitConverter.ToUInt32(image,optional+36),sectionAlignment=BitConverter.ToUInt32(image,optional+32);
            uint raw=Align((uint)image.Length,fileAlignment),rawSize=Align((uint)payload.Length,fileAlignment);
            if(extraHeader)
            {
                uint last=pe.ImageSectionHeaders.Max(s=>checked((uint)s.VirtualAddress+Math.Max(s.VirtualSize,s.SizeOfRawData)));
                newRva=Align(last,sectionAlignment);
                int length=checked((int)(raw+rawSize));if(length>MaxFileBytes)throw Invalid("生成文件超过大小限制。");
                Array.Resize(ref output,length);
                Encoding.ASCII.GetBytes(".mres").CopyTo(output,header);
                Write32(output,header+8,(uint)payload.Length);Write32(output,header+12,newRva);
                Write32(output,header+16,rawSize);Write32(output,header+20,raw);Write32(output,header+36,0x40000040);
                Buffer.BlockCopy(BitConverter.GetBytes((ushort)(sections+1)),0,output,nt+6,2);
                Write32(output,optional+8,checked(BitConverter.ToUInt32(image,optional+8)+rawSize));
            }
            else
            {
                // Typical compiler outputs have no room for another section
                // header. Extend the last physical AND virtual section instead,
                // after its existing virtual zero-fill (never over BSS data).
                var tail=pe.ImageSectionHeaders.OrderByDescending(s=>(ulong)(uint)s.PointerToRawData+s.SizeOfRawData).First();
                uint tailRva=(uint)tail.VirtualAddress,tailRaw=(uint)tail.PointerToRawData;
                if(tail.SizeOfRawData==0 || pe.ImageSectionHeaders.Any(s=>s!=tail &&
                    (ulong)(uint)s.VirtualAddress+Math.Max(s.VirtualSize,s.SizeOfRawData)>tailRva))
                    throw Invalid("PE 尾节布局不支持安全扩容，请使用不增长的替换文件。");
                raw=Align(Math.Max((uint)image.Length,checked(tailRaw+Math.Max(tail.VirtualSize,tail.SizeOfRawData))),fileAlignment);
                uint relative=checked(raw-tailRaw),newRawSize=checked(relative+rawSize);
                newRva=checked(tailRva+relative);
                int length=checked((int)(raw+rawSize));if(length>MaxFileBytes)throw Invalid("生成文件超过大小限制。");
                Array.Resize(ref output,length);
                int tailHeader=checked((int)tail.StartOffset);
                Write32(output,tailHeader+8,checked(relative+(uint)payload.Length));Write32(output,tailHeader+16,newRawSize);
                // CLR resources cannot be discarded along with relocation data.
                Write32(output,tailHeader+36,(BitConverter.ToUInt32(image,tailHeader+36)&~0x02000000u)|0x40000040u);
                Write32(output,optional+8,checked(BitConverter.ToUInt32(image,optional+8)+newRawSize-tail.SizeOfRawData));
            }
            Write32(output,optional+56,Align(checked(newRva+(uint)payload.Length),sectionAlignment));
            Buffer.BlockCopy(payload,0,output,checked((int)raw),payload.Length);
        }
        var tableInfo=module.Metadata.TablesStream.ManifestResourceTable;
        foreach(var resource in resources)
            Write32(output,checked((int)tableInfo.StartOffset+(int)(resource.Rid-1)*(int)tableInfo.RowSize),offsets[resource.Rid]);
        Write32(output,cor+24,newRva);Write32(output,cor+28,(uint)payload.Length);
        // Preserve unrelated header fields: protected loaders may use them as data.
        return output;
    }

    private static uint Align(uint value,uint alignment)
    {
        if(alignment==0 || (alignment&(alignment-1))!=0)throw Invalid("PE 对齐参数无效。");
        return checked(value+alignment-1)&~(alignment-1);
    }
    private static void Write32(byte[] data,int offset,uint value)
    {
        Require(offset,4,data.Length);Buffer.BlockCopy(BitConverter.GetBytes(value),0,data,offset,4);
    }
    private static void Require(int start,int length,int end)
    {
        if(start<0 || length<0 || start>end || length>end-start)throw Invalid("资源文件范围无效。");
    }
    internal static InvalidDataException Invalid(string message)=>new(message);

    private static void ValidatePrimitive(string type,byte[] data)
    {
        int expected=type switch
        {
            "ResourceTypeCode.Null"=>0,
            "ResourceTypeCode.Boolean" or "ResourceTypeCode.Byte" or "ResourceTypeCode.SByte"=>1,
            "ResourceTypeCode.Char" or "ResourceTypeCode.Int16" or "ResourceTypeCode.UInt16"=>2,
            "ResourceTypeCode.Int32" or "ResourceTypeCode.UInt32" or "ResourceTypeCode.Single"=>4,
            "ResourceTypeCode.Int64" or "ResourceTypeCode.UInt64" or "ResourceTypeCode.Double" or
                "ResourceTypeCode.DateTime" or "ResourceTypeCode.TimeSpan"=>8,
            "ResourceTypeCode.Decimal"=>16,
            _=>-1
        };
        if(expected>=0 && data.Length!=expected)throw Invalid("基础类型资源的替换数据长度无效。");
    }
}
