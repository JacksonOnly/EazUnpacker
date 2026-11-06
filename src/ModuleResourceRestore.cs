using System.IO.Compression;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace Unpacker;

internal static class ModuleResourceRestore
{
    internal sealed class Carrier(uint handler,string resource,byte[] image,int state,int multiplier)
    {
        internal uint Handler { get; }=handler;
        internal string Resource { get; }=resource;
        internal byte[] Image { get; }=image;
        internal byte[] Encode(byte[] data)
        {
            if(data.Length>128*1024*1024)throw Invalid();
            var encoded=(byte[])data.Clone();int key=state;
            for(int i=0;i<encoded.Length;i++){encoded[i]^=(byte)key;key=key*multiplier%256;}
            using var output=new MemoryStream();
            using(var compressed=new DeflateStream(output,CompressionLevel.Optimal,true))
            using(var writer=new BinaryWriter(compressed)) {writer.Write(data.Length);writer.Write(encoded);}
            byte[] result=output.ToArray();
            using var input=new MemoryStream(result,false);
            using var inflater=new DeflateStream(input,CompressionMode.Decompress);
            using var reader=new BinaryReader(inflater);
            if(reader.ReadInt32()!=data.Length)throw Invalid();
            byte[] check=reader.ReadBytes(data.Length);key=state;
            for(int i=0;i<check.Length;i++){check[i]^=(byte)key;key=key*multiplier%256;}
            if(!Enumerable.SequenceEqual(check,data) || inflater.ReadByte()!=-1)throw Invalid();
            return result;
        }
    }

    internal static int Process(string input,out Carrier? carrier,bool preferExisting=false)
    {
        carrier=null;
        using var module=ModuleDefMD.Load(File.ReadAllBytes(input));
        var init=module.GlobalType?.FindStaticConstructor()?.Body?.Instructions;
        if(init==null)return 0;
        var handlers=new List<MethodDef>();
        for(int i=0;i+2<init.Count;i++)
            if(init[i].OpCode.Code==Code.Ldftn && init[i].Operand is MethodDef {IsStatic:true,HasBody:true} handler &&
                Calls(init[i+1],"System.ResolveEventHandler",".ctor") && Calls(init[i+2],"System.AppDomain","add_ResourceResolve") &&
                handler.DeclaringType==module.GlobalType && handler.MethodSig.RetType.FullName=="System.Reflection.Assembly" &&
                handler.MethodSig.Params.Select(p=>p.FullName).SequenceEqual(new[]{"System.Object","System.ResolveEventArgs"}))
                handlers.Add(handler);
        if(handlers.Count!=1)return 0;
        var il=handlers[0].Body.Instructions;
        int lookup=Find(il,"System.Reflection.Assembly","GetManifestResourceStream");
        int deflate=Find(il,"System.IO.Compression.DeflateStream",".ctor");
        int sizeRead=Find(il,"System.IO.BinaryReader","ReadInt32");
        int dataRead=Find(il,"System.IO.BinaryReader","ReadBytes");
        int load=Find(il,"System.Reflection.Assembly","Load");
        if(lookup<1 || il[lookup-1].OpCode.Code!=Code.Ldstr || !(lookup<deflate && deflate<sizeRead &&
            sizeRead+1==dataRead && dataRead+2<load) || il[deflate-1].OpCode.Code!=Code.Ldc_I4_0 ||
            !il[dataRead+2].IsLdcI4() || Find(il,"System.Reflection.Assembly","GetManifestResourceNames")<load)
            return 0;
        int state=il[dataRead+2].GetLdcI4Value();
        if(state is <0 or >255)return 0;
        var recurrence=Enumerable.Range(dataRead+3,load-dataRead-3).Where(i=>i+4<load && il[i].IsLdcI4() &&
            il[i+1].OpCode.Code==Code.Mul && il[i+2].IsLdcI4() && il[i+2].GetLdcI4Value()==256 &&
            il[i+3].OpCode.Code==Code.Rem && il[i+4].OpCode.Code==Code.Conv_U1).ToArray();
        if(recurrence.Length!=1 || !il.Skip(dataRead+3).Take(recurrence[0]-dataRead-3)
            .Any(i=>i.OpCode.Code==Code.Xor))return 0;
        int multiplier=il[recurrence[0]].GetLdcI4Value();
        if(multiplier is <0 or >255)return 0;

        string name=(string)il[lookup-1].Operand;
        var entries=module.Resources.OfType<EmbeddedResource>().Where(r=>r.Name==name).ToArray();
        if(entries.Length!=1)return 0;
        using var stream=new MemoryStream(entries[0].CreateReader().ToArray(),false);
        using var inflated=new DeflateStream(stream,CompressionMode.Decompress);
        using var reader=new BinaryReader(inflated);
        int length=reader.ReadInt32();
        if(length is <512 or >128*1024*1024)throw Invalid();
        byte[] bytes=reader.ReadBytes(length);
        if(bytes.Length!=length)throw Invalid();
        int initialState=state;
        for(int i=0;i<bytes.Length;i++)
        {
            bytes[i]^=(byte)state;
            state=state*multiplier%256;
        }
        using var packed=ModuleDefMD.Load(bytes);
        if(packed.Assembly==null || packed.GetTypes().SelectMany(t=>t.Methods).Any(m=>m.HasBody) || packed.Resources.Count==0)
            throw Invalid();
        int added=0;
        foreach(var resource in packed.Resources)
        {
            if(resource is not EmbeddedResource item)throw Invalid();
            var payload=item.CreateReader().ToArray();
            var existing=module.Resources.FirstOrDefault(r=>r.Name==item.Name);
            if(existing!=null)
            {
                if(preferExisting && existing is EmbeddedResource)continue;
                if(existing is not EmbeddedResource old || !Enumerable.SequenceEqual(old.CreateReader().ToArray(),payload))throw Invalid();
                continue;
            }
            module.Resources.Add(new EmbeddedResource(item.Name,payload,item.Attributes));
            added++;
        }
        carrier=new Carrier(handlers[0].MDToken.Raw,name,bytes,initialState,multiplier);
        if(added==0)return 0;
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody))
            method.Body.KeepOldMaxStack=true;
        using var restored=new MemoryStream();
        module.Write(restored,new ModuleWriterOptions(module){MetadataOptions={Flags=MetadataFlags.PreserveAll}});
        File.WriteAllBytes(input,restored.ToArray());
        return added;
    }

    private static int Find(IList<Instruction> il,string type,string name)
    {
        var matches=Enumerable.Range(0,il.Count).Where(i=>Calls(il[i],type,name)).ToArray();
        return matches.Length==1?matches[0]:-1;
    }
    private static bool Calls(Instruction i,string type,string name)=>
        i.Operand is IMethod m && m.DeclaringType.FullName==type && m.Name==name;
    private static InvalidDataException Invalid()=>new("无法验证启动期嵌入资源的解码结果。");
}
