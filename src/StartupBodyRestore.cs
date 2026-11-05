using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.PE;

namespace Unpacker;

// Some PE images store their original IL bodies in an authenticated-by-metadata
// patch table. Recover that table statically instead of running the initializer.
internal static class StartupBodyRestore
{
    internal static int Process(string path)
    {
        byte[] image=File.ReadAllBytes(path);
        using var module=ModuleDefMD.Load(image);
        var init=module.GlobalType?.FindStaticConstructor();
        if(init?.Body==null)return 0;
        var candidates=init.Body.Instructions.Where(i=>i.OpCode.Code==Code.Call &&
            i.Operand is MethodDef {IsStatic:true, HasBody:true} method && method.MethodSig.Params.Count==0 &&
            method.MethodSig.RetType.ElementType==ElementType.Void &&
            HasCall(method,"System.Runtime.InteropServices.Marshal","GetHINSTANCE") &&
            HasCall(method,"System.Runtime.InteropServices.Marshal","Copy") &&
            HasCall(method,"System.Security.Cryptography.MD5","Create")).ToArray();
        if(candidates.Length==0)return 0;
        if(candidates.Length!=1)throw Invalid();
        var invoke=candidates[0];
        var decoder=(MethodDef)invoke.Operand;
        var il=decoder.Body.Instructions;
        var masks32=ReadMasks(il,"ReadUInt32");
        var sizeMasks=ReadMasks(il,"ReadInt32");
        var digestMask=ReadMasks(il,"ReadUInt64");
        if(masks32.Length!=3 || masks32[1]!=masks32[2] || sizeMasks.Length!=2 || digestMask.Length!=1)
            throw Invalid();
        var sectionSelectors=new List<int>();
        for(int i=0;i<il.Count-14;i++)
        {
            if(!Enumerable.Range(0,4).All(n=>IsCall(il[i+n*3+1],"System.IO.BinaryReader","ReadUInt32") &&
                il[i+n*3+2].IsStloc()))continue;
            if(il[i+12].IsLdloc() && il[i+13].IsLdcI4() && il[i+14].OpCode.Code==Code.Ceq)
                sectionSelectors.Add(il[i+13].GetLdcI4Value());
        }
        if(sectionSelectors.Count!=1)throw Invalid();
        var helpers=il.Where(i=>i.OpCode.Code==Code.Call).Select(i=>i.Operand).OfType<MethodDef>()
            .Where(m=>m.HasBody && HasCall(m,"System.Security.Cryptography.Rijndael","Create") &&
                HasCall(m,"System.Security.Cryptography.SHA256","Create") &&
                HasCall(m,"System.Security.Cryptography.SHA512","Create")).Distinct().ToArray();
        if(helpers.Length!=1)throw Invalid();
        var helper=helpers[0].Body.Instructions;
        var byteMasks=Enumerable.Range(0,helper.Count-4).Where(i=>helper[i].OpCode.Code==Code.Ldelem_U1 &&
            helper[i+1].IsLdcI4() && helper[i+2].OpCode.Code==Code.Xor &&
            helper[i+3].OpCode.Code==Code.Conv_U1 && helper[i+4].OpCode.Code==Code.Xor)
            .Select(i=>helper[i+1].GetLdcI4Value()).ToArray();
        if(byteMasks.Length!=1 || byteMasks[0] is <0 or >255)throw Invalid();
        int cryptoCall=il.IndexOf(il.Single(i=>i.Operand==helpers[0]));
        var markers=new List<(int Index,int Value)>();
        for(int i=cryptoCall+1;i<Math.Min(il.Count-2,cryptoCall+40);i++)
            if(il[i].IsLdcI4() && il[i+1].OpCode.Code==Code.Ldelem_U1 && il[i+2].IsLdcI4())
                markers.Add((il[i].GetLdcI4Value(),il[i+2].GetLdcI4Value()));
        if(markers.Count!=2 || markers[0].Index!=0 || markers[1].Index!=1)throw Invalid();

        var pe=module.Metadata.PEImage;
        var sections=pe.ImageSectionHeaders;
        var storage=sections.Where(s=>s.Name.Sum(b=>(int)b)==sectionSelectors[0]).ToArray();
        if(storage.Length!=1)throw Invalid();
        int start=checked((int)storage[0].PointerToRawData), size=checked((int)storage[0].SizeOfRawData);
        RequireRange(start,size,image.Length);
        uint metadataRva=ReadUInt32(image,checked((int)pe.ImageNTHeaders.OptionalHeader.StartOffset+64)) ^ (uint)masks32[0];
        var metadata=GetOffset(metadataRva,16);
        if(ReadUInt32(image,metadata)!=0x424a5342)throw Invalid();
        int cursor=checked(metadata+16+(int)ReadUInt32(image,metadata+12));
        RequireRange(cursor,4,image.Length);
        int streams=BitConverter.ToUInt16(image,cursor+2);cursor+=4;
        if(streams is <1 or >32)throw Invalid();
        using var basisStream=new MemoryStream();
        var sourceRanges=new List<(int Offset,int Size)>();
        for(int i=0;i<streams;i++)
        {
            int relative=checked((int)ReadUInt32(image,cursor));
            int length=checked((int)ReadUInt32(image,cursor+4));
            int offset=GetOffset(checked(metadataRva+(uint)relative),length);
            if(basisStream.Length+length>64*1024*1024 ||
                sourceRanges.Any(r=>offset<r.Offset+r.Size && r.Offset<offset+length))throw Invalid();
            sourceRanges.Add((offset,length));
            basisStream.Write(image,offset,length);
            cursor+=8;
            int nameStart=cursor;
            while(cursor<image.Length && cursor-nameStart<32 && image[cursor]!=0)cursor++;
            if(cursor==image.Length || cursor-nameStart==32)throw Invalid();
            cursor=checked(metadata+((cursor-metadata+4)&~3));
        }
        byte[] basis=basisStream.ToArray();
        using var md5=MD5.Create();
        byte[] digest=md5.ComputeHash(basis);
        RequireRange(start,20,start+size);
        ulong expected=BitConverter.ToUInt64(image,start)^(ulong)digestMask[0];
        if((BitConverter.ToUInt64(digest,0)^BitConverter.ToUInt64(digest,8))!=expected)throw Invalid();
        int pos=start+16;
        int ivLength=(int)(ReadUInt32(image,pos)^(uint)sizeMasks[0]);pos+=4;
        if(ivLength!=16)throw Invalid();
        RequireRange(pos,ivLength+4,start+size);
        var iv=new byte[ivLength];
        Buffer.BlockCopy(image,pos,iv,0,iv.Length);
        pos+=iv.Length;
        int encryptedSize=(int)(ReadUInt32(image,pos)^(uint)sizeMasks[1]);pos+=4;
        RequireRange(pos,encryptedSize,start+size);
        if(encryptedSize==0 || (encryptedSize&15)!=0 || encryptedSize>64*1024*1024)throw Invalid();
        using var aes=Aes.Create();
        using var sha256=SHA256.Create();
        using var sha512=SHA512.Create();
        using var decrypt=aes.CreateDecryptor(sha256.ComputeHash(basis),iv);
        byte[] plaintext=decrypt.TransformFinalBlock(image,pos,encryptedSize);
        // The loader decrypts into a ciphertext-sized array before the second
        // pass, but bytes beyond the AES plaintext cannot form a valid record.
        byte[] seed=sha512.ComputeHash(basis);
        for(int i=0;i<plaintext.Length;i+=64)
        {
            int length=Math.Min(64,plaintext.Length-i);
            for(int j=0;j<length;j++)plaintext[i+j]^=(byte)(seed[j]^byteMasks[0]);
            if(i+length<plaintext.Length)seed=sha512.ComputeHash(plaintext,i,length);
        }
        if(plaintext.Length<6 || plaintext[0]!=markers[0].Value || plaintext[1]!=markers[1].Value)
            throw Invalid();

        var methods=module.GetTypes().SelectMany(t=>t.Methods).ToArray();
        var methodRvas=new HashSet<uint>(methods.Where(m=>m.IsIL && m.RVA!=0).Select(m=>(uint)m.RVA));
        var unreadable=methods.Where(m=>m.IsIL && m.RVA!=0 && !Readable(m)).Select(m=>(uint)m.RVA).Distinct().ToArray();
        int count=checked((int)ReadUInt32(plaintext,2));
        uint recordMask=unchecked((uint)masks32[1]);
        if(count<1 || count>methods.Length || unreadable.Length==0)return 0;
        var patches=new List<(int Raw,int Size,int Source,uint Rva)>();
        pos=6;
        for(int i=0;i<count;i++)
        {
            int raw=checked((int)(ReadUInt32(plaintext,pos)^recordMask));pos+=4;
            if(raw==0)continue;
            uint rva=ReadUInt32(plaintext,pos)^recordMask;
            int length=checked((int)ReadUInt32(plaintext,pos+4));pos+=8;
            RequireRange(pos,length,plaintext.Length);
            if(length==0 || !methodRvas.Contains(rva) || GetOffset(rva,length)!=raw ||
                sourceRanges.Any(r=>raw<r.Offset+r.Size && r.Offset<raw+length) ||
                raw<start+size && start<raw+length)throw Invalid();
            patches.Add((raw,length,pos,rva));pos+=length;
        }
        var writtenRvas=new HashSet<uint>(patches.Select(p=>p.Rva));
        if(writtenRvas.Count!=patches.Count || unreadable.Any(rva=>!writtenRvas.Contains(rva)))throw Invalid();
        var ordered=patches.OrderBy(p=>p.Raw).ToArray();
        for(int i=1;i<ordered.Length;i++)
            if(ordered[i-1].Raw+ordered[i-1].Size>ordered[i].Raw)throw Invalid();

        int initRaw=GetOffset((uint)init.RVA,2);
        int header=(image[initRaw]&3) switch {2=>1,3=>(image[initRaw+1]>>4)*4,_=>throw Invalid()};
        int callOffset=checked(header+(int)invoke.Offset);
        int rawCall=GetOffset(checked((uint)init.RVA+(uint)callOffset),5);
        if(image[rawCall]!=unchecked((byte)OpCodes.Call.Value) || ReadUInt32(image,rawCall+1)!=decoder.MDToken.Raw ||
            patches.Any(p=>rawCall<p.Raw+p.Size && p.Raw<rawCall+5))throw Invalid();
        var restored=(byte[])image.Clone();
        foreach(var p in patches)Buffer.BlockCopy(plaintext,p.Source,restored,p.Raw,p.Size);
        // Remove only the consumed initializer call; keep all other startup IL.
        Array.Clear(restored,rawCall,5);
        using var verified=ModuleDefMD.Load(restored);
        if(verified.GetTypes().SelectMany(t=>t.Methods).Any(m=>m.IsIL && m.RVA!=0 && !Readable(m)))
            throw Invalid();
        File.WriteAllBytes(path,restored);
        return patches.Count;

        int GetOffset(uint rva,int length)
        {
            foreach(var section in sections)
            {
                uint first=(uint)section.VirtualAddress;
                if(rva<first || (ulong)(rva-first)+(uint)length>section.SizeOfRawData)continue;
                int offset=checked((int)((uint)section.PointerToRawData+rva-first));
                RequireRange(offset,length,image.Length);
                return offset;
            }
            throw Invalid();
        }
    }

    private static bool Readable(MethodDef method)=>method.Body is { } body && body.Instructions.Count>0 &&
        body.Instructions.All(i=>i!=null && (i.OpCode.OperandType switch
        {
            OperandType.InlineBrTarget or OperandType.ShortInlineBrTarget=>i.Operand is Instruction,
            OperandType.InlineSwitch=>i.Operand is IList<Instruction> targets && targets.All(t=>t!=null),
            _=>true
        }));

    private static bool HasCall(MethodDef method,string type,string name)=>
        method.Body.Instructions.Any(i=>IsCall(i,type,name));

    private static bool IsCall(Instruction i,string type,string name)=>
        i.Operand is IMethod m && m.DeclaringType.FullName==type && m.Name==name;

    private static long[] ReadMasks(IList<Instruction> il,string name)=>
        Enumerable.Range(0,il.Count-2).Where(i=>IsCall(il[i],"System.IO.BinaryReader",name) &&
            (il[i+1].IsLdcI4() || il[i+1].OpCode.Code==Code.Ldc_I8) && il[i+2].OpCode.Code==Code.Xor)
            .Select(i=>il[i+1].IsLdcI4()?(long)il[i+1].GetLdcI4Value():(long)il[i+1].Operand).ToArray();

    private static uint ReadUInt32(byte[] data,int offset)
    {
        RequireRange(offset,4,data.Length);
        return BitConverter.ToUInt32(data,offset);
    }

    private static void RequireRange(int offset,int length,int end)
    {
        if(offset<0 || length<0 || offset>end || length>end-offset)throw Invalid();
    }

    private static InvalidDataException Invalid()=>new("无法验证启动期 IL 加密表的布局或数据边界。");
}
