using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Newtonsoft.Json;

namespace Unpacker;

internal static class ProtectedComparisonRecovery
{
    internal static int Process(string input,string reference,string output,string reportPath)
    {
        input=Path.GetFullPath(input);reference=Path.GetFullPath(reference);output=Path.GetFullPath(output);
        if(string.Equals(input,output,StringComparison.OrdinalIgnoreCase)||string.Equals(reference,output,StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Output must not overwrite either input.");
        if(File.Exists(output))throw new IOException("Output already exists.");
        using var module=ModuleDefMD.Load(input);
        using var original=ModuleDefMD.Load(reference);
        var report=new List<object>();
        int direct=LowerExisting(module,report);
        var strings=new HashSet<string>(module.GetTypes().Concat(original.GetTypes()).SelectMany(t=>t.Methods)
            .Where(m=>m.HasBody).SelectMany(m=>m.Body.Instructions).Where(i=>i.OpCode.Code==Code.Ldstr)
            .Select(i=>(string)i.Operand).Where(s=>s.Length>0&&s.Length<=512),StringComparer.Ordinal);
        foreach(var type in module.GetTypes().Concat(original.GetTypes()).Cast<ITypeDefOrRef>().Concat(module.GetTypeRefs()).Concat(original.GetTypeRefs()))
            strings.Add(type.FullName);
        var integers=new HashSet<int>(Enumerable.Range(-16,272));
        foreach(var i in module.GetTypes().Concat(original.GetTypes()).SelectMany(t=>t.Methods).Where(m=>m.HasBody).SelectMany(m=>m.Body.Instructions).Where(i=>i.IsLdcI4()))
            integers.Add(i.GetLdcI4Value());
        foreach(var field in module.GetTypes().Concat(original.GetTypes()).SelectMany(t=>t.Fields).Where(f=>f.HasConstant&&f.Constant.Value is int))
            integers.Add((int)field.Constant.Value);
        var watch=System.Diagnostics.Stopwatch.StartNew();
        var candidateStrings=strings.OrderBy(s=>s,StringComparer.Ordinal).Take(4096).ToArray();
        var candidateIntegers=integers.Concat(Enumerable.Range(0,4096).Select(i=>unchecked((int)(0x80070000u|(uint)i))))
            .Distinct().OrderBy(i=>i).Take(8192).ToArray();
        var owner=module.GetTypes().FirstOrDefault(t=>t.FullName=="RecoveredConstantComparisons")??
            new TypeDefUser("","RecoveredConstantComparisons",module.CorLibTypes.Object.TypeDefOrRef)
            {Attributes=TypeAttributes.NotPublic|TypeAttributes.Abstract|TypeAttributes.Sealed};
        int existing=owner.Methods.Count;
        var equality=module.Import(typeof(string).GetMethod("op_Equality",new[]{typeof(string),typeof(string)})!);
        var error=module.Import(typeof(ArgumentException).GetConstructor(Type.EmptyTypes)!);
        foreach(var caller in module.GetTypes().Where(t=>t!=owner).SelectMany(t=>t.Methods).Where(m=>m.HasBody).ToArray())
        {
            var il=caller.Body.Instructions;
            foreach(var call in il.Where(i=>i.OpCode.Code==Code.Call&&i.Operand is IMethod m&&IsPredicate(LocalType(module,m.DeclaringType)?.FindMethod(m.Name,m.MethodSig))).ToArray())
            {
                int end=il.IndexOf(call),start=end-7;
                if(start<0)continue;
                var tail=il.Skip(start).Take(8).ToArray();
                if(!tail[0].IsLdcI4()||tail[1].OpCode.Code!=Code.Newarr||
                    (tail[1].Operand as ITypeDefOrRef)?.FullName!="System.Byte"||tail[2].OpCode.Code!=Code.Dup||
                    tail[3].OpCode.Code!=Code.Ldtoken||tail[3].Operand is not IField field||LocalType(module,field.DeclaringType)?.Fields.FirstOrDefault(f=>f.Name==field.Name&&new SigComparer().Equals(f.FieldSig,field.FieldSig)) is not FieldDef data||data.Module!=module||data.InitialValue==null||
                    data.InitialValue.Length!=tail[0].GetLdcI4Value()||tail[4].OpCode.Code!=Code.Call||
                    tail[4].Operand is not IMethod init||init.FullName!="System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)"||
                    tail[5].OpCode.Code!=Code.Ldc_I8||!tail[6].IsLdcI4())continue;
                var interior=new HashSet<Instruction>(tail.Skip(1));
                if(il.Any(i=>i.Operand is Instruction branch&&interior.Contains(branch)||i.Operand is IList<Instruction> branches&&branches.Any(interior.Contains))||
                    caller.Body.ExceptionHandlers.Any(h=>new[]{h.TryStart,h.TryEnd,h.HandlerStart,h.HandlerEnd,h.FilterStart}.Any(i=>i!=null&&interior.Contains(i))))continue;
                var called=(IMethod)call.Operand; var predicate=LocalType(module,called.DeclaringType)?.FindMethod(called.Name,called.MethodSig); if(predicate?.Module!=module)continue;
                if(!(predicate.IsPublic||predicate.IsAssembly||predicate.IsFamilyOrAssembly)||
                    !(data.IsPublic||data.IsAssembly||data.IsFamilyOrAssembly)||
                    !Accessible(predicate.DeclaringType)||!Accessible(data.DeclaringType))continue;
                var keys=predicate.DeclaringType.Fields.Where(f=>f.InitialValue?.Length==data.InitialValue.Length&&f.InitialValue.Length>=64)
                    .Select(f=>f.InitialValue).ToArray();
                if(keys.Length!=1)continue;
                ulong salt=unchecked((ulong)(long)tail[5].Operand);
                var matches=new List<(string Kind,string Label)>();
                if(watch.Elapsed.TotalSeconds>120)
                {report.Add(new{Caller=caller.MDToken.Raw,Offset=call.Offset,Status="budget-retained"});continue;}
                bool boxedInt=start>=3&&il[start-3].OpCode.Code==Code.Box&&
                    (il[start-3].Operand as ITypeDefOrRef)?.FullName=="System.Int32"&&
                    il[start-2].OpCode.Code==Code.Dup&&il[start-1].IsStloc();
                bool expired=false;
                foreach(string value in boxedInt?Array.Empty<string>():candidateStrings)
                {
                    if(watch.Elapsed.TotalSeconds>120){expired=true;break;}
                    if(Enumerable.SequenceEqual(Encode(Encoding.Unicode.GetBytes(value),salt,keys[0]),data.InitialValue))matches.Add(("String",value));
                }
                foreach(int value in boxedInt?candidateIntegers:Array.Empty<int>())
                {
                    if(watch.Elapsed.TotalSeconds>120){expired=true;break;}
                    if(Enumerable.SequenceEqual(Encode(BigEndian(unchecked((uint)value),4),salt,keys[0]),data.InitialValue))matches.Add(("Int32",value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                }
                if(expired){report.Add(new{Caller=caller.MDToken.Raw,Offset=call.Offset,Status="budget-retained"});continue;}
                if(matches.Count!=1)
                {
                    report.Add(new{Caller=caller.MDToken.Raw,Offset=call.Offset,Status="unresolved",Matches=matches.Count});continue;
                }
                var match=matches[0];
                if(boxedInt&&match.Kind=="Int32")
                {
                    int value=int.Parse(match.Label,System.Globalization.CultureInfo.InvariantCulture);
                    tail[0].OpCode=OpCodes.Unbox_Any;tail[0].Operand=module.CorLibTypes.Int32.TypeDefOrRef;
                    tail[1].OpCode=OpCodes.Ldc_I4;tail[1].Operand=value;
                    tail[2].OpCode=OpCodes.Ceq;tail[2].Operand=null;
                    foreach(var instruction in tail.Skip(3)){instruction.OpCode=OpCodes.Nop;instruction.Operand=null;}
                    direct++;
                    report.Add(new{Caller=caller.MDToken.Raw,Status="direct-int32",Constant=value,
                        Evidence="Statically boxed Int32 input; fixed-width encoding verified against original ciphertext."});
                    continue;
                }
                var wrapper=new MethodDefUser("Equals"+match.Kind+"_"+owner.Methods.Count.ToString("D4"),
                    MethodSig.CreateStatic(module.CorLibTypes.Boolean,module.CorLibTypes.Object,module.CorLibTypes.String),
                    MethodImplAttributes.IL|MethodImplAttributes.Managed,MethodAttributes.Assembly|MethodAttributes.Static|MethodAttributes.HideBySig)
                {Body=new CilBody()};
                wrapper.Parameters[0].Name="value";wrapper.Parameters[1].Name="expectedConstant";
                var body=wrapper.Body.Instructions;
                var load=OpCodes.Ldarg_0.ToInstruction();
                body.Add(OpCodes.Ldarg_1.ToInstruction());body.Add(OpCodes.Ldstr.ToInstruction(match.Label));
                body.Add(OpCodes.Call.ToInstruction(equality));body.Add(OpCodes.Brtrue.ToInstruction(load));
                body.Add(OpCodes.Newobj.ToInstruction(error));body.Add(OpCodes.Throw.ToInstruction());body.Add(load);
                foreach(var instruction in tail)body.Add(new Instruction(instruction.OpCode,instruction.Operand));
                body.Add(OpCodes.Ret.ToInstruction());owner.Methods.Add(wrapper);
                tail[0].OpCode=OpCodes.Ldstr;tail[0].Operand=match.Label;
                foreach(var instruction in tail.Skip(1)){instruction.OpCode=OpCodes.Nop;instruction.Operand=null;}
                call.OpCode=OpCodes.Call;call.Operand=wrapper;
                caller.Body.SimplifyBranches();caller.Body.OptimizeBranches();
                report.Add(new{Caller=caller.MDToken.Raw,Offset=call.Offset,Status="recovered",match.Kind,Constant=match.Label,
                    Salt=salt.ToString(),Predicate=predicate.MDToken.Raw,Helper=wrapper.Name.String,
                    Evidence="PBKDF2-SHA1/XXTEA/RSA re-encoding equals every original ciphertext byte; original predicate, argument evaluation and initialization retained. Not a direct-equality replacement."});
            }
        }
        int changes=direct+owner.Methods.Count-existing;
        if(changes==0)
        {File.WriteAllText(reportPath,JsonConvert.SerializeObject(report,Formatting.Indented));return 0;}
        if(owner.Methods.Count>0&&owner.Module==null)module.Types.Add(owner);
        foreach(var method in module.GetTypes().Where(t=>t!=owner).SelectMany(t=>t.Methods).Where(m=>m.HasBody))
            method.Body.KeepOldMaxStack=true;
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        string temporary=output+"."+Guid.NewGuid().ToString("N")+".tmp";
        try
        {
            module.Write(temporary,new ModuleWriterOptions(module){MetadataOptions={Flags=MetadataFlags.PreserveAll}});
            using(var reopened=ModuleDefMD.Load(temporary))
                if(owner.Methods.Count>0&&reopened.GetTypes().Single(t=>t.FullName==owner.FullName).Methods.Count!=owner.Methods.Count)throw new InvalidDataException("Wrapper readback mismatch.");
            File.WriteAllText(reportPath,JsonConvert.SerializeObject(report,Formatting.Indented));
            File.Move(temporary,output);
        }
        finally{if(File.Exists(temporary))File.Delete(temporary);}
        return changes;
    }

    private static int LowerExisting(ModuleDef module,List<object> report)
    {
        var owner=module.GetTypes().FirstOrDefault(t=>t.FullName=="RecoveredConstantComparisons");
        if(owner==null)return 0;
        int changes=0;
        foreach(var helper in owner.Methods.Where(m=>m.IsStatic&&m.HasBody&&m.Name.String.StartsWith("EqualsInt32_",StringComparison.Ordinal)).ToArray())
        {
            var body=helper.Body.Instructions;
            if(body.Count!=16||helper.Body.ExceptionHandlers.Count!=0||helper.Body.Variables.Count!=0||owner.FindStaticConstructor()!=null||
                helper.MethodSig.Params.Count!=2||helper.MethodSig.Params[0].ElementType!=ElementType.Object||helper.MethodSig.Params[1].ElementType!=ElementType.String||
                body[0].OpCode.Code!=Code.Ldarg_1||body[1].OpCode.Code!=Code.Ldstr||body[2].OpCode.Code!=Code.Call||
                body[2].Operand is not IMethod equality||equality.FullName!="System.Boolean System.String::op_Equality(System.String,System.String)"||
                body[3].OpCode.Code!=Code.Brtrue&&body[3].OpCode.Code!=Code.Brtrue_S||body[3].Operand!=body[6]||
                body[4].OpCode.Code!=Code.Newobj||body[4].Operand is not IMethod error||error.FullName!="System.Void System.ArgumentException::.ctor()"||
                body[5].OpCode.Code!=Code.Throw||body[6].OpCode.Code!=Code.Ldarg_0||!body[7].IsLdcI4()||
                body[8].OpCode.Code!=Code.Newarr||body[9].OpCode.Code!=Code.Dup||body[10].OpCode.Code!=Code.Ldtoken||
                body[11].OpCode.Code!=Code.Call||body[11].Operand is not IMethod initialize||initialize.FullName!="System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)"||
                !body[13].IsLdcI4()||body[15].OpCode.Code!=Code.Ret)continue;
            var labels=body.Where(i=>i.OpCode.Code==Code.Ldstr).Select(i=>i.Operand as string).Distinct().ToArray();
            if(labels.Length!=1||!int.TryParse(labels[0],System.Globalization.NumberStyles.Integer,System.Globalization.CultureInfo.InvariantCulture,out int value))continue;
            int call=body.ToList().FindLastIndex(i=>i.OpCode.Code==Code.Call&&i.Operand is IMethod m&&IsPredicate(LocalType(module,m.DeclaringType)?.FindMethod(m.Name,m.MethodSig)));
            if(call<7||body[call-4].Operand is not IField field||body[call-2].OpCode.Code!=Code.Ldc_I8)continue;
            var data=LocalType(module,field.DeclaringType)?.Fields.FirstOrDefault(f=>f.Name==field.Name)?.InitialValue;
            var target=(IMethod)body[call].Operand;
            var predicate=LocalType(module,target.DeclaringType)?.FindMethod(target.Name,target.MethodSig);
            var keys=predicate?.DeclaringType.Fields.Where(f=>f.InitialValue?.Length==data?.Length&&f.InitialValue?.Length>=64).ToArray();
            if(data==null||keys?.Length!=1||!Enumerable.SequenceEqual(Encode(BigEndian(unchecked((uint)value),4),unchecked((ulong)(long)body[call-2].Operand),keys[0].InitialValue),data))continue;
            foreach(var caller in module.GetTypes().Where(t=>t!=owner).SelectMany(t=>t.Methods).Where(m=>m.HasBody))
            {
                var il=caller.Body.Instructions;
                foreach(var instruction in il.Where(i=>i.OpCode.Code==Code.Call&&i.Operand is IMethod m&&LocalType(module,m.DeclaringType)?.FindMethod(m.Name,m.MethodSig)==helper).ToArray())
                {
                    int index=il.IndexOf(instruction),label=index-1;
                    if(label<3||il[label].OpCode.Code!=Code.Ldstr||(string)il[label].Operand!=labels[0]||
                        il[label-3].OpCode.Code!=Code.Box||(il[label-3].Operand as ITypeDefOrRef)?.FullName!="System.Int32"||
                        il[label-2].OpCode.Code!=Code.Dup||!il[label-1].IsStloc())continue;
                    var interior=new HashSet<Instruction>(il.Skip(label-2).Take(5));
                    if(il.Any(i=>i.Operand is Instruction branch&&interior.Contains(branch)||i.Operand is IList<Instruction> branches&&branches.Any(interior.Contains))||
                        caller.Body.ExceptionHandlers.Any(h=>new[]{h.TryStart,h.TryEnd,h.HandlerStart,h.HandlerEnd,h.FilterStart}.Any(i=>i!=null&&interior.Contains(i))))continue;
                    il[label].OpCode=OpCodes.Nop;il[label].Operand=null;
                    instruction.OpCode=OpCodes.Unbox_Any;instruction.Operand=module.CorLibTypes.Int32.TypeDefOrRef;
                    il.Insert(index+1,OpCodes.Ldc_I4.ToInstruction(value));il.Insert(index+2,OpCodes.Ceq.ToInstruction());
                    caller.Body.SimplifyBranches();caller.Body.OptimizeBranches();changes++;
                    report.Add(new{Caller=caller.MDToken.Raw,Status="lowered-existing-int32",Constant=value});
                }
            }
            bool used=module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody).SelectMany(m=>m.Body.Instructions)
                .Any(i=>i.Operand is IMethod m&&LocalType(module,m.DeclaringType)?.FindMethod(m.Name,m.MethodSig)==helper);
            if(!used)owner.Methods.Remove(helper);
        }
        if(owner.Methods.Count==0)module.Types.Remove(owner);
        return changes;
    }

    private static TypeDef? LocalType(ModuleDef module,ITypeDefOrRef type)
    {
        if(type.Scope!=module && !(type.Scope is ModuleRef scope&&scope.Name==module.Name))return null;
        return module.GetTypes().FirstOrDefault(t=>t.FullName==type.FullName);
    }
    private static bool Accessible(TypeDef type)
    {
        for(var current=type;current.DeclaringType!=null;current=current.DeclaringType)
            if(!(current.IsNestedPublic||current.IsNestedAssembly||current.IsNestedFamilyOrAssembly))return false;
        return true;
    }
    private static bool IsPredicate(MethodDef? m)=>m!=null&&m.IsStatic&&m.MethodSig is {Params.Count:4} s&&s.RetType.ElementType==ElementType.Boolean&&
        s.Params[0].ElementType==ElementType.Object&&s.Params[1].FullName=="System.Byte[]"&&s.Params[2].ElementType==ElementType.U8&&s.Params[3].ElementType==ElementType.I4;
    private static byte[] BigEndian(ulong value,int length)
    {var result=new byte[length];for(int i=length-1;i>=0;i--){result[i]=(byte)value;value>>=8;}return result;}
    private static BigInteger Integer(byte[] bytes)=>new BigInteger(Enumerable.Reverse(bytes).Concat(new byte[]{0}).ToArray());
    private static byte[] Encode(byte[] input,ulong salt,byte[] modulus)
    {
        var n=Integer(modulus);int bits=0;for(var v=n;v>0;v>>=1)bits++;
        int size=(bits-1)/8,block=(bits+7)/8;
        if(size<8||input.Length==0||input.Length>size*4)return Array.Empty<byte>();
        byte[] key=BigEndian(salt,8),data=new byte[(input.Length+size-1)/size*size];
        int rem=input.Length%size;
        if(rem!=0)
        {using var derive=new Rfc2898DeriveBytes(input,key,rem<8?200:1);var padding=derive.GetBytes(size);Buffer.BlockCopy(padding,0,data,data.Length-size,size);}
        Buffer.BlockCopy(input,0,data,0,input.Length);
        int length=data.Length/4;var words=new uint[length];var keys=new uint[4];
        for(int i=0;i<length;i++)words[i]=Read(data,4*i);
        keys[0]=Read(key,0);keys[1]=Read(key,4);
        unchecked
        {
            uint z=words[length-1],sum=0;
            for(int rounds=6+52/length;rounds>0;rounds--)
            {sum+=0x9e3779b9;uint e=(sum>>2)&3;
                for(int i=0;i<length;i++)
                {uint y=words[(i+1)%length];z=words[i]+=(((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((sum^y)+(keys[(i&3)^(int)e]^z));}}
        }
        for(int i=0;i<length;i++)for(int b=0;b<4;b++)data[4*i+b]=(byte)(words[i]>>(8*b));
        var result=new byte[data.Length/size*block];
        for(int i=0;i<data.Length/size;i++)
        {var value=BigInteger.ModPow(Integer(data.Skip(i*size).Take(size).ToArray()),65537,n).ToByteArray();
            for(int b=0;b<Math.Min(value.Length,block);b++)result[i*block+block-1-b]=value[b];}
        return result;
    }
    private static uint Read(byte[] b,int i)=>(uint)(b[i]|b[i+1]<<8|b[i+2]<<16|b[i+3]<<24);
}
