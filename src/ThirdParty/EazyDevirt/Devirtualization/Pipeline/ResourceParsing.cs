using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions;
using EazyDevirt.Core.IO;
using Org.BouncyCastle.Math;

namespace EazyDevirt.Devirtualization.Pipeline;

internal sealed class ResourceParsing : StageBase
{
    private ManifestResource? resource;
    private byte[] key = Array.Empty<byte>();
    private string modulus = "";
    private bool rawRsa;

    public ResourceParsing(DevirtualizationContext ctx) : base(ctx) { }

    private protected override bool Init()
    {
        foreach (var method in Ctx.Module.GetAllTypes().SelectMany(t=>t.Methods))
        {
            if(!method.IsStatic || method.Signature?.ReturnType.FullName!="System.IO.Stream" || method.Parameters.Count!=0 || method.CilMethodBody==null)continue;
            var ins=method.CilMethodBody.Instructions;
            if(!ins.Any(i=>i.Operand is IMethodDescriptor m && m.Name=="GetManifestResourceStream"))continue;
            string? name=ins.Where(i=>i.OpCode.Code==CilCode.Ldstr).Select(i=>i.Operand as string)
                .FirstOrDefault(s=>Ctx.Module.Resources.Any(r=>r.Name==s));
            var field=ins.Where(i=>i.OpCode.Code==CilCode.Ldtoken).Select(i=>i.Operand).OfType<FieldDefinition>().FirstOrDefault(f=>f.FieldRva is DataSegment);
            var modulusMethod=ins.Select(i=>i.Operand).OfType<MethodDefinition>().FirstOrDefault(m=>m.IsStatic && m.Parameters.Count==0 && m.Signature?.ReturnType.FullName=="System.String");
            string? value=modulusMethod?.CilMethodBody?.Instructions.FirstOrDefault(i=>i.OpCode.Code==CilCode.Ldstr)?.Operand as string;
            if(name==null)continue;
            var vmGetter=method.DeclaringType!.Methods.FirstOrDefault(m=>m.IsStatic && m.Parameters.Count==0 && m.Signature?.ReturnsValue==true &&
                m.Signature.ReturnType.ToTypeDefOrRef()?.Resolve() is { } t &&
                t.Methods.Any(MethodDiscovery.IsLoadVMPositionMethod));
            if(vmGetter==null)continue;
            if(field==null || value==null)
            {
                // Older runtimes use a directly seekable resource. Do not
                // mistake an unrecognized decoding wrapper for a plain stream.
                if (ins.Select(i=>i.Operand).OfType<IMethodDescriptor>().Any(m=>
                    m.Signature?.ReturnType.FullName=="System.IO.Stream" && m.Name!="GetManifestResourceStream")) continue;
                if (field!=null || value!=null) continue;
            }
            resource=Ctx.Module.Resources.First(r=>r.Name==name);
            if (field!=null)
            {
                key=((DataSegment)field.FieldRva!).Data;modulus=value!;
                rawRsa=UsesRawRsa(ins.Select(i=>i.Operand).OfType<MethodDefinition>());
            }
            Ctx.VMDeclaringType=vmGetter.Signature!.ReturnType.ToTypeDefOrRef()!.Resolve()!;
            Ctx.VMResourceGetterMdToken=method.MetadataToken;
            Ctx.Console.Info($"VM getter {method.MetadataToken}; runtime {Ctx.VMDeclaringType.MetadataToken}; resource {name}");
            return true;
        }
        Ctx.Console.Error("No supported VM resource getter found by signature and resource references.");return false;
    }

    public override bool Run()
    {
        if(!Init())return false;
        var data=resource!.GetData()!;
        if (key.Length==0)
        {
            Ctx.VMStream=new MemoryStream(data,false);Ctx.VMResolverStream=new MemoryStream(data,false);
            return true;
        }
        var tail=Convert.FromBase64String(modulus);
        var bytes=new byte[key.Length+tail.Length];Buffer.BlockCopy(key,0,bytes,0,key.Length);Buffer.BlockCopy(tail,0,bytes,key.Length,tail.Length);
        var mod=new BigInteger(1,bytes);var exp=BigInteger.ValueOf(65537);
        Ctx.VMStream=new VMCipherStream(data,mod,exp,raw:rawRsa);Ctx.VMResolverStream=new VMCipherStream(data,mod,exp,raw:rawRsa);
        return true;
    }

    private static bool UsesRawRsa(IEnumerable<MethodDefinition> wrappers)
    {
        var constructors = wrappers.Where(m=>m.CilMethodBody!=null)
            .SelectMany(m=>m.CilMethodBody!.Instructions).Where(i=>i.OpCode.Code==CilCode.Newobj)
            .Select(i=>i.Operand).OfType<MethodDefinition>().ToArray();
        // A PKCS1 wrapper can be layered around the very same raw RSA engine.
        // Its output-size reduction takes precedence over the inner formulas.
        foreach (var type in constructors.Select(c=>c.DeclaringType!).Distinct())
        foreach (var method in type.Methods.Where(m=>m.Parameters.Count==0 &&
            m.Signature?.ReturnType.FullName=="System.Int32" && m.CilMethodBody!=null))
        {
            var ins=method.CilMethodBody!.Instructions;
            for(int i=1;i+1<ins.Count;i++)
                if(ins[i].IsLdcI4() && ins[i].GetLdcI4Constant()==10 && ins[i+1].OpCode.Code==CilCode.Sub &&
                    ins[i-1].Operand is IMethodDescriptor size && size.Signature?.ReturnType.FullName=="System.Int32")
                    return false;
        }
        foreach(var constructor in constructors)
        {
            var formulas=constructor.DeclaringType!.Methods.Where(m=>m.IsStatic && m.Parameters.Count==2 &&
                m.Parameters[0].ParameterType.FullName=="System.Int32" &&
                m.Parameters[1].ParameterType.FullName=="System.Boolean" &&
                m.Signature?.ReturnType.FullName=="System.Int32" && m.CilMethodBody!=null).ToArray();
            if(formulas.Length!=2)continue;
            bool HasFormula(MethodDefinition m)=>m.CilMethodBody!.Instructions.Any(i=>i.OpCode.Code==CilCode.Div) &&
                m.CilMethodBody.Instructions.Where(i=>i.IsLdcI4()).Select(i=>i.GetLdcI4Constant()).OrderBy(v=>v)
                    .SequenceEqual(new[]{1,7,8,8});
            if(formulas.All(HasFormula))return true;
        }
        return false;
    }
}
