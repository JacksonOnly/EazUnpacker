using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions.Interfaces;
using EazyDevirt.Core.Architecture;

namespace EazyDevirt.PatternMatching.Patterns.OpCodes;

internal abstract record BooleanComparator : IOpCodePattern
{
    protected abstract IPattern Inner { get; }
    public override IList<CilOpCode> Pattern=>new List<CilOpCode>{CilOpCodes.Call,CilOpCodes.Ldc_I4_0,CilOpCodes.Cgt_Un,CilOpCodes.Newobj,CilOpCodes.Callvirt,CilOpCodes.Ret};
    public override bool MatchEntireBody=>false;
    public override bool Verify(VMOpCode opcode,int index=0)=>opcode.SerializedDelegateMethod.CilMethodBody!.Instructions[index].Operand is MethodDefinition helper
        && helper.IsStatic && helper.Signature?.ReturnType.FullName=="System.Boolean" && helper.Signature.ParameterTypes.Count==2
        && PatternMatcher.MatchesPattern(Inner,helper);
}
internal record BooleanCgt: BooleanComparator {protected override IPattern Inner=>new CgtInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Cgt;}
internal record BooleanCgtUnsigned: BooleanComparator {protected override IPattern Inner=>new Cgt_UnInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Cgt_Un;}
internal record BooleanClt: BooleanComparator {protected override IPattern Inner=>new CltInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Clt;}
internal record BooleanCltUnsigned: BooleanComparator {protected override IPattern Inner=>new Clt_UnInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Clt_Un;}
internal record BooleanEqual: BooleanComparator {protected override IPattern Inner=>new CeqInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Ceq;}

// Temporary trace normalization can inline the zero-result branch, while the
// one-result branch still jumps to the same setter. Verify both CFG paths.
internal abstract record StoredBooleanComparator : IOpCodePattern
{
    protected abstract IPattern Inner { get; }
    public override IList<CilOpCode> Pattern=>new[]{CilOpCodes.Call,CilOpCodes.Brtrue_S,CilOpCodes.Ldc_I4_0};
    public override bool MatchEntireBody=>false;
    public override bool Verify(VMOpCode opcode,int index=0)
    {
        var ins=opcode.SerializedDelegateMethod.CilMethodBody!.Instructions;
        if(ins[index].Operand is not MethodDefinition helper || !helper.IsStatic ||
            helper.Signature?.ReturnType.FullName!="System.Boolean" || helper.Signature.ParameterTypes.Count!=2 ||
            !PatternMatcher.MatchesPattern(Inner,helper) || ins[index+1].Operand is not ICilLabel branch)return false;
        int one=ins.GetIndexByOffset(branch.Offset);
        if(one<0 || !ins[one].IsLdcI4() || ins[one].GetLdcI4Constant()!=1)return false;
        CilInstruction? Setter(int at)
        {
            var seen=new HashSet<int>();
            while(at>=0 && at<ins.Count && seen.Add(at))
            {
                if(ins[at].OpCode.Code==CilCode.Nop){at++;continue;}
                if(ins[at].OpCode.Code is CilCode.Br or CilCode.Br_S && ins[at].Operand is ICilLabel jump)
                {at=ins.GetIndexByOffset(jump.Offset);continue;}
                return ins[at].Operand is IMethodDescriptor setter && setter.Signature?.ReturnType.FullName=="System.Void" &&
                    setter.Signature.ParameterTypes.Count==1 && setter.Signature.ParameterTypes[0].FullName=="System.Int32"
                    ?ins[at]:null;
            }
            return null;
        }
        var zeroSetter=Setter(index+3);
        return zeroSetter!=null && ReferenceEquals(zeroSetter,Setter(one+1));
    }
}
internal record StoredBooleanCgt: StoredBooleanComparator {protected override IPattern Inner=>new CgtInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Cgt;}
internal record StoredBooleanCgtUnsigned: StoredBooleanComparator {protected override IPattern Inner=>new Cgt_UnInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Cgt_Un;}
internal record StoredBooleanClt: StoredBooleanComparator {protected override IPattern Inner=>new CltInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Clt;}
internal record StoredBooleanCltUnsigned: StoredBooleanComparator {protected override IPattern Inner=>new Clt_UnInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Clt_Un;}
internal record StoredBooleanEqual: StoredBooleanComparator {protected override IPattern Inner=>new CeqInnerPattern(); public override CilOpCode? CilOpCode=>CilOpCodes.Ceq;}
