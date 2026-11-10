using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions.Interfaces;
using EazyDevirt.Core.Architecture;

namespace EazyDevirt.PatternMatching.Patterns.OpCodes;

#region EazCall

internal record EazCall : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_1,     // 0	0000	ldarg.1
        CilOpCodes.Castclass,   // 1	0001	castclass	VMIntOperand
        CilOpCodes.Callvirt,    // 2	0006	callvirt	instance int32 VMIntOperand::method_3()
        CilOpCodes.Stloc_0,     // 3	000B	stloc.0
        CilOpCodes.Ldloc_0,     // 4	000C	ldloc.0
        CilOpCodes.Ldc_I4,      // 5	000D	ldc.i4	-0x80000000
        CilOpCodes.And,         // 6	0012	and
        CilOpCodes.Ldc_I4_0,    // 7	0013	ldc.i4.0
        CilOpCodes.Cgt_Un,      // 8	0014	cgt.un
        CilOpCodes.Ldloc_0,     // 9	0016	ldloc.0
        CilOpCodes.Ldc_I4,      // 10	0017	ldc.i4	0x40000000
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Call;
    public override SpecialOpCodes? SpecialOpCode => SpecialOpCodes.EazCall;
    
    public override bool IsSpecial => true;
    public override bool MatchEntireBody => false;

    public override bool Verify(VMOpCode vmOpCode, int index) =>
        vmOpCode.SerializedDelegateMethod.CilMethodBody!.Instructions[index + 5].Operand as int? == -0x80000000;
}

// Equivalent flag extraction expressed with double boolean negation and locals.
internal record EazCallBooleanFlags : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new[]
    {
        CilOpCodes.Ldloc, CilOpCodes.Ldc_I4, CilOpCodes.And, CilOpCodes.Ldc_I4_0,
        CilOpCodes.Ceq, CilOpCodes.Ldc_I4_0, CilOpCodes.Ceq, CilOpCodes.Stloc,
        CilOpCodes.Ldloc, CilOpCodes.Ldc_I4, CilOpCodes.And, CilOpCodes.Ldc_I4_0,
        CilOpCodes.Ceq, CilOpCodes.Ldc_I4_0, CilOpCodes.Ceq, CilOpCodes.Stloc,
        CilOpCodes.Ldloc, CilOpCodes.Ldc_I4, CilOpCodes.And, CilOpCodes.Stloc,
    };
    public override CilOpCode? CilOpCode => CilOpCodes.Call;
    public override SpecialOpCodes? SpecialOpCode => SpecialOpCodes.EazCall;
    public override bool IsSpecial => true;
    public override bool MatchEntireBody => false;
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;
    public override bool Verify(VMOpCode opcode,int index=0)
    {
        var ins=opcode.SerializedDelegateMethod.CilMethodBody!.Instructions;
        int value=ins[index].GetLocalVariableIndex();
        return ins[index+1].IsLdcI4() && ins[index+1].GetLdcI4Constant()==int.MinValue &&
            ins[index+9].IsLdcI4() && ins[index+9].GetLdcI4Constant()==0x40000000 &&
            ins[index+17].IsLdcI4() && ins[index+17].GetLdcI4Constant()==0x3fffffff &&
            ins[index+8].GetLocalVariableIndex()==value && ins[index+16].GetLocalVariableIndex()==value &&
            ins[index+19].GetLocalVariableIndex()==value &&
            ins.Any(i=>i.Operand is IMethodDescriptor target && target.Signature?.ReturnType.FullName=="System.Void" &&
                target.Signature.ParameterTypes.Count==4 && target.Signature.ParameterTypes[0].FullName=="System.Int32" &&
                target.Signature.ParameterTypes[1].FullName=="System.Type[]" &&
                target.Signature.ParameterTypes[2].FullName=="System.Type[]" &&
                target.Signature.ParameterTypes[3].FullName=="System.Boolean");
    }
}
#endregion EazCall

#region Homomorphic Encryption

internal record StartHomomorphic : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Call,        // 1	0001	call	class Class94 VM::smethod_135(class VM)
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Ldfld,       // 4	0008	ldfld	class VMBinaryReader VM::instructionsBinaryReader
        CilOpCodes.Callvirt,    // 5	000D	callvirt	instance class StreamBase VMBinaryReader::GetStream()
        CilOpCodes.Stloc_S,     // 6	0012	stloc.s	V_4 (4)
    };

    public override CilOpCode? CilOpCode => null;
    public override SpecialOpCodes? SpecialOpCode => SpecialOpCodes.StartHomomorphic;
    
    public override bool IsSpecial => true;
    public override bool MatchEntireBody => false;

    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) =>
        ((vmOpCode.SerializedDelegateMethod.CilMethodBody!.Instructions[index + 5].Operand as IMethodDefOrRef)?.Signature?.ReturnType?.Resolve()?.IsAbstract).GetValueOrDefault();
}

internal record EndHomomorphic : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldloc_1,     // 14	0028	ldloc.1
        CilOpCodes.Callvirt,    // 15	0029	callvirt	instance int32 class [System]System.Collections.Generic.Stack`1<class '#=q9lm1K5MbvbOloCUh$L2kujlbpJIte9dF4zmzVcvK$yo='/'#=zbMR0slg='>::get_Count()
        CilOpCodes.Ldc_I4_2,    // 16	002E	ldc.i4.2
        CilOpCodes.Bge_S,       // 17	002F	bge.s	20 (0037) ldloc.1 
        CilOpCodes.Newobj,      // 18	0031	newobj	instance void [mscorlib]System.InvalidOperationException::.ctor()
        CilOpCodes.Throw,       // 19	0036	throw
        CilOpCodes.Ldloc_1,     // 20	0037	ldloc.1
        CilOpCodes.Callvirt,    // 21	0038	callvirt	instance !0 class [System]System.Collections.Generic.Stack`1<class VM/Class85>::Pop()
    };

    public override CilOpCode? CilOpCode => null;
    public override SpecialOpCodes? SpecialOpCode => SpecialOpCodes.EndHomomorphic;
    
    public override bool IsSpecial => true;
    public override bool MatchEntireBody => false;

    public override bool InterchangeLdlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) =>
        vmOpCode.SerializedDelegateMethod.CilMethodBody!.Instructions[index + 1].Operand is IMethodDefOrRef methodDefOrRef
        && methodDefOrRef.Name == "get_Count"
        && (methodDefOrRef.DeclaringType?.FullName.StartsWith("System.Collections.Generic.Stack")).GetValueOrDefault();
}

#endregion

internal record EndHomomorphicDirectCount : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    { CilOpCodes.Ldloc, CilOpCodes.Callvirt, CilOpCodes.Ldc_I4_2, CilOpCodes.Bge_S };
    public override CilOpCode? CilOpCode => null;
    public override SpecialOpCodes? SpecialOpCode => SpecialOpCodes.EndHomomorphic;
    public override bool IsSpecial => true;
    public override bool MatchEntireBody => false;
    public override bool InterchangeLdlocOpCodes => true;
    public override bool Verify(VMOpCode vmOpCode, int index)
    {
        var body=vmOpCode.SerializedDelegateMethod.CilMethodBody!;
        var calls=body.Instructions.Select(i=>i.Operand).OfType<IMethodDescriptor>().ToArray();
        return body.Instructions[index+1].Operand is IMethodDescriptor count && count.Name=="get_Count"
            && count.DeclaringType?.FullName.StartsWith("System.Collections.Generic.Stack") == true
            && calls.Any(m=>m.Name=="Pop" && m.DeclaringType?.FullName.StartsWith("System.Collections.Generic.Stack")==true)
            && calls.Any(m=>m.Name=="Peek" && m.DeclaringType?.FullName.StartsWith("System.Collections.Generic.Stack")==true)
            && calls.Any(m=>m.FullName=="System.Void System.IDisposable::Dispose()")
            && body.ExceptionHandlers.Any(h=>h.HandlerType==AsmResolver.DotNet.Code.Cil.CilExceptionHandlerType.Finally)
            && body.Instructions.Count(i=>i.OpCode.Code==CilCode.Ceq)>=2;
    }
}

#region NoBody

internal record NoBody : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    { 
        CilOpCodes.Ret           // 0	0000	ret
    };

    public override CilOpCode? CilOpCode => null;
    public override SpecialOpCodes? SpecialOpCode => SpecialOpCodes.NoBody;
    
    public override bool IsSpecial => true;
    public override bool AllowMultiple => true;

    public override bool Verify(VMOpCode vmOpCode, int index = 0) => vmOpCode.CilOperandType == CilOperandType.InlineNone;
}

#endregion NoBody
