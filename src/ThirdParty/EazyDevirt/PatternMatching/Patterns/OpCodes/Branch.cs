using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Serialized;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions.Interfaces;
using EazyDevirt.Core.Architecture;

namespace EazyDevirt.PatternMatching.Patterns.OpCodes;

internal record SetBranchIndexPattern : IPattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Ldarg_1,     // 1	0001	ldarg.1
        CilOpCodes.Newobj,      // 2	0002	newobj	instance void valuetype [mscorlib]System.Nullable`1<uint32>::.ctor(!0)
        CilOpCodes.Stfld,       // 3	0007	stfld	valuetype [mscorlib]System.Nullable`1<uint32> VM::branchIndex
        CilOpCodes.Ret          // 4	000C	ret
    };
}

#region Br

internal record Br : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_1,     // 0	0000	ldarg.1
        CilOpCodes.Castclass,   // 1	0001	castclass	VMUIntOperand
        CilOpCodes.Callvirt,    // 2	0006	callvirt	instance uint32 VMUIntOperand::method_3()
        CilOpCodes.Stloc_0,     // 3	000B	stloc.0
        CilOpCodes.Ldarg_0,     // 4	000C	ldarg.0
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Callvirt,    // 6	000E	callvirt	instance void VM::SetBranchIndex(uint32)
        CilOpCodes.Ret          // 7	0013	ret
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Br;

    public override bool Verify(VMOpCode vmOpCode, int index) =>
        PatternMatcher.MatchesPattern(new SetBranchIndexPattern(),
            (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Br

#region Bgt

internal record Bgt : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::CgtInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brfalse_S,   // 7	0013	brfalse.s	15 (0028) ret 
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Bgt;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new CgtInnerPattern(),
            (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Bgt

#region Bgt_Un

internal record Bgt_Un : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::Cgt_UnInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brfalse_S,   // 7	0013	brfalse.s	15 (0028) ret 
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Bgt_Un;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new Cgt_UnInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Bgt_Un

#region Blt
internal record Blt : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::CltInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brfalse_S,   // 7	0013	brfalse.s	15 (0028) ret 
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Blt;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new CltInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}

// Both popped operands can be saved before the comparison, rather than leaving
// the second operand on the evaluation stack.
internal record BltStoredOperands : IOpCodePattern
{
    public override IList<CilOpCode> Pattern=>new[]
    {
        CilOpCodes.Ldarg_0,CilOpCodes.Call,CilOpCodes.Stloc,
        CilOpCodes.Ldarg_0,CilOpCodes.Call,CilOpCodes.Stloc,
        CilOpCodes.Ldloc,CilOpCodes.Ldloc,CilOpCodes.Call,CilOpCodes.Brfalse_S,
        CilOpCodes.Ldarg_1,CilOpCodes.Castclass,CilOpCodes.Callvirt,CilOpCodes.Stloc,
        CilOpCodes.Ldarg_0,CilOpCodes.Ldloc,CilOpCodes.Call,CilOpCodes.Ret,
    };
    public override CilOpCode? CilOpCode=>CilOpCodes.Blt;
    public override bool InterchangeLdlocOpCodes=>true;
    public override bool InterchangeStlocOpCodes=>true;
    public override bool Verify(VMOpCode opcode,int index=0)
    {
        var ins=opcode.SerializedDelegateMethod.CilMethodBody!.Instructions;
        return ins[index+1].Operand is MethodDefinition rightPop &&
            PatternMatcher.MatchesPattern(new PopStackPattern(),rightPop) &&
            ins[index+4].Operand is MethodDefinition leftPop &&
            PatternMatcher.MatchesPattern(new PopStackPattern(),leftPop) &&
            ins[index+2].GetLocalVariableIndex()==ins[index+7].GetLocalVariableIndex() &&
            ins[index+5].GetLocalVariableIndex()==ins[index+6].GetLocalVariableIndex() &&
            ins[index+8].Operand is MethodDefinition compare && compare.IsStatic &&
            compare.Signature?.ReturnType.FullName=="System.Boolean" && compare.Parameters.Count==2 &&
            PatternMatcher.MatchesPattern(new CltInnerPattern(),compare) &&
            ins[index+9].Operand is ICilLabel end && end.Offset==ins[index+17].Offset &&
            ins[index+12].Operand is IMethodDescriptor position && position.Signature?.ReturnType.FullName=="System.UInt32" &&
            position.Signature.ParameterTypes.Count==0 &&
            ins[index+13].GetLocalVariableIndex()==ins[index+15].GetLocalVariableIndex() &&
            ins[index+16].Operand is MethodDefinition setBranch && !setBranch.IsStatic &&
            setBranch.Parameters.Count==1 && setBranch.Parameters[0].ParameterType.FullName=="System.UInt32" &&
            PatternMatcher.MatchesPattern(new SetBranchIndexPattern(),setBranch);
    }
}
#endregion Blt

#region Blt_Un
internal record Blt_Un : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::Clt_UnInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brfalse_S,   // 7	0013	brfalse.s	15 (0028) ret 
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Blt_Un;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new Clt_UnInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Blt_Un

#region Ble
internal record Ble : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Bne_Un_S,    // 9	0016	bne.un.s	17 (0025) ldloc.1 
        CilOpCodes.Ldloc_1,     // 10	0018	ldloc.1
        CilOpCodes.Ldloc_0,     // 11	0019	ldloc.0
        CilOpCodes.Call,        // 12	001A	call	bool VM::CgtInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Ldc_I4_0,    // 13	001F	ldc.i4.0
        CilOpCodes.Ceq,         // 14	0020	ceq
        CilOpCodes.Stloc_2,     // 15	0022	stloc.2
        CilOpCodes.Br_S,        // 16	0023	br.s	23 (0030) ldloc.2 
        CilOpCodes.Ldloc_1,     // 17	0025	ldloc.1
        CilOpCodes.Ldloc_0,     // 18	0026	ldloc.0
        CilOpCodes.Call,        // 19	0027	call	bool VM::Cgt_UnInner(class VMOperandType, class VMOperandType)
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Ble;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new CgtInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[index + 3].Operand as SerializedMethodDefinition)
        !) && PatternMatcher.MatchesPattern(new Cgt_UnInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[index + 10]
            .Operand as SerializedMethodDefinition)!);
}
#endregion Ble

#region Ble_Un
internal record Ble_Un : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Bne_Un_S,    // 9	0016	bne.un.s	17 (0025) ldloc.1 
        CilOpCodes.Ldloc_1,     // 10	0018	ldloc.1
        CilOpCodes.Ldloc_0,     // 11	0019	ldloc.0
        CilOpCodes.Call,        // 12	001A	call	bool VM::Cgt_UnInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Ldc_I4_0,    // 13	001F	ldc.i4.0
        CilOpCodes.Ceq,         // 14	0020	ceq
        CilOpCodes.Stloc_2,     // 15	0022	stloc.2
        CilOpCodes.Br_S,        // 16	0023	br.s	23 (0030) ldloc.2 
        CilOpCodes.Ldloc_1,     // 17	0025	ldloc.1
        CilOpCodes.Ldloc_0,     // 18	0026	ldloc.0
        CilOpCodes.Call,        // 19	0027	call	bool VM::CgtInner(class VMOperandType, class VMOperandType)
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Ble_Un;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new Cgt_UnInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[index + 3].Operand as SerializedMethodDefinition)
        !) && PatternMatcher.MatchesPattern(new CgtInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[index + 10]
            .Operand as SerializedMethodDefinition)!);
}
#endregion Ble_Un

#region Bge
internal record Bge : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::CltInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brtrue_S,    // 7	0013	brtrue.s	15 (0028) ret 
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Bge;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new CltInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Bge

#region Bge_Un
internal record Bge_Un : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::Clt_UnInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brtrue_S,    // 7	0013	brtrue.s	15 (0028) ret 
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Bge_Un;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new Clt_UnInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Bge_Un

#region Beq

internal record Beq : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::CeqInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brfalse_S,   // 7	0013	brfalse.s	15 (0028) ret
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Beq;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new CeqInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Beq

#region Bne_Un

internal record Bne_Un : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,     // 0	0000	ldarg.0
        CilOpCodes.Callvirt,    // 1	0001	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Stloc_0,     // 2	0006	stloc.0
        CilOpCodes.Ldarg_0,     // 3	0007	ldarg.0
        CilOpCodes.Callvirt,    // 4	0008	callvirt	instance class VMOperandType VM::PopStack()
        CilOpCodes.Ldloc_0,     // 5	000D	ldloc.0
        CilOpCodes.Call,        // 6	000E	call	bool VM::CeqInner(class VMOperandType, class VMOperandType)
        CilOpCodes.Brtrue_S,    // 7	0013	brtrue.s	15 (0028) ret
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Bne_Un;

    public override bool MatchEntireBody => false;
    
    public override bool InterchangeLdlocOpCodes => true;
    public override bool InterchangeStlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index) => PatternMatcher.MatchesPattern(new CeqInnerPattern(),
        (vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions[6].Operand as SerializedMethodDefinition)!);
}
#endregion Bne_Un

#region Brtrue

internal record Brtrue : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldloc_0,     // 52	0097	ldloc.0
        CilOpCodes.Callvirt,    // 53	0098	callvirt	instance object VMOperandType::GetOperandValue()
        CilOpCodes.Ldnull,      // 54	009D	ldnull
        CilOpCodes.Cgt_Un,      // 55	009E	cgt.un
        CilOpCodes.Stloc_1,     // 56	00A0	stloc.1
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Brtrue;

    public override bool MatchEntireBody => false;
}
#endregion Brtrue

#region Brfalse

internal record Brfalse : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldloc_0,     // 54	009A	ldloc.0
        CilOpCodes.Callvirt,    // 55	009B	callvirt	instance object VMOperandType::GetOperandValue()
        CilOpCodes.Ldnull,      // 56	00A0	ldnull
        CilOpCodes.Ceq,         // 57	00A1	ceq
        CilOpCodes.Stloc_1,     // 58	00A3	stloc.1
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Brfalse;

    public override bool MatchEntireBody => false;
}
#endregion Brfalse

#region Switch

internal record Switch : IOpCodePattern
{
    public override IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldlen,       // 41	005F	ldlen
        CilOpCodes.Conv_I4,     // 42	0060	conv.i4
        CilOpCodes.Conv_I8,     // 43	0061	conv.i8
        CilOpCodes.Blt_S,       // 44	0062	blt.s	46 (0065) ldloc.3 
        CilOpCodes.Ret,         // 45	0064	ret
        CilOpCodes.Ldloc_3,     // 46	0065	ldloc.3
        CilOpCodes.Ldloc_2,     // 47	0066	ldloc.2
        CilOpCodes.Ldelem,      // 48	0067	ldelem	VMIntOperand
        CilOpCodes.Callvirt,    // 49	006C	callvirt	instance int32 VMIntOperand::method_3()
        CilOpCodes.Stloc_S,     // 50	0071	stloc.s	V_4 (4)
        CilOpCodes.Ldarg_0,     // 51	0073	ldarg.0
        CilOpCodes.Ldloc_S,     // 52	0074	ldloc.s	V_4 (4)
        CilOpCodes.Callvirt,    // 53	0076	callvirt	instance void VM::SetBranchIndex(uint32)
        CilOpCodes.Ret,         // 54	007B	ret
    };

    public override CilOpCode? CilOpCode => CilOpCodes.Switch;

    public override bool MatchEntireBody => false;

    public override bool InterchangeLdlocOpCodes => true;

    public override bool Verify(VMOpCode vmOpCode, int index = 0) =>
        vmOpCode.SerializedDelegateMethod.CilMethodBody?.Instructions![index + 12].Operand is SerializedMethodDefinition
            setBranchIndexCall &&
        PatternMatcher.MatchesPattern(new SetBranchIndexPattern(), setBranchIndexCall);
}
#endregion Switch
