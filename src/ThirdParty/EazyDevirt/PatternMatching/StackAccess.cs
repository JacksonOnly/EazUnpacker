using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace EazyDevirt.PatternMatching;

/// <summary>Verifies local generic stack operations by their array/count updates.</summary>
internal static class StackAccess
{
    internal static bool IsPush(IMethodDescriptor target) => IsAccess(target, true);
    internal static bool IsPop(IMethodDescriptor target) => IsAccess(target, false);

    private static bool IsAccess(IMethodDescriptor target, bool push)
    {
        if (target.DeclaringType?.FullName.StartsWith("System.Collections.Generic.Stack`1<") == true)
            return target.Name == (push ? "Push" : "Pop");
        var method = target.Resolve();
        if (method?.CilMethodBody == null || method.IsStatic || method.DeclaringType?.GenericParameters.Count != 1 ||
            method.DeclaringType.DeclaringModule != EazyDevirt.Devirtualization.DevirtualizationContext.Instance.Module ||
            method.Parameters.Count != (push ? 1 : 0)) return false;
        var ins = method.CilMethodBody.Instructions;
        for (int i=0; !push && i+7<ins.Count; i++)
        {
            if (ins[i].OpCode.Code != CilCode.Ldfld || ins[i].Operand is not IFieldDescriptor count ||
                count.Signature?.FieldType.FullName != "System.Int32" ||
                !ins[i+1].IsLdcI4() || ins[i+1].GetLdcI4Constant()!=1 ||
                ins[i+2].OpCode.Code!=CilCode.Sub) continue;
            bool savedDecrement=ins[i+3].IsStloc() && ins[i+4].IsLdloc() && ins[i+6].IsLdloc() &&
                ins[i+3].GetLocalVariableIndex()==ins[i+4].GetLocalVariableIndex() &&
                ins[i+3].GetLocalVariableIndex()==ins[i+6].GetLocalVariableIndex();
            bool duplicatedDecrement=ins[i+3].OpCode.Code==CilCode.Dup && ins[i+4].IsStloc() && ins[i+6].IsLdloc() &&
                ins[i+4].GetLocalVariableIndex()==ins[i+6].GetLocalVariableIndex();
            if ((savedDecrement || duplicatedDecrement) && ins[i+5].OpCode.Code==CilCode.Stfld &&
                ins[i+5].Operand is IFieldDescriptor store && store.FullName==count.FullName &&
                ins[i+6].IsLdloc() && ins[i+7].OpCode.Code==CilCode.Ldelem) return true;
        }
        if (!push) return false;
        for (int i=0; i+9<ins.Count; i++)
        {
            bool savedIncrement=ins[i+1].IsStloc() && ins[i+2].IsLdloc() && ins[i+6].IsLdloc() &&
                ins[i+1].GetLocalVariableIndex()==ins[i+2].GetLocalVariableIndex() &&
                ins[i+1].GetLocalVariableIndex()==ins[i+6].GetLocalVariableIndex();
            bool duplicatedIncrement=ins[i+1].OpCode.Code==CilCode.Dup && ins[i+2].IsStloc() && ins[i+6].IsLdloc() &&
                ins[i+2].GetLocalVariableIndex()==ins[i+6].GetLocalVariableIndex();
            if (ins[i].OpCode.Code==CilCode.Ldfld && ins[i].Operand is IFieldDescriptor count &&
                count.Signature?.FieldType.FullName=="System.Int32" && (savedIncrement || duplicatedIncrement) &&
                ins[i+3].IsLdcI4() && ins[i+3].GetLdcI4Constant()==1 && ins[i+4].OpCode.Code==CilCode.Add &&
                ins[i+5].OpCode.Code==CilCode.Stfld && ins[i+5].Operand is IFieldDescriptor store && store.FullName==count.FullName &&
                ins[i+6].IsLdloc() && ins[i+7].OpCode.Code==CilCode.Ldarg_1 && ins[i+8].OpCode.Code==CilCode.Stelem) return true;
        }
        return false;
    }
}
