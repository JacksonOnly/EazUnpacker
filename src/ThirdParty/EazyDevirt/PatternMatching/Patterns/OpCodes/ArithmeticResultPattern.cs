using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace EazyDevirt.PatternMatching.Patterns.OpCodes;

internal static class ArithmeticResultPattern
{
    // Eaz's flow pass moves unchecked arithmetic behind a branch to the common
    // result constructor. Check that path and its local instead of requiring
    // the constructor to be immediately after the arithmetic.
    public static bool Verify(CilInstructionCollection instructions, int storeIndex)
    {
        int next = storeIndex + 1;
        var visited = new HashSet<int>();
        while (next < instructions.Count && instructions[next].OpCode.Code is CilCode.Br or CilCode.Br_S)
        {
            if (!visited.Add(next) || instructions[next].Operand is not ICilLabel label) return false;
            next = instructions.GetIndexByOffset(label.Offset);
            if (next < 0) return false;
        }
        if (next + 4 < instructions.Count && instructions[next].OpCode.Code==CilCode.Newobj &&
            instructions[next+1].OpCode.Code==CilCode.Dup && instructions[next+2].IsLdloc() &&
            instructions[next+2].GetLocalVariableIndex()==instructions[storeIndex].GetLocalVariableIndex() &&
            instructions[next+3].Operand is IMethodDescriptor setter && setter.Signature?.ParameterTypes.Count==1 &&
            setter.Signature.ReturnType.FullName=="System.Void" &&
            setter.Signature.ParameterTypes[0].FullName is "System.Int32" or "System.Int64" &&
            instructions[next+4].OpCode.Code==CilCode.Ret &&
            instructions[next].Operand is IMethodDescriptor emptyCtor && emptyCtor.DeclaringType==setter.DeclaringType)
            return true;
        if(next+6<instructions.Count && instructions[next].OpCode.Code==CilCode.Newobj &&
            instructions[next].Operand is IMethodDescriptor storedCtor && storedCtor.Signature?.ParameterTypes.Count==0 &&
            instructions[next+1].IsStloc() && instructions[next+2].IsLdloc() && instructions[next+3].IsLdloc() &&
            instructions[next+5].IsLdloc() &&
            instructions[next+1].GetLocalVariableIndex()==instructions[next+2].GetLocalVariableIndex() &&
            instructions[next+1].GetLocalVariableIndex()==instructions[next+5].GetLocalVariableIndex() &&
            instructions[next+3].GetLocalVariableIndex()==instructions[storeIndex].GetLocalVariableIndex() &&
            instructions[next+4].Operand is IMethodDescriptor storedSetter && storedSetter.DeclaringType==storedCtor.DeclaringType &&
            storedSetter.Signature?.ReturnType.FullName=="System.Void" && storedSetter.Signature.ParameterTypes.Count==1 &&
            storedSetter.Signature.ParameterTypes[0].FullName is "System.Int32" or "System.Int64" &&
            instructions[next+6].OpCode.Code==CilCode.Ret)return true;
        if (next + 2 >= instructions.Count || !instructions[next].IsLdloc() ||
            instructions[next].GetLocalVariableIndex() != instructions[storeIndex].GetLocalVariableIndex() ||
            instructions[next + 1].OpCode.Code != CilCode.Newobj ||
            instructions[next + 2].OpCode.Code != CilCode.Ret ||
            instructions[next + 1].Operand is not IMethodDescriptor ctor) return false;
        return ctor.Signature?.ParameterTypes.Count == 1 &&
            ctor.Signature.ParameterTypes[0].FullName is "System.Int32" or "System.Int64";
    }
}
