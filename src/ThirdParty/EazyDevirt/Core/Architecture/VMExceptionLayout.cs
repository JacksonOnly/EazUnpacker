using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace EazyDevirt.Core.Architecture;

internal enum VMExceptionField { Kind, CatchType, HandlerStart, TryStart, TryLength, FilterStart, UnusedOffset }

internal sealed class VMExceptionLayout
{
    public List<VMExceptionField> Fields { get; } = new();
    public Dictionary<int, CilExceptionHandlerType> Kinds { get; } = new();
    public bool Int32Kind { get; private set; }

    public static VMExceptionLayout Discover(TypeDefinition runtime)
    {
        TypeDefinition? Record(MethodDefinition method) =>
            (method.Signature?.ReturnType is SzArrayTypeSignature array ? array.BaseType : method.Signature?.ReturnType)
                ?.ToTypeDefOrRef()?.Resolve();
        bool IsInt32(FieldDefinition field) => field.Signature?.FieldType.FullName == "System.Int32" ||
            field.Signature?.FieldType.ToTypeDefOrRef()?.Resolve() is { IsEnum: true } type &&
            type.Fields.Any(f=>f.Name=="value__" && f.Signature?.FieldType.FullName=="System.Int32");
        var parser = runtime.Methods.FirstOrDefault(m => m.Parameters.Count == 1 && m.CilMethodBody != null &&
            Record(m) is { } type &&
            type.Fields.Count(f => f.Signature?.FieldType.FullName == "System.UInt32") is 4 or 5 &&
            type.Fields.Count(IsInt32) == 2 &&
            m.CilMethodBody.Instructions.Select(i => i.Operand).OfType<MethodDefinition>().Count(c =>
                c.DeclaringType == type && c.Parameters.Count == 1 && c.Signature?.ReturnType.FullName == "System.Void") == type.Fields.Count)
            ?? throw new NotSupportedException("Cannot discover VM exception record parser.");
        var record = Record(parser)!;
        var roles = new Dictionary<FieldDefinition, VMExceptionField>();
        FieldDefinition? GetterField(CilInstruction instruction) =>
            instruction.Operand is MethodDefinition getter && getter.DeclaringType == record
                ? getter.CilMethodBody?.Instructions.FirstOrDefault(i => i.OpCode.Code == CilCode.Ldfld)?.Operand as FieldDefinition
                : null;
        var layout = new VMExceptionLayout();
        foreach (var method in runtime.Methods.Where(m => m.CilMethodBody != null))
        {
            var instructions = method.CilMethodBody!.Instructions;
            for (int i = 0; i < instructions.Count; i++)
            {
                if (GetterField(instructions[i]) is not { } field) continue;
                if (i + 2 < instructions.Count && instructions[i + 1].IsLdcI4() &&
                    instructions[i + 2].Operand is IMethodDescriptor { Signature.ReturnType.FullName: "System.Type" })
                    roles[field] = VMExceptionField.CatchType;
                if (i + 1 < instructions.Count &&
                    instructions[i + 1].Operand is IMethodDescriptor { Signature.ReturnType.FullName: "System.Type", Signature.ParameterTypes.Count: 1 })
                    roles[field] = VMExceptionField.CatchType;
                if (i + 2 < instructions.Count && instructions[i + 1].IsLdloc() &&
                    GetterField(instructions[i + 2]) is { } length && i + 3 < instructions.Count &&
                    instructions[i + 3].Operand is IMethodDescriptor { Signature.ReturnType.FullName: "System.Boolean", Signature.ParameterTypes.Count: 3 })
                {
                    roles[field] = VMExceptionField.TryStart;
                    roles[length] = VMExceptionField.TryLength;
                }
                if (IsInt32(field) && i + 3 < instructions.Count &&
                    instructions[i + 1].IsStloc() && instructions[i + 2].IsLdloc() &&
                    instructions[i + 3].OpCode.Code == CilCode.Switch && instructions[i + 3].Operand is IList<ICilLabel> cases)
                {
                    roles[field] = VMExceptionField.Kind;
                    for (int kind = 0; kind < cases.Count; kind++)
                    {
                        int start = instructions.GetIndexByOffset(cases[kind].Offset);
                        var block = instructions.Skip(start).TakeWhile(x => x.OpCode.Code is not (CilCode.Br or CilCode.Br_S)).ToArray();
                        var constructor = block.FirstOrDefault(x => x.OpCode.Code == CilCode.Newobj)?.Operand as IMethodDescriptor;
                        if (constructor == null) continue;
                        var offsetGetter = block.FirstOrDefault(x => GetterField(x) is { } offset &&
                            offset.Signature?.FieldType.FullName == "System.UInt32" &&
                            (!roles.TryGetValue(offset,out var role) || role is not (VMExceptionField.TryStart or VMExceptionField.TryLength)));
                        if (offsetGetter == null) continue;
                        bool hasExceptionObject = constructor.Signature!.ParameterTypes.Count == 2 || block.Any(x=>
                            x.Operand is IMethodDescriptor setter && setter.DeclaringType?.FullName==constructor.DeclaringType?.FullName &&
                            setter.Signature?.ReturnType.FullName=="System.Void" && setter.Signature.ParameterTypes.Count==1 &&
                            setter.Signature.ParameterTypes[0].FullName=="System.Object");
                        bool resolvesCatchType = block.Any(x => x.Operand is IMethodDescriptor { Signature.ReturnType.FullName: "System.Type" });
                        bool conditional = block.Length > 1 && block[1].OpCode.Code is CilCode.Brfalse or CilCode.Brfalse_S;
                        layout.Kinds[kind] = resolvesCatchType ? CilExceptionHandlerType.Exception
                            : hasExceptionObject ? CilExceptionHandlerType.Filter
                            : conditional ? CilExceptionHandlerType.Fault : CilExceptionHandlerType.Finally;
                        roles[GetterField(offsetGetter)!] = hasExceptionObject && !resolvesCatchType
                            ? VMExceptionField.FilterStart : VMExceptionField.HandlerStart;
                    }
                }
            }
        }
        // A historical record can serialize one additional UInt32 whose getter
        // is never consumed by the runtime. Keep its wire slot without assigning
        // an unproven exception-region meaning to it.
        var unused=record.Fields.Where(f=>!roles.ContainsKey(f)).ToArray();
        if(unused.Length==1 && unused[0].Signature?.FieldType.FullName=="System.UInt32")
        {
            var getters=record.Methods.Where(m=>m.CilMethodBody?.Instructions.Any(i=>
                i.OpCode.Code==CilCode.Ldfld && i.Operand==unused[0])==true).ToArray();
            bool consumed=runtime.DeclaringModule!.GetAllTypes().SelectMany(t=>t.Methods).Where(m=>m.CilMethodBody!=null)
                .Any(m=>m.CilMethodBody!.Instructions.Any(i=>i.Operand is MethodDefinition called && getters.Contains(called) ||
                    i.OpCode.Code is CilCode.Ldfld or CilCode.Ldflda && i.Operand==unused[0] && !getters.Contains(m)));
            if(!consumed)roles[unused[0]]=VMExceptionField.UnusedOffset;
        }
        var parseInstructions=parser.CilMethodBody!.Instructions;
        for(int index=0;index<parseInstructions.Count;index++)
        {
            if(parseInstructions[index].Operand is not MethodDefinition setter)continue;
            if (setter.DeclaringType != record || setter.Parameters.Count != 1) continue;
            var field = setter.CilMethodBody?.Instructions.FirstOrDefault(i => i.OpCode.Code == CilCode.Stfld)?.Operand as FieldDefinition;
            if (field == null || !roles.TryGetValue(field, out var role))
                throw new NotSupportedException("Unknown VM exception field role.");
            layout.Fields.Add(role);
            if(role==VMExceptionField.Kind)
            {
                var read=parseInstructions.Take(index).Select(i=>i.Operand).OfType<IMethodDescriptor>().LastOrDefault();
                if(read?.Signature?.ReturnType.FullName is not ("System.Byte" or "System.Int32"))
                    throw new NotSupportedException("Unknown VM exception kind encoding.");
                layout.Int32Kind=read.Signature.ReturnType.FullName=="System.Int32";
            }
        }
        if (layout.Fields.Count != record.Fields.Count || layout.Fields.Distinct().Count() != record.Fields.Count || layout.Kinds.Count != 4)
            throw new NotSupportedException("Incomplete VM exception layout: " + string.Join(",", layout.Fields) + "; " + string.Join(",", layout.Kinds.Select(p => p.Key + "=" + p.Value)));
        EazyDevirt.Logging.ConsoleLogger.Detail("VM exception layout: " + string.Join(", ", layout.Fields) + "; kinds: " +
            string.Join(", ", layout.Kinds.Select(p => p.Key + "=" + p.Value)));
        return layout;
    }
}
