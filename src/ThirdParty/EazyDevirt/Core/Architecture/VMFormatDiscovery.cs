using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Architecture.InlineOperands;

namespace EazyDevirt.Core.Architecture;

/// <summary>Derives wire formats from the sample's reader switch tables instead of version-specific enums.</summary>
internal static class VMFormatDiscovery
{
    internal static bool PositionOrCipher(TypeDefinition runtime)
    {
        var loaders=runtime.Methods.Where(EazyDevirt.Devirtualization.Pipeline.MethodDiscovery.IsLoadVMPositionMethod).ToArray();
        var constructors=loaders.SelectMany(m=>m.CilMethodBody!.Instructions)
            .Where(i=>i.OpCode.Code==CilCode.Newobj).Select(i=>i.Operand).OfType<MethodDefinition>()
            .Where(m=>m.Signature?.ParameterTypes.Count==2 && m.Signature.ParameterTypes[0].FullName=="System.IO.Stream" &&
                m.Signature.ParameterTypes[1].FullName=="System.Int32").Distinct().ToArray();
        var positionConstructors=loaders.SelectMany(m=>m.CilMethodBody!.Instructions).Select(i=>i.Operand).OfType<MethodDefinition>()
            .Where(m=>m.Signature?.ReturnType.FullName=="System.Int64" && m.Parameters.Count==1 &&
                m.Parameters[0].ParameterType.FullName=="System.String" && m.CilMethodBody!=null)
            .SelectMany(m=>m.CilMethodBody!.Instructions).Where(i=>i.OpCode.Code==CilCode.Newobj)
            .Select(i=>i.Operand).OfType<MethodDefinition>().Where(m=>m.Signature?.ParameterTypes.Count==2 &&
                m.Signature.ParameterTypes[0].FullName=="System.IO.Stream" && m.Signature.ParameterTypes[1].FullName=="System.Int32").Distinct().ToArray();
        if(constructors.Length!=1 || positionConstructors.Length!=1 || constructors[0]!=positionConstructors[0])
            throw new NotSupportedException("Cannot establish a shared VM method and position cipher.");
        foreach(var constructor in constructors)
        foreach(var method in constructor.DeclaringType!.Methods.Where(m=>!m.IsStatic &&
            m.Signature?.ReturnType.FullName=="System.Byte" && m.Parameters.Count==2 &&
            m.Parameters[0].ParameterType.FullName=="System.Byte" && m.Parameters[1].ParameterType.FullName=="System.Int64" && m.CilMethodBody!=null))
        {
            var code=method.CilMethodBody!.Instructions.Where(i=>i.OpCode.Code!=CilCode.Nop).ToArray();
            if(code.Length!=12 || code[0].OpCode.Code!=CilCode.Ldarg_0 ||
                code[1].OpCode.Code!=CilCode.Ldfld || code[1].Operand is not FieldDefinition field || field.Signature?.FieldType.FullName!="System.Int32" ||
                code[2].OpCode.Code!=CilCode.Conv_U8 || code[3].OpCode.Code!=CilCode.Ldarg_2 || code[4].OpCode.Code!=CilCode.Or ||
                code[5].OpCode.Code!=CilCode.Conv_U1 || !code[6].IsStloc() || code[7].OpCode.Code!=CilCode.Ldarg_1 || !code[8].IsLdloc() ||
                code[6].GetLocalVariable(method.CilMethodBody.LocalVariables)!=code[8].GetLocalVariable(method.CilMethodBody.LocalVariables) ||
                code[9].OpCode.Code!=CilCode.Xor || code[10].OpCode.Code!=CilCode.Conv_U1 || code[11].OpCode.Code!=CilCode.Ret)continue;
            var init=constructor.CilMethodBody?.Instructions;
            if(init!=null && Enumerable.Range(1,init.Count-1).Any(i=>init[i].OpCode.Code==CilCode.Stfld && init[i].Operand==field &&
                init[i-1].OpCode.Code==CilCode.Ldarg_2) && constructor.DeclaringType.Methods.Any(read=>
                    read.Signature?.ReturnType.FullName=="System.Int32" && read.Signature.ParameterTypes.Count==3 &&
                    read.Signature.ParameterTypes[0].FullName=="System.Byte[]" &&
                    read.CilMethodBody?.Instructions.Any(i=>i.Operand==method)==true))return true;
        }
        return false;
    }

    internal static (int Static, int Generic) MethodFlags(TypeDefinition runtime)
    {
        var candidates=new HashSet<TypeDefinition>(runtime.DeclaringModule!.GetAllTypes().Where(t=>
            (t.Fields.Count==6 && t.Fields.Count(f=>f.Signature?.FieldType.FullName=="System.Byte")==1 ||
             t.Fields.Count==7 && t.Fields.Count(f=>f.Signature?.FieldType.FullName=="System.Boolean")==2) &&
            t.Fields.Count(f=>f.Signature?.FieldType.FullName=="System.String")==1 &&
            !t.Fields.Any(f=>f.Signature?.FieldType.FullName=="System.Int32")));
        var records=runtime.Methods.Where(m=>m.CilMethodBody!=null).SelectMany(m=>
            m.CilMethodBody!.Instructions.Zip(m.CilMethodBody.Instructions.Skip(1),(first,second)=>(first,second)))
            .Where(p=>p.first.Operand is MethodDefinition getter && getter.DeclaringType!=null &&
                candidates.Contains(getter.DeclaringType) && getter.Parameters.Count==0 &&
                getter.Signature?.ReturnType.FullName=="System.Boolean" && p.second.Operand is IMethodDescriptor helper &&
                helper.Signature?.ReturnType.FullName=="System.Reflection.BindingFlags")
            .Select(p=>((MethodDefinition)p.first.Operand!).DeclaringType!).Distinct().ToArray();
        if(records.Length!=1)throw new NotSupportedException("Cannot unambiguously discover VM method operand flags.");
        var record=records[0];
        if(record.Fields.Count(f=>f.Signature?.FieldType.FullName=="System.Boolean")==2)
        {
            var staticGetters=runtime.Methods.Where(m=>m.CilMethodBody!=null).SelectMany(m=>
                m.CilMethodBody!.Instructions.Zip(m.CilMethodBody.Instructions.Skip(1),(first,second)=>(first,second)))
                .Where(p=>p.first.Operand is MethodDefinition getter && getter.DeclaringType==record &&
                    getter.Parameters.Count==0 && getter.Signature?.ReturnType.FullName=="System.Boolean" &&
                    p.second.Operand is IMethodDescriptor helper && helper.Signature?.ReturnType.FullName=="System.Reflection.BindingFlags")
                .Select(p=>(MethodDefinition)p.first.Operand!).Distinct().ToArray();
            var setters=runtime.Methods.Where(m=>m.CilMethodBody!=null).Select(m=>m.CilMethodBody!.Instructions
                .Select(i=>i.Operand).OfType<MethodDefinition>().Where(s=>s.DeclaringType==record && s.Parameters.Count==1 &&
                    s.Parameters[0].ParameterType.FullName=="System.Boolean").ToArray()).Where(s=>s.Length==2).ToArray();
            if(staticGetters.Length!=1 || setters.Length!=1)throw new NotSupportedException("Ambiguous VM Boolean method flags.");
            FieldDefinition? Field(MethodDefinition method)=>method.CilMethodBody?.Instructions.Select(i=>i.Operand).OfType<FieldDefinition>().Distinct().SingleOrDefault();
            var staticField=Field(staticGetters[0]);
            if(staticField==null || setters[0].Select(Field).Distinct().Count()!=2 || !setters[0].Any(s=>Field(s)==staticField))
                throw new NotSupportedException("Cannot relate VM Boolean flags to their wire fields.");
            var ctx=EazyDevirt.Devirtualization.DevirtualizationContext.Instance;
            ctx.MethodFlagsAreBooleans=true;ctx.MethodStaticBooleanFirst=Field(setters[0][0])==staticField;
            return(1,2);
        }
        var masks=new Dictionary<MethodDefinition,int>();
        foreach(var getter in record.Methods.Where(m=>m.Signature?.ReturnType.FullName=="System.Boolean" && m.CilMethodBody!=null)) {
            var ins=getter.CilMethodBody!.Instructions;
            for(int i=1;i<ins.Count;i++)if(ins[i].OpCode.Code==CilCode.And && ins[i-1].IsLdcI4())masks[getter]=ins[i-1].GetLdcI4Constant();
        }
        foreach(var method in runtime.Methods.Where(m=>m.CilMethodBody!=null)) {
            var ins=method.CilMethodBody!.Instructions;
            for(int i=0;i<ins.Count-1;i++) {
                if(ins[i].Operand is not MethodDefinition getter || !masks.TryGetValue(getter,out int mask))continue;
                if(ins[i+1].Operand is IMethodDescriptor helper && helper.Signature?.ReturnType.FullName=="System.Reflection.BindingFlags") {
                    var generic=masks.Where(p=>p.Key!=getter).Select(p=>p.Value).Distinct().ToArray();
                    if(generic.Length!=1)throw new NotSupportedException("Ambiguous VM generic flag.");
                    EazyDevirt.Logging.ConsoleLogger.Detail($"VM method flags: static={mask}, generic={generic[0]}");return(mask,generic[0]);
                }
            }
        }
        throw new NotSupportedException("Cannot discover VM static flag usage.");
    }
    internal static byte TokenTag(TypeDefinition runtime)
    {
        foreach(var parser in runtime.Methods.Where(m=>m.Parameters.Count==1 && m.Parameters[0].ParameterType.FullName=="System.Int32" && m.CilMethodBody!=null))
        {
            var record=parser.Signature?.ReturnType.ToTypeDefOrRef()?.Resolve();
            bool IsTag(AsmResolver.DotNet.Signatures.TypeSignature? type)=>type?.FullName=="System.Byte" ||
                type?.ToTypeDefOrRef()?.Resolve() is {IsEnum:true} tag && tag.Fields.Any(f=>!f.IsStatic && f.Signature?.FieldType.FullName=="System.Byte");
            if(record?.Fields.Count!=3 || !record.Fields.Any(f=>IsTag(f.Signature?.FieldType)) ||
                !record.Fields.Any(f=>f.Signature?.FieldType.FullName=="System.Int32"))continue;
            var ins=parser.CilMethodBody!.Instructions;
            for(int i=0;i<ins.Count-1;i++) {
                if(ins[i].Operand is not MethodDefinition getter || getter.DeclaringType!=record || !IsTag(getter.Signature?.ReturnType) || getter.Parameters.Count!=0)continue;
                int at=i+1;byte tag=0;
                if(ins[at].IsLdcI4()) {tag=checked((byte)ins[at].GetLdcI4Constant());at++;}
                if(ins[at].Operand is not ICilLabel target)continue;
                int fall=at+1,jump=ins.GetIndexByOffset(target.Offset);
                bool readsToken(int start) {
                    var seen=new HashSet<int>();
                    while(start>=0 && start<ins.Count && seen.Add(start)) {
                        var item=ins[start];
                        if(item.Operand is MethodDefinition setter && setter.DeclaringType==record && setter.Parameters.Count==1 && setter.Parameters[0].ParameterType.FullName=="System.Int32")return true;
                        if(item.OpCode.Code is CilCode.Br or CilCode.Br_S && item.Operand is ICilLabel label)start=ins.GetIndexByOffset(label.Offset);
                        else if(item.OpCode.FlowControl is CilFlowControl.ConditionalBranch or CilFlowControl.Return)break;
                        else start++;
                    }
                    return false;
                }
                byte? found=ins[at].OpCode.Code switch {
                    CilCode.Bne_Un or CilCode.Bne_Un_S when readsToken(fall) => tag,
                    CilCode.Beq or CilCode.Beq_S when readsToken(jump) => tag,
                    CilCode.Brtrue or CilCode.Brtrue_S when readsToken(fall) => (byte)0,
                    CilCode.Brfalse or CilCode.Brfalse_S when readsToken(jump) => (byte)0,
                    CilCode.Brtrue or CilCode.Brtrue_S when readsToken(jump) => (byte)1,
                    CilCode.Brfalse or CilCode.Brfalse_S when readsToken(fall) => (byte)1,
                    _ => null
                };
                if(found.HasValue) {EazyDevirt.Logging.ConsoleLogger.Detail("VM token tag: "+found.Value);return found.Value;}
            }
        }
        throw new NotSupportedException("Cannot derive VM metadata token discriminator.");
    }
    internal static Dictionary<int, CilOperandType> OperandTypes(TypeDefinition runtime)
    {
        // The discriminator can be widened to Int32 without changing the wire
        // format. Match the reader's behavior, not just its parameter width.
        var candidates = runtime.Methods.Where(m => m.Parameters.Count == 2 &&
            (m.Parameters[1].ParameterType.FullName is "System.Byte" or "System.Int32" ||
             m.Parameters[1].ParameterType.ToTypeDefOrRef()?.Resolve()?.IsEnum==true) &&
            m.Signature?.ReturnsValue == true && m.CilMethodBody?.Instructions.Any(i =>
                i.OpCode.Code == CilCode.Switch && i.Operand is IList<ICilLabel> labels && labels.Count>=10) == true);
        var layouts = new List<Dictionary<int, CilOperandType>>();
        foreach (var candidate in candidates)
        {
            var layout = ReadOperandTypes(candidate);
            if (layout != null) layouts.Add(layout);
        }
        if (layouts.Count != 1)
            throw new NotSupportedException(layouts.Count == 0
                ? "Cannot discover VM operand reader."
                : "Ambiguous VM operand reader.");
        var result = layouts[0];
        EazyDevirt.Logging.ConsoleLogger.Detail("VM operand layout: " + string.Join(", ", result.Select(p => p.Key + "=" + p.Value)));
        return result;
    }

    private static Dictionary<int, CilOperandType>? ReadOperandTypes(MethodDefinition parser)
    {
        var instructions = parser.CilMethodBody!.Instructions;
        var targets = (IList<ICilLabel>)instructions.First(i => i.OpCode.Code == CilCode.Switch &&
            i.Operand is IList<ICilLabel> labels && labels.Count>=10).Operand!;
        string readerType = parser.Parameters[0].ParameterType.FullName;
        var result = new Dictionary<int, CilOperandType>();
        for (int index = 0; index < targets.Count; index++)
        {
            var block = ReachableInstructions(instructions, targets[index]);
            var primitives = block.Select(i => i.Operand).OfType<IMethodDescriptor>().Where(m =>
                m.DeclaringType?.FullName == readerType && m.Signature?.ReturnsValue == true)
                .Select(m => m.Signature!.ReturnType.FullName).Distinct().ToArray();
            if (primitives.Length > 1) return null;
            string? primitive = primitives.SingleOrDefault();
            CilOperandType? kind = primitive switch {
                "System.Int32" => block.Any(i => i.OpCode.Code == CilCode.Newarr ||
                    i.Operand is IMethodDescriptor method && IsSwitchArray(method))
                    ? CilOperandType.InlineSwitch : CilOperandType.InlineI,
                "System.UInt32" => CilOperandType.InlineBrTarget,
                "System.UInt16" => CilOperandType.InlineVar,
                "System.Byte" => CilOperandType.ShortInlineVar,
                "System.SByte" => CilOperandType.ShortInlineI,
                "System.Int64" => CilOperandType.InlineI8,
                "System.Single" => CilOperandType.ShortInlineR,
                "System.Double" => CilOperandType.InlineR,
                null when block.Any(i => i.OpCode.Code == CilCode.Ldnull) => CilOperandType.InlineNone,
                _ => null
            };
            if (!kind.HasValue)
            {
                if(primitive==null && block.Any(i=>i.OpCode.Code==CilCode.Throw))continue;
                return null;
            }
            result[index] = kind.Value;
        }
        // Reject unrelated switch helpers rather than guessing a partial layout.
        return result.Values.Distinct().Count() == 10 ? result : null;
    }

    private static bool IsSwitchArray(IMethodDescriptor method)
    {
        if(method.Name!="ToArray" || method.Signature?.ReturnType is not AsmResolver.DotNet.Signatures.SzArrayTypeSignature ||
            method.DeclaringType?.FullName.StartsWith("System.Collections.Generic.List`1<",StringComparison.Ordinal)!=true ||
            method.DeclaringType.ToTypeSignature() is not AsmResolver.DotNet.Signatures.GenericInstanceTypeSignature {TypeArguments.Count:1} list)return false;
        var item=list.TypeArguments[0];
        if(item.FullName=="System.Int32")return true;
        var element=item.ToTypeDefOrRef()?.Resolve();
        return element?.Fields.Count(f=>!f.IsStatic)==1 && element.Fields.Any(f=>!f.IsStatic && f.Signature?.FieldType.FullName=="System.Int32");
    }

    private static List<CilInstruction> ReachableInstructions(CilInstructionCollection instructions, ICilLabel start)
    {
        var result = new List<CilInstruction>();
        var seen = new HashSet<int>();
        var pending = new Queue<int>();
        void Enqueue(ICilLabel label)
        {
            int index = instructions.GetIndexByOffset(label.Offset);
            if (index < 0) throw new InvalidDataException("Invalid VM reader branch.");
            pending.Enqueue(index);
        }
        Enqueue(start);
        while (pending.Count != 0)
        {
            int index = pending.Dequeue();
            if (index >= instructions.Count || !seen.Add(index)) continue;
            var instruction = instructions[index];
            result.Add(instruction);
            if (instruction.Operand is ICilLabel branch) Enqueue(branch);
            else if (instruction.Operand is IList<ICilLabel> labels)
                foreach (var label in labels) Enqueue(label);
            if (instruction.OpCode.FlowControl is not (CilFlowControl.Branch or CilFlowControl.Return or CilFlowControl.Throw))
                pending.Enqueue(index + 1);
        }
        return result;
    }

    internal static Dictionary<byte, VMInlineOperandType> InlineTypes(TypeDefinition runtime)
    {
        foreach (var parser in runtime.Methods.Where(m => m.Parameters.Count == 1 && m.CilMethodBody != null))
        {
            var instructions = parser.CilMethodBody!.Instructions;
            var dispatch = instructions.FirstOrDefault(i => i.OpCode.Code == CilCode.Switch &&
                i.Operand is IList<ICilLabel> labels && labels.Count == 5);
            if (dispatch == null) continue;
            var result = new Dictionary<byte, VMInlineOperandType>();
            var targets = (IList<ICilLabel>)dispatch.Operand!;
            VMTypeWireLayout? typeLayout = null;
            for (byte index = 0; index < targets.Count; index++)
            {
                var type = UntilReturn(instructions, targets[index]).Where(i => i.OpCode.Code == CilCode.Newobj)
                    .Select(i => i.Operand).OfType<IMethodDescriptor>().FirstOrDefault()?.DeclaringType?.Resolve();
                if (type == null) break;
                var fields = type.Fields.Where(f => !f.IsStatic).Select(f => f.Signature!.FieldType.FullName).ToArray();
                VMInlineOperandType? kind = fields.Length == 2 && fields.All(f => f == "System.Int32") ? VMInlineOperandType.EazCall
                    : fields.Length == 1 && fields[0] == "System.String" ? VMInlineOperandType.UserString
                    : (fields.Contains("System.Byte") && fields.Contains("System.String") ||
                        fields.Length==7 && fields.Count(f=>f=="System.Boolean")==2 && fields.Count(f=>f.EndsWith("[]"))==2) ? VMInlineOperandType.Method
                    : fields.Count(f => f == "System.Boolean") == 2 && fields.Contains("System.String") ? VMInlineOperandType.Type
                    : fields.Count(f => f == "System.Boolean") == 1 && fields.Contains("System.String") ? VMInlineOperandType.Field : null;
                if (!kind.HasValue) break;
                result[index] = kind.Value;
                if (kind == VMInlineOperandType.Type)
                    typeLayout = VMTypeWireLayout.Discover(runtime, type, UntilReturn(instructions, targets[index]));
            }
            if (result.Count == 5 && result.Values.Distinct().Count() == 5)
            {
                EazyDevirt.Devirtualization.DevirtualizationContext.Instance.TypeOperandLayout = typeLayout!;
                EazyDevirt.Logging.ConsoleLogger.Detail("VM inline layout: " + string.Join(", ", result.Select(p => p.Key + "=" + p.Value)));
                return result;
            }
        }
        throw new NotSupportedException("Cannot derive VM inline operand tags.");
    }

    private static List<CilInstruction> UntilReturn(CilInstructionCollection instructions, ICilLabel label)
    {
        var result = new List<CilInstruction>();
        int start = instructions.GetIndexByOffset(label.Offset);
        if (start < 0) throw new InvalidDataException("Invalid VM reader branch.");
        for (int i = start; i < instructions.Count; i++) {
            result.Add(instructions[i]);
            if (instructions[i].OpCode.Code == CilCode.Ret) break;
        }
        return result;
    }
}
