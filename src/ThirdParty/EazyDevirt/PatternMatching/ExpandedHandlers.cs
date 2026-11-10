using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Architecture;
using EazyDevirt.Devirtualization;
using EazyDevirt.PatternMatching.Patterns;
using EazyDevirt.PatternMatching.Patterns.OpCodes;

namespace EazyDevirt.PatternMatching;

/// <summary>Recognizes small handlers whose stack helper has been inlined.</summary>
internal static class ExpandedHandlers
{
    internal static CilOpCode? Identify(VMOpCode opcode)
    {
        var method = opcode.SerializedDelegateMethod;
        var ins = PatternMatcher.StraightLinePrefix(method);
        if (Newobj.IsObjectCreation(method)) return CilOpCodes.Newobj;
        bool Push(int at) => ins[at].Operand is MethodDefinition helper &&
            PatternMatcher.MatchesPattern(new PushStackPattern(), helper);
        bool Clone(int at) => ins[at].Operand is IMethodDescriptor helper && helper.Signature is { HasThis: true, ParameterTypes.Count: 0 } &&
            helper.Signature.ReturnType.FullName == helper.DeclaringType?.FullName;
        var ctx = DevirtualizationContext.Instance;
        bool Pop(int at) => ins[at].Operand is MethodDefinition helper && PatternMatcher.MatchesPattern(new PopStackPattern(), helper);
        if(ins.Count==17 && ins[0].OpCode.Code==CilCode.Ldarg_1 && ins[1].OpCode.Code==CilCode.Castclass &&
            ins[2].IsStloc() && ins[3].OpCode.Code==CilCode.Ldarg_0 && ins[4].IsLdloc() &&
            ins[2].GetLocalVariableIndex()==ins[4].GetLocalVariableIndex() &&
            ins[5].Operand is IMethodDescriptor methodPosition && methodPosition.Signature?.ReturnType.FullName=="System.Int32" &&
            ins[6].Operand is IMethodDescriptor methodResolver && methodResolver.Signature?.ReturnType.FullName=="System.Reflection.MethodBase" &&
            methodResolver.Signature.ParameterTypes.Count==1 && methodResolver.Signature.ParameterTypes[0].FullName=="System.Int32" &&
            ins[7].IsStloc() && ins[8].OpCode.Code==CilCode.Ldarg_0 && ins[9].OpCode.Code==CilCode.Newobj &&
            ins[9].Operand is IMethodDescriptor pointerCtor && pointerCtor.Signature?.ParameterTypes.Count==0 &&
            ins[10].IsStloc() && ins[11].IsLdloc() && ins[12].IsLdloc() && ins[14].IsLdloc() &&
            ins[10].GetLocalVariableIndex()==ins[11].GetLocalVariableIndex() &&
            ins[10].GetLocalVariableIndex()==ins[14].GetLocalVariableIndex() &&
            ins[7].GetLocalVariableIndex()==ins[12].GetLocalVariableIndex() &&
            ins[13].Operand is IMethodDescriptor pointerSetter && pointerSetter.DeclaringType==pointerCtor.DeclaringType &&
            pointerSetter.Signature?.ReturnType.FullName=="System.Void" && pointerSetter.Signature.ParameterTypes.Count==1 &&
            pointerSetter.Signature.ParameterTypes[0].FullName=="System.Reflection.MethodBase" &&
            Push(15) && ins[16].OpCode.Code==CilCode.Ret)return CilOpCodes.Ldftn;
        if(ins.Count==9 && opcode.CilOperandType==CilOperandType.InlineNone &&
            ins[0].OpCode.Code==CilCode.Ldarg_0 && ins[1].Operand is MethodDefinition constantCtor &&
            ins[1].OpCode.Code==CilCode.Newobj && constantCtor.Name==".ctor" && constantCtor.Parameters.Count==0 &&
            ins[2].IsStloc() && ins[3].IsLdloc() && ins[4].IsLdcI4() &&
            ins[6].IsLdloc() && ins[2].GetLocalVariableIndex()==ins[3].GetLocalVariableIndex() &&
            ins[2].GetLocalVariableIndex()==ins[6].GetLocalVariableIndex() &&
            ins[5].Operand is MethodDefinition constantSetter && constantSetter.DeclaringType==constantCtor.DeclaringType &&
            constantSetter.Signature?.ReturnType.FullName=="System.Void" && constantSetter.Parameters.Count==1 &&
            constantSetter.Parameters[0].ParameterType.FullName=="System.Int32" &&
            constantCtor.DeclaringType!.Fields.Count(f=>!f.IsStatic)==1 &&
            constantCtor.DeclaringType.Fields.Single(f=>!f.IsStatic).Signature?.FieldType.FullName=="System.Int32" &&
            Push(7) && ins[8].OpCode.Code==CilCode.Ret)
        {
            int value=ins[4].GetLdcI4Constant();
            if(value>=-1 && value<=8)return new[]{CilOpCodes.Ldc_I4_M1,CilOpCodes.Ldc_I4_0,CilOpCodes.Ldc_I4_1,
                CilOpCodes.Ldc_I4_2,CilOpCodes.Ldc_I4_3,CilOpCodes.Ldc_I4_4,CilOpCodes.Ldc_I4_5,CilOpCodes.Ldc_I4_6,
                CilOpCodes.Ldc_I4_7,CilOpCodes.Ldc_I4_8}[value+1];
        }
        if(ins.Count==15 && ins[0].OpCode.Code==CilCode.Ldarg_0 && Pop(1) &&
            ins[2].Operand is IMethodDescriptor arrayValue && arrayValue.Signature?.ReturnType.FullName=="System.Object" &&
            ins[3].OpCode.Code==CilCode.Castclass && ins[3].Operand is ITypeDefOrRef arrayType && arrayType.FullName=="System.Array" &&
            ins[4].IsStloc() && ins[5].OpCode.Code==CilCode.Ldarg_0 && ins[6].OpCode.Code==CilCode.Newobj &&
            ins[6].Operand is IMethodDescriptor lengthCtor && lengthCtor.Signature?.ParameterTypes.Count==0 &&
            ins[7].IsStloc() && ins[8].IsLdloc() && ins[9].IsLdloc() && ins[12].IsLdloc() &&
            ins[7].GetLocalVariableIndex()==ins[8].GetLocalVariableIndex() &&
            ins[7].GetLocalVariableIndex()==ins[12].GetLocalVariableIndex() &&
            ins[4].GetLocalVariableIndex()==ins[9].GetLocalVariableIndex() &&
            ins[10].Operand is IMethodDescriptor arrayLength && arrayLength.FullName=="System.Int32 System.Array::get_Length()" &&
            ins[11].Operand is IMethodDescriptor lengthSetter && lengthSetter.DeclaringType==lengthCtor.DeclaringType &&
            lengthSetter.Signature?.ReturnType.FullName=="System.Void" && lengthSetter.Signature.ParameterTypes.Count==1 &&
            lengthSetter.Signature.ParameterTypes[0].FullName=="System.Int32" && Push(13) && ins[14].OpCode.Code==CilCode.Ret)
            return CilOpCodes.Ldlen;
        if (ins.Count==13 && ins[0].OpCode.Code==CilCode.Ldarg_0 && Pop(1) &&
            ins[2].Operand is IMethodDescriptor unboxValue && unboxValue.Signature?.ReturnType.FullName=="System.Object" &&
            ins[3].OpCode.Code==CilCode.Castclass && ins[3].Operand is ITypeDefOrRef array && array.FullName=="System.Array" &&
            ins[4].IsStloc() && ins[5].OpCode.Code==CilCode.Ldarg_0 && ins[6].OpCode.Code==CilCode.Newobj &&
            ins[7].OpCode.Code==CilCode.Dup && ins[8].IsLdloc() &&
            ins[4].GetLocalVariableIndex()==ins[8].GetLocalVariableIndex() &&
            ins[9].Operand is IMethodDescriptor length && length.FullName=="System.Int32 System.Array::get_Length()" &&
            ins[10].Operand is IMethodDescriptor setLength && setLength.Signature?.ParameterTypes.Count==1 &&
            setLength.Signature.ParameterTypes[0].FullName=="System.Int32" && Push(11) && ins[12].OpCode.Code==CilCode.Ret)
            return CilOpCodes.Ldlen;
        if (ins.Count is 13 or 14 or 15 && ins[0].OpCode.Code==CilCode.Ldarg_0 && Pop(1) && ins[2].IsStloc() &&
            ins[3].OpCode.Code==CilCode.Ldarg_0 && Pop(4) && ins[5].IsStloc() &&
            ins[6].OpCode.Code==CilCode.Ldarg_0 && ins[7].OpCode.Code==CilCode.Ldarg_0 &&
            ins[8].IsLdloc() && ins[9].IsLdloc() && ins[2].GetLocalVariableIndex()==ins[9].GetLocalVariableIndex() &&
            ins[5].GetLocalVariableIndex()==ins[8].GetLocalVariableIndex() && (ins.Count==13 || ins[10].IsLdcI4()) &&
            (ins.Count!=15 || ins[11].IsLdcI4()) && Push(ins.Count-2) && ins[ins.Count-1].OpCode.Code==CilCode.Ret &&
            ins[ins.Count-3].Operand is MethodDefinition arithmetic && arithmetic.Signature?.HasThis==true)
        {
            bool check=ins.Count>=14 && ins[10].GetLdcI4Constant()!=0;
            bool unsigned=ins.Count==14 ? check : ins.Count==15 && ins[11].GetLdcI4Constant()!=0;
            if(ins.Count==15)
            {
                if(PatternMatcher.MatchesPattern(new AddOperandsPattern(),arithmetic)) return check ? unsigned ? CilOpCodes.Add_Ovf_Un : CilOpCodes.Add_Ovf : CilOpCodes.Add;
                if(PatternMatcher.MatchesPattern(new SubOperandsPattern(),arithmetic)) return check ? unsigned ? CilOpCodes.Sub_Ovf_Un : CilOpCodes.Sub_Ovf : CilOpCodes.Sub;
                if(PatternMatcher.MatchesPattern(new MulOperandsPattern(),arithmetic)) return check ? unsigned ? CilOpCodes.Mul_Ovf_Un : CilOpCodes.Mul_Ovf : CilOpCodes.Mul;
            }
            else
            {
                var body=arithmetic.CilMethodBody!.Instructions;
                var operations=new HashSet<CilCode>();
                for(int i=0;i+2<body.Count;i++)
                    if(body[i].OpCode.Code is CilCode.Div or CilCode.Rem or CilCode.Shr or CilCode.Shr_Un or CilCode.Shl or CilCode.And or CilCode.Or or CilCode.Xor &&
                        ((body[i+1].IsStloc() && ArithmeticResultPattern.Verify(body,i+1)) ||
                        (body[i+1].Operand is IMethodDescriptor resultSetter &&
                        resultSetter.Signature?.ReturnType.FullName=="System.Void" && resultSetter.Signature.ParameterTypes.Count==1 &&
                        resultSetter.Signature.ParameterTypes[0].FullName is "System.Int32" or "System.Int64" &&
                        body[i+2].OpCode.Code==CilCode.Ret) || StoredArithmeticResult(body,i)))
                        operations.Add(body[i].OpCode.Code==CilCode.Shr_Un ? CilCode.Shr : body[i].OpCode.Code);
                if(operations.Count==1) return operations.Single() switch {
                    CilCode.Div => unsigned ? CilOpCodes.Div_Un : CilOpCodes.Div,
                    CilCode.Rem => unsigned ? CilOpCodes.Rem_Un : CilOpCodes.Rem,
                    CilCode.Shr => unsigned ? CilOpCodes.Shr_Un : CilOpCodes.Shr,
                    CilCode.Shl => CilOpCodes.Shl,
                    CilCode.And => CilOpCodes.And,
                    CilCode.Or => CilOpCodes.Or,
                    CilCode.Xor => CilOpCodes.Xor,
                    _ => null
                };
            }
        }
        var bodyInstructions=method.CilMethodBody!.Instructions;
        var calls=bodyInstructions.Select(i=>i.Operand).OfType<MethodDefinition>().ToArray();
        int pops=calls.Count(m=>PatternMatcher.MatchesPattern(new PopStackPattern(),m));
        bool resolvesField=calls.Any(m=>m.Signature?.ReturnType.FullName=="System.Reflection.FieldInfo" && m.Parameters.Count==1);
        bool pushes=calls.Any(m=>PatternMatcher.MatchesPattern(new PushStackPattern(),m));
        if(ins.Count==3 && ins[0].OpCode.Code==CilCode.Ldarg_0 && ins[1].Operand is MethodDefinition indirect &&
            ins[2].OpCode.Code==CilCode.Ret)
        {
            var trace=PatternMatcher.StraightLinePrefix(indirect);
            if(trace.Count==11 && trace[0].OpCode.Code==CilCode.Ldarg_0 &&
                trace[1].Operand is MethodDefinition p1 && PatternMatcher.MatchesPattern(new PopStackPattern(),p1) &&
                trace[2].IsStloc() && trace[3].OpCode.Code==CilCode.Ldarg_0 &&
                trace[4].Operand is MethodDefinition p2 && PatternMatcher.MatchesPattern(new PopStackPattern(),p2) &&
                trace[5].IsStloc() && trace[6].OpCode.Code==CilCode.Ldarg_0 && trace[7].IsLdloc() && trace[8].IsLdloc() &&
                trace[5].GetLocalVariableIndex()==trace[7].GetLocalVariableIndex() &&
                trace[2].GetLocalVariableIndex()==trace[8].GetLocalVariableIndex() &&
                trace[9].Operand is MethodDefinition write && write.Signature?.ReturnType.FullName=="System.Void" &&
                write.Parameters.Count==2 && write.CilMethodBody?.Instructions.Any(x=>x.OpCode.Code==CilCode.Ldfld && x.Operand==ctx.VMLocalsField)==true &&
                write.CilMethodBody.Instructions.Any(x=>x.Operand is IMethodDescriptor set && set.FullName==
                    "System.Void System.Reflection.FieldInfo::SetValue(System.Object, System.Object)"))
                return opcode.CilOperandType==CilOperandType.InlineI ? CilOpCodes.Stobj : CilOpCodes.Stind_I;
        }
        string? indirectType=null;
        if(ins.Count==5 && ins[1].OpCode.Code==CilCode.Ldtoken && ins[1].Operand is ITypeDefOrRef elementType &&
            ins[2].Operand is IMethodDescriptor getType && getType.Name=="GetTypeFromHandle") indirectType=elementType.FullName;
        if(ins.Count==4 && ins[1].OpCode.Code==CilCode.Ldsfld && ins[1].Operand is FieldDefinition typeField)
        {
            var init=typeField.DeclaringType?.Methods.FirstOrDefault(m=>m.Name==".cctor")?.CilMethodBody?.Instructions;
            if(init!=null)for(int i=2;i<init.Count;i++)
                if(init[i].OpCode.Code==CilCode.Stsfld && init[i].Operand==typeField &&
                    init[i-2].OpCode.Code==CilCode.Ldtoken && init[i-2].Operand is ITypeDefOrRef valueType &&
                    init[i-1].Operand is IMethodDescriptor handle && handle.Name=="GetTypeFromHandle") indirectType=valueType.FullName;
        }
        if(indirectType!=null && ins[0].OpCode.Code==CilCode.Ldarg_0 && ins[ins.Count-2].Operand is MethodDefinition load &&
            ins[ins.Count-1].OpCode.Code==CilCode.Ret)
        {
            var trace=PatternMatcher.StraightLinePrefix(load);
            if(trace.Count==12 && trace[1].Operand is MethodDefinition p && PatternMatcher.MatchesPattern(new PopStackPattern(),p) &&
                trace[2].IsStloc() && trace[5].IsLdloc() && trace[2].GetLocalVariableIndex()==trace[5].GetLocalVariableIndex() &&
                trace[7].Operand is IMethodDescriptor getValue && getValue.Signature?.ReturnType.FullName=="System.Object" &&
                trace[8].OpCode.Code==CilCode.Ldarg_1 && trace[9].Operand is IMethodDescriptor convert &&
                convert.Signature?.ParameterTypes.Count==2 && convert.Signature.ParameterTypes[0].FullName=="System.Object" &&
                convert.Signature.ParameterTypes[1].FullName=="System.Type" && trace[10].Operand is MethodDefinition push &&
                PatternMatcher.MatchesPattern(new PushStackPattern(),push))
                return indirectType switch {
                    "System.SByte"=>CilOpCodes.Ldind_I1, "System.Byte"=>CilOpCodes.Ldind_U1,
                    "System.Int16"=>CilOpCodes.Ldind_I2,"System.UInt16"=>CilOpCodes.Ldind_U2,
                    "System.Int32"=>CilOpCodes.Ldind_I4,"System.UInt32"=>CilOpCodes.Ldind_U4,
                    "System.Int64"=>CilOpCodes.Ldind_I8,"System.Single"=>CilOpCodes.Ldind_R4,
                    "System.Double"=>CilOpCodes.Ldind_R8,"System.Object"=>CilOpCodes.Ldind_Ref,_=>null
                };
        }
        if(ins.Count==15 && ins[0].OpCode.Code==CilCode.Ldarg_1 && ins[1].OpCode.Code==CilCode.Castclass && ins[2].IsStloc() &&
            ins[3].OpCode.Code==CilCode.Ldarg_0 && Pop(4) && ins[5].IsStloc() && ins[6].OpCode.Code==CilCode.Ldarg_0 &&
            ins[7].OpCode.Code==CilCode.Ldfld && ins[8].IsLdloc() &&
            ins[2].GetLocalVariableIndex()==ins[8].GetLocalVariableIndex() && ins[9].Operand is IMethodDescriptor slot &&
            slot.Signature?.ReturnType.FullName is "System.Byte" or "System.UInt16" && ins[10].OpCode.Code==CilCode.Ldelem &&
            ins[11].IsLdloc() && ins[5].GetLocalVariableIndex()==ins[11].GetLocalVariableIndex() &&
            ins[12].Operand is IMethodDescriptor assign && assign.Signature?.ParameterTypes.Count==1 &&
            assign.Signature.ReturnType.FullName==assign.DeclaringType?.FullName && ins[13].OpCode.Code==CilCode.Pop &&
            ins[14].OpCode.Code==CilCode.Ret)
        {
            if(ins[7].Operand==ctx.VMLocalsField) return slot.Signature.ReturnType.FullName=="System.Byte" ? CilOpCodes.Stloc_S : CilOpCodes.Stloc;
            if(ins[7].Operand==ctx.VMArgumentsField) return slot.Signature.ReturnType.FullName=="System.Byte" ? CilOpCodes.Starg_S : CilOpCodes.Starg;
        }
        if(resolvesField && bodyInstructions.Any(i=>i.Operand is IMethodDescriptor set &&
            set.FullName=="System.Void System.Reflection.FieldInfo::SetValue(System.Object, System.Object)"))
        {
            if(pops==2) return CilOpCodes.Stfld;
            if(pops==1) return CilOpCodes.Stsfld;
        }
        if(resolvesField && pushes && pops<=1 && bodyInstructions.Where(i=>i.OpCode.Code==CilCode.Newobj)
            .Select(i=>i.Operand).OfType<IMethodDescriptor>().Any(c=>c.DeclaringType?.Resolve() is { } t &&
                t.Fields.Count(f=>!f.IsStatic)==2 && t.Fields.Any(f=>f.Signature?.FieldType.FullName=="System.Reflection.FieldInfo") &&
                t.Fields.Any(f=>f.Signature?.FieldType.FullName=="System.Object")))
            return pops==0 ? CilOpCodes.Ldsflda : CilOpCodes.Ldflda;
        if(ins.Count==11 && ins[0].OpCode.Code==CilCode.Ldarg_1 && ins[1].OpCode.Code==CilCode.Castclass &&
            ins[2].IsStloc() && ins[3].OpCode.Code==CilCode.Ldarg_0 && ins[4].OpCode.Code==CilCode.Newobj &&
            ins[4].Operand is IMethodDescriptor addressCtor && ins[5].OpCode.Code==CilCode.Dup && ins[6].IsLdloc() &&
            ins[2].GetLocalVariableIndex()==ins[6].GetLocalVariableIndex() &&
            ins[7].Operand is IMethodDescriptor indexGetter && indexGetter.Signature?.ReturnType.FullName is "System.Byte" or "System.UInt16" &&
            ins[8].Operand is MethodDefinition setIndex && setIndex.Parameters.Count==1 &&
            setIndex.Parameters[0].ParameterType.FullName=="System.Int32" &&
            setIndex.DeclaringType==addressCtor.DeclaringType && Push(9) && ins[10].OpCode.Code==CilCode.Ret &&
            LocalAddress(ctx,addressCtor.DeclaringType!.Resolve()!))
            return indexGetter.Signature.ReturnType.FullName=="System.Byte" ? CilOpCodes.Ldloca_S : CilOpCodes.Ldloca;
        if(ins.Count==13 && ins[0].OpCode.Code==CilCode.Ldarg_1 && ins[1].OpCode.Code==CilCode.Castclass && ins[2].IsStloc() &&
            ins[3].OpCode.Code==CilCode.Ldarg_0 && ins[4].OpCode.Code==CilCode.Ldfld && ins[5].IsLdloc() &&
            ins[2].GetLocalVariableIndex()==ins[5].GetLocalVariableIndex() && ins[6].Operand is IMethodDescriptor slotGetter &&
            slotGetter.Signature?.ReturnType.FullName is "System.Byte" or "System.UInt16" && ins[7].OpCode.Code==CilCode.Ldelem &&
            ins[8].OpCode.Code==CilCode.Ldarg_0 && Pop(9) && ins[10].Operand is IMethodDescriptor copy &&
            copy.Signature?.ParameterTypes.Count==1 && copy.Signature.ReturnType.FullName==copy.DeclaringType?.FullName &&
            ins[11].OpCode.Code==CilCode.Pop && ins[12].OpCode.Code==CilCode.Ret)
        {
            if(ins[4].Operand==ctx.VMLocalsField) return slotGetter.Signature.ReturnType.FullName=="System.Byte" ? CilOpCodes.Stloc_S : CilOpCodes.Stloc;
            if(ins[4].Operand==ctx.VMArgumentsField) return slotGetter.Signature.ReturnType.FullName=="System.Byte" ? CilOpCodes.Starg_S : CilOpCodes.Starg;
        }
        if (PatternMatcher.MatchesPattern(new CallvirtInnerPattern(), method)) return CilOpCodes.Callvirt;
        if (ins.Count == 13 && ins[0].OpCode.Code == CilCode.Ldarg_0 &&
            ins[1].Operand is MethodDefinition pop && PatternMatcher.MatchesPattern(new PopStackPattern(), pop) &&
            ins[2].IsStloc() && ins[3].IsLdloc() && Clone(4) && ins[5].IsStloc() &&
            ins[6].OpCode.Code == CilCode.Ldarg_0 && ins[7].IsLdloc() && Push(8) &&
            ins[9].OpCode.Code == CilCode.Ldarg_0 && ins[10].IsLdloc() && Push(11) && ins[12].OpCode.Code == CilCode.Ret &&
            ins[2].GetLocalVariableIndex()==ins[3].GetLocalVariableIndex() &&
            ins[2].GetLocalVariableIndex()==ins[7].GetLocalVariableIndex() &&
            ins[5].GetLocalVariableIndex()==ins[10].GetLocalVariableIndex()) return CilOpCodes.Dup;
        if (ins.Count == 8 && ins[0].OpCode.Code == CilCode.Ldarg_0 && ins[1].OpCode.Code == CilCode.Ldarg_0 &&
            ins[2].OpCode.Code == CilCode.Ldfld && ins[3].IsLdcI4() && ins[4].OpCode.Code == CilCode.Ldelem &&
            Clone(5) && Push(6) && ins[7].OpCode.Code == CilCode.Ret)
        {
            int index = ins[3].GetLdcI4Constant();
            if (index < 0 || index > 3) return null;
            if (ins[2].Operand == ctx.VMLocalsField)
                return new[] { CilOpCodes.Ldloc_0, CilOpCodes.Ldloc_1, CilOpCodes.Ldloc_2, CilOpCodes.Ldloc_3 }[index];
            if (ins[2].Operand == ctx.VMArgumentsField)
                return new[] { CilOpCodes.Ldarg_0, CilOpCodes.Ldarg_1, CilOpCodes.Ldarg_2, CilOpCodes.Ldarg_3 }[index];
        }
        if (ins.Count == 12 && ins[0].OpCode.Code == CilCode.Ldarg_1 && ins[1].OpCode.Code == CilCode.Castclass &&
            ins[2].IsStloc() && ins[3].OpCode.Code == CilCode.Ldarg_0 && ins[4].OpCode.Code == CilCode.Ldarg_0 &&
            ins[5].OpCode.Code == CilCode.Ldfld && ins[6].IsLdloc() &&
            ins[2].GetLocalVariableIndex() == ins[6].GetLocalVariableIndex() &&
            ins[7].Operand is IMethodDescriptor getter && getter.Signature?.ParameterTypes.Count == 0 &&
            ins[8].OpCode.Code == CilCode.Ldelem && Clone(9) && Push(10) && ins[11].OpCode.Code == CilCode.Ret)
        {
            bool wide = getter.Signature.ReturnType.FullName == "System.UInt16";
            if (!wide && getter.Signature.ReturnType.FullName != "System.Byte") return null;
            if (ins[5].Operand == ctx.VMLocalsField) return wide ? CilOpCodes.Ldloc : CilOpCodes.Ldloc_S;
            if (ins[5].Operand == ctx.VMArgumentsField) return wide ? CilOpCodes.Ldarg : CilOpCodes.Ldarg_S;
        }
        if (ins.Count == 7 && ins[0].OpCode.Code == CilCode.Ldarg_0 && ins[1].OpCode.Code == CilCode.Newobj &&
            ins[2].OpCode.Code == CilCode.Dup && ins[3].IsLdcI4() &&
            ins[4].Operand is MethodDefinition setter && setter.Signature?.ReturnType.FullName == "System.Void" &&
            setter.Parameters.Count == 1 && setter.Parameters[0].ParameterType.FullName == "System.Int32" &&
            setter.DeclaringType?.Fields.Count(f=>!f.IsStatic) == 1 &&
            setter.DeclaringType.Fields.Single(f=>!f.IsStatic).Signature?.FieldType.FullName == "System.Int32" &&
            ins[1].Operand is IMethodDescriptor ctor && ctor.DeclaringType == setter.DeclaringType &&
            Push(5) && ins[6].OpCode.Code == CilCode.Ret)
        {
            int value = ins[3].GetLdcI4Constant();
            if (value >= -1 && value <= 8)
                return new[] { CilOpCodes.Ldc_I4_M1, CilOpCodes.Ldc_I4_0, CilOpCodes.Ldc_I4_1, CilOpCodes.Ldc_I4_2,
                    CilOpCodes.Ldc_I4_3, CilOpCodes.Ldc_I4_4, CilOpCodes.Ldc_I4_5, CilOpCodes.Ldc_I4_6,
                    CilOpCodes.Ldc_I4_7, CilOpCodes.Ldc_I4_8 }[value + 1];
        }
        return null;
    }

    private static bool StoredArithmeticResult(CilInstructionCollection instructions,int operation)
    {
        if(operation+3>=instructions.Count || instructions[operation+1].Operand is not IMethodDescriptor setter ||
            setter.Signature?.ReturnType.FullName!="System.Void" || setter.Signature.ParameterTypes.Count!=1 ||
            setter.Signature.ParameterTypes[0].FullName is not ("System.Int32" or "System.Int64") ||
            !instructions[operation+2].IsLdloc() || instructions[operation+3].OpCode.Code!=CilCode.Ret)return false;
        int result=instructions[operation+2].GetLocalVariableIndex();
        for(int start=Math.Max(0,operation-6);start+4<operation;start++)
        {
            if(instructions[start].OpCode.Code!=CilCode.Newobj || instructions[start].Operand is not IMethodDescriptor ctor ||
                ctor.Signature?.ParameterTypes.Count!=0 || ctor.DeclaringType!=setter.DeclaringType ||
                !instructions[start+1].IsStloc() || !instructions[start+2].IsLdloc() ||
                instructions[start+1].GetLocalVariableIndex()!=result || instructions[start+2].GetLocalVariableIndex()!=result)continue;
            var operands=instructions.Skip(start+3).Take(operation-start-3).ToArray();
            if(operands.Count(i=>i.IsLdloc())==2 && operands.All(i=>i.IsLdloc() ||
                i.OpCode.Code is CilCode.Conv_I8 or CilCode.Conv_U8))return true;
        }
        return false;
    }

    private static bool LocalAddress(DevirtualizationContext ctx,TypeDefinition wrapper)
    {
        foreach(var helper in ctx.VMDeclaringType.Methods.Where(m=>m.CilMethodBody!=null))
        {
            var ins=helper.CilMethodBody!.Instructions;
            for(int i=0;i<ins.Count;i++)
            {
                if(ins[i].OpCode.Code!=CilCode.Ldfld || ins[i].Operand!=ctx.VMLocalsField)continue;
                var segment=ins.Skip(i+1).Take(8).TakeWhile(x=>x.OpCode.FlowControl is not
                    (CilFlowControl.Branch or CilFlowControl.ConditionalBranch or CilFlowControl.Return)).ToArray();
                if(segment.Any(x=>x.OpCode.Code==CilCode.Castclass && x.Operand==wrapper) &&
                    segment.Any(x=>x.OpCode.Code==CilCode.Ldelem))return true;
            }
        }
        return false;
    }
}
