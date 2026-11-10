using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions;
using EazyDevirt.Core.Architecture;
using EazyDevirt.PatternMatching;
using EazyDevirt.PatternMatching.Patterns;
using EazyDevirt.PatternMatching.Patterns.OpCodes;

// ReSharper disable ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract

namespace EazyDevirt.Devirtualization.Pipeline;

internal class OpCodeMapping : StageBase
{
    private protected override bool Init()
    {
        var executeVMMethodPattern = new ExecuteVMMethodPattern();
        var executeVMMethodWithoutFlagPattern = new ExecuteVMMethodWithoutTypeFlagPattern();
        var executeVMMethod =
            Ctx.VMDeclaringType.Methods.FirstOrDefault(method =>
                PatternMatcher.GetAllMatchingInstructions(executeVMMethodPattern, method).Count >= 1 ||
                PatternMatcher.GetAllMatchingInstructions(executeVMMethodWithoutFlagPattern, method).Count >= 1);
        
        if (executeVMMethod == null)
        {
            Ctx.Console.Error("Failed to find ExecuteVMMethod method!");
            return false;
        }

        Ctx.VMExecuteVMMethod = executeVMMethod;

        Ctx.VMTypeFields = new Dictionary<FieldDefinition, ITypeDefOrRef>();
        var cctor = Ctx.VMDeclaringType.Methods.FirstOrDefault(x => x.Name == ".cctor");
        if (cctor == null || cctor.CilMethodBody?.Instructions.Count <= 0)
        {
            Ctx.Console.Error("Failed to find VM declaring type cctor method!");
            return false;
        }

        var subs = PatternMatcher.GetAllMatchingInstructions(new TypeFieldPattern(), cctor);
        foreach (var sub in subs)
        {
            if (sub[0].Operand is not ITypeDefOrRef typeDefOrRef)
                continue;
            
            if (sub[2].Operand is not FieldDefinition fieldDef)
                continue;

            if (Ctx.VMTypeFields.ContainsKey(fieldDef))
            {
                if (Ctx.Options.VeryVeryVerbose)
                    Ctx.Console.Warning($"Overwriting {fieldDef.Name} type {Ctx.VMTypeFields[fieldDef].Name} with new type {typeDefOrRef.Name}");
                Ctx.VMTypeFields[fieldDef] = typeDefOrRef;
            }
            else
                Ctx.VMTypeFields.Add(fieldDef, typeDefOrRef);
        }
        if (Ctx.Options.VeryVerbose)
            Ctx.Console.InfoStr("Type fields found in VM declaring type", Ctx.VMTypeFields.Count);

        var argumentFieldMatches =
            PatternMatcher.GetAllMatchingInstructions(new ArgumentFieldPattern(), executeVMMethod);
        if (argumentFieldMatches.Count <= 0)
        {
            Ctx.Console.Error("Failed to find VM Arguments field!");
            return false;
        }

        if (argumentFieldMatches.First()[1].Operand is not SerializedFieldDefinition argumentField)
        {
            Ctx.Console.Error("VM Arguments field is not correct!");
            return false;
        }

        Ctx.VMArgumentsField = argumentField;

        var localField = Ctx.VMDeclaringType.Fields.FirstOrDefault(field =>
            field != argumentField &&
            field.Signature!.FieldType.FullName == argumentField.Signature!.FieldType.FullName);
        
        if (localField == null)
        {
            Ctx.Console.Error("Failed to find VM Locals field!");
            return false;
        }
        
        Ctx.VMLocalsField = localField;
        return true;
    }

    public override bool Run()
    {
        using var normalization = new RuntimePatternNormalization(Ctx.VMDeclaringType);
        if (!Init()) return false;
        Ctx.PositionOrCipher=VMFormatDiscovery.PositionOrCipher(Ctx.VMDeclaringType);
        Ctx.StandardMetadataReader=Ctx.VMDeclaringType.Methods.Where(MethodDiscovery.IsLoadVMPositionMethod)
            .Any(m=>m.CilMethodBody!.Instructions.Zip(m.CilMethodBody.Instructions.Skip(1),(first,second)=>(first,second))
                .Any(p=>p.first.OpCode.Code==CilCode.Newobj && p.first.Operand is IMethodDescriptor constructor &&
                    constructor.DeclaringType?.FullName=="System.IO.BinaryReader" && p.second.OpCode.Code==CilCode.Stfld &&
                    p.second.Operand is FieldDefinition field && field.DeclaringType==Ctx.VMDeclaringType &&
                    field.Signature?.FieldType.FullName=="System.IO.BinaryReader" &&
                    m.CilMethodBody.Instructions.Zip(m.CilMethodBody.Instructions.Skip(1),(load,call)=>(load,call)).Any(use=>
                        use.load.OpCode.Code==CilCode.Ldfld && use.load.Operand==field && use.call.Operand is MethodDefinition parser &&
                        parser.Parameters.Count==1 && parser.Parameters[0].ParameterType.FullName=="System.IO.BinaryReader" &&
                        parser.Signature?.ReturnsValue==true)));
        Ctx.OperandLayout = VMFormatDiscovery.OperandTypes(Ctx.VMDeclaringType);
        Ctx.InlineLayout = VMFormatDiscovery.InlineTypes(Ctx.VMDeclaringType);
        Ctx.TokenTag = VMFormatDiscovery.TokenTag(Ctx.VMDeclaringType);
        var flags=VMFormatDiscovery.MethodFlags(Ctx.VMDeclaringType);
        Ctx.MethodStaticMask=flags.Static;Ctx.MethodGenericMask=flags.Generic;

        var dictMethod = FindOpCodeMethod();
        if (dictMethod == null)
        {
            Ctx.Console.Error("Unable to find vm opcode dictionary method.");
            return false;
        }

        if (Ctx.Options.VeryVerbose)
            Ctx.Console.InfoStr("VM opcode dictionary method", dictMethod.MetadataToken);

        var vmOpCodes = new List<VMOpCode>();
        TypeDefinition containerType = null!;
        var dictionaryInstructions=dictMethod.CilMethodBody!.Instructions;
        int start=0;
        for(int i=0;i<dictionaryInstructions.Count;i++)
        {
            if(dictionaryInstructions[i].Operand is not IMethodDescriptor add || add.Name!="Add" ||
                !add.DeclaringType!.FullName.StartsWith("System.Collections.Generic.Dictionary"))continue;
            var segment=dictionaryInstructions.Skip(start).Take(i-start).ToArray();start=i+1;
            var handler=segment.Where(x=>x.OpCode.Code==CilCode.Ldftn).Select(x=>x.Operand).OfType<SerializedMethodDefinition>().LastOrDefault();
            // Instance dictionaries also load the runtime's container field.
            // Only the fields holding the opcode record belong in this map.
            var record = segment.Where(x=>x.OpCode.Code==CilCode.Newobj).Select(x=>x.Operand)
                .OfType<IMethodDescriptor>().LastOrDefault()?.Signature?.ParameterTypes.FirstOrDefault()?.FullName;
            var fields=segment.Where(x=>x.OpCode.Code==CilCode.Ldfld).Select(x=>x.Operand)
                .OfType<SerializedFieldDefinition>().Where(f=>f.Signature?.FieldType.FullName==record).Distinct().ToArray();
            if(fields.Length==0 || handler==null)continue;
            containerType ??=fields[0].DeclaringType!;
            foreach(var field in fields)vmOpCodes.Add(new VMOpCode(field,handler));
        }
        
        if (Ctx.Options.VeryVerbose)
            Ctx.Console.InfoStr("VM opcodes with handlers", vmOpCodes.Count);

        if (containerType == null)
        {
            Ctx.Console.Error("VM opcode container type is null.");
            return false;
        }

        var containerCtorPattern = new OpCodeCtorPattern();
        var containerCtor = containerType.Methods.First(m => m.Name == ".ctor");
        if (!containerCtor.HasMethodBody || containerCtor.CilMethodBody!.Instructions.Count <
            vmOpCodes.Count * containerCtorPattern.Pattern.Count)
        {
            Ctx.Console.Error("VM opcode container .ctor is invalid or too small");
            return false;
        }

        var containerCtorOpCodes = PatternMatcher.GetAllMatchingInstructions(containerCtorPattern, containerCtor);
        if (Ctx.Options.VeryVerbose)
            Ctx.Console.InfoStr("Total VM opcodes found", containerCtorOpCodes.Count);
        
        foreach (var opCodeFieldInstrs in containerCtorOpCodes)
        {
            var opCode = opCodeFieldInstrs[1].GetLdcI4Constant();
            var operandType = opCodeFieldInstrs[2].GetLdcI4Constant();
            
            var matchingVMOpCodes = vmOpCodes.Where(x => x.SerializedInstructionField == opCodeFieldInstrs[4].Operand).ToList();
            if (matchingVMOpCodes.Count <= 0 && Ctx.Options.VeryVerbose)
            {
                Ctx.Console.InfoStr("Unhandled VM opcode", $"{opCode}, {operandType}");
                continue;
            }
            
            // don't worry, this changes the vmOpCodes list too :)
            foreach (var vmOpCode in matchingVMOpCodes)
            {
                vmOpCode.HasVirtualCode = true;
                vmOpCode.VirtualCode = opCode;
                vmOpCode.VirtualOperandType = operandType;
            }
        }

        var identified = 0;
        foreach (var vmOpCode in vmOpCodes)
        {
            if (!vmOpCode.HasVirtualCode)
            {
                Ctx.Console.Warning($"VM opcode [{vmOpCode}] does not have a virtual opcode!");
                continue;
            }

            var opCodePat = Ctx.PatternMatcher.FindOpCode(vmOpCode);
            if (opCodePat != null)
            {
                vmOpCode.IsIdentified = true;
                vmOpCode.CilOpCode = opCodePat.CilOpCode;
                vmOpCode.SpecialOpCode = opCodePat.SpecialOpCode;
                vmOpCode.IsSpecial = opCodePat.IsSpecial;
            }
            else if (ExpandedHandlers.Identify(vmOpCode) is { } expanded)
            {
                vmOpCode.IsIdentified = true;
                vmOpCode.CilOpCode = expanded;
            }
            else if (Ctx.Options.VeryVerbose)
                Ctx.Console.Warning($"Failed to identify VM opcode [{vmOpCode}]");

            Ctx.PatternMatcher.SetOpCodeValue(vmOpCode.VirtualCode, vmOpCode);

            if (!vmOpCode.IsIdentified) continue;
            identified++;
            if (Ctx.Options.VeryVeryVerbose)
                Ctx.Console.Info(vmOpCode);
        }
        
        if (Ctx.Options.VeryVerbose)
            Ctx.Console.InfoStr($"VM opcodes identified ({(double)identified / vmOpCodes.Count:P})", identified);
                
        return true;
    }

    private MethodDefinition? FindOpCodeMethod()
    {
        var candidates = Ctx.VMDeclaringType.Methods.Where(method => method.Signature?.ReturnsValue == true &&
            method.Signature.ReturnType.FullName.StartsWith("System.Collections.Generic.Dictionary") &&
            method.CilMethodBody?.Instructions.Any(i=>i.OpCode.Code==CilCode.Ldftn) == true &&
            method.CilMethodBody.Instructions.Any(i=>i.Operand is IMethodDescriptor add && add.Name=="Add" &&
                add.DeclaringType?.FullName==method.Signature.ReturnType.FullName)).ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    public OpCodeMapping(DevirtualizationContext ctx) : base(ctx)
    {
    }
}
