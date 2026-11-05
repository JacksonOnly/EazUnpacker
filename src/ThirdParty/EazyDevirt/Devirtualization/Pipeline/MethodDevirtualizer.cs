using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions;
using EazyDevirt.Core.Architecture;
using EazyDevirt.Core.IO;

namespace EazyDevirt.Devirtualization.Pipeline;

internal class MethodDevirtualizer : StageBase
{
    private CryptoStreamV3 VMStream { get; set; }
    private VMBinaryReader VMStreamReader { get; set; }
    
    private Resolver Resolver { get; set; }
    private VMHeaderLayout HeaderLayout { get; set; }
    private VMExceptionLayout ExceptionLayout { get; set; }
    private HomomorphicReader Homomorphic { get; set; }
    
    public override bool Run()
    {
        if (!Init()) return false;
        HeaderLayout = VMHeaderLayout.Discover(Ctx.VMDeclaringType);
        Ctx.HeaderLayout=HeaderLayout;
        ExceptionLayout = VMExceptionLayout.Discover(Ctx.VMDeclaringType);
        Homomorphic = new HomomorphicReader(Ctx);
        
        VMStream = new CryptoStreamV3(Ctx.VMStream, Ctx.MethodCryptoKey, true);
        VMStreamReader = new VMBinaryReader(VMStream);
        
        Resolver = new Resolver(Ctx);
        CalibrateHeader();
        Ctx.Progress?.Invoke("VM 方法还原",0,Ctx.VMMethods.Count);
        for (int pass = 0; pass < 3; pass++)
        {
        // Restore producers (including virtualized UI/resource initializers)
        // before spending the module's bounded integer-search budget.
        Homomorphic.AllowBoundedSearch=pass==2;
        int restoredBefore = Ctx.VMMethods.Count(m=>m.SuccessfullyDevirtualized);
        int restoredInPass=restoredBefore;
        foreach (var vmMethod in Ctx.VMMethods.Where(m=>!m.SuccessfullyDevirtualized))
        {
            var originalBody=vmMethod.Parent.CilMethodBody;
            try {
                VMStream.Seek(vmMethod.MethodKey, SeekOrigin.Begin);
                ReadVMMethod(vmMethod);
                if(vmMethod.SuccessfullyDevirtualized)vmMethod.Failure=null;
            }
            catch(Exception ex) {
                if(vmMethod.Parent.CilMethodBody!=originalBody)vmMethod.Parent.CilMethodBody=originalBody;
                vmMethod.SuccessfullyDevirtualized=false;
                vmMethod.RecoveredAdapter = null;
                vmMethod.ArgumentTypes = null;
                vmMethod.Failure = ex.GetType().Name + ": " + ex.Message;
                Ctx.Console.Info($"[{vmMethod.Parent.MetadataToken}] Preserved original body: {ex.GetType().Name}: {ex.Message}");
                if (Ctx.Options.VeryVeryVerbose) Ctx.Console.Warning(ex.StackTrace ?? "");
                if (Ctx.Options.VeryVeryVerbose && vmMethod.Instructions != null)
                    foreach (var instruction in vmMethod.Instructions.Skip(Math.Max(0, vmMethod.Instructions.Count - 160))) Ctx.Console.Info("Rejected IL: " + instruction);
            }
            
            if (Ctx.Options.VeryVerbose)
                Ctx.Console.Info(vmMethod);
            if(vmMethod.SuccessfullyDevirtualized)restoredInPass++;
            Ctx.Progress?.Invoke("VM 调用点还原（第 "+(pass+1)+" 轮）",restoredInPass,Ctx.VMMethods.Count);
        }
        if(Ctx.VMMethods.Count(m=>m.SuccessfullyDevirtualized)==restoredBefore && pass==2)break;
        }
        
        VMStreamReader.Dispose();
        return true;
    }

    private void CalibrateHeader()
    {
        var candidates=new HashSet<int>(new[]{1,2,4,8,16,32,64,128});
        var samples=Ctx.VMMethods.Where(m=>m.MethodKey>=0).GroupBy(m=>m.MethodKey).Select(g=>g.First()).Take(64).ToArray();
        var elapsed=System.Diagnostics.Stopwatch.StartNew();
        int inspected=0;
        Ctx.Progress?.Invoke("VM 头部校准",0,samples.Length);
        foreach(var method in samples)
        {
            if(elapsed.Elapsed.TotalSeconds>=5)
            {
                Ctx.Console.Warning("VM header calibration budget reached; unproven assumptions remain uncalibrated.");
                break;
            }
            try {
                VMStream.Position=method.MethodKey;
                var info=new VMMethodInfo(VMStreamReader,HeaderLayout);
                if(Ctx.Options.VeryVeryVerbose) Ctx.Console.Info($"Header sample {method.Parent.MetadataToken}: flags={info.BindingFlags}, metadata static={method.Parent.IsStatic}, name={method.Parent.Name}");
                // Inlining may put a call to another virtual method inside a
                // nonvirtual host. Such a call does not describe its host's
                // static bit and must not poison the global header calibration.
                string first=Resolver.ResolveType(info.VMDeclaringType)!.FullName;
                string second=Resolver.ResolveType(info.VMReturnType)!.FullName;
                string declaring=method.Parent.DeclaringType!.FullName,returns=method.Parent.Signature!.ReturnType.FullName;
                bool matchingTypes = first==declaring && second==returns || first==returns && second==declaring;
                if (info.Name == method.Parent.Name && matchingTypes && ParametersMatch(method, info))
                    candidates.RemoveWhere(mask=>((info.BindingFlags & mask)!=0)!=method.Parent.IsStatic);
                if (!HeaderLayout.TypeSlotsCalibrated && matchingTypes) {
                    HeaderLayout.FirstTypeIsReturn=first==returns;
                    HeaderLayout.TypeSlotsCalibrated=true;
                }
            }
            catch(Exception ex) { Ctx.Console.Warning("Header calibration skipped: "+ex.Message); }
            inspected++;
            Ctx.Progress?.Invoke("VM 头部校准",inspected,samples.Length);
            if(inspected>=8 && candidates.Count==1 && HeaderLayout.TypeSlotsCalibrated)break;
        }
        HeaderLayout.StaticMaskCandidates=candidates.ToArray();
        if(candidates.Count==1) {HeaderLayout.StaticMask=candidates.Single();HeaderLayout.StaticMaskCalibrated=true;}
        Ctx.Console.Info($"VM header calibration: type slots={HeaderLayout.TypeSlotsCalibrated}, first return={HeaderLayout.FirstTypeIsReturn}, static mask={HeaderLayout.StaticMask} ({HeaderLayout.StaticMaskCalibrated})");
    }
    
    private void ReadVMMethod(VMMethod vmMethod)
    {
        vmMethod.MethodInfo = new VMMethodInfo(VMStreamReader,HeaderLayout);

        ReadExceptionHandlers(vmMethod);

        var wireDeclaringType = Resolver.ResolveType(vmMethod.MethodInfo.VMDeclaringType);
        var wireReturnType = Resolver.ResolveTypeSignature(vmMethod.MethodInfo.VMReturnType)!;
        bool wholeMethod = Ctx.VMMethods.Count(candidate => candidate.Parent == vmMethod.Parent) == 1 &&
            vmMethod.Parent.Name == vmMethod.MethodInfo.Name &&
            (vmMethod.Parent.DeclaringType!.FullName == wireDeclaringType?.FullName ||
             OpenDeclaringType(vmMethod.Parent.DeclaringType).FullName == wireDeclaringType?.FullName) &&
            vmMethod.Parent.Signature!.ReturnType.FullName == wireReturnType.FullName &&
            (!HeaderLayout.StaticMaskCalibrated || vmMethod.Parent.IsStatic == vmMethod.MethodInfo.IsStatic) &&
            ParametersMatch(vmMethod, vmMethod.MethodInfo);
        if (!wholeMethod)
        {
            if (Ctx.Options.VeryVeryVerbose)
            {
                Ctx.Console.Info($"Non-stub VM host {vmMethod.Parent.MetadataToken}: header name={vmMethod.MethodInfo.Name}, declaring={wireDeclaringType?.FullName}, static={vmMethod.MethodInfo.IsStatic}; metadata={vmMethod.Parent.FullName}");
                Ctx.Console.Info("Wire arguments: " + string.Join(", ", vmMethod.MethodInfo.VMParameters.Select(parameter => Resolver.ResolveType(parameter.VMType)!.FullName + (parameter.In ? " [in/ref]" : ""))));
            }
            var owner = wireDeclaringType?.Resolve();
            if (owner?.DeclaringModule != Ctx.Module)
                throw new NotSupportedException("Inlined VM body declaring type is outside the input module.");
            var arguments = vmMethod.MethodInfo.VMParameters.Select(parameter => {
                var type = Resolver.ResolveTypeSignature(parameter.VMType)!;
                return parameter.In && type is not ByReferenceTypeSignature ? new ByReferenceTypeSignature(type) : type;
            }).ToArray();
            vmMethod.RecoveredAdapter = InlineVmCallAdapter.Create(vmMethod, owner, arguments);
        }
        
        // These types already exist in the original method signature; header slots are shuffled independently.
        vmMethod.MethodInfo.DeclaringType = vmMethod.Parent.DeclaringType!;
        vmMethod.MethodInfo.ReturnType = vmMethod.Parent.Signature!.ReturnType.ToTypeDefOrRef()!;
        
        ResolveLocalsAndParameters(vmMethod);

        ReadInstructions(vmMethod);
        if (!vmMethod.SuccessfullyDevirtualized && (!Ctx.Options.SaveAnyway || Ctx.Options.OnlySaveDevirted))
            return;

        // these need all instructions to be successfully devirtualized to work
        IndirectStoreResolver.Rewrite(vmMethod);
        ResolveBranchTargets(vmMethod);
        ResolveExceptionHandlers(vmMethod);

        // recompile method
        var newBody=new CilMethodBody();
        newBody.InitializeLocals=true;
        vmMethod.Locals.ForEach(x=>newBody.LocalVariables.Add(x));
        vmMethod.ExceptionHandlers.ForEach(x=>newBody.ExceptionHandlers.Add(x));
        vmMethod.Instructions.ForEach(x=>newBody.Instructions.Add(x));
        newBody.VerifyLabelsOnBuild=false;newBody.ComputeMaxStackOnBuild=false;
        var bodyMethod = vmMethod.RecoveredAdapter ?? vmMethod.Parent;
        bodyMethod.CilMethodBody=newBody;
        if (vmMethod.Inlined) InlineVmCallAdapter.RewriteBody(vmMethod, newBody, wireReturnType);
        vmMethod.AccessBridges.AddRange(VmAccessBridge.Rewrite(bodyMethod, vmMethod.AdapterDeclaringType ?? vmMethod.Parent.DeclaringType));
        if (vmMethod.SuccessfullyDevirtualized && !Ctx.Options.NoVerify)
        {
            newBody.MaxStack=newBody.ComputeMaxStack();
            newBody.VerifyLabels();
        }
        if (vmMethod.Inlined)
        {
            vmMethod.AdapterDeclaringType!.Methods.Add(bodyMethod);
            vmMethod.ExecutorInstruction!.OpCode = CilOpCodes.Call;
            vmMethod.ExecutorInstruction.Operand = bodyMethod;
            Ctx.Console.Info($"Recovered inlined VM call in {vmMethod.Parent.MetadataToken} using {bodyMethod.Name}; host body retained.");
        }
    }

    private bool ParametersMatch(VMMethod method, VMMethodInfo info)
    {
        int first = method.Parent.IsStatic ? 0 : 1;
        if (method.Parent.Parameters.Count + first != info.VMParameters.Count) return false;
        for (int i = 0; i < info.VMParameters.Count; i++)
        {
            var encoded = info.VMParameters[i];
            string wire = Resolver.ResolveType(encoded.VMType)!.FullName;
            var metadata = first == 1 && i == 0
                ? OpenDeclaringType(method.Parent.DeclaringType!)
                : method.Parent.Parameters[i - first].ParameterType;
            if (metadata.FullName == wire) continue;
            // Some VM headers put the byref shape in the separate parameter
            // flag. Require that flag as well as an exact element signature.
            if (encoded.In && metadata is AsmResolver.DotNet.Signatures.ByReferenceTypeSignature reference && reference.BaseType.FullName == wire)
                continue;
            return false;
        }
        return true;
    }

    private static AsmResolver.DotNet.Signatures.TypeSignature OpenDeclaringType(AsmResolver.DotNet.TypeDefinition type)
    {
        var signature = type.ToTypeSignature();
        return type.GenericParameters.Count == 0 ? signature : new AsmResolver.DotNet.Signatures.GenericInstanceTypeSignature(type, type.IsValueType,
            Enumerable.Range(0, type.GenericParameters.Count).Select(index =>
                (AsmResolver.DotNet.Signatures.TypeSignature)new AsmResolver.DotNet.Signatures.GenericParameterSignature(
                    type.DeclaringModule!, AsmResolver.DotNet.Signatures.GenericParameterType.Type, index)).ToArray());
    }
    
    private void ReadExceptionHandlers(VMMethod vmMethod)
    {
        vmMethod.VMExceptionHandlers = new List<VMExceptionHandler>(VMStreamReader.ReadInt16());
        for (var i = 0; i < vmMethod.VMExceptionHandlers.Capacity; i++)
            vmMethod.VMExceptionHandlers.Add(new VMExceptionHandler(VMStreamReader, ExceptionLayout));

        vmMethod.VMExceptionHandlers.Sort((first, second) =>
            first.TryStart == second.TryStart
                ? first.TryLength.CompareTo(second.TryLength)
                : second.TryStart.CompareTo(first.TryStart));
    }
    
    private void ResolveLocalsAndParameters(VMMethod vmMethod)
    {
        vmMethod.Locals = new List<CilLocalVariable>();
        foreach (var local in vmMethod.MethodInfo.VMLocals)
        {
            var type = Resolver.ResolveTypeSignature(local.VMType)!;
            vmMethod.Locals.Add(new CilLocalVariable(type));

            // if (Ctx.Options.VeryVeryVerbose)
            //     Ctx.Console.Info($"[{vmMethod.MethodInfo.Name}] Local: {type.Name}");
        }
        
        // the parameters should already be the correct types and in the correct order so we don't need to resolve those
    }

    private void ReadInstructions(VMMethod vmMethod)
    {
        vmMethod.Instructions = new List<CilInstruction>();
        vmMethod.EncryptedRegions=0;
        vmMethod.VirtualOffsets = new List<uint>();
        vmMethod.CodeSize = VMStreamReader.ReadInt32();
        if (vmMethod.CodeSize <= 0 || vmMethod.CodeSize > VMStream.Length - VMStream.Position)
            throw new InvalidDataException("Invalid VM code size.");
        vmMethod.InitialCodeStreamPosition = VMStream.Position;
        vmMethod.SuccessfullyDevirtualized = true;
        var finalPosition = VMStream.Position + vmMethod.CodeSize;
        ReadInstructionRange(vmMethod, VMStream, finalPosition, vmMethod.InitialCodeStreamPosition, false, 0);
    }

    private void AddInstruction(VMMethod method, CilInstruction instruction)
    {
        method.VirtualOffsets.Add(checked((uint)method.CodePosition));
        method.Instructions.Add(instruction);
    }

    private void ReadInstructionRange(VMMethod vmMethod, Stream stream, long finalPosition, long virtualOrigin, bool encrypted, int regionId)
    {
        while (stream.Position < finalPosition)
        {
            vmMethod.CodePosition = stream.Position - virtualOrigin;
            var virtualOpCode = VMStreamReader.ReadInt32Special();
            var vmOpCode = Ctx.PatternMatcher.GetOpCodeValue(virtualOpCode);
            if (!vmOpCode.HasVirtualCode)
            {
                throw new InvalidDataException($"Unknown VM opcode {virtualOpCode} at {vmMethod.Instructions.Count}.");
            }

            if (!vmOpCode.IsIdentified)
            {
                throw new NotSupportedException($"VM opcode {virtualOpCode} has no verified CIL mapping.");
            }

            if (vmOpCode.SpecialOpCode == SpecialOpCodes.StartHomomorphic)
            {
                long virtualStart = stream.Position - virtualOrigin;
                var block = Homomorphic.Read(vmMethod, vmOpCode, VMStreamReader, finalPosition - stream.Position);
                for (int i = 0; i < 3; i++) AddInstruction(vmMethod, new CilInstruction(CilOpCodes.Pop));
                var previousReader = VMStreamReader;
                using var nested = new MemoryStream(block.Code, false);
                using var nestedReader = new VMBinaryReader(nested, true);
                VMStreamReader = nestedReader;
                try { ReadInstructionRange(vmMethod, nested, nested.Length, -virtualStart, true, block.Id); }
                finally { VMStreamReader = previousReader; }
                vmMethod.EncryptedRegions++;
                vmMethod.HasHomomorphicEncryption = true;
                continue;
            }
            if (vmOpCode.SpecialOpCode == SpecialOpCodes.EndHomomorphic)
            {
                if (!encrypted || vmMethod.Instructions.Count == 0 ||
                    !vmMethod.Instructions.Last().IsLdcI4() || vmMethod.Instructions.Last().GetLdcI4Constant() != regionId || stream.Position != finalPosition)
                    throw new InvalidDataException("Encrypted region has no matching final identifier.");
                AddInstruction(vmMethod, new CilInstruction(CilOpCodes.Pop));
                return;
            }
            if (vmOpCode.IsSpecial && vmOpCode.SpecialOpCode is not (SpecialOpCodes.EazCall or SpecialOpCodes.NoBody))
                throw new NotSupportedException("Unsupported special VM opcode: " + vmOpCode.SpecialOpCode);

            if (vmOpCode is { IsSpecial: true, CilOpCode: null })
            {
                vmOpCode.CilOpCode = ResolveSpecialCilOpCode(vmOpCode, vmMethod);
                if (vmOpCode.CilOpCode != null && Ctx.Options.VeryVerbose)
                    Ctx.Console.InfoStr($"Resolved special opcode {vmOpCode.SpecialOpCode.ToString()!} to CIL opcode {vmOpCode.CilOpCode.ToString()}", vmOpCode.SerializedDelegateMethod.MetadataToken);
            }

            var operand = vmOpCode.IsSpecial ? ReadSpecialOperand(vmOpCode, vmMethod) : ReadOperand(vmOpCode, vmMethod);
            if (vmOpCode.CilOpCode != null)
            {
                // Log these for now since they're special cases. 
                if (vmOpCode.CilOpCode.Value.Mnemonic.StartsWith("stind"))
                    Ctx.Console.Info($"Placing stind instruction at #{vmMethod.Instructions.Count}");
                else if (vmOpCode.SpecialOpCode == SpecialOpCodes.NoBody)
                    Ctx.Console.Info($"Placing NoBody instruction at #{vmMethod.Instructions.Count}");

                if (vmOpCode.CilOpCode.Value.OperandType != CilOperandType.InlineNone && operand == null)
                    throw new InvalidDataException("Unresolved CIL operand: " + vmOpCode.CilOpCode);

                var instruction =
                    new CilInstruction(vmOpCode.CilOpCode.Value, operand);
                AddInstruction(vmMethod, instruction);
            }
        }

        if (stream.Position != finalPosition) throw new InvalidDataException("VM operand exceeded method code boundary.");
        if (encrypted) throw new InvalidDataException("Encrypted region end marker is missing.");
    }

    internal static Dictionary<uint, int> GetVirtualOffsets(VMMethod vmMethod)
    {
        var virtualOffsets = new Dictionary<uint, int>(vmMethod.Instructions.Count);
        var lastCilOffset = 0;
        for (int i = 0; i < vmMethod.Instructions.Count; i++)
        {
            var ins = vmMethod.Instructions[i];
            ins.Offset = lastCilOffset;
            if (!virtualOffsets.ContainsKey(vmMethod.VirtualOffsets[i])) virtualOffsets.Add(vmMethod.VirtualOffsets[i], lastCilOffset);
            // Before branch resolution switch operands are raw VM offsets (int[]).
            // AsmResolver only counts switch entries represented by ICilLabel,
            // otherwise every following label lands inside the switch table.
            lastCilOffset += ins.OpCode.OperandType == CilOperandType.InlineSwitch && ins.Operand is int[] targets
                ? ins.OpCode.Size + sizeof(int) * (targets.Length + 1)
                : ins.Size;
        }
        virtualOffsets.Add((uint)vmMethod.CodeSize, lastCilOffset);

        return virtualOffsets;
    }
    
    private void ResolveBranchTargets(VMMethod vmMethod)
    {
        var virtualOffsets = GetVirtualOffsets(vmMethod);

        for (var i = 0; i < vmMethod.Instructions.Count; i++)
        {
            var ins = vmMethod.Instructions[i];
            switch (ins.OpCode.OperandType)
            {
                case CilOperandType.InlineBrTarget:
                case CilOperandType.ShortInlineBrTarget:
                    ins.Operand = vmMethod.SuccessfullyDevirtualized
                        ? new CilOffsetLabel(virtualOffsets[(uint)ins.Operand!])
                        : new CilOffsetLabel(0);
                    break;
                case CilOperandType.InlineSwitch:
                    var offsets = (int[])ins.Operand!;
                    var labels = new ICilLabel[offsets!.Length];
                    for (var x = 0; x < offsets.Length; x++)
                        labels[x] = vmMethod.SuccessfullyDevirtualized
                            ? new CilOffsetLabel(virtualOffsets[unchecked((uint)offsets[x])])
                            : new CilOffsetLabel(0);
                    ins.Operand = labels;
                    break;
            }
        }
    }

    private void ResolveExceptionHandlers(VMMethod vmMethod)
    {
        vmMethod.ExceptionHandlers = new List<CilExceptionHandler>();
        if (!vmMethod.SuccessfullyDevirtualized) return;
        
        var virtualOffsets = GetVirtualOffsets(vmMethod);
        foreach (var vmExceptionHandler in vmMethod.VMExceptionHandlers)
        {
            var exceptionHandler = new CilExceptionHandler
            {
                HandlerType = vmExceptionHandler.HandlerType,
                ExceptionType = vmExceptionHandler.HandlerType == CilExceptionHandlerType.Exception ? Resolver.ResolveType(vmExceptionHandler.CatchType) : null
            };

            var handlerStart = vmMethod.Instructions.GetByOffset(virtualOffsets[vmExceptionHandler.HandlerStart]);
            exceptionHandler.HandlerStart = handlerStart?.CreateLabel();

            // HandlerEnd is not explicitly defined, and we don't have a length, so we need to find it ourselves
            var handlerEndIndex = vmMethod.Instructions.GetIndexByOffset(virtualOffsets[vmExceptionHandler.HandlerStart]);
            var foundHandlerEnd = false;
            if (vmExceptionHandler.HandlerType is CilExceptionHandlerType.Finally or CilExceptionHandlerType.Fault)
            {
                handlerEndIndex = FindFinallyHandlerEnd(vmMethod.Instructions, handlerEndIndex);
                foundHandlerEnd = true;
            }
            while (!foundHandlerEnd && vmMethod.Instructions.Count - 1 > handlerEndIndex)
            {
                var possibleHandlerEnd = vmMethod.Instructions[handlerEndIndex];
                
                // if there is a branch, skip past it to ensure the correct HandlerEnd is found
                if (possibleHandlerEnd.IsBranch() && possibleHandlerEnd.OpCode.Code is not (CilCode.Leave or CilCode.Leave_S))
                {
                    handlerEndIndex = vmMethod.Instructions.GetIndexByOffset(((ICilLabel)possibleHandlerEnd.Operand!).Offset);
                    continue;
                }
                
                switch (possibleHandlerEnd.OpCode.Code)
                {
                    case CilCode.Endfilter:
                        if (vmExceptionHandler.HandlerType == CilExceptionHandlerType.Filter)
                            foundHandlerEnd = true;
                        break;
                    case CilCode.Endfinally:
                        if (vmExceptionHandler.HandlerType == CilExceptionHandlerType.Finally)
                            foundHandlerEnd = true;
                        break;
                    case CilCode.Leave:
                    case CilCode.Leave_S:
                        if (possibleHandlerEnd.Operand is ICilLabel target &&
                            target.Offset >= exceptionHandler.HandlerStart?.Offset)
                        {
                            // An inner try/finally leaves to a continuation in
                            // this outer finally, not out of the outer handler.
                            if (vmExceptionHandler.HandlerType is CilExceptionHandlerType.Finally or CilExceptionHandlerType.Fault)
                            {
                                handlerEndIndex = vmMethod.Instructions.GetIndexByOffset(target.Offset);
                                continue;
                            }
                            foundHandlerEnd = true;
                        }
                        break;
                    case CilCode.Ret:
                        // this shouldn't happen, but this makes the handler end set on the ret instruction instead of one after it
                        if (handlerEndIndex == vmMethod.Instructions.Count - 1)
                            handlerEndIndex--;
                        foundHandlerEnd = true;
                        break;
                    case CilCode.Rethrow:
                    case CilCode.Throw:
                        foundHandlerEnd = true;
                        break;
                }

                handlerEndIndex++;
            }

            exceptionHandler.HandlerEnd = vmMethod.Instructions[handlerEndIndex].CreateLabel();

            exceptionHandler.TryStart = vmMethod.Instructions.GetByOffset(virtualOffsets[vmExceptionHandler.TryStart])?.CreateLabel();

            // TryEnd is equal to TryStart + TryLength + 1
            var tryEndIndex = vmMethod
                .Instructions.GetIndexByOffset(
                    virtualOffsets[vmExceptionHandler.TryStart + vmExceptionHandler.TryLength]);
            exceptionHandler.TryEnd = vmMethod
                .Instructions[tryEndIndex + (vmMethod.Instructions.Count - 2 >= tryEndIndex ? 1 : 0)].CreateLabel();

            if (vmExceptionHandler.HandlerType == CilExceptionHandlerType.Filter)
                exceptionHandler.FilterStart = vmMethod.Instructions.GetByOffset(virtualOffsets[vmExceptionHandler.FilterStart])?.CreateLabel();
            
            vmMethod.ExceptionHandlers.Add(exceptionHandler);
        }
    }

    internal static int FindFinallyHandlerEnd(IList<CilInstruction> instructions, int start)
    {
        var visited = new HashSet<int>();
        var pending = new Stack<int>();
        var offsets = instructions.Select((instruction, index) => (instruction.Offset, index))
            .ToDictionary(item => item.Offset, item => item.index);
        int terminalEnd = -1;
        pending.Push(start);
        while (pending.Count != 0)
        {
            int index = pending.Pop();
            if (index < start || index >= instructions.Count)
                throw new InvalidDataException("Finally continuation is outside the handler.");
            if (!visited.Add(index)) continue;
            var instruction = instructions[index];
            if (instruction.OpCode.Code is CilCode.Endfinally or CilCode.Throw or CilCode.Rethrow)
            {
                terminalEnd = Math.Max(terminalEnd, index + 1);
                continue;
            }
            if (instruction.OpCode.Code is CilCode.Ret or CilCode.Endfilter)
                throw new InvalidDataException("Unexpected finally continuation terminal.");
            // Visit both edges of conditional branches. Following only the
            // taken edge mistakes ordinary loops for an unbounded handler.
            if (instruction.Operand is ICilLabel label &&
                (instruction.IsBranch() || instruction.OpCode.Code is CilCode.Leave or CilCode.Leave_S))
            {
                if (!offsets.TryGetValue(label.Offset, out int target))
                    throw new InvalidDataException("Invalid finally branch target.");
                pending.Push(target);
                if (instruction.OpCode.FlowControl != CilFlowControl.ConditionalBranch) continue;
            }
            else if (instruction.Operand is ICilLabel[] labels)
            {
                foreach (var targetLabel in labels)
                {
                    if (!offsets.TryGetValue(targetLabel.Offset, out int target))
                        throw new InvalidDataException("Invalid finally switch target.");
                    pending.Push(target);
                }
            }
            pending.Push(index + 1);
        }
        if (terminalEnd >= 0) return terminalEnd;
        throw new InvalidDataException("Finally handler has no bounded terminal continuation.");
    }

    private object? ReadOperand(VMOpCode vmOpCode, VMMethod vmMethod)
    {
        if (vmOpCode.CilOperandType == CilOperandType.InlineI && vmOpCode.CilOpCode?.OperandType is
            CilOperandType.InlineTok or CilOperandType.InlineType or CilOperandType.InlineField or CilOperandType.InlineMethod or CilOperandType.InlineString)
            return ReadInlineTok(vmOpCode);
        return
        vmOpCode.CilOperandType switch // maybe switch this to vmOpCode.CilOpCode.OperandType and add more handlers
        {
            CilOperandType.InlineI => VMStreamReader.ReadInt32Special(),
            CilOperandType.ShortInlineI => VMStreamReader.ReadSByte(),
            CilOperandType.InlineI8 => VMStreamReader.ReadInt64(),
            CilOperandType.InlineR => VMStreamReader.ReadDouble(),
            CilOperandType.ShortInlineR => VMStreamReader.ReadSingle(),
            CilOperandType.InlineVar => VMStreamReader.ReadUInt16(),    // IsInlineArgument(vmOpCode.CilOpCode) ? GetArgument(vmMethod, VMStreamReader.ReadUInt16()) : GetLocal(vmMethod, VMStreamReader.ReadUInt16()),
            CilOperandType.ShortInlineVar => VMStreamReader.ReadByte(), // IsInlineArgument(vmOpCode.CilOpCode) ? GetArgument(vmMethod, VMStreamReader.ReadByte()) : GetLocal(vmMethod, VMStreamReader.ReadByte()),
            CilOperandType.InlineTok => ReadInlineTok(vmOpCode),
            CilOperandType.InlineSwitch => ReadInlineSwitch(),
            CilOperandType.InlineBrTarget => VMStreamReader.ReadUInt32(),
            CilOperandType.InlineArgument => VMStreamReader.ReadUInt16(),    // GetArgument(vmMethod, VMStreamReader.ReadUInt16()),  // this doesn't seem to be used, might not be correct
            CilOperandType.ShortInlineArgument => VMStreamReader.ReadByte(), // GetArgument(vmMethod, VMStreamReader.ReadByte()),    // this doesn't seem to be used, might not be correct
            CilOperandType.InlineNone => null,
            _ => throw new NotSupportedException("Unsupported VM operand: " + vmOpCode.CilOperandType)
        };
    }

    private object? ReadSpecialOperand(VMOpCode vmOpCode, VMMethod vmMethod) =>
        vmOpCode.SpecialOpCode switch
        {
            SpecialOpCodes.EazCall => Resolver.ResolveEazCall(VMStreamReader.ReadInt32Special()),
            SpecialOpCodes.StartHomomorphic => ReadHomomorphicEncryption(vmMethod),
            _ => null
        };

    /// <summary>
    /// Resolves special opcodes with no CIL opcode.
    /// </summary>
    /// <param name="vmOpCode"></param>
    /// <param name="vmMethod"></param>
    /// <returns>
    /// A CIL opcode that matches the special opcode.
    /// TODO: maybe a list of op codes?
    /// </returns>
    private static CilOpCode? ResolveSpecialCilOpCode(VMOpCode vmOpCode, VMMethod vmMethod)
    {
        switch (vmOpCode.SpecialOpCode)
        {
            // case SpecialOpCodes.Stind:
            // case SpecialOpCodes.StartHomomorphic:
            case SpecialOpCodes.NoBody:
                // TODO: Analyze vm method instructions / stack to determine CIL opcode (2 opcode handlers have this pattern)
                return CilOpCodes.Nop;
        }

        return CilOpCodes.Nop;
    }

    /// <summary>
    /// Processes homomorphic encryption data into CIL instructions 
    /// </summary>
    /// <param name="vmMethod"></param>
    /// <returns>
    /// branch offset
    /// </returns>
    private int? ReadHomomorphicEncryption(VMMethod vmMethod)
    {
        Ctx.Console.Info($"[{vmMethod.Parent.MetadataToken}] Detected homomorphic encryption.");

        vmMethod.HasHomomorphicEncryption = true;
        return null;
    }

    private object? ReadInlineTok(VMOpCode vmOpCode) =>
        vmOpCode.CilOpCode?.OperandType switch
        {
            CilOperandType.InlineString => Resolver.ResolveString(VMStreamReader.ReadInt32Special()),
            _ => Resolver.ResolveToken(VMStreamReader.ReadInt32Special())
        };

    private int[] ReadInlineSwitch()
    {
        var destCount = VMStreamReader.ReadInt32Special();
        if (destCount < 0 || destCount > 1000000) throw new InvalidDataException("Invalid VM switch length.");
        var branchDests = new int[destCount];
        for (var i = 0; i < destCount; i++)
            branchDests[i] = VMStreamReader.ReadInt32Special();
        return branchDests;
    }

#pragma warning disable CS8618
    public MethodDevirtualizer(DevirtualizationContext ctx) : base(ctx)
    {
    }
#pragma warning restore CS8618
}
