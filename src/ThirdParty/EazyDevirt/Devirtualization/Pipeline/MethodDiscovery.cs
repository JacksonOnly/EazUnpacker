using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions;
using EazyDevirt.Core.Architecture;
using EazyDevirt.Core.IO;
using EazyDevirt.Util;

namespace EazyDevirt.Devirtualization.Pipeline;

internal sealed class MethodDiscovery : StageBase
{
    public MethodDiscovery(DevirtualizationContext ctx) : base(ctx)
    {
    }

    private protected override bool Init()
    {
        var module = Ctx.Module;

        var methods = module
            .GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody != null);

        foreach (var method in methods)
        {
            if (!IsLoadVMPositionMethod(method))
                continue;

            var cilMethodBody = method.CilMethodBody;
            var instructions = cilMethodBody?.Instructions;

            // The instruction indices are the same across all samples I've analyzed.
            if (instructions?.Select(i=>i.Operand).OfType<SerializedMethodDefinition>().FirstOrDefault(IsCryptoKeyMethod) is SerializedMethodDefinition cryptoKeyMethod)
            {
                if (!IsCryptoKeyMethod(cryptoKeyMethod))
                    continue;

                var cryptoKeyBody = cryptoKeyMethod.CilMethodBody;
                var cryptoKeyInstructions = cryptoKeyBody!.Instructions;

                Ctx.MethodCryptoKey = cryptoKeyInstructions[0].GetLdcI4Constant();

                if (Ctx.Options.Verbose)
                {
                    Ctx.Console.Success("Found VM method crypto key!");

                    if (Ctx.Options.VeryVerbose)
                        Ctx.Console.InfoStr("VM Method Crypto Key", Ctx.MethodCryptoKey);
                }

                // this should be in the same method
                if (instructions?.Select(i=>i.Operand).OfType<SerializedMethodDefinition>().FirstOrDefault(IsDecryptPositionMethod) is SerializedMethodDefinition decryptVMPositionMethod)
                {
                    var vmPositionBody = decryptVMPositionMethod.CilMethodBody;
                    var vmPositionInstructions = vmPositionBody!.Instructions;

                    if (!IsDecryptPositionMethod(decryptVMPositionMethod))
                    {
                        Ctx.Console.Error("Failed to find VM position decrypt method.");
                        return false;
                    }

                    if (vmPositionInstructions.Select(i=>i.Operand).OfType<SerializedMethodDefinition>().FirstOrDefault(IsCryptoKeyMethod) is SerializedMethodDefinition
                        positionCryptoKeyMethod)
                    {
                        var positionCryptoKeyBody = positionCryptoKeyMethod.CilMethodBody;
                        var positionCryptoInstr = positionCryptoKeyBody!.Instructions;

                        if (!IsCryptoKeyMethod(positionCryptoKeyMethod))
                        {
                            Ctx.Console.Error("Failed to find VM position crypto key.");
                            return false;
                        }

                        Ctx.PositionCryptoKey = positionCryptoInstr[0].GetLdcI4Constant();

                        if (Ctx.Options.Verbose)
                        {
                            Ctx.Console.Success("Found VM position crypto key!");
                            if (Ctx.Options.VeryVerbose)
                                Ctx.Console.InfoStr("VM Position Crypto Key", Ctx.PositionCryptoKey);
                        }
                    }
                }
            }

            break;
        }

        if (Ctx.MethodCryptoKey == 0)
        {
            Ctx.Console.Error("Failed to find vm method crypto key.");
            return false;
        }

        Ctx.VMMethods = new List<VMMethod>();
        return true;
    }

    public override bool Run()
    {
        if (!Init())
            return false;

        var module = Ctx.Module;

        var methods = module
            .GetAllTypes()
            .SelectMany(t => t.Methods)
            .Where(m => m.CilMethodBody != null);

        // TODO: Use echo?
        foreach (var method in methods)
        {
            var cilMethodBody = method.CilMethodBody;
            if (cilMethodBody is null)
                continue;

            foreach (var callSite in FindCallSites(method, Ctx.VMResourceGetterMdToken))
            {
            string encodedMethodKey = callSite.Key;
            if (Ctx.Options.VeryVerbose)
                Ctx.Console.InfoStr("Virtualized method found", method.MetadataToken);

            long methodKey;
            try { methodKey = DecodeMethodKey(encodedMethodKey, Ctx.PositionCryptoKey); }
            catch (Exception ex) when (ex is FormatException or OverflowException or EndOfStreamException)
            {
                Ctx.VMMethods.Add(new VMMethod(method, encodedMethodKey, -1) { ExecutorInstruction = callSite.Executor,
                    Failure = "Invalid VM position encoding." });
                continue;
            }
            if(methodKey<0 || methodKey>=Ctx.VMStream.Length)
            {
                Ctx.Console.Warning("VM method position out of bounds: "+method.MetadataToken);
                Ctx.VMMethods.Add(new VMMethod(method,encodedMethodKey,-1){ExecutorInstruction=callSite.Executor,
                    Failure="VM method position is outside the resource."});
                continue;
            }
            Ctx.VMMethods.Add(new VMMethod(method, encodedMethodKey, methodKey) { ExecutorInstruction = callSite.Executor });
            }
        }

        if (Ctx.Options.Verbose)
            Ctx.Console.Success($"Discovered {Ctx.VMMethods.Count} virtualized methods!");

        return true;
    }

    internal static IEnumerable<(CilInstruction Executor, string Key)> FindCallSites(MethodDefinition method, AsmResolver.PE.DotNet.Metadata.Tables.MetadataToken getterToken)
    {
        var linear = FindLinearCallSites(method, getterToken).ToArray();
        foreach (var call in linear) yield return call;
        var body = method.CilMethodBody!;
        var missing = body.Instructions.Select((instruction,index)=>(instruction,index)).Where(pair =>
            !linear.Any(call => ReferenceEquals(call.Executor,pair.instruction)) &&
            pair.instruction.OpCode.Code is CilCode.Call or CilCode.Callvirt &&
            pair.instruction.Operand is IMethodDescriptor target && target.Signature?.ParameterTypes.Count >= 3 &&
            target.Signature.ParameterTypes[0].FullName == "System.IO.Stream" && target.Signature.ParameterTypes[1].FullName == "System.String" &&
            target.Signature.ParameterTypes.Last().FullName == "System.Object[]").ToArray();
        if (missing.Length == 0) yield break;
        body.Instructions.CalculateOffsets();
        var indices = body.Instructions.Select((instruction,index)=>(instruction.Offset,index)).ToDictionary(p=>p.Offset,p=>p.index);
        var predecessors = Enumerable.Range(0,body.Instructions.Count).Select(_=>new List<int>()).ToArray();
        for (int i=0;i<body.Instructions.Count;i++)
        {
            var instruction=body.Instructions[i];
            if(instruction.Operand is ICilLabel label && indices.TryGetValue(label.Offset,out int target)) predecessors[target].Add(i);
            else if(instruction.Operand is IList<ICilLabel> table)
                foreach(var item in table)if(indices.TryGetValue(item.Offset,out int destination))predecessors[destination].Add(i);
            if(i+1<body.Instructions.Count && instruction.OpCode.FlowControl is not (CilFlowControl.Branch or CilFlowControl.Return or CilFlowControl.Throw))
                predecessors[i+1].Add(i);
        }
        CilInstruction? Producer(int callIndex,int initialDepth)
        {
            var pending=new Stack<(int Index,int Depth)>();var visited=new HashSet<(int,int)>();CilInstruction? result=null;
            foreach(int p in predecessors[callIndex])pending.Push((p,initialDepth));
            while(pending.Count>0)
            {
                var state=pending.Pop();if(!visited.Add(state))continue;
                if(visited.Count>20000 || state.Depth<0 || state.Depth>4096)return null;
                var instruction=body.Instructions[state.Index];
                if(instruction.OpCode.FlowControl is CilFlowControl.Return or CilFlowControl.Throw ||
                    instruction.OpCode.Code is CilCode.Leave or CilCode.Leave_S or CilCode.Endfinally or CilCode.Endfilter)return null;
                int depth;
                if(instruction.OpCode.Code==CilCode.Dup)depth=state.Depth<2?0:state.Depth-1;
                else
                {
                    int pushes=instruction.GetStackPushCount();
                    if(state.Depth<pushes)
                    {
                        if(result!=null && !ReferenceEquals(result,instruction))return null;
                        result=instruction;continue;
                    }
                    depth=state.Depth-pushes+instruction.GetStackPopCount(body);
                }
                if(predecessors[state.Index].Count==0)return null;
                foreach(int p in predecessors[state.Index])pending.Push((p,depth));
            }
            return result;
        }
        foreach(var pair in missing)
        {
            int count=((IMethodDescriptor)pair.instruction.Operand!).Signature!.ParameterTypes.Count;
            var key=Producer(pair.index,count-2);var stream=Producer(pair.index,count-1);
            if(key?.OpCode.Code==CilCode.Ldstr && key.Operand is string value && stream?.OpCode.Code==CilCode.Call &&
                stream.Operand is MethodDefinition getter && getter.MetadataToken==getterToken)
                yield return (pair.instruction,value);
        }
    }

    private static IEnumerable<(CilInstruction Executor, string Key)> FindLinearCallSites(MethodDefinition method, AsmResolver.PE.DotNet.Metadata.Tables.MetadataToken getterToken)
    {
        var instructions = method.CilMethodBody!.Instructions;
        var indices = Enumerable.Range(0, instructions.Count).Where(index =>
            instructions[index].OpCode.Code == CilCode.Call && instructions[index].Operand is MethodDefinition getter && getter.MetadataToken == getterToken).ToArray();
        for (int n = 0; n < indices.Length; n++)
        {
            int index = indices[n]; int end = n + 1 < indices.Length ? indices[n + 1] : instructions.Count;
            for (int at = index + 1; at < end; at++)
            {
                var executor = instructions[at];
                if (executor.OpCode.Code is not (CilCode.Call or CilCode.Callvirt) || executor.Operand is not IMethodDescriptor target || target.Signature?.ParameterTypes.Count < 3 ||
                    target.Signature == null || target.Signature.ParameterTypes[0].FullName != "System.IO.Stream" || target.Signature.ParameterTypes[1].FullName != "System.String" || target.Signature.ParameterTypes[2].FullName != "System.Object[]" ||
                    target.Signature.ParameterTypes[target.Signature.ParameterTypes.Count - 1].FullName != "System.Object[]") continue;
                string? key = instructions.Skip(index + 1).Take(at-index-1).Where(i => i.OpCode.Code == CilCode.Ldstr).Select(i => i.Operand as string).FirstOrDefault();
                if (key != null) yield return (executor, key);
                break;
            }
        }
    }
    private static long DecodeMethodKey(string positionString, int positionKey)
    {
        var decoded = Ascii85.FromAscii85String(positionString);

        using var stream = DevirtualizationContext.Instance.CreateCryptoStream(new MemoryStream(decoded), positionKey,false);
        using var reader = DevirtualizationContext.Instance.CreateMetadataReader(stream);
        return reader.ReadInt64();
    }

    private static bool IsDecryptPositionMethod(MethodDefinition method)
    {
        return method.Signature?.ReturnType.FullName == typeof(long).FullName
               && method.Parameters.Count == 1
               && method.Parameters[0].ParameterType.FullName == typeof(string).FullName
               && method.CilMethodBody != null;
    }

    private static bool IsCryptoKeyMethod(MethodDefinition method)
    {
        return method.Signature?.ReturnType.FullName == typeof(int).FullName
               && method.CilMethodBody is { Instructions.Count: 2 }
               && method.CilMethodBody.Instructions[0].IsLdcI4();
    }

    internal static bool IsLoadVMPositionMethod(MethodDefinition method)
    {
        return method is { IsStatic: false, Signature.ReturnsValue: false, Parameters.Count: 3 }
               && method.Parameters.Select(p=>p.ParameterType.FullName).OrderBy(n=>n,StringComparer.Ordinal)
                   .SequenceEqual(new[]{"System.IO.Stream","System.Int64","System.String"})
               && method.CilMethodBody is not null;
    }
}
