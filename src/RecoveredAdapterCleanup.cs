using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Newtonsoft.Json.Linq;

namespace Unpacker;

// Generated inline adapters read only their object[] argument. Remove the
// protection-only receiver/stream setup, not any user argument computation.
internal static class RecoveredAdapterCleanup
{
    internal static int Process(ModuleDef module,string report,IEnumerable<TypeDef> runtimes)
    {
        if(!File.Exists(report))return 0;
        var runtimeTypes=new HashSet<TypeDef>(runtimes);
        if(runtimeTypes.Count==0)return 0;
        var all=module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody).ToArray();
        var readers=new HashSet<MethodDef>(all.Where(m=>m.IsStatic && m.MethodSig.Params.Count==0 &&
            m.Body.Instructions.Any(i=>i.Operand is IMethod called && called.Name=="GetManifestResourceStream") &&
            m.MethodSig.RetType.FullName=="System.IO.Stream"));
        var instances=new HashSet<MethodDef>(all.Where(m=>m.IsStatic && m.MethodSig.Params.Count==0 &&
            runtimeTypes.Contains(m.MethodSig.RetType.ToTypeDefOrRef()?.ResolveTypeDef())));
        int changes=0;
        var records=JArray.Parse(File.ReadAllText(report));
        foreach(var record in records.Where(e=>(bool?)e["Restored"]==true && e["RecoveredAdapterToken"]?.Type==JTokenType.String))
        {
            string text=(string)record["RecoveredAdapterToken"]!;
            if(!text.StartsWith("0x",StringComparison.OrdinalIgnoreCase) ||
                !uint.TryParse(text.Substring(2),System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture,out uint token) ||
                module.ResolveToken(token) is not MethodDef adapter || !adapter.IsStatic || !adapter.HasBody ||
                !adapter.Name.String.StartsWith("__RecoveredVM_",StringComparison.Ordinal))continue;
            var parameters=adapter.MethodSig.Params;
            int count=parameters.Count;
            if(count is not (3 or 4) || parameters[count-3].FullName!="System.IO.Stream" ||
                parameters[count-2].ElementType!=ElementType.String || parameters[count-1].FullName!="System.Object[]" ||
                count==4 && !runtimeTypes.Contains(parameters[0].ToTypeDefOrRef()?.ResolveTypeDef()))continue;
            adapter.Body.SimplifyMacros(adapter.Parameters);
            adapter.Body.SimplifyBranches();
            adapter.Body.OptimizeBranches();
            if(adapter.Body.Instructions.Any(i=>
                (i.IsLdarg() || i.OpCode.Code is Code.Ldarga or Code.Ldarga_S || i.IsStarg()) &&
                i.GetParameter(adapter.Parameters)?.MethodSigIndex!=count-1))continue;

            var references=all.SelectMany(m=>m.Body.Instructions.Select(i=>(Method:m,Instruction:i)))
                .Where(p=>p.Instruction.Operand==adapter).ToArray();
            if(references.Length==0 || references.Any(r=>r.Instruction.OpCode.Code!=Code.Call))continue;
            var replacements=new HashSet<Instruction>();
            bool safe=true;
            foreach(var reference in references)
            {
                var body=reference.Method.Body;
                var il=body.Instructions;
                int call=il.IndexOf(reference.Instruction);
                var boundaries=StringFixerBoundaries(body);
                int streamPosition=Producer(call,count-1), instancePosition=count==4?Producer(call,count):-1;
                if(streamPosition<0 || il[streamPosition].OpCode.Code!=Code.Call ||
                    il[streamPosition].Operand is not MethodDef stream || !readers.Contains(stream) ||
                    count==4 && (instancePosition<0 || il[instancePosition].OpCode.Code!=Code.Call ||
                        il[instancePosition].Operand is not MethodDef instance || !instances.Contains(instance)) ||
                    Enumerable.Range(streamPosition+1,call-streamPosition).Any(i=>boundaries.Contains(il[i])))
                {safe=false;break;}
                replacements.Add(il[streamPosition]);
                if(count==4)replacements.Add(il[instancePosition]);

                int Producer(int end,int depth)
                {
                    for(int index=end-1,steps=0;index>=0 && steps<4096;index--,steps++)
                    {
                        var instruction=il[index];
                        if(index+1<end && boundaries.Contains(il[index+1]) ||
                            instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Return or FlowControl.Throw ||
                            instruction.OpCode.OpCodeType==OpCodeType.Prefix)return -1;
                        instruction.CalculateStackUsage(out int pushes,out int pops);
                        if(pops<0)return -1;
                        // depth is one-based: count-1 identifies stream, count receiver.
                        if(depth<=pushes)return pushes==1?index:-1;
                        depth=depth-pushes+pops;
                        if(depth>4096)return -1;
                    }
                    return -1;
                }
            }
            if(!safe)continue;
            foreach(var instruction in replacements){instruction.OpCode=OpCodes.Ldnull;instruction.Operand=null;changes++;}
            if(count==4)parameters[0]=module.CorLibTypes.Object;
        }
        return changes;
    }

    private static HashSet<Instruction> StringFixerBoundaries(CilBody body)
    {
        var set=new HashSet<Instruction>();
        foreach(var i in body.Instructions)
        {
            if(i.Operand is Instruction target)set.Add(target);
            else if(i.Operand is IList<Instruction> targets)set.UnionWith(targets);
        }
        foreach(var eh in body.ExceptionHandlers)
            foreach(var p in new[]{eh.TryStart,eh.TryEnd,eh.HandlerStart,eh.HandlerEnd,eh.FilterStart})if(p!=null)set.Add(p);
        return set;
    }
}
