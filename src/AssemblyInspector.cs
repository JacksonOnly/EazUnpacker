using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Unpacker;

internal static class AssemblyInspector
{
    internal static AssemblyInfo Inspect(string path)
    {
        using var module = ModuleDefMD.Load(path);
        var types = module.GetTypes().ToArray();
        var methods = types.SelectMany(t => t.Methods).ToArray();
        // Eaz has both boxed-result and void executor wrappers. Return type
        // alone loses real VM methods. Require the runtime's decoded-position
        // entry point as corroboration instead: an ordinary formatting helper
        // with (Stream,string,object[]) has no matching decoded-position loader.
        // The loader's argument order is not stable; require the full type set.
        var runtimes=new HashSet<string>(types.Where(IsVmRuntime)
            .Select(t=>t.FullName),StringComparer.Ordinal);
        var result = new AssemblyInfo
        {
            Runtime = module.RuntimeVersion,
            Types = types.Length,
            Methods = methods.Length,
            Resources = module.Resources.Count,
            ModernRuntime = module.GetAssemblyRefs().Any(a => a.Name == "System.Private.CoreLib" || a.Name == "System.Runtime" && a.Version.Major >= 5)
        };
        foreach (var method in methods.Where(m => m.HasBody))
        {
            if (method.IsStatic && method.MethodSig?.ToString() == "System.String (System.Int32)")
                result.StringInt32Candidates.Add(method.MDToken.Raw);
            var ins = method.Body.Instructions;
            result.StringLiterals += ins.Count(i => i.OpCode.Code == Code.Ldstr);
            result.StringInt32Calls += ins.Count(i => i.Operand is IMethod target && target.MethodSig?.ToString() == "System.String (System.Int32)");
            // Calls into a VM executor use Stream as first argument and either an encoded string or decoded position as second.
            if (ins.Any(i => (i.OpCode.Code == Code.Call || i.OpCode.Code == Code.Callvirt) && i.Operand is IMethod target &&
                IsExecutor(target.MethodSig) && target.DeclaringType?.DefinitionAssembly?.FullName==module.Assembly?.FullName &&
                runtimes.Contains(target.DeclaringType!.FullName) &&
                !runtimes.Contains(method.DeclaringType.FullName)))
                result.VirtualizedMethods.Add(method.MDToken.Raw);
        }
        return result;
    }

    private static bool IsExecutor(MethodSig? signature)=>signature?.Params.Count>=3
        && signature.Params[0].FullName=="System.IO.Stream"
        && signature.Params[1].FullName is "System.String" or "System.Int64"
        && signature.Params.Last().FullName=="System.Object[]";

    internal static bool IsVmRuntime(TypeDef type)=>type.Methods.Any(m=>!m.IsStatic && m.HasBody &&
        m.MethodSig is {Params.Count:3} signature && signature.RetType.ElementType==ElementType.Void &&
        signature.Params.Select(p=>p.FullName).OrderBy(n=>n,StringComparer.Ordinal)
            .SequenceEqual(new[]{"System.IO.Stream","System.Int64","System.String"})) &&
        type.Methods.Any(m=>IsExecutor(m.MethodSig));
}
