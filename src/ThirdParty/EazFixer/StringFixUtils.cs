using System.Linq;
using dnlib.DotNet;
using System.Collections.Generic;
using dnlib.DotNet.Emit;

namespace EazFixer
{
    public static class StringFixUtils
    {
        public static MethodDef FindStringDecryptMethod(ModuleDef module)
        {
            return FindStringDecryptMethods(module).FirstOrDefault();
        }

        /// <summary>Finds all structurally matched Eaz string entry points, including nested and non-internal variants.</summary>
        public static IEnumerable<MethodDef> FindStringDecryptMethods(ModuleDef module) =>
            Utils.GetMethodsRecursive(module).Where(CanBeStringMethod);

        public static string FindDecoderResource(MethodDef wrapper)
        {
            if (!wrapper.HasBody) return null;
            var cores = wrapper.Body.Instructions.Where(i => i.OpCode.Code == Code.Call)
                .Select(i => (i.Operand as IMethod)?.ResolveMethodDef())
                .Where(m => m != null && m.DeclaringType == wrapper.DeclaringType && m.HasBody && m.IsStatic &&
                    m.MethodSig?.RetType.ElementType == ElementType.String && m.MethodSig.Params.Count == 2 &&
                    m.MethodSig.Params[0].ElementType == ElementType.I4 && m.MethodSig.Params[1].ElementType == ElementType.Boolean &&
                    m.Body.Instructions.Any(i => i.Operand is IMethod called && called.Name == "GetManifestResourceStream" &&
                        called.DeclaringType.FullName == "System.Reflection.Assembly"))
                .Distinct().ToArray();
            if (cores.Length != 1) return null;
            try { return StringResourceLayout.Detect(cores[0]).ResourceName; }
            catch (StringResourceException) { return null; }
        }

        private static bool CanBeStringMethod(MethodDef method)
        {
            // Visibility is not stable across protection versions.
            if (!method.IsStatic)
                return false;

            //takes int, returns string
            if (method.MethodSig == null || method.MethodSig.Params.Count != 1 ||
                method.MethodSig.RetType.ElementType != ElementType.String ||
                method.MethodSig.Params[0].ElementType != ElementType.I4)
                return false;

            //actually a proper method, not abstract or from an interface
            if (!method.HasBody || !method.Body.HasInstructions)
                return false;

            //calls the second resolve method (used if string isn't in cache)
            if (!method.Body.Instructions.Any(a => a.OpCode.Code == Code.Call && a.Operand is IMethod m
                && m.DeclaringType.FullName == method.DeclaringType.FullName
                && m.MethodSig != null && !m.MethodSig.HasThis && m.MethodSig.Params.Count == 2
                && m.MethodSig.RetType.ElementType == ElementType.String
                && m.MethodSig.Params[0].ElementType == ElementType.I4
                && m.MethodSig.Params[1].ElementType == ElementType.Boolean
                && !IsNumericFormatter(m.ResolveMethodDef())))
                return false;
            return true;
        }

        // Percent and fixed-point unit formatters share the entry-point signature.
        // A state-free floating-point formatter is not an encrypted-string cache.
        private static bool IsNumericFormatter(MethodDef method)
        {
            if (method == null || !method.HasBody) return false;
            var il = method.Body.Instructions;
            if (il.Any(i => i.OpCode.Code == Code.Ldfld || i.OpCode.Code == Code.Ldsfld ||
                i.OpCode.Code == Code.Ldflda || i.OpCode.Code == Code.Ldsflda ||
                i.OpCode.Code == Code.Stfld || i.OpCode.Code == Code.Stsfld || i.OpCode.Code == Code.Newarr ||
                i.OpCode.Code == Code.Newobj || i.OpCode.Code == Code.Xor ||
                i.OpCode.Code == Code.Shl || i.OpCode.Code == Code.Shr || i.OpCode.Code == Code.Shr_Un)) return false;
            bool floating = il.Any(i => i.OpCode.Code == Code.Ldc_R8 || i.OpCode.Code == Code.Conv_R8);
            bool formatting = il.Any(i => i.Operand is IMethod m &&
                ((m.DeclaringType.FullName == "System.String" && m.Name == "Format") ||
                 (m.DeclaringType.FullName == "System.Int32" && m.Name == "ToString")));
            return floating && formatting;
        }
    }
}
