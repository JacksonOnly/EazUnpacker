using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer.Processors
{
    internal class ResourceResolver : ProcessorBase
    {
        public List<Assembly> ResourceAssemblies = new List<Assembly>();
        private TypeDef _resourceResolver;
        private MethodDef _initMethod;
        private readonly bool _preferExisting;
        private HashSet<string> _originalNames;

        internal ResourceResolver(bool preferExisting = false) { _preferExisting = preferExisting; }

        internal static bool IsDetected(ModuleDef module) => module.GetTypes().Where(type => !type.IsGlobalModuleType)
            .Any(type => CanBeResourceResolver(type) && type.Methods.Count(CanBeInitMethod) == 1);

        protected override void InitializeInternal()
        {
            if (!Flags.ResResolverTok.IsNull)
                _resourceResolver = Ctx.Module.ResolveToken(Flags.ResResolverTok) as TypeDef ?? throw new Exception("ResourceResolver token set but token not found");
            else
                _resourceResolver = Ctx.Module.GetTypes().Where(type => !type.IsGlobalModuleType).SingleOrDefault(CanBeResourceResolver) ?? throw new ProtectionNotFoundException("No resource resolver event registration found");
            if (!Flags.ResInitTok.IsNull)
                _initMethod = Ctx.Module.ResolveToken(Flags.ResInitTok) as MethodDef ?? throw new Exception("InitMethod token set but method not found");
            else
                _initMethod = _resourceResolver.Methods.SingleOrDefault(CanBeInitMethod) ?? throw new Exception("Could not find unambiguous init method");
        }

        protected override void ProcessInternal()
        {
            _originalNames = new HashSet<string>(Ctx.Module.Resources.Select(resource => resource.Name.String), StringComparer.Ordinal);
            var init = Utils.FindMethod(Ctx.Assembly, _initMethod, Type.EmptyTypes) ?? throw new Exception("Could not find init method through reflection");
            init.Invoke(null, null);
            var dictionaries = init.DeclaringType.GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)
                .Where(field => typeof(IDictionary).IsAssignableFrom(field.FieldType))
                .Select(field => field.GetValue(null) as IDictionary).Where(dictionary => dictionary != null).ToArray();
            if (dictionaries.Length == 0) throw new Exception("No initialized resource dictionary found");
            int entries = 0, extracted = 0, duplicates = 0;
            foreach (var dictionary in dictionaries)
                foreach (var entry in dictionary.Values)
                {
                    entries++;
                    try
                    {
                        var assembly = entry as Assembly;
                        if (assembly == null && entry != null)
                        {
                            var getters = entry.GetType().GetMethods(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)
                                .Where(method => !method.IsConstructor && method.ReturnType == typeof(Assembly) && method.GetParameters().Length == 0).ToArray();
                            if (getters.Length != 1) throw new Exception("Resource entry has no unambiguous assembly getter");
                            assembly = getters[0].Invoke(entry, null) as Assembly;
                        }
                        if (assembly == null) throw new Exception("Resource entry returned no assembly");
                        if (!ResourceAssemblies.Contains(assembly)) ResourceAssemblies.Add(assembly);
                    }
                    catch (Exception error) { Warn("Resource assembly entry " + entries + ": " + error.GetBaseException().Message); }
                }
            foreach (var assembly in ResourceAssemblies)
                foreach (var module in assembly.GetModules())
                    try
                    {
                        using (var recovered = ModuleDefMD.Load(module))
                            foreach (var resource in recovered.Resources)
                            {
                                // A resource editor can intentionally shadow a
                                // protected payload with a direct manifest entry.
                                if (_preferExisting && _originalNames.Contains(resource.Name.String))
                                { duplicates++; continue; }
                                if (TryAddRecoveredResource(Ctx.Module, resource, out var error)) extracted++;
                                else if (error == null) duplicates++;
                                else Warn(error);
                            }
                    }
                    catch (Exception error) { Warn("Resource module " + module.Name + ": " + error.GetBaseException().Message); }
            Summary = "Read " + entries + " resource manifest entries; loaded " + ResourceAssemblies.Count + " assembly(s); added " + extracted +
                " resource(s), ignored " + duplicates + " identical duplicate(s). Resolver types preserved.";
        }

        internal static bool TryAddRecoveredResource(ModuleDef module, Resource resource, out string error)
        {
            error = null;
            if (!(resource is EmbeddedResource embedded))
            { error = "Unsupported linked resource retained: " + resource.Name; return false; }
            var bytes = embedded.CreateReader().ToArray();
            var existing = module.Resources.FirstOrDefault(item => item.Name == resource.Name);
            if (existing != null)
            {
                if (existing is EmbeddedResource old && old.CreateReader().ToArray().SequenceEqual(bytes)) return false;
                error = "Conflicting resource name retained without overwrite: " + resource.Name; return false;
            }
            module.Resources.Add(new EmbeddedResource(resource.Name, bytes, resource.Attributes));
            return true;
        }

        protected override void CleanupInternal()
        {
            // Failed/unknown entries still need the runtime resolver.
            if (WarningCount > 0) return;
            var instructions = Ctx.Module.GlobalType?.FindStaticConstructor()?.Body?.Instructions;
            if (instructions != null)
                foreach (var instruction in instructions)
                    if (instruction.OpCode.Code == Code.Call && instruction.Operand is MethodDef method && method.DeclaringType == _resourceResolver)
                    { instruction.OpCode = OpCodes.Nop; instruction.Operand = null; }
            Ctx.Module.Types.Remove(_resourceResolver);
        }

        private static bool CanBeResourceResolver(TypeDef type) => type.Methods.Where(method => method.HasBody)
            .Any(method => method.Body.Instructions.Any(instruction => (instruction.OpCode.Code == Code.Callvirt || instruction.OpCode.Code == Code.Call)
                && instruction.Operand is IMethod called && called.Name == "add_ResourceResolve"));

        private static bool CanBeInitMethod(MethodDef method) => method.IsStatic && method.HasBody && method.MethodSig.Params.Count == 0 &&
            method.MethodSig.RetType.ElementType == ElementType.Void && method.Body.Instructions.Any(instruction => instruction.OpCode.Code == Code.Volatile);
    }
}
