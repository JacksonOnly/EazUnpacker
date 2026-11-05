using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using EazFixer;
using Newtonsoft.Json.Linq;

namespace Unpacker;

// Only families identified by a protection entry point are candidates. The
// graph still roots every unrelated type/member, including dead business IL.
internal static class ProtectionCleanupPass
{
    internal sealed class Outcome
    {
        internal int Types, Methods, Fields, Resources, Retained, AdapterCalls, IdentityReferences;
        internal bool Changed=>Types+Methods+Fields+Resources+AdapterCalls+IdentityReferences!=0;
    }

    private sealed class Hook(object owner,Instruction[] registration,string[] resources)
    {
        internal object Owner {get;}=owner;
        internal Instruction[] Registration {get;}=registration;
        internal string[] Resources {get;}=resources;
    }

    internal static Outcome Process(string input,string output,string original,SampleResult result,
        ModuleResourceRestore.Carrier? carrier,bool startupRestored)
    {
        using var module=ModuleDefMD.Load(input);
        using var evidence=ModuleDefMD.Load(original);
        var graph=new ReferenceGraph(module);
        var seeds=new HashSet<object>();
        var resources=new List<(string Name,object[] Owners)>();
        var hooks=new List<Hook>();
        var names=new HashSet<string>(module.Resources.Select(r=>r.Name.String),StringComparer.Ordinal);
        void Register(string? name,params object?[] owners)
        {
            var proven=owners.OfType<object>().Distinct().ToArray();
            if(proven.Length==0)return;
            seeds.UnionWith(proven);
            if(name!=null && names.Contains(name))resources.Add((name,proven));
        }

        foreach(var wrapper in StringFixUtils.FindStringDecryptMethods(evidence))
        {
            string? name=StringFixUtils.FindDecoderResource(wrapper);
            if(name==null || !names.Contains(name) || module.ResolveToken(wrapper.MDToken.Raw) is not MethodDef current ||
                current.DeclaringType.FullName!=wrapper.DeclaringType.FullName)continue;
            Register(name,graph.Owner(current));
        }
        foreach(var type in module.GetTypes().Where(t=>!t.IsGlobalModuleType))
        foreach(var getter in type.Methods.Where(m=>m.IsStatic && m.HasBody && m.MethodSig is {Params.Count:0} s &&
            s.RetType.FullName=="System.IO.Stream" && Calls(m,"System.Reflection.Assembly","GetManifestResourceStream")))
        {
            var namesRead=getter.Body.Instructions.Where(i=>i.OpCode.Code==Code.Ldstr && i.Operand is string name && names.Contains(name))
                .Select(i=>(string)i.Operand).Distinct().ToArray();
            var runtimes=type.Methods.Where(m=>m.IsStatic && m.MethodSig is {Params.Count:0})
                .Select(m=>graph.LocalType(m.MethodSig.RetType.ToTypeDefOrRef()))
                .OfType<TypeDef>().Where(IsVmRuntime).Distinct().ToArray();
            if(namesRead.Length==1 && runtimes.Length==1)
                Register(namesRead[0],graph.Owner(getter),graph.Owner(runtimes[0]));
        }
        if(startupRestored)
            foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.IsStatic && m.HasBody &&
                Calls(m,"System.Runtime.InteropServices.Marshal","GetHINSTANCE") &&
                Calls(m,"System.Runtime.InteropServices.Marshal","Copy") &&
                Calls(m,"System.Security.Cryptography.MD5","Create")))
                Register(null,graph.Owner(method));

        var initializer=module.GlobalType?.FindStaticConstructor();
        if(initializer?.Body is { } body)
        {
            var il=body.Instructions;
            if(carrier!=null && module.ResolveToken(carrier.Handler) is MethodDef resourceHandler && names.Contains(carrier.Resource))
            {
                for(int i=0;i+4<il.Count;i++)
                {
                    if(!Call(il[i],"System.AppDomain","get_CurrentDomain") || il[i+1].OpCode.Code!=Code.Ldnull ||
                        il[i+2].OpCode.Code!=Code.Ldftn || il[i+2].Operand!=resourceHandler ||
                        !Call(il[i+3],"System.ResolveEventHandler",".ctor") ||
                        !Call(il[i+4],"System.AppDomain","add_ResourceResolve"))continue;
                    var sequence=il.Skip(i).Take(5).ToArray();
                    if(!HasIncomingBoundary(body,sequence.Skip(1)))hooks.Add(new Hook(graph.Owner(resourceHandler)!,sequence,new[]{carrier.Resource}));
                }
            }
            // Desktop CLR probes sibling assemblies by their original identity.
            // Modern hosts can require .deps.json entries; do not strip their loader.
            if(result.Before?.ModernRuntime==false && module.Kind!=ModuleKind.Dll)
            foreach(var call in il.Where(i=>i.OpCode.Code==Code.Call && i.Operand is MethodDef).ToArray())
            {
                var init=(MethodDef)call.Operand;
                var handler=FindRegistrar(init);
                if(handler==null || graph.Owner(init) is not TypeDef owner || graph.Owner(handler)!=owner)continue;
                string[] replaced=ResolverResources(module,result,handler,owner);
                if(replaced.Length!=0)
                {
                    var calls=module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody)
                        .SelectMany(m=>m.Body.Instructions).Where(i=>i.OpCode.Code==Code.Call && i.Operand==init).ToArray();
                    hooks.Add(new Hook(owner,calls,replaced));
                }
            }
        }
        foreach(var hook in hooks)seeds.Add(hook.Owner);
        var outcome=new Outcome();
        if(seeds.Count==0)return outcome;
        outcome.AdapterCalls=RecoveredAdapterCleanup.Process(module,Path.Combine(Path.GetDirectoryName(output)!,"vm-methods.json"),
            seeds.OfType<TypeDef>().Where(IsVmRuntime).ToArray());
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody))
        {
            var il=method.Body.Instructions;
            for(int i=0;i+2<il.Count;i++)
            {
                if(il[i].OpCode.Code!=Code.Ldtoken || il[i].Operand is not TypeDef type ||
                    !seeds.Contains(graph.Owner(type)!) || type==module.GlobalType ||
                    !Call(il[i+1],"System.Type","GetTypeFromHandle") ||
                    !(Call(il[i+2],"System.Type","get_Assembly") || Call(il[i+2],"System.Type","get_Module")))continue;
                var identityOwner=method.DeclaringType.IsGlobalModuleType
                    ? module.EntryPoint?.DeclaringType??module.Types.FirstOrDefault(t=>!t.IsGlobalModuleType && !seeds.Contains(t))
                    : method.DeclaringType;
                if(identityOwner==null)continue;
                il[i].Operand=identityOwner;
                outcome.IdentityReferences++;
            }
        }
        graph.Scan(new HashSet<Instruction>());
        var candidates=new HashSet<object>(seeds);
        var queue=new Queue<object>(seeds);
        while(queue.Count>0)
        {
            foreach(var target in graph.Edges[queue.Dequeue()])
            {
                bool eligible=target is TypeDef t && !t.IsPublic && !t.IsGlobalModuleType &&
                    t!=module.EntryPoint?.DeclaringType ||
                    target is FieldDef f && f.DeclaringType.IsGlobalModuleType && !f.IsPublic;
                if(eligible && candidates.Add(target))queue.Enqueue(target);
            }
        }
        var active=hooks.ToList();
        HashSet<object> removed;
        do
        {
            graph.Scan(new HashSet<Instruction>(active.SelectMany(h=>h.Registration)));
            var live=new HashSet<object>(graph.Edges.Keys.Where(n=>!candidates.Contains(n)));
            if(graph.Owner(module.EntryPoint) is { } entry)live.Add(entry);
            var roots=new Queue<object>(live);
            while(roots.Count>0)
                foreach(var target in graph.Edges[roots.Dequeue()])
                    if(live.Add(target))roots.Enqueue(target);
            removed=new HashSet<object>(candidates.Where(n=>!live.Contains(n)));
            if(active.RemoveAll(h=>!removed.Contains(h.Owner))==0)break;
        }while(true);

        foreach(var hook in active)
        {
            foreach(var instruction in hook.Registration){instruction.OpCode=OpCodes.Nop;instruction.Operand=null;}
            foreach(string name in hook.Resources)resources.Add((name,new[]{hook.Owner}));
        }
        foreach(string name in resources.Where(r=>r.Owners.All(removed.Contains) &&
            !graph.ResourceUsers(r.Name).Any(user=>!removed.Contains(user))).Select(r=>r.Name).Distinct())
        {
            var entries=module.Resources.Where(r=>r.Name==name && r is EmbeddedResource).ToArray();
            if(entries.Length==1){module.Resources.Remove(entries[0]);outcome.Resources++;}
        }
        foreach(var candidate in removed)
        {
            switch(candidate)
            {
                case TypeDef type:
                    outcome.Types+=CountTypes(type);
                    outcome.Methods+=CountMethods(type);
                    module.Types.Remove(type);
                    break;
                case MethodDef method:
                    method.DeclaringType.Methods.Remove(method);outcome.Methods++;
                    break;
                case FieldDef field:
                    field.DeclaringType.Fields.Remove(field);outcome.Fields++;
                    break;
            }
        }
        outcome.Retained=seeds.Count(n=>!removed.Contains(n));
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(output)!,"protection-cleanup.json"),
            Newtonsoft.Json.JsonConvert.SerializeObject(new
            {
                RemovedTypes=outcome.Types,RemovedMethods=outcome.Methods,RemovedFields=outcome.Fields,
                RemovedResources=outcome.Resources,RemovedAdapterSetup=outcome.AdapterCalls,
                Retained=seeds.Where(n=>!removed.Contains(n)).Select(n=>new
                {
                    Token=(n as IMDTokenProvider)?.MDToken.ToString(),
                    Incoming=graph.Edges.Where(p=>p.Value.Contains(n) && !removed.Contains(p.Key))
                        .Select(p=>(p.Key as IMDTokenProvider)?.MDToken.ToString()).ToArray()
                }).ToArray()
            },Newtonsoft.Json.Formatting.Indented));
        if(!outcome.Changed)return outcome;
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody && m.Body.MaxStack>0))
            method.Body.KeepOldMaxStack=true;
        var tokens=module.GetTypes().SelectMany(t=>t.Methods).ToDictionary(m=>m,m=>m.MDToken.Raw);
        var writer=new ModuleWriter(module,new ModuleWriterOptions(module));
        writer.Write(output);
        using(var verified=ModuleDefMD.Load(output))
            if(verified.GetTypes().Count()!=module.GetTypes().Count() ||
                verified.GetTypes().Sum(t=>t.Methods.Count)!=module.GetTypes().Sum(t=>t.Methods.Count) ||
                !verified.Resources.Select(r=>r.Name.String).SequenceEqual(module.Resources.Select(r=>r.Name.String),StringComparer.Ordinal))
                throw new InvalidDataException("保护残留清理后的元数据不一致。");
        var remap=tokens.ToDictionary(p=>p.Value,p=>0x06000000U|writer.Metadata.GetRid(p.Key));
        RemapVmReport(Path.Combine(Path.GetDirectoryName(output)!,"vm-methods.json"),remap);
        return outcome;
    }

    private static void RemapVmReport(string path,Dictionary<uint,uint> tokens)
    {
        if(!File.Exists(path))return;
        var report=JArray.Parse(File.ReadAllText(path));
        foreach(var entry in report.OfType<JObject>().ToArray())
        {
            string? host=(string?)entry["Token"];
            if(host!=null && TryToken(host,out uint hostToken) && !tokens.ContainsKey(hostToken))
            {
                // A VM-protected protection helper can itself become dead.
                // Its restored business host does not exist in the final PE.
                entry.Remove();
                continue;
            }
            foreach(string name in new[]{"Token","HostToken","RecoveredAdapterToken"})
                if(entry[name]?.Type==JTokenType.String)entry[name]=Remap((string)entry[name]!);
            if(entry["AccessBridgeTokens"] is JArray bridges)
                for(int i=bridges.Count-1;i>=0;i--)
                {
                    string bridge=(string)bridges[i]!;
                    if(TryToken(bridge,out uint token) && !tokens.ContainsKey(token))bridges.RemoveAt(i);
                    else bridges[i]=Remap(bridge);
                }
        }
        string original=Path.Combine(Path.GetDirectoryName(path)!,"vm-methods-before-cleanup.json");
        if(!File.Exists(original))File.Copy(path,original);
        File.WriteAllText(path,report.ToString(Newtonsoft.Json.Formatting.Indented));
        string Remap(string value)
        {
            if(!TryToken(value,out uint token))return value;
            if(!tokens.TryGetValue(token,out uint mapped))throw new InvalidDataException("清理后的 VM 方法映射缺失。");
            return "0x"+mapped.ToString("X8");
        }
        static bool TryToken(string value,out uint token)
        {
            token=0;
            return value.StartsWith("0x",StringComparison.OrdinalIgnoreCase) &&
                uint.TryParse(value.Substring(2),System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture,out token);
        }
    }

    private static int CountTypes(TypeDef type)=>1+type.NestedTypes.Sum(CountTypes);
    private static int CountMethods(TypeDef type)=>type.Methods.Count+type.NestedTypes.Sum(CountMethods);

    private static bool IsVmRuntime(TypeDef type)=>type.Methods.Any(m=>m.MethodSig is {Params.Count:3} s &&
        s.RetType.ElementType==ElementType.Void && s.Params[0].FullName=="System.IO.Stream" &&
        s.Params[1].ElementType==ElementType.I8 && s.Params[2].ElementType==ElementType.String) &&
        type.Methods.Any(m=>m.MethodSig is {Params.Count:>=3} s && s.Params[0].FullName=="System.IO.Stream" &&
            s.Params[1].ElementType==ElementType.String && s.Params.Last().FullName=="System.Object[]");

    private static MethodDef? FindRegistrar(MethodDef init)
    {
        if(!init.IsStatic || !init.HasBody || init.MethodSig is not {Params.Count:0} sig ||
            sig.RetType.ElementType!=ElementType.Void || init.Body.ExceptionHandlers.Count!=0)return null;
        var il=init.Body.Instructions;
        var handles=il.Where(i=>i.OpCode.Code==Code.Ldftn).Select(i=>i.Operand).OfType<MethodDef>().ToArray();
        if(handles.Length!=1 || !handles[0].IsStatic || !handles[0].HasBody ||
            il.Count(i=>Call(i,"System.AppDomain","add_AssemblyResolve"))!=1)return null;
        foreach(var i in il)
        {
            if(i.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj)
            {
                if(!Call(i,"System.AppDomain","get_CurrentDomain") && !Call(i,"System.ResolveEventHandler",".ctor") &&
                    !Call(i,"System.AppDomain","add_AssemblyResolve"))return null;
            }
            else if(i.Operand is IField f && f.DeclaringType.FullName!=init.DeclaringType.FullName)return null;
            else if(i.OpCode.Code is Code.Stfld or Code.Stobj or Code.Stind_I or Code.Stind_Ref or Code.Throw or Code.Calli)
                return null;
        }
        return handles[0];
    }

    private static string[] ResolverResources(ModuleDef module,SampleResult result,MethodDef handler,TypeDef owner)
    {
        var raw=new HashSet<string>(result.EmbeddedAssemblies.Where(e=>e.Format=="raw" &&
            new System.Reflection.AssemblyName(e.Identity).CultureName is "" or null).Select(e=>e.Resource),StringComparer.Ordinal);
        var available=module.Resources.OfType<EmbeddedResource>().Select(r=>r.Name.String).ToArray();
        if(raw.Count!=0 && Calls(handler,"System.Reflection.Assembly","GetManifestResourceStream") &&
            Calls(handler,"System.Reflection.Assembly","Load") && Calls(handler,"System.Convert","ToBase64String"))
        {
            var prefixes=handler.Body.Instructions.Where(i=>i.OpCode.Code==Code.Ldstr && i.Operand is string s && s.Length>=4)
                .Select(i=>(string)i.Operand).Where(s=>raw.All(r=>r.StartsWith(s,StringComparison.Ordinal)))
                .Distinct().ToArray();
            if(prefixes.Length==1 && available.Where(n=>n.StartsWith(prefixes[0],StringComparison.Ordinal)).All(raw.Contains))
                return raw.ToArray();
        }
        var costura=new HashSet<string>(result.EmbeddedAssemblies.Where(e=>e.Format=="costura" &&
            new System.Reflection.AssemblyName(e.Identity).CultureName is "" or null &&
            (e.Resource.Equals("costura."+Path.GetFileName(e.File),StringComparison.OrdinalIgnoreCase) ||
             e.Resource.Equals("costura."+Path.GetFileName(e.File)+".compressed",StringComparison.OrdinalIgnoreCase)))
            .Select(e=>e.Resource),StringComparer.Ordinal);
        if(costura.Count!=0 && owner.Namespace=="Costura" &&
            available.Where(n=>n.StartsWith("costura.",StringComparison.OrdinalIgnoreCase)).All(costura.Contains))
            return costura.ToArray();

        var eaz=result.EmbeddedAssemblies.Where(e=>e.Format=="eaz" &&
            new System.Reflection.AssemblyName(e.Identity).CultureName is "" or null).Select(e=>e.Resource).Distinct().ToArray();
        if(eaz.Length!=0 && result.Stages.Any(s=>s.Name=="AssemblyResolver" && s.Status=="success") &&
            Descendants(owner).SelectMany(t=>t.Methods).Any(m=>m.Overrides.Any(o=>
                o.MethodDeclaration.DeclaringType.FullName=="System.Collections.IEnumerator" && o.MethodDeclaration.Name=="MoveNext")))
            return eaz;
        return Array.Empty<string>();
    }

    private static IEnumerable<TypeDef> Descendants(TypeDef owner)
    {
        yield return owner;
        foreach(var type in owner.NestedTypes)
            foreach(var child in Descendants(type))yield return child;
    }

    private static bool Calls(MethodDef method,string type,string name)=>
        method.Body.Instructions.Any(i=>Call(i,type,name));
    private static bool Call(Instruction i,string type,string name)=>
        i.Operand is IMethod m && m.Name==name && m.DeclaringType.FullName==type;

    private static bool HasIncomingBoundary(CilBody body,IEnumerable<Instruction> sequence)
    {
        var set=new HashSet<Instruction>(sequence);
        return body.Instructions.Any(i=>i.Operand is Instruction target && set.Contains(target) ||
            i.Operand is IList<Instruction> targets && targets.Any(set.Contains)) ||
            body.ExceptionHandlers.Any(h=>new[]{h.TryStart,h.TryEnd,h.HandlerStart,h.HandlerEnd,h.FilterStart}
                .Any(i=>i!=null && set.Contains(i)));
    }

    private sealed class ReferenceGraph
    {
        private readonly ModuleDefMD module;
        private readonly TypeDef[] types;
        private readonly Dictionary<string,TypeDef> local;
        private readonly Dictionary<string,HashSet<object>> resourceUsers;
        internal Dictionary<object,HashSet<object>> Edges {get;}=new();

        internal ReferenceGraph(ModuleDefMD module)
        {
            this.module=module;
            types=module.GetTypes().ToArray();
            local=types.GroupBy(t=>t.FullName).Where(g=>g.Count()==1).ToDictionary(g=>g.Key,g=>g.First());
            foreach(var type in types)
                foreach(string key in new[]{type.ReflectionFullName,type.FullName})if(!local.ContainsKey(key))local.Add(key,type);
            resourceUsers=module.Resources.Select(r=>r.Name.String).Distinct().ToDictionary(n=>n,n=>new HashSet<object>());
            Scan(new HashSet<Instruction>());
        }

        internal TypeDef? LocalType(ITypeDefOrRef? type)
        {
            if(type is TypeDef definition)return definition.Module==module?definition:null;
            if(type==null || type.DefinitionAssembly?.FullName!=module.Assembly?.FullName)return null;
            return local.TryGetValue(type.FullName,out var found)?found:null;
        }

        internal object? Owner(IMemberDef? member)
        {
            if(member==null)return null;
            TypeDef? type=member as TypeDef??member.DeclaringType;
            if(type==null)return null;
            if(type.IsGlobalModuleType)return member;
            while(type.DeclaringType!=null)type=type.DeclaringType;
            return type;
        }

        internal IEnumerable<object> ResourceUsers(string name)=>resourceUsers.TryGetValue(name,out var users)?users:Array.Empty<object>();

        internal void Scan(HashSet<Instruction> ignored)
        {
            Edges.Clear();
            foreach(var users in resourceUsers.Values)users.Clear();
            foreach(var type in types)
            {
                var node=Owner(type)!;
                Ensure(node);
                Ref(node,type.BaseType);
                Attributes(node,type.CustomAttributes);
                foreach(var impl in type.Interfaces){Ref(node,impl.Interface);Attributes(node,impl.CustomAttributes);}
                Generic(node,type.GenericParameters);
                foreach(var field in type.Fields)
                {
                    var origin=Owner(field)!;Ensure(origin);
                    Signature(origin,field.FieldType);
                    Attributes(origin,field.CustomAttributes);
                }
                foreach(var property in type.Properties)
                {
                    Signature(node,property.PropertySig.RetType);
                    foreach(var arg in property.PropertySig.Params)Signature(node,arg);
                    Attributes(node,property.CustomAttributes);
                }
                foreach(var ev in type.Events){Ref(node,ev.EventType);Attributes(node,ev.CustomAttributes);}
                foreach(var method in type.Methods)
                {
                    var origin=Owner(method)!;Ensure(origin);
                    MethodSignature(origin,method.MethodSig);
                    Attributes(origin,method.CustomAttributes);
                    Generic(origin,method.GenericParameters);
                    foreach(var p in method.ParamDefs)Attributes(origin,p.CustomAttributes);
                    foreach(var impl in method.Overrides){Ref(origin,impl.MethodBody);Ref(origin,impl.MethodDeclaration);}
                    if(!method.HasBody)continue;
                    foreach(var loc in method.Body.Variables)Signature(origin,loc.Type);
                    foreach(var eh in method.Body.ExceptionHandlers)Ref(origin,eh.CatchType);
                    foreach(var i in method.Body.Instructions.Where(i=>!ignored.Contains(i)))Ref(origin,i.Operand);
                }
            }
            Ensure(module);
            Attributes(module,module.CustomAttributes);
            if(module.Assembly!=null)Attributes(module,module.Assembly.CustomAttributes);
        }

        private void Ensure(object node)
        {
            if(!Edges.ContainsKey(node))Edges.Add(node,new HashSet<object>());
        }

        private void Add(object origin,IMemberDef? member)
        {
            var target=Owner(member);
            if(target==null || target==origin)return;
            Ensure(target);
            Edges[origin].Add(target);
        }

        private void Ref(object origin,object? value)
        {
            switch(value)
            {
                case TypeSpec spec: Signature(origin,spec.TypeSig);break;
                case ITypeDefOrRef type: Add(origin,LocalType(type));break;
                case MethodSpec generic:
                    Ref(origin,generic.Method);
                    if(generic.Instantiation is GenericInstMethodSig instance)
                        foreach(var arg in instance.GenericArguments)Signature(origin,arg);
                    break;
                case IMethod method when method is not MemberRef {IsFieldRef:true}:
                    Ref(origin,method.DeclaringType);
                    if(method is MethodDef definition)Add(origin,definition);
                    else if(LocalType(method.DeclaringType)?.IsGlobalModuleType==true)Add(origin,method.ResolveMethodDef());
                    MethodSignature(origin,method.MethodSig);
                    break;
                case IField field:
                    Ref(origin,field.DeclaringType);
                    if(field is FieldDef definitionField)Add(origin,definitionField);
                    else if(LocalType(field.DeclaringType)?.IsGlobalModuleType==true)Add(origin,field.ResolveFieldDef());
                    Signature(origin,field.FieldSig?.Type);
                    break;
                case MethodSig sig:MethodSignature(origin,sig);break;
                case TypeSig sig:Signature(origin,sig);break;
                case string text:
                    if(resourceUsers.TryGetValue(text,out var users))users.Add(origin);
                    if(local.TryGetValue(text,out var matched))Add(origin,matched);
                    else if(text.IndexOf(',') is int comma && comma>0 &&
                        local.TryGetValue(text.Substring(0,comma).Trim(),out matched))Add(origin,matched);
                    break;
                case UTF8String utf8:Ref(origin,utf8.String);break;
                case IList<CAArgument> arguments:
                    foreach(var argument in arguments){Signature(origin,argument.Type);Ref(origin,argument.Value);}
                    break;
            }
        }

        private void Signature(object origin,TypeSig? signature)
        {
            if(signature==null)return;
            if(signature is TypeDefOrRefSig named)Ref(origin,named.TypeDefOrRef);
            if(signature is GenericInstSig generic)
            {
                Signature(origin,generic.GenericType);
                foreach(var arg in generic.GenericArguments)Signature(origin,arg);
            }
            if(signature is ModifierSig mod)Ref(origin,mod.Modifier);
            if(signature is FnPtrSig pointer)MethodSignature(origin,pointer.MethodSig);
            Signature(origin,signature.Next);
        }

        private void MethodSignature(object origin,MethodSig? signature)
        {
            if(signature==null)return;
            Signature(origin,signature.RetType);
            foreach(var arg in signature.Params)Signature(origin,arg);
            if(signature.ParamsAfterSentinel!=null)foreach(var arg in signature.ParamsAfterSentinel)Signature(origin,arg);
        }

        private void Attributes(object origin,IEnumerable<CustomAttribute> attributes)
        {
            foreach(var attr in attributes)
            {
                Ref(origin,attr.Constructor);
                foreach(var arg in attr.ConstructorArguments){Signature(origin,arg.Type);Ref(origin,arg.Value);}
                foreach(var arg in attr.NamedArguments){Signature(origin,arg.Type);Ref(origin,arg.Argument.Value);}
            }
        }

        private void Generic(object origin,IEnumerable<GenericParam> parameters)
        {
            foreach(var param in parameters)
            {
                Attributes(origin,param.CustomAttributes);
                foreach(var constraint in param.GenericParamConstraints)
                {Ref(origin,constraint.Constraint);Attributes(origin,constraint.CustomAttributes);}
            }
        }
    }
}
