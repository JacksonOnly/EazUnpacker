using System.Globalization;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Pdb;
using dnlib.DotNet.Writer;
using Newtonsoft.Json;

namespace Unpacker;

internal sealed class NameChange
{
    public string Kind { get; set; } = "";
    public string Token { get; set; } = "";
    public string Original { get; set; } = "";
    public string Renamed { get; set; } = "";
    public string Type { get; set; } = "";
    public string Evidence { get; set; } = "";
}

internal static class NameRecoveryPass
{
    private static readonly HashSet<string> Keywords = new("abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while".Split(' '));

    internal static bool NeedsName(string? name, bool genericType = false)
    {
        if (string.IsNullOrEmpty(name)) return true;
        if (genericType) name = Regex.Replace(name!, @"`\d+$", "");
        if (name!.StartsWith("#=") || name.StartsWith("<") || Keywords.Contains(name)) return true;
        if(Regex.IsMatch(name,@"^[acfmv]\d{5,}$"))return true;
        if(name.Length>=64&&name.Count(char.IsDigit)>=name.Length/8&&name.Count(char.IsUpper)>=name.Length/8)return true;
        if (!(name[0] == '_' || char.IsLetter(name[0]))) return true;
        if (name.Any(c => c > 127 || !(c == '_' || char.IsLetterOrDigit(c)))) return true;
        if(Regex.IsMatch(name,@"^[A-Za-z_][A-Za-z0-9_]*(?:Field[0-9A-F]{4,}|Argument\d+|Local\d+)_*$"))return false;
        return name.Length >= 24 && name.Count(char.IsUpper) >= 6 && name.Count(char.IsLower) >= 6
            && name.Zip(name.Skip(1), (a,b) => char.IsUpper(a) != char.IsUpper(b)).Count(x => x) >= 12;
    }

    internal static int Process(string input, string output, string mapPath)
    {
        using var module = ModuleDefMD.Load(input);
        var types = module.GetTypes().Where(t => !t.IsGlobalModuleType).ToArray();
        var changes = new List<NameChange>();
        bool preserveMarkupNames=MarkupNameGuard.RequiresStableNames(module);
        if(preserveMarkupNames)
            changes.Add(new NameChange {Kind="NamePreservation",Evidence=
                "Markup resources can bind types, members, events and property paths by name. Retained metadata names until all markup references can be rewritten; parameter and PDB local naming remains enabled."});
        SafeProxyPass.Process(module,Path.Combine(Path.GetDirectoryName(mapPath)!,"safe-proxies.json"));
        InlineExpressionPass.Process(module,Path.Combine(Path.GetDirectoryName(mapPath)!,"inline-expressions.json"));
        // Fold literal conditional branches before per-method PDB scopes are
        // materialized, so a folded-away first instruction cannot leave a stale
        // scope start. This shares the single final write below, which keeps the
        // adjusted max-stack values authoritative without an extra serialization.
        var flowStats=ControlFlowCleanupPass.Clean(module);
        RestoreAccessorMetadata(types,changes);
        RestoreInheritedProperties(types,changes);
        RepairAttributeTargets(module,types,changes);
        var originalTypes = types.ToDictionary(t => t, t => t.FullName);
        var originalReflectionNames = types.ToDictionary(t => t, t => t.ReflectionFullName);
        var attributeTypes=new List<(IHasCustomAttribute Owner,int Index,CustomAttribute Attribute,TypeDef Definition)>();
        foreach(var owner in GetAttributeOwners(module,types))
        for(int index=0;index<owner.CustomAttributes.Count;index++)
        {
            var attribute=owner.CustomAttributes[index];
            if(attribute.Constructor.MethodSig.Params.Count!=1 || attribute.Constructor.MethodSig.Params[0].FullName!="System.Type")continue;
            byte[] blob=attribute.IsRawBlob?attribute.RawData:module.BlobStream.Read(attribute.BlobOffset);
            if(blob.Length<5 || blob[0]!=1 || blob[1]!=0)continue;
            int cursor=2;uint length=blob[cursor++];
            if(length==255)continue;
            if((length&128)!=0)length=(length&64)==0?(length&63)<<8|blob[cursor++]:
                (length&31)<<24|(uint)blob[cursor++]<<16|(uint)blob[cursor++]<<8|blob[cursor++];
            if(length>blob.Length-cursor-2)continue;
            string value=System.Text.Encoding.UTF8.GetString(blob,cursor,(int)length);
            string name=value.Split(',')[0];
            var definition=types.FirstOrDefault(t=>originalReflectionNames[t]==name);
            if(definition==null)
            {
                string normalized=Regex.Replace(name,@"`\d+","");
                var candidates=types.Where(t=>Regex.Replace(originalReflectionNames[t],@"`\d+","") is var reflected && (reflected==normalized||reflected.EndsWith("."+normalized,StringComparison.Ordinal))).ToArray();
                if(owner is MethodDef {HasBody:true} method)
                {
                    var locals=method.Body.Variables.Select(l=>l.Type.ToTypeDefOrRef()?.ResolveTypeDef())
                        .Concat(method.Body.Instructions.Select(i=>i.Operand).OfType<IMethod>().Select(m=>m.DeclaringType.ResolveTypeDef())).ToArray();
                    definition=candidates.FirstOrDefault(locals.Contains);
                }
                if(definition==null && candidates.Length==1)definition=candidates[0];
            }
            if(definition!=null && blob[cursor+(int)length]==0 && blob[cursor+(int)length+1]==0)
                attributeTypes.Add((owner,index,attribute,definition));
        }
        var typeIndex=types.ToDictionary(t=>t.FullName);
        TypeDef? OwnType(ITypeDefOrRef? reference)
        {
            if(reference is TypeDef definition && definition.Module==module)return definition;
            if(reference is TypeSpec {TypeSig:GenericInstSig genericInstance})return OwnType(genericInstance.GenericType.TypeDefOrRef);
            if(reference==null || reference.DefinitionAssembly?.FullName!=module.Assembly.FullName)return null;
            if(typeIndex.TryGetValue(reference.FullName,out var direct))return direct;
            return null;
        }
        var comparer=new SigComparer(SigComparerOptions.DontCompareTypeScope);
        MethodDef? OwnMethod(MemberRef reference)
        {
            var type=OwnType(reference.DeclaringType);
            while(type!=null && type.Module==module)
            {
                var arguments=(reference.DeclaringType as TypeSpec)?.TypeSig is GenericInstSig instance?instance.GenericArguments:Array.Empty<TypeSig>();
                var matches=type.Methods.Where(m=>m.Name==reference.Name && (comparer.Equals(m.MethodSig,reference.MethodSig)||comparer.Equals(CloseSignature(m.MethodSig,arguments),reference.MethodSig))).ToArray();
                if(matches.Length==1)return matches[0];
                type=OwnType(type.BaseType);
            }
            return null;
        }
        FieldDef? OwnField(MemberRef reference)=>OwnType(reference.DeclaringType)?.Fields.FirstOrDefault(f=>f.Name==reference.Name && comparer.Equals(f.FieldSig,reference.FieldSig));
        var hints=new ReadableNameHints(module,OwnField,OwnMethod);
        var typeReferences = module.GetTypeRefs().Concat(AttributeTypeReferences(GetAttributeOwners(module,types).SelectMany(o=>o.CustomAttributes)))
            .Distinct().Select(r => (Reference:r, Definition:OwnType(r))).Where(p => p.Definition!=null).ToArray();
        // dnlib materializes separate MemberRef objects for different generic
        // contexts. Update the objects actually used by bodies and MethodImpls.
        var allMethods=types.SelectMany(t=>t.Methods).ToArray();
        var operands=allMethods.Where(m=>m.HasBody).SelectMany(m=>m.Body.Instructions).Select(i=>i.Operand).ToArray();
        var references=module.GetMemberRefs().Concat(operands.OfType<MemberRef>())
            .Concat(operands.OfType<MethodSpec>().Select(m=>m.Method).OfType<MemberRef>())
            .Concat(allMethods.SelectMany(m=>m.Overrides).SelectMany(o=>new[]{o.MethodDeclaration,o.MethodBody}).OfType<MemberRef>()).Distinct().ToArray();
        var methodReferences = references.Where(r => r.IsMethodRef).Select(r => (Reference:r, Definition:OwnMethod(r))).Where(p => p.Definition!=null).ToArray();
        var fieldReferences = references.Where(r => r.IsFieldRef).Select(r => (Reference:r, Definition:OwnField(r))).Where(p => p.Definition!=null).ToArray();
        var originalMethods = types.SelectMany(t => t.Methods).ToDictionary(m => m, m => m.Name.String);
        var originalFields = types.SelectMany(t => t.Fields).ToDictionary(f => f, f => f.Name.String);
        var originalProperties = types.SelectMany(t => t.Properties).ToDictionary(p => p, p => p.Name.String);
        var originalEvents = types.SelectMany(t => t.Events).ToDictionary(e => e, e => e.Name.String);
        foreach(var constructor in GetAttributeOwners(module,types).SelectMany(o=>o.CustomAttributes)
            .Select(a=>a.Constructor as MethodDef).OfType<MethodDef>().Distinct())
        {
            if(!originalMethods.ContainsKey(constructor) || constructor.IsConstructor || constructor.IsStatic ||
                !constructor.IsRuntimeSpecialName || !constructor.IsSpecialName || !constructor.HasBody ||
                constructor.MethodSig.RetType.ElementType!=ElementType.Void ||
                constructor.DeclaringType.Methods.Any(m=>m.IsInstanceConstructor && comparer.Equals(m.MethodSig,constructor.MethodSig)) ||
                !constructor.Body.Instructions.Any(i=>i.OpCode.Code==Code.Call && i.Operand is IMethod called &&
                    called.Name==".ctor" && called.DeclaringType.FullName==constructor.DeclaringType.BaseType?.FullName))
                continue;
            string old=constructor.Name.String;
            constructor.Name=".ctor";
            Add(changes,"Method",constructor,old,".ctor",evidence:"custom-attribute metadata and base constructor call");
        }
        var namedArguments = GetAttributeOwners(module, types).SelectMany(p => p.CustomAttributes).SelectMany(a => a.NamedArguments.Select(n => (Argument:n, Type:OwnType(a.AttributeType))))
            .Where(p => p.Type?.Module == module).Select(p => (p.Argument, Member:p.Argument.IsField
                ? (IMemberDef?)p.Type!.Fields.FirstOrDefault(f => f.Name == p.Argument.Name)
                : p.Type!.Properties.FirstOrDefault(f => f.Name == p.Argument.Name))).Where(p => p.Member != null).ToArray();
        var namespaces = new Dictionary<string,string>();
        // Large vendor assemblies have tens of thousands of top-level types.
        // Re-enumerating all their names for each rename is quadratic. Reserve
        // each scope once; generated legal names can never reuse an obfuscated
        // original name, so retaining the old reservations is conservative.
        var topLevelNames=module.Types.GroupBy(t=>t.Namespace.String)
            .ToDictionary(g=>g.Key,g=>new HashSet<string>(g.Select(t=>t.Name.String)));
        var nestedNames=types.Where(t=>t.DeclaringType!=null).GroupBy(t=>t.DeclaringType)
            .ToDictionary(g=>g.Key,g=>new HashSet<string>(g.Select(t=>t.Name.String)));
        var groups = BuildMethodGroups(types);
        var methodGroups=groups.SelectMany(g=>g.Select(m=>(Method:m,Group:g))).ToDictionary(p=>p.Method,p=>p.Group);
        var propertyNames=BuildPropertyContractNames(types,methodGroups,originalProperties);
        foreach (var type in types)
        {
            if(type.IsNested && !type.IsNestedPublic)
            {Add(changes,"TypeVisibility",type,type.Visibility.ToString(),TypeAttributes.NestedPublic.ToString());type.Visibility=TypeAttributes.NestedPublic;}
            if(type.IsSealed && !type.IsValueType && type.BaseType?.FullName!="System.MulticastDelegate" && type.Methods.Any(m=>m.IsVirtual && m.IsNewSlot && m.Overrides.Count==0))
            {Add(changes,"TypeModifier",type,"sealed","unsealed");type.IsSealed=false;}
            string original = type.Name.String;
            bool entryType=module.EntryPoint?.DeclaringType==type;
            if (!preserveMarkupNames && (entryType || NeedsName(original, true) || IsGeneratedTypeName(original)))
            {
                string suffix = type.GenericParameters.Count>0?"`"+type.GenericParameters.Count:Regex.Match(original, @"`\d+$").Value;
                var hint=hints.Get(type);
                var used=type.DeclaringType==null?topLevelNames[type.Namespace.String]:nestedNames[type.DeclaringType];
                string? inherited=BaseTypeStem(type);
                string stem=entryType?"Program":hint?.Name??inherited??TypePrefix(type)+type.MDToken.Rid.ToString(CultureInfo.InvariantCulture);
                used.Remove(original);
                string proposed=stem+suffix;int collision=2;
                while(!used.Add(proposed))proposed=stem+collision++.ToString(CultureInfo.InvariantCulture)+suffix;
                type.Name=proposed;
                if(original!=proposed)Add(changes, "Type", type, originalTypes[type], type.FullName,evidence:entryType?"CLI entry-point declaring type; generated-role":hint?.Evidence??(inherited!=null?"declared base-type name; generated-role":"category numbered fallback; original-name-unavailable"));
            }
            if (!preserveMarkupNames && type.DeclaringType == null && type.Namespace.String.Split('.').Any(n => n.Length > 0 && NeedsName(n)))
            {
                string ns = type.Namespace.String;
                if (!namespaces.TryGetValue(ns, out string newNamespace)) namespaces.Add(ns, newNamespace = "Recovered.Namespace" + type.MDToken.Rid.ToString("X4"));
                type.Namespace = newNamespace;
                Add(changes, "Namespace", type, ns, newNamespace);
            }
            foreach (var parameter in type.GenericParameters)
                RenameGeneric(parameter, changes);
        }
        foreach (var group in groups)
        {
            if(preserveMarkupNames)continue;
            if (!group.Any(m => !m.IsConstructor && NeedsName(m.Name))) continue;
            var fixedName = group.FirstOrDefault(m => !NeedsName(m.Name) && !m.IsConstructor)?.Name.String;
            var proposals=group.Select(hints.Get).Where(h=>h!=null).Select(h=>h!.Name).Distinct().ToArray();
            var role=proposals.Length==1?group.Select(hints.Get).First(h=>h?.Name==proposals[0]):null;
            string name = fixedName ?? Unique(role?.Name??"method_"+group.Min(m=>m.MDToken.Rid).ToString(CultureInfo.InvariantCulture),
                group.SelectMany(m=>m.DeclaringType.Methods.Where(o=>!group.Contains(o)).Select(o=>o.Name.String)
                    .Concat(m.DeclaringType.Fields.Select(f=>f.Name.String)).Concat(m.DeclaringType.NestedTypes.Select(t=>t.Name.String))));
            foreach (var method in group.Where(m => !m.IsConstructor))
            {
                // Explicit MethodImpl links preserve external interface contracts.
                // Implicit external overrides keep their existing legal contract names.
                method.Name = name;
                Add(changes, "Method", method, originalMethods[method], name,evidence:fixedName!=null?"existing dispatch contract":role?.Evidence??"numbered fallback; original-name-unavailable");
            }
        }
        if(!preserveMarkupNames && module.EntryPoint is { } entryPoint && NeedsName(originalMethods[entryPoint]))
        {
            entryPoint.Name="Main";
            foreach(var change in changes.Where(c=>c.Kind=="Method" && c.Token==entryPoint.MDToken.ToString())){change.Renamed="Main";change.Evidence="entry-point metadata";}
        }
        foreach (var type in types)
        {
            foreach (var field in type.Fields.Where(f => !preserveMarkupNames && (NeedsName(f.Name) || type.NestedTypes.Any(t=>t.Name==f.Name))))
            {
                var hint=hints.Get(field);
                string name = Unique(hint?.Name??"field_"+field.MDToken.Rid.ToString(CultureInfo.InvariantCulture), type.Fields.Where(f => f != field).Select(f => f.Name.String)
                    .Concat(type.Methods.Select(m=>m.Name.String)).Concat(type.NestedTypes.Select(t=>t.Name.String)).Concat(type.Properties.Select(p=>p.Name.String)));
                Add(changes, "Field", field, originalFields[field], name, field.FieldType.FullName,hint?.Evidence??"numbered fallback; original-name-unavailable"); field.Name = name;
            }
            foreach (var property in type.Properties)
            {
                if(preserveMarkupNames)continue;
                var externalAccessor=property.GetMethods.Concat(property.SetMethods).SelectMany(m=>m.Overrides).Select(o=>o.MethodDeclaration)
                    .FirstOrDefault(m=>(m.Name.String.StartsWith("get_")||m.Name.String.StartsWith("set_")) && OwnType(m.DeclaringType)==null);
                if(externalAccessor!=null && property.GetMethods.Concat(property.SetMethods).All(m=>m.IsPrivate))
                {
                    string interfaceName=externalAccessor.DeclaringType.FullName;
                    property.Name=interfaceName+"."+externalAccessor.Name.String.Substring(4);
                    RenameAccessor(property.GetMethod,interfaceName+".get_"+externalAccessor.Name.String.Substring(4));
                    RenameAccessor(property.SetMethod,interfaceName+".set_"+externalAccessor.Name.String.Substring(4));
                    continue;
                }
                if(!NeedsName(property.Name))continue;
                string name = propertyNames[property];
                Add(changes, "Property", property, originalProperties[property], name, property.PropertySig.RetType.FullName); property.Name = name;
                RenameAccessor(property.GetMethod, "get_"+name); RenameAccessor(property.SetMethod, "set_"+name);
            }
            foreach(var attribute in type.CustomAttributes.Where(a=>a.TypeFullName=="System.Reflection.DefaultMemberAttribute" && a.ConstructorArguments.Count==1))
            {
                string original=attribute.ConstructorArguments[0].Value?.ToString()??"";
                var property=type.Properties.FirstOrDefault(p=>originalProperties[p]==original);
                if(property!=null)attribute.ConstructorArguments[0]=new CAArgument(module.CorLibTypes.String,new UTF8String(property.Name));
            }
            foreach (var ev in type.Events.Where(e => !preserveMarkupNames && NeedsName(e.Name)))
            {
                string name = "Event" + ev.MDToken.Rid.ToString("X4");
                Add(changes, "Event", ev, originalEvents[ev], name); ev.Name = name;
                RenameAccessor(ev.AddMethod, "add_"+name); RenameAccessor(ev.RemoveMethod, "remove_"+name); RenameAccessor(ev.InvokeMethod, "raise_"+name);
            }
            foreach (var method in type.Methods)
            {
                foreach (var generic in method.GenericParameters) RenameGeneric(generic, changes);
                var indexer=type.Properties.FirstOrDefault(p=>p.PropertySig.Params.Count>0&&(p.GetMethods.Contains(method)||p.SetMethods.Contains(method)));
                int indexCount=indexer?.PropertySig.Params.Count??0;
                bool indexSetter=indexer?.SetMethods.Contains(method)==true;
                bool NeedsParameterRename(Parameter p)=>NeedsParameterName(p.Name)
                    || (indexer!=null&&p.MethodSigIndex<indexCount&&p.Name=="value")
                    || (indexSetter&&p.MethodSigIndex==indexCount&&p.Name!="value");
                var usedParameters=new HashSet<string>(method.Parameters.Where(p=>!p.IsHiddenThisParameter&&!p.IsReturnTypeParameter
                    && !NeedsParameterRename(p)).Select(p=>p.Name));
                if(indexer!=null)usedParameters.Add("value"); // implicit C# setter argument
                foreach (var parameter in method.Parameters.Where(p => !p.IsHiddenThisParameter && !p.IsReturnTypeParameter))
                {
                    if (!NeedsParameterRename(parameter)) continue;
                    bool eventParameter=hints.EventHandlers.Contains(method) && method.MethodSig.Params.Count==2
                        && method.MethodSig.Params[0].ElementType==ElementType.Object;
                    var parameterHint=hints.Get(parameter);
                    bool entryArgs=method==module.EntryPoint&&parameter.Type.FullName=="System.String[]";
                    bool setterValue=indexSetter&&parameter.MethodSigIndex==indexCount;
                    bool indexArgument=indexer!=null&&parameter.MethodSigIndex<indexCount;
                    string stem=setterValue?"value":indexArgument?(parameterHint?.Name is { } hint&&hint!="value"?hint:parameter.Type.ElementType==ElementType.String?"key":"index"):
                        parameterHint?.Name??(entryArgs?"args":eventParameter?(parameter.MethodSigIndex==0?"sender":"e"):ParameterStem(parameter.Type));
                    string name=stem;int collision=2;
                    if(!setterValue)while(!usedParameters.Add(name))name=stem+collision++.ToString(CultureInfo.InvariantCulture);
                    parameter.CreateParamDef();
                    var definition = parameter.ParamDef!;
                    Add(changes, "Parameter", method, parameter.Name, name, parameter.Type.FullName,parameterHint?.Evidence??(eventParameter?"event callback signature role":"actual CLR type plus argument index"));
                    definition.Name = name;
                }
                if (!method.HasBody || method.Body.Instructions.Count == 0) continue;
                IEnumerable<PdbLocal> DebugLocals(PdbScope? existing)
                {
                    if(existing==null)yield break;
                    foreach(var variable in existing.Variables)yield return variable;
                    foreach(var child in existing.Scopes)foreach(var variable in DebugLocals(child))yield return variable;
                }
                var originalLocals=DebugLocals(method.Body.PdbMethod?.Scope).Where(v=>v.Local!=null && !NeedsName(v.Name))
                    .GroupBy(v=>v.Local).ToDictionary(g=>g.Key,g=>g.Select(v=>v.Name).Distinct().ToArray());
                var localNames=new HashSet<string>(method.Parameters.Select(p=>p.Name));
                var scope = new PdbScope { Start = method.Body.Instructions[0] };
                method.Body.PdbMethod = new PdbMethod { Scope = scope };
                foreach (var local in method.Body.Variables)
                {
                    string name = TypeStem(local.Type) + "Local" + local.Index;
                    bool preserved=originalLocals.TryGetValue(local,out var oldNames) && oldNames.Length==1 && !localNames.Contains(oldNames[0]);
                    if(preserved)name=oldNames![0];
                    name=Unique(name,localNames);localNames.Add(name);
                    scope.Variables.Add(new PdbLocal(local, name, PdbLocalAttributes.None));
                    Add(changes, "Local", method, "V_" + local.Index, name, local.Type.FullName,preserved?"preserved unambiguous PDB local name":"actual CLR type plus local slot; generated-name");
                }
            }
        }
        foreach (var pair in typeReferences) {pair.Reference.Name=pair.Definition!.Name; pair.Reference.Namespace=pair.Definition.Namespace;}
        foreach(var pair in attributeTypes)
            pair.Owner.CustomAttributes[pair.Index]=new CustomAttribute(pair.Attribute.Constructor,new[]{new CAArgument(pair.Attribute.Constructor.MethodSig.Params[0],pair.Definition.ToTypeSig())});
        foreach (var pair in methodReferences) pair.Reference.Name=pair.Definition!.Name;
        foreach (var pair in fieldReferences) pair.Reference.Name=pair.Definition!.Name;
        foreach(var method in types.SelectMany(t=>t.Methods))
            foreach(var implementation in method.Overrides)
                if(implementation.MethodDeclaration is MemberRef reference)
                {
                    var cached=methodReferences.FirstOrDefault(p=>p.Reference==reference).Definition;
                    if(cached!=null)reference.Name=cached.Name;
                }
        foreach (var pair in namedArguments) pair.Argument.Name=pair.Member!.Name;

        var typeStrings = new Dictionary<string,string>();
        foreach (var type in types)
        {
            typeStrings[originalTypes[type]] = type.FullName;
            typeStrings[originalReflectionNames[type]] = type.ReflectionFullName;
        }
        var members = types.SelectMany(t => t.Methods.Select(m => (Old:originalMethods[m], New:m.Name.String, Type:t)))
            .Concat(types.SelectMany(t => t.Fields.Select(f => (Old:originalFields[f], New:f.Name.String, Type:t))))
            .Concat(types.SelectMany(t => t.Properties.Select(p => (Old:originalProperties[p], New:p.Name.String, Type:t))))
            .Concat(types.SelectMany(t => t.Events.Select(e => (Old:originalEvents[e], New:e.Name.String, Type:t))))
            .Where(p => p.Old != p.New).ToLookup(p => p.Old);
        foreach (var method in types.SelectMany(t=>t.Methods).Where(m=>m.HasBody))
        {
            var instructions=method.Body.Instructions;
            var dynamicNames=DynamicMemberNames(method.Body);
            for(int i=0;i<instructions.Count;i++)
            {
                if(instructions[i].OpCode.Code!=Code.Ldstr || instructions[i].Operand is not string value) continue;
                if(dynamicNames.TryGetValue(instructions[i],out var receiver))
                {
                    // Binder member names can be identical to unrelated type
                    // names. Update them only using the proven CallSite receiver.
                    if(OwnType(receiver.Type) is { } owner)
                    {
                        var alternatives=owner.Methods.Where(m=>originalMethods[m]==value &&
                            m.MethodSig.Params.Count==receiver.ArgumentCount).Select(m=>m.Name.String).Distinct().ToArray();
                        if(alternatives.Length==1)instructions[i].Operand=alternatives[0];
                    }
                    continue;
                }
                if(typeStrings.TryGetValue(value,out string typeName)) {instructions[i].Operand=typeName;continue;}
                int comma=value.IndexOf(',');
                if(comma>0 && typeStrings.TryGetValue(value.Substring(0,comma),out typeName)) {instructions[i].Operand=typeName+value.Substring(comma);continue;}
                var next=instructions.Skip(i+1).Take(6).FirstOrDefault(x=>x.Operand is IMethod called && called.DeclaringType.FullName=="System.Type" &&
                    called.Name.String is "GetMethod" or "GetField" or "GetProperty" or "GetEvent");
                if(next==null || !members.Contains(value))continue;
                var known=instructions.Take(i).Reverse().Take(15).Select(x=>x.Operand).OfType<ITypeDefOrRef>().Select(t=>t.ResolveTypeDef()).FirstOrDefault(t=>t?.Module==module);
                var candidates=members[value].Where(p=>known==null || p.Type==known).Select(p=>p.New).Distinct().ToArray();
                if(candidates.Length==1)instructions[i].Operand=candidates[0];
                else throw new NotSupportedException("Ambiguous reflective member name: "+method.FullName+". Preserve behavior before publishing renamed output.");
            }
        }
        foreach (var resource in module.Resources)
            foreach(var type in types.OrderByDescending(t=>originalTypes[t].Length))
                if(resource.Name.String.StartsWith(originalReflectionNames[type]+".",StringComparison.Ordinal))
                {resource.Name=type.ReflectionFullName+resource.Name.String.Substring(originalReflectionNames[type].Length);break;}
        if(module.PdbState==null)module.CreatePdbState(PdbFileKind.PortablePDB);
        // Reconstructed property rows cannot preserve their original row order.
        // Portable PDBs cannot reference the resulting PropertyPtr/EventPtr tables.
        AsyncRecoveryPass.Process(module,Path.Combine(Path.GetDirectoryName(mapPath)!,"async-recovery.json"));
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody))
        {
            // Async forwarding and string/proxy edits can move even an otherwise
            // untouched edge out of the short-branch range.
            method.Body.SimplifyBranches();method.Body.OptimizeBranches();
        }
        module.Write(output,new ModuleWriterOptions(module) {WritePdb=true,PdbOptions=PdbWriterOptions.Deterministic,
            PdbFileName=Path.ChangeExtension(output,".pdb"),PdbFileNameInDebugDirectory=Path.GetFileName(Path.ChangeExtension(output,".pdb")),
            MetadataOptions={Flags=MetadataFlags.PreserveAll & ~MetadataFlags.PreservePropertyRids & ~MetadataFlags.PreserveEventRids & ~MetadataFlags.PreserveParamRids}});
        PortablePdbCompatibility.Normalize(output,Path.ChangeExtension(output,".pdb"));
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(mapPath)!,"control-flow-cleanup.json"),JsonConvert.SerializeObject(new{
            FoldedBranches=flowStats.FoldedBranches,RemovedInstructions=flowStats.RemovedInstructions,Methods=flowStats.Methods,
            Preserved="Method/type definitions, metadata tokens, exception-region boundaries, reflection-visible members and every reachable side effect."
        },Formatting.Indented));
        File.WriteAllText(mapPath,JsonConvert.SerializeObject(changes,Formatting.Indented));
        return changes.Count;

        void RenameAccessor(MethodDef? method,string name)
        {
            if(method==null || !NeedsName(originalMethods[method]))return;
            method.Name=name;
            foreach(var change in changes.Where(c=>c.Kind=="Method" && c.Token==method.MDToken.ToString()))change.Renamed=name;
        }
    }

    private static Dictionary<Instruction,(ITypeDefOrRef? Type,int ArgumentCount)> DynamicMemberNames(CilBody body)
    {
        var result=new Dictionary<Instruction,(ITypeDefOrRef? Type,int ArgumentCount)>();
        var il=body.Instructions;
        static bool IsBinder(Instruction i)=>i.Operand is IMethod m &&
            m.DeclaringType.FullName=="Microsoft.CSharp.RuntimeBinder.Binder" && m.Name=="InvokeMember" &&
            m.MethodSig.Params.Count==5;
        if(!il.Any(IsBinder))return result;
        var joins=new HashSet<Instruction>(il.SelectMany(i=>i.Operand switch
        { Instruction target=>new[]{target},IList<Instruction> targets=>targets,_=>Array.Empty<Instruction>() }));
        foreach(var handler in body.ExceptionHandlers)
            foreach(var point in new[]{handler.TryStart,handler.HandlerStart,handler.FilterStart,handler.TryEnd,handler.HandlerEnd})
                if(point!=null)joins.Add(point);
        var stack=new List<Instruction?>();
        for(int i=0;i<il.Count;i++)
        {
            var instruction=il[i];
            if(joins.Contains(instruction))stack.Clear();
            if(IsBinder(instruction) && stack.Count>=5 && stack[stack.Count-4] is { } literal)
            {
                (ITypeDefOrRef? Type,int ArgumentCount) receiver=(null,0);
                if(i+1<il.Count && il[i+1].Operand is IMethod create && create.Name=="Create" &&
                    create.DeclaringType is TypeSpec {TypeSig:GenericInstSig site} &&
                    site.GenericType.FullName=="System.Runtime.CompilerServices.CallSite`1" &&
                    site.GenericArguments.Count==1 && site.GenericArguments[0] is GenericInstSig signature &&
                    signature.GenericArguments.Count>=2 &&
                    signature.GenericArguments[0].FullName=="System.Runtime.CompilerServices.CallSite")
                {
                    bool returns=signature.GenericType.FullName.StartsWith("System.Func`",StringComparison.Ordinal);
                    bool action=signature.GenericType.FullName.StartsWith("System.Action`",StringComparison.Ordinal);
                    if(returns || action)
                        receiver=(signature.GenericArguments[1].ToTypeDefOrRef(),signature.GenericArguments.Count-2-(returns?1:0));
                }
                if(result.TryGetValue(literal,out var previous) && previous!=receiver)result[literal]=(null,0);
                else result[literal]=receiver;
            }
            if(instruction.OpCode.Code==Code.Dup)
            {
                stack.Add(stack.Count==0?null:stack[stack.Count-1]);
                continue;
            }
            instruction.CalculateStackUsage(out int pushes,out int pops);
            if(pops<0 || pops>stack.Count)stack.Clear();
            else if(pops>0)stack.RemoveRange(stack.Count-pops,pops);
            for(int n=0;n<pushes;n++)stack.Add(instruction.OpCode.Code==Code.Ldstr?instruction:null);
            if(instruction.OpCode.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch or FlowControl.Throw or FlowControl.Return)
                stack.Clear();
        }
        return result;
    }

    private static Dictionary<PropertyDef,string> BuildPropertyContractNames(TypeDef[] types,
        Dictionary<MethodDef,List<MethodDef>> methodGroups,Dictionary<PropertyDef,string> originals)
    {
        // A getter and setter are separate dispatch slots, but a property is one
        // naming contract. A setter-only interface or a derived type with only
        // one reconstructed accessor must not rename that slot independently of
        // the base property's getter. Join properties through *either* accessor
        // before changing any names (including across generic base types).
        var properties=types.SelectMany(t=>t.Properties).ToArray();
        var parent=properties.ToDictionary(p=>p,p=>p);
        PropertyDef Find(PropertyDef p)
        {
            var root=p;while(parent[root]!=root)root=parent[root];
            while(parent[p]!=p){var next=parent[p];parent[p]=root;p=next;}
            return root;
        }
        var slots=new Dictionary<List<MethodDef>,PropertyDef>();
        foreach(var property in properties)
        foreach(var accessor in property.GetMethods.Concat(property.SetMethods))
        {
            var slot=methodGroups[accessor];
            if(slots.TryGetValue(slot,out var other))parent[Find(property)]=Find(other);
            else slots.Add(slot,property);
        }
        var names=new Dictionary<PropertyDef,string>();
        foreach(var family in properties.GroupBy(Find))
        {
            var members=family.ToArray();
            string? contract=members.Select(p=>originals[p]).FirstOrDefault(n=>!NeedsName(n));
            var accessors=members.SelectMany(p=>p.GetMethods.Concat(p.SetMethods)).ToArray();
            uint rid=accessors.Length==0?members.Min(p=>p.MDToken.Rid):accessors.SelectMany(a=>methodGroups[a]).Min(a=>a.MDToken.Rid);
            string name=contract??(members.Any(p=>p.PropertySig.Params.Count>0)?"Item":"Property"+rid.ToString("X4"));
            foreach(var property in members)names.Add(property,name);
        }
        return names;
    }

    private static List<List<MethodDef>> BuildMethodGroups(TypeDef[] types)
    {
        var methods=types.SelectMany(t=>t.Methods).ToArray();
        var ownTypes=new HashSet<TypeDef>(types);
        var parent=methods.ToDictionary(m=>m,m=>m);
        var signatures=new SigComparer(SigComparerOptions.DontCompareTypeScope);
        MethodDef Find(MethodDef m) {while(parent[m]!=m)m=parent[m];return m;}
        void Join(MethodDef a,MethodDef b) {if(parent.ContainsKey(b))parent[Find(a)]=Find(b);}
        foreach(var method in methods)
        {
            foreach(var implementation in method.Overrides)
                if(implementation.MethodDeclaration.ResolveMethodDef() is { } declaration)Join(method,declaration);
            if(!method.IsVirtual)continue;
            for(var baseReference=method.DeclaringType.BaseType;baseReference!=null;)
            {
                var baseType=baseReference.ResolveTypeDef();
                if(baseType==null || !ownTypes.Contains(baseType))break;
                var arguments=(baseReference as TypeSpec)?.TypeSig is GenericInstSig instance?instance.GenericArguments:Array.Empty<TypeSig>();
                if(!method.IsNewSlot)
                    foreach(var candidate in baseType.Methods.Where(m=>m.IsVirtual && m.Name==method.Name && signatures.Equals(CloseSignature(m.MethodSig,arguments),method.MethodSig)))Join(method,candidate);
                baseReference=baseType.BaseType==null?null:Substitute(baseType.BaseType.ToTypeSig(),arguments).ToTypeDefOrRef();
            }
        }
        // The implementing method can live on a base class which never declared
        // the interface itself. Also visit parent interfaces and close both
        // signatures in the implementing type's generic context.
        foreach(var type in types)
        {
            var pending=new Queue<ITypeDefOrRef>(type.Interfaces.Select(i=>i.Interface));
            var visited=new HashSet<string>();
            while(pending.Count>0)
            {
                var reference=pending.Dequeue();
                if(!visited.Add(reference.FullName))continue;
                var contract=reference.ResolveTypeDef();
                if(contract==null || !ownTypes.Contains(contract))continue;
                var arguments=(reference as TypeSpec)?.TypeSig is GenericInstSig instance?instance.GenericArguments:Array.Empty<TypeSig>();
                foreach(var inherited in contract.Interfaces)
                    pending.Enqueue(Substitute(inherited.Interface.ToTypeSig(),arguments).ToTypeDefOrRef());
                foreach(var declaration in contract.Methods.Where(m=>!m.IsStatic))
                {
                    var expected=CloseSignature(declaration.MethodSig,arguments);
                    TypeDef? owner=type;IList<TypeSig> ownerArguments=Array.Empty<TypeSig>();
                    while(owner!=null && ownTypes.Contains(owner))
                    {
                        // An explicit MethodImpl takes precedence over a
                        // same-name public method. Joining both would rename a
                        // distinct overridable slot to the private final slot's
                        // name, making derived overrides fail CLR type loading.
                        var explicitImplementation=owner.Methods.FirstOrDefault(m=>m.Overrides.Any(o=>
                            o.MethodDeclaration.ResolveMethodDef()==declaration));
                        if(explicitImplementation!=null){Join(explicitImplementation,declaration);break;}
                        var implementation=owner.Methods.FirstOrDefault(m=>m.IsPublic && !m.IsStatic && m.Name==declaration.Name
                            && signatures.Equals(CloseSignature(m.MethodSig,ownerArguments),expected));
                        if(implementation!=null){Join(implementation,declaration);break;}
                        var baseReference=owner.BaseType==null?null:Substitute(owner.BaseType.ToTypeSig(),ownerArguments).ToTypeDefOrRef();
                        owner=baseReference?.ResolveTypeDef();
                        ownerArguments=(baseReference as TypeSpec)?.TypeSig is GenericInstSig baseInstance?baseInstance.GenericArguments:Array.Empty<TypeSig>();
                    }
                }
            }
        }
        return methods.GroupBy(Find).Select(g=>g.ToList()).ToList();
    }

    private static MethodSig CloseSignature(MethodSig signature,IList<TypeSig> arguments)
    {
        var closed=signature.Clone();closed.RetType=Substitute(signature.RetType,arguments);
        for(int i=0;i<closed.Params.Count;i++)closed.Params[i]=Substitute(signature.Params[i],arguments);
        return closed;
    }
    private static TypeSig Substitute(TypeSig type,IList<TypeSig> arguments)=>type switch
    {
        GenericVar variable when variable.Number<arguments.Count=>arguments[(int)variable.Number],
        SZArraySig array=>new SZArraySig(Substitute(array.Next,arguments)),
        ByRefSig reference=>new ByRefSig(Substitute(reference.Next,arguments)),
        PtrSig pointer=>new PtrSig(Substitute(pointer.Next,arguments)),
        PinnedSig pinned=>new PinnedSig(Substitute(pinned.Next,arguments)),
        CModReqdSig modified=>new CModReqdSig(modified.Modifier,Substitute(modified.Next,arguments)),
        CModOptSig modified=>new CModOptSig(modified.Modifier,Substitute(modified.Next,arguments)),
        GenericInstSig generic=>new GenericInstSig(generic.GenericType,generic.GenericArguments.Select(a=>Substitute(a,arguments)).ToArray()),
        ArraySig array=>new ArraySig(Substitute(array.Next,arguments),array.Rank,array.Sizes,array.LowerBounds),
        _=>type
    };
    private static IEnumerable<TypeRef> AttributeTypeReferences(IEnumerable<CustomAttribute> attributes)
    {
        var references=new HashSet<TypeRef>();
        void Visit(object? value)
        {
            if(value is TypeRef reference)
            {if(references.Add(reference))Visit(reference.ResolutionScope);}
            else if(value is GenericInstSig generic){Visit(generic.GenericType);foreach(var argument in generic.GenericArguments)Visit(argument);}
            else if(value is TypeDefOrRefSig definition)Visit(definition.TypeDefOrRef);
            else if(value is TypeSig signature)Visit(signature.Next);
            else if(value is CAArgument argument)Visit(argument.Value);
            else if(value is IEnumerable<CAArgument> arguments)foreach(var nestedArgument in arguments)Visit(nestedArgument.Value);
        }
        foreach(var attribute in attributes)
        {Visit(attribute.AttributeType);foreach(var argument in attribute.ConstructorArguments)Visit(argument.Value);foreach(var argument in attribute.NamedArguments)Visit(argument.Argument.Value);}
        return references;
    }

    private static void RestoreAccessorMetadata(TypeDef[] types,List<NameChange> changes)
    {
        foreach(var type in types)
        foreach(var method in type.Methods)
        {
            if(type.Properties.Any(p=>p.GetMethods.Contains(method)||p.SetMethods.Contains(method)))continue;
            var declaration=method.Overrides.Select(o=>o.MethodDeclaration).FirstOrDefault(m=>m.Name.String.StartsWith("get_")||m.Name.String.StartsWith("set_"));
            if(declaration is null)continue;
            string name=declaration.Name.String.Substring(4);
            if(method.IsPrivate)name=declaration.DeclaringType.FullName+"."+name;
            bool getter=declaration.Name.String.StartsWith("get_");
            var signature=method.MethodSig;
            var propertySignature=new PropertySig(signature.HasThis,getter?signature.RetType:signature.Params.Last(),
                getter?signature.Params.ToArray():signature.Params.Take(signature.Params.Count-1).ToArray());
            var property=type.Properties.FirstOrDefault(p=>p.Name==name && new SigComparer().Equals(p.PropertySig,propertySignature))
                ?? new PropertyDefUser(name,propertySignature);
            if(getter)property.GetMethod=method;else property.SetMethod=method;
            method.IsSpecialName=true;
            if(!type.Properties.Contains(property))type.Properties.Add(property);
            changes.Add(new NameChange{Kind="PropertyMetadata",Token=method.MDToken.ToString(),Original="",Renamed=name,Type=property.PropertySig.RetType.FullName});
        }
    }

    private static void RestoreInheritedProperties(TypeDef[] types,List<NameChange> changes)
    {
        // Index in original property order to preserve the previous first-match
        // selection without scanning every property for every method group.
        var accessors=new Dictionary<MethodDef,(PropertyDef Property,int Order)>();
        int ordinal=0;
        foreach(var property in types.SelectMany(t=>t.Properties))
        {
            foreach(var method in property.GetMethods.Concat(property.SetMethods))
                if(!accessors.ContainsKey(method))accessors.Add(method,(property,ordinal));
            ordinal++;
        }
        foreach(var group in BuildMethodGroups(types))
        {
            PropertyDef? template=null;int first=int.MaxValue;
            foreach(var method in group)
                if(accessors.TryGetValue(method,out var match) && match.Order<first)
                {template=match.Property;first=match.Order;}
            if(template==null)continue;
            bool getter=template.GetMethods.Any(group.Contains);
            foreach(var method in group)
            {
                var type=method.DeclaringType;
                if(type.Properties.Any(p=>p.GetMethods.Concat(p.SetMethods).Contains(method)))continue;
                var signature=method.MethodSig;
                var property=new PropertyDefUser(template.Name,new PropertySig(signature.HasThis,getter?signature.RetType:signature.Params.Last(),
                    getter?signature.Params.ToArray():signature.Params.Take(signature.Params.Count-1).ToArray()));
                if(getter)property.GetMethod=method;else property.SetMethod=method;
                method.IsSpecialName=true;type.Properties.Add(property);
                changes.Add(new NameChange{Kind="PropertyMetadata",Token=method.MDToken.ToString(),Renamed=template.Name,Type=property.PropertySig.RetType.FullName});
            }
        }
    }

    private static void RepairAttributeTargets(ModuleDef module,TypeDef[] types,List<NameChange> changes)
    {
        foreach(var owner in GetAttributeOwners(module,types))
        foreach(var attribute in owner.CustomAttributes)
        {
            var definition=attribute.AttributeType.ResolveTypeDef();
            if(definition?.Module!=module)continue;
            var usage=definition.CustomAttributes.FirstOrDefault(a=>a.TypeFullName=="System.AttributeUsageAttribute");
            if(usage==null || usage.ConstructorArguments.Count==0)continue;
            int target=owner switch
            {
                AssemblyDef=>1,ModuleDef=>2,TypeDef t=>t.IsInterface?1024:t.IsEnum?16:t.IsValueType?8:t.BaseType?.FullName=="System.MulticastDelegate"?4096:4,
                MethodDef m=>m.IsConstructor?32:64,PropertyDef=>128,FieldDef=>256,EventDef=>512,ParamDef p=>p.Sequence==0?8192:2048,GenericParam=>16384,_=>0
            };
            int original=Convert.ToInt32(usage.ConstructorArguments[0].Value);
            if((original&target)==target)continue;
            usage.ConstructorArguments[0]=new CAArgument(usage.ConstructorArguments[0].Type,original|target);
            changes.Add(new NameChange{Kind="AttributeTargets",Token=definition.MDToken.ToString(),Original=original.ToString(),Renamed=(original|target).ToString()});
        }
    }

    private static IEnumerable<IHasCustomAttribute> GetAttributeOwners(ModuleDef module,TypeDef[] types) =>
        new IHasCustomAttribute[]{module,module.Assembly}.Concat(types).Concat(types.SelectMany(t=>t.Methods))
            .Concat(types.SelectMany(t=>t.Fields)).Concat(types.SelectMany(t=>t.Properties)).Concat(types.SelectMany(t=>t.Events))
            .Concat(types.SelectMany(t=>t.GenericParameters)).Concat(types.SelectMany(t=>t.Methods).SelectMany(m=>m.GenericParameters))
            .Concat(types.SelectMany(t=>t.Methods).SelectMany(m=>m.ParamDefs));
    private static void RenameGeneric(GenericParam parameter,List<NameChange> changes)
    {
        if(!NeedsName(parameter.Name))return;
        string name="T"+parameter.Number; Add(changes,"GenericParameter",parameter,parameter.Name,name,evidence:"generic parameter ordinal; generated-name");parameter.Name=name;
    }
    private static void Add(List<NameChange> changes,string kind,IMDTokenProvider member,string? original,string renamed,string type="",string evidence="") =>
        changes.Add(new NameChange{Kind=kind,Token=member.MDToken.ToString(),Original=original??"",Renamed=renamed,Type=type,Evidence=evidence});
    private static string Unique(string name,IEnumerable<string> used) {var set=new HashSet<string>(used);while(set.Contains(name))name+="_";return name;}
    private static bool IsGeneratedTypeName(string name)=>Regex.IsMatch(name,@"^(?:Class|StaticClass|Struct|Interface|Enum|Delegate)\d+_*(?:`\d+)?$");
    private static bool NeedsParameterName(string name)=>NeedsName(name)||Regex.IsMatch(name,@"^[A-Za-z_][A-Za-z0-9_]*Argument\d+_*$");
    private static string? BaseTypeStem(TypeDef type)
    {
        if(type.IsInterface||type.IsEnum||type.IsValueType||type.BaseType==null)return null;
        var seen=new HashSet<string>();ITypeDefOrRef? reference=type.BaseType;
        while(reference!=null && seen.Add(reference.FullName))
        {
            if(reference.FullName is "System.Object" or "System.ValueType" or "System.Enum" or "System.MulticastDelegate" or "System.Delegate")return null;
            string name=Regex.Replace(reference.Name.String,@"`\d+$","");
            if(!NeedsName(name)&&!IsGeneratedTypeName(name))
            {
                // Avoid a C# self-base spelling when a local type shares the
                // external base's full name, even though assembly scopes differ.
                return type.Namespace+"."+name==reference.FullName?name+"2":name;
            }
            var definition=reference.ResolveTypeDef();
            if(definition==null||definition.Module!=type.Module)return null;
            reference=definition.BaseType;
        }
        return null;
    }
    private static string ParameterStem(TypeSig type)
    {
        type=type.RemovePinnedAndModifiers();if(type is ByRefSig byRef)return ParameterStem(byRef.Next);
        if(type is SZArraySig or ArraySig)return "items";
        string? simple=type.ElementType switch {
            ElementType.Boolean=>"flag",ElementType.String=>"text",ElementType.Object=>"obj",ElementType.Char=>"ch",
            ElementType.I1 or ElementType.U1 or ElementType.I2 or ElementType.U2 or ElementType.I4 or ElementType.U4 or
            ElementType.I8 or ElementType.U8 or ElementType.R4 or ElementType.R8 or ElementType.I or ElementType.U=>"value",_=>null};
        if(simple!=null)return simple;
        if(type.FullName=="System.Threading.CancellationToken")return "token";
        string stem=TypeStem(type);if(Regex.IsMatch(stem,@"^(?:class|struct|enum|interface|delegate)\d+$"))return "value";
        return Keywords.Contains(stem)?"value":stem.Length>24?"value":stem;
    }
    private static string TypePrefix(TypeDef type) => type.IsInterface?"Interface":type.IsEnum?"Enum":type.IsValueType?"Struct":
        type.BaseType?.FullName=="System.MulticastDelegate"?"Delegate":type.BaseType?.FullName=="System.Windows.Forms.Form"?"Form":type.IsAbstract&&type.IsSealed?"StaticClass":"Class";
    private static string TypeStem(TypeSig type)
    {
        type=type.RemovePinnedAndModifiers();
        if(type is ByRefSig byRef)return TypeStem(byRef.Next);
        if(type is SZArraySig array)return TypeStem(array.Next)+"Array";
        if(type is ArraySig multi)return TypeStem(multi.Next)+"Array"+multi.Rank;
        if(type is PtrSig pointer)return TypeStem(pointer.Next)+"Pointer";
        if(type is GenericInstSig generic)return TypeStem(generic.GenericType)+"Of"+string.Join("And",generic.GenericArguments.Select(a=> {
            string stem=TypeStem(a);return char.ToUpperInvariant(stem[0])+stem.Substring(1); }));
        string? primitive=type.ElementType switch {ElementType.I4=>"int",ElementType.U4=>"uint",ElementType.I8=>"long",ElementType.U8=>"ulong",
            ElementType.I2=>"short",ElementType.U2=>"ushort",ElementType.R4=>"float",ElementType.R8=>"double",ElementType.Boolean=>"bool",
            ElementType.I1=>"sbyte",ElementType.U1=>"byte",ElementType.Object=>"object",ElementType.String=>"string",ElementType.Char=>"char",_=>null};
        if(primitive!=null)return primitive;
        string name=Regex.Replace(type.TypeName??"value",@"`\d+$","");
        name=Regex.Replace(name,@"[^A-Za-z0-9_]","");
        if(string.IsNullOrEmpty(name) || !char.IsLetter(name[0]))name="value";
        return char.ToLowerInvariant(name[0])+name.Substring(1);
    }
}
