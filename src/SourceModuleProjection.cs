using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace Unpacker;

// C# cannot declare metadata globals. Project them into an ordinary
// internal static type for source export only, not the unpacked PE.
internal static class SourceModuleProjection
{
    internal static byte[]? Prepare(string assembly)
    {
        using var module=ModuleDefMD.Load(assembly);
        var global=module.GlobalType;
        if(global==null)return null;
        var valueStatics=FindStaticTypesUsedAsValues(module);
        var initializer=global.FindStaticConstructor();
        var methods=global.Methods.Where(m=>m!=initializer).ToArray();
        var fields=global.Fields.ToArray();
        bool complex=initializer?.Body is { } body && (body.ExceptionHandlers.Count!=0 || body.Variables.Count!=0 ||
            body.Instructions.Count==0 || body.Instructions.Last().OpCode.Code!=Code.Ret ||
            body.Instructions.Take(body.Instructions.Count-1).Any(i=>i.OpCode.Code!=Code.Nop &&
                (i.OpCode.Code!=Code.Call || i.Operand is not MethodDef {IsStatic:true} method ||
                 method.MethodSig.Params.Count!=0 || method.MethodSig.RetType.ElementType!=ElementType.Void ||
                 method.HasGenericParameters || method.DeclaringType.HasGenericParameters)));
        if(methods.Length==0 && fields.Length==0 && !complex && valueStatics.Count==0)return null;
        // Abstract/sealed metadata types may appear in arrays and signatures;
        // C# static types cannot. Keep them non-instantiable in the projection.
        foreach(var type in valueStatics)type.IsSealed=false;
        if(methods.Length==0 && fields.Length==0 && !complex)return Serialize(module);
        if(methods.Any(m=>!m.IsStatic || m.IsPublic) || fields.Any(f=>!f.IsStatic || f.IsPublic) ||
            module.GetMemberRefs().Any(r=>r.DeclaringType?.FullName=="<Module>"))
            throw new NotSupportedException("Externally referenced metadata globals cannot be projected safely.");
        var globalHandles=new List<Instruction>();
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody))
        {
            var instructions=method.Body.Instructions;
            for(int i=0;i<instructions.Count;i++)
            {
                if(instructions[i].Operand!=global)continue;
                if(instructions[i].OpCode.Code!=Code.Ldtoken || i+2>=instructions.Count ||
                    instructions[i+1].Operand is not IMethod type || type.DeclaringType.FullName!="System.Type" ||
                    type.Name!="GetTypeFromHandle" || instructions[i+2].Operand is not IMethod member ||
                    member.DeclaringType.FullName!="System.Type" || member.Name.String is not ("get_Assembly" or "get_Module"))
                    throw new NotSupportedException("A global type handle is used for more than assembly/module identity.");
                globalHandles.Add(instructions[i]);
            }
        }

        string name="UnpackModuleGlobals";
        while(module.Types.Any(t=>t.Namespace=="" && t.Name==name))name+="_";
        var container=new TypeDefUser("",name,module.CorLibTypes.Object.TypeDefOrRef)
        { Attributes=TypeAttributes.NotPublic|TypeAttributes.Abstract|TypeAttributes.Sealed };
        module.Types.Add(container);
        foreach(var instruction in globalHandles)instruction.Operand=container;
        for(int i=0;i<methods.Length;i++)
        {
            var method=methods[i];
            global.Methods.Remove(method);
            method.Name="GlobalMethod"+i;
            method.Access=MethodAttributes.Assembly;
            container.Methods.Add(method);
        }
        for(int i=0;i<fields.Length;i++)
        {
            var field=fields[i];
            global.Fields.Remove(field);
            field.Name="GlobalField"+i;
            field.Access=FieldAttributes.Assembly;
            container.Fields.Add(field);
        }
        if(initializer?.Body is { } initialization)
        {
            var startup=new MethodDefUser("Initialize",MethodSig.CreateStatic(module.CorLibTypes.Void),
                MethodImplAttributes.IL|MethodImplAttributes.Managed,MethodAttributes.Static|MethodAttributes.Assembly)
            { Body=initialization };
            container.Methods.Add(startup);
            initializer.Body=new CilBody();
            initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Call,startup));
            initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        }
        return Serialize(module);
    }

    private static byte[] Serialize(ModuleDefMD module)
    {
        foreach(var method in module.GetTypes().SelectMany(t=>t.Methods).Where(m=>m.HasBody && m.Body.MaxStack>0))
            method.Body.KeepOldMaxStack=true;
        using var projection=new MemoryStream();
        module.Write(projection,new ModuleWriterOptions(module)
        {MetadataOptions={Flags=MetadataFlags.PreserveAll & ~MetadataFlags.PreserveMethodRids & ~MetadataFlags.PreserveFieldRids}});
        return projection.ToArray();
    }

    private static HashSet<TypeDef> FindStaticTypesUsedAsValues(ModuleDefMD module)
    {
        var result=new HashSet<TypeDef>();
        var types=module.GetTypes().ToArray();
        var candidates=new HashSet<TypeDef>(types.Where(t=>t.IsAbstract && t.IsSealed && !t.IsGlobalModuleType));
        if(candidates.Count==0)return result;
        foreach(var type in types)
        {
            VisitAttributes(type.CustomAttributes);
            foreach(var field in type.Fields)
            {
                Visit(field.FieldType);
                VisitAttributes(field.CustomAttributes);
            }
            foreach(var property in type.Properties)
            {
                VisitAttributes(property.CustomAttributes);
                Visit(property.PropertySig.RetType);
                foreach(var p in property.PropertySig.Params)Visit(p);
            }
            foreach(var method in type.Methods)
            {
                VisitAttributes(method.CustomAttributes);
                Visit(method.MethodSig.RetType);
                foreach(var p in method.MethodSig.Params)Visit(p);
                if(!method.HasBody)continue;
                foreach(var local in method.Body.Variables)Visit(local.Type);
                foreach(var i in method.Body.Instructions.Where(i=>i.OpCode.Code==Code.Newarr))
                    if(i.Operand is ITypeDefOrRef item && item.ResolveTypeDef() is { } definition && candidates.Contains(definition))
                        result.Add(definition);
            }
        }
        VisitAttributes(module.CustomAttributes);
        if(module.Assembly!=null)VisitAttributes(module.Assembly.CustomAttributes);
        return result;

        void VisitAttributes(IEnumerable<CustomAttribute> attributes)
        {
            foreach(var attribute in attributes)
            {
                foreach(var argument in attribute.ConstructorArguments)VisitArgument(argument);
                foreach(var argument in attribute.NamedArguments)VisitArgument(argument.Argument);
            }
        }

        void VisitArgument(CAArgument argument)
        {
            if(argument.Value is TypeSig type)Visit(type);
            else if(argument.Value is IList<CAArgument> items)
                foreach(var item in items)VisitArgument(item);
        }

        void Visit(TypeSig? signature)
        {
            if(signature==null)return;
            if(signature is GenericInstSig generic)
            {
                Visit(generic.GenericType);
                foreach(var arg in generic.GenericArguments)Visit(arg);
            }
            else if(signature is TypeDefOrRefSig named && named.TypeDefOrRef.ResolveTypeDef() is { } definition &&
                candidates.Contains(definition))result.Add(definition);
            if(signature.Next!=null)Visit(signature.Next);
        }
    }
}
