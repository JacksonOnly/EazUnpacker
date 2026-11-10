using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

namespace EazyDevirt.Core.Architecture;

internal enum VMTypeWireField { Name, GenericParameter, GenericArguments, MethodIndex, TypeIndex, Arguments }
internal enum VMArrayCountEncoding { Encoded, Int16, Int32 }

/// <summary>Derives reordered type-record fields from their resolver consumers.</summary>
internal sealed class VMTypeWireLayout
{
    internal List<VMTypeWireField> Fields { get; } = new();
    internal VMArrayCountEncoding ArrayCountEncoding { get; private set; }

    internal static VMTypeWireLayout Discover(TypeDefinition runtime, TypeDefinition record, IEnumerable<CilInstruction> block)
    {
        FieldDefinition? Field(MethodDefinition method) => method.CilMethodBody?.Instructions
            .Where(i=>i.OpCode.Code is CilCode.Ldfld or CilCode.Stfld).Select(i=>i.Operand).OfType<FieldDefinition>()
            .Distinct().SingleOrDefault();
        var resolver = runtime.Methods.FirstOrDefault(m=>m.Signature?.ReturnType.FullName=="System.Type" &&
            m.CilMethodBody?.Instructions.Any(i=>i.Operand is IMethodDescriptor target && target.Name=="MakeGenericType")==true &&
            m.CilMethodBody.Instructions.Any(i=>i.Operand is MethodDefinition getter && getter.DeclaringType==record));
        if(resolver==null)throw new NotSupportedException("Cannot discover VM type record consumers.");
        var getters=resolver.CilMethodBody!.Instructions.Select(i=>i.Operand).OfType<MethodDefinition>()
            .Where(m=>m.DeclaringType==record && m.Parameters.Count==0).Distinct().ToArray();
        var booleans=getters.Where(m=>m.Signature?.ReturnType.FullName=="System.Boolean").Select(Field).Distinct().ToArray();
        var integers=getters.Where(m=>m.Signature?.ReturnType.FullName=="System.Int32").Select(Field).Distinct().ToArray();
        if(booleans.Length!=2 || integers.Length!=2 || booleans.Any(f=>f==null) || integers.Any(f=>f==null))
            throw new NotSupportedException("Ambiguous VM type record consumers.");
        var layout=new VMTypeWireLayout();
        var items=block.ToArray();
        foreach(var setter in items.Select(i=>i.Operand).OfType<MethodDefinition>()
            .Where(m=>m.DeclaringType==record && m.Parameters.Count==1 && m.Signature?.ReturnType.FullName=="System.Void"))
        {
            var field=Field(setter);
            if(field==null)throw new NotSupportedException("Cannot discover VM type record setter.");
            var kind=field.Signature!.FieldType.FullName;
            layout.Fields.Add(kind=="System.String" ? VMTypeWireField.Name :
                field==booleans[0] ? VMTypeWireField.GenericParameter : field==booleans[1] ? VMTypeWireField.GenericArguments :
                field==integers[0] ? VMTypeWireField.MethodIndex : field==integers[1] ? VMTypeWireField.TypeIndex :
                kind.EndsWith("[]") ? VMTypeWireField.Arguments : throw new NotSupportedException("Unknown VM type record field."));
        }
        int arrayIndex=Array.FindIndex(items,i=>i.OpCode.Code==CilCode.Newarr);
        var countRead=items.Take(arrayIndex).Select(i=>i.Operand).OfType<IMethodDescriptor>().LastOrDefault(m=>
            m.Signature?.ParameterTypes.Count==0 && m.Signature?.ReturnType.FullName is "System.Int16" or "System.Int32");
        if(countRead==null)throw new NotSupportedException("Cannot discover VM operand array count encoding.");
        var countBody=(countRead as MethodDefinition)?.CilMethodBody?.Instructions;
        layout.ArrayCountEncoding=countRead.Signature!.ReturnType.FullName=="System.Int16" ? VMArrayCountEncoding.Int16 :
            countBody!=null && countBody.Any(i=>i.IsLdcI4() && i.GetLdcI4Constant()==127) &&
                countBody.Any(i=>i.OpCode.Code==CilCode.And) && countBody.Any(i=>i.OpCode.Code==CilCode.Shl)
                ? VMArrayCountEncoding.Encoded : VMArrayCountEncoding.Int32;
        if(layout.Fields.Count!=6 || layout.Fields.Distinct().Count()!=6)
            throw new NotSupportedException("Incomplete VM type record layout.");
        return layout;
    }
}
