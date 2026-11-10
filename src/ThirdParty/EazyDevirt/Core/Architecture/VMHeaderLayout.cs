using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace EazyDevirt.Core.Architecture;

internal enum VMHeaderField { Type, Name, Flags, Locals, Parameters }

internal sealed class VMHeaderLayout
{
    public List<VMHeaderField> Fields { get; } = new();
    public bool ParameterBooleanFirst { get; private set; }
    public bool BooleanFlags { get; private set; }
    public bool LeadingZeroByte { get; private set; }
    public bool FirstTypeIsReturn { get; set; }
    public bool TypeSlotsCalibrated { get; set; }
    public int StaticMask { get; set; } = 2;
    public bool StaticMaskCalibrated { get; set; }
    public int[] StaticMaskCandidates { get; set; } = Array.Empty<int>();

    public bool TryResolveStatic(int flags, out bool isStatic)
    {
        isStatic = (flags & StaticMask) != 0;
        if (StaticMaskCalibrated) return true;
        if (StaticMaskCandidates.Length == 0) return false;
        bool value = (flags & StaticMaskCandidates[0]) != 0;
        isStatic = value;
        return StaticMaskCandidates.All(mask => ((flags & mask) != 0) == value);
    }

    public static VMHeaderLayout Discover(TypeDefinition runtime)
    {
        var loader=runtime.Methods.Single(m=>!m.IsStatic && m.CilMethodBody!=null &&
            m.Signature?.ReturnType.FullName=="System.Void" && m.Parameters.Count==3 &&
            m.Parameters.Select(p=>p.ParameterType.FullName).OrderBy(n=>n,StringComparer.Ordinal)
                .SequenceEqual(new[]{"System.IO.Stream","System.Int64","System.String"}));
        var header=loader.CilMethodBody!.Instructions.Select(i=>i.Operand).OfType<MethodDefinition>().FirstOrDefault(m=>
            m.Parameters.Count==1 && m.Signature?.ReturnType.ToTypeDefOrRef()?.Resolve() is { } t &&
            t.Fields.Count(f=>f.Signature?.FieldType.FullName=="System.String")==1 &&
            t.Fields.Count(f=>f.Signature?.FieldType.FullName is "System.Byte" or "System.Boolean")==1 &&
            t.Fields.Count(f=>f.Signature?.FieldType.FullName=="System.Int32")==2);
        if(header?.CilMethodBody==null)throw new NotSupportedException("Cannot derive VM method header layout.");
        var record=header.Signature!.ReturnType.ToTypeDefOrRef()!.Resolve()!;
        var layout=new VMHeaderLayout();
        layout.LeadingZeroByte=loader.CilMethodBody.Instructions.TakeWhile(i=>i.Operand!=header)
            .Select(i=>i.Operand).OfType<MethodDefinition>().Any(m=>
                m.Parameters.Count==1 && m.Signature?.ReturnType.FullName=="System.Void" &&
                m.CilMethodBody?.Instructions is {Count:6} code &&
                code[1].Operand is IMethodDescriptor read && read.Name=="ReadByte" &&
                read.DeclaringType?.FullName=="System.IO.BinaryReader" &&
                code[2].OpCode.Code is CilCode.Brfalse or CilCode.Brfalse_S &&
                code[3].Operand is IMethodDescriptor error && error.DeclaringType?.FullName=="System.IO.InvalidDataException" &&
                code[4].OpCode.Code==CilCode.Throw);
        foreach(var setter in header.CilMethodBody.Instructions.Select(i=>i.Operand).OfType<MethodDefinition>())
        {
            if(setter.DeclaringType!=record || setter.Parameters.Count!=1 || setter.Signature?.ReturnType.FullName!="System.Void")continue;
            var parameter=setter.Parameters[0].ParameterType;
            switch(parameter.FullName) {
                case "System.Int32":layout.Fields.Add(VMHeaderField.Type);break;
                case "System.Byte":layout.Fields.Add(VMHeaderField.Flags);break;
                case "System.Boolean":
                    layout.Fields.Add(VMHeaderField.Flags);layout.BooleanFlags=true;layout.StaticMask=1;break;
                case "System.String":layout.Fields.Add(VMHeaderField.Name);break;
                default:
                    if(parameter is not SzArrayTypeSignature array)throw new NotSupportedException("Unexpected VM header field: "+parameter.FullName);
                    var element=array.BaseType.ToTypeDefOrRef()!.Resolve()!;
                    bool isParameter=element.Fields.Any(f=>f.Signature?.FieldType.FullName=="System.Boolean");
                    layout.Fields.Add(isParameter?VMHeaderField.Parameters:VMHeaderField.Locals);
                    if(isParameter) {
                        var parser=runtime.Methods.FirstOrDefault(m=>m.Parameters.Count==1 && m.Signature?.ReturnType.FullName==element.FullName && m.CilMethodBody!=null);
                        var firstRead=parser?.CilMethodBody!.Instructions.Select(i=>i.Operand).OfType<IMethodDescriptor>()
                            .FirstOrDefault(m=>m.Signature?.ParameterTypes.Count==0 && (m.Signature.ReturnType.FullName=="System.Boolean" || m.Signature.ReturnType.FullName=="System.Int32"));
                        layout.ParameterBooleanFirst=firstRead?.Signature?.ReturnType.FullName=="System.Boolean";
                    }
                    break;
            }
        }
        if(layout.Fields.Count!=6 || layout.Fields.Count(f=>f==VMHeaderField.Type)!=2 ||
            !layout.Fields.Contains(VMHeaderField.Locals) || !layout.Fields.Contains(VMHeaderField.Parameters))
            throw new NotSupportedException("VM header layout has unsupported fields.");
        EazyDevirt.Logging.ConsoleLogger.Detail("VM header layout: "+string.Join(", ",layout.Fields));
        return layout;
    }
}
