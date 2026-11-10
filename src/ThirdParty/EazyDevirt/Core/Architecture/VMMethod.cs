using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;

namespace EazyDevirt.Core.Architecture;

internal record VMMethod(MethodDefinition Parent, string EncodedMethodKey, long MethodKey)
{
    public MethodDefinition Parent { get; } = Parent;
    public string EncodedMethodKey { get; } = EncodedMethodKey;
    public long MethodKey { get; } = MethodKey;
    public VMMethodInfo MethodInfo { get; set; } = null!;
    public List<VMExceptionHandler> VMExceptionHandlers { get; set; } = new();
    
    public List<CilExceptionHandler> ExceptionHandlers { get; set; } = new();
    // public List<Parameter> Parameters { get; set; } = new();
    public List<CilLocalVariable> Locals { get; set; } = new();
    public List<CilInstruction> Instructions { get; set; } = new();
    public List<uint> VirtualOffsets { get; set; } = new();
    public int EncryptedRegions { get; set; }
    public string? Failure { get; set; }
    public CilInstruction? ExecutorInstruction { get; set; }
    public MethodDefinition? RecoveredAdapter { get; set; }
    public List<MethodDefinition> AccessBridges { get; } = new();
    public TypeDefinition? AdapterDeclaringType { get; set; }
    public TypeSignature[]? ArgumentTypes { get; set; }
    public bool Inlined => RecoveredAdapter != null;
    
    
    public bool SuccessfullyDevirtualized { get; set; }
    public bool HasHomomorphicEncryption { get; set; }
    public int CodeSize { get; set; }
    public long CodePosition { get; set; }
    public long InitialCodeStreamPosition { get; set; }
    
    public override string ToString() =>
        $"Parent: {Parent.MetadataToken} | EncodedMethodKey: {EncodedMethodKey} | MethodKey: 0x{MethodKey:X} | " +
        $"MethodInfo: [{MethodInfo}] | VMExceptionHandlers: [{string.Join(", ", VMExceptionHandlers)}] | " +
        $"ExceptionHandlers: {ExceptionHandlers?.Count} | Locals: {Locals?.Count} | " +
        $"Instructions: {Instructions?.Count}";
}

// TODO: The order of these fields are scrambled across samples. See issue #3
internal record VMMethodInfo
{
    private readonly VMHeaderLayout _layout;
    private readonly int _firstType;
    private readonly int _secondType;
    public int VMDeclaringType => _layout.FirstTypeIsReturn ? _secondType : _firstType;
    public string Name { get; }
    public byte BindingFlags { get; }
    public bool IsStatic => (BindingFlags & _layout.StaticMask) > 0;
    public bool IsSecurityCritical => (BindingFlags & 4) > 0;
    public bool IsUnknownFlag2 => (BindingFlags & 8) > 0;
    public int VMReturnType => _layout.FirstTypeIsReturn ? _firstType : _secondType;
    public List<VMLocal> VMLocals { get; }
    public List<VMParameter> VMParameters { get; }

    public ITypeDefOrRef DeclaringType { get; set; } = null!;
    public ITypeDefOrRef ReturnType { get; set; } = null!;
    
    public VMMethodInfo(BinaryReader reader, VMHeaderLayout layout)
    {
        _layout=layout;
        if(layout.LeadingZeroByte && reader.ReadByte()!=0)
            throw new InvalidDataException("Invalid VM method format marker.");
        Name="";VMLocals=new();VMParameters=new();int types=0;
        int ReadTypePosition()
        {
            int value=reader.ReadInt32();
            if(value<0 || value>=reader.BaseStream.Length)
                throw new InvalidDataException("VM header type position is outside the resource.");
            return value;
        }
        int ReadCount(int itemBytes)
        {
            int count=reader.ReadInt16();
            if(count<0 || count>(reader.BaseStream.Length-reader.BaseStream.Position)/itemBytes)
                throw new InvalidDataException("VM header array exceeds the resource.");
            return count;
        }
        foreach(var field in layout.Fields)
        {
            switch(field) {
                case VMHeaderField.Type:
                    if(types++==0)_firstType=ReadTypePosition();else _secondType=ReadTypePosition();break;
                case VMHeaderField.Name:Name=reader.ReadString();break;
                case VMHeaderField.Flags:BindingFlags=layout.BooleanFlags?(byte)(reader.ReadBoolean()?1:0):reader.ReadByte();break;
                case VMHeaderField.Locals:
                    int locals=ReadCount(4);
                    for(int i=0;i<locals;i++)VMLocals.Add(new VMLocal(ReadTypePosition()));break;
                case VMHeaderField.Parameters:
                    int parameters=ReadCount(5);
                    for(int i=0;i<parameters;i++) {
                        bool flag=false;int type;
                        if(layout.ParameterBooleanFirst) {flag=reader.ReadBoolean();type=ReadTypePosition();}
                        else {type=ReadTypePosition();flag=reader.ReadBoolean();}
                        VMParameters.Add(new VMParameter(type,flag));
                    }
                    break;
            }
        }
    }

    public override string ToString() =>
        $"VMDeclaringType: 0x{VMDeclaringType:X} | Name: {Name} | BindingFlags: {BindingFlags} | " +
        $"IsStatic: {IsStatic} | IsSecurityCritical: {IsSecurityCritical} | IsUnknownFlag2: {IsUnknownFlag2} | " +
        $"VMReturnType: 0x{VMReturnType:X} | VMLocals: [{string.Join(", ", VMLocals)}] | VMParameters: [{string.Join(", ", VMParameters)}] | " +
        $"DeclaringType: {DeclaringType?.FullName} | ReturnType: {ReturnType?.FullName}";
}

internal record VMLocal(int VMType)
{
    public int VMType { get; } = VMType;
    
    public override string ToString() => $"VMType: 0x{VMType:X}";
}

internal record VMParameter(int VMType, bool In)
{
    public int VMType { get; } = VMType;
    public bool In { get; } = In;
    
    public override string ToString() => $"VMType: 0x{VMType:X} | In: {In}";
}

