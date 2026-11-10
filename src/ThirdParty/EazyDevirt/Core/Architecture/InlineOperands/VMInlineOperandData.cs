using System.Reflection;

namespace EazyDevirt.Core.Architecture.InlineOperands;

// thank you to saneki

/// <summary>
/// Operand data.
/// </summary>
internal abstract record VMInlineOperandData(VMInlineOperandType Type)
{
    /// <summary>
    /// Describes the type of operand data.
    /// </summary>
    public VMInlineOperandType Type { get; } = Type;

    /// <summary>
    /// Read some inline operand data from a BinaryReader.
    /// </summary>
    /// <param name="reader">BinaryReader</param>
    /// <returns>InlineOperandData</returns>
    public static VMInlineOperandData Read(BinaryReader reader)
    {
        var operandType = reader.ReadByte();
        if (!EazyDevirt.Devirtualization.DevirtualizationContext.Instance.InlineLayout.TryGetValue(operandType, out var kind))
            throw new InvalidDataException("Unknown VM inline tag: " + operandType);
        return kind switch
        {
            VMInlineOperandType.Type => new VMTypeData(reader),
            VMInlineOperandType.Field => new VMFieldData(reader),
            VMInlineOperandType.Method => new VMMethodData(reader),
            VMInlineOperandType.UserString => new VMUserStringData(reader),
            VMInlineOperandType.EazCall => new VMEazCallData(reader),
            _ => throw new ArgumentOutOfRangeException(nameof(operandType), "Not a valid inline operand type!")
        };
    }
}

/// <summary>
/// Type operand data.
/// </summary>
internal record VMTypeData : VMInlineOperandData
{
    public string Name { get; }
    public bool HasGenericTypeParameters { get; }
    public bool IsGenericParameterIndex { get; }
    public int GenericMethodParameterIndex { get; } 
    public int GenericTypeParameterIndex { get; }
    public VMInlineOperand[] GenericParameters { get; }
    
    public VMTypeData(BinaryReader reader) : base(VMInlineOperandType.Type)
    {
        Name = "";
        GenericParameters = Array.Empty<VMInlineOperand>();
        foreach (var field in EazyDevirt.Devirtualization.DevirtualizationContext.Instance.TypeOperandLayout.Fields)
        {
            switch(field)
            {
                case VMTypeWireField.Name: Name=reader.ReadString();break;
                case VMTypeWireField.GenericParameter: IsGenericParameterIndex=reader.ReadBoolean();break;
                case VMTypeWireField.GenericArguments: HasGenericTypeParameters=reader.ReadBoolean();break;
                case VMTypeWireField.MethodIndex: GenericMethodParameterIndex=reader.ReadInt32();break;
                case VMTypeWireField.TypeIndex: GenericTypeParameterIndex=reader.ReadInt32();break;
                case VMTypeWireField.Arguments: GenericParameters=VMInlineOperand.ReadArrayInternal(reader);break;
            }
        }
    }
}

/// <summary>
/// Field operand data.
/// </summary>
internal record VMFieldData : VMInlineOperandData
{
    public VMInlineOperand DeclaringType { get; }
    public string Name { get; }
    public bool IsStatic { get; }
    
    public VMFieldData(BinaryReader reader) : base(VMInlineOperandType.Field)
    {
        DeclaringType = VMInlineOperand.ReadInternal(reader);
        Name = reader.ReadString();
        IsStatic = reader.ReadBoolean();
    }
}

/// <summary>
/// Method operand data.
/// </summary>
internal record VMMethodData : VMInlineOperandData
{
    public VMInlineOperand DeclaringType { get; }
    public byte Flags { get; } 
    
    public bool IsStatic { get; } 
    public bool HasGenericParameters { get; }
    public string Name { get; } 
    public VMInlineOperand ReturnType { get; } 
    public VMInlineOperand[] Parameters { get; } 
    public VMInlineOperand[] GenericParameters { get; } 

    public VMMethodData(BinaryReader reader) : base(VMInlineOperandType.Method)
    {
        DeclaringType = VMInlineOperand.ReadInternal(reader);
        var context=EazyDevirt.Devirtualization.DevirtualizationContext.Instance;
        if(context.MethodFlagsAreBooleans)
        {
            bool first=reader.ReadBoolean(),second=reader.ReadBoolean();
            IsStatic=context.MethodStaticBooleanFirst?first:second;
            HasGenericParameters=context.MethodStaticBooleanFirst?second:first;
            Flags=(byte)((IsStatic?context.MethodStaticMask:0)|(HasGenericParameters?context.MethodGenericMask:0));
        }
        else
        {
        Flags = reader.ReadByte();
        // these constants are also different between versions (#3)
        IsStatic = (Flags & EazyDevirt.Devirtualization.DevirtualizationContext.Instance.MethodStaticMask) > 0;
        HasGenericParameters = (Flags & EazyDevirt.Devirtualization.DevirtualizationContext.Instance.MethodGenericMask) > 0;
        }
        Name = reader.ReadString();
        ReturnType = VMInlineOperand.ReadInternal(reader);
        Parameters = VMInlineOperand.ReadArrayInternal(reader);
        GenericParameters = VMInlineOperand.ReadArrayInternal(reader);
    }
}

/// <summary>
/// String operand data.
/// </summary>
internal record VMUserStringData : VMInlineOperandData
{
    /// <summary>
    /// String value.
    /// </summary>
    public string Value { get; }

    public VMUserStringData(BinaryReader reader) : base(VMInlineOperandType.UserString)
    {
        Value = reader.ReadString();
    }
}

/// <summary>
/// Eaz call operand data.
/// </summary>
internal record VMEazCallData : VMInlineOperandData
{
    /// <summary>
    /// Contains the flags of the vm method contained.
    /// </summary>
    public int EazCallValue { get; }
    
    /// <summary>
    /// The method's operand data vm stream position.
    /// </summary>
    public int VMMethodPosition { get; }

    public VMEazCallData(BinaryReader reader) : base(VMInlineOperandType.EazCall)
    {
        EazCallValue = reader.ReadInt32();
        VMMethodPosition = reader.ReadInt32();
    }
}
