using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Abstractions;
using EazyDevirt.Devirtualization;
using Echo.Memory;
using Echo.Platforms.AsmResolver.Emulation;
using Echo.Platforms.AsmResolver.Emulation.Dispatch;
using Echo.Platforms.AsmResolver.Emulation.Invocation;

namespace EazyDevirt.Core.IO;

internal class VMBinaryReader : VMBinaryReaderBase
{
    private static DevirtualizationContext Ctx => DevirtualizationContext.Instance;

    private static TypeDefinition _instanceType = null!;
    private static FieldDefinition _isMemoryStreamFieldDef = null!;
    private static FieldDefinition _bufferFieldDef = null!;
    private static MethodDefinition _fillBufferMethodDef = null!;
    private static HashSet<IMethodDescriptor> _fillBufferOperands = null!;
    private static SzArrayTypeSignature _byteArrayType = null!;

    private sealed class MethodOperandComparer : IEqualityComparer<IMethodDescriptor>
    {
        internal static readonly MethodOperandComparer Instance = new();
        public bool Equals(IMethodDescriptor? x, IMethodDescriptor? y) => ReferenceEquals(x, y);
        public int GetHashCode(IMethodDescriptor value) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(value);
    }

    private static MethodDefinition _readInt32MethodDef = null!;
    private static MethodDefinition _readUInt32MethodDef = null!;
    private static MethodDefinition _readInt64MethodDef = null!;
    private static MethodDefinition _readUInt64MethodDef = null!;
    private static MethodDefinition _readInt16MethodDef = null!;
    private static MethodDefinition _readUInt16MethodDef = null!;
    private static MethodDefinition _readSingleMethodDef = null!;
    private static MethodDefinition _readDoubleMethodDef = null!;
    private static MethodDefinition _readDecimalMethodDef = null!;

    private static CilVirtualMachine _vm = null!;
    private static CilThread _thread = null!;
    private static BitVector _instanceObj = null!;

    private static bool _initialized;
    private static int _steps;
    private static int _primitiveSize;

    public VMBinaryReader(Stream input, bool leaveOpen = false) : base(input, Encoding.UTF8, leaveOpen)
    {
        if (!_initialized || !ReferenceEquals(_vm.ContextModule, Ctx.Module))
        {
            _initialized = false;
            _vm = new CilVirtualMachine(Ctx.Module, false); // 32 bit always breaks something, even on 32 bit only assemblies.
            _byteArrayType = new SzArrayTypeSignature(Ctx.Module.CorLibTypeFactory.Byte);
            _fillBufferOperands = new HashSet<IMethodDescriptor>(MethodOperandComparer.Instance);
            _vm.Invoker = DefaultInvokers.StepIn;
            _vm.Dispatcher.BeforeInstructionDispatch += DispatcherOnBeforeInstructionDispatch;
            
            _thread = _vm.CreateThread();

            FindInstanceDefs();
            if (_instanceType is null)
                throw new ArgumentNullException(nameof(_instanceType), "Failed finding VMBinaryReader instance type!");
            if (_bufferFieldDef is null)
                throw new ArgumentNullException(nameof(_bufferFieldDef),
                    "Failed finding VMBinaryReader _buffer field!");

            SetupInstanceObj();
            _initialized = true;
        }
    }

    #region Setup

    private static void FindInstanceDefs()
    {
        _instanceType = null!; _bufferFieldDef = null!; _isMemoryStreamFieldDef = null!;
        _fillBufferMethodDef = null!;
        var candidates = new List<(TypeDefinition Type, MethodDefinition Int32, FieldDefinition Buffer)>();
        // Prefer the reader actually stored by the VM runtime. Nested string and
        // resource readers can otherwise share the same primitive signatures.
        var referenced = Ctx.VMDeclaringType?.Fields.Where(f => !f.IsStatic)
            .Select(f => f.Signature?.FieldType.ToTypeDefOrRef()?.Resolve()).Where(t => t != null).ToArray()
            ?? Array.Empty<TypeDefinition>();
        foreach (var type in Ctx.Module.GetAllTypes())
        {
            if (!type.Fields.Any(f => !f.IsStatic && f.Signature?.FieldType.FullName == "System.Text.Decoder")) continue;
            foreach (var method in type.Methods.Where(m => Primitive(m, "System.Int32")))
            {
                var buffers = method.CilMethodBody!.Instructions.Where(i => i.OpCode.Code == CilCode.Ldfld)
                    .Select(i => i.Operand).OfType<FieldDefinition>().Where(f => !f.IsStatic &&
                        f.DeclaringType == type && f.Signature?.FieldType.FullName == "System.Byte[]")
                    .GroupBy(f => f).Where(g => g.Count() == 4).Select(g => g.Key).ToArray();
                if (buffers.Length != 1 || !method.CilMethodBody.Instructions.Any(i => i.OpCode.Code == CilCode.Shl)) continue;
                if (new[] { "System.UInt32", "System.Int64", "System.UInt64", "System.Int16", "System.UInt16",
                    "System.Single", "System.Double", "System.Decimal" }.Any(name => type.Methods.Count(m => Primitive(m, name)) != 1)) continue;
                candidates.Add((type, method, buffers[0]));
            }
        }
        var anchored = candidates.Where(c => referenced.Contains(c.Type)).ToArray();
        var matches = anchored.Length != 0 ? anchored : candidates.ToArray();
        if (matches.Length != 1) throw new NotSupportedException(matches.Length == 0
            ? "Cannot identify the VM primitive reader." : "Ambiguous VM primitive reader.");
        var selected = matches[0];
        _instanceType = selected.Type; _readInt32MethodDef = selected.Int32; _bufferFieldDef = selected.Buffer;
        var booleans = _readInt32MethodDef.CilMethodBody!.Instructions.Where(i => i.OpCode.Code == CilCode.Ldfld)
            .Select(i => i.Operand).OfType<FieldDefinition>().Where(f => f.DeclaringType == _instanceType &&
                f.Signature?.FieldType.FullName == "System.Boolean").Distinct().ToArray();
        if (booleans.Length > 1) throw new NotSupportedException("Ambiguous VM primitive fast-path flag.");
        _isMemoryStreamFieldDef = booleans.SingleOrDefault()!;
        var fills = _readInt32MethodDef.CilMethodBody.Instructions.Select(i => i.Operand).OfType<IMethodDescriptor>()
            .Select(m => m.Resolve()).Where(m => m != null && m.DeclaringType == _instanceType && !m.IsStatic &&
                m.Signature?.ReturnType.FullName == "System.Void" && m.Signature.ParameterTypes.Count == 1 &&
                m.Signature.ParameterTypes[0].FullName == "System.Int32").Distinct().ToArray();
        if (fills.Length != 1) throw new NotSupportedException("Cannot identify the VM primitive buffer refill.");
        _fillBufferMethodDef = fills[0]!;
        _fillBufferOperands.Add(_fillBufferMethodDef);
        // Resolve call-site aliases once, never on the per-primitive hot path.
        foreach (var operand in _instanceType.Methods.Where(m => m.CilMethodBody != null)
            .SelectMany(m => m.CilMethodBody!.Instructions).Where(i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt)
            .Select(i => i.Operand).OfType<IMethodDescriptor>())
            if (operand.DeclaringType?.FullName == _instanceType.FullName && operand.Resolve() == _fillBufferMethodDef)
                _fillBufferOperands.Add(operand);
        MethodDefinition Read(string name) => _instanceType.Methods.Single(m => Primitive(m, name));
        _readUInt32MethodDef = Read("System.UInt32"); _readInt64MethodDef = Read("System.Int64");
        _readUInt64MethodDef = Read("System.UInt64"); _readInt16MethodDef = Read("System.Int16");
        _readUInt16MethodDef = Read("System.UInt16"); _readSingleMethodDef = Read("System.Single");
        _readDoubleMethodDef = Read("System.Double"); _readDecimalMethodDef = Read("System.Decimal");
    }

    private static bool Primitive(MethodDefinition method, string name) => !method.IsStatic &&
        method.Signature?.ParameterTypes.Count == 0 && method.Signature.ReturnType.FullName == name &&
        method.CilMethodBody?.Instructions.Count > 0;

    private void SetupInstanceObj()
    {
        var instanceAddress = _vm.Heap.AllocateObject(_instanceType, true); 
        var instanceObjectSpan = _vm.Heap.GetObjectSpan(instanceAddress);
        // This is a boolean that determines whether to use ReadInt32Special in the ReadInt32 method.
        // It should never have to be set to 1 unless ReadInt32Special changes endianness, in which case, we will need to find the ReadInt32Special method and add a handler for it as well.
        if (_isMemoryStreamFieldDef != null)
            instanceObjectSpan.SliceObjectField(_vm.ValueFactory, _isMemoryStreamFieldDef).U8 = 0;
        _instanceObj = _vm.ValueFactory.CreateNativeInteger(instanceAddress);
    }
    
    #endregion Setup

    #region Emulation
    
    private static void DispatcherOnBeforeInstructionDispatch(object? _, CilDispatchEventArgs e)
    {
        if (++_steps > 100000) throw new InvalidDataException("VM primitive reader exceeded its instruction budget.");
        var ins = e.Instruction;
        if (ins.OpCode.Code is not (CilCode.Call or CilCode.Callvirt or CilCode.Newobj) ||
            ins.Operand is not IMethodDescriptor method || method.Signature is not { } signature) return;
        var frame = e.Context.CurrentFrame;
        var vm = e.Context.Machine;
        var factory = vm.ContextModule.CorLibTypeFactory;
        T Pop<T>(TypeSignature type)
        {
            var vector = frame.EvaluationStack.Pop(type);
            try { return vm.ObjectMarshaller.ToObject<T>(vector)!; }
            finally { vm.ValueFactory.BitVectorPool.Return(vector); }
        }
        void DropThis()
        {
            if (!signature.HasThis) return;
            var vector = frame.EvaluationStack.Pop(factory.Object);
            vm.ValueFactory.BitVectorPool.Return(vector);
        }
        var bytesType = _byteArrayType;
        if (ins.OpCode.Code != CilCode.Newobj &&
            (ReferenceEquals(method, _fillBufferMethodDef) || _fillBufferOperands.Contains(method)))
        {
            int count = Pop<int>(factory.Int32); DropThis();
            if (count < 0 || count > _primitiveSize) throw new InvalidDataException("Invalid VM primitive buffer size.");
        }
        else if (ins.OpCode.Code != CilCode.Newobj && method.DeclaringType == _instanceType &&
            signature.ReturnType.FullName == "System.Byte[]" && signature.ParameterTypes.Count == 0)
        {
            DropThis();
            frame.EvaluationStack.Push(vm.ObjectMarshaller.ToBitVector(new byte[16]), signature.ReturnType);
        }
        else if (ins.OpCode.Code != CilCode.Newobj && method.DeclaringType == _instanceType &&
            signature.ReturnType.FullName == "System.IO.BinaryReader" && signature.ParameterTypes.Count == 1 &&
            signature.ParameterTypes[0].FullName == "System.Byte[]")
        {
            var bytes = Pop<byte[]>(bytesType); DropThis();
            // Keep the byte buffer as an opaque reader handle. Only the two
            // standard floating-point reads below may consume this handle.
            frame.EvaluationStack.Push(vm.ObjectMarshaller.ToBitVector(bytes), signature.ReturnType);
        }
        else if (ins.OpCode.Code != CilCode.Newobj && method.DeclaringType?.FullName == "System.IO.BinaryReader" &&
            signature.ParameterTypes.Count == 0 && signature.HasThis &&
            method.Name?.ToString() is "ReadSingle" or "ReadDouble")
        {
            var bytes = Pop<byte[]>(signature.HasThis ? method.DeclaringType.ToTypeSignature() : bytesType);
            using var reader = ToBinaryReader(bytes);
            if (method.Name == "ReadSingle") frame.EvaluationStack.Push(reader.ReadSingle(), factory.Single);
            else frame.EvaluationStack.Push(reader.ReadDouble(), factory.Double);
        }
        else if (ins.OpCode.Code != CilCode.Newobj && method.DeclaringType?.FullName == "System.BitConverter" &&
            method.Name == "Int64BitsToDouble" && signature.ParameterTypes.Count == 1 &&
            signature.ParameterTypes[0].FullName == "System.Int64" && signature.ReturnType.FullName == "System.Double")
        {
            frame.EvaluationStack.Push(BitConverter.Int64BitsToDouble(Pop<long>(factory.Int64)), factory.Double);
        }
        else if (ins.OpCode.Code == CilCode.Newobj && method.DeclaringType?.FullName == "System.Decimal" &&
            signature.ParameterTypes.Select(p => p.FullName).SequenceEqual(new[] {
                "System.Int32", "System.Int32", "System.Int32", "System.Boolean", "System.Byte" }))
        {
            byte scale = Pop<byte>(factory.Byte); bool negative = Pop<bool>(factory.Boolean);
            int high = Pop<int>(factory.Int32), middle = Pop<int>(factory.Int32), low = Pop<int>(factory.Int32);
            var value = new decimal(low, middle, high, negative, scale);
            frame.EvaluationStack.Push(vm.ObjectMarshaller.ToBitVector(value), method.DeclaringType.ToTypeSignature());
        }
        else return;
        e.IsHandled = true;
        frame.ProgramCounter += ins.Size;
    }

    private T ReadEmulated<T>(byte[] bytes)
    {
        var instanceObjectHandle = _instanceObj.AsObjectHandle(_vm);
        instanceObjectHandle.WriteField(_bufferFieldDef, _vm.ObjectMarshaller.ToBitVector(bytes));

        
        _thread.CallStack.Peek().WriteArgument(0, _instanceObj);
        _primitiveSize = bytes.Length; _steps = 0;
        try { _thread.Run(); }
        catch
        {
            while (_thread.CallStack.Count > 1) _thread.CallStack.Pop();
            _vm.ObjectMapMemory.Clear();
            throw;
        }

        var typeSig = Ctx.Importer.ImportTypeSignature(typeof(T));
        var value = _thread.CallStack.Peek().EvaluationStack.Pop(typeSig);
        try { return _vm.ObjectMarshaller.ToObject<T>(value)!; }
        finally
        {
            _vm.ValueFactory.BitVectorPool.Return(value);
            _vm.ObjectMapMemory.Clear();
        }
    }

    #endregion Emulation

    #region Overrides

    private byte[] ReadPrimitiveBytes(int count)
    {
        var bytes=ReadBytes(count);
        if(bytes.Length!=count)throw new EndOfStreamException("Truncated VM primitive.");
        return bytes;
    }

    public override string ReadString()
    {
        uint length=0;
        for(int shift=0;shift<35;shift+=7)
        {
            byte part=ReadByte();
            if(shift==28 && part>7)throw new FormatException("Invalid VM string length.");
            length|=(uint)(part & 127)<<shift;
            if((part & 128)!=0)continue;
            if(length>BaseStream.Length-BaseStream.Position)
                throw new EndOfStreamException("VM string exceeds the resource.");
            return Encoding.UTF8.GetString(ReadPrimitiveBytes((int)length));
        }
        throw new FormatException("Invalid VM string length.");
    }

    public override sbyte ReadSByte()
    {
        var bytes = ReadPrimitiveBytes(1);
        return (sbyte)bytes[0];
    }

    public override int ReadInt32()
    {
        var bytes = ReadPrimitiveBytes(4);

        _thread.CallStack.Push(_readInt32MethodDef);
        return ReadEmulated<int>(bytes);
    }

    // this always has the same endianness as ReadInt32
    public override int ReadInt32Special()
    {
        var bytes = ReadPrimitiveBytes(4);

        _thread.CallStack.Push(_readInt32MethodDef);
        return ReadEmulated<int>(bytes);
    }

    public override uint ReadUInt32()
    {
        var bytes = ReadPrimitiveBytes(4);

        _thread.CallStack.Push(_readUInt32MethodDef);
        return ReadEmulated<uint>(bytes);
    }

    public override long ReadInt64()
    {
        var bytes = ReadPrimitiveBytes(8);

        _thread.CallStack.Push(_readInt64MethodDef);
        return ReadEmulated<long>(bytes);
    }

    public override ulong ReadUInt64()
    {
        var bytes = ReadPrimitiveBytes(8);

        _thread.CallStack.Push(_readUInt64MethodDef);
        return ReadEmulated<ulong>(bytes);
    }

    public override short ReadInt16()
    {
        var bytes = ReadPrimitiveBytes(2);
     
        _thread.CallStack.Push(_readInt16MethodDef);
        return ReadEmulated<short>(bytes);
    }
    
    public override ushort ReadUInt16()
    {
        var bytes = ReadPrimitiveBytes(2);
  
        _thread.CallStack.Push(_readUInt16MethodDef);
        return ReadEmulated<ushort>(bytes);
    }
    
    public override float ReadSingle()
    {
        var bytes = ReadPrimitiveBytes(4);

        _thread.CallStack.Push(_readSingleMethodDef);
        return ReadEmulated<float>(bytes);
    }

    public override double ReadDouble()
    {
        var bytes = ReadPrimitiveBytes(8);

        _thread.CallStack.Push(_readDoubleMethodDef);
        return ReadEmulated<double>(bytes);
    }

    // untested, looks to be unused
    public override decimal ReadDecimal()
    {
        var bytes = ReadPrimitiveBytes(16);

        _thread.CallStack.Push(_readDecimalMethodDef);
        return ReadEmulated<decimal>(bytes);
    }
    
    #endregion Overrides

    private static BinaryReader ToBinaryReader(byte[] input)
    {
        var memoryStream = new MemoryStream(8);
        var binaryReader = new BinaryReader(memoryStream);
        binaryReader.BaseStream.Position = 0L;
        memoryStream.Write(input, 0, input.Length);
        memoryStream.Position = 0L;
        return binaryReader;
    }
}
