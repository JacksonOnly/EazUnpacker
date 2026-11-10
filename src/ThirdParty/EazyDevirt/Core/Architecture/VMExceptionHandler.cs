using AsmResolver.DotNet.Code.Cil;

namespace EazyDevirt.Core.Architecture;

internal record VMExceptionHandler
{
    public int VMHandlerType { get; }
    public int CatchType { get; }
    public uint TryStart { get; }
    public uint HandlerStart { get; }
    public uint TryLength { get; }
    public uint FilterStart { get; }
    private readonly VMExceptionLayout _layout;

    public CilExceptionHandlerType HandlerType
    {
        get
        {
            return _layout.Kinds.TryGetValue(VMHandlerType, out var kind) ? kind
                : throw new NotSupportedException("Unknown VM exception kind: " + VMHandlerType);
        }
    }
    
    public VMExceptionHandler(BinaryReader reader, VMExceptionLayout layout)
    {
        _layout = layout;
        foreach (var field in layout.Fields)
            switch (field) {
                case VMExceptionField.Kind: VMHandlerType = layout.Int32Kind ? reader.ReadInt32() : reader.ReadByte(); break;
                case VMExceptionField.CatchType: CatchType = reader.ReadInt32(); break;
                case VMExceptionField.HandlerStart: HandlerStart = reader.ReadUInt32(); break;
                case VMExceptionField.TryStart: TryStart = reader.ReadUInt32(); break;
                case VMExceptionField.TryLength: TryLength = reader.ReadUInt32(); break;
                case VMExceptionField.FilterStart: FilterStart = reader.ReadUInt32(); break;
                case VMExceptionField.UnusedOffset: reader.ReadUInt32(); break;
            }
    }

    public override string ToString() =>
        $"HandlerType: {HandlerType} | TryStart: {TryStart} | TryEnd: {TryStart + TryLength}";
}
