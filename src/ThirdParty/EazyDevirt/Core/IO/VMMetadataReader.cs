using System.Text;

namespace EazyDevirt.Core.IO;

/// <summary>Reads standard metadata primitives while bounding serialized string allocations.</summary>
internal sealed class VMMetadataReader : BinaryReader
{
    internal VMMetadataReader(Stream stream) : base(stream,Encoding.UTF8,true) { }

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
            var bytes=ReadBytes((int)length);
            if(bytes.Length!=(int)length)throw new EndOfStreamException("Truncated VM string.");
            return Encoding.UTF8.GetString(bytes);
        }
        throw new FormatException("Invalid VM string length.");
    }
}
