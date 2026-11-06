namespace Unpacker;

// The preserialized resource reader uses the same v2 tables but a different
// reader header and opaque user-type payloads. Normalize only a private read
// copy; preserve the original reader profile when rebuilding the container.
internal static class ResourceContainerEnvelope
{
    internal static byte[] ForRead(byte[] image,out byte[] header)
    {
        int size=HeaderSize(image);
        header=new byte[size];Buffer.BlockCopy(image,12,header,0,size);
        string reader;
        using(var stream=new MemoryStream(header,false))
        using(var binary=new BinaryReader(stream,ResourceFileEditor.Utf8))reader=binary.ReadString().Split(',')[0].Trim();
        if(reader is not ("System.Resources.ResourceReader" or "System.Resources.Extensions.DeserializingResourceReader"))
            throw ResourceFileEditor.Invalid("资源容器使用尚不支持的自定义读取器。");
        // Future resource-manager header versions are skipped by their declared
        // length. This private copy therefore bypasses only the reader-type
        // check; the v2 resource tables and all payload bytes remain unchanged.
        var readable=(byte[])image.Clone();
        Buffer.BlockCopy(BitConverter.GetBytes(2),0,readable,4,4);
        return readable;
    }

    internal static byte[] WithHeader(byte[] image,byte[] header)
    {
        int oldSize=HeaderSize(image);
        using var stream=new MemoryStream(image,false);
        using var binary=new BinaryReader(stream,ResourceFileEditor.Utf8);
        int oldHeaderEnd=12+oldSize,newHeaderEnd=checked(12+header.Length);
        stream.Position=oldHeaderEnd;
        int version=binary.ReadInt32(),count=binary.ReadInt32(),types=binary.ReadInt32();
        if(version!=2 || count<0 || count>ResourceFileEditor.MaxEntries || types<0 || types>ResourceFileEditor.MaxEntries)
            throw ResourceFileEditor.Invalid("资源容器表格式无效。");
        for(int i=0;i<types;i++)binary.ReadString();
        int oldTypeEnd=checked((int)stream.Position),newTypeEnd=checked(oldTypeEnd+newHeaderEnd-oldHeaderEnd);
        int oldHashStart=checked((oldTypeEnd+7)&~7),newHashStart=checked((newTypeEnd+7)&~7);
        int shift=checked(newHashStart-oldHashStart),newLength=checked(image.Length+shift);
        if(newLength>ResourceFileEditor.MaxFileBytes)throw ResourceFileEditor.Invalid("资源容器超过大小限制。");
        int table=checked(oldHashStart+count*8);
        if(table>image.Length-4)throw ResourceFileEditor.Invalid("资源容器索引越界。");
        stream.Position=table;int dataOffset=binary.ReadInt32();
        if(dataOffset<table+4 || dataOffset>image.Length)throw ResourceFileEditor.Invalid("资源容器数据偏移无效。");
        var output=new byte[newLength];
        Buffer.BlockCopy(image,0,output,0,12);
        Buffer.BlockCopy(BitConverter.GetBytes(header.Length),0,output,8,4);
        Buffer.BlockCopy(header,0,output,12,header.Length);
        Buffer.BlockCopy(image,oldHeaderEnd,output,newHeaderEnd,oldTypeEnd-oldHeaderEnd);
        for(int i=newTypeEnd;i<newHashStart;i++)output[i]=(byte)"PAD"[(i-newTypeEnd)%3];
        Buffer.BlockCopy(image,oldHashStart,output,newHashStart,image.Length-oldHashStart);
        Buffer.BlockCopy(BitConverter.GetBytes(checked(dataOffset+shift)),0,output,table+shift,4);
        return output;
    }

    private static int HeaderSize(byte[] image)
    {
        if(image.Length<12 || BitConverter.ToUInt32(image,0)!=0xBEEFCACE || BitConverter.ToInt32(image,4)!=1)
            throw ResourceFileEditor.Invalid("资源容器头无效。");
        int size=BitConverter.ToInt32(image,8);
        if(size<0 || size>image.Length-12)throw ResourceFileEditor.Invalid("资源容器头长度无效。");
        return size;
    }
}
