using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Writer;

namespace EazFixer.Processors
{
    // Reuse the target decoder only in the isolated backend. An encoder is
    // accepted only after an exact forward-decoder roundtrip, never guessed.
    internal static class ResourceRepacker
    {
        internal static Dictionary<string,byte[]> Pack(ModuleDef source,ModuleDef edited,IEnumerable<Assembly> assemblies,
            IEnumerable<string> requested,MethodInfo decrypt,MethodInfo decompress,out HashSet<string> handled)
        {
            handled=new HashSet<string>(StringComparer.Ordinal);
            var wanted=new HashSet<string>(requested,StringComparer.Ordinal);
            var identities=new HashSet<string>(assemblies.Select(a=>a.FullName),StringComparer.Ordinal);
            var replacements=edited.Resources.OfType<EmbeddedResource>().ToDictionary(r=>r.Name.String,StringComparer.Ordinal);
            var updates=new Dictionary<string,byte[]>(StringComparer.Ordinal);
            foreach(var resource in source.Resources.OfType<EmbeddedResource>())
            {
                byte[] raw=resource.CreateReader().ToArray();
                if(raw.Length>256*1024*1024)throw new InvalidDataException("Protected resource limit exceeded.");
                bool matched=false;
                foreach(bool encrypted in new[]{false,true})
                {
                    if(encrypted && decrypt==null)continue;
                    byte[] decoded;
                    try {decoded=encrypted?Invoke(decrypt,raw):raw;}
                    catch(TargetInvocationException) {continue;}
                    foreach(bool compressed in new[]{false,true})
                    {
                        if(compressed && decompress==null)continue;
                        byte[] image;
                        try {image=compressed?Invoke(decompress,decoded):decoded;}
                        catch(TargetInvocationException) {continue;}
                        if(image.Length<512 || image.Length>256*1024*1024 || image[0]!='M' || image[1]!='Z')continue;
                        using(var carrier=TryLoad(image))
                        {
                            if(carrier==null || carrier.Assembly==null || !identities.Contains(carrier.Assembly.FullName))continue;
                            if(carrier.GetTypes().SelectMany(t=>t.Methods).Any(m=>m.HasBody))throw new InvalidDataException("Resource carrier contains executable code.");
                            var changes=carrier.Resources.OfType<EmbeddedResource>().Where(r=>wanted.Contains(r.Name.String)).ToArray();
                            if(changes.Length==0){matched=true;break;}
                            foreach(var entry in changes)
                            {
                                if(!replacements.TryGetValue(entry.Name.String,out var replacement) || replacement.Attributes!=entry.Attributes)
                                    throw new InvalidDataException("Protected resource identity mismatch.");
                                int index=carrier.Resources.IndexOf(entry);
                                carrier.Resources[index]=new EmbeddedResource(entry.Name,replacement.CreateReader().ToArray(),entry.Attributes);
                            }
                            using var output=new MemoryStream();
                            carrier.Write(output,new ModuleWriterOptions(carrier){MetadataOptions={Flags=MetadataFlags.PreserveAll}});
                            byte[] plain=output.ToArray();
                            byte[] encoded=compressed?Compress(decoded,image,plain,decompress):plain;
                            if(encrypted)
                            {
                                // XOR/stream transforms are self-inverse. Other
                                // ciphers require an explicit supported encoder.
                                bool reversible;
                                try {reversible=Invoke(decrypt,decoded).SequenceEqual(raw);}
                                catch(TargetInvocationException) {reversible=false;}
                                if(!reversible)throw new InvalidDataException("The protected cipher has no verified reverse transform.");
                                encoded=Invoke(decrypt,encoded);
                            }
                            byte[] check=encrypted?Invoke(decrypt,encoded):encoded;
                            if(compressed)check=Invoke(decompress,check);
                            if(!check.SequenceEqual(plain))throw new InvalidDataException("Protected resource encoding roundtrip failed.");
                            updates.Add(resource.Name.String,encoded);
                            foreach(var entry in changes)handled.Add(entry.Name.String);
                            matched=true;
                        }
                        if(matched)break;
                    }
                    if(matched)break;
                }
            }
            return updates;
        }

        private static ModuleDefMD TryLoad(byte[] image)
        {
            try {return ModuleDefMD.Load(image);}
            catch(BadImageFormatException) {return null;}
            catch(IOException) {return null;}
        }

        private static byte[] Invoke(MethodInfo method,byte[] data)
        {
            var result=method.Invoke(null,new object[]{(byte[])data.Clone()}) as byte[];
            if(result==null || result.Length>256*1024*1024)throw new InvalidDataException("Protected resource decoder returned invalid bytes.");
            return result;
        }

        private static byte[] Compress(byte[] encoded,byte[] original,byte[] edited,MethodInfo decoder)
        {
            int prefix=encoded.Length-original.Length;
            if(prefix>=0 && prefix<=32 && encoded.Skip(prefix).SequenceEqual(original))
            {
                byte[] result=new byte[prefix+edited.Length];Buffer.BlockCopy(encoded,0,result,0,prefix);
                for(int i=0;i+4<=prefix;i+=4)
                    if(BitConverter.ToInt32(result,i)==original.Length)Buffer.BlockCopy(BitConverter.GetBytes(edited.Length),0,result,i,4);
                Buffer.BlockCopy(edited,0,result,prefix,edited.Length);
                if(Invoke(decoder,result).SequenceEqual(edited))return result;
            }
            if(encoded.Length>2 && encoded[0]==0x1f && encoded[1]==0x8b)
            {
                using var output=new MemoryStream();
                using(var gzip=new GZipStream(output,CompressionLevel.Optimal,true))gzip.Write(edited,0,edited.Length);
                byte[] result=output.ToArray();
                if(Invoke(decoder,result).SequenceEqual(edited))return result;
            }
            // Admit raw deflate only after reproducing the original plaintext;
            // supported length-prefixed streams retain their framing as well.
            foreach(int offset in new[]{0,4})
            {
                if(encoded.Length<=offset || offset==4 && BitConverter.ToInt32(encoded,0)!=original.Length)continue;
                try
                {
                    using var input=new MemoryStream(encoded,offset,encoded.Length-offset,false);
                    using var deflate=new DeflateStream(input,CompressionMode.Decompress);
                    using var inflated=new MemoryStream();
                    var buffer=new byte[8192];int count;
                    while((count=deflate.Read(buffer,0,buffer.Length))!=0)
                    {if(inflated.Length+count>original.Length)throw new InvalidDataException();inflated.Write(buffer,0,count);}
                    if(!inflated.ToArray().SequenceEqual(original))continue;
                    using var output=new MemoryStream();
                    if(offset==4)output.Write(BitConverter.GetBytes(edited.Length),0,4);
                    using(var compressor=new DeflateStream(output,CompressionLevel.Optimal,true))compressor.Write(edited,0,edited.Length);
                    byte[] result=output.ToArray();
                    if(Invoke(decoder,result).SequenceEqual(edited))return result;
                }
                catch(InvalidDataException) { }
                catch(TargetInvocationException) { }
            }
            throw new InvalidDataException("No verified encoder for the original resource compression format.");
        }
    }
}
