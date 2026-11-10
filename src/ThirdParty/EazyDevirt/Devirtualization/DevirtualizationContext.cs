using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Metadata.Tables;
using EazyDevirt.Core.Architecture;
using EazyDevirt.Core.IO;
using EazyDevirt.Devirtualization.Options;
using EazyDevirt.Logging;
using EazyDevirt.PatternMatching;

namespace EazyDevirt.Devirtualization;

internal record DevirtualizationContext
{
    // got lazy
    public static DevirtualizationContext Instance { get; set; } = null!;
    
    public DevirtualizationOptions Options { get; }
    public ModuleDefinition Module { get; }
    public PatternMatcher PatternMatcher { get; }
    public ConsoleLogger Console { get; }
    public List<VerifiedKeyRecord> VerifiedKeys { get; } = new();
    public Dictionary<MethodDefinition,(string Namespace,string TypeName,string MethodName,string FullName)> OriginalMethodNames { get; } = new();
    public Action<string,int,int>? Progress {get;set;}
    public ReferenceImporter Importer { get; }
    
    public MetadataToken VMResourceGetterMdToken { get; set; }
    
    /// <summary>
    /// VM Type fields set in the vm type's constructor.
    /// Used in pattern matching opcodes.
    /// </summary>
    public Dictionary<FieldDefinition, ITypeDefOrRef> VMTypeFields { get; set; } = null!;

    /// <summary>
    /// VM method locals field.
    /// Used in pattern matching ldloc and stloc opcodes.
    /// </summary>
    public FieldDefinition VMLocalsField { get; set; } = null!;

    /// <summary>
    /// VM method arguments field.
    /// Used in pattern matching ldarg and starg opcodes.
    /// </summary>
    public FieldDefinition VMArgumentsField { get; set; } = null!;
    public MethodDefinition VMExecuteVMMethod { get; set; } = null!;
    public TypeDefinition VMDeclaringType { get; set; } = null!;
    public Stream VMStream { get; set; } = null!;
    public Stream VMResolverStream { get; set; } = null!;
    public int PositionCryptoKey { get; set; }
    public int MethodCryptoKey { get; set; }

    public List<VMMethod> VMMethods { get; set; } = null!;
    public VMHeaderLayout HeaderLayout { get; set; } = null!;
    public Dictionary<int, AsmResolver.PE.DotNet.Cil.CilOperandType> OperandLayout { get; set; } = new();
    public Dictionary<byte, EazyDevirt.Core.Architecture.InlineOperands.VMInlineOperandType> InlineLayout { get; set; } = new();
    public byte TokenTag { get; set; }
    public VMTypeWireLayout TypeOperandLayout { get; set; } = null!;
    public int MethodStaticMask { get; set; }
    public int MethodGenericMask { get; set; }
    public bool MethodFlagsAreBooleans { get; set; }
    public bool MethodStaticBooleanFirst { get; set; }
    public bool StandardMetadataReader { get; set; }
    public bool PositionOrCipher { get; set; }

    internal CryptoStreamV3 CreateCryptoStream(Stream stream,int key,bool leaveOpen=true) =>
        new(stream,key,leaveOpen,PositionOrCipher);

    internal BinaryReader CreateMetadataReader(Stream stream) => StandardMetadataReader
        ? new VMMetadataReader(stream) : new VMBinaryReader(stream,true);

    public DevirtualizationContext(DevirtualizationOptions opts)
    {
        Options = opts;
        Module = ModuleDefinition.FromFile(Options.Assembly.FullName);
        foreach(var type in Module.GetAllTypes())
        {
            var top=type;while(top.DeclaringType!=null)top=top.DeclaringType;
            string ns=top.Namespace?.ToString()??"";
            string qualified=type.FullName;
            string typeName=ns.Length>0&&qualified.StartsWith(ns+".",StringComparison.Ordinal)?qualified.Substring(ns.Length+1):qualified;
            foreach(var method in type.Methods)OriginalMethodNames[method]=(ns,typeName,method.Name?.ToString()??"",method.FullName);
        }
        if(Module.MetadataResolver is DefaultMetadataResolver metadata && metadata.AssemblyResolver is AssemblyResolverBase resolver)
        {
            resolver.SearchDirectories.Add(Path.GetDirectoryName(Options.Assembly.FullName)!);
            resolver.SearchDirectories.Add(AppDomain.CurrentDomain.BaseDirectory);
            resolver.SearchDirectories.Add(Path.GetDirectoryName(typeof(object).Assembly.Location)!);
            foreach (string directory in Enumerable.Reverse(Options.DependencyDirectories))
                if (Directory.Exists(directory)) resolver.SearchDirectories.Insert(0, directory);
            foreach (string directory in RuntimeReferencePaths.Discover(Module).Reverse())
                resolver.SearchDirectories.Insert(0, directory);
        }
        PatternMatcher = new PatternMatcher();
        Console = new ConsoleLogger();
        Importer = Module.DefaultImporter;
        // hacky fix for resolved types within current assembly / module
        Importer.ImportScope(new AssemblyReference(Module.Assembly!));
    }
}

