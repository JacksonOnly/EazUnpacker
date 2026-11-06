using System.ComponentModel;
using System.Reflection;
using System.Xaml;
using System.Xaml.Schema;
using System.Xml;
using System.Xml.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Newtonsoft.Json.Linq;

namespace Unpacker;

// WPF's binary writer is used in the matching CLR worker, never in the CLI.
// Target constructors are not called; initializer suppression applies only to
// the temporary reflection copy, never to the assembly being edited.
internal sealed class BamlCompiler
{
    private static readonly XNamespace Roundtrip="urn:unpacker:baml";
    private static readonly XNamespace Xaml="http://schemas.microsoft.com/winfx/2006/xaml";
    private static readonly XNamespace Compatibility="http://schemas.openxmlformats.org/markup-compatibility/2006";
    private static readonly XNamespace Options="http://schemas.microsoft.com/winfx/2006/xaml/presentation/options";
    private readonly XamlSchemaContext schema=new();
    private readonly Dictionary<string,XElement> baseline;
    private readonly Type writerType=typeof(System.Windows.Application).Assembly.GetType("System.Windows.Markup.BamlWriter",true)!;
    private object writer=null!;

    private BamlCompiler(XDocument original)=>baseline=original.Descendants().ToDictionary(e=>(string)e.Attribute(Roundtrip+"Id")!,StringComparer.Ordinal);

    internal static int Run(string requestFile)
    {
        var request=JObject.Parse(File.ReadAllText(requestFile));
        string ownerPath=(string)request["owner"]!,originalPath=(string)request["original"]!;
        using var dependencies=new DependencyLoadScope(originalPath,ownerPath);
        string reflectionDirectory=Path.Combine(Path.GetDirectoryName(requestFile)!,"reflection");
        Directory.CreateDirectory(reflectionDirectory);
        string reflectionPath=Path.Combine(reflectionDirectory,Path.GetFileName(ownerPath));
        using(var module=ModuleDefMD.Load(ownerPath))
        {
            foreach(var type in module.GetTypes())
            {
                var initializer=type.FindStaticConstructor();
                if(initializer==null)continue;
                initializer.Body=new CilBody();initializer.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            module.IsILOnly=true;module.Is32BitRequired=false;module.Is32BitPreferred=false;module.Machine=dnlib.PE.Machine.I386;
            module.Write(reflectionPath,new ModuleWriterOptions(module){Logger=DummyLogger.NoThrowInstance});
        }
        var owner=Assembly.LoadFrom(reflectionPath);
        ResolveEventHandler resolve=(_,e)=>new AssemblyName(e.Name).FullName==owner.FullName?owner:null;
        AppDomain.CurrentDomain.AssemblyResolve+=resolve;
        try
        {
            foreach(var reference in owner.GetReferencedAssemblies())
                try {Assembly.Load(reference);}
                catch(FileNotFoundException) { }
                catch(FileLoadException) { }
                catch(BadImageFormatException) { }
            foreach(var item in (JArray)request["items"]!)
            {
                var before=ReadXml((string)item["baseline"]!);
                var after=ReadXml((string)item["xaml"]!);
                var compiler=new BamlCompiler(before);
                compiler.Validate(before,after);
                bool unchanged=Equivalent(before.Root!,after.Root!);
                byte[] data=unchanged?File.ReadAllBytes((string)item["baml"]!):compiler.Compile(after);
                if(!unchanged)ValidateBinary(data,owner);
                File.WriteAllBytes((string)item["output"]!,data);
            }
            return 0;
        }
        finally {AppDomain.CurrentDomain.AssemblyResolve-=resolve;}
    }

    private static XDocument ReadXml(string path)
    {
        using var stream=File.OpenRead(path);
        using var reader=XmlReader.Create(stream,new XmlReaderSettings {DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=256L*1024*1024});
        var document=XDocument.Load(reader,LoadOptions.PreserveWhitespace);
        if(document.Root==null || document.Descendants().Count()>250000 || document.Descendants().Any(e=>e.Ancestors().Take(257).Count()>256))
            throw new InvalidDataException("XAML document limits exceeded.");
        // Accept the spelling emitted by older exports as well.
        foreach(var element in document.Descendants())
        {
            var legacy=element.Attribute(Xaml+"XmlAttributeProperties.XmlSpace");
            if(legacy==null)continue;
            var space=element.Attribute(XNamespace.Xml+"space");
            if(space!=null && space.Value!=legacy.Value)throw new InvalidDataException("Conflicting XML whitespace directives.");
            element.SetAttributeValue(XNamespace.Xml+"space",legacy.Value);legacy.Remove();
        }
        return document;
    }

    private void Validate(XDocument before,XDocument after)
    {
        if(after.Root!.Name!=before.Root!.Name || (string?)after.Root.Attribute(Xaml+"Class")!=(string?)before.Root.Attribute(Xaml+"Class") ||
            (string?)after.Root.Attribute(Roundtrip+"Id")!=(string?)before.Root.Attribute(Roundtrip+"Id"))
            throw new InvalidDataException("The root type and code-behind class must be preserved.");
        var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var element in after.Descendants())
        {
            string? id=(string?)element.Attribute(Roundtrip+"Id");
            if(id==null)
            {
                if(element.Attributes().Any(a=>a.Name.Namespace==Roundtrip))throw new InvalidDataException("Invalid roundtrip marker.");
                continue;
            }
            if(!seen.Add(id) || !baseline.TryGetValue(id,out var original) || element.Name!=original.Name ||
                !element.Attributes().Where(a=>a.Name.Namespace==Roundtrip).OrderBy(a=>a.Name.LocalName).Select(a=>a.ToString())
                    .SequenceEqual(original.Attributes().Where(a=>a.Name.Namespace==Roundtrip).OrderBy(a=>a.Name.LocalName).Select(a=>a.ToString())))
                throw new InvalidDataException("Roundtrip markers and connected element types must be preserved.");
            foreach(string name in Events(original))
                if((string?)element.Attribute(XName.Get(name))!=(string?)original.Attribute(XName.Get(name)))
                    throw new InvalidDataException("Code-behind handlers cannot be changed by a resource edit.");
            if(original.Attribute(Roundtrip+"Generated")!=null && !Equivalent(original,element))
                throw new InvalidDataException("Generated connector nodes must be preserved.");
        }
        foreach(var generated in baseline.Values.Where(e=>e.Attribute(Roundtrip+"Generated")!=null))
            if(!seen.Contains((string)generated.Attribute(Roundtrip+"Id")!) && generated.Parent!=null && seen.Contains((string?)generated.Parent.Attribute(Roundtrip+"Id")??""))
                throw new InvalidDataException("Generated connector nodes cannot be removed from a connected element.");
    }

    private byte[] Compile(XDocument document)
    {
        using var stream=new MemoryStream();
        writer=Activator.CreateInstance(writerType,BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance,null,new object[]{stream},null)!;
        Call("WriteStartDocument");
        WriteElement(document.Root!);
        Call("WriteEndDocument");Call("Close");
        return stream.ToArray();
    }

    private void WriteElement(XElement element)
    {
        if(element.Attribute(Roundtrip+"Generated")!=null)return;
        Type type=Resolve(element);
        bool converted=!element.HasElements && element.Nodes().OfType<XText>().Any(t=>!string.IsNullOrWhiteSpace(t.Value)) && TypeDescriptor.GetConverter(type).CanConvertFrom(typeof(string));
        Call("WriteStartElement",type.Assembly.FullName,type.FullName,false,converted);
        foreach(var attribute in element.Attributes().Where(a=>a.IsNamespaceDeclaration))
            Call("WriteXmlnsProperty",attribute.Name.LocalName=="xmlns"?"":attribute.Name.LocalName,attribute.Value);
        foreach(var attribute in element.Attributes().Where(a=>!a.IsNamespaceDeclaration && a.Name.Namespace!=Roundtrip))
        {
            if(attribute.Name.Namespace==Compatibility)
            {
                if(attribute.Name.LocalName!="Ignorable")throw new NotSupportedException("Unsupported markup compatibility directive.");
                continue;
            }
            if(Ignorable(element,attribute.Name.Namespace))continue;
            if(attribute.Name.Namespace==Xaml)
            {
                if(attribute.Name.LocalName is "Class" or "ClassModifier")continue;
                if(attribute.Name.LocalName is not ("Name" or "Key" or "Uid" or "Shared"))throw new NotSupportedException("Unsupported XAML directive.");
                Call("WriteDefAttribute",attribute.Name.LocalName,attribute.Value);continue;
            }
            if(attribute.Name.Namespace==Options)
            {Call("WritePresentationOptionsAttribute",attribute.Name.LocalName,attribute.Value);continue;}
            if(attribute.Name.Namespace==XNamespace.Xml)
            {
                Type xmlOwner;string property,usage;
                if(attribute.Name.LocalName=="lang")
                {xmlOwner=typeof(System.Windows.FrameworkElement);property="Language";usage="XmlLang";}
                else if(attribute.Name.LocalName=="space" && attribute.Value is "default" or "preserve")
                {xmlOwner=typeof(System.Windows.Markup.XmlAttributeProperties);property="XmlSpace";usage="XmlSpace";}
                else throw new NotSupportedException("Unsupported XML directive.");
                Call("WriteProperty",xmlOwner.Assembly.FullName,xmlOwner.FullName,property,attribute.Value,
                    Enum.Parse(writerType.Assembly.GetType("System.Windows.Markup.BamlAttributeUsage",true)!,usage));
                continue;
            }
            string name=attribute.Name.LocalName;Type declaring=type;
            int dot=name.LastIndexOf('.');
            XamlMember? member;
            if(dot>=0)
            {
                declaring=Resolve(element,name.Substring(0,dot),attribute.Name.NamespaceName.Length==0?element.GetDefaultNamespace().NamespaceName:attribute.Name.NamespaceName);
                name=name.Substring(dot+1);
                var owner=schema.GetXamlType(declaring);
                member=owner.GetAttachableMember(name)??owner.GetMember(name);
            }
            else member=schema.GetXamlType(type).GetMember(name);
            string? id=(string?)element.Attribute(Roundtrip+"Id");
            if(id!=null && Events(baseline[id]).Contains(attribute.Name.ToString(),StringComparer.Ordinal))continue;
            if(member?.IsEvent==true || declaring.GetEvent(name)!=null)throw new NotSupportedException("New code-behind event handlers cannot be compiled as resources.");
            if(member==null || member.IsUnknown)throw new InvalidDataException("Unknown XAML property.");
            declaring=member.DeclaringType?.UnderlyingType??declaring;
            string value=attribute.Value;
            // The public runtime writer does not maintain the build task's
            // implicit Style/Template TargetType while parsing property names.
            if(member.Type?.UnderlyingType==typeof(System.Windows.DependencyProperty) && value.IndexOf('.')<0 && !value.StartsWith("{",StringComparison.Ordinal))
            {
                string? target=element.Ancestors().Select(e=>(string?)e.Attribute("TargetType")).FirstOrDefault(v=>v!=null);
                if(target!=null)
                {
                    if(target.StartsWith("{",StringComparison.Ordinal))
                    {
                        int space=target.IndexOf(' ');
                        if(space<0 || !target.EndsWith("}",StringComparison.Ordinal))throw new NotSupportedException("Unsupported style target type.");
                        target=target.Substring(space+1,target.Length-space-2).Trim();
                    }
                    value=target+"."+value;
                }
            }
            Call("WriteProperty",declaring.Assembly.FullName,declaring.FullName,name,value,
                Enum.ToObject(writerType.Assembly.GetType("System.Windows.Markup.BamlAttributeUsage",true)!,0));
        }
        string? connections=(string?)element.Attribute(Roundtrip+"ConnectionId");
        if(connections!=null)
            foreach(string id in connections.Split(','))Call("WriteConnectionId",int.Parse(id,System.Globalization.CultureInfo.InvariantCulture));
        WriteNodes(element,type);
        Call("WriteEndElement");
    }

    private void WriteNodes(XElement parent,Type contentType)
    {
        foreach(var node in parent.Nodes())
        {
            if(node is XElement child)
            {
                if(Ignorable(child,child.Name.Namespace))continue;
                if(child.Name.Namespace==Xaml && child.Name.LocalName=="Arguments")
                {Call("WriteStartConstructor");WriteNodes(child,contentType);Call("WriteEndConstructor");continue;}
                int dot=child.Name.LocalName.LastIndexOf('.');
                if(dot<0) {WriteElement(child);continue;}
                var declaring=Resolve(child,child.Name.LocalName.Substring(0,dot),child.Name.NamespaceName);
                string property=child.Name.LocalName.Substring(dot+1);
                var owner=schema.GetXamlType(declaring);
                var member=owner.GetMember(property)??owner.GetAttachableMember(property);
                if(member==null || member.IsUnknown || member.IsEvent)throw new InvalidDataException("Unknown XAML property element.");
                declaring=member.DeclaringType?.UnderlyingType??declaring;
                Call("WriteStartComplexProperty",declaring.Assembly.FullName,declaring.FullName,property);
                WriteNodes(child,member.Type?.UnderlyingType??typeof(object));
                Call("WriteEndComplexProperty");
            }
            else if(node is XText text)
            {
                // Pretty-printing around comments creates text nodes even in
                // otherwise empty controls. Such indentation is not UI content.
                if(!PreservesSpace(parent) && string.IsNullOrWhiteSpace(text.Value))continue;
                if(text.Value.Length==0)continue;
                var converter=TypeDescriptor.GetConverter(contentType);
                bool convert=converter.CanConvertFrom(typeof(string));
                Call("WriteText",text.Value,convert?converter.GetType().Assembly.FullName:null,convert?converter.GetType().FullName:null);
            }
        }
    }

    private Type Resolve(XElement context,string? local=null,string? ns=null)
    {
        if(local==null && (string?)context.Attribute(Roundtrip+"Type") is string hint)return Type.GetType(hint,true)!;
        string name=XmlConvert.DecodeName(local??context.Name.LocalName);
        string xmlNamespace=ns??context.Name.NamespaceName;
        if(xmlNamespace.StartsWith("clr-namespace:",StringComparison.Ordinal))
        {
            string[] parts=xmlNamespace.Substring(14).Split(';');
            string clr=parts[0];string? assembly=parts.Skip(1).FirstOrDefault(p=>p.StartsWith("assembly=",StringComparison.Ordinal))?.Substring(9);
            var found=AppDomain.CurrentDomain.GetAssemblies().Where(a=>assembly==null || a.GetName().Name==assembly)
                .Select(a=>a.GetType(clr.Length==0?name:clr+"."+name,false)).FirstOrDefault(t=>t!=null);
            if(found!=null)return found;
        }
        return schema.GetXamlType(new XamlTypeName(xmlNamespace,name))?.UnderlyingType??throw new InvalidDataException("Unknown XAML type or missing dependency.");
    }

    private void Call(string method,params object?[] values)
    {
        try {writerType.GetMethod(method)!.Invoke(writer,values);}
        catch(TargetInvocationException exception) {throw new InvalidDataException("BAML writer rejected "+method+".",exception.InnerException);}
    }

    private static IEnumerable<string> Events(XElement element)=>((string?)element.Attribute(Roundtrip+"Events")??"").Split('|').Where(v=>v.Length!=0);

    private static bool PreservesSpace(XElement element)=>element.AncestorsAndSelf()
        .Select(e=>(string?)e.Attribute(XNamespace.Xml+"space")).FirstOrDefault(v=>v!=null)=="preserve";

    private static void ValidateBinary(byte[] data,Assembly owner)
    {
        // Read through WPF's actual binary reader, without constructing the
        // target UI. Reject malformed node streams before publishing resources.
        using var stream=new MemoryStream(data,false);
        var type=typeof(System.Windows.Application).Assembly.GetType("System.Windows.Baml2006.Baml2006Reader",true)!;
        using var reader=(System.Xaml.XamlReader)Activator.CreateInstance(type,BindingFlags.Instance|BindingFlags.Public|BindingFlags.NonPublic,
            null,new object[]{stream,new XamlReaderSettings {LocalAssembly=owner}},null)!;
        var stack=new Stack<XamlNodeType>();int roots=0;
        while(reader.Read())
        {
            var current=stack.Count==0?XamlNodeType.None:stack.Peek();
            switch(reader.NodeType)
            {
                case XamlNodeType.StartObject:
                case XamlNodeType.GetObject:
                    if(current!=XamlNodeType.StartMember && !(current==XamlNodeType.None && reader.NodeType==XamlNodeType.StartObject && roots++==0))
                        throw new InvalidDataException("BAML contains an object outside a member.");
                    stack.Push(XamlNodeType.StartObject);break;
                case XamlNodeType.StartMember:
                    if(current!=XamlNodeType.StartObject)throw new InvalidDataException("BAML contains an invalid member start.");
                    stack.Push(XamlNodeType.StartMember);break;
                case XamlNodeType.Value:
                    if(current!=XamlNodeType.StartMember)throw new InvalidDataException("BAML contains text outside a member.");
                    break;
                case XamlNodeType.EndMember:
                    if(current!=XamlNodeType.StartMember)throw new InvalidDataException("BAML contains an invalid member end.");
                    stack.Pop();break;
                case XamlNodeType.EndObject:
                    if(current!=XamlNodeType.StartObject)throw new InvalidDataException("BAML contains an invalid object end.");
                    stack.Pop();break;
            }
        }
        if(stack.Count!=0 || roots!=1)throw new InvalidDataException("BAML node stream is incomplete.");
    }

    private static bool Ignorable(XElement element,XNamespace ns)=>ns!=XNamespace.None && element.AncestorsAndSelf()
        .SelectMany(e=>((string?)e.Attribute(Compatibility+"Ignorable")??"").Split(' '))
        .Where(p=>p.Length!=0 && p!="ub").Any(p=>element.GetNamespaceOfPrefix(p)==ns);

    private static bool Equivalent(XElement left,XElement right)
    {
        if(left.Name!=right.Name || !left.Attributes().OrderBy(a=>a.Name.ToString()).Select(a=>a.Name+"="+a.Value)
            .SequenceEqual(right.Attributes().OrderBy(a=>a.Name.ToString()).Select(a=>a.Name+"="+a.Value)))return false;
        XNode[] Nodes(XElement element)=>element.Nodes().Where(n=>n is XElement || n is XText text &&
            (!string.IsNullOrWhiteSpace(text.Value) || PreservesSpace(element))).ToArray();
        var a=Nodes(left);var b=Nodes(right);
        return a.Length==b.Length && a.Zip(b,(x,y)=>x is XElement ex && y is XElement ey?Equivalent(ex,ey):XNode.DeepEquals(x,y)).All(equal=>equal);
    }
}
