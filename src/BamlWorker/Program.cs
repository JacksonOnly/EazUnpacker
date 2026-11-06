using System.Reflection;
using System.Xml.Linq;
using ICSharpCode.BamlDecompiler;
using ICSharpCode.Decompiler.Metadata;
using Newtonsoft.Json.Linq;

namespace Unpacker;

// Keep the pinned decompiler's private record model isolated from the main
// ILSpy dependency. Persist annotations before its document pass clones nodes.
internal static class Program
{
    private static readonly XNamespace Roundtrip="urn:unpacker:baml";
    private static readonly XNamespace Compatibility="http://schemas.openxmlformats.org/markup-compatibility/2006";
    private const BindingFlags Instance=BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance;
    private const BindingFlags Static=BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static;

    [STAThread]
    private static int Main(string[] args)
    {
        try {return WorkerDesktop.Run(args,Run);}
        catch {Console.Error.WriteLine("BAML backend failed.");return 1;}
    }

    private static int Run(string[] args)
    {
        var request=JObject.Parse(File.ReadAllText(args[0]));
        string owner=(string)request["owner"]!;
        using var module=new PEFile(owner);
        var resolver=new UniversalAssemblyResolver(owner,false,module.DetectTargetFrameworkId());
        foreach(string directory in request["directories"]!.Values<string>())resolver.AddSearchDirectory(directory);
        var settings=new BamlDecompilerSettings {ThrowOnAssemblyResolveErrors=false};
        var decompiler=new XamlDecompiler(module,resolver,settings);
        foreach(var item in (JArray)request["items"]!)
        {
            using var stream=File.OpenRead((string)item["baml"]!);
            var document=Decompile(decompiler,settings,stream);
            document.Save((string)item["xaml"]!);
        }
        return 0;
    }

    private static XDocument Decompile(XamlDecompiler decompiler,BamlDecompilerSettings settings,Stream stream)
    {
        var assembly=typeof(XamlDecompiler).Assembly;
        var baml=assembly.GetType("ICSharpCode.BamlDecompiler.Baml.BamlReader")!.GetMethod("ReadDocument",Static)!
            .Invoke(null,new object[]{stream,CancellationToken.None})!;
        var context=assembly.GetType("ICSharpCode.BamlDecompiler.XamlContext")!.GetMethod("Construct",Static)!
            .Invoke(null,new[]{Get(decompiler,"typeSystem"),baml,CancellationToken.None,settings})!;
        var node=Get(context,"RootNode");
        var handler=assembly.GetType("ICSharpCode.BamlDecompiler.HandlerMap")!.GetMethod("LookupHandler",Static)!
            .Invoke(null,new[]{Get(node,"Type")})!;
        var translated=handler.GetType().GetMethod("Translate",Instance)!.Invoke(handler,new object?[]{context,node,null})!;
        var document=new XDocument((XElement)Get(Get(translated,"Xaml"),"Element"));
        var passes=(Array)typeof(XamlDecompiler).GetField("rewritePasses",Static)!.GetValue(null)!;
        foreach(var pass in passes)
        {
            Dictionary<XElement,HashSet<XAttribute>>? attributes=null;
            HashSet<XElement>? elements=null;
            if(pass!.GetType().Name=="ConnectionIdRewritePass")
            {
                attributes=document.Descendants().ToDictionary(e=>e,e=>e.Attributes().ToHashSet());
                elements=document.Descendants().ToHashSet();
            }
            if(pass.GetType().Name=="DocumentRewritePass")
                foreach(var element in document.Descendants())
                {
                    var annotations=element.Annotations<object>().ToArray();
                    var ids=annotations.Where(a=>a.GetType().Name=="BamlConnectionId").Select(a=>Get(a,"Id").ToString());
                    if(ids.Any())element.SetAttributeValue(Roundtrip+"ConnectionId",string.Join(",",ids));
                    var type=annotations.FirstOrDefault(a=>a.GetType().Name=="XamlType");
                    if(type!=null)
                    {
                        string ns=Get(type,"TypeNamespace").ToString()!;
                        element.SetAttributeValue(Roundtrip+"Type",(ns.Length==0?"":ns+".")+Get(type,"TypeName")+", "+Get(type,"FullAssemblyName"));
                    }
                }
            pass.GetType().GetMethod("Run",Instance)!.Invoke(pass,new object[]{context,document});
            if(attributes!=null)
                foreach(var element in document.Descendants())
                {
                    if(!elements!.Contains(element)) {element.SetAttributeValue(Roundtrip+"Generated","true");continue;}
                    var added=element.Attributes().Where(a=>!attributes[element].Contains(a) && !a.IsNamespaceDeclaration &&
                        a.Name.Namespace!=Roundtrip && a.Name.LocalName!="Name").Select(a=>a.Name.ToString()).ToArray();
                    if(added.Length!=0)element.SetAttributeValue(Roundtrip+"Events",string.Join("|",added));
                }
        }
        var root=document.Root??throw new InvalidDataException();
        root.SetAttributeValue(XNamespace.Xmlns+"ub",Roundtrip.NamespaceName);
        root.SetAttributeValue(XNamespace.Xmlns+"mc",Compatibility.NamespaceName);
        root.SetAttributeValue(Compatibility+"Ignorable",((string?)root.Attribute(Compatibility+"Ignorable")+" ub").Trim());
        // Some custom-control roots have a non-default namespace with no prefix.
        if(root.Name.Namespace!=root.GetDefaultNamespace() && root.GetPrefixOfNamespace(root.Name.Namespace)==null)
        {
            string prefix="ui";int suffix=2;
            while(root.GetNamespaceOfPrefix(prefix)!=null)prefix="ui"+suffix++;
            root.SetAttributeValue(XNamespace.Xmlns+prefix,root.Name.NamespaceName);
        }
        int index=0;
        foreach(var element in root.DescendantsAndSelf())element.SetAttributeValue(Roundtrip+"Id",(index++).ToString(System.Globalization.CultureInfo.InvariantCulture));
        return document;
    }

    private static object Get(object value,string name)=>value.GetType().GetProperty(name,Instance)?.GetValue(value)??
        value.GetType().GetField(name,Instance)!.GetValue(value)!;
}
