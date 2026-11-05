using System.Collections.Concurrent;
using System.Xml.Linq;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Transforms;
using ICSharpCode.Decompiler.TypeSystem;

namespace Unpacker;

internal sealed class SourceTypeAliases
{
    private readonly ConcurrentDictionary<string,string> used=new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string,string>? byAssembly;
    private HashSet<string>? ambiguous;
    private readonly object initialization=new();

    internal IAstTransform For(DecompilerTypeSystem types)
    {
        lock(initialization)
        {
            if(ambiguous==null)
            {
                var modules=types.ReferencedModules.OrderBy(m=>m.AssemblyName,StringComparer.Ordinal).ToArray();
                var owners=new Dictionary<string,string>(StringComparer.Ordinal);
                ambiguous=new HashSet<string>(StringComparer.Ordinal);
                foreach(var module in modules)
                foreach(var type in module.TopLevelTypeDefinitions.Where(t=>t.Accessibility==Accessibility.Public))
                {
                    string name=type.ReflectionName;
                    if(owners.TryGetValue(name,out string previous))
                    {
                        if(previous!=module.AssemblyName)ambiguous.Add(name);
                    }
                    else owners.Add(name,module.AssemblyName);
                }
                byAssembly=modules.Select(m=>m.AssemblyName).Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select((name,index)=>(name,alias:"UnpackReference"+index)).ToDictionary(p=>p.name,p=>p.alias,StringComparer.OrdinalIgnoreCase);
            }
            return new Qualify(ambiguous,byAssembly!,used);
        }
    }

    internal void ConfigureProject(XDocument project)
    {
        foreach(var alias in used)
        {
            var matches=project.Descendants("Reference").Where(r=>string.Equals(
                ((string?)r.Attribute("Include")??"").Split(',')[0],alias.Key,StringComparison.OrdinalIgnoreCase)).ToArray();
            if(matches.Length!=1)throw new InvalidDataException("An aliased source reference is missing or ambiguous.");
            matches[0].SetElementValue("Aliases","global,"+alias.Value);
        }
    }

    private sealed class Qualify : DepthFirstAstVisitor,IAstTransform
    {
        private readonly HashSet<string> ambiguous;
        private readonly Dictionary<string,string> assemblies;
        private readonly ConcurrentDictionary<string,string> used;
        private readonly HashSet<string> fileAliases=new(StringComparer.Ordinal);
        internal Qualify(HashSet<string> ambiguous,Dictionary<string,string> assemblies,ConcurrentDictionary<string,string> used)
        {this.ambiguous=ambiguous;this.assemblies=assemblies;this.used=used;}

        public void Run(AstNode root,TransformContext context)
        {
            fileAliases.Clear();
            if(root is not SyntaxTree tree || ambiguous.Count==0)return;
            root.AcceptVisitor(this);
            foreach(string alias in fileAliases.OrderBy(a=>a,StringComparer.Ordinal))
            {
                var first=tree.Members.FirstOrDefault();
                if(first!=null)tree.Members.InsertBefore(first,new ExternAliasDeclaration(alias));
            }
        }

        public override void VisitTypeReferenceExpression(TypeReferenceExpression expression)
        {
            base.VisitTypeReferenceExpression(expression);
            var type=expression.Type.GetResolveResult().Type;
            var definition=type.GetDefinition();
            if(definition==null || !ambiguous.Contains(definition.ReflectionName) ||
                definition.ParentModule?.AssemblyName is not string name || !assemblies.TryGetValue(name,out string alias))return;
            var replacement=new TypeSystemAstBuilder {AlwaysUseGlobal=true}.ConvertType(type);
            var qualifier=replacement.DescendantsAndSelf.OfType<MemberType>()
                .FirstOrDefault(t=>t.IsDoubleColon && t.Target is SimpleType {Identifier:"global"});
            if(qualifier==null)return;
            qualifier.Target=new SimpleType(alias);
            expression.Type=replacement;
            used.TryAdd(name,alias);
            fileAliases.Add(alias);
        }
    }
}
