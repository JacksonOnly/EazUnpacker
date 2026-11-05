using System.Collections.Concurrent;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Transforms;
using ICSharpCode.Decompiler.TypeSystem;
using Newtonsoft.Json;

namespace Unpacker;

internal sealed class SourceDataPlan
{
    internal readonly Dictionary<int, (string Name, byte[] Bytes)> Fields = new();
    internal readonly HashSet<int> EmptyInitializers = new();
    internal readonly ConcurrentDictionary<int, byte> Exported = new();

    internal SourceDataPlan(string assembly,byte[]? projection=null)
    {
        using var module=projection==null?dnlib.DotNet.ModuleDefMD.Load(assembly):dnlib.DotNet.ModuleDefMD.Load(projection);
        foreach(var type in module.GetTypes())
        {
            foreach(var field in type.Fields.Where(f=>f.HasFieldRVA && f.InitialValue?.Length>0))
                Fields.Add((int)field.MDToken.Raw,(field.FullName,field.InitialValue.ToArray()));
            var ctor=type.FindStaticConstructor();
            if(!type.IsGlobalModuleType && ctor?.HasBody==true && ctor.Body.ExceptionHandlers.Count==0
                && ctor.Body.Instructions.Count>0 && ctor.Body.Instructions.Last().OpCode.Code==dnlib.DotNet.Emit.Code.Ret
                && ctor.Body.Instructions.All(i=>i.OpCode.Code is dnlib.DotNet.Emit.Code.Nop or dnlib.DotNet.Emit.Code.Ret))
                EmptyInitializers.Add((int)type.MDToken.Raw);
        }
    }

    internal void WriteReport(string path)
    {
        using var sha=SHA256.Create();
        File.WriteAllText(path,JsonConvert.SerializeObject(Fields.Select(f=>new {
            Token="0x"+f.Key.ToString("X8"),Field=f.Value.Name,Bytes=f.Value.Bytes.Length,
            Sha256=BitConverter.ToString(sha.ComputeHash(f.Value.Bytes)).Replace("-","").ToLowerInvariant(),
            Exported=Exported.ContainsKey(f.Key),
            Detail=Exported.ContainsKey(f.Key)?"Concrete unmanaged C# field initializer; original bytes retained.":"No standalone field emitted (may be folded into array initialization)."
        }),Formatting.Indented));
    }
}

internal sealed class SourceDataCompatibility : DepthFirstAstVisitor, IAstTransform
{
    private readonly SourceDataPlan plan;
    internal SourceDataCompatibility(SourceDataPlan plan) => this.plan=plan;
    public void Run(AstNode root,TransformContext context)=>root.AcceptVisitor(this);

    public override void VisitTypeDeclaration(TypeDeclaration type)
    {
        if(type.GetSymbol() is ITypeDefinition symbol && plan.EmptyInitializers.Contains(MetadataTokens.GetToken(symbol.MetadataToken))
            && !type.Members.OfType<ConstructorDeclaration>().Any(c=>(c.Modifiers&Modifiers.Static)!=0))
            type.Members.Add(new ConstructorDeclaration {Name=type.Name,Modifiers=Modifiers.Static,Body=new BlockStatement()});
        foreach(var field in type.Members.OfType<FieldDeclaration>().ToArray())
        foreach(var variable in field.Variables)
        {
            var definition=variable.GetSymbol() as IField ?? field.GetSymbol() as IField;
            if(definition==null || !plan.Fields.TryGetValue(MetadataTokens.GetToken(definition.MetadataToken),out var data))continue;
            if(variable.Initializer!=null)throw new NotSupportedException("RVA field already has an initializer: "+data.Name);
            string helper="RestoreFieldData"+MetadataTokens.GetToken(definition.MetadataToken).ToString("X8");
            while(type.Members.Any(m=>m.Name==helper))helper+="_";
            var body=new BlockStatement();
            body.Statements.Add(new VariableDeclarationStatement(field.ReturnType.Clone(),"value",new DefaultValueExpression(field.ReturnType.Clone())));
            AstType SystemType(string name)=>new MemberType(new MemberType(new SimpleType("global"),"System"){IsDoubleColon=true},name);
            body.Statements.Add(new VariableDeclarationStatement(new PrimitiveType("byte").MakeArrayType(),"bytes",
                new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(SystemType("Convert")),"FromBase64String"),new PrimitiveExpression(Convert.ToBase64String(data.Bytes)))));
            body.Statements.Add(new IfElseStatement(new BinaryOperatorExpression(new SizeOfExpression(field.ReturnType.Clone()),BinaryOperatorType.InEquality,
                new MemberReferenceExpression(new IdentifierExpression("bytes"),"Length")),
                new ThrowStatement(new ObjectCreateExpression(SystemType("InvalidOperationException"),new PrimitiveExpression("Recovered field layout mismatch")))));
            body.Statements.Add(new VariableDeclarationStatement(new PrimitiveType("byte").MakePointerType(),"address",
                new CastExpression(new PrimitiveType("byte").MakePointerType(),new UnaryOperatorExpression(UnaryOperatorType.AddressOf,new IdentifierExpression("value")))));
            var loop=new ForStatement {
                Condition=new BinaryOperatorExpression(new IdentifierExpression("index"),BinaryOperatorType.LessThan,new MemberReferenceExpression(new IdentifierExpression("bytes"),"Length")),
                EmbeddedStatement=new ExpressionStatement(new AssignmentExpression(
                    new IndexerExpression(new IdentifierExpression("address"),new IdentifierExpression("index")),
                    new IndexerExpression(new IdentifierExpression("bytes"),new IdentifierExpression("index")))) };
            loop.Initializers.Add(new VariableDeclarationStatement(new PrimitiveType("int"),"index",new PrimitiveExpression(0)));
            loop.Iterators.Add(new ExpressionStatement(new UnaryOperatorExpression(UnaryOperatorType.PostIncrement,new IdentifierExpression("index"))));
            body.Statements.Add(loop);body.Statements.Add(new ReturnStatement(new IdentifierExpression("value")));
            type.Members.Add(new MethodDeclaration {Name=helper,Modifiers=Modifiers.Private|Modifiers.Static|Modifiers.Unsafe,ReturnType=field.ReturnType.Clone(),Body=body});
            variable.Initializer=new InvocationExpression(new IdentifierExpression(helper));
            foreach(var comment in field.Descendants.OfType<Comment>().Where(c=>c.Content.Contains("Not supported: data(")).ToArray())comment.Remove();
            plan.Exported.TryAdd(MetadataTokens.GetToken(definition.MetadataToken),0);
        }
        if(type.Members.OfType<FieldDeclaration>().Any(f=>f.Descendants.OfType<Comment>().Any(c=>c.Content.Contains("Not supported: data("))))
            throw new NotSupportedException("Unexported RVA field data in "+type.Name+"; refusing a silently zero-initialized C# field.");
        base.VisitTypeDeclaration(type);
    }
}
