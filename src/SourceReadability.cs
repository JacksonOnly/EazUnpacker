using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.OutputVisitor;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Transforms;
using Newtonsoft.Json;

namespace Unpacker;

internal sealed class ReadabilityStats
{
    internal int ConstantConditions,EmptyFinally,AsyncMethods,StateMachines;
    internal readonly ConcurrentDictionary<string,string> ExtraFiles=new();
    internal readonly ConcurrentBag<object> Moved=new();
}

internal sealed class ReadableControlFlow : DepthFirstAstVisitor,IAstTransform
{
    private readonly ReadabilityStats stats;
    internal ReadableControlFlow(ReadabilityStats stats)=>this.stats=stats;
    public void Run(AstNode root,TransformContext context)=>root.AcceptVisitor(this);
    public override void VisitIfElseStatement(IfElseStatement statement)
    {
        base.VisitIfElseStatement(statement);
        if(!TryBoolean(statement.Condition,out bool value))return;
        var chosen=value?statement.TrueStatement:statement.FalseStatement;
        if(chosen==null)statement.ReplaceWith(new BlockStatement());
        else statement.ReplaceWith(chosen.Detach());
        Interlocked.Increment(ref stats.ConstantConditions);
    }
    public override void VisitTryCatchStatement(TryCatchStatement statement)
    {
        base.VisitTryCatchStatement(statement);
        if(statement.FinallyBlock is not { } block || block.Statements.Count!=0)return;
        if(statement.CatchClauses.Count==0)statement.ReplaceWith(statement.TryBlock.Detach());
        else statement.FinallyBlock=null;
        Interlocked.Increment(ref stats.EmptyFinally);
    }
    private static bool TryBoolean(Expression expression,out bool value)
    {
        value=false;
        if(expression is ParenthesizedExpression p)return TryBoolean(p.Expression,out value);
        if(expression is PrimitiveExpression {Value:bool literal}){value=literal;return true;}
        if(expression is not BinaryOperatorExpression b || !Integer(b.Left,out decimal left) || !Integer(b.Right,out decimal right))return false;
        switch(b.Operator){
            case BinaryOperatorType.Equality:value=left==right;return true;
            case BinaryOperatorType.InEquality:value=left!=right;return true;
            case BinaryOperatorType.LessThan:value=left<right;return true;
            case BinaryOperatorType.LessThanOrEqual:value=left<=right;return true;
            case BinaryOperatorType.GreaterThan:value=left>right;return true;
            case BinaryOperatorType.GreaterThanOrEqual:value=left>=right;return true;
            default:return false;
        }
    }
    private static bool Integer(Expression? expression,out decimal value)
    {
        value=0;
        if(expression is ParenthesizedExpression p)return Integer(p.Expression,out value);
        object? constant=expression is PrimitiveExpression literal?literal.Value:null;
        if(constant==null && expression is not null)
        {
            var resolved=expression.GetResolveResult();
            if(resolved.IsCompileTimeConstant)constant=resolved.ConstantValue;
        }
        if(constant is not (sbyte or byte or short or ushort or int or uint or long or ulong or char))return false;
        value=constant is char c?c:Convert.ToDecimal(constant);return true;
    }
}

internal static class SourceReadability
{
    internal static void Finish(string directory,ReadabilityStats stats)
    {
        int dataComments=0;
        foreach(string path in Directory.GetFiles(directory,"*.cs",SearchOption.AllDirectories))
        {
            string source=File.ReadAllText(path);
            // ILSpy's output visitor emits these from field metadata after AST
            // transforms. Remove only a data comment with our concrete initializer.
            source=Regex.Replace(source,@"(RestoreFieldData[0-9A-F_]+\(\))/\* Not supported: data\([0-9A-Fa-f\s]+\) \*/",m=>{dataComments++;return m.Groups[1].Value;});
            if(source.Contains("Not supported: data("))throw new InvalidDataException("Unexported field data: "+path);
            File.WriteAllText(path,source);
        }
        foreach(var file in stats.ExtraFiles)
        {
            string path=Path.Combine(directory,file.Key);
            if(File.Exists(path))throw new IOException("Generated state-machine source collision: "+path);
            File.WriteAllText(path,file.Value);
        }
        File.WriteAllText(Path.Combine(directory,"readability.json"),JsonConvert.SerializeObject(new{
            AsyncMethods=stats.AsyncMethods,SeparatedStateMachines=stats.StateMachines,ConstantConditions=stats.ConstantConditions,
            EmptyFinally=stats.EmptyFinally,RemovedRvaComments=dataComments,Moved=stats.Moved,
            Preserved="ConfigureAwait, cancellation, exception handlers, original compatibility types and non-literal predicates remain unchanged."
        },Formatting.Indented));
    }
}

internal sealed class SeparateAsyncCompatibility : IAstTransform
{
    private readonly ReadabilityStats stats;
    internal SeparateAsyncCompatibility(ReadabilityStats stats)=>this.stats=stats;
    public void Run(AstNode root,TransformContext context)
    {
        Interlocked.Add(ref stats.AsyncMethods,root.Descendants.OfType<MethodDeclaration>().Count(m=>m.Modifiers.HasFlag(Modifiers.Async)));
        if(root is not SyntaxTree tree)return;
        foreach(var owner in tree.Members.OfType<TypeDeclaration>().ToArray())
        {
            var states=owner.Members.OfType<TypeDeclaration>().Where(t=>t.BaseTypes.Any(b=>b.ToString()=="IAsyncStateMachine")
                && t.Attributes.SelectMany(a=>a.Attributes).Any(a=>a.Type.ToString()=="CompilerGenerated")).ToArray();
            if(states.Length==0 || !owner.Members.OfType<MethodDeclaration>().Any(m=>m.Modifiers.HasFlag(Modifiers.Async)))continue;
            var names=new HashSet<string>(states.Select(s=>s.Name));
            var wrappers=owner.Members.OfType<MethodDeclaration>().Where(m=>m.Modifiers.HasFlag(Modifiers.Private) && m.Modifiers.HasFlag(Modifiers.Static)
                && m.Parameters.Any(p=>p.Type?.DescendantsAndSelf.OfType<SimpleType>().Any(t=>t.Identifier!=null && names.Contains(t.Identifier))==true)).ToArray();
            owner.Modifiers|=Modifiers.Partial;
            var compatibility=(TypeDeclaration)owner.Clone();compatibility.Members.Clear();compatibility.Attributes.Clear();compatibility.BaseTypes.Clear();
            foreach(var state in states)compatibility.Members.Add(state.Detach());
            foreach(var wrapper in wrappers)compatibility.Members.Add(wrapper.Detach());
            var extra=new SyntaxTree();
            foreach(var item in tree.Members.Where(n=>n is ExternAliasDeclaration or UsingDeclaration or UsingAliasDeclaration))
                extra.Members.Add(item.Clone());
            extra.Members.Add(compatibility);
            // This separate tree bypasses the decompiler's final output pass.
            // Reinsert precedence parentheses before serializing it ourselves.
            extra.AcceptVisitor(new InsertParenthesesVisitor());
            string file=owner.Name+".RecoveredAsyncStateMachines.cs";
            if(!stats.ExtraFiles.TryAdd(file,"// Original recovered state-machine compatibility definitions.\n// Read/edit async business methods in "+owner.Name+".cs.\n"+extra))
                throw new IOException("Generated state-machine source collision: "+file);
            Interlocked.Add(ref stats.StateMachines,states.Length);
            stats.Moved.Add(new{Source=owner.Name+".cs",Compatibility=file,StateMachines=states.Length,Forwarders=wrappers.Length});
        }
    }
}
