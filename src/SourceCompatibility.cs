using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.ProjectDecompiler;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Syntax.PatternMatching;
using ICSharpCode.Decompiler.CSharp.Transforms;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.DebugInfo;
using ICSharpCode.Decompiler.Semantics;
using ICSharpCode.Decompiler.TypeSystem;

namespace Unpacker;

internal sealed class RecoveredProjectDecompiler : WholeProjectDecompiler
{
    private readonly SourceDataPlan data;
    private readonly ReadabilityStats stats;
    internal SourceTypeAliases TypeAliases { get; }=new();
    internal RecoveredProjectDecompiler(DecompilerSettings settings,IAssemblyResolver resolver,IDebugInfoProvider? debugInfo,SourceDataPlan data,ReadabilityStats stats)
        :base(settings,resolver,null,null,debugInfo) { this.data=data;this.stats=stats; }

    protected override CSharpDecompiler CreateDecompiler(DecompilerTypeSystem types)
    {
        var decompiler=base.CreateDecompiler(types);
        decompiler.AstTransforms.Add(new ReadableControlFlow(stats));
        decompiler.AstTransforms.Add(new ExceptionCompatibility());
        decompiler.AstTransforms.Add(new MetadataCompatibility());
        decompiler.AstTransforms.Add(new LocalInitializationCompatibility());
        decompiler.AstTransforms.Add(new SourceMemberCompatibility());
        decompiler.AstTransforms.Add(TypeAliases.For(types));
        decompiler.AstTransforms.Add(new SourceDataCompatibility(data));
        decompiler.AstTransforms.Add(new SeparateAsyncCompatibility(stats));
        return decompiler;
    }
}

internal sealed class SourceMemberCompatibility : DepthFirstAstVisitor,IAstTransform
{
    public void Run(AstNode root,TransformContext context)=>root.AcceptVisitor(this);

    public override void VisitInvocationExpression(InvocationExpression invocation)
    {
        base.VisitInvocationExpression(invocation);
        if(invocation.Target is not MemberReferenceExpression {Target:CastExpression {Expression:ThisReferenceExpression} cast} member ||
            invocation.GetResolveResult() is not CSharpInvocationResolveResult call ||
            !invocation.Annotations.OfType<ICSharpCode.Decompiler.IL.Call>().Any() ||
            call.Member.Accessibility is not (Accessibility.Protected or Accessibility.ProtectedOrInternal or Accessibility.ProtectedAndInternal))
            return;
        var declaringType=call.Member.DeclaringType;
        if(!Equals(declaringType,cast.Type.GetResolveResult().Type))return;
        member.Target=new BaseReferenceExpression();
    }

    public override void VisitObjectCreateExpression(ObjectCreateExpression creation)
    {
        base.VisitObjectCreateExpression(creation);
        if(creation.Type is not SimpleType ||
            creation.GetResolveResult().Type.GetDefinition() is not {Namespace:"",DeclaringType:null} definition)
            return;
        // A nested type inherited from the containing class can shadow a
        // global-namespace constructor's name in generated C#.
        creation.Type=new TypeSystemAstBuilder {AlwaysUseGlobal=true}.ConvertType(creation.GetResolveResult().Type);
    }

    public override void VisitFieldDeclaration(FieldDeclaration field)
    {
        base.VisitFieldDeclaration(field);
        if(field.ReturnType is not SimpleType ||
            field.ReturnType.GetResolveResult().Type.GetDefinition() is not {Namespace:"",DeclaringType:null})
            return;
        field.ReturnType=new TypeSystemAstBuilder {AlwaysUseGlobal=true}.ConvertType(field.ReturnType.GetResolveResult().Type);
    }

    public override void VisitExpressionStatement(ExpressionStatement statement)
    {
        base.VisitExpressionStatement(statement);
        if(statement.Expression is not ObjectCreateExpression creation || creation.GetResolveResult().Type.Kind!=TypeKind.Delegate)
            return;
        var scope=statement.Ancestors.FirstOrDefault(n=>n is MethodDeclaration or ConstructorDeclaration)??statement.Parent;
        if(scope==null)return;
        var names=new HashSet<string>(scope.Descendants.OfType<VariableInitializer>().Select(v=>v.Name)
            .Concat(scope.Descendants.OfType<ParameterDeclaration>().Select(p=>p.Name)));
        string name="unpackUnusedDelegate";
        while(names.Contains(name))name+="_";
        statement.ReplaceWith(new VariableDeclarationStatement(new SimpleType("var"),name,creation.Detach()));
    }
}

internal sealed class LocalInitializationCompatibility : DepthFirstAstVisitor,IAstTransform
{
    public void Run(AstNode root,TransformContext context)=>root.AcceptVisitor(this);
    public override void VisitTypeDeclaration(TypeDeclaration type)
    {
        var assignments=type.Members.OfType<PropertyDeclaration>().Where(p=>p.Setter?.Body!=null)
            .SelectMany(p=>p.Setter!.Body!.Descendants.OfType<AssignmentExpression>())
            .Concat(type.Members.OfType<MethodDeclaration>().Where(m=>m.Body!=null).SelectMany(m=>m.Body!.Descendants.OfType<AssignmentExpression>()))
            .Select(a=>a.Left is IdentifierExpression identifier?identifier.Identifier:(a.Left as MemberReferenceExpression)?.MemberName).ToArray();
        foreach(var field in type.Members.OfType<FieldDeclaration>().Where(f=>f.Variables.Any(v=>assignments.Contains(v.Name))))field.Modifiers&=~Modifiers.Readonly;
        base.VisitTypeDeclaration(type);
    }
    public override void VisitMethodDeclaration(MethodDeclaration method)
    {
        if(method.Body is { } body)
        {
            var declarations=body.Descendants.OfType<VariableDeclarationStatement>().ToArray();
            bool unstructured=body.Descendants.Any(n=>n is GotoStatement or GotoCaseStatement or LabelStatement);
            var names=declarations.SelectMany(d=>d.Variables).GroupBy(v=>v.Name).ToDictionary(g=>g.Key,g=>g.Count());
            foreach(var declaration in declarations.Where(d=>d.Parent is BlockStatement && d.Type.ToString()!="var" && d.Type is not ComposedType {HasRefSpecifier:true}
                && d.Modifiers==Modifiers.None && d.Variables.Count==1 && d.Variables.All(v=>names[v.Name]==1)).ToArray())
            {
                var variable=declaration.Variables.Single();
                // Keep normal lexical declarations in place. Only lift a unique
                // local when ILSpy emitted a reference outside its block/before declaration.
                var block=(BlockStatement)declaration.Parent!;
                var scope=new HashSet<AstNode>(block.Descendants);
                bool escapes=body.Descendants.OfType<IdentifierExpression>().Any(i=>i.Identifier==variable.Name && !scope.Contains(i));
                bool before=block.Statements.TakeWhile(s=>s!=declaration).SelectMany(s=>s.DescendantsAndSelf)
                    .OfType<IdentifierExpression>().Any(i=>i.Identifier==variable.Name);
                bool selfReference=variable.Initializer?.DescendantsAndSelf.OfType<IdentifierExpression>().Any(i=>i.Identifier==variable.Name)==true;
                if(!escapes && !before && !unstructured && !selfReference)continue;
                var entry=new VariableDeclarationStatement(declaration.Type.Clone(),variable.Name,new DefaultValueExpression(declaration.Type.Clone()));
                string typeName=declaration.Type.ToString();
                if((typeName.StartsWith("Span<")||typeName.StartsWith("ReadOnlySpan<")||typeName.StartsWith("System.Span<")||typeName.StartsWith("System.ReadOnlySpan<"))
                    && variable.Initializer?.DescendantsAndSelf.OfType<StackAllocExpression>().Any()==true)entry.Modifiers=Modifiers.Scoped;
                if(variable.Initializer is { } original)declaration.ReplaceWith(new ExpressionStatement(new AssignmentExpression(new IdentifierExpression(variable.Name),original.Detach())));
                else declaration.Remove();
                var first=body.Statements.FirstOrDefault();if(first is null)body.Statements.Add(entry);else body.Statements.InsertBefore(first,entry);
            }
        }
        base.VisitMethodDeclaration(method);
    }
    public override void VisitVariableDeclarationStatement(VariableDeclarationStatement declaration)
    {
        base.VisitVariableDeclarationStatement(declaration);
        foreach(var variable in declaration.Variables.Where(v=>v.Initializer is null))
        {
            if(declaration.Type is ComposedType {HasRefSpecifier:true} reference)
            {
                var valueType=(ComposedType)reference.Clone();valueType.HasRefSpecifier=false;valueType.HasReadOnlySpecifier=false;
                string name=variable.Name+"InitialValue";
                var backing=new VariableDeclarationStatement(valueType.Clone(),name,new DefaultValueExpression(valueType.Clone()));
                if(declaration.Parent is BlockStatement block)block.Statements.InsertBefore(declaration,backing);
                else throw new NotSupportedException("Uninitialized ref local outside block.");
                variable.Initializer=new DirectionExpression(FieldDirection.Ref,new IdentifierExpression(name));
            }
            else if(declaration.Type.ToString()!="var")variable.Initializer=new DefaultValueExpression(declaration.Type.Clone());
        }
    }
}

internal sealed class MetadataCompatibility : DepthFirstAstVisitor,IAstTransform
{
    public void Run(AstNode root,TransformContext context)=>root.AcceptVisitor(this);
    public override void VisitTypeDeclaration(TypeDeclaration type)
    {
        var constructors=type.Members.OfType<ConstructorDeclaration>().Where(c=>(c.Modifiers&Modifiers.Static)==0).ToArray();
        if(constructors.Length>1)
        {
            // C# emits the same field initializer sequence in every direct-base
            // constructor. Lift it once only when both syntax and binding agree.
            var prefixes=constructors.Select(BasePrefix).ToArray();
            var first=prefixes[0];
            if(first is {Length:>0} && prefixes.All(prefix=>prefix?.Length==first.Length &&
                prefix.Zip(first,SameStatement).All(equal=>equal)) &&
                TryLiftFieldPrefix(type,constructors[0],first,constructors.SelectMany(c=>c.Parameters.Select(p=>p.Name))))
                foreach(var prefix in prefixes)
                    foreach(var statement in prefix!)statement.Remove();
        }
        foreach(var constructor in constructors)
        {
            if(constructor.Body is null)continue;
            var statements=constructor.Body.Statements.ToArray();
            var baseStatement=statements.OfType<ExpressionStatement>().FirstOrDefault(s=>s.Expression is InvocationExpression {Target:MemberReferenceExpression {Target:BaseReferenceExpression or ThisReferenceExpression,MemberName:".ctor" or "_002Ector"}});
            if(baseStatement is null)continue;
            var originalCall=(InvocationExpression)baseStatement.Expression;
            var member=(MemberReferenceExpression)originalCall.Target;
            bool self=member.Target is ThisReferenceExpression;
            if(originalCall.GetResolveResult() is ICSharpCode.Decompiler.Semantics.MemberResolveResult {Member:IMethod {DeclaringType.FullName:"System.Object"}}
                || member.GetResolveResult() is ICSharpCode.Decompiler.Semantics.MemberResolveResult {Member:IMethod {DeclaringType.FullName:"System.Object"}})
            {
                constructor.Initializer=new ConstructorInitializer {ConstructorInitializerType=ConstructorInitializerType.Base};
                baseStatement.Remove();continue;
            }
            var preceding=statements.TakeWhile(s=>s!=baseStatement).ToArray();
            if(!self && constructors.Length==1 && TryLiftFieldPrefix(type,constructor,preceding))
            {
                foreach(var statement in preceding)statement.Remove();
                preceding=Array.Empty<Statement>();
                statements=constructor.Body.Statements.ToArray();
            }
            if(constructors.Length==1 && TryInlineTemporaryFieldInitializations(type,constructor,preceding))
            {
                foreach(var statement in preceding)statement.Remove();
                preceding=Array.Empty<Statement>();
                statements=constructor.Body.Statements.ToArray();
            }
            if(preceding.Length==1 && TryInlineDictionaryInitialization(type,preceding[0]))
            {
                preceding[0].Remove();
                preceding=Array.Empty<Statement>();
                statements=constructor.Body.Statements.ToArray();
            }
            if(preceding.Any(s=>s is VariableDeclarationStatement || s is ExpressionStatement {Expression:InvocationExpression invocation} && invocation.Arguments.OfType<DirectionExpression>().Count()!=1))
            {
                PreserveConstructorLocals(type,constructor,baseStatement,preceding);
                continue;
            }
            foreach(var prefix in statements.TakeWhile(s=>s!=baseStatement))
            {
                if(constructors.Length==1 && TryInlineConstantFieldInitialization(type,constructor,prefix))
                {
                    prefix.Remove();
                    continue;
                }
                if(constructors.Length!=1 || prefix is not ExpressionStatement {Expression:InvocationExpression initializer})
                    throw new NotSupportedException("Unsupported initialization before base constructor: "+constructor.Name+"; prefix: "+prefix);
                var fieldArgument=initializer.Arguments.OfType<DirectionExpression>().SingleOrDefault();
                if(fieldArgument?.Expression is not IdentifierExpression fieldName)
                    throw new NotSupportedException("Cannot preserve initialization before base constructor: "+constructor.Name);
                var field=type.Members.OfType<FieldDeclaration>().First(f=>f.Variables.Any(v=>v.Name==fieldName.Identifier));
                var variable=field.Variables.Single(v=>v.Name==fieldName.Identifier);
                string factory="Initialize"+fieldName.Identifier;
                var body=new BlockStatement();
                body.Statements.Add(new VariableDeclarationStatement(field.ReturnType.Clone(),"value",new DefaultValueExpression(field.ReturnType.Clone())));
                var copied=prefix.Clone();
                foreach(var identifier in copied.Descendants.OfType<IdentifierExpression>().Where(i=>i.Identifier==fieldName.Identifier))identifier.Identifier="value";
                body.Statements.Add(copied);
                body.Statements.Add(new ReturnStatement(new IdentifierExpression("value")));
                type.Members.Add(new MethodDeclaration {Name=factory,ReturnType=field.ReturnType.Clone(),Modifiers=Modifiers.Private|Modifiers.Static,Body=body});
                variable.Initializer=new InvocationExpression(new IdentifierExpression(factory));
                prefix.Remove();
            }
            var call=(InvocationExpression)baseStatement.Expression;
            var baseInitializer=new ConstructorInitializer {ConstructorInitializerType=self?ConstructorInitializerType.This:ConstructorInitializerType.Base};
            foreach(var argument in call.Arguments.ToArray())baseInitializer.Arguments.Add(argument.Detach());
            constructor.Initializer=baseInitializer;
            baseStatement.Remove();
        }
        base.VisitTypeDeclaration(type);
    }

    private static Statement[]? BasePrefix(ConstructorDeclaration constructor)
    {
        if(constructor.Body==null)return null;
        var statements=constructor.Body.Statements.ToArray();
        int index=Array.FindIndex(statements,s=>s is ExpressionStatement {Expression:InvocationExpression
        {Target:MemberReferenceExpression {Target:BaseReferenceExpression,MemberName:".ctor" or "_002Ector"}}});
        return index<0?null:statements.Take(index).ToArray();
    }

    private static bool SameStatement(Statement left,Statement right)
    {
        if(!left.Match(right).Success)return false;
        static IEnumerable<string> Bindings(Statement statement)=>statement.DescendantsAndSelf.OfType<Expression>()
            .Select(n=>n.GetResolveResult()).OfType<MemberResolveResult>()
            .Select(r=>r.Member.FullName+"@"+r.Member.ParentModule?.FullAssemblyName);
        return Bindings(left).SequenceEqual(Bindings(right),StringComparer.Ordinal);
    }

    private static bool TryLiftFieldPrefix(TypeDeclaration type,ConstructorDeclaration constructor,Statement[] prefix,
        IEnumerable<string>? allParameters=null)
    {
        if(prefix.Length==0)return false;
        IEnumerable<Statement> Flatten(Statement statement)=>statement is BlockStatement block
            ?block.Statements.SelectMany(Flatten):new[]{statement};
        var fields=type.Members.OfType<FieldDeclaration>().Where(f=>(f.Modifiers&Modifiers.Static)==0)
            .SelectMany(f=>f.Variables.Select(v=>(Field:f,Variable:v))).ToArray();
        if(fields.Any(f=>f.Variable.Initializer!=null))return false;
        var preceding=new List<Statement>();
        var initializers=new List<(int Index,Expression Value,Statement[] Before)>();
        var parameters=new HashSet<string>(allParameters??constructor.Parameters.Select(p=>p.Name));
        foreach(var statement in prefix.SelectMany(Flatten))
        {
            if(statement is ExpressionStatement {Expression:AssignmentExpression {Operator:AssignmentOperatorType.Assign} assignment})
            {
                string? name=assignment.Left switch
                {
                    MemberReferenceExpression {Target:ThisReferenceExpression} m=>m.MemberName,
                    IdentifierExpression id when !parameters.Contains(id.Identifier) &&
                        id.GetResolveResult() is MemberResolveResult {Member:IField {IsStatic:false}}=>id.Identifier,
                    _=>null
                };
                int index=Array.FindIndex(fields,f=>f.Variable.Name==name);
                if(index<0 || initializers.Count>0 && initializers[initializers.Count-1].Index>=index ||
                    UsesInstanceOrParameter(assignment.Right))return false;
                initializers.Add((index,assignment.Right,preceding.ToArray()));
                preceding.Clear();
            }
            else if(statement is ExpressionStatement {Expression:InvocationExpression invoke} &&
                invoke.GetResolveResult() is MemberResolveResult {Member:IMethod {IsStatic:true}} &&
                !UsesInstanceOrParameter(invoke))
                preceding.Add(statement);
            else return false;
        }
        if(initializers.Count==0 || preceding.Count!=0)return false;
        foreach(var initializer in initializers)
        {
            var (field,variable)=fields[initializer.Index];
            if(initializer.Before.Length==0)
            {
                variable.Initializer=initializer.Value.Clone();
                continue;
            }
            string factory="InitializeField"+initializer.Index;
            while(type.Members.Any(m=>m.Name==factory))factory+="_";
            var body=new BlockStatement();
            foreach(var statement in initializer.Before)body.Statements.Add(statement.Clone());
            body.Statements.Add(new ReturnStatement(initializer.Value.Clone()));
            type.Members.Add(new MethodDeclaration {Name=factory,Modifiers=Modifiers.Private|Modifiers.Static,
                ReturnType=field.ReturnType.Clone(),Body=body});
            variable.Initializer=new InvocationExpression(new IdentifierExpression(factory));
        }
        return true;

        bool UsesInstanceOrParameter(Expression expression)=>expression.DescendantsAndSelf.Any(node=>
            node is ThisReferenceExpression or BaseReferenceExpression ||
            node is IdentifierExpression identifier && parameters.Contains(identifier.Identifier) ||
            node is Expression member && member.GetResolveResult() is MemberResolveResult {Member:{IsStatic:false}} &&
                member is not ObjectCreateExpression);
    }

    private static bool TryInlineTemporaryFieldInitializations(TypeDeclaration type,ConstructorDeclaration constructor,Statement[] prefix)
    {
        IEnumerable<Statement> Flatten(Statement statement)=>statement is BlockStatement block?block.Statements.SelectMany(Flatten):new[]{statement};
        var flat=prefix.SelectMany(Flatten).ToArray();
        if(flat.Length==0 || flat.Length%2!=0)return false;
        var fields=type.Members.OfType<FieldDeclaration>().Where(f=>(f.Modifiers&Modifiers.Static)==0).SelectMany(f=>f.Variables).ToArray();
        if(fields.Any(f=>f.Initializer!=null))return false;
        var initializers=new List<(VariableInitializer Field,Expression Value)>();
        for(int i=0;i<flat.Length;i+=2)
        {
            if(flat[i] is not VariableDeclarationStatement declaration || declaration.Variables.Count!=1)return false;
            var local=declaration.Variables.Single();
            // Match an isolated temporary creation followed by exactly one field
            // store. Lift the creation itself, not a static helper using instance fields.
            if(local.Initializer is not ObjectCreateExpression creation || creation.Initializer!=null
                || creation.Arguments.Any(a=>a is not (PrimitiveExpression or NullReferenceExpression)))return false;
            if(flat[i+1] is not ExpressionStatement {Expression:AssignmentExpression {Operator:AssignmentOperatorType.Assign,Left:IdentifierExpression target,Right:IdentifierExpression source}}
                || source.Identifier!=local.Name || constructor.Parameters.Any(p=>p.Name==target.Identifier)
                || flat.OfType<VariableDeclarationStatement>().SelectMany(d=>d.Variables).Any(v=>v.Name==target.Identifier))return false;
            var field=fields.FirstOrDefault(f=>f.Name==target.Identifier);
            if(field==null || initializers.Any(p=>p.Field==field))return false;
            var prefixNodes=new HashSet<AstNode>(prefix.SelectMany(s=>s.DescendantsAndSelf));
            if(constructor.Body!.Descendants.OfType<IdentifierExpression>().Any(id=>id.Identifier==local.Name && !prefixNodes.Contains(id)))return false;
            initializers.Add((field,creation));
        }
        var order=initializers.Select(p=>Array.IndexOf(fields,p.Field)).ToArray();
        if(!order.SequenceEqual(order.OrderBy(i=>i)))return false;
        foreach(var initializer in initializers)initializer.Field.Initializer=initializer.Value.Clone();
        return true;
    }

    private static bool TryInlineConstantFieldInitialization(TypeDeclaration type,ConstructorDeclaration constructor,Statement prefix)
    {
        // ILSpy can leave lexical blocks around pre-base field assignments.
        // Only lift constants: moving arbitrary expressions could change evaluation
        // order, capture constructor parameters, or access an uninitialized instance.
        var statements=prefix is BlockStatement block?block.Statements.ToArray():new[]{prefix};
        if(statements.Length==0)return true;
        var initializers=new List<(VariableInitializer Field,Expression Value)>();
        foreach(var statement in statements)
        {
            if(statement is not ExpressionStatement {Expression:AssignmentExpression {Operator:AssignmentOperatorType.Assign} assignment}
                || assignment.Right is not (PrimitiveExpression or NullReferenceExpression or DefaultValueExpression))return false;
            string? name=assignment.Left switch {
                IdentifierExpression identifier=>identifier.Identifier,
                MemberReferenceExpression {Target:ThisReferenceExpression} member=>member.MemberName,
                _=>null
            };
            if(assignment.Left is IdentifierExpression && constructor.Parameters.Any(p=>p.Name==name))return false;
            var field=type.Members.OfType<FieldDeclaration>().Where(f=>(f.Modifiers&Modifiers.Static)==0)
                .SelectMany(f=>f.Variables).FirstOrDefault(v=>v.Name==name);
            if(field==null || field.Initializer!=null || initializers.Any(i=>i.Field==field))return false;
            initializers.Add((field,assignment.Right));
        }
        foreach(var initializer in initializers)initializer.Field.Initializer=initializer.Value.Clone();
        return true;
    }

    private static bool TryInlineDictionaryInitialization(TypeDeclaration type,Statement prefix)
    {
        if(prefix is not ExpressionStatement {Expression:InvocationExpression {Target:IdentifierExpression target} call})return false;
        var helper=type.Members.OfType<MethodDeclaration>().FirstOrDefault(m=>m.Name==target.Identifier && m.Parameters.Count==call.Arguments.Count);
        if(helper?.Body==null || helper.Body.Descendants.Any(n=>n is InvocationExpression or ThrowStatement or IfElseStatement or WhileStatement or ForStatement or ForeachStatement))return false;
        var locals=helper.Body.Statements.OfType<VariableDeclarationStatement>().SelectMany(d=>d.Variables).ToDictionary(v=>v.Name,v=>v.Initializer);
        var assignments=helper.Body.Statements.OfType<ExpressionStatement>().Select(s=>s.Expression).OfType<AssignmentExpression>().ToArray();
        if(assignments.Length!=call.Arguments.Count)return false;
        var initializers=new List<(VariableInitializer Field,Expression Value)>();
        for(int index=0;index<call.Arguments.Count;index++)
        {
            if(call.Arguments.ElementAt(index) is not DirectionExpression {Expression:IdentifierExpression fieldName})return false;
            var field=type.Members.OfType<FieldDeclaration>().SelectMany(f=>f.Variables).FirstOrDefault(v=>v.Name==fieldName.Identifier);
            var assignment=assignments.FirstOrDefault(a=>a.Left is IdentifierExpression name && name.Identifier==helper.Parameters.ElementAt(index).Name);
            Expression? value=assignment?.Right;
            if(value is IdentifierExpression local && locals.TryGetValue(local.Identifier,out var initializer))value=initializer;
            if(field==null || field.Initializer!=null || value is not ObjectCreateExpression creation || creation.Arguments.Count!=0
                || !(creation.Type.ToString().StartsWith("Dictionary<",StringComparison.Ordinal)
                     || creation.GetResolveResult().Type.FullName.StartsWith("System.Collections.Generic.Dictionary",StringComparison.Ordinal)))return false;
            initializers.Add((field,creation));
        }
        foreach(var initializer in initializers)initializer.Field.Initializer=initializer.Value.Clone();
        return true;
    }
    private static void PreserveConstructorLocals(TypeDeclaration type,ConstructorDeclaration constructor,ExpressionStatement baseStatement,Statement[] prefix)
    {
        if(prefix.SelectMany(s=>s.Descendants).Any(n=>n is ThisReferenceExpression or BaseReferenceExpression))throw new NotSupportedException("Instance access before constructor base call: "+constructor.Name);
        string suffix=type.Members.OfType<TypeDeclaration>().Count().ToString();
        string contextName="ConstructorContext"+suffix,factory="InitializeConstructor"+suffix;
        var locals=prefix.OfType<VariableDeclarationStatement>().SelectMany(d=>d.Variables.Select(v=>(Name:v.Name,Type:d.Type.ToString()=="var" && v.Initializer is ObjectCreateExpression creation?creation.Type.Clone():d.Type.Clone()))).ToArray();
        if(locals.Any(l=>l.Type.ToString()=="var"))throw new NotSupportedException("Unresolved constructor temporary type: "+constructor.Name);
        var contextType=new TypeDeclaration {Name=contextName,ClassType=ClassType.Class,Modifiers=Modifiers.Private|Modifiers.Sealed};
        foreach(var local in locals)
        {
            var field=new FieldDeclaration {ReturnType=local.Type.Clone(),Modifiers=Modifiers.Public};field.Variables.Add(new VariableInitializer(local.Name));contextType.Members.Add(field);
        }
        type.Members.Add(contextType);
        var factoryBody=new BlockStatement();
        foreach(var statement in prefix)factoryBody.Statements.Add(statement.Clone());
        factoryBody.Statements.Add(new VariableDeclarationStatement(new SimpleType(contextName),"context",new ObjectCreateExpression(new SimpleType(contextName))));
        foreach(var local in locals)factoryBody.Statements.Add(new ExpressionStatement(new AssignmentExpression(new MemberReferenceExpression(new IdentifierExpression("context"),local.Name),new IdentifierExpression(local.Name))));
        factoryBody.Statements.Add(new ReturnStatement(new IdentifierExpression("context")));
        var helper=new MethodDeclaration {Name=factory,ReturnType=new SimpleType(contextName),Modifiers=Modifiers.Private|Modifiers.Static,Body=factoryBody};
        foreach(var parameter in constructor.Parameters)helper.Parameters.Add(parameter.Clone());
        type.Members.Add(helper);
        var implementation=(ConstructorDeclaration)constructor.Clone();implementation.Modifiers=Modifiers.Private;implementation.Attributes.Clear();
        implementation.Parameters.InsertBefore(implementation.Parameters.FirstOrDefault(),new ParameterDeclaration {Type=new SimpleType(contextName),Name="context"});
        foreach(var statement in implementation.Body!.Statements.Take(prefix.Length+1).ToArray())statement.Remove();
        var originalCall=(InvocationExpression)baseStatement.Expression;
        var initializer=new ConstructorInitializer {ConstructorInitializerType=((MemberReferenceExpression)originalCall.Target).Target is ThisReferenceExpression?ConstructorInitializerType.This:ConstructorInitializerType.Base};
        foreach(var argument in ((InvocationExpression)baseStatement.Expression).Arguments)
        {
            var copy=argument.Clone();
            foreach(var identifier in copy.DescendantsAndSelf.OfType<IdentifierExpression>().Where(i=>locals.Any(l=>l.Name==i.Identifier)).ToArray())
                identifier.ReplaceWith(new MemberReferenceExpression(new IdentifierExpression("context"),identifier.Identifier));
            initializer.Arguments.Add(copy);
        }
        implementation.Initializer=initializer;
        foreach(var local in Enumerable.Reverse(locals))
        {
            var declaration=new VariableDeclarationStatement(local.Type.Clone(),local.Name,new MemberReferenceExpression(new IdentifierExpression("context"),local.Name));
            var first=implementation.Body.Statements.FirstOrDefault();if(first is null)implementation.Body.Statements.Add(declaration);else implementation.Body.Statements.InsertBefore(first,declaration);
        }
        type.Members.Add(implementation);
        constructor.Body!.Statements.Clear();
        var chain=new ConstructorInitializer {ConstructorInitializerType=ConstructorInitializerType.This};
        chain.Arguments.Add(new InvocationExpression(new IdentifierExpression(factory),constructor.Parameters.Select(p=>(Expression)new IdentifierExpression(p.Name!))));
        foreach(var parameter in constructor.Parameters)chain.Arguments.Add(new IdentifierExpression(parameter.Name!));
        constructor.Initializer=chain;
    }
    public override void VisitInvocationExpression(InvocationExpression invocation)
    {
        base.VisitInvocationExpression(invocation);
        if(invocation.Target is not IdentifierExpression {Identifier:"__ldtoken"})return;
        var argument=invocation.Arguments.Single();
        var member=argument is InvocationExpression call?call.Target as MemberReferenceExpression:argument as MemberReferenceExpression;
        if(member?.Target is not TypeReferenceExpression owner)throw new NotSupportedException("Cannot rebuild metadata token expression: "+invocation);
        string helper=argument is InvocationExpression?"MethodHandle":"FieldHandle";
        var replacement=new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(new SimpleType("UnpackMetadataCompatibility")),helper),
            new TypeOfExpression(owner.Type.Clone()),new PrimitiveExpression(member.MemberName));
        if(argument is InvocationExpression method)
        {
            foreach(var parameter in method.Arguments.Cast<TypeReferenceExpression>())replacement.Arguments.Add(new TypeOfExpression(parameter.Type.Clone()));
        }
        invocation.ReplaceWith(replacement);
    }
    internal const string HelperSource="using System;\nusing System.Linq;\nusing System.Reflection;\ninternal static class UnpackMetadataCompatibility\n{\n    private const BindingFlags Flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static;\n    internal static RuntimeMethodHandle MethodHandle(Type owner, string name, params Type[] arguments) => owner.GetMethods(Flags).Single(m => m.Name == name && m.GetParameters().Select(p => p.ParameterType).SequenceEqual(arguments)).MethodHandle;\n    internal static RuntimeFieldHandle FieldHandle(Type owner, string name) => owner.GetField(name, Flags).FieldHandle;\n}\n";
}

internal sealed class ExceptionCompatibility : DepthFirstAstVisitor,IAstTransform
{
    public void Run(AstNode root,TransformContext context)=>root.AcceptVisitor(this);

    public override void VisitThrowStatement(ThrowStatement statement)
    {
        base.VisitThrowStatement(statement);
        if(statement.Expression is null || statement.Expression.GetResolveResult().Type.FullName!="System.Object")return;
        var expression=statement.Expression.Detach();
        statement.Expression=new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(new SimpleType("UnpackExceptionCompatibility")),"ToException"),expression);
    }
    public override void VisitThrowExpression(ThrowExpression expression)
    {
        base.VisitThrowExpression(expression);
        if(expression.Expression.GetResolveResult().Type.FullName!="System.Object")return;
        expression.Expression=new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(new SimpleType("UnpackExceptionCompatibility")),"ToException"),expression.Expression.Detach());
    }

    public override void VisitCatchClause(CatchClause clause)
    {
        base.VisitCatchClause(clause);
        if(clause.Type?.ToString() is not ("object" or "System.Object" or "global::System.Object"))return;
        string? original=clause.VariableName;
        clause.Type=new MemberType(new SimpleType("System"),"Exception");
        if(original is null || original.Length==0)return;
        string exceptionName=original+"CaughtException";
        clause.VariableName=exceptionName;
        var declaration=new VariableDeclarationStatement(new PrimitiveType("object"),original,
            new InvocationExpression(new MemberReferenceExpression(new TypeReferenceExpression(new SimpleType("UnpackExceptionCompatibility")),"Unwrap"),new IdentifierExpression(exceptionName)));
        var first=clause.Body.Statements.FirstOrDefault();
        if(first is null)clause.Body.Statements.Add(declaration);else clause.Body.Statements.InsertBefore(first,declaration);
    }

    internal const string HelperSource="internal static class UnpackExceptionCompatibility\n{\n    private static readonly global::System.Reflection.ConstructorInfo Constructor = typeof(global::System.Runtime.CompilerServices.RuntimeWrappedException).GetConstructor(global::System.Reflection.BindingFlags.Public | global::System.Reflection.BindingFlags.NonPublic | global::System.Reflection.BindingFlags.Instance, null, new[] { typeof(object) }, null);\n    internal static global::System.Exception ToException(object value) => value as global::System.Exception ?? (value == null ? null : (global::System.Exception)Constructor.Invoke(new[] { value }));\n    internal static object Unwrap(global::System.Exception value) => value is global::System.Runtime.CompilerServices.RuntimeWrappedException wrapped ? wrapped.WrappedException : (object)value;\n}\n";
}
