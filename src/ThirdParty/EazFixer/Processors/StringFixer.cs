using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer.Processors
{
    internal class StringFixer : ProcessorBase
    {
        private List<MethodDef> _decrypters;
        public int RecoveredCount { get; private set; }

        protected override void InitializeInternal()
        {
            _decrypters = !Flags.StrDecTok.IsNull
                ? new List<MethodDef> { Ctx.Module.ResolveToken(Flags.StrDecTok) as MethodDef ?? throw new Exception("StringDecrypter token set but method not found") }
                : StringFixUtils.FindStringDecryptMethods(Ctx.Module).ToList();
            if (_decrypters.Count == 0) throw new ProtectionNotFoundException("No structurally matched string decoder found");
        }

        protected override void ProcessInternal()
        {
            var methods = _decrypters.ToDictionary(method => method, method => Utils.FindMethod(Ctx.Assembly, method, new[] { typeof(int) }));
            var dictionary = new Dictionary<Tuple<MethodDef, int>, string>();
            var failures = new HashSet<Tuple<MethodDef, int>>();
            var unavailable = new HashSet<MethodDef>();
            int unresolved = 0, constructors = 0;
            // Keep decoder internals intact. A same-signature cache wrapper passes
            // its runtime argument to the core; that implementation call is not an
            // unresolved business call and may still be needed by retained users.
            foreach (var method in Utils.GetMethodsRecursive(Ctx.Module).Where(item => item.HasBody && item.Body.HasInstructions && !_decrypters.Contains(item)))
            {
                var body = method.Body;
                var targets = GetBoundaries(body);
                var tracker = new ConstantArgumentTracker(body);
                for (int index = 0; index < body.Instructions.Count; index++)
                {
                    var current = body.Instructions[index];
                    if (targets.Contains(current)) tracker.Reset();
                    int? argument = tracker.Top;
                    tracker.Step(current, body);
                    if (current.OpCode.Code != Code.Call || !(current.Operand is IMethod reference)) continue;
                    var decoder = reference as MethodDef;
                    if (decoder == null && reference.DeclaringType.DefinitionAssembly?.FullName == Ctx.Module.Assembly.FullName)
                        decoder = _decrypters.FirstOrDefault(candidate => candidate.FullName == reference.FullName);
                    if (decoder == null || !methods.TryGetValue(decoder, out var runtime)) continue;
                    if (unavailable.Contains(decoder)) { unresolved++; continue; }
                    if (!argument.HasValue || index > 0 && body.Instructions[index - 1].OpCode.Code == Code.Tailcall)
                    { unresolved++; continue; }
                    var key = Tuple.Create(decoder, argument.Value);
                    if (failures.Contains(key)) { unresolved++; continue; }
                    if (!dictionary.TryGetValue(key, out var value))
                    {
                        try
                        {
                            if (runtime == null) throw new MissingMethodException("Could not resolve decoder metadata token");
                            StacktracePatcher.PatchStackTraceGetMethod.MethodToReplace = runtime;
                            value = (string)runtime.Invoke(null, new object[] { argument.Value });
                            dictionary.Add(key, value);
                        }
                        catch (Exception error)
                        {
                            failures.Add(key); unresolved++;
                            var actual = error is TargetInvocationException && error.InnerException != null ? error.InnerException : error;
                            if (actual is TypeInitializationException || runtime == null) unavailable.Add(decoder);
                            Warn("Decoder " + decoder.MDToken + ", argument " + argument.Value + ": " + actual.GetType().Name + ": " + actual.Message);
                            continue;
                        }
                    }
                    if (value == ".ctor" && Flags.VirtFix) { constructors++; continue; }
                    // Keep the producers (and their side effects). Consume the proven
                    // argument and push the decoded value. Existing branch/EH labels
                    // keep referring to the original instruction objects.
                    if (index > 0 && body.Instructions[index - 1].IsLdcI4() && !targets.Contains(current))
                    {
                        body.Instructions[index - 1].OpCode = OpCodes.Nop;
                        body.Instructions[index - 1].Operand = null;
                        current.OpCode = value == null ? OpCodes.Ldnull : OpCodes.Ldstr;
                        current.Operand = value;
                    }
                    else
                    {
                        current.OpCode = OpCodes.Pop; current.Operand = null;
                        body.Instructions.Insert(++index, value == null ? Instruction.Create(OpCodes.Ldnull) : Instruction.Create(OpCodes.Ldstr, value));
                    }
                    RecoveredCount++;
                }
            }
            if (unresolved > 0 && failures.Count == 0) Warn(unresolved + " calls have unknown or control-flow-dependent arguments and were retained.");
            Summary = "Detected " + _decrypters.Count + " decoder(s); restored " + RecoveredCount + " call(s); retained " + unresolved +
                " unresolved and " + constructors + " VM constructor-name call(s). Runtime types preserved.";
        }

        internal static HashSet<Instruction> GetBoundaries(CilBody body)
        {
            var targets = new HashSet<Instruction>();
            foreach (var instruction in body.Instructions)
            {
                if (instruction.Operand is Instruction target) targets.Add(target);
                else if (instruction.Operand is IList<Instruction> branches) foreach (var branch in branches) targets.Add(branch);
            }
            foreach (var handler in body.ExceptionHandlers)
            {
                if (handler.TryStart != null) targets.Add(handler.TryStart);
                if (handler.TryEnd != null) targets.Add(handler.TryEnd);
                if (handler.HandlerStart != null) targets.Add(handler.HandlerStart);
                if (handler.HandlerEnd != null) targets.Add(handler.HandlerEnd);
                if (handler.FilterStart != null) targets.Add(handler.FilterStart);
            }
            return targets;
        }

        protected override void CleanupInternal()
        {
            if (Flags.VirtFix) return;
            foreach (var decoder in _decrypters)
            {
                if (Utils.LookForReferences(Ctx.Module, decoder)) continue;
                // Removing an entire declaring type can delete unrelated helpers.
                decoder.DeclaringType.Methods.Remove(decoder);
            }
        }
    }
}
