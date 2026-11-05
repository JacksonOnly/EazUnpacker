using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer
{
    // Extract per-build constants from the decoder, not from its obfuscated names
    // or metadata tokens. Only accept the stream/seed/frame/LCG layout we can write.
    internal sealed class StringResourceLayout
    {
        internal string ResourceName;
        internal int PositionMask, FrameMask, RedirectMarker, RedirectMask;
        internal int GlobalSeedMask, SeedModeMask, EntrySeedMask;
        internal int ByteTextFlag, CompressedFlag, LengthMask;

        internal static StringResourceLayout Detect(MethodDef method)
        {
            var body = method.Body;
            var il = body.Instructions;
            var seeds = ReadPrologue(body);
            var resource = Single(il, i => Calls(i, "System.Reflection.Assembly", "GetManifestResourceStream") &&
                ((IMethod)i.Operand).MethodSig.Params.Count == 1);
            int builder = FindLast(il, 0, resource, i => i.OpCode.Code == Code.Newobj && Calls(i, "System.Text.StringBuilder", ".ctor"));
            var name = new System.Text.StringBuilder();
            var trace = CreateTracker(body, seeds);
            Walk(body, builder + 1, resource, trace, i =>
            {
                if (!Calls(i, "System.Text.StringBuilder", "Append")) return;
                if (!trace.Top.HasValue || ((IMethod)i.Operand).MethodSig.Params.Count != 1 ||
                    ((IMethod)i.Operand).MethodSig.Params[0].ElementType != ElementType.Char)
                    throw Unknown();
                name.Append((char)trace.Top.Value);
            });
            if (name.Length == 0 || name.Length > 256) throw Unknown();

            int seek = Single(il, i => Calls(i, "System.IO.Stream", "set_Position"));
            int arg = FindLast(il, resource, seek, i => i.OpCode.Code == Code.Ldarg_0);
            var position = ConstantsBefore(body, seeds, arg + 1, seek, Code.Xor);
            if (position.Count != 2) throw Unknown();

            int global = Find(il, resource + 1, seek, i => Reader(i, ElementType.I2));
            var read16 = (IMethod)il[global].Operand;
            int mode = Find(il, global + 1, seek, i => Reader(i, ElementType.I2, read16));
            int entry = Find(il, seek + 1, il.Count, i => Reader(i, ElementType.I2, read16));
            int frame = Find(il, entry + 1, il.Count, i => Reader(i, ElementType.I4, read16));
            int compare = Find(il, frame + 1, Math.Min(il.Count, frame + 40),
                i => i.OpCode.Code == Code.Bne_Un || i.OpCode.Code == Code.Bne_Un_S);
            if (!(il[compare].Operand is Instruction target)) throw Unknown();
            int direct = il.IndexOf(target);
            if (direct <= compare || direct - compare > 100) throw Unknown();
            int redirectRead = Find(il, compare + 1, direct, i => Reader(i, ElementType.SZArray, read16));
            int storeArg = Find(il, redirectRead + 1, direct, i => i.OpCode.Code == Code.Starg || i.OpCode.Code == Code.Starg_S);
            int? redirect = il[storeArg - 1].OpCode.Code != Code.Xor ? null :
                ConstantRightOperand(body, seeds, redirectRead + 1, storeArg - 1) ??
                (il[storeArg - 2].IsLdloc() ? ConstantEndingAt(body, seeds, redirectRead + 1, storeArg - 2) : null);
            // The first write to arg0 builds the negated XOR key for the alias.
            if (!redirect.HasValue || !il.Skip(storeArg + 1).Take(direct - storeArg - 1)
                .Any(i => i.OpCode.Code == Code.Neg)) throw Unknown();

            var lcg = Enumerable.Range(direct, il.Count - direct).Where(i => il[i].OpCode.Code == Code.Mul &&
                ConstantEndingAt(body, seeds, direct, i) == 214013).ToArray();
            if (lcg.Length != 1) throw Unknown();
            int add = FindIndex(lcg[0] + 1, Math.Min(il.Count, lcg[0] + 16), i =>
                il[i].OpCode.Code == Code.Add && ConstantEndingAt(body, seeds, lcg[0] + 1, i) == 2531011);
            int next = Math.Min(il.Count, add + 12);
            if (!il.Skip(add + 1).Take(next - add - 1).Any(i => i.OpCode.Code == Code.Shr_Un)) throw Unknown();

            var masks = ConstantsBefore(body, seeds, direct, lcg[0], Code.And);
            var flags = masks.Where(x => x == 0x20000000 || x == 0x40000000 || x == unchecked((int)0x80000000)).ToArray();
            if (flags.Length != 3 || flags.Distinct().Count() != 3 || masks.Count(x => x == 0x0fffffff) != 1)
                throw Unknown();

            return new StringResourceLayout
            {
                ResourceName = name.ToString(),
                PositionMask = position[0] ^ position[1],
                GlobalSeedMask = ReadMask(body, seeds, global, mode),
                SeedModeMask = ReadMask(body, seeds, mode, seek),
                EntrySeedMask = ReadMask(body, seeds, entry, frame),
                FrameMask = ReadMask(body, seeds, frame, compare),
                RedirectMarker = ConstantEndingAt(body, seeds, frame + 1, compare) ?? throw Unknown(),
                RedirectMask = redirect.Value,
                ByteTextFlag = flags[0], CompressedFlag = flags[1], LengthMask = 0x0fffffff
            };
        }

        private static int ReadMask(CilBody body, Dictionary<Local, int> seeds, int read, int end)
        {
            // The obfuscated mask expression immediately follows the integer read
            // (the frame-length read also XORs the current offset first).
            for (int i = read + 1; i < Math.Min(end, read + 32); i++)
                if (body.Instructions[i].OpCode.Code == Code.Xor &&
                    ConstantRightOperand(body, seeds, read + 1, i) is int mask)
                    return mask;
            throw Unknown();
        }

        private static bool Reader(Instruction instruction, ElementType result, IMethod reference = null) =>
            (instruction.OpCode.Code == Code.Call || instruction.OpCode.Code == Code.Callvirt) &&
            instruction.Operand is IMethod method && method.MethodSig != null && method.MethodSig.HasThis &&
            method.MethodSig.RetType.ElementType == result &&
            method.MethodSig.Params.Count == (result == ElementType.SZArray ? 1 : 0) &&
            (reference != null ? method.DeclaringType.FullName == reference.DeclaringType.FullName :
                method.DeclaringType.ResolveTypeDef()?.DeclaringType != null);

        private static bool Calls(Instruction instruction, string type, string name) =>
            instruction.Operand is IMethod m && m.Name == name && m.DeclaringType.FullName == type;

        private static Dictionary<Local, int> ReadPrologue(CilBody body)
        {
            var il = body.Instructions;
            int firstCall = Find(il, 0, il.Count, i => i.OpCode.FlowControl == FlowControl.Call);
            var immutable = new HashSet<Local>(il.Where(i => i.IsStloc() || i.OpCode.Code == Code.Ldloca ||
                i.OpCode.Code == Code.Ldloca_S).GroupBy(i => i.GetLocal(body.Variables))
                .Where(g => g.Count() == 1 && g.First().IsStloc()).Select(g => g.Key));
            var seeds = new Dictionary<Local, int>();
            var tracker = new ConstantArgumentTracker(body);
            // Stop when initialization first reads runtime state. Until then,
            // only follow concrete branch decisions in the arithmetic prologue.
            Walk(body, 0, firstCall, tracker, i =>
            {
                if (!i.IsStloc() || !tracker.Top.HasValue) return;
                var local = i.GetLocal(body.Variables);
                if (immutable.Contains(local)) seeds[local] = tracker.Top.Value;
            }, stopOnUnknown: true);
            return seeds;
        }

        private static void Walk(CilBody body, int start, int end, ConstantArgumentTracker tracker,
            Action<Instruction> visit, bool stopOnUnknown = false)
        {
            var il = body.Instructions;
            var visited = new HashSet<int>();
            for (int p = start; p != end;)
            {
                if (p < 0 || p >= il.Count || visited.Count >= 2048 || !visited.Add(p))
                {
                    if (stopOnUnknown) return;
                    throw Unknown();
                }
                var i = il[p];
                visit(i);
                switch (i.OpCode.Code)
                {
                    case Code.Br: case Code.Br_S:
                        p = il.IndexOf((Instruction)i.Operand);
                        continue;
                    case Code.Brtrue: case Code.Brtrue_S: case Code.Brfalse: case Code.Brfalse_S:
                        if (tracker.Top.HasValue)
                        {
                            bool whenTrue = i.OpCode.Code == Code.Brtrue || i.OpCode.Code == Code.Brtrue_S;
                            bool take = (tracker.Top.Value != 0) == whenTrue;
                            tracker.DiscardTop();
                            p = take ? il.IndexOf((Instruction)i.Operand) : p + 1;
                            continue;
                        }
                        break;
                    default:
                        if (i.OpCode.FlowControl != FlowControl.Branch && i.OpCode.FlowControl != FlowControl.Cond_Branch &&
                            i.OpCode.FlowControl != FlowControl.Return && i.OpCode.FlowControl != FlowControl.Throw)
                        {
                            tracker.Step(i, body, false);
                            p++;
                            continue;
                        }
                        break;
                }
                if (stopOnUnknown) return;
                throw Unknown();
            }
        }

        private static ConstantArgumentTracker CreateTracker(CilBody body, Dictionary<Local, int> seeds)
        {
            var tracker = new ConstantArgumentTracker(body);
            foreach (var pair in seeds) tracker.SetConstant(pair.Key, pair.Value);
            return tracker;
        }

        private static List<int> ConstantsBefore(CilBody body, Dictionary<Local, int> seeds, int start, int end, Code op)
        {
            var found = new List<int>();
            for (int i = start; i < end; i++)
                if (body.Instructions[i].OpCode.Code == op && ConstantRightOperand(body, seeds, start, i) is int value)
                    found.Add(value);
            return found;
        }

        private static int? ConstantRightOperand(CilBody body, Dictionary<Local, int> seeds, int start, int end)
        {
            int right = ConstantStart(body, seeds, start, end);
            return right < 0 || ConstantStart(body, seeds, start, right) >= 0 ? (int?)null :
                ConstantEndingAt(body, seeds, right, end);
        }

        private static int ConstantStart(CilBody body, Dictionary<Local, int> seeds, int start, int end)
        {
            var il = body.Instructions;
            int needed = 1;
            int p = end;
            while (p > start && needed > 0)
            {
                var i = il[--p];
                if (!i.IsLdcI4() && !IsArithmetic(i.OpCode.Code) &&
                    !(i.IsLdloc() && seeds.ContainsKey(i.GetLocal(body.Variables)))) return -1;
                i.CalculateStackUsage(out var pushes, out var pops);
                needed += pops - pushes;
            }
            return needed == 0 ? p : -1;
        }

        private static int? ConstantEndingAt(CilBody body, Dictionary<Local, int> seeds, int start, int end)
        {
            int p = ConstantStart(body, seeds, start, end);
            if (p < 0) return null;
            var tracker = CreateTracker(body, seeds);
            while (p < end) tracker.Step(body.Instructions[p++], body);
            return tracker.Top;
        }

        private static bool IsArithmetic(Code code)
        {
            switch (code)
            {
                case Code.Add: case Code.Sub: case Code.Mul: case Code.Xor: case Code.Or: case Code.And:
                case Code.Neg: case Code.Not: case Code.Shl: case Code.Shr: case Code.Shr_Un:
                case Code.Conv_I1: case Code.Conv_I2: case Code.Conv_I4: case Code.Conv_U1: case Code.Conv_U2: case Code.Conv_U4:
                    return true;
                default: return false;
            }
        }

        private static int Single(IList<Instruction> il, Func<Instruction, bool> predicate)
        {
            int first = Find(il, 0, il.Count, predicate);
            if (il.Skip(first + 1).Any(predicate)) throw Unknown();
            return first;
        }

        private static int Find(IList<Instruction> il, int start, int end, Func<Instruction, bool> predicate) =>
            FindIndex(start, end, i => predicate(il[i]));

        private static int FindIndex(int start, int end, Func<int, bool> predicate)
        {
            for (int i = start; i < end; i++) if (predicate(i)) return i;
            throw Unknown();
        }

        private static int FindLast(IList<Instruction> il, int start, int end, Func<Instruction, bool> predicate)
        {
            for (int i = end - 1; i >= start; i--) if (predicate(il[i])) return i;
            throw Unknown();
        }

        private static StringResourceException Unknown() => new StringResourceException("无法识别 Eaz 字符串解码布局。");
    }
}
