using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace EazFixer
{
    // Deliberately basic-block local: unknown joins and escaped local addresses
    // must never become a guessed decoder argument.
    internal sealed class ConstantArgumentTracker
    {
        private readonly List<int?> _stack = new List<int?>();
        private readonly Dictionary<Local, int?> _locals = new Dictionary<Local, int?>();
        private readonly HashSet<Local> _addressTaken;
        internal ConstantArgumentTracker(CilBody body)
        {
            _addressTaken = new HashSet<Local>(body.Instructions
                .Where(item => item.OpCode.Code == Code.Ldloca || item.OpCode.Code == Code.Ldloca_S)
                .Select(item => item.GetLocal(body.Variables)).Where(item => item != null));
        }
        internal int? Top => _stack.Count == 0 ? null : _stack[_stack.Count - 1];
        internal void SetConstant(Local local, int value)
        {
            if (!_addressTaken.Contains(local)) _locals[local] = value;
        }
        internal void DiscardTop() => Pop();
        internal void Reset() { _stack.Clear(); _locals.Clear(); }
        private int? Pop()
        {
            if (_stack.Count == 0) return null;
            var value = _stack[_stack.Count - 1]; _stack.RemoveAt(_stack.Count - 1); return value;
        }
        internal void Step(Instruction instruction, CilBody body, bool resetOnTransfer = true)
        {
            if (instruction.IsLdcI4()) { _stack.Add(instruction.GetLdcI4Value()); return; }
            if (instruction.IsLdloc())
            {
                var local = instruction.GetLocal(body.Variables);
                _stack.Add(local != null && !_addressTaken.Contains(local) && _locals.TryGetValue(local, out var value) ? value : null); return;
            }
            if (instruction.IsStloc())
            {
                var value = Pop(); var local = instruction.GetLocal(body.Variables);
                if (local != null && !_addressTaken.Contains(local)) _locals[local] = value; return;
            }
            switch (instruction.OpCode.Code)
            {
                case Code.Nop: return;
                case Code.Dup: _stack.Add(Top); return;
                case Code.Pop: Pop(); return;
                case Code.Ldloca: case Code.Ldloca_S:
                    _locals.Clear(); _stack.Add(null); return;
                case Code.Neg: { var value = Pop(); _stack.Add(value.HasValue ? unchecked(-value.Value) : (int?)null); return; }
                case Code.Not: { var value = Pop(); _stack.Add(value.HasValue ? ~value.Value : (int?)null); return; }
                case Code.Conv_I4: case Code.Conv_U4: return;
                case Code.Conv_I1: Convert(value => (sbyte)value); return;
                case Code.Conv_U1: Convert(value => (byte)value); return;
                case Code.Conv_I2: Convert(value => (short)value); return;
                case Code.Conv_U2: Convert(value => (ushort)value); return;
                case Code.Add: case Code.Sub: case Code.Mul: case Code.Xor: case Code.And: case Code.Or:
                case Code.Shl: case Code.Shr: case Code.Shr_Un: case Code.Div: case Code.Div_Un: case Code.Rem: case Code.Rem_Un:
                case Code.Ceq: case Code.Cgt: case Code.Cgt_Un: case Code.Clt: case Code.Clt_Un:
                    var right = Pop(); var left = Pop();
                    _stack.Add(left.HasValue && right.HasValue ? Evaluate(instruction.OpCode.Code, left.Value, right.Value) : null); return;
            }
            instruction.CalculateStackUsage(out var pushes, out var pops);
            if (pops < 0 || pops > _stack.Count) _stack.Clear();
            else if (pops > 0) _stack.RemoveRange(_stack.Count - pops, pops);
            for (int index = 0; index < pushes; index++) _stack.Add(null);
            if (resetOnTransfer && (instruction.OpCode.FlowControl == FlowControl.Branch || instruction.OpCode.FlowControl == FlowControl.Cond_Branch ||
                instruction.OpCode.FlowControl == FlowControl.Return || instruction.OpCode.FlowControl == FlowControl.Throw)) Reset();
        }
        private void Convert(Func<int, int> convert)
        {
            var value = Pop(); _stack.Add(value.HasValue ? convert(value.Value) : (int?)null);
        }
        private static int? Evaluate(Code code, int left, int right)
        {
            unchecked
            {
                switch (code)
                {
                    case Code.Add: return left + right;
                    case Code.Sub: return left - right;
                    case Code.Mul: return left * right;
                    case Code.Xor: return left ^ right;
                    case Code.And: return left & right;
                    case Code.Or: return left | right;
                    case Code.Shl: return left << right;
                    case Code.Shr: return left >> right;
                    case Code.Shr_Un: return (int)((uint)left >> right);
                    case Code.Div: return right == 0 || left == int.MinValue && right == -1 ? (int?)null : left / right;
                    case Code.Div_Un: return right == 0 ? (int?)null : (int)((uint)left / (uint)right);
                    case Code.Rem: return right == 0 || left == int.MinValue && right == -1 ? (int?)null : left % right;
                    case Code.Rem_Un: return right == 0 ? (int?)null : (int)((uint)left % (uint)right);
                    case Code.Ceq: return left == right ? 1 : 0;
                    case Code.Cgt: return left > right ? 1 : 0;
                    case Code.Cgt_Un: return (uint)left > (uint)right ? 1 : 0;
                    case Code.Clt: return left < right ? 1 : 0;
                    case Code.Clt_Un: return (uint)left < (uint)right ? 1 : 0;
                    default: return null;
                }
            }
        }
    }
}
