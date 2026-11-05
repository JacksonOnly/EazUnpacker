using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using EazFixer.Processors;

namespace EazFixer
{
    // A resized table still uses the original logical offsets for ID decoding,
    // seed lengths, frame masks and aliases. Translate only the actual seek.
    internal static class StringResourceOffsets
    {
        private const string MapNamespace = "Unpacker.StringResources";
        private const string MapPrefix = "OffsetMap_";
        private const string MapMethod = "Translate";

        internal static Dictionary<int, int> Read(MethodDef decoder)
        {
            var mapper = GetMapper(decoder);
            if (mapper == null) return null;
            byte[] bytes = GetStorage(mapper).InitialValue;
            if (bytes == null || bytes.Length == 0 || bytes.Length % 8 != 0 || bytes.Length > 250000 * 8)
                throw Invalid();
            var map = new Dictionary<int, int>(bytes.Length / 8);
            int lastLogical = -1, lastPhysical = -1;
            for (int i = 0; i < bytes.Length; i += 8)
            {
                int logical = BitConverter.ToInt32(bytes, i), physical = BitConverter.ToInt32(bytes, i + 4);
                if (logical <= lastLogical || physical <= lastPhysical || i == 0 && logical != physical)
                    throw Invalid();
                map.Add(physical, logical);
                lastLogical = logical;
                lastPhysical = physical;
            }
            return map;
        }

        internal static void Install(ModuleDef module, MethodDef decoder, int[] offsets)
        {
            var mapper = GetMapper(decoder);
            if (mapper == null)
            {
                var body = decoder.Body;
                int conversion = FindConversion(decoder);
                var targets = StringFixer.GetBoundaries(body);
                if (conversion < 1 || !body.Instructions[conversion - 1].IsLdloc() ||
                    targets.Contains(body.Instructions[conversion]) || targets.Contains(body.Instructions[conversion + 1]))
                    throw new StringResourceException("解码器的定位指令不支持扩容回写。");

                mapper = CreateMapper(module, decoder);
                body.Instructions.Insert(conversion, Instruction.Create(OpCodes.Call, mapper));
                body.SimplifyBranches();
                body.OptimizeBranches();
            }

            var field = GetStorage(mapper);
            var init = mapper.DeclaringType.FindStaticConstructor();
            if (init?.Body == null || init.Body.Instructions.Count == 0 || !init.Body.Instructions[0].IsLdcI4() ||
                !init.Body.Instructions.Any(i => i.OpCode.Code == Code.Ldtoken && i.Operand == field))
                throw Invalid();
            byte[] bytes = new byte[offsets.Length * sizeof(int)];
            Buffer.BlockCopy(offsets, 0, bytes, 0, bytes.Length);
            var layout = field.FieldType.ToTypeDefOrRef()?.ResolveTypeDef()?.ClassLayout;
            if (layout == null || bytes.Length == 0 || bytes.Length % 8 != 0) throw Invalid();
            layout.ClassSize = (uint)bytes.Length;
            field.InitialValue = bytes;
            init.Body.Instructions[0].OpCode = OpCodes.Ldc_I4;
            init.Body.Instructions[0].Operand = offsets.Length;
        }

        private static int FindConversion(MethodDef decoder)
        {
            var il = decoder.Body.Instructions;
            for (int i = 1; i < il.Count; i++)
                if (il[i].Operand is IMethod m && m.Name == "set_Position" &&
                    m.DeclaringType.FullName == "System.IO.Stream" && il[i - 1].OpCode.Code == Code.Conv_I8)
                    return i - 1;
            return -1;
        }

        private static MethodDef GetMapper(MethodDef decoder)
        {
            int conversion = FindConversion(decoder);
            if (conversion <= 0) return null;
            var call = decoder.Body.Instructions[conversion - 1];
            return call.OpCode.Code == Code.Call && call.Operand is MethodDef mapper && mapper.Name == MapMethod &&
                mapper.DeclaringType.Namespace == MapNamespace &&
                mapper.DeclaringType.Name.String.StartsWith(MapPrefix, StringComparison.Ordinal) ? mapper : null;
        }

        private static FieldDef GetStorage(MethodDef mapper)
        {
            var fields = mapper.DeclaringType.Fields.Where(f => f.Name == "Data" && f.IsStatic && f.HasFieldRVA).ToArray();
            if (fields.Length != 1) throw Invalid();
            return fields[0];
        }

        private static MethodDef CreateMapper(ModuleDef module, MethodDef decoder)
        {
            var core = module.CorLibTypes;
            string name = MapPrefix + decoder.MDToken.Raw.ToString("X8");
            while (module.Types.Any(t => t.Namespace == MapNamespace && t.Name == name)) name += "_";
            var owner = new TypeDefUser(MapNamespace, name, core.Object.TypeDefOrRef)
            {
                Attributes = TypeAttributes.NotPublic | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit
            };
            var storage = new TypeDefUser("DataBlock", core.GetTypeRef("System", "ValueType"))
            {
                Attributes = TypeAttributes.NestedPrivate | TypeAttributes.ExplicitLayout | TypeAttributes.Sealed,
                ClassLayout = new ClassLayoutUser(1, 8)
            };
            owner.NestedTypes.Add(storage);
            var data = new FieldDefUser("Data", new FieldSig(new ValueTypeSig(storage)),
                FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.InitOnly | FieldAttributes.HasFieldRVA);
            var index = new FieldDefUser("Offsets", new FieldSig(new SZArraySig(core.Int32)),
                FieldAttributes.Private | FieldAttributes.Static | FieldAttributes.InitOnly);
            owner.Fields.Add(data);
            owner.Fields.Add(index);
            module.Types.Add(owner);

            var initialize = new MemberRefUser(module, "InitializeArray", MethodSig.CreateStatic(core.Void,
                new ClassSig(core.GetTypeRef("System", "Array")), new ValueTypeSig(core.GetTypeRef("System", "RuntimeFieldHandle"))),
                core.GetTypeRef("System.Runtime.CompilerServices", "RuntimeHelpers"));
            var init = new MethodDefUser(".cctor", MethodSig.CreateStatic(core.Void), MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Private | MethodAttributes.Static | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName)
            {
                Body = new CilBody()
            };
            owner.Methods.Add(init);
            Append(init.Body, Instruction.Create(OpCodes.Ldc_I4, 0), Instruction.Create(OpCodes.Newarr, core.Int32.TypeDefOrRef),
                Instruction.Create(OpCodes.Dup), Instruction.Create(OpCodes.Ldtoken, data), Instruction.Create(OpCodes.Call, initialize),
                Instruction.Create(OpCodes.Stsfld, index), Instruction.Create(OpCodes.Ret));

            var mapper = new MethodDefUser(MapMethod, MethodSig.CreateStatic(core.Int32, core.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Assembly | MethodAttributes.Static | MethodAttributes.HideBySig)
            {
                Body = new CilBody { InitLocals = true }
            };
            owner.Methods.Add(mapper);
            var body = mapper.Body;
            var lo = new Local(core.Int32);
            var hi = new Local(core.Int32);
            var mid = new Local(core.Int32);
            var key = new Local(core.Int32);
            foreach (var local in new[] { lo, hi, mid, key }) body.Variables.Add(local);

            var ctor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(core.Void),
                core.GetTypeRef("System", "ArgumentOutOfRangeException"));
            var loop = Instruction.Create(OpCodes.Ldloc, lo);
            var increase = Instruction.Create(OpCodes.Ldloc, mid);
            var decrease = Instruction.Create(OpCodes.Ldloc, mid);
            var missing = Instruction.Create(OpCodes.Newobj, ctor);
            Append(body,
                Instruction.Create(OpCodes.Ldc_I4_0), Instruction.Create(OpCodes.Stloc, lo),
                Instruction.Create(OpCodes.Ldsfld, index), Instruction.Create(OpCodes.Ldlen), Instruction.Create(OpCodes.Conv_I4),
                Instruction.Create(OpCodes.Ldc_I4_1), Instruction.Create(OpCodes.Shr), Instruction.Create(OpCodes.Stloc, hi),
                loop, Instruction.Create(OpCodes.Ldloc, hi), Instruction.Create(OpCodes.Bge, missing),
                Instruction.Create(OpCodes.Ldloc, lo), Instruction.Create(OpCodes.Ldloc, hi), Instruction.Create(OpCodes.Add),
                Instruction.Create(OpCodes.Ldc_I4_1), Instruction.Create(OpCodes.Shr), Instruction.Create(OpCodes.Stloc, mid),
                Instruction.Create(OpCodes.Ldsfld, index), Instruction.Create(OpCodes.Ldloc, mid), Instruction.Create(OpCodes.Ldc_I4_1),
                Instruction.Create(OpCodes.Shl), Instruction.Create(OpCodes.Ldelem_I4), Instruction.Create(OpCodes.Stloc, key),
                Instruction.Create(OpCodes.Ldloc, key), Instruction.Create(OpCodes.Ldarg_0), Instruction.Create(OpCodes.Blt, increase),
                Instruction.Create(OpCodes.Ldloc, key), Instruction.Create(OpCodes.Ldarg_0), Instruction.Create(OpCodes.Bgt, decrease),
                Instruction.Create(OpCodes.Ldsfld, index), Instruction.Create(OpCodes.Ldloc, mid), Instruction.Create(OpCodes.Ldc_I4_1),
                Instruction.Create(OpCodes.Shl), Instruction.Create(OpCodes.Ldc_I4_1), Instruction.Create(OpCodes.Add),
                Instruction.Create(OpCodes.Ldelem_I4), Instruction.Create(OpCodes.Ret),
                increase, Instruction.Create(OpCodes.Ldc_I4_1), Instruction.Create(OpCodes.Add),
                Instruction.Create(OpCodes.Stloc, lo), Instruction.Create(OpCodes.Br, loop),
                decrease, Instruction.Create(OpCodes.Stloc, hi), Instruction.Create(OpCodes.Br, loop),
                missing, Instruction.Create(OpCodes.Throw));
            body.OptimizeMacros();
            body.OptimizeBranches();
            return mapper;
        }

        private static void Append(CilBody body, params Instruction[] instructions)
        {
            foreach (var instruction in instructions) body.Instructions.Add(instruction);
        }

        private static StringResourceException Invalid() => new StringResourceException("回写后的字符串偏移映射无效。");
    }
}
