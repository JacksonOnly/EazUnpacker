using System.Reflection;
using System.Security.Cryptography;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using EazyDevirt.Core.Architecture;
using EazyDevirt.Devirtualization;

namespace EazyDevirt.Core.IO;

internal sealed class HomomorphicReader
{
    private readonly DevirtualizationContext _context;
    private Assembly? _runtime;
    private ResourceStringCandidates? _resourceKeys;
    private readonly Dictionary<string, object> _verifiedKeys = new();
    private readonly Dictionary<string,HashSet<object>> _rejectedKeys=new();
    private readonly HashSet<string> _searchedIntegers=new();
    private double _integerSearchSeconds;
    internal bool AllowBoundedSearch {get;set;}

    public HomomorphicReader(DevirtualizationContext context)
    {
        _context=context;
        _integerSearchSeconds=double.TryParse(Environment.GetEnvironmentVariable("UNPACKER_VM_KEY_SEARCH_SECONDS"),System.Globalization.NumberStyles.Float,System.Globalization.CultureInfo.InvariantCulture,out double seconds)
            && !double.IsNaN(seconds) ? Math.Max(0,Math.Min(seconds,120)) : 20;
    }

    internal (byte[] Code, int Id) Read(VMMethod method, VMOpCode opcode, BinaryReader reader, long available)
    {
        var instructions = method.Instructions;
        int count = instructions.Count;
        if (count < 3 || !instructions[count - 3].IsLdcI4() || instructions[count - 1].OpCode.Code != CilCode.Ldc_I8)
            throw new NotSupportedException("Encrypted region has no supported identifier/IV setup: " +
                string.Join("; ", instructions.Skip(Math.Max(0, count - 5)).Select(i => i.ToString())));
        int id = instructions[count - 3].GetLdcI4Constant();
        long iv = (long)instructions[count - 1].Operand!;
        _context.Console.Info($"[{method.Parent.MetadataToken}] Cipher key operand: {instructions[count - 2]}");

        var guards = instructions.Select((i, n) => (Instruction: i, Index: n)).Where(p =>
            p.Instruction.Operand is IMethodDescriptor descriptor && descriptor.Signature is { } signature &&
            signature.ReturnType.FullName == "System.Boolean" && signature.ParameterTypes.Count is 3 or 4 &&
            signature.ParameterTypes[0].FullName == "System.Object" && signature.ParameterTypes[1].FullName == "System.Byte[]" &&
            signature.ParameterTypes[2].FullName == "System.UInt64");
        var keyLoad = instructions[count - 2];
        var guard = guards.LastOrDefault(p => !keyLoad.IsLdloc() ||
            instructions.Take(p.Index).LastOrDefault(i => i.IsStloc()) is { } store &&
            store.GetLocalVariable(method.Locals) == keyLoad.GetLocalVariable(method.Locals));
        if (guard.Instruction?.Operand is not IMethodDescriptor guardDescriptor || guardDescriptor.Resolve() is not { } verifierDefinition)
            throw new NotSupportedException("Cannot identify encrypted region key verifier.");
        int saltIndex = guard.Index - (guardDescriptor.Signature!.ParameterTypes.Count == 4 ? 2 : 1);
        if (saltIndex < 0 || instructions[saltIndex].OpCode.Code != CilCode.Ldc_I8)
            throw new NotSupportedException("Encrypted region verifier salt is not constant.");
        ulong salt = unchecked((ulong)(long)instructions[saltIndex].Operand!);
        int flag = guardDescriptor.Signature.ParameterTypes.Count == 4 && instructions[guard.Index - 1].IsLdcI4()
            ? instructions[guard.Index - 1].GetLdcI4Constant() : 0;
        var dataField = instructions.Take(saltIndex).LastOrDefault(i => i.OpCode.Code == CilCode.Ldtoken &&
            i.Operand is IFieldDescriptor field && field.Resolve()?.FieldRva is DataSegment)?.Operand as IFieldDescriptor;
        byte[] verifierBytes = (dataField?.Resolve()?.FieldRva as DataSegment)?.Data
            ?? throw new NotSupportedException("Encrypted region verifier is not an RVA byte array.");

        _runtime ??= Assembly.LoadFile(_context.Options.Assembly.FullName);
        var verifier = _runtime.ManifestModule.ResolveMethod(verifierDefinition.MetadataToken.ToInt32()) as MethodInfo
            ?? throw new MissingMethodException("Encrypted region verifier token is not a runtime method.");
        string cacheId = verifierDefinition.MetadataToken + ":" + Convert.ToBase64String(verifierBytes) + ":" + salt + ":" + flag;
        if (!_verifiedKeys.TryGetValue(cacheId, out object? key))
        {
            if(!_rejectedKeys.TryGetValue(cacheId,out var rejected))_rejectedKeys[cacheId]=rejected=new HashSet<object>();
            var parameters=verifier.GetParameters();
            bool booleanFlag=parameters.Length==4&&parameters[3].ParameterType==typeof(bool);
            var verifyBoolean=booleanFlag?(Func<object,byte[],ulong,bool,bool>)Delegate.CreateDelegate(typeof(Func<object,byte[],ulong,bool,bool>),verifier):null;
            var verifyFour=parameters.Length==4&&parameters[3].ParameterType==typeof(int)?(Func<object,byte[],ulong,int,bool>)Delegate.CreateDelegate(typeof(Func<object,byte[],ulong,int,bool>),verifier):null;
            var verifyThree=parameters.Length==3?(Func<object,byte[],ulong,bool>)Delegate.CreateDelegate(typeof(Func<object,byte[],ulong,bool>),verifier):null;
            bool Verify(object value)
            {
                if(rejected.Contains(value))return false;
                bool valid;
                try {
                    if(verifyBoolean!=null)valid=verifyBoolean(value,verifierBytes,salt,flag!=0);
                    else if(verifyFour!=null)valid=verifyFour(value,verifierBytes,salt,flag);
                    else if(verifyThree!=null)valid=verifyThree(value,verifierBytes,salt);
                    else {
                        object converted=parameters[3].ParameterType.IsEnum?Enum.ToObject(parameters[3].ParameterType,flag):Convert.ChangeType(flag,parameters[3].ParameterType,System.Globalization.CultureInfo.InvariantCulture);
                        valid=verifier.Invoke(null,new object[]{value,verifierBytes,salt,converted}) is true;
                    }
                }
                catch (TargetInvocationException exception) when (exception.InnerException is ArgumentException || exception.InnerException is InvalidCastException)
                {valid=false;}
                catch(Exception exception) when(exception is ArgumentException or InvalidCastException){valid=false;}
                if(!valid)rejected.Add(value);return valid;
            }
            string? kind=KeyExpressionEvaluator.InferKeyType(method,count-2);
            _context.Console.Info($"[{method.Parent.MetadataToken}] Key producer type: {kind??"unknown"}; bounded search allowed: {AllowBoundedSearch}.");
            var expressionCandidates=KeyExpressionEvaluator.Candidates(method,count-2).ToArray();
            object? found=expressionCandidates.FirstOrDefault(Verify);
            string keySource="元数据 / IL 表达式推导";
            if(found!=null)_context.Console.Info($"[{method.Parent.MetadataToken}] Key obtained from a bounded metadata/IL expression; original verifier passed.");
            if(found==null){found=KeyExpressionEvaluator.IntrinsicCandidates(method).FirstOrDefault(Verify);keySource="标准互操作语义候选";}
            var candidates = KeyCandidates(method, verifierBytes, salt, flag).ToArray();
            if(found==null&&kind!="System.String"){found=candidates.Cast<object>().FirstOrDefault(Verify);keySource="常量 / 显式候选";}
            if (found == null)
            {
                found = StringKeyCandidates(method, verifierBytes, salt, flag).FirstOrDefault(Verify);
                keySource="字符串 / 资源候选";
            }
            if (found == null && kind is null or "System.String")
            {
                found = (_resourceKeys ??= new ResourceStringCandidates(_context)).External().FirstOrDefault(Verify);
                keySource = "外部程序集 / BAML 资源候选";
            }
            if(found==null&&kind=="System.String"){found=candidates.Cast<object>().FirstOrDefault(Verify);keySource="常量 / 显式候选";}
            int limit=int.TryParse(Environment.GetEnvironmentVariable("UNPACKER_VM_KEY_SEARCH_LIMIT"),out int configuredLimit)?configuredLimit:65536;
            if (found == null && kind!="System.String" && AllowBoundedSearch && limit > 0 && _integerSearchSeconds>0 && _searchedIntegers.Add(cacheId))
            {
                limit = Math.Min(limit, 10000000);
                _context.Console.Info($"[{method.Parent.MetadataToken}] Checking {limit} bounded Int32 candidates with verifier {verifierDefinition.MetadataToken}.");
                string searching=$"[密钥] 有界整数搜索（方法 0x{method.Parent.MetadataToken.ToUInt32():X8}，区域 {id}，最多 {limit:N0} 项）";
                _context.Console.Summary(searching);_context.Progress?.Invoke(searching,0,0);
                keySource="有界整数搜索";
                var elapsed=System.Diagnostics.Stopwatch.StartNew();double nextProgress=1;
                double budget=Math.Min(5,_integerSearchSeconds);int tested=0;
                for (int value = 0; value < limit && elapsed.Elapsed.TotalSeconds<budget; value++)
                {
                    tested++;
                    if (Verify(value)) { found = value; break; }
                    if(elapsed.Elapsed.TotalSeconds>=nextProgress){_context.Progress?.Invoke(searching+$"；已检查 {tested:N0} 项，耗时 {elapsed.Elapsed.TotalSeconds:F1}s",tested,limit);nextProgress+=1;}
                }
                _integerSearchSeconds=Math.Max(0,_integerSearchSeconds-elapsed.Elapsed.TotalSeconds);
                _context.Console.Summary($"[密钥] 整数搜索结束：检查 {tested:N0}/{limit:N0} 项，耗时 {elapsed.Elapsed.TotalSeconds:F1}s；"+(found==null?"未命中，保留原方法。":"原始校验通过。"));
            }
            if (found == null)
            {
                foreach (var instruction in instructions.Take(guard.Index + 1).Take(35).Concat(instructions.Take(guard.Index + 1).Skip(Math.Max(0, guard.Index - 45))))
                    _context.Console.Info($"[{method.Parent.MetadataToken}] Key setup: {instruction}");
                _context.Console.Info($"[{method.Parent.MetadataToken}] Guard {verifierDefinition.MetadataToken}; salt={salt}; flag={flag}; RVA={Convert.ToBase64String(verifierBytes)}");
                throw new NotSupportedException($"Encrypted region {id} needs a verified {kind??"runtime"} key; {rejected.Count} distinct candidates rejected. "+(!AllowBoundedSearch?"Deferred until other VM producers are restored.":"No verified candidate; original method preserved. For external resource keys, supply assets with UNPACKER_VM_KEY_ASSET_PATHS."));
            }
            key = found;
            var recovered=new EazyDevirt.Logging.VerifiedKeyRecord("0x"+method.Parent.MetadataToken.ToUInt32().ToString("X8"),id,key is int?"Int32":"String",key,keySource);
            if(_context.OriginalMethodNames.TryGetValue(method.Parent,out var original))
                recovered=recovered with {OriginalNamespace=original.Namespace,OriginalTypeName=original.TypeName,OriginalMethodName=original.MethodName,OriginalMethodFullName=original.FullName};
            _context.VerifiedKeys.Add(recovered);
            File.AppendAllText(Path.Combine(_context.Options.OutputPath.FullName,"vm-keys.jsonl"),Newtonsoft.Json.JsonConvert.SerializeObject(recovered)+Environment.NewLine,new System.Text.UTF8Encoding(false));
            string keyMessage=recovered.Format();_context.Console.Summary(keyMessage);
            _context.Progress?.Invoke(keyMessage.Length<=3500?keyMessage:$"[密钥] 方法 {recovered.MethodToken} / 区域 {id} 已通过原校验；完整值见 vm-keys.jsonl。",0,0);
            using (var sha = SHA256.Create())
                _context.Console.Info("Verified key profile: " + BitConverter.ToString(sha.ComputeHash(verifierBytes)).Replace("-", "").ToLowerInvariant() + "|" + salt + "|" + flag + "|" +
                    (key is string textKey?"s:"+Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(textKey)):key.ToString()));
            _verifiedKeys.Add(cacheId, key);
        }

        var constructor = opcode.SerializedDelegateMethod.CilMethodBody!.Instructions
            .Where(i => i.OpCode.Code == CilCode.Newobj).Select(i => i.Operand).OfType<IMethodDescriptor>()
            .FirstOrDefault(m => m.Signature?.ParameterTypes.Count == 2 &&
                m.Signature.ParameterTypes[0].FullName == "System.Byte[]" && m.Signature.ParameterTypes[1].FullName == "System.Int64")
            ?.Resolve() ?? throw new NotSupportedException("Cannot identify encrypted region cipher constructor.");
        var cipherType = constructor.DeclaringType!.BaseType!.Resolve()!;
        var decryptDefinition = cipherType.Methods.Single(m => m.Signature?.ReturnType.FullName == "System.Byte[]" &&
            m.Signature.ParameterTypes.Count == 2 && m.Signature.ParameterTypes[0].FullName == "System.Byte[]" &&
            m.Signature.ParameterTypes[1].FullName == "System.Boolean");
        var sizeDefinition = cipherType.Methods.Single(m => m.IsStatic && m.Signature?.ReturnType.FullName == "System.Int32" &&
            m.Signature.ParameterTypes.Count == 1 && m.CilMethodBody!.Instructions.Any(i =>
                i.Operand is MethodDefinition called && called.DeclaringType == cipherType));
        var constructorInfo = _runtime.ManifestModule.ResolveMethod(constructor.MetadataToken.ToInt32()) as ConstructorInfo
            ?? throw new MissingMethodException("Encrypted region cipher token is not a runtime constructor.");
        byte[] keyBytes=EazyDevirt.Logging.VerifiedKeyRecord.Serialize(key);
        object cipher = constructorInfo.Invoke(new object[] { keyBytes, iv });
        var decrypt = _runtime.ManifestModule.ResolveMethod(decryptDefinition.MetadataToken.ToInt32()) as MethodInfo
            ?? throw new MissingMethodException("Encrypted region decrypt token is not a runtime method.");
        try
        {
            byte[] prefix = reader.ReadBytes(4);
            if (prefix.Length != 4) throw new EndOfStreamException("Truncated encrypted region header.");
            byte[] decryptedPrefix = (byte[])decrypt.Invoke(cipher, new object[] { prefix, false })!;
            int length = BitConverter.ToInt32(decryptedPrefix, 0);
            if (length <= 0 || length > available - 4) throw new InvalidDataException("Encrypted region length is outside its method.");
            var getSize = _runtime.ManifestModule.ResolveMethod(sizeDefinition.MetadataToken.ToInt32()) as MethodInfo
                ?? throw new MissingMethodException("Encrypted region size token is not a runtime method.");
            int encryptedLength = (int)getSize.Invoke(null, new object[] { length })!;
            if (encryptedLength < length + 4 || encryptedLength > available || encryptedLength > 16 * 1024 * 1024)
                throw new InvalidDataException("Invalid encrypted region padded length.");
            var encrypted = new byte[encryptedLength];
            Buffer.BlockCopy(prefix, 0, encrypted, 0, 4);
            byte[] tail = reader.ReadBytes(encryptedLength - 4);
            if (tail.Length != encryptedLength - 4) throw new EndOfStreamException("Truncated encrypted region data.");
            Buffer.BlockCopy(tail, 0, encrypted, 4, tail.Length);
            var plaintext = (byte[])decrypt.Invoke(cipher, new object[] { encrypted, false })!;
            if (plaintext.Length < length + 4 || BitConverter.ToInt32(plaintext, 0) != length)
                throw new InvalidDataException("Encrypted region length changed during full decryption.");
            var code = new byte[length];
            Buffer.BlockCopy(plaintext, 4, code, 0, length);
            _context.Console.Info($"[{method.Parent.MetadataToken}] Decrypted region {id}: {length} bytes; key verified against the original guard.");
            return (code, id);
        }
        finally { if (cipher is IDisposable disposable) disposable.Dispose(); }
    }

    private IEnumerable<int> KeyCandidates(VMMethod method, byte[] verifier, ulong salt, int flag)
    {
        var supplied = (Environment.GetEnvironmentVariable("UNPACKER_VM_INT32_KEYS") ?? "").Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(int.Parse);
        var profiles = new List<int>();
        string profilePath = Environment.GetEnvironmentVariable("UNPACKER_VM_KEY_CACHE_PATH") ?? "";
        if (Environment.GetEnvironmentVariable("UNPACKER_VM_USE_KEY_CACHE")=="1" && File.Exists(profilePath))
        {
            using var sha = SHA256.Create();
            string digest = BitConverter.ToString(sha.ComputeHash(verifier)).Replace("-", "").ToLowerInvariant();
            foreach (string line in File.ReadLines(profilePath).Where(l => l.Length > 0 && !l.StartsWith("#")))
            {
                var parts = line.Split('|');
                if (parts.Length == 4 && parts[0] == digest && parts[1] == salt.ToString() && parts[2] == flag.ToString())
                    if(int.TryParse(parts[3],out int value))profiles.Add(value);
            }
        }
        var constants = _context.Module.GetAllTypes().SelectMany(t => t.Methods).Where(m => m.CilMethodBody != null)
            .SelectMany(m => m.CilMethodBody!.Instructions).Where(i => i.IsLdcI4()).Select(i => i.GetLdcI4Constant());
        var metadataConstants = _context.Module.GetAllTypes().SelectMany(t=>t.Fields)
            .Select(f=>f.Constant?.InterpretData()).OfType<int>();
        // Decoded VM literals are not necessarily present in the original CLR IL.
        // Prefer the current region's actual literals before a bounded module scan.
        var regionConstants=method.Instructions.Where(i=>i.IsLdcI4()).Select(i=>i.GetLdcI4Constant()).Reverse();
        return supplied.Concat(profiles).Concat(regionConstants).Concat(constants).Concat(metadataConstants)
            .Concat(Enumerable.Range(0, 32)).Distinct().Take(10000);
    }

    private IEnumerable<string> StringKeyCandidates(VMMethod method,byte[] verifier,ulong salt,int flag)
    {
        string suppliedJson=Environment.GetEnvironmentVariable("UNPACKER_VM_STRING_KEYS")??"[]";
        List<string> supplied;
        try {supplied=Newtonsoft.Json.JsonConvert.DeserializeObject<List<string>>(suppliedJson)??new();}
        catch(Newtonsoft.Json.JsonException ex){throw new ArgumentException("UNPACKER_VM_STRING_KEYS must be a JSON array of strings.",ex);}
        var profiles=new List<string>();
        string profilePath=Environment.GetEnvironmentVariable("UNPACKER_VM_KEY_CACHE_PATH")??"";
        if(Environment.GetEnvironmentVariable("UNPACKER_VM_USE_KEY_CACHE")=="1" && File.Exists(profilePath))
        {
            using var sha=SHA256.Create();
            string digest=BitConverter.ToString(sha.ComputeHash(verifier)).Replace("-", "").ToLowerInvariant();
            foreach(string line in File.ReadLines(profilePath))
            {
                var parts=line.Split('|');
                if(parts.Length==4 && parts[0]==digest && parts[1]==salt.ToString() && parts[2]==flag.ToString() && parts[3].StartsWith("s:"))
                    profiles.Add(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(parts[3].Substring(2))));
            }
        }
        var definitions = _context.Module.GetAllTypes();
        var literals = definitions.SelectMany(t => t.Methods).Where(m => m.CilMethodBody != null)
            .SelectMany(m => m.CilMethodBody!.Instructions).Where(i => i.OpCode.Code == CilCode.Ldstr).Select(i => (string)i.Operand!);
        var metadataNames = definitions.Select(t => t.FullName).Concat(_context.Module.GetImportedTypeReferences().Select(t => t.FullName));
        return supplied.Take(1000).Concat(profiles).Concat(method.Instructions.Where(i=>i.OpCode.Code==CilCode.Ldstr).Select(i=>(string)i.Operand!))
            .Concat(literals).Concat(metadataNames).Concat(ResourceKeyCandidates()).Where(s=>s!=null && s.Length<512).Distinct().Take(10000);
    }

    private IEnumerable<string> ResourceKeyCandidates()
    {
        return (_resourceKeys ??= new ResourceStringCandidates(_context)).Local();
    }
}
