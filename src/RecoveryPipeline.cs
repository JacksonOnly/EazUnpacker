using System.Reflection;
using System.Security.Cryptography;
using EazFixer;
using EazyDevirt;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Unpacker;

internal static class RecoveryPipeline
{
    internal static int Run(string[] args)
    {
        string input = Path.GetFullPath(args[1]), dir = Path.GetFullPath(args[2]);
        bool analyze = bool.Parse(args[3]), noVm = bool.Parse(args[4]); int timeout = int.Parse(args[5]);
        bool validateClr=args.Length>6&&bool.Parse(args[6]);
        var result = new SampleResult { Input = input,ClrValidationRequested=validateClr };
        try
        {
            using var dependencyScope=new DependencyLoadScope(input);
            ProgressEvents.Send(1,"start","读取输入、计算 SHA-256 并检查单文件载荷");
            byte[] bytes = File.ReadAllBytes(input);
            using (var hash = SHA256.Create()) result.Sha256 = BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            string target = Path.Combine(dir, "input", Path.GetFileName(input));
            if (string.Equals(target, input, StringComparison.OrdinalIgnoreCase)) throw new IOException("Output would overwrite input.");
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllBytes(target, bytes);
            if (File.Exists(input + ".config")) File.Copy(input + ".config", target + ".config");
            List<string>? bundleFiles = null;
            if (BundleExtractor.IsBundle(bytes, out long header))
            {
                ProgressEvents.Send(1,"info","发现 .NET 单文件包，正在提取载荷");
                var extracted = BundleExtractor.Extract(bytes, header, Path.Combine(dir, "bundle"));
                bundleFiles = extracted;
                var main = extracted.Where(p => Path.GetExtension(p) == ".dll").FirstOrDefault(p =>
                {
                    try { using var m = dnlib.DotNet.ModuleDefMD.Load(p); return m.EntryPoint != null; } catch { return false; }
                });
                if (main == null) throw new InvalidDataException("Bundle has no managed entry point.");
                target = main;
                result.Stages.Add(new StageResult { Name = "Bundle", Status = "success", Changes = extracted.Count, Detail = "Extracted single-file payloads." });
                ProgressEvents.Send(1,"info","已提取 "+extracted.Count+" 个载荷");
            }
            result.Before = AssemblyInspector.Inspect(target);
            ProgressEvents.Send(1,"success","元数据检查完成："+result.Before.Types+" 个类型，"+result.Before.Methods+" 个方法，发现 "+result.Before.VirtualizedMethods.Count+" 个 VM 方法");
            if (analyze)
            {
                result.Output = target; result.After = result.Before; result.Status = "analyzed";
                result.Stages.Add(new StageResult { Name = "Inspection", Status = "success", Detail = "Static metadata inspection." }); return 0;
            }
            int startupBodies=StartupBodyRestore.Process(target);
            if(startupBodies>0)
            {
                result.Stages.Add(new StageResult { Name="StartupIL", Status="success", Changes=startupBodies,
                    Detail="Restored verified IL from the startup patch table and removed only its consumed initialization call." });
                ProgressEvents.Send(1,"info","已恢复启动期加密 IL："+startupBodies+" 个方法体");
            }
            int moduleResources=ModuleResourceRestore.Process(target,out var carrier);
            if(moduleResources>0)
            {
                result.Stages.Add(new StageResult { Name="ModuleResources", Status="success", Changes=moduleResources,
                    Detail="Expanded a verified resource-only payload from the module resolver. Original resolver and payload retained." });
                ProgressEvents.Send(2,"info","已恢复启动期嵌入资源："+moduleResources+" 项");
            }
            int costuraDependencies = CosturaDependencies.Extract(target, Path.GetDirectoryName(target)!,result.EmbeddedAssemblies);
            if (costuraDependencies > 0) result.Stages.Add(new StageResult { Name = "CosturaDependencies", Status = "success",
                Changes = costuraDependencies, Detail = "Materialized identity-checked embedded managed dependencies; original resources and initializer retained; see input/costura-dependencies.json." });
            int rawDependencies=CosturaDependencies.ExtractRawManaged(target,Path.GetDirectoryName(target)!,result.EmbeddedAssemblies);
            if(rawDependencies>0)
                result.Stages.Add(new StageResult { Name="EmbeddedManagedDependencies", Status="success", Changes=rawDependencies,
                    Detail="Materialized embedded managed references matching the input's dependency graph. Original resources retained." });
            using var extractedDependencyScope = new DependencyLoadScope(input, target);
            string cleaned = Path.Combine(dir, Path.GetFileNameWithoutExtension(target) + "-clean" + Path.GetExtension(target));
            ProgressEvents.Send(2,"start","恢复字符串、资源并整理控制流");
            int tableChanges = StringTablePass.Process(target, cleaned);
            if (tableChanges > 0)
            {
                result.Stages.Add(new StageResult { Name = "RvaStrings", Status = "success", Changes = tableChanges, Detail = "Static UTF8 index-XOR table recovery; no target code executed." });
                ProgressEvents.Send(2,"info","静态字符串表恢复 "+tableChanges+" 项");
            }
            else if (result.Before.ModernRuntime)
            {
                string modern = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "modern", "Unpacker.ModernWorker.exe");
                string modernReport = Path.Combine(dir, "modern.json");
                if (File.Exists(modern))
                {
                    ProgressEvents.Send(2,"info","启动现代 .NET 字符串后端；日志："+Path.Combine(dir,"modern.log"));
                    int code = ProcessRunner.Run(modern, new[] { target, cleaned, modernReport }, Path.Combine(dir, "modern.log"), Math.Max(1, timeout / 2));
                    if (File.Exists(modernReport))
                    {
                        var stages = JsonConvert.DeserializeObject<List<StageResult>>(File.ReadAllText(modernReport))!; result.Stages.AddRange(stages);
                    }
                    else result.Stages.Add(new StageResult { Name = "ModernStrings", Status = "failed", Detail = "Modern backend exited " + code + "; see modern.log." });
                }
                else result.Stages.Add(new StageResult { Name = "ModernStrings", Status = "failed", Detail = "Build ModernWorker and copy it to bin/Release/net48/modern." });
            }
            else
            {
                foreach (var stage in FixerBridge.Process(target, cleaned,false,(name,state,count)=>ProgressEvents.Backend(2,name,state,count)))
                {
                    result.Stages.Add(new StageResult { Name = stage.Name, Status = stage.Status, Detail = stage.Detail, Changes = stage.Changes });
                    result.EmbeddedAssemblies.AddRange(stage.Exports);
                }
            }
            if (!File.Exists(cleaned)) File.Copy(target, cleaned);
            foreach(var dependency in Directory.GetFiles(Path.GetDirectoryName(target)!,"*.dll").Where(f=>f!=target))
                File.Copy(dependency,Path.Combine(dir,Path.GetFileName(dependency)),true);
            string sourceConfig = target + ".config";
            if (File.Exists(sourceConfig)) File.Copy(sourceConfig, cleaned + ".config");
            RememberOutput(result,cleaned,dir);
            // VM opcode handlers can themselves contain opaque predicates. Run
            // the same proven-only flow normalization before matching handlers,
            // not just after devirtualization/name recovery.
            string normalized=Path.Combine(dir,Path.GetFileNameWithoutExtension(target)+"-normalized"+Path.GetExtension(target));
            int preVmFlow=ControlFlowCleanupPass.Process(cleaned,normalized,Path.Combine(dir,"pre-vm-control-flow.json"));
            if(preVmFlow>0)
            {
                if(File.Exists(cleaned+".config"))File.Copy(cleaned+".config",normalized+".config");
                cleaned=normalized;
                result.Stages.Add(new StageResult{Name="PreVM.ControlFlow",Status="success",Changes=preVmFlow,
                    Detail="Proven integer predicates, switch dispatchers and same-region jump chains normalized before VM handler matching; see pre-vm-control-flow.json."});
            }
            var postStrings = AssemblyInspector.Inspect(cleaned);
            RememberOutput(result,cleaned,dir);
            ProgressEvents.Send(2,"success","字符串/资源阶段结束；待还原 VM 方法："+postStrings.VirtualizedMethods.Count);
            if (postStrings.VirtualizedMethods.Count > 0 && !noVm)
            {
                string devirt = Path.Combine(dir, Path.GetFileNameWithoutExtension(target) + "-devirt" + Path.GetExtension(target));
                string countFile = Path.Combine(dir, "vm-count.txt");
                ProgressEvents.Send(3,"start","还原 "+postStrings.VirtualizedMethods.Count+" 个 VM 方法；详细日志："+Path.Combine(dir,"vm.log"));
                string vmWorker=postStrings.ModernRuntime
                    ?Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"modern","Unpacker.ModernWorker.exe")
                    :Assembly.GetExecutingAssembly().Location;
                int code = File.Exists(vmWorker)?ProcessRunner.Run(vmWorker, new[] { "--vm-worker", cleaned, devirt, countFile }, Path.Combine(dir, "vm.log"), Math.Max(1, timeout / 2)):-1;
                int count = File.Exists(countFile) ? int.Parse(File.ReadAllText(countFile)) : 0;
                string methodsReport=Path.Combine(dir,"vm-methods.json");
                var vmEntries=File.Exists(methodsReport)?JToken.Parse(File.ReadAllText(methodsReport)) as JArray??new JArray():new JArray();
                var restoredHosts=new HashSet<string>(vmEntries.Where(e=>(bool?)e["Restored"]==true)
                    .Select(e=>(string?)e["Token"]??""),StringComparer.OrdinalIgnoreCase);
                int hosts=restoredHosts.Count;
                int remaining=File.Exists(devirt)?AssemblyInspector.Inspect(devirt).VirtualizedMethods.Count:postStrings.VirtualizedMethods.Count;
                // One host can contain multiple inlined VM call sites. Counting
                // recovered bodies alone can both overcount hosts and hide an
                // unprocessed second call in a supposedly restored method.
                bool vmComplete=code==0 && count>0 && hosts==postStrings.VirtualizedMethods.Count && remaining==0
                    && postStrings.VirtualizedMethods.All(token=>restoredHosts.Contains("0x"+token.ToString("X8")))
                    && vmEntries.Count==count && vmEntries.All(e=>(bool?)e["Restored"]==true);
                ProgressEvents.Send(3,vmComplete?"success":"warning","VM 已还原 "+count+" 个方法体、"+hosts+"/"+postStrings.VirtualizedMethods.Count+" 个宿主；剩余 "+remaining+"，后端退出码 "+code);
                result.Stages.Add(new StageResult { Name = "VM", Status = vmComplete ? "success" : count > 0 ? "partial" : "failed", Changes = count,
                    Detail = "Restored "+count+" VM bodies in "+hosts+"/"+postStrings.VirtualizedMethods.Count+" hosts; remaining hosts "+remaining+"; backend exit " + code + "; see vm-methods.json and vm.log." });
                if (code == 0 && count > 0 && File.Exists(devirt))
                {
                    if (File.Exists(cleaned + ".config")) File.Copy(cleaned + ".config", devirt + ".config");
                    cleaned = devirt;
                    RememberOutput(result,cleaned,dir);
                    string stringWorker=postStrings.ModernRuntime
                        ?Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"modern","Unpacker.ModernWorker.exe")
                        :Assembly.GetExecutingAssembly().Location;
                    if (File.Exists(stringWorker))
                    {
                        string final = Path.Combine(dir, Path.GetFileNameWithoutExtension(target) + "-unpacked" + Path.GetExtension(target));
                        string stringsReport = Path.Combine(dir, "post-vm-strings.json");
                        ProgressEvents.Send(3,"info","还原后的字符串与控制流复处理");
                        int stringsCode = ProcessRunner.Run(stringWorker, new[] { "--strings-worker", cleaned, final, stringsReport,input }, Path.Combine(dir, "post-vm-strings.log"), Math.Max(1, timeout / 4));
                        if (stringsCode is 0 or 2 && File.Exists(final) && File.Exists(stringsReport))
                        {
                            var stages = JsonConvert.DeserializeObject<List<StageResult>>(File.ReadAllText(stringsReport))!;
                            foreach (var stage in stages) stage.Name = "PostVM." + stage.Name;
                            result.Stages.AddRange(stages);
                            if (File.Exists(cleaned + ".config")) File.Copy(cleaned + ".config", final + ".config");
                            cleaned = final;
                            RememberOutput(result,cleaned,dir);
                        }
                        else result.Stages.Add(new StageResult { Name = "PostVM.Strings", Status = "failed", Detail = "Backend exit " + stringsCode + "; see post-vm-strings.log." });
                    }
                    else result.Stages.Add(new StageResult { Name = "PostVM.Strings", Status = "failed", Detail = "Modern backend missing: "+stringWorker });
                }
            }
            else if (postStrings.VirtualizedMethods.Count > 0) result.Stages.Add(new StageResult { Name = "VM", Status = "skipped", Detail = "--no-vm" });
            else ProgressEvents.Send(3,"info","未检测到 VM 方法，跳过反虚拟化");
            ProgressEvents.Send(4,"start","恢复元数据命名、异步转发与改写兼容性");
            string compatible=Path.Combine(dir,Path.GetFileNameWithoutExtension(target)+"-compatible"+Path.GetExtension(target));
            int integrity=IntegrityCompatibilityPass.Process(cleaned,compatible,Path.Combine(dir,"integrity-compatibility.json"));
            if(integrity>0)
            {
                if(File.Exists(cleaned+".config"))File.Copy(cleaned+".config",compatible+".config");
                cleaned=compatible;
                RememberOutput(result,cleaned,dir);
                result.Stages.Add(new StageResult{Name="IntegrityCompatibility",Status="success",Changes=integrity,
                    Detail="Adapted identified self-signature guards invalidated by rewriting; other checks retained; see integrity-compatibility.json."});
            }
            if((postStrings.VirtualizedMethods.Count==0 || result.Stages.Any(s=>s.Name=="VM" && s.Status=="success")) &&
                AssemblyInspector.Inspect(cleaned).VirtualizedMethods.Count==0)
            {
                string pruned=Path.Combine(dir,"pruned"+Path.GetExtension(cleaned));
                try
                {
                    var cleanup=ProtectionCleanupPass.Process(cleaned,pruned,target,result,carrier,startupBodies>0);
                    if(cleanup.Changed)
                    {
                        if(File.Exists(cleaned+".config"))File.Copy(cleaned+".config",pruned+".config");
                        cleaned=pruned;
                        RememberOutput(result,cleaned,dir);
                    }
                    if(cleanup.Changed || cleanup.Retained>0)
                    {
                        string detail=$"已清理保护残留：{cleanup.Types} 个类型、{cleanup.Methods} 个方法、{cleanup.Resources} 项资源；仍有引用的保护入口 {cleanup.Retained} 个。";
                        result.Stages.Add(new StageResult{Name="ProtectionCleanup",Status=cleanup.Retained==0?"success":"partial",
                            Changes=cleanup.Types+cleanup.Methods+cleanup.Fields+cleanup.Resources,Detail=detail});
                        ProgressEvents.Send(4,cleanup.Retained==0?"success":"warning",detail);
                    }
                }
                catch(Exception ex)
                {
                    result.Stages.Add(new StageResult{Name="ProtectionCleanup",Status="partial",Detail=ex.ToString()});
                    ProgressEvents.Send(4,"warning","残留清理未通过校验，保留清理前的恢复产物。");
                }
            }
            string named=Path.Combine(dir,Path.GetFileNameWithoutExtension(target)+"-recovered"+Path.GetExtension(target));
            int renamed=NameRecoveryPass.Process(cleaned,named,Path.Combine(dir,"rename-map.json"));
            string inlineReport=Path.Combine(dir,"inline-expressions.json");
            int inlineCount=File.Exists(inlineReport)?JArray.Parse(File.ReadAllText(inlineReport)).Count:0;
            result.Stages.Add(new StageResult{Name="InlineExpressions",Status="success",Changes=inlineCount,Detail="Bounded total integer leaf expressions inlined with exact-once argument evaluation; see inline-expressions.json."});
            ProgressEvents.Send(4,"info","整数表达式内联 "+inlineCount+" 处；调用参数的求值次数与顺序保留");
            ProgressEvents.Send(4,"success","命名恢复 "+renamed+" 项；自身完整性兼容 "+integrity+" 处");
            result.Stages.Add(new StageResult{Name="Names",Status="success",Changes=renamed,Detail="Stable readable metadata names, references, resources and PDB locals recovered."});
            if(File.Exists(cleaned+".config"))File.Copy(cleaned+".config",named+".config");
            cleaned=named;
            RememberOutput(result,cleaned,dir);
            // Literal conditional branches are folded inside the naming stage's
            // single final write (see NameRecoveryPass), so the adjusted
            // per-method max-stack values stay authoritative and no extra
            // serialization grows the published assembly.
            string flowReport=Path.Combine(dir,"control-flow-cleanup.json");
            if(File.Exists(flowReport))
            {
                var flow=JObject.Parse(File.ReadAllText(flowReport));
                int flowChanges=((int?)flow["FoldedBranches"]??0)+((int?)flow["RemovedInstructions"]??0);
                if(flowChanges>0)
                {
                    ProgressEvents.Send(4,"info","控制流清理：折叠字面量条件分支并删除不可达指令 "+flowChanges+" 处");
                    result.Stages.Add(new StageResult{Name="ControlFlowCleanup",Status="success",Changes=flowChanges,
                        Detail="Folded literal conditional branches and dropped only statically unreachable instructions; exception regions, tokens, definitions and reachable effects retained; see control-flow-cleanup.json."});
                }
            }
            result.After = AssemblyInspector.Inspect(cleaned); result.Output = cleaned;
            if (bundleFiles != null)
            {
                foreach (string payload in bundleFiles.Where(p => p != target))
                {
                    string relative = payload.Substring(Path.Combine(dir, "bundle").Length + 1);
                    if (relative == Path.GetFileNameWithoutExtension(target) + ".runtimeconfig.json" || relative == Path.GetFileNameWithoutExtension(target) + ".deps.json")
                        relative = Path.GetFileNameWithoutExtension(cleaned) + relative.Substring(Path.GetFileNameWithoutExtension(target).Length);
                    string dest = Path.Combine(dir, relative); Directory.CreateDirectory(Path.GetDirectoryName(dest)!); File.Copy(payload, dest,true);
                }
            }
            string vmReport = Path.Combine(dir, "vm-methods.json");
            int validationTargets=File.Exists(vmReport)?ClrValidator.ReadTargets(vmReport).Count:0;
            if (validateClr && validationTargets>0 && result.Stages.Any(s => s.Name == "VM" && s.Changes > 0))
            {
                string clrReport = Path.Combine(dir, "clr-validation.json");
                ProgressEvents.Send(5,"start","隔离 CLR 准备检查（不调用业务方法）");
                string validator=result.After.ModernRuntime
                    ?Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"modern","Unpacker.ModernWorker.exe")
                    :Assembly.GetExecutingAssembly().Location;
                int code = File.Exists(validator)?ProcessRunner.Run(validator,
                    new[] { "--validate-worker", cleaned, vmReport, clrReport,"5",input }, Path.Combine(dir, "clr-validation.log"), Math.Max(1, timeout / 4)):-1;
                int expected=validationTargets;
                bool validated=code==0 && ClrValidator.HasCompleteReport(clrReport,expected);
                result.Stages.Add(new StageResult { Name = "CLRValidation", Status = validated ? "success" : "failed",
                    Detail = "Expected "+expected+" recovered methods prepared by CLR in an isolated process; exit " + code + "; complete report: "+validated+"; see clr-validation.json/log. No business methods explicitly invoked; CLR may initialize helpers." });
                ProgressEvents.Send(5,validated?"success":"error","恢复后 CLR 检查退出码 "+code+"；日志："+Path.Combine(dir,"clr-validation.log"));
            }
            else ProgressEvents.Send(5,"info",validateClr?"没有待验证的 VM 方法，跳过 CLR 准备检查":"CLR 检查：未请求（默认关闭，使用 --validate-clr 开启）");
            result.Stages.Add(new StageResult { Name = "Validation", Status = "success", Detail = "Output metadata reloaded. Full business/UI equivalence requires additional checks." });
            bool changed = result.Stages.Any(s => s.Changes > 0);
            bool pending = result.Stages.Any(s => s.Status is "failed" or "skipped" or "partial") || result.After.VirtualizedMethods.Count > 0 ||
                result.After.StringLiterals == 0 && result.Before.StringInt32Calls > 0;
            result.Status = changed && !pending ? "complete" : "partial";
            return result.Status == "complete" ? 0 : 2;
        }
        catch (Exception ex) { ProgressEvents.Send(ProgressEvents.CurrentStage,"error","恢复后端异常："+ex.Message);result.Stages.Add(new StageResult { Name = "Worker", Status = "failed", Detail = ex.ToString() }); return 1; }
        finally { WriteResult(result,dir); }
    }

    private static void RememberOutput(SampleResult result,string output,string directory)
    {
        result.Output=output;
        result.Status="partial";
        WriteResult(result,directory);
    }

    internal static void WriteResult(SampleResult result,string directory)
    {
        string report=Path.Combine(directory,"result.json"),pending=report+".pending";
        try
        {
            File.WriteAllText(pending,JsonConvert.SerializeObject(result,Formatting.Indented));
            // File scanners can briefly hold the previous checkpoint without
            // delete sharing on Windows. Retain the pending snapshot and retry.
            for(int attempt=0;;attempt++)
            {
                try {if(File.Exists(report))File.Replace(pending,report,null);else File.Move(pending,report);break;}
                catch(IOException ex) when(attempt<4 && (ex.HResult&0xffff) is 32 or 33 or 1175)
                {System.Threading.Thread.Sleep(150<<attempt);}
            }
        }
        finally { if(File.Exists(pending))File.Delete(pending); }
    }
}
