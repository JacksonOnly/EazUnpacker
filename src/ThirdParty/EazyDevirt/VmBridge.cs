using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Code.Cil;
using EazyDevirt.Devirtualization;
using EazyDevirt.Devirtualization.Options;

namespace EazyDevirt;

/// <summary>Runs the devirtualizer in a per-input worker, preserving unrecovered methods.</summary>
public static class VmBridge
{
    public static int Process(string input, string output,Action<string,int,int>? progress=null,string[]? dependencyDirectories=null)
    {
        var elapsed=System.Diagnostics.Stopwatch.StartNew();
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
        var options = new DevirtualizationOptions {
            Assembly = new FileInfo(input), OutputPath = new DirectoryInfo(Path.GetDirectoryName(output)!),
            DependencyDirectories = dependencyDirectories ?? Array.Empty<string>(),
            Verbosity = Environment.GetEnvironmentVariable("UNPACKER_VM_DEBUG") == "1" ? 3 : Environment.GetEnvironmentVariable("UNPACKER_VM_VERBOSE")=="1"?1:0,
            PreserveAll = true, KeepTypes = true, NoVerify = false,
            SaveAnyway = true, OnlySaveDevirted = true, RequireDepsForGenericMethods = true
        };
        var ctx = new DevirtualizationContext(options);
        using var logging=ctx.Console.Capture(Path.Combine(options.OutputPath.FullName,"vm-detail.log"),options.Verbosity);
        File.WriteAllText(Path.Combine(options.OutputPath.FullName,"vm-keys.jsonl"),"");
        ctx.Progress=progress;
        DevirtualizationContext.Instance = ctx;
        int assemblyMethods=ctx.Module.GetAllTypes().Sum(t=>t.Methods.Count);
        ctx.Console.Summary("[VM] 开始恢复："+Path.GetFileName(input)+"；程序集方法总数 "+assemblyMethods.ToString("N0")+"。");
        bool completed = new Devirtualizer(ctx).Run();
        int restored = ctx.VMMethods?.Count(m=>m.SuccessfullyDevirtualized) ?? 0;
        var adapters=new Dictionary<string,uint>(StringComparer.Ordinal);
        if(restored>0)
        {
            ctx.Module.Write(output, new ManagedPEImageBuilder(new DotNetDirectoryFactory(MetadataBuilderFlags.PreserveAll) {
                MethodBodySerializer = new CilMethodBodySerializer { ComputeMaxStackOnBuildOverride = false }
            }));
            if(ctx.VMMethods!.Any(m=>m.SuccessfullyDevirtualized && (m.RecoveredAdapter!=null || m.AccessBridges.Count!=0)))
            {
                // Newly added definitions receive their final row IDs during
                // serialization. Validate the actual published tokens, not RID 0
                // from an unsaved in-memory definition or just its host method.
                var saved=AsmResolver.DotNet.ModuleDefinition.FromFile(output);
                adapters=saved.GetAllTypes().SelectMany(t=>t.Methods).GroupBy(m=>m.FullName)
                    .Where(g=>g.Count()==1).ToDictionary(g=>g.Key,g=>g.Single().MetadataToken.ToUInt32(),StringComparer.Ordinal);
            }
        }
        File.WriteAllText(Path.Combine(Path.GetDirectoryName(output)!, "vm-methods.json"),
            Newtonsoft.Json.JsonConvert.SerializeObject(ctx.VMMethods?.Select(m => new {
                Token = "0x" + m.Parent.MetadataToken.ToUInt32().ToString("X8"), Method = m.Parent.FullName,
                Restored = m.SuccessfullyDevirtualized, m.EncryptedRegions, m.Failure,
                m.Inlined, RecoveredAdapter = m.RecoveredAdapter?.FullName,
                RecoveredAdapterToken=m.RecoveredAdapter!=null && adapters.TryGetValue(m.RecoveredAdapter.FullName,out uint token)?"0x"+token.ToString("X8"):null,
                AccessBridgeTokens=m.AccessBridges.Select(b=>"0x"+adapters[b.FullName].ToString("X8")).ToArray(),
                Instructions = m.Instructions.Count, ExceptionHandlers = m.ExceptionHandlers.Count
            }), Newtonsoft.Json.Formatting.Indented));
        var methods=ctx.VMMethods??new List<EazyDevirt.Core.Architecture.VMMethod>();
        var hosts=methods.GroupBy(m=>m.Parent).ToArray();
        int full=hosts.Count(g=>g.All(m=>m.SuccessfullyDevirtualized));
        int partial=hosts.Count(g=>g.Any(m=>m.SuccessfullyDevirtualized)&&g.Any(m=>!m.SuccessfullyDevirtualized));
        int regions=methods.Where(m=>m.SuccessfullyDevirtualized).Sum(m=>m.EncryptedRegions);
        var summary=new {AssemblyMethods=assemblyMethods,DetectedMethods=hosts.Length,RestoredMethods=full,PartiallyRestoredMethods=partial,
            DetectedVmCallSites=methods.Count,RestoredVmCallSites=restored,RemainingVmCallSites=methods.Count-restored,
            RecoveredInlineAdapters=methods.Count(m=>m.SuccessfullyDevirtualized&&m.Inlined),DecryptedRegions=regions,VerifiedKeys=ctx.VerifiedKeys.Count,
            PipelineCompleted=completed,AllDetectedCallSitesRestored=completed&&restored==methods.Count,ElapsedSeconds=Math.Round(elapsed.Elapsed.TotalSeconds,2)};
        File.WriteAllText(Path.Combine(options.OutputPath.FullName,"vm-summary.json"),Newtonsoft.Json.JsonConvert.SerializeObject(summary,Newtonsoft.Json.Formatting.Indented));
        File.WriteAllText(Path.Combine(options.OutputPath.FullName,"vm-keys.json"),Newtonsoft.Json.JsonConvert.SerializeObject(ctx.VerifiedKeys,Newtonsoft.Json.Formatting.Indented));
        void Report(string message){ctx.Console.Summary(message);progress?.Invoke(message,0,0);}
        Report($"[恢复统计] 方法：完整恢复 {full:N0} / 检测 {hosts.Length:N0}，部分恢复 {partial:N0}；VM 调用点：恢复 {restored:N0} / {methods.Count:N0}，剩余 {methods.Count-restored:N0}。");
        Report($"[恢复统计] 解密区域 {regions:N0}，已验证密钥 {ctx.VerifiedKeys.Count:N0}，内联适配器 {summary.RecoveredInlineAdapters:N0}；耗时 {elapsed.Elapsed.TotalSeconds:F1}s；结果：{(summary.AllDetectedCallSitesRestored?"全部检测调用点已恢复":"仍有未完成项")}。");
        foreach(var failure in methods.Where(m=>!m.SuccessfullyDevirtualized).Take(10))
        {
            string reason=(failure.Failure??"未恢复，详见诊断").Replace('\r',' ').Replace('\n',' ');
            if(reason.Length>220)reason=reason.Substring(0,220)+"…";
            Report($"[未恢复] 方法 0x{failure.Parent.MetadataToken.ToUInt32():X8}：{reason}");
        }
        if(methods.Count-restored>10)Report("[未恢复] 其余条目见 vm-methods.json；完整细节见 vm-detail.log。");
        return restored;
    }
}
