using System;
using System.Collections.Generic;
using System.IO;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.Linq;
using EazFixer.Processors;

namespace EazFixer
{
    /// <summary>A stage outcome with an explicit applicability/success distinction.</summary>
    public sealed class FixerStageResult
    {
        public string Name { get; set; }
        public string Status { get; set; }
        public string Detail { get; set; }
        public int Changes { get; set; }
        public List<EmbeddedAssemblyExport> Exports { get; set; } = new List<EmbeddedAssemblyExport>();
    }

    public sealed class EmbeddedAssemblyExport
    {
        public string File { get; set; }
        public string Identity { get; set; }
        public string Resource { get; set; }
        public string Format { get; set; }
    }

    /// <summary>Runs the retained reference processors without deleting VM dependencies.</summary>
    public static class FixerBridge
    {
        /// <summary>Detects the supported protected-resource resolver without executing it.</summary>
        public static bool HasResourceResolver(ModuleDef module) => ResourceResolver.IsDetected(module);

        /// <summary>Recovers resources only, retaining direct manifest entries as authoritative.</summary>
        public static void RecoverResources(string input, string output)
        {
            Flags.InFile = Path.GetFullPath(input);
            Flags.OutFile = Path.GetFullPath(output);
            Flags.KeepTypes = Flags.VirtFix = Flags.PreserveAll = true;
            var processor = new ResourceResolver(true);
            var ctx = new EazContext(Flags.InFile, new ProcessorBase[] { processor });
            try
            {
                StacktracePatcher.Patch();
                processor.Initialize(ctx);
                if (!processor.Initialized) throw new InvalidDataException(processor.DetailMessage);
                processor.Process();
                if (!processor.Processed || processor.WarningCount != 0) throw new InvalidDataException(processor.DetailMessage);
                if (processor.ResourceAssemblies.Count == 0) throw new InvalidDataException("No protected resource payload was recovered.");
                // The interchange image contains no target code and is never
                // executed. The caller merges only missing resource identities.
                using (var payload = new ModuleDefUser("RecoveredResources.dll"))
                {
                    new AssemblyDefUser("RecoveredResources", new Version(1, 0)).Modules.Add(payload);
                    long total = 0; int count = 0;
                    foreach (var resource in ctx.Module.Resources.OfType<EmbeddedResource>().OrderBy(r => r.Name.String, StringComparer.Ordinal))
                    {
                        var reader = resource.CreateReader(); total += reader.Length;
                        if (++count > 250000 || reader.Length > 256 * 1024 * 1024 || total > 512 * 1024 * 1024)
                            throw new InvalidDataException("Recovered resource limits exceeded.");
                        payload.Resources.Add(new EmbeddedResource(resource.Name, reader.ToArray(), resource.Attributes));
                    }
                    payload.Write(Flags.OutFile);
                }
            }
            finally { StacktracePatcher.UnPatch(); ctx.Module.Dispose(); }
        }

        public static List<FixerStageResult> Process(string input, string output, bool stringsOnly = false, Action<string,string,int> progress = null, bool runControlFlow = true)
        {
            Flags.InFile = Path.GetFullPath(input);
            Flags.OutFile = Path.GetFullPath(output);
            Flags.KeepTypes = Flags.VirtFix = Flags.PreserveAll = true;
            var processors = stringsOnly ? new ProcessorBase[] {new StringFixer()}
                : new ProcessorBase[] {new StringFixer(),new ResourceResolver(),new Processors.AssemblyResolver()};
            var results = new List<FixerStageResult>();
            var ctx = new EazContext(Flags.InFile, processors);
            try
            {
                results.Add(new FixerStageResult { Name = "DecoderRuntime", Status = "success", Changes = 0,
                    Detail = "Isolated decoder runtime: " + ctx.RuntimePath + "; <Module> initializer suppressed only in runtime copy: " + ctx.RuntimeInitializerSuppressed + ". Output initializer retained." });
                StacktracePatcher.Patch();
                foreach (var proc in processors){progress?.Invoke(proc.GetType().Name+" 初始化","start",0);proc.Initialize(ctx);}
                foreach (var proc in processors)
                {
                    int resources = ctx.Module.Resources.Count;
                    progress?.Invoke(proc.GetType().Name,"start",0);
                    if (proc.Initialized) proc.Process();
                    if (proc.Processed) proc.Cleanup();
                    int changes = proc is StringFixer strings ? strings.RecoveredCount : proc is Processors.AssemblyResolver assemblies
                        ? assemblies.ExtractedCount : ctx.Module.Resources.Count-resources;
                    results.Add(new FixerStageResult {
                        Name = proc.GetType().Name,
                        Status = proc.Processed ? proc.WarningCount > 0 ? "partial" : "success" : proc.NotDetected ? "not-detected" : "failed",
                        Detail = proc.DetailMessage, Changes = changes,
                        Exports = proc is Processors.AssemblyResolver resolver ? resolver.Exports : new List<EmbeddedAssemblyExport>() });
                    progress?.Invoke(proc.GetType().Name,results[results.Count-1].Status,changes);
                }
                if(runControlFlow)
                {
                    progress?.Invoke("ControlFlow","start",0);
                    int flowChanges=ControlFlowPass.Process(ctx.Module);
                    progress?.Invoke("ControlFlow","success",flowChanges);
                    results.Add(new FixerStageResult{Name="ControlFlow",Status="success",Detail="Constant branches folded; protected regions preserved.",Changes=flowChanges});
                }
                progress?.Invoke("写入恢复程序集","start",0);
                PrepareForWrite(ctx.Module);
                ctx.Module.Write(Flags.OutFile, new ModuleWriterOptions(ctx.Module) { MetadataOptions = { Flags = MetadataFlags.PreserveAll } });
                return results;
            }
            finally
            {
                StacktracePatcher.UnPatch();
                ctx.Module.Dispose();
            }
        }

        internal static void PrepareForWrite(ModuleDef module)
        {
            // A non-adjacent argument replacement inserts pop/ldstr even when the
            // control-flow pass is disabled. Recompute branch widths for that path
            // too; short branches loaded from disk may no longer span the body.
            foreach (var type in module.GetTypes())
                foreach (var method in type.Methods)
                    if (method.HasBody)
                    {
                        method.Body.SimplifyBranches();
                        method.Body.OptimizeBranches();
                    }
        }
    }
}
