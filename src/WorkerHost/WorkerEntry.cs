using EazFixer;
using EazyDevirt;
using Newtonsoft.Json;

namespace Unpacker;

internal static class WorkerEntry
{
    [STAThread]
    private static void Main(string[] args)
    {
        try { Environment.Exit(WorkerDesktop.Run(args, Run)); }
        catch(Exception ex) { Console.Error.WriteLine(ex); Environment.Exit(1); }
    }

    private static int Run(string[] args)
    {
        Console.OutputEncoding=System.Text.Encoding.UTF8;
        try
        {
            WorkCache.Initialize();
            switch(args[0])
            {
                case "pipeline": return RecoveryPipeline.Run(args);
                case "--validate-worker": return ClrValidator.Run(args[1],args[2],args[3],args.Length>4?int.Parse(args[4]):5,args.Length>5?args[5]:null);
                case "--vm-worker":
                {
                    ProgressEvents.Send(3,"info","加载 VM 还原后端");
                    using var vmDependencies=new DependencyLoadScope(args.Length>4?args[4]:args[1],args[1]);
                    var vmProgress=new ProgressEvents.Counter(3);
                    File.WriteAllText(args[3],VmBridge.Process(args[1],args[2],(message,current,total)=>vmProgress.Report(message switch {
                        "ResourceParsing"=>"VM 资源解析", "OpCodeMapping"=>"VM 操作码映射", "MethodDiscovery"=>"VM 方法发现", "MethodDevirtualizer"=>"读取 VM 方法体、校准头部布局", _=>message},current,total),DependencyLoadScope.DependencyDirectories(args[1],args.Length>4?args[4]:args[1])).ToString());return 0;
                }
                case "--index-strings":
                case "--strings-worker":
                    ProgressEvents.Send(3,"info","加载复处理后端");
                    using(var dependencies=new DependencyLoadScope(args.Length>4?args[4]:args[1],args[1]))
                    {
                        var stages=FixerBridge.Process(args[1],args[2],true,(name,state,count)=>ProgressEvents.Backend(3,name,state,count,"复处理："),args[0]!="--index-strings");
                        File.WriteAllText(args[3],JsonConvert.SerializeObject(stages));
                        return stages.Any(s=>s.Status=="failed")?2:0;
                    }
                case "source": ProgressEvents.Send(6,"info","加载待反编译程序集");return SourceCompiler.Run(args[1],args[2],args[3],args[4]);
                case "string-index": return StringSearchIndex.Run(args[1],args[2],args[3]);
                case "--names-worker": NameRecoveryPass.Process(args[1],args[2],args[3]);return 0;
                case "--map-worker": RebuiltValidation.MapMethods(args[1],args[2],args[3],args[4]);return 0;
                case "--flow-worker": ControlFlowCleanupPass.Process(args[1],args[2],args[3]);return 0;
                case "--publish-symbols": PortablePdbCompatibility.PublishSidecar(args[1],args[2]);return 0;
                case "--repair-symbols": PortablePdbCompatibility.Normalize(args[1],args[2]);PortablePdbCompatibility.PublishSidecar(args[1],args[2]);return 0;
                default: throw new ArgumentException("Unknown worker operation.");
            }
        }
        catch(Exception ex){ProgressEvents.Send(ProgressEvents.CurrentStage,"error",ex.Message);Console.Error.WriteLine(ex);return 1;}
    }
}
