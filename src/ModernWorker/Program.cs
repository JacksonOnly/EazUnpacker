using EazFixer;
using EazyDevirt;
using Newtonsoft.Json;

namespace Unpacker.ModernWorker;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        Console.OutputEncoding=new System.Text.UTF8Encoding(false);
        // Harmony's net8 build also runs on newer hosts. Select its JSON patch
        // metadata path before the first patch; BinaryFormatter is removed on 9+.
        AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization",false);
        try {
            WorkCache.Initialize();
            if(args.Length==4 && args[0]=="--resources-worker")
                return WorkerDesktop.Run(args,a=>ResourceRecoveryWorker.Run(a[1],a[2],a[3]));
            if(args.Length>=4 && args[0]=="--vm-worker")
            {
                using var vmDependencies=new DependencyLoadScope(args.Length>4?args[4]:args[1],args[1]);
                var progress=new ProgressEvents.Counter(3);
                File.WriteAllText(args[3],VmBridge.Process(args[1],args[2],(message,current,total)=>progress.Report(message,current,total),
                    DependencyLoadScope.DependencyDirectories(args[1],args.Length>4?args[4]:args[1])).ToString());
                return 0;
            }
            if(args.Length>=4 && args[0]=="--validate-worker")
                return ClrValidator.Run(args[1],args[2],args[3],args.Length>4?int.Parse(args[4]):5,args.Length>5?args[5]:null);
            if(args.Length>=4 && args[0]=="--strings-worker")
            {
                using var dependencies=new DependencyLoadScope(args.Length>4?args[4]:args[1],args[1]);
                var post=FixerBridge.Process(args[1],args[2],true);
                File.WriteAllText(args[3],JsonConvert.SerializeObject(post,Formatting.Indented));
                return post.Any(s=>s.Status is "failed" or "partial")?2:0;
            }
            if(args.Length!=3) return 1;
            using var scope=new DependencyLoadScope(args[0]);
            var stages=FixerBridge.Process(args[0],args[1]);
            File.WriteAllText(args[2],JsonConvert.SerializeObject(stages,Formatting.Indented));
            return stages.Any(s=>s.Status=="failed")?2:0;
        }
        catch(Exception ex) {Console.Error.WriteLine(ex);return 1;}
    }
}
