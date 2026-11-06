using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Unpacker;

internal static class Program
{
    private const string Usage="用法：Unpacker unpack <输入EXE/DLL> <输出文件> [--export-source] [--validate-clr]\n      Unpacker analyzer <输入EXE/DLL>\n      Unpacker strings <输入EXE/DLL> [清单.strings.json]\n      Unpacker strings apply <输入EXE/DLL> [清单.strings.json] [输出EXE/DLL|--in-place]\n      Unpacker resources [export] <输入EXE/DLL/resources> [清单.resources.json]\n      Unpacker resources apply <输入EXE/DLL/resources> [清单.resources.json] [输出文件|--in-place]\n默认不检查 CLR；--validate-clr 显式开启；--export-source 导出并重构建 C# 工程。";

    [STAThread]
    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        if (args.Length > 0 && args[0] == "resources") return ResourceFileCommand.Run(args);
        if (args.Length > 0 && args[0] == "strings") return StringResourceCommand.Run(args);
        if (args.Length > 0 && args[0] == "apply")
            return StringResourceCommand.Run(new[] { "strings", "apply" }.Concat(args.Skip(1)).ToArray());
        CliProgress? progress=null;
        try
        {
            WorkCache.Initialize();
            if (args.Length == 2 && args[0] == "analyzer") return Analyzer.Run(args[1]);
            if (args.Length == 0 || args[0] != "unpack") throw new ArgumentException(Usage);
            bool exportSource=false,validateClr=false;
            var paths=new List<string>();
            foreach(string argument in args.Skip(1))
            {
                if(argument=="--export-source" && !exportSource)exportSource=true;
                else if(argument=="--validate-clr" && !validateClr)validateClr=true;
                else if(argument.StartsWith("--",StringComparison.Ordinal))throw new ArgumentException("未知或重复的选项："+argument+"\n"+Usage);
                else paths.Add(argument);
            }
            if(paths.Count!=2)throw new ArgumentException(Usage);
            string input = Path.GetFullPath(paths[0]), output = Path.GetFullPath(paths[1]);
            if (!File.Exists(input)) throw new FileNotFoundException("输入文件不存在。",input);
            if (Directory.Exists(output) || !new[]{".exe",".dll"}.Contains(Path.GetExtension(output),StringComparer.OrdinalIgnoreCase)) throw new ArgumentException("输出必须是 EXE/DLL 文件路径。");
            if (string.Equals(input,output,StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("输出不能覆盖输入原件。");
            Directory.CreateDirectory(Path.GetDirectoryName(output)!);
            string worker=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","Unpacker.Worker.exe");
            if(!File.Exists(worker))throw new FileNotFoundException("工作后端缺失，请重新构建完整项目。",worker);
            string root=WorkCache.ForOutput(output);
            string run=Path.Combine(root,"run-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8));
            Directory.CreateDirectory(run);
            progress=new CliProgress(run);
            progress.Report(1,"start","开始恢复："+input);
            progress.Report(1,"info","目标文件："+output);
            progress.Report(1,"info","实时日志/诊断目录："+run);
            int code=ProcessRunner.Run(worker,new[]{"pipeline",input,run,"False","False","600",validateClr.ToString()},Path.Combine(run,"worker.log"),600,progress.Report);
            var result=File.Exists(Path.Combine(run,"result.json")) ? JsonConvert.DeserializeObject<SampleResult>(File.ReadAllText(Path.Combine(run,"result.json")))!
                : new SampleResult{Input=input,Status="failed",Stages=new(){new StageResult{Name="Worker",Status="failed",Detail="Worker exit "+code}}};
            result.DiagnosticsDirectory=run;
            if(string.IsNullOrEmpty(result.Output) || !File.Exists(result.Output))
            {
                File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
                string failures=string.Join(", ",result.Stages.Where(s=>s.Status is "failed" or "skipped").Select(s=>s.Name));
                progress.Failure((code==124?"恢复超时":"恢复未完成："+result.Status)+(failures.Length>0?"；未通过阶段："+failures:"")+"；结果与失败阶段："+Path.Combine(run,"result.json")+"；后端日志："+Path.Combine(run,"worker.log"));
                Console.Error.WriteLine("恢复未完成："+result.Status+"；诊断保存在 Unpacker 工作缓存。");
                return code==124 || result.Status=="failed" ? 1 : 2;
            }
            bool recoveryComplete=code==0 && result.Status=="complete";
            if(!recoveryComplete)
            {
                result.Stages.Add(new StageResult{Name="RecoveryPipeline",Status="partial",
                    Detail="Backend exit "+code+"; recovery status "+result.Status+". Publishing the available recovered assembly."});
                progress.Report(5,"warning","恢复阶段尚未全部完成（退出码 "+code+"）；仍将输出已生成的 unpacked 程序");
            }
            // Publish available recovered IL even when a later recovery stage fails.
            // Configuration and optional source work must not withhold the file.
            string recovered=result.Output;
            result.After??=AssemblyInspector.Inspect(recovered);
            int dependencies=DependencyPublisher.Publish(result.EmbeddedAssemblies,run,input,output);
            if(dependencies>0)
            {
                result.Stages.Add(new StageResult{Name="EmbeddedAssemblyPublish",Status="success",Changes=dependencies,
                    Detail="Published exact embedded assembly images alongside the output before publishing the main PE."});
                progress.Report(5,"success","已就位内嵌程序集："+dependencies+" 个");
            }
            progress.Report(5,"info",exportSource?"发布恢复文件（源码重建将单独检查）":"发布恢复文件");
            if(result.After.ModernRuntime && Path.GetExtension(output).Equals(".exe",StringComparison.OrdinalIgnoreCase))
            {
                string packed=Path.Combine(run,"unpacked.exe");
                BundleExtractor.Repack(input,recovered,Path.Combine(run,"bundle"),packed);
                Publish(packed,output);
            }
            else Publish(recovered,output);
            result.Output=output;result.Status="partial";
            result.Stages.Add(new StageResult{Name="Publish",Status="success",Detail=output});
            File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
            progress.Report(5,"success","已输出 unpacked 程序："+output);
            if(!result.After!.ModernRuntime && Path.GetExtension(output).Equals(".exe",StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                string configuration=Path.Combine(run,"published-runtime.config");
                if(File.Exists(output+".config"))File.Copy(output+".config",Path.Combine(run,"previous-output.config"));
                RuntimeCompatibility.WriteConfiguration(input+".config",output+".config",configuration);
                Publish(configuration,output+".config");
                result.RuntimeConfig=output+".config";
                result.Stages.Add(new StageResult{Name="RuntimeSignatureCompatibility",Status="success",Changes=1,
                    Detail="Preserved assembly public key/token; enabled per-EXE CLR full-trust bypass in "+result.RuntimeConfig+". No machine-wide changes. External enforced host policy and native self-checks are not re-signing."});
                progress.Report(5,"info","保留原始程序集身份；运行配置已输出："+result.RuntimeConfig);
                }
                catch(Exception ex)
                {
                    result.Stages.Add(new StageResult{Name="RuntimeSignatureCompatibility",Status="failed",Detail=ex.ToString()});
                    progress.Report(5,"warning","运行配置生成失败；unpacked 程序已保留："+output+"；"+ex.Message);
                }
            }
            else if(!result.After.ModernRuntime)
            {
                progress.Report(5,"warning","DLL 的强名称验证由宿主控制；没有原始私钥时无法重新签出原签名。请在受信任宿主的 EXE.config 配置兼容策略。");
            }
            File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
            if(exportSource)
            {
                string stringIndex=Path.Combine(run,"string-index");
                progress.Report(6,"start","建立带模块/方法/资源来源的字符串搜索索引（不替换运行依赖）");
                int indexCode=ProcessRunner.Run(worker,new[]{"string-index",recovered,input,stringIndex},Path.Combine(run,"string-index.log"),240,progress.Report);
                result.StringIndex=Path.Combine(stringIndex,"strings.txt");
                result.Stages.Add(new StageResult{Name="StringSearchIndex",Status=indexCode==0?"success":"partial",Detail="Search-only provenance index exit "+indexCode+"; "+Path.Combine(stringIndex,"index.json")});
                File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
                string source=Path.Combine(run,"source");
                progress.Report(6,"start","导出完整 C# 工程；日志："+Path.Combine(run,"source.log"));
                int sourceCode=ProcessRunner.Run(worker,new[]{"source",recovered,source,Path.Combine(run,"source-build.json"),input},Path.Combine(run,"source.log"),1200,progress.Report);
                result.SourceProject=Directory.Exists(source)?Directory.GetFiles(source,"*.csproj").FirstOrDefault()??"":"";
                result.Stages.Add(new StageResult{Name="SourceBuild",Status=sourceCode==0?"success":"failed",Detail="C# project compilation exit "+sourceCode+"; see "+Path.Combine(run,"source.log")});
                if(sourceCode!=0)
                {
                    result.Status="partial";File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
                    progress.Warning("C# 源码导出/构建失败（退出码 "+sourceCode+"）；unpacked 程序已保留："+output+"；查看 "+Path.Combine(run,"source-build.json")+" / "+Path.Combine(run,"source.log"));
                    Console.Error.WriteLine("部分完成："+output+"；C# 源码未通过重新构建，诊断保存在 Unpacker 工作缓存。");return 2;
                }
                var build=JObject.Parse(File.ReadAllText(Path.Combine(run,"source-build.json")));
                result.RebuiltAssembly=(string?)build["RebuiltAssembly"]??"";
                string vmReport=Path.Combine(run,"vm-methods.json");
                if(validateClr && File.Exists(vmReport) && ClrValidator.ReadTargets(vmReport).Count>0)
                {
                    int rebuiltCode;
                    string detail;
                    try
                    {
                        string mapped=Path.Combine(run,"rebuilt-vm-methods.json");
                        progress.Report(7,"start","映射重编译后的 VM/异步方法并进行 CLR 检查");
                        int mappedCount=RebuiltValidation.MapMethods(recovered,result.RebuiltAssembly,vmReport,mapped);
                        string rebuiltReport=Path.Combine(run,"rebuilt-clr-validation.json");
                        string validator=result.After.ModernRuntime?Path.Combine(Path.GetDirectoryName(worker)!,"modern","Unpacker.ModernWorker.exe"):worker;
                        if(!File.Exists(validator))throw new FileNotFoundException("CLR validation backend missing.",validator);
                        rebuiltCode=ProcessRunner.Run(validator,new[]{"--validate-worker",result.RebuiltAssembly,mapped,rebuiltReport,"7",input},Path.Combine(run,"rebuilt-clr-validation.log"),150,progress.Report);
                        if(rebuiltCode==0)
                        {
                            if(!File.Exists(rebuiltReport))throw new InvalidDataException("Rebuilt CLR worker exited without a validation report.");
                            if(!ClrValidator.HasCompleteReport(rebuiltReport,mappedCount))
                                throw new InvalidDataException("Rebuilt CLR validation counts do not match recovered VM methods.");
                        }
                        detail="Mapped "+mappedCount+" recovered VM methods by signature; isolated rebuilt CLR compilation exit "+rebuiltCode+".";
                        progress.Report(7,rebuiltCode==0?"success":"error","重编译 CLR 检查退出码 "+rebuiltCode+"；映射 "+mappedCount+" 个方法");
                    }
                    catch(Exception ex) {rebuiltCode=1;detail=ex.ToString();}
                    result.Stages.Add(new StageResult{Name="RebuiltCLRValidation",Status=rebuiltCode==0?"success":"failed",Detail=detail});
                    if(rebuiltCode!=0)
                    {
                        result.Status="partial";File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
                        progress.Report(7,"warning","重编译 CLR 检查失败；unpacked 程序已保留："+output+"。查看 "+Path.Combine(run,"rebuilt-clr-validation.log"));
                        Console.Error.WriteLine("C# 重编译产物未通过 CLR 检查；恢复文件已输出："+output);return 2;
                    }
                }
            }
            bool complete=recoveryComplete && !result.Stages.Any(s=>s.Status is "failed" or "skipped" or "partial");
            result.Output=output;result.Status=complete?"complete":"partial";
            foreach(string summary in RecoveryStatistics.Save(result,run))progress.Report(8,"info",summary);
            File.WriteAllText(Path.Combine(root,"latest.json"),JsonConvert.SerializeObject(result,Formatting.Indented));
            progress.Report(8,complete?"success":"warning",(complete?"输出：":"部分完成，已输出：")+output);
            if(exportSource)
            {
                progress.Report(8,"info","源码工程："+result.SourceProject);
                progress.Report(8,"info","字符串搜索索引："+result.StringIndex);
            }
            progress.Report(8,"info","完整阶段日志："+Path.Combine(run,"progress.log"));
            Console.WriteLine((complete?"完成：":"部分完成：")+output);
            return complete?0:2;
        }
        catch(Exception ex){progress?.Failure(ex.Message);Console.Error.WriteLine(ex.Message);return 1;}
        finally{progress?.Dispose();}
    }

    private static void Publish(string candidate,string output)
    {
        string pending=output+".pending-"+Guid.NewGuid().ToString("N");
        try
        {
            File.Copy(candidate,pending);
            string previousPdb=Path.ChangeExtension(output,".pdb");
            if(File.Exists(Path.ChangeExtension(candidate,".pdb"))&&File.Exists(output)&&File.Exists(previousPdb))
            {
                // Retire this output's matching legacy alias before replacing
                // the old DLL/PDB pair with different deterministic symbols.
                try {PortablePdbCompatibility.PublishSidecar(output,previousPdb);}
                catch(BadImageFormatException){} // An arbitrary prior output may not be a managed PE.
            }
            for(int attempt=0;;attempt++)
            {
                try {if(File.Exists(output))File.Replace(pending,output,null);else File.Move(pending,output);break;}
                catch(IOException ex) when(attempt<4 && (ex.HResult&0xffff) is 32 or 33 or 1175)
                {System.Threading.Thread.Sleep(150<<attempt);}
            }
            string pdb=Path.ChangeExtension(candidate,".pdb");
            if(Path.GetExtension(candidate).ToLowerInvariant() is ".dll" or ".exe" && File.Exists(pdb))
            {
                string publishedPdb=Path.ChangeExtension(output,".pdb");
                File.Copy(pdb,publishedPdb,true);
                PortablePdbCompatibility.PublishSidecar(output,publishedPdb);
            }
        }
        finally {if(File.Exists(pending))File.Delete(pending);}
    }
}
