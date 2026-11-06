using dnlib.DotNet;
using EazFixer;

namespace Unpacker;

internal static class ResourceRecovery
{
    internal static byte[] Prepare(byte[] image,string original)
    {
        using var module=ModuleDefMD.Load(image);
        bool globalResolver=module.GlobalType?.FindStaticConstructor()?.Body?.Instructions.Any(i=>
            i.Operand is IMethod m && m.DeclaringType.FullName=="System.AppDomain" && m.Name=="add_ResourceResolve")==true;
        if(!globalResolver && !FixerBridge.HasResourceResolver(module))return image;
        bool modern=AssemblyInspector.Inspect(original).ModernRuntime;
        string worker=modern?Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","modern","Unpacker.ModernWorker.exe"):
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"worker","Unpacker.Worker.exe");
        if(!File.Exists(worker))throw ResourceFileEditor.Invalid("资源恢复后端缺失，请保留完整构建目录。");
        Console.WriteLine("[resources] 正在自动恢复保护层资源。");
        WorkCache.Initialize();string directory=WorkCache.CreateTemporary("resources");bool success=false;
        try
        {
            string input=Path.Combine(directory,"input"+Path.GetExtension(original)),output=Path.Combine(directory,"prepared"+Path.GetExtension(original));
            File.WriteAllBytes(input,image);
            int code=ProcessRunner.Run(worker,new[]{"--resources-worker",input,output,original},Path.Combine(directory,"recovery.log"),180);
            if(code!=0 || !File.Exists(output))throw ResourceFileEditor.Invalid("资源恢复未完成；诊断保存在程序 temp 内，未输出密文清单或部分结果。");
            var info=new FileInfo(output);
            if(info.Length>ResourceFileEditor.MaxFileBytes)throw ResourceFileEditor.Invalid("恢复后的程序集超过大小限制。");
            byte[] prepared=File.ReadAllBytes(output);
            using var check=ModuleDefMD.Load(prepared);
            if(check.Assembly?.FullName!=module.Assembly?.FullName || check.Mvid!=module.Mvid)
                throw ResourceFileEditor.Invalid("资源恢复后的程序集身份校验失败。");
            success=true;return prepared;
        }
        finally
        {
            if(success)
                try {Directory.Delete(directory,true);}
                catch(IOException) { /* A transient file lock may leave local diagnostics in temp. */ }
                catch(UnauthorizedAccessException) { /* Do not discard a verified result for cleanup failure. */ }
        }
    }
}
