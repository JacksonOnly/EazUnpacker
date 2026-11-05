using System.Reflection;
using EazFixer;

namespace Unpacker;

internal static class DependencyPublisher
{
    internal static int Publish(IEnumerable<EmbeddedAssemblyExport> exports,string run,string input,string output)
    {
        string root=Path.GetFullPath(run).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
        var files=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach(var export in exports)
        {
            string source=Path.GetFullPath(export.File);
            if(!source.StartsWith(root,StringComparison.OrdinalIgnoreCase) || !File.Exists(source))
                throw new InvalidDataException("内嵌程序集缺少经过验证的导出文件。");
            var actual=AssemblyName.GetAssemblyName(source);
            if(!DependencyLoadScope.MatchesIdentity(new AssemblyName(export.Identity),actual,false) ||
                !string.Equals(Path.GetFileNameWithoutExtension(source),actual.Name,StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("内嵌程序集的导出身份或文件名不匹配。");
            string target=Path.Combine(Path.GetDirectoryName(output)!,Path.GetFileName(source));
            if(target.Equals(output,StringComparison.OrdinalIgnoreCase) || target.Equals(input,StringComparison.OrdinalIgnoreCase))
                throw new IOException("内嵌程序集与主程序路径冲突，未发布主程序。");
            if(files.TryGetValue(target,out string prior) && !SameBytes(prior,source))
                throw new IOException("多个内嵌程序集使用同一文件名，未发布主程序。");
            files[target]=source;
        }

        foreach(var pair in files)
            if(Directory.Exists(pair.Key) || File.Exists(pair.Key) && !SameBytes(pair.Key,pair.Value))
                throw new IOException("输出目录已有同名但内容不同的依赖文件，未发布主程序。");
        foreach(var pair in files)
        {
            if(File.Exists(pair.Key))continue;
            string temp=Path.Combine(Path.GetDirectoryName(pair.Key)!,".dependency-"+Guid.NewGuid().ToString("N")+".tmp");
            try
            {
                File.Copy(pair.Value,temp);
                try {File.Move(temp,pair.Key);}
                catch(IOException) when(File.Exists(pair.Key) && SameBytes(pair.Key,pair.Value)){}
            }
            finally {if(File.Exists(temp))File.Delete(temp);}
        }
        return files.Count;
    }

    private static bool SameBytes(string a,string b)
    {
        using var left=File.OpenRead(a);
        using var right=File.OpenRead(b);
        if(left.Length!=right.Length)return false;
        using var sha=System.Security.Cryptography.SHA256.Create();
        return Enumerable.SequenceEqual(sha.ComputeHash(left),sha.ComputeHash(right));
    }
}
