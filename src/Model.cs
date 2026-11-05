namespace Unpacker;

internal sealed class StageResult
{
    public string Name { get; set; } = "";
    public string Status { get; set; } = "";
    public string Detail { get; set; } = "";
    public int Changes { get; set; }
}

internal sealed class SampleResult
{
    public string Input { get; set; } = "";
    public string Output { get; set; } = "";
    public string RuntimeConfig { get; set; } = "";
    public string StringIndex { get; set; } = "";
    public string SourceProject { get; set; } = "";
    public string RebuiltAssembly { get; set; } = "";
    public string DiagnosticsDirectory { get; set; } = "";
    public string Status { get; set; } = "failed";
    public bool ClrValidationRequested {get;set;}
    public string Sha256 { get; set; } = "";
    public List<StageResult> Stages { get; set; } = new();
    public List<EazFixer.EmbeddedAssemblyExport> EmbeddedAssemblies { get; set; } = new();
    public AssemblyInfo? Before { get; set; }
    public AssemblyInfo? After { get; set; }
}

internal sealed class AssemblyInfo
{
    public string Runtime { get; set; } = "";
    public bool ModernRuntime { get; set; }
    public int Types { get; set; }
    public int Methods { get; set; }
    public int Resources { get; set; }
    public int StringLiterals { get; set; }
    public int StringInt32Calls { get; set; }
    public List<uint> StringInt32Candidates { get; set; } = new();
    public List<uint> VirtualizedMethods { get; set; } = new();
}
