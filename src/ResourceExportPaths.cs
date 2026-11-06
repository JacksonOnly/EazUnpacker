using System.Globalization;
using System.Text;

namespace Unpacker;

// Resource identities are not trusted disk paths. Keep readable names/keys,
// escaping only filesystem-unsafe characters and disambiguating collisions.
internal static class ResourceExportPaths
{
    internal static Dictionary<string,string> Create(ResourceEditSession session,string directory)
    {
        int budget=Math.Min(180,Math.Max(16,240-directory.Length-1));
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var folders=new Dictionary<string,string>(StringComparer.Ordinal);
        var result=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(var asset in session.Assets.Where(a=>session.ContainerName(a.Id)==null))
            result.Add(asset.Id,Unique(Component(ExportName(asset),budget),"",budget,names));
        foreach(var asset in session.Assets.Where(a=>session.ContainerName(a.Id)!=null))
        {
            string parent=session.ContainerName(asset.Id)!;
            if(budget<40)
            {
                result.Add(asset.Id,Unique(Component(ExportName(asset),budget),"",budget,names));continue;
            }
            if(!folders.TryGetValue(parent,out var folder))
            {
                int folderBudget=Math.Max(16,budget/2);
                folder=Unique(Component(parent+".entries",folderBudget),"",folderBudget,names);
                folders.Add(parent,folder);
            }
            int remaining=budget-folder.Length-1;
            result.Add(asset.Id,Unique(Component(ExportName(asset),remaining),folder+"/",remaining,names));
        }
        return result;
    }

    private static string ExportName(ResourceFileEditor.Asset asset)=>asset.Format!="xaml"?asset.Name:
        asset.Name.EndsWith(".baml",StringComparison.OrdinalIgnoreCase)?asset.Name.Substring(0,asset.Name.Length-5)+".xaml":asset.Name+".xaml";

    private static string Component(string name,int maximum)
    {
        var text=new StringBuilder();
        for(int i=0;i<name.Length;i++)
        {
            char c=name[i];
            if(char.IsHighSurrogate(c) && i+1<name.Length && char.IsLowSurrogate(name[i+1]))
            {text.Append(c).Append(name[++i]);continue;}
            var category=char.GetUnicodeCategory(c);
            bool escape=c<32 || char.IsWhiteSpace(c) && c!=' ' || "<>:\"/\\|?*%".IndexOf(c)>=0 ||
                category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.Surrogate;
            if((c=='.'||c==' ') && i==name.Length-1)escape=true;
            if(escape)text.Append('%').Append(((int)c).ToString("X4",CultureInfo.InvariantCulture));else text.Append(c);
        }
        string value=text.Length==0?"resource":text.ToString();
        if(value is "." or "..")value=value.Replace(".","%002E");
        string stem=value.Split('.')[0].Trim(' ','.');
        if(stem.Equals("CON",StringComparison.OrdinalIgnoreCase)||stem.Equals("PRN",StringComparison.OrdinalIgnoreCase)||
            stem.Equals("AUX",StringComparison.OrdinalIgnoreCase)||stem.Equals("NUL",StringComparison.OrdinalIgnoreCase)||
            stem.Equals("CONIN$",StringComparison.OrdinalIgnoreCase)||stem.Equals("CONOUT$",StringComparison.OrdinalIgnoreCase)||
            stem.Equals("CLOCK$",StringComparison.OrdinalIgnoreCase)||
            stem.Length==4 && (stem.StartsWith("COM",StringComparison.OrdinalIgnoreCase)||stem.StartsWith("LPT",StringComparison.OrdinalIgnoreCase)) &&
                (stem[3] is >= '0' and <= '9' || stem[3] is '¹' or '²' or '³'))
            value="%"+((int)value[0]).ToString("X4",CultureInfo.InvariantCulture)+value.Substring(1);
        return Shorten(value,maximum);
    }

    private static string Unique(string name,string prefix,int maximum,HashSet<string> occupied)
    {
        string candidate=name;int index=2;
        while(!occupied.Add(prefix+candidate))
        {
            string suffix=" ("+index++.ToString(CultureInfo.InvariantCulture)+")";
            string extension=Path.GetExtension(name);
            if(extension.Length>Math.Min(12,Math.Max(0,maximum-suffix.Length-2)))extension="";
            string stem=extension.Length==0?name:name.Substring(0,name.Length-extension.Length);
            candidate=Shorten(stem,maximum-suffix.Length-extension.Length)+suffix+extension;
        }
        return prefix+candidate;
    }

    private static string Shorten(string value,int maximum)
    {
        if(value.Length<=maximum)return value;
        string extension=Path.GetExtension(value);
        if(extension.Length>12)extension="";
        int length=Math.Max(1,maximum-extension.Length-1);
        if(length<value.Length && char.IsHighSurrogate(value[length-1]))length--;
        return value.Substring(0,length)+"~"+extension;
    }
}
