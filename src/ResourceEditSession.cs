namespace Unpacker;

// Exposes both whole containers and their editable leaf files. Changes to a
// leaf rebuild its container automatically before the outer PE is updated.
internal sealed class ResourceEditSession
{
    private readonly ResourceFileEditor editor;
    private readonly Dictionary<string,ResourceFileEditor> containers=new(StringComparer.Ordinal);
    private readonly Dictionary<string,string> containerNames=new(StringComparer.Ordinal);
    private readonly Dictionary<string,(string Parent,string Local)> children=new(StringComparer.Ordinal);
    internal List<ResourceFileEditor.Asset> Assets {get;}=new();
    internal bool IsContainer=>editor.IsContainer;
    internal bool HasSignature=>editor.HasSignature;

    internal ResourceEditSession(byte[] image,bool container)
    {
        editor=new ResourceFileEditor(image,container);
        long total=0;
        void Add(ResourceFileEditor.Asset asset)
        {
            total+=asset.Data.Length;
            if(Assets.Count>=ResourceFileEditor.MaxEntries || total>ResourceFileEditor.MaxFileBytes)
                throw ResourceFileEditor.Invalid("展开后的资源数量或体积超过限制。");
            Assets.Add(asset);
        }
        foreach(var asset in editor.Assets)
        {
            Add(asset);
            if(container || asset.Format!="binary" || !asset.Name.EndsWith(".resources",StringComparison.OrdinalIgnoreCase) ||
                asset.Data.Length<4 || BitConverter.ToUInt32(asset.Data,0)!=0xBEEFCACE)continue;
            var nested=new ResourceFileEditor(asset.Data,true);
            containers.Add(asset.Id,nested);
            containerNames.Add(asset.Id,asset.Name);
            foreach(var leaf in nested.Assets)
            {
                string id=asset.Id+"."+leaf.Id;
                children.Add(id,(asset.Id,leaf.Id));
                Add(new ResourceFileEditor.Asset(id,leaf.Name,leaf.Type,leaf.Format,leaf.Data,leaf.Stored));
            }
        }
    }

    internal string? ContainerName(string id)=>children.TryGetValue(id,out var child)?
        containerNames[child.Parent]:null;

    internal byte[] Apply(IReadOnlyDictionary<string,byte[]> edits,out int changes)
    {
        var originals=Assets.ToDictionary(a=>a.Id,StringComparer.Ordinal);
        var changed=new Dictionary<string,byte[]>(StringComparer.Ordinal);
        foreach(var edit in edits)
        {
            if(!originals.TryGetValue(edit.Key,out var asset) || edit.Value.Length>ResourceFileEditor.MaxAssetBytes)
                throw ResourceFileEditor.Invalid("替换资源条目无效。");
            if(!Enumerable.SequenceEqual(edit.Value,asset.Data))changed.Add(edit.Key,edit.Value);
        }
        changes=changed.Count;
        var outer=changed.Where(p=>!children.ContainsKey(p.Key)).ToDictionary(p=>p.Key,p=>p.Value,StringComparer.Ordinal);
        foreach(var group in changed.Where(p=>children.ContainsKey(p.Key)).GroupBy(p=>children[p.Key].Parent))
        {
            if(outer.ContainsKey(group.Key))throw ResourceFileEditor.Invalid("不能同时修改整个资源容器及其子条目；请只保留其中一种修改。");
            var inner=group.ToDictionary(p=>children[p.Key].Local,p=>p.Value,StringComparer.Ordinal);
            outer.Add(group.Key,containers[group.Key].Apply(inner,out _));
        }
        return editor.Apply(outer,out _);
    }
}
