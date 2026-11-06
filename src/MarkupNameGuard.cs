using System.Collections;
using System.Resources;
using dnlib.DotNet;

namespace Unpacker;

// BAML and XAML contain contracts outside the IL reference graph, including
// type identities, event handlers, binding paths and resource keys. Keeping
// only public names, or only types deriving from FrameworkElement, is not
// sufficient: converters, view models and private handlers can be referenced.
internal static class MarkupNameGuard
{
    internal static bool RequiresStableNames(ModuleDef module)
    {
        bool wpf=module.GetAssemblyRefs().Any(a=>a.Name=="PresentationFramework");
        foreach(var resource in module.Resources)
        {
            string name=resource.Name.String;
            if(IsMarkup(name) || name.EndsWith(".g.resources",StringComparison.OrdinalIgnoreCase))return true;
            if(resource is not EmbeddedResource embedded || !name.EndsWith(".resources",StringComparison.OrdinalIgnoreCase))continue;
            try
            {
                using var stream=new MemoryStream(embedded.CreateReader().ToArray(),false);
                using var reader=new ResourceReader(stream);
                // Enumerate keys only. Reading Value would deserialize arbitrary
                // user-defined resource types and is unnecessary for detection.
                IDictionaryEnumerator entries=reader.GetEnumerator();
                while(entries.MoveNext())
                    if(entries.Key is string key && IsMarkup(key))return true;
            }
            catch(Exception ex) when(ex is ArgumentException or IOException or BadImageFormatException or NotSupportedException or FormatException or OverflowException)
            {
                // An opaque WPF resource container cannot prove renaming safe.
                if(wpf)return true;
            }
        }
        return false;
    }

    private static bool IsMarkup(string name)=>name.EndsWith(".baml",StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".xaml",StringComparison.OrdinalIgnoreCase);
}
