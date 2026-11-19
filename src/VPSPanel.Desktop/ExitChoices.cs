using VPSPanel.Core;

namespace VPSPanel.Desktop;

internal static class ExitChoices
{
    internal static IEnumerable<(string Id,string Label)> ForHost(ManagedHost host,string? selected)
    {
        bool found=false;
        foreach(var exit in host.Workspace.Items){
            string label=exit.Name==exit.Id?exit.Id:$"{exit.Name}（{exit.Id}）";
            yield return (exit.Id,exit.Enabled?label:label+" · 已停用");
            found|=exit.Id==selected;
        }
        if(selected!=null && !found)yield return (selected,selected+" · 出口已不存在");
    }
}
