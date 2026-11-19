using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal sealed record RelayOptions(string Xray, int ApiPort, int ListenPort, string CheckUrl = "https://www.gstatic.com/generate_204", int ProbeSeconds = 5);
internal sealed record Journal(string PreviousXray, RuntimeState PreviousState);
internal sealed record Submission(string Id, RelayPlan? Plan, PolicyUpdate? Update = null);
internal static class Disk
{
    public static T Read<T>(string path) => JsonSerializer.Deserialize<T>(File.ReadAllBytes(path)) ?? throw new InvalidDataException();
    public static void Write(string path, string value, bool replace = true)
    {
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var opts = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) opts.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        try
        {
            using (var f = new FileStream(temp, opts)) { f.Write(System.Text.Encoding.UTF8.GetBytes(value)); f.Flush(true); }
            File.Move(temp, path, replace); Sync(path);
        }
        finally { File.Delete(temp); }
    }
    public static void Restore(string path, string value)
    {
        if (!File.Exists(path) || File.ReadAllText(path) != value) Write(path, value);
    }
    public static void Remove(string path) { File.Delete(path); Sync(path); }
    private static void Sync(string path)
    {
        if (!OperatingSystem.IsLinux()) return;
        int fd = open(Path.GetDirectoryName(Path.GetFullPath(path))!, 0);
        if (fd < 0) throw new IOException("目录不可用。");
        try { if (fsync(fd) != 0) throw new IOException("目录同步失败。"); } finally { close(fd); }
    }
    [DllImport("libc")] private static extern int open(string path, int flags);
    [DllImport("libc")] private static extern int fsync(int fd);
    [DllImport("libc")] private static extern int close(int fd);
}

internal sealed class XrayManager(string dir, RelayOptions options, RoutingRuntime runtime)
{
    private const string Prefix = "vp3-";
    private RuntimeState current = new(new(RoutingPolicy.Empty, [], new()), []);
    public RelayPlan CurrentPlan => current.Plan;
    private readonly List<Lane> draining = [];
    private string FileAt(string name) => Path.Combine(dir, name);
    private GeoCatalog Geo() => new(Directory.Exists(FileAt("rules-geo")) ? FileAt("rules-geo") : dir);
    private static bool Managed(string? tag) => tag != null && tag.StartsWith(Prefix, StringComparison.Ordinal) && Guid.TryParseExact(tag[Prefix.Length..], "N", out _);
    private async Task<string> Run(string[] args, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(15));
        var info = new ProcessStartInfo(options.Xray)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = dir,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var s in args) info.ArgumentList.Add(s);
        using var p = Process.Start(info)!;
        try
        {
            var stdout = p.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderr = p.StandardError.ReadToEndAsync(deadline.Token);
            await Task.WhenAll(stdout, stderr, p.WaitForExitAsync(deadline.Token));
            if (p.ExitCode != 0) throw new PanelException("Xray 校验或管理调用失败：" + string.Join(" ", args.Take(2)));
            return await stdout;
        }
        finally { if (!p.HasExited) p.Kill(true); }
    }
    private Task<string> Api(string verb, CancellationToken ct, params string[] arguments) =>
        Run(["api", verb, "--server=127.0.0.1:" + options.ApiPort, .. arguments], ct);
    private async Task<HashSet<string>> Tags(string verb, CancellationToken ct)
    {
        string body = await Api(verb, ct);
        var set = new HashSet<string>();
        void Visit(JsonNode? n)
        {
            if (n is JsonObject obj) { foreach (var pair in obj) Visit(pair.Value); }
            else if (n is JsonArray arr) { foreach (var item in arr) Visit(item); }
            else if (n is JsonValue value && value.TryGetValue<string>(out var tag) && Managed(tag)) set.Add(tag);
        }
        Visit(JsonNode.Parse(body)); return set;
    }
    private static JsonObject In(Lane lane) => new()
    {
        ["tag"] = lane.Tag,
        ["listen"] = "127.0.0.1",
        ["port"] = lane.Port,
        ["protocol"] = "socks",
        ["settings"] = new JsonObject { ["udp"] = true, ["auth"] = "noauth", ["ip"] = "127.0.0.1" }
    };
    private static JsonObject Out(RelayExit exit, Lane lane)
    { var o = exit.Outbound.DeepClone().AsObject(); o["tag"] = lane.Tag; return o; }
    private static JsonObject Rule(Lane lane) => new() { ["type"] = "field", ["ruleTag"] = lane.Tag, ["inboundTag"] = new JsonArray(lane.Tag), ["outboundTag"] = lane.Tag };
    private static JsonArray Array(JsonObject obj, string key)
    { if (obj[key] is JsonArray a) return a; var next = new JsonArray(); obj[key] = next; return next; }
    private static void Filter(JsonArray arr, string key) { for (int i = arr.Count - 1; i >= 0; i--) if (Managed(arr[i]?[key]?.ToString())) arr.RemoveAt(i); }
    internal static JsonObject Compose(string existing, RuntimeState state, IEnumerable<Lane> extra)
    {
        var root = JsonNode.Parse(existing, documentOptions: new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })!.AsObject();
        var ins = Array(root, "inbounds"); var outs = Array(root, "outbounds"); Filter(ins, "tag"); Filter(outs, "tag");
        if (root["routing"] == null) root["routing"] = new JsonObject();
        var rules = Array(root["routing"]!.AsObject(), "rules"); Filter(rules, "ruleTag");
        foreach (var l in state.Lanes) { ins.Add(In(l)); outs.Add(Out(state.Plan.Exits.Single(e => e.Id == l.Id), l)); }
        foreach (var l in state.Lanes.Concat(extra).DistinctBy(l => l.Tag).Reverse()) rules.Insert(0, Rule(l));
        return root;
    }
    private async Task LoadRules(JsonObject root, CancellationToken ct)
    {
        string path = FileAt("runtime-rules.json");
        var rules = new JsonObject { ["routing"] = root["routing"]!.DeepClone() };
        Disk.Write(path, rules.ToJsonString());
        try { await Api("adrules", ct, path); } finally { File.Delete(path); }
    }
    private async Task Add(Lane lane, RelayExit exit, bool inbound, bool outbound, CancellationToken ct)
    {
        var part = new JsonObject { ["inbounds"] = new JsonArray(In(lane)), ["outbounds"] = new JsonArray(Out(exit, lane)) };
        string path = FileAt("runtime-handler.json"); Disk.Write(path, part.ToJsonString());
        try
        {
            if (outbound) await Api("ado", ct, path);
            if (inbound) await Api("adi", ct, path);
        }
        finally { File.Delete(path); }
    }
    private async Task Reconcile(RuntimeState state, string disk, IReadOnlyList<Lane> keep, CancellationToken ct)
    {
        var ins = await Tags("lsi", ct); var outs = await Tags("lso", ct);
        foreach (var lane in state.Lanes) await Add(lane, state.Plan.Exits.Single(e => e.Id == lane.Id), !ins.Contains(lane.Tag), !outs.Contains(lane.Tag), ct);
        await LoadRules(Compose(disk, state, keep), ct);
        var wanted = state.Lanes.Concat(keep).Select(l => l.Tag).ToHashSet();
        foreach (string tag in ins.Except(wanted)) await Api("rmi", ct, tag);
        foreach (string tag in outs.Except(wanted)) await Api("rmo", ct, tag);
    }
    internal async Task Start(CancellationToken ct)
    {
        if (!(await Run(["version"], ct)).StartsWith("Xray 26.10.31 ", StringComparison.Ordinal)) throw new PanelException("Relay 需要已验证的 Xray 26.10.31。");
        string state = FileAt("committed.json"), journal = FileAt("transaction.json"), config = FileAt("xray.json");
        if (File.Exists(journal))
        {
            var old = Disk.Read<Journal>(journal);
            Disk.Restore(config, old.PreviousXray); Disk.Restore(state, JsonSerializer.Serialize(old.PreviousState));
        }
        if (File.Exists(state)) current = Disk.Read<RuntimeState>(state);
        var engine = new RuleEngine(current.Plan.Policy, Geo());
        await Reconcile(current, File.ReadAllText(config), [], ct);
        runtime.Publish(current, engine, new HashSet<string>());
        Disk.Remove(journal);
    }
    private static int Port(HashSet<int> ports)
    {
        while (true)
        {
            using var socket = new TcpListener(IPAddress.Loopback, 0); socket.Start();
            int port = ((IPEndPoint)socket.LocalEndpoint).Port; if (ports.Add(port)) return port;
        }
    }
    internal async Task Apply(RelayPlan plan, CancellationToken ct)
    {
        var engine = new RuleEngine(plan.Policy, Geo()); plan.Total.Validate();
        if (plan.Exits.Count(e => e.Direct) > 1 || plan.Exits.Select(e => e.Id).Distinct().Count() != plan.Exits.Length)
            throw new PanelException("直连或稳定 ID 重复。");
        foreach (var exit in plan.Exits)
        {
            exit.Limit.Validate(); var proto = exit.Outbound["protocol"]?.ToString();
            if (string.IsNullOrWhiteSpace(exit.Id) || (exit.Direct ? proto != "freedom" : proto is not ("vless" or "hysteria")))
                throw new PanelException("出口类型与角色不匹配。");
        }
        if (plan.Policy.Rules.Any(r => r.Action == RouteAction.Fixed && !plan.Exits.Any(e => e.Id == r.Exit && !e.Direct)))
            throw new PanelException("规则引用了不存在的上游。");
        var ports = current.Lanes.Concat(draining).Select(l => l.Port).ToHashSet();
        var lanes = plan.Exits.Where(e => e.Enabled).Select(e =>
        {
            var old = current.Plan.Exits.FirstOrDefault(x => x.Id == e.Id);
            var lane = current.Lanes.FirstOrDefault(l => l.Id == e.Id);
            return lane != null && JsonNode.DeepEquals(old?.Outbound, e.Outbound) ? lane : new Lane(e.Id, Prefix + Guid.NewGuid().ToString("N"), Port(ports));
        }).ToArray();
        var next = new RuntimeState(plan, lanes);
        string config = FileAt("xray.json"), before = File.ReadAllText(config), candidate = FileAt("candidate.json");
        var root = Compose(before, next, []);
        var added = lanes.Except(current.Lanes).ToArray();
        var retired = current.Lanes.Except(lanes).ToArray();
        Disk.Write(candidate, root.ToJsonString());
        try
        {
            await Run(["run", "-test", "-c", candidate], ct);
            var previous = new Journal(before, current);
            Disk.Write(FileAt("previous.json"), JsonSerializer.Serialize(previous));
            Disk.Write(FileAt("transaction.json"), JsonSerializer.Serialize(previous));
            try
            {
                foreach (var l in added) await Add(l, plan.Exits.Single(e => e.Id == l.Id), true, true, ct);
                await LoadRules(Compose(before, next, retired.Concat(draining)), ct);
                var ins = await Tags("lsi", ct); var outs = await Tags("lso", ct);
                if (lanes.Any(l => !ins.Contains(l.Tag) || !outs.Contains(l.Tag))) throw new PanelException("运行中的出口与候选清单不符。");
                foreach (var l in added) await Socks.Check(l.Port, new(options.CheckUrl), ct);
                Disk.Write(config, root.ToJsonString()); Disk.Write(FileAt("committed.json"), JsonSerializer.Serialize(next));
                Disk.Remove(FileAt("transaction.json"));
            }
            catch
            {
                Disk.Restore(config, before); Disk.Restore(FileAt("committed.json"), JsonSerializer.Serialize(current));
                await Reconcile(current, before, draining, CancellationToken.None);
                Disk.Remove(FileAt("transaction.json")); throw;
            }
            draining.AddRange(retired); current = next; runtime.Publish(next, engine, added.Select(l => l.Tag).ToHashSet());
        }
        finally { File.Delete(candidate); }
    }
    internal async Task Collect(Lane lane, CancellationToken ct)
    {
        if (!draining.Contains(lane)) return;
        var ins = await Tags("lsi", ct); var outs = await Tags("lso", ct);
        if (ins.Contains(lane.Tag)) await Api("rmi", ct, lane.Tag);
        if (outs.Contains(lane.Tag)) await Api("rmo", ct, lane.Tag);
        await LoadRules(Compose(File.ReadAllText(FileAt("xray.json")), current, draining.Where(l => l != lane)), ct);
        draining.Remove(lane); runtime.Collected(lane);
    }
}
