using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal sealed record RelayOptions(string Xray, int ApiPort, int ListenPort, string CheckUrl = "https://www.gstatic.com/generate_204", int ProbeSeconds = 5);
internal sealed record Journal(string PreviousXray, RuntimeState PreviousState, string? XrayService = null, string? RestartId = null,
    byte[]? PreviousBootstrapAsset = null);
internal sealed record Submission(string Id, RelayPlan? Plan, PolicyUpdate? Update = null, string? XrayService = null);
internal static class Disk
{
    public static T Read<T>(string path) => JsonSerializer.Deserialize<T>(File.ReadAllBytes(path)) ?? throw new InvalidDataException();
    public static void Write(string path, string value, bool replace = true)
        => Write(path, System.Text.Encoding.UTF8.GetBytes(value), replace);
    public static void Write(string path, byte[] value, bool replace = true, UnixFileMode? unixMode = null)
    {
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var opts = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) opts.UnixCreateMode = unixMode ?? (UnixFileMode.UserRead | UnixFileMode.UserWrite);
        try
        {
            using (var f = new FileStream(temp, opts))
            {
                if (!OperatingSystem.IsWindows() && unixMode is { } mode) File.SetUnixFileMode(f.SafeFileHandle, mode);
                f.Write(value); f.Flush(true);
            }
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
    private static bool Managed(string? tag) => tag == EncryptedDnsRoute.Tag ||
        tag != null && tag.StartsWith(Prefix, StringComparison.Ordinal) && Guid.TryParseExact(tag[Prefix.Length..], "N", out _);
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
        if (File.Exists(BootstrapGeneration.AssetPath(dir)))
        {
            info.Environment.Remove("xray.location.asset");
            info.Environment["XRAY_LOCATION_ASSET"] = BootstrapGeneration.AssetDirectory(dir);
        }
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
    private static JsonObject Out(RelayExit exit, Lane lane, bool managed)
    {
        var o = exit.Outbound.DeepClone().AsObject();
        o["tag"] = lane.Tag;
        if (managed)
        {
            if (exit.Direct)
            {
                o["settings"] ??= new JsonObject();
                o["settings"]!["targetStrategy"] = "ForceIP";
            }
            else
            {
                o["streamSettings"] ??= new JsonObject();
                var stream = o["streamSettings"]!;
                stream["sockopt"] ??= new JsonObject();
                stream["sockopt"]!["domainStrategy"] = "ForceIP";
            }
        }
        return o;
    }
    private static JsonObject Rule(Lane lane) => new() { ["type"] = "field", ["ruleTag"] = lane.Tag, ["inboundTag"] = new JsonArray(lane.Tag), ["outboundTag"] = lane.Tag };
    private static JsonArray Array(JsonObject obj, string key)
    { if (obj[key] is JsonArray a) return a; var next = new JsonArray(); obj[key] = next; return next; }
    private static void Filter(JsonArray arr, string key)
    {
        for (int i = arr.Count - 1; i >= 0; i--)
        {
            var tag = arr[i]?[key]?.ToString();
            if (Managed(tag) || key == "ruleTag" && tag is EncryptedDnsRoute.VerificationTag or EncryptedDnsRoute.UnmatchedTag)
                arr.RemoveAt(i);
        }
    }
    internal static JsonObject Compose(string existing, RuntimeState state, IEnumerable<Lane> extra, int relayPort, bool hotBindings = true)
    {
        var root = JsonNode.Parse(existing, documentOptions: new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })!.AsObject();
        var ins = Array(root, "inbounds"); var outs = Array(root, "outbounds"); Filter(ins, "tag"); Filter(outs, "tag");
        if (root["routing"] == null) root["routing"] = new JsonObject();
        var rules = Array(root["routing"]!.AsObject(), "rules"); Filter(rules, "ruleTag");
        var internalRules = state.Lanes.Concat(extra).DistinctBy(l => l.Tag).Select(Rule).ToList();
        if (state.Plan.ManagedDohResolvers != null)
        {
            if (!state.Plan.FollowHealthyDns) throw new PanelException("面板配置的 DoH 需要跟随健康出口。");
            if (hotBindings)
            {
                root["dns"] = EncryptedDnsRoute.ManagedConfiguration(state.Plan);
                root["geodata"] ??= new JsonObject();
                var geo = root["geodata"]!.AsObject();
                if (geo["assets"] is JsonArray {Count: > 0} && geo["cron"]?.ToString() is not ("@every 1m" or "* * * * *"))
                    throw new PanelException("服务器的 GeoData 下载计划与引导域名热更新周期冲突，已保留原计划。");
                geo["cron"] = "@every 1m";
                if (ins.Any(i => i?["tag"]?.ToString() == EncryptedDnsRoute.VerificationTag))
                    throw new PanelException("已有入口与面板的引导域名校验标签冲突。");
                foreach (bool matched in new[] { true, false })
                {
                    var proof = new JsonObject { ["type"] = "field", ["ruleTag"] = matched ? EncryptedDnsRoute.VerificationTag : EncryptedDnsRoute.UnmatchedTag,
                        ["inboundTag"] = new JsonArray(EncryptedDnsRoute.VerificationTag),
                        ["outboundTag"] = matched ? EncryptedDnsRoute.Tag : EncryptedDnsRoute.VerificationTag };
                    if (matched) proof["domain"] = new JsonArray("ext:" + EncryptedDnsRoute.Asset + ":generation");
                    internalRules.Add(proof);
                }
            }
        }
        if (state.Plan.FollowHealthyDns)
        {
            if (relayPort is < 1 or > 65535) throw new PanelException("缺少加密 DNS 的 Relay 监听端口。");
            internalRules.Add(EncryptedDnsRoute.Read(root).Rule());
            outs.Add(EncryptedDnsRoute.Outbound(relayPort));
        }
        foreach (var l in state.Lanes) { ins.Add(In(l)); outs.Add(Out(state.Plan.Exits.Single(e => e.Id == l.Id), l, state.Plan.ManagedDohResolvers != null)); }
        var internalSources = internalRules.Select(r => r["inboundTag"]![0]!.ToString()).ToHashSet();
        int insert = 0;
        while (insert < rules.Count && rules[insert]?["inboundTag"] is JsonArray { Count: > 0 } sources &&
               sources.All(s => !internalSources.Contains(s!.ToString())))
            insert++;
        foreach (var rule in internalRules) rules.Insert(insert++, rule);
        return root;
    }
    private async Task LoadRules(JsonObject root, CancellationToken ct)
    {
        string path = FileAt("runtime-rules.json");
        var rules = new JsonObject { ["routing"] = root["routing"]!.DeepClone() };
        Disk.Write(path, rules.ToJsonString());
        try { await Api("adrules", ct, path); } finally { File.Delete(path); }
    }
    private async Task Add(Lane lane, RelayExit exit, bool inbound, bool outbound, bool managed, CancellationToken ct)
    {
        var part = new JsonObject { ["inbounds"] = new JsonArray(In(lane)), ["outbounds"] = new JsonArray(Out(exit, lane, managed)) };
        await AddHandlers(part, inbound, outbound, ct);
    }
    private async Task AddHandlers(JsonObject config, bool inbound, bool outbound, CancellationToken ct)
    {
        string path = FileAt("runtime-handler.json"); Disk.Write(path, config.ToJsonString());
        try
        {
            if (outbound) await Api("ado", ct, path);
            if (inbound) await Api("adi", ct, path);
        }
        finally { File.Delete(path); }
    }
    private async Task Reconcile(RuntimeState state, string disk, IReadOnlyList<Lane> keep, CancellationToken ct)
    {
        var config = Compose(disk, state, keep, options.ListenPort, HasAsset(disk));
        var ins = await Tags("lsi", ct); var outs = await Tags("lso", ct);
        foreach (var lane in state.Lanes) await Add(lane, state.Plan.Exits.Single(e => e.Id == lane.Id), !ins.Contains(lane.Tag), !outs.Contains(lane.Tag), state.Plan.ManagedDohResolvers != null, ct);
        await EnsureDnsOutbound(state.Plan.FollowHealthyDns, outs, ct);
        await LoadRules(config, ct);
        var wanted = state.Lanes.Concat(keep).Select(l => l.Tag).ToHashSet();
        if (state.Plan.FollowHealthyDns) wanted.Add(EncryptedDnsRoute.Tag);
        foreach (string tag in ins.Except(wanted)) await Api("rmi", ct, tag);
        foreach (string tag in outs.Except(wanted)) await Api("rmo", ct, tag);
    }
    private async Task EnsureDnsOutbound(bool enabled, IReadOnlySet<string> existing, CancellationToken ct)
    {
        if (!enabled || existing.Contains(EncryptedDnsRoute.Tag)) return;
        var config = new JsonObject { ["outbounds"] = new JsonArray(EncryptedDnsRoute.Outbound(options.ListenPort)) };
        await AddHandlers(config, false, true, ct);
    }
    internal async Task Start(CancellationToken ct)
    {
        if (!(await Run(["version"], ct)).StartsWith("Xray 26.10.31 ", StringComparison.Ordinal)) throw new PanelException("Relay 需要已验证的 Xray 26.10.31。");
        string state = FileAt("committed.json"), journal = FileAt("transaction.json"), config = FileAt("xray.json");
        bool interrupted = File.Exists(journal);
        if (interrupted)
        {
            var old = Disk.Read<Journal>(journal);
            if (old.XrayService is not null && old.RestartId is { } id)
                await DnsRestartGuard.Recover(dir, id, ct);
            else
                DnsRestartGuard.RestoreFiles(dir, old);
        }
        if (File.Exists(state)) current = Disk.Read<RuntimeState>(state);
        var engine = new RuleEngine(current.Plan.Policy, Geo());
        var saved = File.ReadAllText(config);
        await Reconcile(current, saved, [], ct);
        if (interrupted && HasAsset(saved))
            await BootstrapGeneration.Wait(options.ApiPort, Geo().BootstrapAsset(current.Plan).Generation, ct);
        runtime.Publish(current, engine, new HashSet<string>());
        Disk.Remove(journal);
    }
    private static bool HasAsset(string config) => RecoveryLayout.Parse(config)["dns"]?["servers"] is JsonArray servers &&
        servers.OfType<JsonObject>().Any(s => s["domains"] is JsonArray domains &&
            domains.Any(d => d?.ToString() == "ext:" + EncryptedDnsRoute.Asset + ":bindings"));
    private static int Port(HashSet<int> ports)
    {
        while (true)
        {
            using var socket = new TcpListener(IPAddress.Loopback, 0); socket.Start();
            int port = ((IPEndPoint)socket.LocalEndpoint).Port; if (ports.Add(port)) return port;
        }
    }
    internal async Task Apply(RelayPlan plan, CancellationToken ct, string? xrayService = null, string? requestId = null)
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
        if (plan.DnsOnFailure != DnsFailureAction.Reject)
            throw new PanelException("加密 DNS 仅支持全上游失效时拒绝解析。");
        string config = FileAt("xray.json"), before = File.ReadAllText(config), candidate = FileAt("candidate.json");
        bool changedDns = !plan.SameDns(current.Plan) || plan.ManagedDohResolvers != null && !HasAsset(before);
        if (changedDns && xrayService is null)
            throw new PanelException("DNS 解析器变更需要确认重启 Xray。");
        if (xrayService is not null)
        {
            _ = DnsRestartGuard.Service(xrayService);
            if (!Guid.TryParseExact(requestId, "N", out _))
                throw new PanelException("DNS 事务编号无效。");
        }
        var source = RecoveryLayout.Parse(before);
        var originalGeo = current.Plan.ManagedDohResolvers is null || !HasAsset(before)
            ? source["geodata"]?.DeepClone().AsObject() : current.PreviousGeodata;
        JsonObject? originalDns = current.Plan.ManagedDohResolvers is null
            ? EncryptedDnsRoute.OriginalDns(source["dns"]) : current.PreviousDns;
        if (plan.ManagedDohResolvers is null && current.Plan.ManagedDohResolvers is not null)
        {
            if (originalDns is null) source.Remove("dns");
            else source["dns"] = originalDns.DeepClone();
            if (originalGeo is null) source.Remove("geodata");
            else source["geodata"] = originalGeo.DeepClone();
        }
        var next = new RuntimeState(plan, lanes)
        { PreviousDns = plan.ManagedDohResolvers is null ? null : originalDns,
          PreviousGeodata = plan.ManagedDohResolvers is null ? null : originalGeo };
        var root = Compose(source.ToJsonString(), next, [], options.ListenPort);
        var added = lanes.Except(current.Lanes).ToArray();
        var retired = current.Lanes.Except(lanes).ToArray();
        var assetPath = BootstrapGeneration.AssetPath(dir);
        var oldAsset = File.Exists(assetPath) ? File.ReadAllBytes(assetPath) : null;
        var asset = plan.ManagedDohResolvers is null ? default : Geo().BootstrapAsset(plan);
        bool newAsset = asset.Data != null && (oldAsset == null || !oldAsset.AsSpan().SequenceEqual(asset.Data));
        Disk.Write(candidate, root.ToJsonString());
        try
        {
            using var transition = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var commitToken = ct;
            await using var restartLock = xrayService is null ? null : await DnsRestartGuard.Lock(dir, ct);
            if (xrayService is not null)
            {
                transition.CancelAfter(TimeSpan.FromSeconds(60));
                commitToken = transition.Token;
                await DnsRestartGuard.Arm(dir, requestId!, commitToken);
            }
            var previous = new Journal(before, current, xrayService, xrayService is null ? null : requestId, oldAsset);
            Disk.Write(FileAt("previous.json"), JsonSerializer.Serialize(previous));
            Disk.Write(FileAt("transaction.json"), JsonSerializer.Serialize(previous));
            try
            {
                if (newAsset) BootstrapGeneration.WriteAsset(dir, asset.Data!);
                await Run(["run", "-test", "-c", candidate], commitToken);
                if (xrayService is null)
                {
                    if (newAsset)
                        await BootstrapGeneration.Wait(options.ApiPort, asset.Generation!, commitToken);
                    foreach (var l in added) await Add(l, plan.Exits.Single(e => e.Id == l.Id), true, true, plan.ManagedDohResolvers != null, commitToken);
                    if (plan.FollowHealthyDns) await EnsureDnsOutbound(true, await Tags("lso", commitToken), commitToken);
                    await LoadRules(Compose(source.ToJsonString(), next, retired.Concat(draining), options.ListenPort), commitToken);
                    if (!plan.FollowHealthyDns && current.Plan.FollowHealthyDns)
                        await Api("rmo", commitToken, EncryptedDnsRoute.Tag);
                }
                else
                {
                    Disk.Write(config, root.ToJsonString());
                    await DnsRestartGuard.Restart(xrayService, commitToken);
                    await DnsRestartGuard.WaitForApi(options.ApiPort, commitToken);
                    if (asset.Data != null) await BootstrapGeneration.Wait(options.ApiPort, asset.Generation, commitToken);
                    if (plan.ManagedDohResolvers is { } urls) await ProbeDoh(next, urls, commitToken);
                }
                var ins = await Tags("lsi", commitToken); var outs = await Tags("lso", commitToken);
                if (outs.Contains(EncryptedDnsRoute.Tag) != plan.FollowHealthyDns)
                    throw new PanelException("运行中的加密 DNS 出站与候选清单不符。");
                if (lanes.Any(l => !ins.Contains(l.Tag) || !outs.Contains(l.Tag))) throw new PanelException("运行中的出口与候选清单不符。");
                foreach (var l in added) await Socks.Check(l.Port, new(options.CheckUrl), commitToken, plan.HealthResolvers(l.Id));
                commitToken.ThrowIfCancellationRequested();
                Disk.Write(config, root.ToJsonString()); Disk.Write(FileAt("committed.json"), JsonSerializer.Serialize(next));
                if (asset.Data == null && oldAsset != null) Disk.Remove(assetPath);
                Disk.Remove(FileAt("transaction.json"));
            }
            catch
            {
                DnsRestartGuard.RestoreFiles(dir, previous);
                if (xrayService is not null)
                {
                    await DnsRestartGuard.Restart(xrayService, CancellationToken.None);
                    await DnsRestartGuard.WaitForApi(options.ApiPort, CancellationToken.None);
                }
                await Reconcile(current, before, draining, CancellationToken.None);
                if (newAsset && xrayService == null && HasAsset(before))
                    await BootstrapGeneration.Wait(options.ApiPort, Geo().BootstrapAsset(current.Plan).Generation, CancellationToken.None);
                Disk.Remove(FileAt("transaction.json")); throw;
            }
            draining.AddRange(retired); current = next; runtime.Publish(next, engine, added.Select(l => l.Tag).ToHashSet());
        }
        finally { File.Delete(candidate); }
    }
    private static async Task ProbeDoh(RuntimeState next, string[] urls, CancellationToken token)
    {
        var proxies = next.Plan.Exits.Where(exit => exit.Enabled && !exit.Direct).Select(exit => exit.Id).ToHashSet();
        foreach (var lane in next.Lanes.Where(lane => proxies.Contains(lane.Id)))
        foreach (var url in urls)
        {
            // A record for example.com, reserved for documentation and testing.
            var query = Convert.FromHexString("000001000001000000000000076578616D706C6503636F6D0000010001");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                var answer = await Socks.ExchangeDoh(lane.Port, new Uri(url), query, deadline.Token, requireHttp2: true);
                if ((answer[3] & 15) == 0 && (answer[6] != 0 || answer[7] != 0)) return;
            }
            catch (Exception ex) when (!token.IsCancellationRequested && ex is IOException or HttpRequestException or OperationCanceledException) { }
        }
        throw new PanelException("健康代理出口未能通过新 DoH 解析器完成测试，DNS 变更已回滚。");
    }

    internal async Task Collect(Lane lane, CancellationToken ct)
    {
        if (!draining.Contains(lane)) return;
        var ins = await Tags("lsi", ct); var outs = await Tags("lso", ct);
        if (ins.Contains(lane.Tag)) await Api("rmi", ct, lane.Tag);
        if (outs.Contains(lane.Tag)) await Api("rmo", ct, lane.Tag);
        await LoadRules(Compose(File.ReadAllText(FileAt("xray.json")), current, draining.Where(l => l != lane), options.ListenPort), ct);
        draining.Remove(lane); runtime.Collected(lane);
    }
}
