
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using VPSPanel.Core;
using VPSPanel.Relay;

try
{
    if (args is ["version"]) { Console.WriteLine("VPSPanel.Relay "+RecoveryPackage.RelayVersion); return 0; }
    if (args is ["capabilities"]) { Console.WriteLine("configurable-default"); Console.WriteLine("exit-failover"); Console.WriteLine("encrypted-dns-routing"); Console.WriteLine("split-doh"); Console.WriteLine("managed-doh"); return 0; }
    if (args is ["prepare-probe", var directory])
    {
        var state = Disk.Read<RuntimeState>(Path.Combine(directory, "committed.json"));
        if (state.Plan.ManagedDohResolvers == null) { Console.WriteLine("existing"); return 0; }
        var outbound = System.Text.Json.Nodes.JsonNode.Parse(Console.OpenStandardInput())!.AsObject();
        var settings = outbound["settings"]!;
        var endpoint = settings["vnext"] is System.Text.Json.Nodes.JsonArray list ? list[0]! : settings;
        var hostname = endpoint["address"]!.ToString();
        var address = await BootstrapDns.Resolve(hostname, state.Plan.BootstrapDohResolvers ?? DohResolvers.Domestic, CancellationToken.None);
        var stream = outbound["streamSettings"]!;
        var tls = stream["security"]?.ToString() == "reality" ? stream["realitySettings"] : stream["tlsSettings"];
        if (tls != null && string.IsNullOrEmpty(tls["serverName"]?.ToString())) tls["serverName"] = hostname;
        endpoint["address"] = address.ToString();
        Console.WriteLine(outbound.ToJsonString());
        return 0;
    }
    if (args is ["recover-dns", var dnsDirectory, var dnsId])
    {
        await DnsRestartGuard.Recover(Path.GetFullPath(dnsDirectory), dnsId, CancellationToken.None);
        return 0;
    }
    if (args is ["restore-unpack",var package,var target]) { await RestoreRuntime.Unpack(package,target); return 0; }
    if (args is ["restore-check",var release]) { await RestoreRuntime.Check(release); return 0; }
    if (args is [("submit" or "submit-policy" or "submit-existing"), var folder, var planFile])
    {
        string dir = Path.GetFullPath(folder);
        if (args[0] == "submit-existing" && !File.Exists(Path.Combine(dir, "committed.json"))) throw new PanelException("隔离 Relay 尚未接管。");
        RelayPlan LoadPlan() => planFile == "-" ? JsonSerializer.Deserialize<RelayPlan>(Console.OpenStandardInput()) ?? throw new InvalidDataException() : Disk.Read<RelayPlan>(planFile);
        var id = Guid.NewGuid().ToString("N");
        var request = args[0] == "submit-policy" ? new Submission(id, null, Disk.Read<PolicyUpdate>(planFile)) : new Submission(id, LoadPlan());
        Disk.Write(Path.Combine(dir, "request.json"), JsonSerializer.Serialize(request), false);
        Console.WriteLine(request.Id); return 0;
    }
    if (args is not ["serve", var location]) { Console.Error.WriteLine("用法：serve <工作目录> 或 submit <工作目录> <方案.json>"); return 2; }
    string work = Path.GetFullPath(location);
    var options = Disk.Read<RelayOptions>(Path.Combine(work, "relay.json"));
    var check = new Uri(options.CheckUrl);
    if (options.ListenPort is < 1 or > 65535 || options.ApiPort is < 1 or > 65535 || options.ProbeSeconds is < 1 or > 300 ||
       !(check.Scheme == "https" || check.Scheme == "http" && check.IsLoopback)) throw new PanelException("Relay 监听或健康探测设置无效。");
    using var instance = File.Open(Path.Combine(work, "serve.lock"), FileMode.OpenOrCreate, FileAccess.Write, FileShare.None);
    using var stop = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
    using var sig = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, c => { c.Cancel = true; stop.Cancel(); }) : null;
    var token = stop.Token;
    var runtime = new RoutingRuntime();
    var manager = new XrayManager(work, options, runtime);
    using var listener = new TcpListener(IPAddress.Loopback, options.ListenPort);
    using var dnsListener = new TcpListener(IPAddress.Parse(EncryptedDnsRoute.LoopbackAddress), options.ListenPort);
    dnsListener.Start();
    await manager.Start(token);
    Disk.Write(Path.Combine(work, "status.json"), JsonSerializer.Serialize(runtime.Snapshot()));
    listener.Start();
    async Task Health()
    {
        while (!token.IsCancellationRequested)
        {
            await Task.WhenAll(runtime.ActiveLanes().Select(async lane =>
            {
                try { double ms = await Socks.Check(lane.Port, check, token, manager.CurrentPlan.HealthResolvers(lane.Id)); runtime.Observe(lane.Tag, true, ms); }
                catch (Exception ex) when (ex is not OutOfMemoryException) { runtime.Observe(lane.Tag, false, null); }
            }));
            await Task.Delay(TimeSpan.FromSeconds(options.ProbeSeconds), token);
        }
    }
    var expired = new System.Collections.Concurrent.ConcurrentDictionary<string, Lane>();
    async Task Metrics()
    {
        while (!token.IsCancellationRequested)
        {
            foreach (var lane in runtime.Tick(TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(30))) expired[lane.Tag] = lane;
            Disk.Write(Path.Combine(work, "status.json"), JsonSerializer.Serialize(runtime.Snapshot()));
            await Task.Delay(1000, token);
        }
    }
    async Task Changes()
    {
        string path = Path.Combine(work, "request.json");
        while (!token.IsCancellationRequested)
        {
            if (File.Exists(path))
            {
                string id = ""; string? error = null;
                try { var req = Disk.Read<Submission>(path); id = req.Id; var plan = req.Update?.Apply(manager.CurrentPlan) ?? req.Plan ?? throw new PanelException("缺少 Relay 方案。"); await manager.Apply(plan, token, req.XrayService, req.Id); }
                catch (Exception ex) when (!token.IsCancellationRequested && ex is not OutOfMemoryException)
                {
                    if (File.Exists(Path.Combine(work, "transaction.json"))) throw new PanelException("事务恢复未完成，请重启 Relay 以重试。");
                    error = ex is PanelException ? ex.Message : "候选校验或探测失败，已保留上一版。";
                }
                string receipt = JsonSerializer.Serialize(new { Id = id, Success = error == null, Error = error });
                if (Guid.TryParseExact(id, "N", out _))
                {
                    string receipts = Path.Combine(work, "receipts");
                    Directory.CreateDirectory(receipts);
                    Disk.Write(Path.Combine(receipts, id + ".json"), receipt);
                    foreach (var old in Directory.EnumerateFiles(receipts, "*.json"))
                        if (File.GetLastWriteTimeUtc(old) < DateTime.UtcNow.AddDays(-1)) File.Delete(old);
                }
                Disk.Write(Path.Combine(work, "result.json"), receipt);
                Disk.Remove(path);
            }
            foreach (var lane in expired.Values)
            {
                try { await manager.Collect(lane, token); expired.TryRemove(lane.Tag, out _); }
                catch (Exception ex) when (!token.IsCancellationRequested && ex is not OutOfMemoryException) { Console.Error.WriteLine("待排空出口回收失败，将重试。"); }
            }
            await Task.Delay(250, token);
        }
    }
    var server = new RelayServer(runtime);
    var tasks = new[] { server.Serve(listener, token), server.Serve(dnsListener, token, healthyDns: true), Health(), Metrics(), Changes() };
    await Task.WhenAny(tasks); stop.Cancel();
    try { await Task.WhenAll(tasks); } catch (OperationCanceledException) when (!tasks.Any(t => t.IsFaulted)) { }
    return 0;
}
catch (Exception ex) { Console.Error.WriteLine(ex is PanelException ? ex.Message : "Relay 操作失败，请检查工作目录、内核与管理接口。"); return 1; }
