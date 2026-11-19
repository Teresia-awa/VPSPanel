using System.Diagnostics;
using VPSPanel.Core;

namespace VPSPanel.Relay;

public sealed record Lane(string Id, string Tag, int Port);
public sealed record RuntimeState(RelayPlan Plan, Lane[] Lanes);
internal sealed class Line(Lane lane)
{
    public Lane Lane { get; } = lane;
    public DateTimeOffset? Retired;
    public bool Healthy;
    public int Good, Bad, Active;
    public double Baseline, Latency, Failures, Rate;
    public long UpBytes, DownBytes, Assigned;
    public double UpRate, DownRate;
    public double Recovery;
}
internal sealed class Lease : IDisposable
{
    private readonly RoutingRuntime runtime;
    internal Line Line { get; }
    internal CancellationTokenSource Stop { get; }
    internal bool Udp { get; }
    internal long LastActivity = Stopwatch.GetTimestamp();
    internal Lease(RoutingRuntime owner, Line line, bool udp, CancellationToken token)
    { runtime = owner; Line = line; Udp = udp; Stop = CancellationTokenSource.CreateLinkedTokenSource(token); }
    public void Bytes(int count, bool upload)
    {
        if (upload) Interlocked.Add(ref Line.UpBytes, count);
        else Interlocked.Add(ref Line.DownBytes, count);
        Interlocked.Exchange(ref LastActivity, Stopwatch.GetTimestamp());
    }
    public void Dispose() { runtime.Release(this); Stop.Dispose(); }
}
internal sealed class RoutingRuntime
{
    private readonly object gate = new();
    private readonly HashSet<Lease> sessions = [];
    private readonly Dictionary<string, Line> lines = [];
    private RuntimeState state = new(new(RoutingPolicy.Empty, [], new()), []);
    private RuleEngine engine = new(RoutingPolicy.Empty, new("."));
    private long sequence, lastTick = Stopwatch.GetTimestamp();
    internal SharedRates Rates { get; } = new();

    public void Publish(RuntimeState next, RuleEngine compiled, IReadOnlySet<string> verified)
    {
        lock (gate)
        {
            foreach (var line in lines.Values.Where(l => next.Lanes.All(n => n.Tag != l.Lane.Tag)))
                line.Retired ??= DateTimeOffset.UtcNow;
            foreach (var lane in next.Lanes)
            {
                if (!lines.TryGetValue(lane.Tag, out var line)) lines[lane.Tag] = line = new(lane);
                if (verified.Contains(lane.Tag)) { line.Healthy = true; line.Recovery = .25; line.Good = 2; }
            }
            state = next; engine = compiled; Rates.Configure(next.Plan);
        }
    }
    private RelaySnapshot Sample()
    {
        var items = state.Plan.Exits.Select(e =>
        {
            var lane = state.Lanes.FirstOrDefault(l => l.Id == e.Id);
            var line = lane == null ? null : lines.GetValueOrDefault(lane.Tag);
            var generations = lines.Values.Where(g => g.Lane.Id == e.Id).ToArray();
            return new LinkSample(e.Id, e.Direct, e.Enabled && line?.Healthy == true, line?.Baseline ?? 0,
                line?.Latency ?? 0, line?.Failures ?? 0, generations.Sum(g => g.Rate), generations.Sum(g => g.Active), line?.Recovery ?? 0, line?.Assigned ?? 0,
                generations.Sum(g => g.UpRate), generations.Sum(g => g.DownRate));
        }).ToArray();
        return new(DateTimeOffset.UtcNow, sequence, items) { SupportsDefaultRoute = true, SupportsExitFailover = true };
    }
    public RelaySnapshot Snapshot() { lock (gate) return Sample(); }
    public Lease Open(string target, bool udp, CancellationToken token)
    {
        lock (gate)
        {
            var decision = engine.Select(target, Sample()); sequence++;
            if (decision.Error != null) throw new PanelException(decision.Error);
            var lane = state.Lanes.Single(l => l.Id == decision.Exit);
            var line = lines[lane.Tag];
            var session = new Lease(this, line, udp, token);
            sessions.Add(session); line.Active++; line.Assigned++; return session;
        }
    }
    internal void Release(Lease lease) { lock (gate) { if (sessions.Remove(lease)) lease.Line.Active--; } }
    public void Observe(string tag, bool success, double? milliseconds)
    {
        lock (gate)
        {
            if (!lines.TryGetValue(tag, out var line) || line.Retired != null) return;
            line.Failures = .8 * line.Failures + (success ? 0 : .2);
            if (!success) { line.Good = 0; if (++line.Bad >= 2) { line.Healthy = false; line.Recovery = 0; } return; }
            if (milliseconds is not double measured) return;
            measured = Math.Max(.1, measured);
            line.Baseline = line.Baseline == 0 ? measured : Math.Min(measured, line.Baseline * 1.001);
            line.Latency = line.Latency == 0 ? measured : .65 * line.Latency + .35 * measured;
            line.Bad = 0;
            if (++line.Good >= 2) { line.Healthy = true; line.Recovery = Math.Min(1, line.Recovery + .2); }
        }
    }
    public Lane[] ActiveLanes() { lock (gate) return state.Lanes.ToArray(); }
    public Lane[] Tick(TimeSpan tcpIdle, TimeSpan udpIdle, TimeSpan maxDrain)
    {
        lock (gate)
        {
            double elapsed = Math.Max(.001, Stopwatch.GetElapsedTime(lastTick).TotalSeconds); lastTick = Stopwatch.GetTimestamp();
            foreach (var line in lines.Values)
            {
                line.UpRate = .7 * line.UpRate + .3 * Interlocked.Exchange(ref line.UpBytes, 0) / elapsed;
                line.DownRate = .7 * line.DownRate + .3 * Interlocked.Exchange(ref line.DownBytes, 0) / elapsed;
                line.Rate = line.UpRate + line.DownRate;
            }
            foreach (var s in sessions.ToArray())
            {
                var idle = Stopwatch.GetElapsedTime(Interlocked.Read(ref s.LastActivity));
                if (s.Udp && idle >= udpIdle || s.Line.Retired is { } t &&
                   (DateTimeOffset.UtcNow - t >= maxDrain || idle >= (s.Udp ? udpIdle : tcpIdle))) s.Stop.Cancel();
            }
            return lines.Values.Where(l => l.Retired != null && l.Active == 0).Select(l => l.Lane).ToArray();
        }
    }
    public void Collected(Lane lane) { lock (gate) lines.Remove(lane.Tag); }
}

// Both levels are charged atomically. Buckets for a stable exit are shared by its old and new generations.
internal sealed class SharedRates
{
    private sealed class Bucket
    {
        public double Speed, Credit;
        private long time = Stopwatch.GetTimestamp();
        public void Refill()
        {
            long now = Stopwatch.GetTimestamp();
            Credit = Math.Min(Math.Max(8192, Speed * .05), Credit + Stopwatch.GetElapsedTime(time, now).TotalSeconds * Speed);
            time = now;
        }
        public void Set(double speed) { Refill(); if (Speed != speed) Credit = 0; Speed = speed; }
    }
    private readonly object gate = new();
    private readonly Dictionary<(string?, bool), Bucket> buckets = [];
    public void Configure(RelayPlan plan)
    {
        lock (gate)
        {
            void Set(string? id, Bandwidth limit, bool up)
            {
                if (!buckets.TryGetValue((id, up), out var b)) buckets[(id, up)] = b = new();
                b.Set(limit.Enabled ? (up ? limit.Upload : limit.Download) * 125000 : 0);
            }
            foreach (bool up in new[] { true, false })
            { Set(null, plan.Total, up); foreach (var exit in plan.Exits) Set(exit.Id, exit.Limit, up); }
        }
    }
    public async ValueTask Charge(string id, bool up, int bytes, CancellationToken token)
    {
        while (bytes > 0)
        {
            token.ThrowIfCancellationRequested();
            int piece = Math.Min(bytes, 8192);
            double wait = 0;
            lock (gate)
            {
                var total = buckets[(null, up)]; var exit = buckets[(id, up)];
                total.Refill(); exit.Refill();
                double Delay(Bucket b) => b.Speed <= 0 ? 0 : Math.Max(0, (piece - b.Credit) / b.Speed);
                wait = Math.Max(Delay(total), Delay(exit));
                if (wait <= 0) { if (total.Speed > 0) total.Credit -= piece; if (exit.Speed > 0) exit.Credit -= piece; bytes -= piece; }
            }
            if (wait > 0) await Task.Delay(TimeSpan.FromMilliseconds(Math.Clamp(wait * 1000, 1, 50)), token);
        }
    }
}
