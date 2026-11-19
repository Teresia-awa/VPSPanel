using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal sealed class RelayServer(RoutingRuntime runtime)
{
    public async Task Serve(TcpListener listener, CancellationToken token)
    {
        var workers = new ConcurrentDictionary<long, Task>();
        long next = 0;
        try
        {
            while (!token.IsCancellationRequested)
            {
                var tcp = await listener.AcceptTcpClientAsync(token); tcp.NoDelay = true;
                long key = ++next;
                var work = Handle(tcp, token); workers[key] = work;
                _ = work.ContinueWith(t => workers.TryRemove(key, out var _), TaskScheduler.Default);
            }
        }
        finally { listener.Stop(); await Task.WhenAll(workers.Values); }
    }
    private static Task Reply(Stream s, byte code, int port, CancellationToken ct) =>
        s.WriteAsync(new byte[] { 5, code, 0, 1, 127, 0, 0, 1, (byte)(port >> 8), (byte)port }, ct).AsTask();
    private async Task Handle(TcpClient client, CancellationToken token)
    {
        using (client)
        using (var init = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            init.CancelAfter(TimeSpan.FromSeconds(10));
            var stream = client.GetStream();
            bool pending = false;
            try
            {
                var hello = await Socks.Read(stream, 2, init.Token);
                if (hello[0] != 5) return;
                bool allowed = (await Socks.Read(stream, hello[1], init.Token)).Contains((byte)0);
                await stream.WriteAsync(new byte[] { 5, allowed ? (byte)0 : (byte)255 }, init.Token);
                if (!allowed) return;
                var request = await Socks.Read(stream, 3, init.Token);
                if (request[0] != 5 || request[2] != 0) return;
                var dest = await Socks.Address(stream, init.Token); pending = true;
                if (request[1] == 3)
                {
                    using var incoming = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                    await Reply(stream, 0, ((IPEndPoint)incoming.Client.LocalEndPoint!).Port, init.Token); pending = false;
                    await Associate(stream, incoming, dest, token); return;
                }
                if (request[1] != 1) { await Reply(stream, 7, 0, init.Token); return; }
                using var lease = runtime.Open(dest.Host, false, token);
                var ct = lease.Stop.Token;
                TcpClient upstream;
                try { (upstream, _) = await Socks.Connect(lease.Line.Lane.Port, 1, dest, ct); }
                catch { runtime.Observe(lease.Line.Lane.Tag, false, null); throw; }
                using (upstream)
                {
                    runtime.Observe(lease.Line.Lane.Tag, true, null);
                    await Reply(stream, 0, 0, ct); pending = false;
                    var up = Pump(client, upstream, true, lease);
                    var down = Pump(upstream, client, false, lease);
                    await Task.WhenAll(up, down);
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { if (pending && !token.IsCancellationRequested) try { await Reply(stream, 1, 0, token); } catch (IOException) { } }
        }
    }
    private async Task Pump(TcpClient from, TcpClient to, bool up, Lease lease)
    {
        var ct = lease.Stop.Token;
        var buf = new byte[8192];
        try
        {
            var src = from.GetStream(); var dst = to.GetStream(); int n;
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                await runtime.Rates.Charge(lease.Line.Lane.Id, up, n, ct);
                await dst.WriteAsync(buf.AsMemory(0, n), ct); lease.Bytes(n, up);
            }
            to.Client.Shutdown(SocketShutdown.Send);
        }
        catch { lease.Stop.Cancel(); throw; }
    }

    private async Task Associate(Stream control, UdpClient incoming, Destination hint, CancellationToken token)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
        var ct = stop.Token;
        async Task Monitor() { try { await control.ReadExactlyAsync(new byte[1], ct); } catch (IOException) { } finally { stop.Cancel(); } }
        var monitor = Monitor();
        var mappings = new ConcurrentDictionary<Destination, UdpFlow>();
        IPEndPoint? sender = null;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await incoming.ReceiveAsync(ct);
                if (!IPAddress.IsLoopback(packet.RemoteEndPoint.Address) || hint.Port != 0 && hint.Port != packet.RemoteEndPoint.Port ||
                    sender != null && !packet.RemoteEndPoint.Equals(sender)) continue;
                var data = packet.Buffer;
                if (data.Length < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0) continue;
                Destination dest; int header;
                try { dest = Destination.Decode(data.AsSpan(3), out header); } catch (InvalidDataException) { continue; }
                sender ??= packet.RemoteEndPoint;
                try
                {
                    if (!mappings.TryGetValue(dest, out var flow))
                    {
                        var lease = runtime.Open(dest.Host, true, ct);
                        try
                        {
                            var (tcp, bound) = await Socks.Connect(lease.Line.Lane.Port, 3, new("0.0.0.0", 0), lease.Stop.Token);
                            flow = new(tcp, bound, lease); mappings[dest] = flow;
                            flow.Completion = Return(flow, dest, sender, incoming, mappings);
                        }
                        catch { runtime.Observe(lease.Line.Lane.Tag, false, null); lease.Dispose(); throw; }
                    }
                    int bytes = data.Length - 3 - header;
                    await runtime.Rates.Charge(flow.Lease.Line.Lane.Id, true, bytes, flow.Lease.Stop.Token);
                    await flow.Socket.SendAsync(data, flow.Lease.Stop.Token);
                    flow.Lease.Bytes(bytes, true);
                }
                catch (Exception ex) when (ex is PanelException or IOException or SocketException or OperationCanceledException or ObjectDisposedException)
                { /* RFC 1928 has no per-datagram failure reply. Drop, never send directly. */ }
            }
        }
        finally { stop.Cancel(); await Task.WhenAll(mappings.Values.Select(f => f.Completion).Append(monitor)); }
    }
    private sealed class UdpFlow
    {
        public TcpClient Control { get; }
        public Lease Lease { get; }
        public UdpClient Socket { get; }
        public Task Completion = Task.CompletedTask;
        public UdpFlow(TcpClient tcp, Destination bound, Lease lease)
        {
            Control = tcp; Lease = lease;
            try
            {
                if (!IPAddress.TryParse(bound.Host, out var ip) || (!ip.Equals(IPAddress.Any) && !IPAddress.IsLoopback(ip)) || bound.Port == 0)
                    throw new IOException("上游 UDP 回环端点无效。");
                Socket = new UdpClient(AddressFamily.InterNetwork);
                Socket.Connect(IPAddress.Loopback, bound.Port);
            }
            catch { tcp.Dispose(); throw; }
        }
    }
    private async Task Return(UdpFlow flow, Destination dest, IPEndPoint sender, UdpClient incoming, ConcurrentDictionary<Destination, UdpFlow> mappings)
    {
        var ct = flow.Lease.Stop.Token;
        async Task WatchControl() { try { await flow.Control.GetStream().ReadExactlyAsync(new byte[1], ct); } catch (Exception ex) when (ex is IOException or OperationCanceledException) { } finally { flow.Lease.Stop.Cancel(); } }
        var watch = WatchControl();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await flow.Socket.ReceiveAsync(ct);
                var data = packet.Buffer;
                if (data.Length < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0) continue;
                Destination.Decode(data.AsSpan(3), out int size);
                int bytes = data.Length - 3 - size;
                await runtime.Rates.Charge(flow.Lease.Line.Lane.Id, false, bytes, ct);
                await incoming.SendAsync(data, sender, ct); flow.Lease.Bytes(bytes, false);
            }
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException or ObjectDisposedException or InvalidDataException) { }
        finally
        {
            mappings.TryRemove(new KeyValuePair<Destination, UdpFlow>(dest, flow));
            flow.Lease.Stop.Cancel(); await watch; flow.Socket.Dispose(); flow.Control.Dispose(); flow.Lease.Dispose();
        }
    }
}
