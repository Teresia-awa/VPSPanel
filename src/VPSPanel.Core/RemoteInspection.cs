using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace VPSPanel.Core;

public sealed record LiveRead(string Version, string Binary, string ConfigPath, XraySnapshot Snapshot, bool Sftp, string WorkingDirectory, string RawJson);

public sealed class RemoteInspection(ISshTransport ssh)
{
    private const string Discover = """
        set -eu
        pid=$(systemctl show --property=MainPID --value "$1")
        case "$pid" in ''|0|*[!0-9]*) exit 1;; esac
        bin=$(readlink -f "/proc/$pid/exe")
        case "${bin##*/}" in xray|xray-*|Xray) ;; *) exit 1;; esac
        "$bin" version | head -n 1
        printf '%s\n' "$bin"
        readlink -f "/proc/$pid/cwd"
        base64 -w0 "/proc/$pid/cmdline"
        """;
    public async Task<LiveRead> Read(SshTarget target, CancellationToken token)
    {
        target.Validate();
        string meta = await ssh.Command("sh -s -- " + OpenSsh.Quote(target.Service), Discover.ReplaceLineEndings("\n") + "\n", token);
        var data = meta.TrimEnd().Split('\n');
        if (data.Length != 4 || !data[0].StartsWith("Xray ", StringComparison.OrdinalIgnoreCase))
            throw new PanelException("未找到活动 Xray 服务或内核版本。");
        string[] args = Encoding.UTF8.GetString(Convert.FromBase64String(data[3])).Split('\0', StringSplitOptions.RemoveEmptyEntries);
        string file = ConfigurationPath(args, data[2].TrimEnd('\r'));
        var (json, sftp) = await ssh.ReadConfiguration(file, token);
        return new(data[0].Split(' ', StringSplitOptions.RemoveEmptyEntries)[1], data[1].TrimEnd('\r'), file, XraySnapshot.Parse(json), sftp, data[2].TrimEnd('\r'), json);
    }
    public static string ConfigurationPath(string[] args, string cwd)
    {
        var files = new List<string>();
        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i].TrimStart('-');
            if (arg == "confdir" || arg.StartsWith("confdir=")) throw new PanelException("检测到配置目录，本阶段只读接管需要单一活动 JSON 文件。");
            if (arg is "c" or "config") { if (++i >= args.Length) break; files.Add(args[i]); }
            else if (arg.StartsWith("c=") || arg.StartsWith("config=")) files.Add(arg[(arg.IndexOf('=') + 1)..]);
        }
        if (files.Count != 1 || files[0].Any(char.IsControl) || files[0].Contains(':') || !cwd.StartsWith('/'))
            throw new PanelException("无法确定唯一活动配置文件，请核对服务启动参数。");
        return files[0].StartsWith('/') ? files[0] : cwd.TrimEnd('/') + "/" + files[0];
    }

    // The private Unix socket and child process exist only for this single check.
    // The candidate JSON is supplied on stdin and is never written to a remote file.
    private const string ProbeShell = """
        set -eu
        umask 077
        cd -- "$6"
        dir=$(mktemp -d)
        child=''
        reader=''
        tidy() {
            for pid in "$child" "$reader"; do
                [ -z "$pid" ] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
            done
            rm -f -- "$dir/probe.sock" "$dir/events" "$dir/connected"
            rmdir -- "$dir" 2>/dev/null || true
        }
        trap tidy EXIT
        trap 'exit 1' HUP INT TERM
        sock="$dir/probe.sock"
        candidate=$(cat)
        mode=$7
        if [ -f /var/lib/vpspanel/committed.json ]; then
            active=$(python3 -c 'import json; print("managed" if json.load(open("/var/lib/vpspanel/committed.json"))["Plan"].get("ManagedDohResolvers") is not None else "existing")') || exit 1
            if [ "$active" = managed ]; then mode=managed; fi
        fi
        if [ "$mode" = managed ]; then
            if ! candidate=$(printf '%s' "$candidate" | /var/lib/vpspanel/relay prepare-probe /var/lib/vpspanel 2>/dev/null) || [ "$candidate" = existing ]; then
                printf 'DNS_FAIL\n'; exit 0
            fi
        elif ! getent ahosts "$2" >/dev/null; then printf 'DNS_FAIL\n'; exit 0; fi
        printf 'DNS_OK\n'
        destination=$3
        port=$4
        build() { printf '{"log":{"loglevel":"info"},"inbounds":[{"listen":"%s","protocol":"tunnel","settings":{"rewriteAddress":"%s","rewritePort":%s,"allowedNetwork":"tcp"}}],"outbounds":[%s]}' "$sock" "$destination" "$port" "$candidate"; }
        if ! build | "$1" run -test -format json -c stdin: >/dev/null 2>&1; then printf 'CONFIG_FAIL\n'; exit 0; fi
        mkfifo "$dir/events"
        while IFS= read -r line; do
            case "$line" in *"proxy/hysteria: tunneling request to "*|*"proxy/vless/outbound: tunneling request to "*) : >"$dir/connected";; esac
        done <"$dir/events" & reader=$!
        build | "$1" run -format json -c stdin: >"$dir/events" 2>&1 & child=$!
        for t in $(seq 1 100); do [ -S "$sock" ] && break; kill -0 "$child" 2>/dev/null || break; sleep 0.04; done
        if [ ! -S "$sock" ]; then printf 'START_FAIL\n'; exit 0; fi
        curl -q --noproxy '*' --unix-socket "$sock" --proto '=https' --connect-timeout 8 --max-time 12 --silent --output /dev/null --write-out 'TLS=%{time_appconnect}\nHTTP=%{http_code}\nTOTAL=%{time_total}\n' "$5" || true
        if [ -f "$dir/connected" ]; then printf 'UPSTREAM_OK\n'; fi
        """;
    public async Task<ProbeResult> Probe(string binary, string workingDirectory, ExitProfile exit, CancellationToken token, Uri? checkUrl = null, bool managedDns = false)
    {
        exit.Validate();
        var url = checkUrl ?? new Uri("https://www.gstatic.com/generate_204");
        if (!binary.StartsWith('/') || binary.Any(char.IsControl) || !workingDirectory.StartsWith('/') || workingDirectory.Any(char.IsControl)
            || url.Scheme != "https" || !ExitProfile.ValidHost(url.IdnHost) || url.UserInfo.Length > 0)
            throw new PanelException("预检目标或内核路径无效。");
        var script = Convert.ToBase64String(Encoding.UTF8.GetBytes(ProbeShell.ReplaceLineEndings("\n")));
        var command = "timeout -k 3 32 sh -c \"$(printf %s " + script + " | base64 -d)\" probe " + string.Join(" ", new[] { binary, exit.Host, url.IdnHost, url.Port.ToString(), url.AbsoluteUri, workingDirectory, managedDns ? "managed" : "existing" }.Select(OpenSsh.Quote));
        var outbound = exit.ToOutbound();
        if (outbound["streamSettings"]?["tlsSettings"] is JsonObject tlsOptions) tlsOptions.Remove("masterKeyLog");
        if (outbound["streamSettings"]?["realitySettings"] is JsonObject realityOptions) realityOptions.Remove("masterKeyLog");
        string result = await ssh.Command(command, outbound.ToJsonString(), token);
        var lines = result.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        bool dns = lines.Contains("DNS_OK");
        double Number(string key) => double.TryParse(lines.FirstOrDefault(s => s.StartsWith(key))?[key.Length..], NumberStyles.Float, CultureInfo.InvariantCulture, out var n) ? n : 0;
        bool tls = Number("TLS=") > 0;
        bool handshake = lines.Contains("UPSTREAM_OK") || tls, request = tls && lines.Contains("HTTP=204");
        string detail = !dns ? "候选地址解析失败" : lines.Contains("CONFIG_FAIL") ? "候选配置静态校验失败" : lines.Contains("START_FAIL") ? "候选进程未就绪" :
            !handshake ? "候选上游握手未完成，请检查节点认证、证书及连通性" : !request ? "已连接上游，代理请求未通过 HTTPS 204 检查" : "三项预检通过";
        return new(dns, handshake, request, (int)(Number("TOTAL=") * 1000), DateTimeOffset.Now, detail);
    }
}
