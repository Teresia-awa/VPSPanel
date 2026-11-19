using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace VPSPanel.Core;

public sealed record ExitProfile
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Protocol { get; init; } = "HY2";
    public string Host { get; init; } = "";
    public int Port { get; init; } = 443;
    public string Sni { get; init; } = "";
    public string Secret { get; init; } = "";
    public string PublicKey { get; init; } = "";
    public string ShortId { get; init; } = "";
    public string Flow { get; init; } = "";
    public string Fingerprint { get; init; } = "chrome";
    public string[] Aliases { get; init; } = [];
    public bool Enabled { get; init; } = true;
    public bool Limited { get; init; }
    public decimal Up { get; init; }
    public decimal Down { get; init; }
    public JsonObject Original { get; init; } = new();
    public ProbeResult? LastProbe { get; init; }
    [System.Text.Json.Serialization.JsonIgnore]
    public string AliasText => Aliases.Length == 0 ? "无" : string.Join("、", Aliases);
    [System.Text.Json.Serialization.JsonIgnore]
    public string Status => !Enabled ? "草稿已停用" : LastProbe is null ? "待预检" :
        LastProbe.Passed ? $"预检通过 · {LastProbe.Milliseconds} ms" : "预检失败";
    public static bool ValidHost(string host) =>
        IPAddress.TryParse(host, out _) || (host.Length is > 0 and <= 253 &&
        host.TrimEnd('.').Split('.').All(label => Regex.IsMatch(label, @"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")));
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name) || string.IsNullOrWhiteSpace(Id) || Id.Any(char.IsControl))
            throw new PanelException("请填写出口名称和稳定 ID。");
        if (!ValidHost(Host) || Port is < 1 or > 65535 || (Sni.Length > 0 && !ValidHost(Sni)))
            throw new PanelException("请检查连接地址、端口和 TLS 名称。");
        if (Aliases.Any(h => !ValidHost(h)) || Aliases.Append(Host).Distinct(StringComparer.OrdinalIgnoreCase).Count() != Aliases.Length + 1)
            throw new PanelException("备用域名须有效、互不重复，并与当前地址不同。");
        if (Limited && (Up <= 0 || Down <= 0)) throw new PanelException("开启限速时，上下行 Mbps 均须大于零。");
        if (Protocol is not ("HY2" or "VLESS REALITY") || string.IsNullOrWhiteSpace(Secret))
            throw new PanelException("请填写支持的协议及认证信息。");
        if (Protocol == "VLESS REALITY" && (!Guid.TryParse(Secret, out _) || string.IsNullOrWhiteSpace(PublicKey)
            || ShortId.Length > 16 || ShortId.Length % 2 != 0 || !ShortId.All(Uri.IsHexDigit)))
            throw new PanelException("请检查 VLESS 用户 ID、REALITY 公钥与 Short ID。");
    }

    public JsonObject ToOutbound()
    {
        var result = Original.DeepClone().AsObject();
        result["tag"] = Id;
        var settings = Child(result, "settings");
        var stream = Child(result, "streamSettings");
        if (Protocol == "HY2")
        {
            result["protocol"] = "hysteria";
            settings["version"] = 2; settings["address"] = Host; settings["port"] = Port;
            stream["network"] = "hysteria"; stream["security"] = "tls";
            Child(stream, "tlsSettings")["serverName"] = Sni;
            var transport = Child(stream, "hysteriaSettings");
            transport["version"] = 2; transport["auth"] = Secret;
        }
        else
        {
            result["protocol"] = "vless";
            var server = settings["vnext"] is JsonArray entries ? entries[0]!.AsObject() : settings;
            server["address"] = Host; server["port"] = Port;
            var user = server["users"] is JsonArray users ? users[0]!.AsObject() : server;
            user["id"] = Secret; user["flow"] = Flow;
            if (user["encryption"] is null) user["encryption"] = "none";
            stream["security"] = "reality";
            if (stream["network"] is null && stream["method"] is null) stream["network"] = "raw";
            var tls = Child(stream, "realitySettings");
            tls["serverName"] = Sni; tls["shortId"] = ShortId; tls["fingerprint"] = Fingerprint;
            tls.Remove("publicKey"); tls["password"] = PublicKey;
        }
        return result;
    }
    internal static JsonObject Child(JsonObject o, string key)
    {
        if (o[key] is JsonObject child) return child;
        var value = new JsonObject(); o[key] = value; return value;
    }
}

public sealed record ProbeResult(bool Dns, bool Handshake, bool Request, int Milliseconds, DateTimeOffset At, string Detail)
{
    public bool Passed => Dns && Handshake && Request;
}
public class PanelException(string message) : Exception(message);
