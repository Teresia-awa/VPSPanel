using System.Text.Json.Nodes;

namespace VPSPanel.Core;

public static class ShareLink
{
    public static ExitProfile Parse(string input)
    {
        if (!Uri.TryCreate(input.Trim(), UriKind.Absolute, out var uri) || uri.UserInfo.Length == 0 ||
            uri.AbsolutePath is not ("" or "/") || uri.Scheme is not ("hy2" or "hysteria2" or "vless"))
            throw new PanelException("请输入单节点 HY2 或 VLESS REALITY 分享链接。");
        var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length != 2 || !q.TryAdd(Uri.UnescapeDataString(parts[0]), Uri.UnescapeDataString(parts[1])))
                throw new PanelException("链接参数缺失或重复。");
        }
        string Get(string key, string fallback = "") => q.GetValueOrDefault(key, fallback);
        string host = uri.IdnHost.Trim('[', ']');
        var p = new ExitProfile
        {
            Id = "exit-" + Guid.NewGuid().ToString("N")[..8],
            Name = uri.Fragment.Length > 1 ? Uri.UnescapeDataString(uri.Fragment[1..]) : host,
            Host = host,
            Port = uri.Port < 0 ? 443 : uri.Port,
            Sni = Get("sni", host),
            Secret = Uri.UnescapeDataString(uri.UserInfo)
        };
        if (uri.Scheme == "vless")
        {
            if (Get("security") != "reality" || Get("type", "tcp") is not ("tcp" or "raw") || Get("encryption", "none") != "none")
                throw new PanelException("链接导入支持 RAW/TCP VLESS REALITY。其他传输需保留原配置。");
            CheckKeys(q, ["security", "type", "encryption", "sni", "pbk", "sid", "spx", "flow", "fp", "headerType"]);
            if (Get("headerType", "none") != "none") throw new PanelException("此链接包含未支持的传输头。");
            p = p with { Protocol = "VLESS REALITY", PublicKey = Get("pbk"), ShortId = Get("sid"), Flow = Get("flow"), Fingerprint = Get("fp", "chrome") };
            if (q.ContainsKey("spx")) p.Original["streamSettings"] = new JsonObject { ["realitySettings"] = new JsonObject { ["spiderX"] = Get("spx") } };
        }
        else
        {
            CheckKeys(q, ["sni", "insecure", "pinSHA256", "obfs", "obfs-password", "ech"]);
            var insecure = Get("insecure", "0");
            if (insecure is not ("0" or "false" or "1" or "true")) throw new PanelException("HY2 证书校验参数无效。");
            string pin = Get("pinSHA256").Replace(":", "");
            if (q.ContainsKey("pinSHA256") && (pin.Length != 64 || !pin.All(Uri.IsHexDigit))) throw new PanelException("HY2 证书指纹须为 SHA-256。");
            if (insecure is "1" or "true" && pin.Length == 0) throw new PanelException("当前锁定内核已移除跳过证书校验，请提供证书指纹或启用证书验证。");
            var stream = ExitProfile.Child(p.Original, "streamSettings");
            var tls = ExitProfile.Child(stream, "tlsSettings");
            if (pin.Length > 0) tls["pinnedPeerCertSha256"] = pin;
            if (q.ContainsKey("ech")) tls["echConfigList"] = Get("ech");
            if (q.ContainsKey("obfs") || q.ContainsKey("obfs-password"))
            {
                if (Get("obfs") is not ("salamander" or "gecko") || Get("obfs-password").Length == 0)
                    throw new PanelException("请检查 HY2 混淆类型与口令。");
                var args = new JsonObject { ["password"] = Get("obfs-password") };
                if (Get("obfs") == "gecko") args["packetSize"] = "512-1200";
                stream["finalmask"] = new JsonObject { ["udp"] = new JsonArray(new JsonObject { ["type"] = "salamander", ["settings"] = args }) };
            }
        }
        p.Validate(); return p;
    }
    private static void CheckKeys(Dictionary<string, string> query, string[] allowed)
    {
        if (query.Keys.Except(allowed, StringComparer.OrdinalIgnoreCase).Any())
            throw new PanelException("链接含未支持的参数，已停止导入以保留原有连接行为。");
    }
}
