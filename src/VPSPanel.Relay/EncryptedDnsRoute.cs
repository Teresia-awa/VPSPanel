using System.Net;
using System.Text.Json.Nodes;
using VPSPanel.Core;

namespace VPSPanel.Relay;

internal sealed record EncryptedDnsRoute(string InboundTag)
{
    internal const string Tag = "vpspanel-encrypted-dns";
    internal const string Asset = "vpspanel-bootstrap.dat";
    internal const string VerificationTag = Tag + "-generation";
    internal const string UnmatchedTag = Tag + "-unmatched";
    internal const string LoopbackAddress = "127.0.0.2";
    internal const string PlaintextLoopback = "127.0.0.3";
    private const string PlaintextId = "vpspanel-plaintext-dns";

    internal static JsonObject ManagedConfiguration(RelayPlan plan)
    {
        var servers = new JsonArray();
        foreach (var url in DohResolvers.Validate(plan.ManagedDohResolvers ?? []))
            servers.Add(url);
        foreach (var url in DohResolvers.Validate(plan.BootstrapDohResolvers ?? DohResolvers.Domestic, true))
            servers.Add(new JsonObject { ["address"] = url, ["skipFallback"] = true,
                ["domains"] = new JsonArray("ext:" + Asset + ":bindings") });
        return new JsonObject { ["tag"] = Tag + "-queries", ["servers"] = servers,
            ["disableFallbackIfMatch"] = true, ["disableCache"] = true, ["useSystemHosts"] = false };
    }

    internal static EncryptedDnsRoute Read(JsonObject config)
    {
        if (config["dns"] is not JsonObject dns || dns["tag"] is not JsonValue tagValue ||
            !tagValue.TryGetValue<string>(out var tag) || string.IsNullOrWhiteSpace(tag) ||
            dns["servers"] is not JsonArray { Count: > 0 } servers)
            throw new PanelException("当前 Xray 缺少带标签的 DoH 配置。");

        if (dns["script"]?.ToString() is { Length: > 0 })
            throw new PanelException("跟随健康上游需要使用 Xray 的标准 DoH 解析配置。");

        bool hasProxy = false;
        foreach (var server in servers)
        {
            if (IsManagedPlaintext(server)) continue; // compatibility with the previous generation
            if (server is JsonObject local && local["skipFallback"]?.GetValue<bool>() == true &&
                local["address"]?.ToString().StartsWith("https+local://", StringComparison.Ordinal) == true) continue;
            var options = server as JsonObject;
            if (options?["tag"]?.ToString() is { Length: > 0 } serverTag && serverTag != tag)
                throw new PanelException("DoH 服务器自定义的路由标签与 Xray DNS 标签不一致。");
            var address = options is null ? server : options["address"];
            if (address is not JsonValue value || !value.TryGetValue<string>(out var text) ||
                !Uri.TryCreate(text, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
                !string.IsNullOrEmpty(uri.UserInfo) || !IPAddress.TryParse(uri.IdnHost.Trim('[', ']'), out var ip) ||
                IPAddress.IsLoopback(ip))
                throw new PanelException("跟随健康上游需要用 IP 地址配置 DoH，所有解析器必须使用 HTTPS。");
            hasProxy = true;
        }
        if (!hasProxy) throw new PanelException("Xray 缺少 HTTPS DNS 解析器。");
        return new(tag);
    }

    private static bool IsManagedPlaintext(JsonNode? server) =>
        server is JsonObject options && options["id"]?.ToString() == PlaintextId &&
        Uri.TryCreate(options["address"]?.ToString(), UriKind.Absolute, out var uri) &&
        uri.Scheme == "tcp+local" && uri.Host == PlaintextLoopback;

    private static void RemovePlaintextFallback(JsonArray servers)
    {
        for (int i = servers.Count - 1; i >= 0; i--)
            if (IsManagedPlaintext(servers[i])) servers.RemoveAt(i);
    }

    internal static JsonObject? OriginalDns(JsonNode? value)
    {
        var original = value?.DeepClone().AsObject();
        if (original?["servers"] is JsonArray servers) RemovePlaintextFallback(servers);
        return original;
    }

    internal static JsonObject Outbound(int port) => new()
    {
        ["tag"] = Tag, ["protocol"] = "socks",
        ["settings"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["address"] = LoopbackAddress, ["port"] = port }) }
    };

    internal JsonObject Rule() => new()
    {
        ["type"] = "field", ["ruleTag"] = Tag,
        ["inboundTag"] = new JsonArray(InboundTag), ["outboundTag"] = Tag
    };
}
