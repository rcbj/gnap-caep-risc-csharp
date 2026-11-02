// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace IyaSec.Gnap;

public static class Proofs
{
    public static string InteractionHash(string clientNonce, string serverNonce, string interactRef, string grantEndpoint)
        => JsonUtil.B64Url(JsonUtil.Sha256(Encoding.UTF8.GetBytes(clientNonce + "\n" + serverNonce + "\n" + interactRef + "\n" + grantEndpoint)));

    public static Dictionary<string, string> SignRequest(ClientKey key, string method, string rawUrl, IDictionary<string, string> headers, string body)
    {
        var href = Urls.Href(rawUrl);
        var lower = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (headers != null)
            foreach (var pair in headers) lower[pair.Key.ToLowerInvariant()] = pair.Value;
        var components = new List<string> { "@method", "@target-uri" };
        var added = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(body))
        {
            added["content-digest"] = "sha-256=:" + JsonUtil.B64Std(JsonUtil.Sha256(Encoding.UTF8.GetBytes(body))) + ":";
            lower["content-digest"] = added["content-digest"];
            components.Add("content-digest");
        }
        if (lower.ContainsKey("authorization")) components.Add("authorization");
        var nonce = new byte[16];
        RandomNumberGenerator.Fill(nonce);
        var serialised = "(" + string.Join(" ", components.Select(c => "\"" + c + "\"")) + ");created=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            + ";nonce=" + Sf(JsonUtil.B64Url(nonce)) + ";keyid=" + Sf(key.Kid) + ";tag=\"gnap\"";
        var lines = new List<string>();
        foreach (var component in components)
        {
            string value = component switch
            {
                "@method" => method.ToUpperInvariant(),
                "@target-uri" => href,
                _ => lower[component].Trim()
            };
            lines.Add("\"" + component + "\": " + value);
        }
        lines.Add("\"@signature-params\": " + serialised);
        var signature = Keys.Sign(key, Encoding.UTF8.GetBytes(string.Join("\n", lines)));
        added["signature-input"] = "sig1=" + serialised;
        added["signature"] = "sig1=:" + JsonUtil.B64Std(signature) + ":";
        return added;
    }

    public static string DetachedJws(ClientKey key, string method, string rawUrl, string body, string token)
    {
        var header = new JsonObject
        {
            ["alg"] = key.Alg,
            ["created"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["htm"] = method.ToUpperInvariant(),
            ["kid"] = key.Kid,
            ["typ"] = "gnap-binding-jwsd",
            ["uri"] = Urls.Href(rawUrl)
        };
        if (!string.IsNullOrEmpty(token)) header["ath"] = JsonUtil.B64Url(JsonUtil.Sha256(Encoding.ASCII.GetBytes(token)));
        var encoded = JsonUtil.B64Url(Encoding.UTF8.GetBytes(JsonUtil.Dump(header)));
        var payload = string.IsNullOrEmpty(body) ? "" : JsonUtil.B64Url(JsonUtil.Sha256(Encoding.UTF8.GetBytes(body)));
        var signature = Keys.Sign(key, Encoding.ASCII.GetBytes(encoded + "." + payload));
        return encoded + "." + payload + "." + JsonUtil.B64Url(signature);
    }

    static string Sf(string value) => "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
}

public static class Urls
{
    public static string Origin(string raw)
    {
        var uri = Absolute(raw);
        return uri.Scheme + "://" + HostPort(uri);
    }

    public static string Href(string raw)
    {
        var uri = Absolute(raw);
        var path = string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath;
        var query = uri.Query;
        return uri.Scheme + "://" + HostPort(uri) + path + query;
    }

    public static bool IsLoopback(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)) return false;
        var host = uri.Host.Trim('[', ']').ToLowerInvariant();
        return host == "localhost" || host == "127.0.0.1" || host == "::1";
    }

    public static IReadOnlyList<string> WellKnown(string issuer, string suffix)
    {
        var uri = Absolute(issuer);
        var origin = uri.Scheme + "://" + HostPort(uri);
        var path = uri.AbsolutePath.TrimEnd('/');
        if (path == "/") path = "";
        var inserted = origin + "/.well-known/" + suffix + path;
        var appended = origin + path + "/.well-known/" + suffix;
        return inserted == appended ? new[] { inserted } : new[] { inserted, appended };
    }

    static Uri Absolute(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https") || string.IsNullOrEmpty(uri.Host))
            throw new GnapException("validation", raw + " is not a URL");
        return uri;
    }

    static string HostPort(Uri uri)
    {
        var host = uri.Host.Contains(':') && !uri.Host.StartsWith('[') ? "[" + uri.IdnHost + "]" : uri.Host;
        if (uri.IsDefaultPort) return host;
        return host + ":" + uri.Port;
    }
}
