// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace IyaSec.Gnap;

public sealed class VerifiedJws
{
    public JsonObject Header { get; init; }
    public JsonObject Payload { get; init; }
}

public static class JwsVerify
{
    static readonly (string Alg, string Kty)[] Algs =
    {
        ("RS256", "RSA"), ("RS384", "RSA"), ("RS512", "RSA"),
        ("PS256", "RSA"), ("PS384", "RSA"), ("PS512", "RSA"),
        ("ES256", "EC"), ("ES384", "EC"), ("ES512", "EC"),
        ("EdDSA", "OKP"), ("Ed25519", "OKP")
    };
    static readonly Regex B64 = new(@"^[A-Za-z0-9_-]*$", RegexOptions.Compiled);

    public static VerifiedJws Compact(string token, IReadOnlyList<JsonObject> keys)
    {
        var parts = (token ?? "").Split('.');
        if (parts.Length != 3 || parts.Any(string.IsNullOrEmpty))
            throw new GnapException("signature", "the token is not a compact JWS");
        JsonObject header;
        JsonObject payload;
        try
        {
            header = JsonUtil.Obj(JsonUtil.Parse(Encoding.UTF8.GetString(Strict(parts[0], "header"))));
            payload = JsonUtil.Obj(JsonUtil.Parse(Encoding.UTF8.GetString(Strict(parts[1], "payload"))));
        }
        catch (GnapException) { throw; }
        catch (Exception err) { throw new GnapException("signature", "the token's header or payload is not JSON", err); }
        if (header == null || payload == null) throw new GnapException("signature", "the token's header or payload is not a JSON object");
        var alg = JsonUtil.Str(header["alg"]) ?? "";
        var spec = Algs.FirstOrDefault(item => item.Alg == alg);
        if (spec.Alg == null)
        {
            var shown = alg == "" ? "(no alg)" : alg;
            throw new GnapException("signature", "the token is signed with " + shown + ", which this client does not verify (" + string.Join(", ", Algs.Select(a => a.Alg)) + ")");
        }
        if (header.ContainsKey("crit"))
            throw new GnapException("signature", "the token's header has a crit member this client does not understand");
        var kid = JsonUtil.Str(header["kid"]);
        var candidates = new List<JsonObject>();
        foreach (var key in keys)
        {
            if (kid != null && JsonUtil.Str(key["kid"]) != kid) continue;
            if (JsonUtil.Str(key["kty"]) != spec.Kty) continue;
            var use = JsonUtil.Str(key["use"]);
            if (!string.IsNullOrEmpty(use) && use != "sig") continue;
            var keyAlg = JsonUtil.Str(key["alg"]);
            if (!string.IsNullOrEmpty(keyAlg) && keyAlg != alg) continue;
            candidates.Add(key);
        }
        if (candidates.Count == 0)
            throw new GnapException("signature", "no " + spec.Kty + " signing key" + (kid == null ? "" : " with kid " + kid) + " was published");
        var signature = Strict(parts[2], "signature");
        var data = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        foreach (var jwk in candidates)
        {
            try { if (Keys.Verify(jwk, alg, data, signature)) return new VerifiedJws { Header = header, Payload = payload }; }
            catch (GnapException) { }
        }
        throw new GnapException("signature", "the token's signature does not verify against the published keys");
    }

    static byte[] Strict(string value, string what)
    {
        if (value == null || !B64.IsMatch(value)) throw new GnapException("signature", "the JWS " + what + " is not base64url");
        try { return JsonUtil.B64UrlDecode(value); }
        catch { throw new GnapException("signature", "the JWS " + what + " is not base64url"); }
    }
}
