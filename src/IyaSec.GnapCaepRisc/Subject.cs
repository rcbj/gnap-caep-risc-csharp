// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace IyaSec.Gnap;

public sealed class Person
{
    public string Sub { get; init; }
    public JsonObject Claims { get; init; }
    public bool AssertionVerified { get; init; }
    public string Iss { get; init; }
    public string Uid { get; init; }
    public bool HasUid { get; init; }
    public string Email { get; init; }
    public string Name { get; init; }
    public string PreferredUsername { get; init; }
    public string Sid { get; init; }
    public string Acr { get; init; }
    public List<string> Amr { get; init; }
}

public sealed class IdCheck
{
    public string Issuer { get; init; }
    public IReadOnlyList<string> Audiences { get; init; }
    public double Skew { get; init; }
    public Func<List<JsonObject>> Keys { get; init; }
}

public static class Subjects
{
    static readonly Regex Acct = new(@"^acct:([^@]+)@(.+)$", RegexOptions.Compiled);

    public static string UidFromAccount(string uri, out bool ok)
    {
        ok = false;
        var match = Acct.Match(uri ?? "");
        if (!match.Success) return null;
        ok = true;
        try { return Decode(match.Groups[1].Value); }
        catch { return match.Groups[1].Value; }
    }

    static string Decode(string value)
    {
        var bytes = new List<byte>();
        for (var i = 0; i < value.Length;)
        {
            if (value[i] != '%')
            {
                bytes.AddRange(Encoding.UTF8.GetBytes(value[i].ToString()));
                i++;
                continue;
            }
            if (i + 3 > value.Length) throw new FormatException("bad");
            var hex = value.Substring(i + 1, 2);
            if (!byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var b)) throw new FormatException("bad");
            bytes.Add(b);
            i += 3;
        }
        var raw = bytes.ToArray();
        var text = Encoding.UTF8.GetString(raw);
        if (Encoding.UTF8.GetBytes(text).Length != raw.Length && !text.Contains('\uFFFD') == false && Encoding.UTF8.GetByteCount(text) != raw.Length)
            throw new FormatException("bad");
        if (text.Contains('\uFFFD')) throw new FormatException("bad");
        return text;
    }

    public static Person From(JsonNode subject, IdCheck check)
    {
        var doc = JsonUtil.Obj(subject);
        if (doc == null) return null;
        var subIds = JsonUtil.Arr(doc["sub_ids"]) ?? new JsonArray();
        var issSub = Find(subIds, "iss_sub", "sub");
        var opaque = Find(subIds, "opaque", "id");
        var account = Find(subIds, "account", "uri");
        JsonObject idToken = null;
        foreach (var item in JsonUtil.Arr(doc["assertions"]) ?? new JsonArray())
        {
            var one = JsonUtil.Obj(item);
            if (one != null && JsonUtil.Str(one["format"]) == "id_token" && JsonUtil.Str(one["value"]) != null) { idToken = one; break; }
        }
        var claims = new JsonObject();
        string sub = issSub == null ? null : JsonUtil.Str(issSub["sub"]);
        string iss = issSub != null ? JsonUtil.Str(issSub["iss"]) : null;
        var verified = false;
        if (idToken != null)
        {
            if (check.Keys == null) throw new GnapException("validation", "subject key lookup must be synchronous");
            var verifiedJws = JwsVerify.Compact(JsonUtil.Str(idToken["value"]), check.Keys());
            var payload = verifiedJws.Payload;
            if (JsonUtil.Str(payload["iss"]) != check.Issuer)
                throw new GnapException("validation", "the id_token was issued by " + (JsonUtil.Str(payload["iss"]) ?? "") + ", not " + check.Issuer);
            var tokenSub = JsonUtil.Str(payload["sub"]);
            if (string.IsNullOrEmpty(tokenSub)) throw new GnapException("validation", "the id_token has no sub");
            if (!JsonUtil.TryNumber(payload["exp"], out var exp)) throw new GnapException("validation", "the id_token has no exp");
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (exp + check.Skew < now) throw new GnapException("validation", "the id_token has expired");
            if (JsonUtil.TryNumber(payload["nbf"], out var nbf) && nbf - check.Skew > now) throw new GnapException("validation", "the id_token is not valid yet");
            if (JsonUtil.TryNumber(payload["iat"], out var iat) && iat - check.Skew > now) throw new GnapException("validation", "the id_token is issued in the future");
            var aud = Strings(payload["aud"]);
            var known = (check.Audiences ?? Array.Empty<string>()).Where(a => !string.IsNullOrEmpty(a)).ToList();
            if (known.Count > 0 && !aud.Any(known.Contains))
            {
                var shown = aud.Count == 0 ? "(no audience)" : string.Join(", ", aud);
                throw new GnapException("validation", "the id_token is for " + shown + ", not " + string.Join(" or ", known));
            }
            if (!string.IsNullOrEmpty(sub) && tokenSub != sub)
                throw new GnapException("validation", "the id_token is about somebody other than the subject identifier");
            sub = tokenSub;
            iss = JsonUtil.Str(payload["iss"]);
            claims = payload;
            verified = true;
        }
        if (string.IsNullOrEmpty(sub) && opaque != null) sub = JsonUtil.Str(opaque["id"]);
        if (string.IsNullOrEmpty(sub) && account != null) sub = JsonUtil.Str(account["uri"]);
        if (string.IsNullOrEmpty(sub)) return null;
        string uid = null;
        var hasUid = false;
        if (account != null)
        {
            uid = UidFromAccount(JsonUtil.Str(account["uri"]), out hasUid);
            if (!hasUid) uid = null;
        }
        return new Person
        {
            Sub = sub, Claims = claims, AssertionVerified = verified, Iss = iss, Uid = uid, HasUid = hasUid && uid != null || hasUid,
            Email = JsonUtil.Str(claims["email"]), Name = JsonUtil.Str(claims["name"]),
            PreferredUsername = JsonUtil.Str(claims["preferred_username"]),
            Sid = JsonUtil.Str(claims["sid"]) ?? JsonUtil.Str(claims["session_id"]),
            Acr = JsonUtil.Str(claims["acr"]),
            Amr = JsonUtil.Arr(claims["amr"])?.Select(item => JsonUtil.Str(item) ?? item.ToJsonString()).ToList()
        };
    }

    static JsonObject Find(JsonArray list, string format, string field)
    {
        foreach (var item in list)
        {
            var doc = JsonUtil.Obj(item);
            if (doc != null && JsonUtil.Str(doc["format"]) == format && JsonUtil.Str(doc[field]) != null) return doc;
        }
        return null;
    }

    public static List<string> Strings(JsonNode value)
    {
        if (value == null) return new List<string>();
        if (JsonUtil.Arr(value) is JsonArray list) return list.Select(item => JsonUtil.Str(item) ?? item.ToJsonString()).ToList();
        var text = JsonUtil.Str(value);
        return text == null ? new List<string> { value.ToJsonString() } : new List<string> { text };
    }
}
