// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json.Nodes;

namespace IyaSec.Gnap;

public sealed class Display
{
    public string Name { get; init; }
    public string Uri { get; init; }
}

public sealed class SsfConfig
{
    public string Transmitter { get; init; }
    public int PollIntervalMs { get; init; }
}

public sealed class Config
{
    public string GrantEndpoint { get; init; }
    public string IdTokenIssuer { get; init; }
    public string Application { get; init; }
    public string ClassId { get; init; }
    public Display Display { get; init; }
    public List<JsonNode> Access { get; init; }
    public bool? Signals { get; init; }
    public List<string> SubIdFormats { get; init; }
    public List<string> AssertionFormats { get; init; }
    public ClientKey Key { get; init; }
    public string FinishUri { get; init; }
    public string FinishMethod { get; init; }
    public List<string> InteractionStart { get; init; }
    public string HashMethod { get; init; }
    public bool RequireBoundTokens { get; init; }
    public bool UseInstanceId { get; init; }
    public string TlsCa { get; init; }
    public bool AllowInsecure { get; init; }
    public double ClockToleranceSec { get; init; }
    public double MaxWaitSec { get; init; }
    public double TransactionTtlSec { get; init; }
    public SsfConfig Ssf { get; init; }
}

public static class ConfigLoader
{
    public static Config Resolve(JsonObject raw, string baseDir)
    {
        if (raw == null) throw new GnapException("config", "the configuration must be a JSON object");
        if (raw.ContainsKey("signals") && raw["signals"] is not JsonValue sigValue || (raw.ContainsKey("signals") && !IsBool(raw["signals"])))
            throw new GnapException("config", "signals must be true or false");
        var signalsOff = raw["signals"] is JsonValue flag && flag.TryGetValue<bool>(out var on) && !on;
        var application = (JsonUtil.Str(raw["application"]) ?? "").Trim();
        if (application == "") throw new GnapException("config", "application is required: the registered GNAP client");
        var grantRaw = (JsonUtil.Str(raw["grantEndpoint"]) ?? "").Trim();
        if (grantRaw == "") throw new GnapException("config", "grantEndpoint is required");
        var allowInsecure = raw["allowInsecure"] is JsonValue insecure && insecure.TryGetValue<bool>(out var allow) && allow;
        var grantEndpoint = CheckUrl(grantRaw, "grantEndpoint", allowInsecure);
        var issuer = (JsonUtil.Str(raw["idTokenIssuer"]) ?? "").Trim().TrimEnd('/');
        if (issuer == "") issuer = Urls.Origin(grantEndpoint).TrimEnd('/');
        if (!issuer.StartsWith("https://") && !issuer.StartsWith("http://"))
            throw new GnapException("config", "idTokenIssuer must be an http(s) URL");
        var proof = (JsonUtil.Str(raw["keyProof"]) ?? "").Trim();
        if (proof != "" && !Keys.Proofs.Contains(proof))
            throw new GnapException("config", "keyProof must be " + string.Join(", ", Keys.Proofs) + ", not " + proof);
        if (JsonUtil.Str(raw["privateKey"]) == null) throw new GnapException("config", "privateKey is required");
        var privateKey = KeyValue(JsonUtil.Str(raw["privateKey"]), baseDir, "the private key");
        string certificate = null;
        if (!string.IsNullOrEmpty(JsonUtil.Str(raw["certificate"])))
            certificate = KeyValue(JsonUtil.Str(raw["certificate"]), baseDir, "the certificate");
        var key = Keys.Load(privateKey, certificate, proof);
        if (key.Proof == "mtls" && !grantEndpoint.StartsWith("https://"))
            throw new GnapException("config", "mutual TLS needs an https grant endpoint");
        var finishMethod = JsonUtil.Str(raw["finishMethod"]) ?? "redirect";
        if (finishMethod != "redirect" && finishMethod != "push")
            throw new GnapException("config", "finishMethod must be redirect or push");
        var finishRaw = (JsonUtil.Str(raw["finishUri"]) ?? "").Trim();
        string finishUri = null;
        if (finishRaw != "") finishUri = CheckUrl(finishRaw, "finishUri", allowInsecure || Urls.IsLoopback(finishRaw));
        var hash = JsonUtil.Str(raw["hashMethod"]) ?? "sha-256";
        if (hash != "sha-256") throw new GnapException("config", "hashMethod must be sha-256");
        List<string> interaction;
        if (!raw.ContainsKey("interactionStart") || raw["interactionStart"] == null) interaction = new List<string> { "redirect" };
        else
        {
            var list = JsonUtil.Arr(raw["interactionStart"]);
            if (list == null || list.Count == 0) throw new GnapException("config", "interactionStart must name at least one mode");
            interaction = list.Select(item => JsonUtil.Str(item)).ToList();
            if (interaction.Any(string.IsNullOrEmpty)) throw new GnapException("config", "interactionStart must name at least one mode");
        }
        List<JsonNode> requested;
        if (!raw.ContainsKey("access") || raw["access"] == null) requested = new List<JsonNode> { "ssf.read", "ssf.manage" };
        else
        {
            var list = JsonUtil.Arr(raw["access"]);
            if (list == null) throw new GnapException("config", "access must list at least one right");
            requested = list.ToList();
        }
        var access = signalsOff ? requested.Where(right => !SsfRight(right)).ToList() : requested.ToList();
        if (access.Count == 0)
            throw new GnapException("config", signalsOff
                ? "signals is false and access has no rights left after ssf.read and ssf.manage were removed; the caller must name a right this authorization server grants"
                : "access must list at least one right");
        var tlsCa = raw["tlsCa"] == null ? "" : ReadTrust(JsonUtil.Str(raw["tlsCa"]), baseDir);
        SsfConfig ssf = null;
        if (!signalsOff)
        {
            var rawSsf = JsonUtil.Obj(raw["ssf"]);
            var transmitter = rawSsf?["transmitter"] != null ? JsonUtil.Str(rawSsf["transmitter"]) : JsonUtil.Str(raw["transmitterIssuer"]);
            transmitter = (transmitter ?? "").TrimEnd('/');
            if (transmitter != "")
            {
                if (!transmitter.StartsWith("https://") && !transmitter.StartsWith("http://"))
                    throw new GnapException("config", "ssf.transmitter must be an http(s) URL");
                var interval = 0;
                if (rawSsf != null && JsonUtil.TryNumber(rawSsf["pollIntervalMs"], out var ms) && ms != 0) interval = (int)ms;
                ssf = new SsfConfig { Transmitter = transmitter, PollIntervalMs = interval };
            }
        }
        Display display = null;
        var displayIn = JsonUtil.Obj(raw["display"]);
        if (displayIn != null && (JsonUtil.Str(displayIn["name"]) != null || JsonUtil.Str(displayIn["uri"]) != null))
            display = new Display { Name = JsonUtil.Str(displayIn["name"]), Uri = JsonUtil.Str(displayIn["uri"]) };
        return new Config
        {
            GrantEndpoint = grantEndpoint,
            IdTokenIssuer = issuer,
            Application = application,
            ClassId = JsonUtil.Str(raw["classId"]),
            Display = display,
            Access = access,
            Signals = signalsOff ? false : null,
            SubIdFormats = StringsOr(raw["subIdFormats"], "iss_sub", "account", "opaque"),
            AssertionFormats = StringsOr(raw["assertionFormats"], "id_token"),
            Key = key,
            FinishUri = finishUri,
            FinishMethod = finishMethod,
            InteractionStart = interaction,
            HashMethod = "sha-256",
            RequireBoundTokens = !(raw["requireBoundTokens"] is JsonValue bound && bound.TryGetValue<bool>(out var rb) && !rb),
            UseInstanceId = !(raw["useInstanceId"] is JsonValue inst && inst.TryGetValue<bool>(out var ui) && !ui),
            TlsCa = tlsCa,
            AllowInsecure = allowInsecure,
            ClockToleranceSec = NumberOr(raw, "clockToleranceSec", 30),
            MaxWaitSec = NumberOr(raw, "maxWaitSec", 30),
            TransactionTtlSec = NumberOr(raw, "transactionTtlSec", 600),
            Ssf = ssf
        };
    }

    public static Config ReadFile(string path)
    {
        string text;
        try { text = File.ReadAllText(path); }
        catch (Exception err) { throw new GnapException("config", "could not read " + path + ": " + err.Message, err); }
        JsonObject doc;
        try { doc = JsonUtil.Obj(JsonUtil.Parse(text)); }
        catch (GnapException) { throw; }
        catch (Exception err) { throw new GnapException("config", "could not read " + path + ": " + err.Message, err); }
        if (doc == null) throw new GnapException("config", "the configuration must be a JSON object");
        return Resolve(doc, Path.GetDirectoryName(Path.GetFullPath(path)));
    }

    static bool IsBool(JsonNode node) => node is JsonValue value && value.TryGetValue<bool>(out _);

    static bool SsfRight(JsonNode right)
    {
        var text = JsonUtil.Str(right);
        if (text != null) { var trimmed = text.Trim(); return trimmed == "ssf.read" || trimmed == "ssf.manage"; }
        var obj = JsonUtil.Obj(right);
        var type = obj == null ? null : JsonUtil.Str(obj["type"]);
        return type == "ssf.read" || type == "ssf.manage";
    }

    static string CheckUrl(string value, string name, bool allowHttp)
    {
        string href;
        try { href = Urls.Href(value); }
        catch { throw new GnapException("config", name + " is not a URL: " + value); }
        var scheme = href.Split(':')[0];
        if (scheme == "https" || (scheme == "http" && allowHttp)) return href;
        throw new GnapException("config", name + " must use https" + (allowHttp ? "" : ", or http on loopback") + ": " + value);
    }

    static string KeyValue(string raw, string baseDir, string what)
    {
        if (raw.StartsWith("env:") || raw.StartsWith("file:") || raw.Contains("-----BEGIN")) return Secret(raw, baseDir, what);
        return ReadPath(raw, baseDir, what);
    }

    static string Secret(string raw, string baseDir, string what)
    {
        if (raw.StartsWith("env:"))
        {
            var name = raw[4..];
            var value = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrEmpty(value)) throw new GnapException("config", what + " reads " + name + ", and that variable is empty");
            return value;
        }
        if (raw.StartsWith("file:")) return ReadPath(raw[5..], baseDir, what);
        return raw;
    }

    static string ReadPath(string path, string baseDir, string what)
    {
        var full = Path.IsPathRooted(path) ? path : Path.Combine(baseDir, path);
        try { return File.ReadAllText(full); }
        catch (Exception err) { throw new GnapException("config", "could not read " + what + " at " + full + ": " + err.Message, err); }
    }

    public static string ReadTrust(string raw, string baseDir)
    {
        if (string.IsNullOrEmpty(raw)) return "";
        if (raw.Contains("-----BEGIN")) return raw;
        if (raw.StartsWith("env:")) return Environment.GetEnvironmentVariable(raw[4..]) ?? "";
        var path = raw.StartsWith("file:") ? raw[5..] : raw;
        var full = Path.IsPathRooted(path) ? path : Path.Combine(baseDir, path);
        try { return File.ReadAllText(full); }
        catch { return ""; }
    }

    static List<string> StringsOr(JsonNode node, params string[] fallback)
    {
        var list = JsonUtil.Arr(node);
        if (list == null || list.Count == 0) return fallback.ToList();
        return list.Select(item => JsonUtil.Str(item) ?? "").ToList();
    }

    static double NumberOr(JsonObject raw, string key, double fallback)
    {
        if (!raw.ContainsKey(key) || raw[key] == null) return fallback;
        return JsonUtil.TryNumber(raw[key], out var n) ? n : fallback;
    }
}
