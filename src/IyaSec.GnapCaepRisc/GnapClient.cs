// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Text.Json.Nodes;

namespace IyaSec.Gnap;

public sealed class Continuation
{
    public string Uri { get; init; }
    public string AccessToken { get; init; }
    public double? Wait { get; init; }
}

public sealed class Grant
{
    public string AccessToken { get; set; }
    public bool Bearer { get; set; }
    public JsonNode Access { get; set; }
    public double? ExpiresIn { get; set; }
    public double? ExpiresAt { get; set; }
    public Continuation Manage { get; set; }
    public Continuation Continuation { get; set; }
    public string InstanceId { get; set; }
    public Person Subject { get; set; }
    public string GrantId { get; set; }
}

public sealed class Pending
{
    public string Id { get; init; }
    public string ClientNonce { get; init; }
    public string ServerNonce { get; init; }
    public Continuation Continuation { get; init; }
    public double ContinueNotBefore { get; init; }
    public string GrantEndpoint { get; init; }
    public double CreatedAt { get; init; }
    public object Context { get; init; }
    public string ExpectedSub { get; init; }
}

public sealed class GrantResult
{
    public string RedirectUrl { get; init; }
    public Pending Pending { get; init; }
    public Grant Grant { get; init; }
}

public sealed class Finished
{
    public Grant Grant { get; init; }
    public object Context { get; init; }
}

public sealed class GnapClient
{
    static readonly string[] Front = { "access_token", "id_token", "token", "value", "continue", "refresh_token" };
    readonly object gate = new();
    JsonObject metadata;
    string instanceId;
    List<string> subIds;
    List<string> assertions;
    List<JsonObject> jwks;
    readonly Dictionary<string, Pending> pending = new();
    readonly Dictionary<string, byte> used = new();

    public Config Config { get; }

    public GnapClient(Config config)
    {
        Config = config;
        subIds = new List<string>(config.SubIdFormats);
        assertions = new List<string>(config.AssertionFormats);
    }

    public static GnapClient FromFile(string path) => new(ConfigLoader.ReadFile(path));

    public static Config Resolve(JsonObject raw, string baseDir) => ConfigLoader.Resolve(raw, baseDir);

    public TlsOpt Tls()
    {
        var opt = new TlsOpt { Ca = Config.TlsCa };
        var key = Config.Key;
        if (key != null && key.Proof == "mtls" && (!string.IsNullOrEmpty(key.ChainPem) || !string.IsNullOrEmpty(key.CertPem)))
            return new TlsOpt { Ca = Config.TlsCa, Cert = string.IsNullOrEmpty(key.ChainPem) ? key.CertPem : key.ChainPem, Key = key.PrivatePem() };
        return opt;
    }

    public GrantResult RequestGrant() => RequestGrant(null, null, null);

    public GrantResult RequestGrant(List<JsonNode> access, string expectedSub, JsonNode user)
    {
        Discover();
        var rights = access ?? Config.Access;
        if (rights == null || rights.Count == 0) throw new GnapException("config", "access is required");
        var nonceBytes = new byte[24];
        System.Security.Cryptography.RandomNumberGenerator.Fill(nonceBytes);
        var clientNonce = JsonUtil.B64Url(nonceBytes);
        var body = new JsonObject
        {
            ["access_token"] = new JsonObject { ["access"] = new JsonArray(rights.Select(r => r?.DeepClone()).ToArray()) },
            ["client"] = ClientMember()
        };
        if (!string.IsNullOrEmpty(Config.FinishUri))
        {
            body["interact"] = new JsonObject
            {
                ["start"] = new JsonArray(Config.InteractionStart.Select(s => (JsonNode)s).ToArray()),
                ["finish"] = new JsonObject { ["method"] = Config.FinishMethod, ["uri"] = Config.FinishUri, ["nonce"] = clientNonce }
            };
        }
        List<string> subs, asserts;
        lock (gate) { subs = new List<string>(subIds); asserts = new List<string>(assertions); }
        if (subs.Count > 0 || asserts.Count > 0)
        {
            var subject = new JsonObject();
            if (subs.Count > 0) subject["sub_id_formats"] = new JsonArray(subs.Select(s => (JsonNode)s).ToArray());
            if (asserts.Count > 0) subject["assertion_formats"] = new JsonArray(asserts.Select(s => (JsonNode)s).ToArray());
            body["subject"] = subject;
        }
        if (user != null) body["user"] = user.DeepClone();
        var answer = SignedJson("POST", Config.GrantEndpoint, body, null);
        RememberInstance(answer);
        var doc = JsonUtil.Obj(answer);
        if (doc?["interact"] != null)
            return new GrantResult { RedirectUrl = RedirectOf(doc), Pending = RememberPending(doc, clientNonce, null, expectedSub) };
        if (HasToken(answer))
        {
            var grant = GrantFrom(answer, null, null);
            Expect(grant, expectedSub);
            return new GrantResult { Grant = grant };
        }
        throw new GnapException("protocol", "the grant response has neither an interaction nor an access token");
    }

    public Finished FinishRedirect(object query, IReadOnlyList<string> allowedIds)
    {
        var names = QueryNames(query);
        var injected = Front.Where(names.ContainsKey).ToList();
        if (injected.Count > 0)
            throw new GnapException("validation", "the finish redirect carries " + string.Join(", ", injected) + "; GNAP does not send tokens through the browser");
        foreach (var pair in names)
            if (pair.Value.Count > 1) throw new GnapException("validation", "the finish redirect repeats \"" + pair.Key + "\"");
        var digest = First(names, "hash");
        var interact = First(names, "interact_ref");
        if (string.IsNullOrEmpty(digest) || string.IsNullOrEmpty(interact))
        {
            var code = First(names, "error");
            if (!string.IsNullOrEmpty(code))
            {
                var msg = First(names, "error_description");
                if (string.IsNullOrEmpty(msg)) msg = code;
                throw new GnapException("protocol", msg, gnapError: code);
            }
            throw new GnapException("validation", "the finish redirect has no hash or interact_ref");
        }
        var found = Match(digest, interact, allowedIds, true);
        return Finish(found, interact, digest);
    }

    public Finished FinishPush(JsonNode body)
    {
        var doc = JsonUtil.Obj(body);
        if (doc == null) throw new GnapException("validation", "a push finish is a JSON object");
        var digest = JsonUtil.Str(doc["hash"]);
        var interact = JsonUtil.Str(doc["interact_ref"]);
        if (digest == null || interact == null)
        {
            var code = JsonUtil.Str(doc["error"]);
            if (code != null) throw new GnapException("protocol", code, gnapError: code);
            throw new GnapException("validation", "a push finish needs hash and interact_ref");
        }
        return Finish(Match(digest, interact, null, false), interact, digest);
    }

    public Dictionary<string, string> AuthorizationHeaders(Grant grant, string method, string url, string body)
        => ProofHeaders(method, url, body, grant.AccessToken, null);

    public Answer Call(Grant grant, string url, string method = "GET", IDictionary<string, string> headers = null, string body = null)
    {
        var proof = AuthorizationHeaders(grant, method, url, body);
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (headers != null) foreach (var pair in headers) merged[pair.Key] = pair.Value;
        foreach (var pair in proof) merged[pair.Key] = pair.Value;
        return Http.Send(url, method, merged, body, Tls(), "protocol");
    }

    public Grant Rotate(Grant grant)
    {
        if (grant.Manage == null) throw new GnapException("protocol", "this access token has no manage URI");
        CheckOrigin(grant.Manage.Uri, "manage.uri");
        var answer = SignedJson("POST", grant.Manage.Uri, null, grant.Manage.AccessToken);
        if (!HasToken(answer)) throw new GnapException("protocol", "the rotation returned no access token");
        var next = GrantFrom(answer, grant, null);
        if (!grant.Bearer && next.Bearer) throw new GnapException("validation", "rotating a key-bound token returned a bearer token");
        return next;
    }

    public void Revoke(Grant grant)
    {
        if (grant.Continuation == null) throw new GnapException("protocol", "this grant has no continuation, so it cannot be revoked");
        CheckOrigin(grant.Continuation.Uri, "continue.uri");
        SignedJson("DELETE", grant.Continuation.Uri, null, grant.Continuation.AccessToken);
    }

    public Grant EnsureFresh(Grant grant)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (grant.ExpiresAt == null || grant.ExpiresAt.Value - now > 60000) return grant;
        return Rotate(grant);
    }

    void Discover()
    {
        lock (gate) if (metadata != null) return;
        var answer = Http.Send(Config.GrantEndpoint, "OPTIONS", new Dictionary<string, string> { ["accept"] = "application/json" }, null, Tls(), "discovery");
        JsonNode parsed;
        try { parsed = JsonUtil.Parse(answer.Body); }
        catch (Exception err) { throw new GnapException("discovery", Config.GrantEndpoint + " did not answer JSON grant-server metadata (" + answer.Status + ")", err); }
        if (answer.Status != 200) throw new GnapException("discovery", Config.GrantEndpoint + " answered " + answer.Status + " for discovery");
        var doc = JsonUtil.Obj(parsed) ?? throw new GnapException("discovery", "grant-server metadata must be a JSON object");
        var endpoint = JsonUtil.Str(doc["grant_request_endpoint"]);
        if (string.IsNullOrEmpty(endpoint)) throw new GnapException("discovery", "grant-server metadata has no grant_request_endpoint");
        if (Urls.Href(endpoint).TrimEnd('/') != Urls.Href(Config.GrantEndpoint).TrimEnd('/'))
            throw new GnapException("discovery", "the grant server says its endpoint is " + endpoint + ", not " + Config.GrantEndpoint);
        var proofs = StringList(doc["key_proofs_supported"]);
        if (proofs != null && !proofs.Contains(Config.Key.Proof))
            throw new GnapException("discovery", "the grant server does not accept the " + Config.Key.Proof + " key proof");
        var finishes = StringList(doc["interaction_finish_methods_supported"]);
        if (finishes != null && !string.IsNullOrEmpty(Config.FinishUri) && !finishes.Contains(Config.FinishMethod))
            throw new GnapException("discovery", "the grant server does not accept a " + Config.FinishMethod + " interaction finish");
        lock (gate)
        {
            if (metadata != null) return;
            var subs = StringList(doc["sub_id_formats_supported"]);
            var asserts = StringList(doc["assertion_formats_supported"]);
            if (subs != null) subIds = subIds.Where(subs.Contains).ToList();
            if (asserts != null) assertions = assertions.Where(asserts.Contains).ToList();
            metadata = doc;
        }
    }

    JsonNode ClientMember()
    {
        string instance;
        lock (gate) instance = instanceId;
        if (Config.UseInstanceId && !string.IsNullOrEmpty(instance)) return instance;
        var member = new JsonObject { ["key"] = Keys.PublicKeyObject(Config.Key) };
        if (Config.Display != null)
        {
            var display = new JsonObject();
            if (!string.IsNullOrEmpty(Config.Display.Name)) display["name"] = Config.Display.Name;
            if (!string.IsNullOrEmpty(Config.Display.Uri)) display["uri"] = Config.Display.Uri;
            if (display.Count > 0) member["display"] = display;
        }
        if (!string.IsNullOrEmpty(Config.ClassId)) member["class_id"] = Config.ClassId;
        return member;
    }

    void RememberInstance(JsonNode answer)
    {
        if (!Config.UseInstanceId) return;
        var id = JsonUtil.Str(JsonUtil.Obj(answer)?["instance_id"]);
        if (!string.IsNullOrEmpty(id)) lock (gate) instanceId = id;
    }

    string RedirectOf(JsonObject answer)
    {
        var redirect = JsonUtil.Str(JsonUtil.Obj(answer["interact"])?["redirect"]);
        if (string.IsNullOrEmpty(redirect)) throw new GnapException("protocol", "the interaction is not a redirect");
        if (!Uri.TryCreate(redirect, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            throw new GnapException("protocol", "interact.redirect is not a URL: " + redirect);
        if (uri.Scheme != "https" && !(uri.Scheme == "http" && (Config.AllowInsecure || Urls.IsLoopback(redirect))))
            throw new GnapException("validation", "interact.redirect must use https: " + redirect);
        return redirect;
    }

    Pending RememberPending(JsonObject answer, string clientNonce, object context, string expectedSub)
    {
        var finish = JsonUtil.Str(JsonUtil.Obj(answer["interact"])?["finish"]);
        if (string.IsNullOrEmpty(finish)) throw new GnapException("protocol", "the grant response has no interaction finish nonce");
        var cont = ReadContinuation(answer["continue"], "continue");
        var wait = cont.Wait ?? 0;
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var item = new Pending
        {
            Id = clientNonce, ClientNonce = clientNonce, ServerNonce = finish, Continuation = cont,
            ContinueNotBefore = now + wait * 1000, GrantEndpoint = Config.GrantEndpoint, CreatedAt = now,
            Context = context, ExpectedSub = expectedSub
        };
        lock (gate)
        {
            var cutoff = now - Config.TransactionTtlSec * 1000;
            foreach (var key in pending.Where(p => p.Value.CreatedAt < cutoff).Select(p => p.Key).ToList()) pending.Remove(key);
            pending[item.Id] = item;
            while (pending.Count > 1000) pending.Remove(pending.Keys.First());
        }
        return item;
    }

    Pending Match(string digest, string interactRef, IReadOnlyList<string> allowed, bool useAllow)
    {
        lock (gate)
        {
            if (used.ContainsKey(digest)) throw new GnapException("validation", "this interaction finish was already used");
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            foreach (var item in pending.Values)
            {
                if (useAllow && (allowed == null || !allowed.Contains(item.Id))) continue;
                var expected = Proofs.InteractionHash(item.ClientNonce, item.ServerNonce, interactRef, item.GrantEndpoint);
                if (!JsonUtil.TimingEqual(digest, expected)) continue;
                if (now - item.CreatedAt > Config.TransactionTtlSec * 1000)
                {
                    pending.Remove(item.Id);
                    throw new GnapException("validation", "the approval took too long; start again", context: item.Context);
                }
                return item;
            }
        }
        throw new GnapException("validation", useAllow ? "this finish is not a sign-in this browser started" : "the interaction hash matches no grant in progress");
    }

    Finished Finish(Pending item, string interactRef, string digest)
    {
        lock (gate)
        {
            pending.Remove(item.Id);
            used[digest] = 1;
            while (used.Count > 1000) used.Remove(used.Keys.First());
        }
        var due = item.ContinueNotBefore - DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (due > 0)
        {
            var cap = Config.MaxWaitSec * 1000;
            if (due > cap) due = cap;
            Thread.Sleep(TimeSpan.FromMilliseconds(due));
        }
        JsonNode answer;
        try { answer = Continue(item.Continuation, new JsonObject { ["interact_ref"] = interactRef }); }
        catch (GnapException err) { err.Context = item.Context; throw; }
        if (!HasToken(answer)) throw new GnapException("protocol", "the resource owner did not approve the grant", gnapError: "user_denied", context: item.Context);
        try
        {
            var grant = GrantFrom(answer, null, item.Continuation);
            Expect(grant, item.ExpectedSub);
            return new Finished { Grant = grant, Context = item.Context };
        }
        catch (GnapException err) { err.Context = item.Context; throw; }
    }

    JsonNode Continue(Continuation cont, JsonObject body)
    {
        var current = cont;
        double waited = 0;
        var immediate = 0;
        while (true)
        {
            try { return SignedJson("POST", current.Uri, body, current.AccessToken); }
            catch (GnapException err)
            {
                if (err.GnapError != "too_fast") throw;
                if (err.Continuation != null)
                {
                    CheckOrigin(err.Continuation.Uri, "continue.uri");
                    current = err.Continuation;
                }
                var wait = current.Wait ?? 0;
                if (wait < 0) wait = 0;
                if (wait == 0)
                {
                    immediate++;
                    if (immediate > 2) throw;
                    continue;
                }
                if (waited + wait > Config.MaxWaitSec) throw;
                Thread.Sleep(TimeSpan.FromSeconds(wait));
                waited += wait;
            }
        }
    }

    JsonNode SignedJson(string method, string url, JsonNode body, string token)
    {
        CheckOrigin(url, "the request URL");
        string text = body == null ? null : JsonUtil.Dump(body);
        var headers = ProofHeaders(method, url, text, token, text == null ? null : new Dictionary<string, string> { ["content-type"] = "application/json" });
        headers["accept"] = "application/json";
        return Read(Http.Send(url, method, headers, text, Tls(), "protocol"));
    }

    Dictionary<string, string> ProofHeaders(string method, string url, string body, string token, Dictionary<string, string> extra)
    {
        var headers = extra == null ? new Dictionary<string, string>() : new Dictionary<string, string>(extra);
        if (!string.IsNullOrEmpty(token)) headers["authorization"] = "GNAP " + token;
        if (Config.Key.Proof == "httpsig")
            foreach (var pair in Proofs.SignRequest(Config.Key, method, url, headers, body)) headers[pair.Key] = pair.Value;
        else if (Config.Key.Proof == "jwsd")
            headers["detached-jws"] = Proofs.DetachedJws(Config.Key, method, url, body, token);
        return headers;
    }

    JsonNode Read(Answer answer)
    {
        if (answer.Status == 204 || string.IsNullOrEmpty(answer.Body))
        {
            if (answer.Status >= 400) throw new GnapException("protocol", "the authorization server answered " + answer.Status);
            return null;
        }
        JsonNode parsed;
        try { parsed = JsonUtil.Parse(answer.Body); }
        catch (Exception err) { throw new GnapException("protocol", "the authorization server answered " + answer.Status + " with a body that is not JSON", err); }
        if (answer.Status is >= 200 and < 300) return parsed;
        var doc = JsonUtil.Obj(parsed);
        var code = JsonUtil.Str(doc?["error"]);
        Continuation cont = null;
        var raw = JsonUtil.Obj(doc?["continue"]);
        if (raw != null)
        {
            var token = JsonUtil.Str(JsonUtil.Obj(raw["access_token"])?["value"]);
            var uri = JsonUtil.Str(raw["uri"]);
            if (uri != null && token != null)
            {
                double? wait = JsonUtil.TryNumber(raw["wait"], out var n) ? n : null;
                cont = new Continuation { Uri = uri, AccessToken = token, Wait = wait };
            }
        }
        var msg = JsonUtil.Str(doc?["error_description"]);
        if (string.IsNullOrEmpty(msg)) msg = code;
        if (string.IsNullOrEmpty(msg)) msg = "the authorization server answered " + answer.Status;
        throw new GnapException("protocol", msg, gnapError: code, continuation: cont);
    }

    static bool HasToken(JsonNode answer)
    {
        var doc = JsonUtil.Obj(answer);
        if (doc == null || doc["access_token"] == null) return false;
        var list = JsonUtil.Arr(doc["access_token"]);
        if (list != null) return list.Count > 0;
        return JsonUtil.Str(doc["access_token"]) != "";
    }

    Grant GrantFrom(JsonNode answer, Grant previous, Continuation previousContinue)
    {
        var doc = JsonUtil.Obj(answer) ?? new JsonObject();
        var token = doc["access_token"];
        if (JsonUtil.Arr(token) is JsonArray list) token = list.Count == 0 ? null : list[0];
        var tokenDoc = JsonUtil.Obj(token) ?? throw new GnapException("protocol", "the access token is not an object");
        var value = JsonUtil.Str(tokenDoc["value"]);
        if (string.IsNullOrEmpty(value)) throw new GnapException("protocol", "the access token has no value");
        var flags = JsonUtil.Arr(tokenDoc["flags"])?.Select(item => JsonUtil.Str(item) ?? "").ToList() ?? new List<string>();
        var bearer = flags.Contains("bearer");
        if (bearer && Config.RequireBoundTokens)
            throw new GnapException("validation", "the authorization server issued a bearer token, and this client requires a key-bound one");
        RememberInstance(answer);
        Continuation manage = null;
        if (JsonUtil.Obj(tokenDoc["manage"]) is JsonObject rawManage)
        {
            var manageToken = JsonUtil.Str(JsonUtil.Obj(rawManage["access_token"])?["value"]);
            var uri = JsonUtil.Str(rawManage["uri"]);
            if (uri == null || manageToken == null) throw new GnapException("protocol", "the access token manage object is not usable");
            CheckOrigin(uri, "manage.uri");
            manage = new Continuation { Uri = uri, AccessToken = manageToken };
        }
        else if (previous != null) manage = previous.Manage;
        Continuation cont = null;
        if (doc["continue"] != null) cont = ReadContinuation(doc["continue"], "continue");
        else if (previousContinue != null) cont = previousContinue;
        else if (previous != null) cont = previous.Continuation;
        string instance;
        lock (gate) instance = instanceId;
        var audiences = new List<string>();
        if (!string.IsNullOrEmpty(instance)) audiences.Add(instance);
        if (!string.IsNullOrEmpty(Config.Application)) audiences.Add(Config.Application);
        Person subject = null;
        if (doc["subject"] != null)
            subject = Subjects.From(doc["subject"], new IdCheck { Issuer = Config.IdTokenIssuer, Audiences = audiences, Skew = Config.ClockToleranceSec, Keys = IdTokenKeys });
        else if (previous != null) subject = previous.Subject;
        double? expiresIn = JsonUtil.TryNumber(tokenDoc["expires_in"], out var exp) ? exp : null;
        double? expiresAt = expiresIn == null ? null : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + expiresIn.Value * 1000;
        return new Grant
        {
            AccessToken = value, Bearer = bearer, Access = tokenDoc["access"]?.DeepClone(), ExpiresIn = expiresIn, ExpiresAt = expiresAt,
            Manage = manage, Continuation = cont, InstanceId = instance, Subject = subject,
            GrantId = GrantIdOf(cont?.Uri)
        };
    }

    static void Expect(Grant grant, string expected)
    {
        if (!string.IsNullOrEmpty(expected) && grant.Subject != null && grant.Subject.Sub != expected)
            throw new GnapException("validation", "the grant was approved by somebody other than the account that was asked for");
    }

    Continuation ReadContinuation(JsonNode raw, string what)
    {
        var doc = JsonUtil.Obj(raw) ?? throw new GnapException("protocol", "the response has no " + what + " object");
        var token = JsonUtil.Str(JsonUtil.Obj(doc["access_token"])?["value"]);
        var uri = JsonUtil.Str(doc["uri"]);
        if (uri == null || token == null) throw new GnapException("protocol", "the response has no usable " + what + " object");
        CheckOrigin(uri, what + ".uri");
        double? wait = null;
        if (doc.ContainsKey("wait") && doc["wait"] != null)
        {
            if (!JsonUtil.TryNumber(doc["wait"], out var n) || n < 0)
                throw new GnapException("protocol", what + ".wait is not a number of seconds");
            wait = n;
        }
        return new Continuation { Uri = uri, AccessToken = token, Wait = wait };
    }

    void CheckOrigin(string uri, string what)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parts) || (parts.Scheme != "http" && parts.Scheme != "https") || string.IsNullOrEmpty(parts.Host))
            throw new GnapException("validation", what + " is not a URL: " + uri);
        if (parts.Scheme != "https" && !Config.AllowInsecure)
            throw new GnapException("validation", what + " must use https: " + uri);
        if (Urls.Origin(uri) != Urls.Origin(Config.GrantEndpoint))
            throw new GnapException("validation", what + " " + uri + " is not on the grant endpoint's origin");
    }

    List<JsonObject> IdTokenKeys()
    {
        lock (gate) if (jwks != null) return jwks;
        var urls = Urls.WellKnown(Config.IdTokenIssuer, "openid-configuration");
        GnapException last = new("discovery", "no OpenID Provider metadata at " + string.Join(" or ", urls));
        JsonObject openid = null;
        for (var i = 0; i < urls.Count; i++)
        {
            var answer = Http.Send(urls[i], "GET", new Dictionary<string, string> { ["accept"] = "application/json" }, null, Tls(), "discovery");
            if (answer.Status == 404 && i != urls.Count - 1) continue;
            JsonObject doc = null;
            try { doc = JsonUtil.Obj(JsonUtil.Parse(answer.Body)); } catch { doc = null; }
            if (answer.Status != 200 || doc == null || string.IsNullOrEmpty(JsonUtil.Str(doc["jwks_uri"])))
            {
                last = new GnapException("discovery", urls[i] + " answered " + answer.Status + " without OpenID Provider metadata");
                continue;
            }
            var got = JsonUtil.Str(doc["issuer"]);
            if (!string.IsNullOrEmpty(got) && got.TrimEnd('/') != Config.IdTokenIssuer.TrimEnd('/'))
                throw new GnapException("discovery", urls[i] + " says its issuer is " + got + ", not " + Config.IdTokenIssuer);
            openid = doc;
            break;
        }
        if (openid == null) throw last;
        var jwksAnswer = Http.Send(JsonUtil.Str(openid["jwks_uri"]), "GET", new Dictionary<string, string> { ["accept"] = "application/json" }, null, Tls(), "discovery");
        JsonObject parsed;
        try { parsed = JsonUtil.Obj(JsonUtil.Parse(jwksAnswer.Body)); }
        catch (Exception err) { throw new GnapException("discovery", "the issuer JWKS is not JSON", err); }
        var list = JsonUtil.Arr(parsed?["keys"]);
        if (jwksAnswer.Status != 200 || list == null) throw new GnapException("discovery", "the issuer JWKS answered " + jwksAnswer.Status);
        var keys = list.Select(JsonUtil.Obj).Where(o => o != null).ToList();
        lock (gate) jwks = keys;
        return keys;
    }

    static string GrantIdOf(string uri)
    {
        if (string.IsNullOrEmpty(uri) || !Uri.TryCreate(uri, UriKind.Absolute, out var parts)) return null;
        var chunks = parts.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        return chunks.Length == 0 ? null : Uri.UnescapeDataString(chunks[^1]);
    }

    static List<string> StringList(JsonNode node)
    {
        if (node == null) return null;
        var list = JsonUtil.Arr(node) ?? throw new GnapException("discovery", "a grant-server metadata list is not an array of strings");
        var outp = new List<string>();
        foreach (var item in list)
        {
            var text = JsonUtil.Str(item) ?? throw new GnapException("discovery", "a grant-server metadata list is not an array of strings");
            outp.Add(text);
        }
        return outp;
    }

    static Dictionary<string, List<string>> QueryNames(object query)
    {
        if (query is string text)
        {
            if (text.Contains("://") || text.StartsWith('/'))
            {
                if (!Uri.TryCreate(text, UriKind.Absolute, out var uri) && !Uri.TryCreate("http://local" + text, UriKind.Absolute, out uri))
                    throw new GnapException("validation", "the finish redirect could not be read");
                text = uri.Query.TrimStart('?');
            }
            else if (text.StartsWith('?') || text.StartsWith('#')) text = text[1..];
            var parsed = System.Web.HttpUtility.ParseQueryString(text);
            var names = new Dictionary<string, List<string>>();
            foreach (string key in parsed)
            {
                if (key == null) continue;
                names[key] = parsed.GetValues(key)?.ToList() ?? new List<string>();
            }
            return names;
        }
        if (query is IReadOnlyDictionary<string, string> map)
            return map.ToDictionary(p => p.Key, p => new List<string> { p.Value });
        if (query is Dictionary<string, string> dict)
            return dict.ToDictionary(p => p.Key, p => new List<string> { p.Value });
        throw new GnapException("validation", "the finish redirect could not be read");
    }

    static string First(Dictionary<string, List<string>> names, string key) => names.TryGetValue(key, out var values) && values.Count > 0 ? values[0] : null;
}
