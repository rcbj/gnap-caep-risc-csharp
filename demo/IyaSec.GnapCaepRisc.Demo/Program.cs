// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using IyaSec.Gnap;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

var (publicUrl, publicGiven) = PublicUrl(args);
var port = Environment.GetEnvironmentVariable("PORT");
if (string.IsNullOrEmpty(port)) port = "3000";
var demo = new DemoApp(publicUrl, publicGiven, port);
var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
builder.Logging.ClearProviders();
builder.WebHost.UseUrls("http://0.0.0.0:" + port);
var app = builder.Build();
Console.WriteLine("gnap-caep-risc demo on port " + port + ", configuration " + demo.ConfigPath);
app.Run(demo.Handle);
app.Run();

static (string Url, bool Given) PublicUrl(string[] argv)
{
    var given = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PUBLIC_URL"));
    var publicUrl = (Environment.GetEnvironmentVariable("PUBLIC_URL") ?? "").TrimEnd('/');
    for (var i = 0; i < argv.Length; i++)
    {
        if (argv[i] == "--public-url" && i + 1 < argv.Length)
        {
            publicUrl = argv[++i].TrimEnd('/');
            given = true;
        }
    }
    return (publicUrl, given);
}

sealed class DemoApp
{
    public string ConfigPath { get; }
    readonly string publicDir;
    readonly string publicUrl;
    readonly bool publicGiven;
    readonly string port;
    readonly byte[] secret;
    readonly object gate = new();
    GnapClient client;
    string clientErr = "";
    readonly Dictionary<string, (Person Person, Grant Grant)> sessions = new();
    SignalsReceiver receiver;
    Grant latest;
    // For GET /live-status: the receiver's state, and the type and jti of each event it accepted. No tokens.
    string receiverState = "not started (no sign-in yet)";
    readonly List<(string Type, string Jti)> liveEvents = new();

    public DemoApp(string publicUrl, bool given, string port)
    {
        var env = Environment.GetEnvironmentVariable("SESSION_SECRET");
        secret = string.IsNullOrEmpty(env) ? RandomNumberGenerator.GetBytes(32) : Encoding.UTF8.GetBytes(env);
        ConfigPath = Environment.GetEnvironmentVariable("GNAP_CONFIG");
        if (string.IsNullOrEmpty(ConfigPath)) ConfigPath = Path.Combine("demo", "gnap.json");
        publicDir = Path.Combine(Path.GetDirectoryName(ConfigPath) ?? "demo", "public");
        this.publicUrl = publicUrl;
        publicGiven = given;
        this.port = port;
    }

    public async Task Handle(HttpContext ctx)
    {
        try
        {
            var path = ctx.Request.Path.Value ?? "/";
            if (path == "/healthz" && ctx.Request.Method == "GET")
            {
                ctx.Response.ContentType = "text/plain";
                ctx.Response.StatusCode = 200;
                await ctx.Response.WriteAsync("ok");
                return;
            }
            if (path == "/live-status" && ctx.Request.Method == "GET") { await LiveStatus(ctx); return; }
            if (path == "/styles.css" && ctx.Request.Method == "GET") { await Static(ctx, "styles.css", "text/css; charset=utf-8"); return; }
            if (path == "/app.js" && ctx.Request.Method == "GET") { await Static(ctx, "app.js", "text/javascript; charset=utf-8"); return; }
            if (path == "/" && ctx.Request.Method == "GET") { await Home(ctx); return; }
            if (path == "/login" && ctx.Request.Method == "GET") { await Login(ctx); return; }
            if (path == "/callback" && ctx.Request.Method == "GET") { await Callback(ctx); return; }
            if (path == "/logout" && ctx.Request.Method == "POST") { await Logout(ctx); return; }
            if (path == "/gnap/push" && ctx.Request.Method == "POST") { await Push(ctx); return; }
            await Html(ctx, 404, "Not found", "<h1>Not found</h1>", null);
        }
        catch (Exception err)
        {
            Console.WriteLine(err);
            await Html(ctx, 500, "Error", "<h1>Something went wrong</h1><p>" + WebUtility.HtmlEncode(err.Message) + "</p><p><a href=\"/\">Home</a></p>", null);
        }
    }

    // JSON for scripts/live_iya_sts.py: whether this browser is signed in, as whom, the receiver's
    // state, and the type and jti of every event received. It carries no tokens.
    async Task LiveStatus(HttpContext ctx)
    {
        var opened = Session(ctx);
        string subject = null;
        if (opened.Person != null)
        {
            var person = opened.Person;
            subject = new[] { person.PreferredUsername, person.Email, person.Name, person.Sub }.FirstOrDefault(value => !string.IsNullOrEmpty(value));
        }
        var events = new JsonArray();
        string state;
        lock (gate)
        {
            foreach (var item in liveEvents) events.Add(new JsonObject { ["type"] = item.Type, ["jti"] = item.Jti });
            state = receiverState;
        }
        var body = new JsonObject
        {
            ["signedIn"] = opened.Person != null,
            ["subject"] = subject,
            ["receiver"] = state,
            ["events"] = events
        };
        ctx.Response.ContentType = "application/json";
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.StatusCode = 200;
        await ctx.Response.WriteAsync(body.ToJsonString());
    }

    // The id the receiver knows a session by: the grant id, or the subject.
    static string TrackedId(Grant grant, Person person)
    {
        if (!string.IsNullOrEmpty(grant?.GrantId)) return grant.GrantId;
        return person?.Sub ?? grant?.Subject?.Sub ?? "";
    }

    // Ends every cookie session whose grant the receiver tracks under one of ids. The cookie id and the
    // tracked id differ, so this looks the sessions up by grant.
    void EndTracked(IReadOnlyList<string> ids)
    {
        lock (gate)
        {
            foreach (var local in sessions.Keys.ToList())
            {
                var known = TrackedId(sessions[local].Grant, sessions[local].Person);
                if (known != "" && ids.Contains(known)) sessions.Remove(local);
            }
        }
    }

    // Records an accepted event for /live-status. A session-revoked event that ended no tracked session
    // still ends this demo's one local session, if it has exactly one: the event can name the sign-on
    // session by an id the grant did not carry.
    void Remember(SignalEvent signal)
    {
        string orphan = null;
        SignalsReceiver current;
        lock (gate)
        {
            liveEvents.Add((signal.Type, signal.Jti));
            if (liveEvents.Count > 100) liveEvents.RemoveRange(0, liveEvents.Count - 100);
            if (signal.Type == Events.SessionRevoked && !signal.Ended && sessions.Count == 1)
            {
                var only = sessions.First();
                orphan = TrackedId(only.Value.Grant, only.Value.Person);
                sessions.Remove(only.Key);
            }
            current = receiver;
        }
        if (orphan != null)
        {
            Console.WriteLine("ssf: session-revoked matched no tracked session; ending this demo's one local session");
            if (current != null && orphan != "") current.Untrack(orphan);
        }
    }

    async Task Static(HttpContext ctx, string name, string contentType)
    {
        var full = Path.Combine(publicDir, name);
        if (!File.Exists(full)) { await Html(ctx, 404, "Not found", "<h1>Not found</h1>", null); return; }
        ctx.Response.ContentType = contentType;
        ctx.Response.Headers.CacheControl = "max-age=300";
        await ctx.Response.WriteAsync(await File.ReadAllTextAsync(full));
    }

    async Task Home(HttpContext ctx)
    {
        var opened = Session(ctx);
        if (opened.Person != null)
        {
            var who = opened.Person.Sub;
            if (!string.IsNullOrEmpty(opened.Person.Email)) who = opened.Person.Email;
            else if (!string.IsNullOrEmpty(opened.Person.Name)) who = opened.Person.Name;
            await Html(ctx, 200, "Signed in", "<h1>Signed in</h1><p>" + WebUtility.HtmlEncode(who) + "</p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>", null);
            return;
        }
        var current = TryClient();
        var body = "<h1>GNAP CAEP RISC demo</h1>";
        if (current == null)
        {
            var msg = clientErr;
            if (string.IsNullOrEmpty(msg)) msg = "the key could not be read";
            body += "<p>The GNAP client is not configured yet: " + WebUtility.HtmlEncode(msg) + ". Generate the key at the privateKey path, then run scripts/configure_iya_sts.py.</p>";
        }
        else body += "<p><a class=\"button\" href=\"/login\">Sign in with GNAP</a></p>";
        await Html(ctx, 200, "GNAP demo", body, null);
    }

    async Task Login(HttpContext ctx)
    {
        GnapClient current;
        try { current = Client(); }
        catch (Exception err)
        {
            await Html(ctx, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>" + WebUtility.HtmlEncode(err.Message) + "</p><p><a href=\"/\">Start again</a></p>", null);
            return;
        }
        GrantResult started;
        try { started = current.RequestGrant(); }
        catch (Exception err)
        {
            await Html(ctx, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>" + WebUtility.HtmlEncode(err.Message) + "</p><p><a href=\"/\">Start again</a></p>", null);
            return;
        }
        if (started.Grant != null) { await Place(ctx, started.Grant, null); return; }
        var pending = Seal(new JsonObject { ["ids"] = new JsonArray(started.Pending.Id) });
        var secure = current.Config.FinishUri.StartsWith("https:") ? "; Secure" : "";
        ctx.Response.Headers.Location = started.RedirectUrl;
        ctx.Response.Headers.Append("set-cookie", "gpending=" + pending + "; Path=/callback; Max-Age=600; HttpOnly; SameSite=Lax" + secure);
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.StatusCode = 302;
    }

    async Task Callback(HttpContext ctx)
    {
        var pending = Unseal(Cookie(ctx, "gpending"));
        var ids = new List<string>();
        if (pending?["ids"] is JsonArray list)
            foreach (var item in list)
                if (item?.GetValue<string>() is string id) ids.Add(id);
        var flat = new Dictionary<string, string>();
        foreach (var pair in ctx.Request.Query)
            if (pair.Value.Count > 0) flat[pair.Key] = pair.Value[0];
        var clear = "gpending=; Path=/callback; Max-Age=0; HttpOnly; SameSite=Lax";
        GnapClient current;
        try { current = Client(); }
        catch (Exception err)
        {
            await Html(ctx, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>" + WebUtility.HtmlEncode(err.Message) + "</p><p><a href=\"/\">Start again</a></p>", clear);
            return;
        }
        Finished done;
        try { done = current.FinishRedirect(flat, ids); }
        catch (Exception err)
        {
            Console.WriteLine("sign-in refused: " + err.Message);
            await Html(ctx, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>" + WebUtility.HtmlEncode(err.Message) + "</p><p><a href=\"/\">Start again</a></p>", clear);
            return;
        }
        if (done.Grant.Subject == null)
        {
            await Html(ctx, 400, "Sign-in failed", "<h1>Sign-in failed</h1><p>the grant has no subject</p><p><a href=\"/\">Start again</a></p>", clear);
            return;
        }
        await Place(ctx, done.Grant, clear);
        Watch(done.Grant, done.Grant.Subject);
    }

    async Task Place(HttpContext ctx, Grant grant, string extra)
    {
        var local = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
        lock (gate) sessions[local] = (grant.Subject, grant);
        ctx.Response.Headers.Location = "/";
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Append("set-cookie", "gsid=" + Seal(new JsonObject { ["id"] = local }) + "; Path=/; HttpOnly; SameSite=Lax");
        if (!string.IsNullOrEmpty(extra)) ctx.Response.Headers.Append("set-cookie", extra);
        ctx.Response.StatusCode = 303;
        await Task.CompletedTask;
    }

    async Task Logout(HttpContext ctx)
    {
        var opened = Unseal(Cookie(ctx, "gsid"));
        if (opened != null && opened["id"]?.GetValue<string>() is string id)
        {
            (Person Person, Grant Grant) session = default;
            var found = false;
            SignalsReceiver currentReceiver;
            lock (gate)
            {
                found = sessions.TryGetValue(id, out session);
                sessions.Remove(id);
                currentReceiver = receiver;
            }
            if (found && currentReceiver != null && !string.IsNullOrEmpty(session.Grant.GrantId)) currentReceiver.Untrack(session.Grant.GrantId);
            if (found)
            {
                try { Client().Revoke(session.Grant); }
                catch (Exception err) { Console.WriteLine("revoke: " + err.Message); }
            }
        }
        ctx.Response.Headers.Location = "/";
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Append("set-cookie", "gsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
        ctx.Response.StatusCode = 303;
        await Task.CompletedTask;
    }

    async Task Push(HttpContext ctx)
    {
        var raw = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
        try
        {
            var current = Client();
            JsonNode body = string.IsNullOrEmpty(raw) ? null : JsonNode.Parse(raw);
            var done = current.FinishPush(body);
            if (done.Grant.Subject != null) Watch(done.Grant, done.Grant.Subject);
            ctx.Response.Headers.CacheControl = "no-store";
            ctx.Response.StatusCode = 204;
        }
        catch (Exception err)
        {
            ctx.Response.StatusCode = 400;
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(new JsonObject { ["error"] = err.Message }.ToJsonString());
        }
    }

    GnapClient Client()
    {
        lock (gate)
        {
            if (client != null) return client;
            var doc = ReadRaw();
            client = new GnapClient(ConfigLoader.Resolve(doc, Path.GetDirectoryName(Path.GetFullPath(ConfigPath))));
            clientErr = "";
            return client;
        }
    }

    GnapClient TryClient()
    {
        try { return Client(); }
        catch (Exception err) { lock (gate) clientErr = err.Message; return null; }
    }

    JsonObject ReadRaw()
    {
        var doc = JsonNode.Parse(File.ReadAllText(ConfigPath)).AsObject();
        var display = doc["display"] as JsonObject;
        var displayUri = display?["uri"]?.GetValue<string>() ?? "";
        var finish = doc["finishUri"]?.GetValue<string>() ?? "";
        var moved = RedirectsFor(finish, displayUri, publicUrl, publicGiven, port);
        if (!string.IsNullOrEmpty(moved.Finish)) doc["finishUri"] = moved.Finish;
        if (display != null && !string.IsNullOrEmpty(moved.Display)) display["uri"] = moved.Display;
        return doc;
    }

    JsonObject SignalsWanted()
    {
        JsonObject doc;
        try { doc = JsonNode.Parse(File.ReadAllText(ConfigPath)).AsObject(); }
        catch { return null; }
        if (doc["signals"] is JsonValue flag && flag.TryGetValue<bool>(out var on) && !on) return null;
        if (doc["ssf"] is not JsonObject ssf) return null;
        var transmitter = ssf["transmitter"]?.GetValue<string>();
        if (string.IsNullOrEmpty(transmitter)) return null;
        return ssf;
    }

    void Watch(Grant grant, Person person)
    {
        SignalsReceiver running;
        lock (gate)
        {
            latest = grant;
            running = receiver;
        }
        if (running != null)
        {
            running.Track(Sessions.FromPerson(TrackedId(grant, person), person, grant.ExpiresAt));
            return;
        }
        var wanted = SignalsWanted();
        if (wanted == null)
        {
            lock (gate) receiverState = "not configured (signals are off, or no ssf.transmitter)";
            return;
        }
        var interval = 5000;
        if (wanted["pollIntervalMs"] is JsonValue ms && ms.TryGetValue<int>(out var parsed) && parsed != 0) interval = parsed;
        else if (wanted["pollIntervalMs"] is JsonValue num && num.TryGetValue<double>(out var dbl) && dbl != 0) interval = (int)dbl;
        var transmitter = wanted["transmitter"].GetValue<string>();
        GnapClient current;
        try { current = Client(); }
        catch (Exception err) { Console.WriteLine("ssf: not started: " + err.Message); return; }
        SignalsReceiver opened;
        try
        {
            opened = new SignalsReceiver(transmitter, (ids, _) => EndTracked(ids), new ReceiverOpt
            {
                Tls = current.Tls(),
                PollIntervalMs = interval,
                Headers = request =>
                {
                    Grant token;
                    lock (gate) token = latest;
                    if (token == null) return new Dictionary<string, string>();
                    try { return Client().AuthorizationHeaders(token, request.Method, request.Url, request.Body); }
                    catch { return new Dictionary<string, string>(); }
                }
            });
            opened.On("*", Remember);
            opened.Start();
        }
        catch (Exception err)
        {
            Console.WriteLine("ssf: not started: " + err.Message);
            lock (gate) receiverState = "not running: " + err.Message;
            return;
        }
        opened.Track(Sessions.FromPerson(TrackedId(grant, person), person, grant.ExpiresAt));
        lock (gate)
        {
            receiver = opened;
            receiverState = "polling stream " + (opened.Stream?["stream_id"]?.ToString() ?? "") + " at " + transmitter;
        }
    }

    (Person Person, Grant Grant) Session(HttpContext ctx)
    {
        var opened = Unseal(Cookie(ctx, "gsid"));
        if (opened?["id"]?.GetValue<string>() is not string id) return default;
        lock (gate) return sessions.TryGetValue(id, out var record) ? record : default;
    }

    static string Cookie(HttpContext ctx, string name)
    {
        var header = ctx.Request.Headers.Cookie.ToString();
        foreach (var part in header.Split(';'))
        {
            var item = part.Trim();
            if (item.StartsWith(name + "=")) return item[(name.Length + 1)..];
        }
        return "";
    }

    string Seal(JsonObject payload)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.ToJsonString())).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        using var hmac = new HMACSHA256(secret);
        var mac = Convert.ToHexString(hmac.ComputeHash(Encoding.ASCII.GetBytes(encoded))).ToLowerInvariant();
        return encoded + "." + mac;
    }

    JsonObject Unseal(string token)
    {
        var dot = token?.LastIndexOf('.') ?? -1;
        if (string.IsNullOrEmpty(token) || dot <= 0) return null;
        var raw = token[..dot];
        var macText = token[(dot + 1)..];
        using var hmac = new HMACSHA256(secret);
        var mac = Convert.ToHexString(hmac.ComputeHash(Encoding.ASCII.GetBytes(raw))).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(mac), Encoding.ASCII.GetBytes(macText))) return null;
        try
        {
            var text = raw.Replace('-', '+').Replace('_', '/');
            switch (text.Length % 4) { case 2: text += "=="; break; case 3: text += "="; break; }
            return JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(text))) as JsonObject;
        }
        catch { return null; }
    }

    async Task Html(HttpContext ctx, int status, string title, string body, string cookie)
    {
        var page = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>" + WebUtility.HtmlEncode(title) + "</title>\n<link rel=\"stylesheet\" href=\"/styles.css\">\n</head>\n<body>\n<main>\n" + body + "\n</main>\n</body>\n</html>\n";
        if (!string.IsNullOrEmpty(cookie)) ctx.Response.Headers.Append("set-cookie", cookie);
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.Response.StatusCode = status;
        await ctx.Response.WriteAsync(page);
    }

    static (string Finish, string Display) RedirectsFor(string finishUri, string displayUri, string publicUrl, bool given, string port)
    {
        if (given && !string.IsNullOrEmpty(publicUrl) && Uri.TryCreate(publicUrl + "/", UriKind.Absolute, out var baseUri))
            return (Move(finishUri, baseUri), Move(displayUri, baseUri));
        if (!string.IsNullOrEmpty(port)) return (OnPort(finishUri, port), OnPort(displayUri, port));
        return (finishUri, displayUri);
    }

    static string Move(string value, Uri baseUri)
    {
        if (string.IsNullOrEmpty(value) || !Uri.TryCreate(value, UriKind.Absolute, out var next)) return value;
        var path = string.IsNullOrEmpty(next.AbsolutePath) ? "/" : next.AbsolutePath;
        var builder = new UriBuilder(baseUri.Scheme, baseUri.Host, baseUri.Port, path) { Query = next.Query.TrimStart('?'), Fragment = next.Fragment.TrimStart('#') };
        return builder.Uri.ToString();
    }

    static string OnPort(string raw, string port)
    {
        if (string.IsNullOrEmpty(raw) || !Uri.TryCreate(raw, UriKind.Absolute, out var parsed) || string.IsNullOrEmpty(parsed.Host)) return raw;
        var host = parsed.Host.Trim('[', ']').ToLowerInvariant();
        if (host != "localhost" && host != "127.0.0.1" && host != "::1") return raw;
        var shown = parsed.Host;
        if (shown.Contains(':') && !shown.StartsWith('[')) shown = "[" + shown + "]";
        var builder = new UriBuilder(parsed) { Host = shown, Port = int.Parse(port) };
        return builder.Uri.ToString();
    }
}
