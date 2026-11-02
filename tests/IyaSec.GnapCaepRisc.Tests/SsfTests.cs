// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IyaSec.Gnap.Tests;

public class SsfTests
{
    static readonly RSA Private = RSA.Create(2048);
    static readonly RSA Other = RSA.Create(2048);
    static readonly JsonObject Jwk = TestCrypto.RsaJwk(Private, "k1");

    sealed class Quiet : ISignalsLog
    {
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message) { }
    }

    [Fact]
    public void VerifiesASetAndRefusesAnotherKey()
    {
        var good = Sign(new JsonObject { ["alg"] = "RS256", ["kid"] = "k1", ["typ"] = "secevent+jwt" }, new JsonObject { ["a"] = 1 }, Private);
        var verified = JwsVerify.Compact(good, new[] { Jwk });
        Assert.Equal(1, verified.Payload["a"].GetValue<int>());
        var badKey = Sign(new JsonObject { ["alg"] = "RS256", ["kid"] = "k1", ["typ"] = "secevent+jwt" }, new JsonObject { ["a"] = 1 }, Other);
        var err = Assert.Throws<GnapException>(() => JwsVerify.Compact(badKey, new[] { Jwk }));
        Assert.Contains("does not verify", err.Message);
        var badKid = Sign(new JsonObject { ["alg"] = "RS256", ["kid"] = "nope" }, new JsonObject { ["a"] = 1 }, Private);
        err = Assert.Throws<GnapException>(() => JwsVerify.Compact(badKid, new[] { Jwk }));
        Assert.Contains("kid nope", err.Message);
        var none = Sign(new JsonObject { ["alg"] = "none" }, new JsonObject { ["a"] = 1 }, Private);
        err = Assert.Throws<GnapException>(() => JwsVerify.Compact(none, new[] { Jwk }));
        Assert.Contains("does not verify", err.Message);
    }

    [Fact]
    public void ReadsSubjectForms()
    {
        Assert.Equal("https://schemas.openid.net/secevent/caep/event-type/session-revoked", Events.SessionRevoked);
        Assert.Equal("https://schemas.openid.net/secevent/risc/event-type/credential-compromise", Events.CredentialCompromise);
        var got = Events.SubjectOf(JsonNode.Parse("""
        {"format":"complex","user":{"format":"iss_sub","iss":"https://i","sub":"urn:uuid:a"},"session":{"format":"opaque","id":"S1"}}
        """), "https://i");
        Assert.Equal("urn:uuid:a", got["person"]);
        Assert.Equal("S1", got["idp_session"]);
        Assert.Equal(2, got.Count);
        Assert.Empty(Events.SubjectOf(JsonNode.Parse("""{"format":"iss_sub","iss":"https://other","sub":"urn:uuid:a"}"""), "https://i"));
        var email = Events.SubjectOf(JsonNode.Parse("""{"format":"email","email":"A@x.com"}"""), "https://i");
        Assert.Equal("A@x.com", email["email"]);
        Assert.Single(email);
    }

    [Fact]
    public void PollsWithTheGnapTokenAndAcknowledges()
    {
        var state = TxState.Start();
        var ended = new List<string[]>();
        var seen = new List<SignalEvent>();
        var signed = new List<SsfRequest>();
        var gate = new object();
        var receiver = new SignalsReceiver(state.Base, (ids, _) => ended.Add(ids.ToArray()), new ReceiverOpt
        {
            Headers = request =>
            {
                lock (gate) signed.Add(request);
                return new Dictionary<string, string> { ["authorization"] = "GNAP app-token" };
            },
            PollIntervalMs = 60000,
            Log = new Quiet()
        });
        receiver.On("*", seen.Add);
        receiver.Start();
        receiver.Stop();
        Assert.Equal(1, state.Streams);
        Assert.Equal("GNAP app-token", state.Authorization);
        Assert.Equal("s1", receiver.Stream["stream_id"].GetValue<string>());
        string createBody;
        lock (gate) createBody = signed.Last(request => request.Method == "POST" && request.Url.EndsWith("/ssf/stream")).Body;
        Assert.Contains("\"delivery\"", createBody);
        receiver.Track(new TrackedSession { LocalId = "L-a1", Person = "urn:uuid:alice", Email = "alice@example.com", IdpSession = "IDP-A1" });
        receiver.Track(new TrackedSession { LocalId = "L-a2", Person = "urn:uuid:alice", Email = "alice@example.com", IdpSession = "IDP-A2" });
        receiver.Track(new TrackedSession { LocalId = "L-b1", Person = "urn:uuid:bob", Email = "bob@example.com", IdpSession = "IDP-B1" });
        var revoked = state.Deliver(Events.SessionRevoked, JsonNode.Parse("""
        {"format":"complex","user":{"format":"iss_sub","sub":"urn:uuid:alice"},"session":{"format":"opaque","id":"IDP-A1"}}
        """).AsObject(), null, Private);
        state.Deliver(Events.CredentialChange, new JsonObject { ["format"] = "iss_sub", ["iss"] = state.Base, ["sub"] = "urn:uuid:bob" }, new JsonObject { ["credential_type"] = "password" }, Private);
        receiver.PollOnce();
        Assert.Single(ended);
        Assert.Equal(new[] { "L-a1" }, ended[0]);
        Assert.Equal(2, seen.Count);
        Assert.True(seen[0].Ended);
        Assert.Equal(Events.CredentialChange, seen[1].Type);
        Assert.False(seen[1].Ended);
        SsfRequest poll;
        lock (gate) poll = signed.First(request => request.Url.Contains("/ssf/poll/"));
        Assert.Equal("POST", poll.Method);
        Assert.Contains("maxEvents", poll.Body);
        receiver.PollOnce();
        var acked = state.Acked.ToArray();
        Assert.NotEmpty(acked);
        Assert.Equal(revoked, acked[0]);
        Assert.Equal(new[] { revoked }.Concat(acked.Where(item => item != revoked)).ToArray(), acked);
        var bad = state.Deliver(Events.AccountDisabled, new JsonObject { ["format"] = "email", ["email"] = "alice@example.com" }, null, Other);
        receiver.PollOnce();
        receiver.PollOnce();
        Assert.Equal("invalid_key", state.Errs[bad]["err"]);
        receiver.Verify("abc");
        receiver.Stop();
        state.Stop();
    }

    static string Sign(JsonObject header, JsonObject payload, RSA key) => TestCrypto.SignJws(header, payload, key);

    sealed class TxItem
    {
        public string Jti;
        public string Token;
    }

    sealed class TxState
    {
        public string Base;
        public int Streams;
        public string Authorization = "";
        public List<string> Acked = new();
        public Dictionary<string, Dictionary<string, string>> Errs = new();
        readonly List<TxItem> queue = new();
        readonly object gate = new();
        WebApplication app;

        public static TxState Start()
        {
            var state = new TxState();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            state.app = builder.Build();
            state.app.Run(ctx => state.Handle(ctx));
            state.app.StartAsync().GetAwaiter().GetResult();
            var feature = state.app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
            state.Base = feature.Addresses.First(item => item.StartsWith("http://")).TrimEnd('/');
            return state;
        }

        public void Stop() => app.StopAsync().GetAwaiter().GetResult();

        public string Deliver(string eventType, JsonObject subId, JsonObject extra, RSA key)
        {
            var jti = TestCrypto.B64Url(RandomNumberGenerator.GetBytes(16));
            var subject = subId.DeepClone().AsObject();
            if (subject["user"] is JsonObject user) user["iss"] = Base;
            else if (subject["iss"] == null) subject["iss"] = Base;
            var body = new JsonObject { ["event_timestamp"] = 1 };
            if (extra != null) foreach (var pair in extra) body[pair.Key] = pair.Value?.DeepClone();
            var token = TestCrypto.SignJws(
                new JsonObject { ["alg"] = "RS256", ["kid"] = "k1", ["typ"] = "secevent+jwt" },
                new JsonObject
                {
                    ["iss"] = Base, ["aud"] = "my-app", ["jti"] = jti, ["iat"] = 1,
                    ["sub_id"] = subject,
                    ["events"] = new JsonObject { [eventType] = body }
                }, key ?? Private);
            lock (gate) queue.Add(new TxItem { Jti = jti, Token = token });
            return jti;
        }

        async Task Handle(HttpContext ctx)
        {
            var raw = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            var path = ctx.Request.Path.Value ?? "/";
            var auth = ctx.Request.Headers.Authorization.ToString();
            lock (gate) Authorization = auth;
            if (auth != "GNAP app-token" && path != "/.well-known/ssf-configuration" && !path.StartsWith("/jwks"))
            {
                await Json(ctx, 401, new JsonObject { ["error"] = "invalid_token" });
                return;
            }
            if (path == "/.well-known/ssf-configuration" && ctx.Request.Method == "GET")
            {
                await Json(ctx, 200, new JsonObject
                {
                    ["issuer"] = Base,
                    ["jwks_uri"] = Base + "/jwks",
                    ["configuration_endpoint"] = Base + "/ssf/stream",
                    ["verification_endpoint"] = Base + "/ssf/verify",
                    ["delivery_methods_supported"] = new JsonArray("urn:ietf:rfc:8936")
                });
                return;
            }
            if (path == "/jwks")
            {
                await Json(ctx, 200, new JsonObject { ["keys"] = new JsonArray(Jwk.DeepClone()) });
                return;
            }
            if (path == "/ssf/stream" && ctx.Request.Method == "GET")
            {
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync("[]");
                return;
            }
            if (path == "/ssf/stream" && ctx.Request.Method == "POST")
            {
                var body = JsonNode.Parse(raw).AsObject();
                int id;
                lock (gate) { Streams++; id = Streams; }
                var delivery = body["delivery"].AsObject();
                await Json(ctx, 201, new JsonObject
                {
                    ["stream_id"] = "s" + id,
                    ["iss"] = Base,
                    ["aud"] = "my-app",
                    ["delivery"] = new JsonObject { ["method"] = delivery["method"].GetValue<string>(), ["endpoint_url"] = Base + "/ssf/poll/s" + id },
                    ["events_requested"] = body["events_requested"].DeepClone(),
                    ["events_delivered"] = body["events_requested"].DeepClone()
                });
                return;
            }
            if (path == "/ssf/verify")
            {
                ctx.Response.StatusCode = 204;
                return;
            }
            if (path.StartsWith("/ssf/poll/"))
            {
                var body = string.IsNullOrEmpty(raw) ? new JsonObject() : JsonNode.Parse(raw).AsObject();
                lock (gate)
                {
                    if (body["ack"] is JsonArray ack)
                        foreach (var item in ack)
                        {
                            var jti = item.GetValue<string>();
                            Acked.Add(jti);
                            queue.RemoveAll(one => one.Jti == jti);
                        }
                    if (body["setErrs"] is JsonObject setErrs)
                        foreach (var pair in setErrs)
                        {
                            var doc = new Dictionary<string, string>();
                            foreach (var field in pair.Value.AsObject()) doc[field.Key] = field.Value.GetValue<string>();
                            Errs[pair.Key] = doc;
                            queue.RemoveAll(one => one.Jti == pair.Key);
                        }
                }
                string payload;
                lock (gate)
                {
                    var sets = new JsonObject();
                    foreach (var item in queue) sets[item.Jti] = item.Token;
                    payload = new JsonObject { ["sets"] = sets, ["moreAvailable"] = false }.ToJsonString();
                }
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync(payload);
                return;
            }
            await Json(ctx, 404, new JsonObject { ["error"] = "not_found" });
        }

        static async Task Json(HttpContext ctx, int status, JsonObject body)
        {
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(body.ToJsonString());
        }
    }
}
