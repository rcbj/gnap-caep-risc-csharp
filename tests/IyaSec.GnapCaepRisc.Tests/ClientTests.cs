// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IyaSec.Gnap.Tests;

public class ClientTests
{
    static readonly RSA IdKey = RSA.Create(2048);
    static readonly JsonObject IdJwk = TestCrypto.RsaJwk(IdKey, "id1");
    static readonly AuthStub As = AuthStub.Start(IdJwk);

    static string IdToken(string issuer, string aud, string sub)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return TestCrypto.SignJws(new JsonObject { ["alg"] = "RS256", ["kid"] = "id1", ["typ"] = "JWT" }, new JsonObject
        {
            ["iss"] = issuer, ["aud"] = aud, ["sub"] = sub, ["exp"] = now + 600, ["iat"] = now,
            ["email"] = sub + "@example.com", ["sid"] = "sess-1", ["name"] = "Ada"
        }, IdKey);
    }

    [Fact]
    public void InteractionHashVector()
    {
        Assert.Equal("2o3b9NeEcvp0At5d-71yCgybP45eTGm1_pTNMmjv_V0", Proofs.InteractionHash("abc", "def", "xyz", "https://as.example/gnap"));
    }

    [Fact]
    public void RefusesFrontChannelForeignAndAHashThatIsNotOurs()
    {
        As.Reset();
        var gnap = ClientFor("httpsig");
        As.Foreign = true;
        var err = Assert.Throws<GnapException>(() => gnap.RequestGrant());
        Assert.Contains("not on the grant endpoint", err.Message);
        Assert.DoesNotContain(As.Seen, call => call.Url == "/continue");
        As.Foreign = false;
        As.ClearSeen();
        var presenting = ClientFor("httpsig");
        var (result, request) = Started(presenting);
        var client = request["client"].AsObject();
        Assert.Equal("httpsig", client["key"]["proof"].GetValue<string>());
        Assert.False(client.ContainsKey("class_id"));
        Assert.Equal(new[] { "iss_sub", "opaque" }, request["subject"]["sub_id_formats"].AsArray().Select(item => item.GetValue<string>()).ToArray());
        Assert.True(As.Seen[^1].Signature.Length > 0);
        var digest = FinishHash(request["interact"]["finish"]["nonce"].GetValue<string>(), "ref-1");
        err = Assert.Throws<GnapException>(() => presenting.FinishRedirect("hash=" + digest + "&interact_ref=ref-1&access_token=no", new[] { result.Pending.Id }));
        Assert.Contains("tokens through the browser", err.Message);
        Assert.DoesNotContain("front", err.Message);
        err = Assert.Throws<GnapException>(() => presenting.FinishRedirect("hash=" + digest + "&interact_ref=ref-1", new[] { "somebody-else" }));
        Assert.Contains("this browser", err.Message);
        Assert.DoesNotContain(As.Seen, call => call.Url == "/continue");
        err = Assert.Throws<GnapException>(() => presenting.FinishRedirect("hash=nope&interact_ref=ref-1", new[] { result.Pending.Id }));
        Assert.Contains("this browser", err.Message);
    }

    [Fact]
    public void FinishesARedirectChecksTheIdTokenAndRotates()
    {
        As.Reset();
        As.TooFast = true;
        var gnap = ClientFor("httpsig");
        var (result, request) = Started(gnap);
        var digest = FinishHash(request["interact"]["finish"]["nonce"].GetValue<string>(), "ref-1");
        var done = gnap.FinishRedirect(new Dictionary<string, string> { ["hash"] = digest, ["interact_ref"] = "ref-1" }, new[] { result.Pending.Id });
        Assert.Equal("access-1", done.Grant.AccessToken);
        Assert.False(done.Grant.Bearer);
        Assert.Equal("user-1", done.Grant.Subject.Sub);
        Assert.Equal("user-1@example.com", done.Grant.Subject.Email);
        Assert.Equal("sess-1", done.Grant.Subject.Sid);
        Assert.True(done.Grant.Subject.AssertionVerified);
        Assert.Equal("grant-9", done.Grant.GrantId);
        Assert.True(As.TooFastSent);
        var again = gnap.RequestGrant();
        Assert.NotNull(again.Pending);
        var second = JsonNode.Parse(As.Seen.Last(call => call.Url == "/gnap" && call.Method == "POST").Body);
        Assert.Equal("instance-1", second["client"].GetValue<string>());
        var rotated = gnap.Rotate(done.Grant);
        Assert.Equal("access-2", rotated.AccessToken);
        Assert.Equal("user-1", rotated.Subject.Sub);
        Assert.Equal(done.Grant.Continuation.Uri, rotated.Continuation.Uri);
        gnap.Revoke(rotated);
        Assert.Equal("DELETE", As.Seen[^1].Method);
        var err = Assert.Throws<GnapException>(() => gnap.FinishRedirect(new Dictionary<string, string> { ["hash"] = digest, ["interact_ref"] = "ref-1" }, new[] { result.Pending.Id }));
        Assert.Contains("already used", err.Message);
    }

    [Fact]
    public void ProvesTheKeyWithDetachedJwsAndMutualTls()
    {
        As.Reset();
        var jwsd = ClientFor("jwsd");
        var (firstResult, first) = Started(jwsd);
        Assert.Equal("jwsd", first["client"]["key"]["proof"].GetValue<string>());
        var digest = FinishHash(first["interact"]["finish"]["nonce"].GetValue<string>(), "ref-j");
        var done = jwsd.FinishRedirect("?hash=" + digest + "&interact_ref=ref-j", new[] { firstResult.Pending.Id });
        Assert.Equal("Ada", done.Grant.Subject.Name);
        Assert.Contains(As.Seen, call => call.Url == "/continue" && call.Detached.Contains('.'));
        Assert.Equal("", As.Seen.First(call => call.Url == "/continue").Signature);
        As.ClearSeen();
        var mtls = ClientFor("mtls");
        var (secondResult, second) = Started(mtls);
        Assert.Equal("mtls", second["client"]["key"]["proof"].GetValue<string>());
        var gnapCall = As.Seen.First(call => call.Url == "/gnap");
        Assert.Equal(As.Fingerprint, gnapCall.Cert);
        Assert.Equal("", gnapCall.Signature);
        Assert.Equal("", gnapCall.Detached);
        var digest2 = FinishHash(second["interact"]["finish"]["nonce"].GetValue<string>(), "ref-m");
        var finished = mtls.FinishPush(JsonNode.Parse("{\"hash\":\"" + digest2 + "\",\"interact_ref\":\"ref-m\"}"));
        Assert.Equal("access-1", finished.Grant.AccessToken);
        var answer = mtls.Call(finished.Grant, As.Base + "/jwks");
        Assert.Equal(200, answer.Status);
        Assert.Equal("GNAP access-1", As.Seen[^1].Authorization);
        Assert.False(string.IsNullOrEmpty(secondResult.Pending.Id));
    }

    [Fact]
    public void RefusesBearerBadAudienceAndASubjectThatDoesNotMatch()
    {
        As.Reset();
        As.Bearer = true;
        var gnap = ClientFor("httpsig");
        var (result, request) = Started(gnap);
        var digest = FinishHash(request["interact"]["finish"]["nonce"].GetValue<string>(), "ref-b");
        var err = Assert.Throws<GnapException>(() => gnap.FinishRedirect(new Dictionary<string, string> { ["hash"] = digest, ["interact_ref"] = "ref-b" }, new[] { result.Pending.Id }));
        Assert.Equal("validation", err.Code);
        Assert.Contains("bearer", err.Message);
        As.Bearer = false;
        As.Aud = "someone-else";
        var audience = ClientFor("httpsig");
        var (nextResult, nextRequest) = Started(audience);
        var digest2 = FinishHash(nextRequest["interact"]["finish"]["nonce"].GetValue<string>(), "ref-a");
        err = Assert.Throws<GnapException>(() => audience.FinishRedirect(new Dictionary<string, string> { ["hash"] = digest2, ["interact_ref"] = "ref-a" }, new[] { nextResult.Pending.Id }));
        Assert.Contains("id_token is for", err.Message);
        As.Aud = "gnap-caep-risc-demo";
        As.IssSub = "other-user";
        As.Sub = "user-1";
        var (thirdResult, third) = Started(gnap);
        var digest3 = FinishHash(third["interact"]["finish"]["nonce"].GetValue<string>(), "ref-s");
        err = Assert.Throws<GnapException>(() => gnap.FinishRedirect(new Dictionary<string, string> { ["hash"] = digest3, ["interact_ref"] = "ref-s" }, new[] { thirdResult.Pending.Id }));
        Assert.Contains("somebody other", err.Message);
    }

    [Fact]
    public void AcceptsTheApplicationIdentifierAsTheIdTokenAudience()
    {
        As.Reset();
        As.Aud = "gnap-caep-risc-demo";
        As.Sub = "user-2";
        var gnap = ClientFor("httpsig");
        var (result, request) = Started(gnap);
        var digest = FinishHash(request["interact"]["finish"]["nonce"].GetValue<string>(), "ref-app");
        var done = gnap.FinishRedirect(new Dictionary<string, string> { ["hash"] = digest, ["interact_ref"] = "ref-app" }, new[] { result.Pending.Id });
        Assert.Equal("user-2", done.Grant.Subject.Sub);
        done.Grant.ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 10000;
        var fresh = gnap.EnsureFresh(done.Grant);
        Assert.Equal("access-2", fresh.AccessToken);
        fresh.ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 3600000;
        var held = gnap.EnsureFresh(fresh);
        Assert.Equal("access-2", held.AccessToken);
    }

    [Fact]
    public void CertificateChainPutsTheLeafInTheKeyAndTheChainOnTls()
    {
        var leaf = TestCrypto.SelfSigned("leaf.example", null, null);
        var issuer = TestCrypto.SelfSigned("issuer.example", null, null);
        var chain = leaf.CertPem.Trim() + "\n" + issuer.CertPem.Trim() + "\n";
        var key = Keys.Load(leaf.KeyPem, chain, "mtls");
        var published = Keys.PublicKeyObject(key);
        Assert.Single(Regex.Matches(published["cert"].GetValue<string>(), "BEGIN CERTIFICATE"));
        var loaded = X509Certificate2.CreateFromPem(published["cert"].GetValue<string>());
        Assert.Equal(leaf.Fingerprint, Keys.Fingerprint(loaded));
        var cfg = ConfigLoader.Resolve(new JsonObject
        {
            ["grantEndpoint"] = "https://as.example/gnap",
            ["application"] = "chain-demo",
            ["keyProof"] = "mtls",
            ["privateKey"] = leaf.KeyPem,
            ["certificate"] = chain,
            ["finishUri"] = "http://127.0.0.1:9/callback"
        }, ".");
        Assert.Equal(2, Regex.Matches(new GnapClient(cfg).Tls().Cert, "BEGIN CERTIFICATE").Count);
    }

    static GnapClient ClientFor(string proof)
    {
        return new GnapClient(ConfigLoader.Resolve(new JsonObject
        {
            ["grantEndpoint"] = As.Base + "/gnap",
            ["idTokenIssuer"] = As.Base,
            ["application"] = "gnap-caep-risc-demo",
            ["display"] = new JsonObject { ["name"] = "GNAP CAEP RISC demo", ["uri"] = "http://127.0.0.1:3000/" },
            ["access"] = new JsonArray("ssf.read", "ssf.manage"),
            ["subIdFormats"] = new JsonArray("iss_sub", "account", "opaque"),
            ["assertionFormats"] = new JsonArray("id_token"),
            ["keyProof"] = proof,
            ["privateKey"] = As.ClientKeyPem,
            ["certificate"] = As.ClientCertPem,
            ["finishUri"] = "http://127.0.0.1:3000/callback",
            ["finishMethod"] = "redirect",
            ["tlsCa"] = As.ServerCertPem
        }, "."));
    }

    static (GrantResult Result, JsonObject Request) Started(GnapClient gnap)
    {
        var result = gnap.RequestGrant();
        Assert.NotNull(result.Pending);
        var body = As.Seen.Last(call => call.Method == "POST" && call.Url == "/gnap").Body;
        return (result, JsonNode.Parse(body).AsObject());
    }

    static string FinishHash(string clientNonce, string interactRef)
        => Proofs.InteractionHash(clientNonce, "server-nonce", interactRef, As.Base + "/gnap");

    sealed class Seen
    {
        public string Method;
        public string Url;
        public string Body;
        public string Authorization = "";
        public string Signature = "";
        public string Detached = "";
        public string Cert = "";
    }

    sealed class AuthStub
    {
        public string Base;
        public string ServerCertPem;
        public string ClientKeyPem;
        public string ClientCertPem;
        public string Fingerprint;
        public bool Foreign;
        public bool Bearer;
        public bool TooFast;
        public bool TooFastSent;
        public bool OmitToken;
        public string Aud = "instance-1";
        public string Sub = "user-1";
        public string IssSub;
        public List<Seen> Seen = new();
        readonly object gate = new();
        ECDsa publicKey;
        string kid;
        WebApplication app;

        public static AuthStub Start(JsonObject idJwk)
        {
            var server = TestCrypto.SelfSigned("localhost", new[] { "localhost" }, new[] { "127.0.0.1" });
            var client = TestCrypto.SelfSigned("gnap-client", null, null);
            var serverCert = X509Certificate2.CreateFromPem(server.CertPem, server.KeyPem);
            var stub = new AuthStub
            {
                ServerCertPem = server.CertPem,
                ClientKeyPem = client.KeyPem,
                ClientCertPem = client.CertPem,
                Fingerprint = client.Fingerprint
            };
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = Array.Empty<string>() });
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("https://127.0.0.1:0");
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ConfigureHttpsDefaults(https =>
                {
                    https.ServerCertificate = serverCert;
                    https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                    https.AllowAnyClientCertificate();
                    https.CheckCertificateRevocation = false;
                });
            });
            stub.app = builder.Build();
            stub.app.Run(ctx => stub.Handle(ctx, idJwk));
            stub.app.StartAsync().GetAwaiter().GetResult();
            var feature = stub.app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>();
            stub.Base = feature.Addresses.First(item => item.StartsWith("https://")).TrimEnd('/');
            return stub;
        }

        public void Reset()
        {
            lock (gate)
            {
                Seen = new List<Seen>();
                Foreign = false;
                Bearer = false;
                TooFast = false;
                TooFastSent = false;
                OmitToken = false;
                Aud = "instance-1";
                Sub = "user-1";
                IssSub = null;
            }
        }

        public void ClearSeen()
        {
            lock (gate) Seen = new List<Seen>();
        }

        async Task Handle(HttpContext ctx, JsonObject idJwk)
        {
            var raw = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            var path = ctx.Request.Path.Value ?? "/";
            var cert = await ctx.Connection.GetClientCertificateAsync();
            var fp = "";
            if (cert != null) fp = Keys.Fingerprint(new X509Certificate2(cert));
            var call = new Seen
            {
                Method = ctx.Request.Method,
                Url = path,
                Body = raw,
                Authorization = ctx.Request.Headers.Authorization.ToString(),
                Signature = ctx.Request.Headers["signature"].ToString(),
                Detached = ctx.Request.Headers["detached-jws"].ToString(),
                Cert = fp
            };
            lock (gate) Seen.Add(call);
            var problem = Verify(ctx, raw, Base + path);
            if (problem != null)
            {
                await Write(ctx, 401, new JsonObject { ["error"] = "invalid_client", ["error_description"] = problem });
                return;
            }
            bool foreign, bearer, tooFast, omit;
            string aud, sub, issSub;
            lock (gate)
            {
                foreign = Foreign;
                bearer = Bearer;
                tooFast = TooFast;
                omit = OmitToken;
                aud = Aud;
                sub = Sub;
                issSub = IssSub;
                if (path == "/continue" && ctx.Request.Method == "POST" && tooFast && !TooFastSent)
                {
                    TooFastSent = true;
                    tooFast = true;
                }
                else tooFast = false;
            }
            if (path == "/continue" && ctx.Request.Method == "POST" && tooFast)
            {
                await Write(ctx, 400, new JsonObject
                {
                    ["error"] = "too_fast",
                    ["continue"] = new JsonObject
                    {
                        ["uri"] = Base + "/continue",
                        ["wait"] = 0,
                        ["access_token"] = new JsonObject { ["value"] = "cont-token" }
                    }
                });
                return;
            }
            if (ctx.Request.Method == "OPTIONS" && path == "/gnap")
            {
                await Write(ctx, 200, new JsonObject
                {
                    ["grant_request_endpoint"] = Base + "/gnap",
                    ["key_proofs_supported"] = new JsonArray("httpsig", "jwsd", "mtls"),
                    ["interaction_start_modes_supported"] = new JsonArray("redirect"),
                    ["interaction_finish_methods_supported"] = new JsonArray("redirect", "push"),
                    ["sub_id_formats_supported"] = new JsonArray("iss_sub", "opaque"),
                    ["assertion_formats_supported"] = new JsonArray("id_token")
                });
                return;
            }
            if (path == "/.well-known/openid-configuration")
            {
                await Write(ctx, 200, new JsonObject { ["issuer"] = Base, ["jwks_uri"] = Base + "/jwks" });
                return;
            }
            if (path == "/jwks")
            {
                await Write(ctx, 200, new JsonObject { ["keys"] = new JsonArray(idJwk.DeepClone()) });
                return;
            }
            if (path == "/gnap" && ctx.Request.Method == "POST")
            {
                var cont = foreign ? "https://evil.example/continue" : Base + "/continue";
                await Write(ctx, 200, new JsonObject
                {
                    ["instance_id"] = "instance-1",
                    ["interact"] = new JsonObject { ["redirect"] = Base + "/interact/1", ["finish"] = "server-nonce" },
                    ["continue"] = new JsonObject
                    {
                        ["uri"] = cont,
                        ["wait"] = 0,
                        ["access_token"] = new JsonObject { ["value"] = "cont-token" }
                    }
                });
                return;
            }
            if (path == "/continue" && ctx.Request.Method == "POST")
            {
                if (ctx.Request.Headers.Authorization.ToString() != "GNAP cont-token")
                {
                    await Write(ctx, 401, new JsonObject { ["error"] = "invalid_token" });
                    return;
                }
                if (omit)
                {
                    await Write(ctx, 200, new JsonObject { ["instance_id"] = "instance-1" });
                    return;
                }
                var subjectSub = string.IsNullOrEmpty(issSub) ? sub : issSub;
                var token = new JsonObject
                {
                    ["value"] = "access-1",
                    ["access"] = new JsonArray("ssf.read", "ssf.manage"),
                    ["expires_in"] = 3600,
                    ["manage"] = new JsonObject
                    {
                        ["uri"] = Base + "/token/grant-9",
                        ["access_token"] = new JsonObject { ["value"] = "manage-1" }
                    }
                };
                if (bearer) token["flags"] = new JsonArray("bearer");
                await Write(ctx, 200, new JsonObject
                {
                    ["instance_id"] = "instance-1",
                    ["access_token"] = token,
                    ["continue"] = new JsonObject
                    {
                        ["uri"] = Base + "/continue/grant-9",
                        ["access_token"] = new JsonObject { ["value"] = "cont-next" }
                    },
                    ["subject"] = new JsonObject
                    {
                        ["sub_ids"] = new JsonArray(new JsonObject { ["format"] = "iss_sub", ["iss"] = Base, ["sub"] = subjectSub }),
                        ["assertions"] = new JsonArray(new JsonObject { ["format"] = "id_token", ["value"] = IdToken(Base, aud, sub) })
                    }
                });
                return;
            }
            if (path == "/token/grant-9" && ctx.Request.Method == "POST")
            {
                if (ctx.Request.Headers.Authorization.ToString() != "GNAP manage-1")
                {
                    await Write(ctx, 401, new JsonObject { ["error"] = "invalid_token" });
                    return;
                }
                await Write(ctx, 200, new JsonObject
                {
                    ["access_token"] = new JsonObject
                    {
                        ["value"] = "access-2",
                        ["expires_in"] = 3600,
                        ["manage"] = new JsonObject
                        {
                            ["uri"] = Base + "/token/grant-9",
                            ["access_token"] = new JsonObject { ["value"] = "manage-2" }
                        }
                    }
                });
                return;
            }
            if (ctx.Request.Method == "DELETE")
            {
                ctx.Response.StatusCode = 204;
                return;
            }
            await Write(ctx, 404, new JsonObject { ["error"] = "not_found" });
        }

        string Verify(HttpContext ctx, string raw, string target)
        {
            if (!string.IsNullOrEmpty(raw) && ctx.Request.Path == "/gnap")
            {
                try
                {
                    var doc = JsonNode.Parse(raw).AsObject();
                    var jwk = doc["client"] is JsonObject clientNode && clientNode["key"] is JsonObject keyNode ? keyNode["jwk"] as JsonObject : null;
                    if (jwk != null && jwk["kty"]?.GetValue<string>() == "EC")
                    {
                        var x = TestCrypto.B64UrlDecode(jwk["x"].GetValue<string>());
                        var y = TestCrypto.B64UrlDecode(jwk["y"].GetValue<string>());
                        var key = ECDsa.Create(new ECParameters
                        {
                            Curve = ECCurve.NamedCurves.nistP256,
                            Q = new ECPoint { X = Pad(x, 32), Y = Pad(y, 32) }
                        });
                        lock (gate)
                        {
                            publicKey = key;
                            kid = jwk["kid"].GetValue<string>();
                        }
                    }
                }
                catch (Exception err) { return err.Message; }
            }
            if (!string.IsNullOrEmpty(ctx.Request.Headers["signature"]))
            {
                var problem = VerifyHttpSig(ctx, raw, target);
                if (problem != null) return problem;
            }
            if (!string.IsNullOrEmpty(ctx.Request.Headers["detached-jws"]))
            {
                var problem = VerifyJwsd(ctx, raw, target);
                if (problem != null) return problem;
            }
            return null;
        }

        string VerifyHttpSig(HttpContext ctx, string raw, string target)
        {
            var input = ctx.Request.Headers["signature-input"].ToString();
            if (input.Contains(";alg=")) return "alg parameter";
            var match = Regex.Match(input, @"^sig1=\(([^)]*)\)(.*)$");
            if (!match.Success) return input;
            if (!match.Groups[2].Value.Contains("tag=\"gnap\"")) return "tag";
            string wantKid;
            ECDsa key;
            lock (gate) { wantKid = kid; key = publicKey; }
            if (!match.Groups[2].Value.Contains("keyid=\"" + wantKid + "\"")) return "keyid";
            var names = Regex.Matches(match.Groups[1].Value, "\"([^\"]+)\"").Select(item => item.Groups[1].Value).ToList();
            var serialised = "(" + string.Join(" ", names.Select(name => "\"" + name + "\"")) + ")" + match.Groups[2].Value;
            var lines = new List<string>();
            foreach (var component in names)
            {
                string value = component switch
                {
                    "@method" => ctx.Request.Method.ToUpperInvariant(),
                    "@target-uri" => target,
                    _ => ctx.Request.Headers[component].ToString().Trim()
                };
                lines.Add("\"" + component + "\": " + value);
            }
            lines.Add("\"@signature-params\": " + serialised);
            var sigMatch = Regex.Match(ctx.Request.Headers["signature"].ToString(), @"^sig1=:([A-Za-z0-9+/=]*):$");
            if (!sigMatch.Success || key == null) return "signature";
            var signature = Convert.FromBase64String(sigMatch.Groups[1].Value);
            if (!key.VerifyData(Encoding.UTF8.GetBytes(string.Join("\n", lines)), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                return "httpsig verify";
            if (!string.IsNullOrEmpty(raw))
            {
                var digest = "sha-256=:" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(raw))) + ":";
                if (ctx.Request.Headers["content-digest"].ToString() != digest) return "content-digest";
            }
            return null;
        }

        string VerifyJwsd(HttpContext ctx, string raw, string target)
        {
            var parts = ctx.Request.Headers["detached-jws"].ToString().Split('.');
            if (parts.Length != 3) return "detached";
            JsonObject header;
            try { header = JsonNode.Parse(Encoding.UTF8.GetString(TestCrypto.B64UrlDecode(parts[0]))).AsObject(); }
            catch { return "jws header"; }
            if (header["typ"]?.GetValue<string>() != "gnap-binding-jwsd" || header["alg"]?.GetValue<string>() != "ES256") return "jws header";
            string wantKid;
            ECDsa key;
            lock (gate) { wantKid = kid; key = publicKey; }
            if (header["kid"]?.GetValue<string>() != wantKid || header["htm"]?.GetValue<string>() != ctx.Request.Method.ToUpperInvariant() || header["uri"]?.GetValue<string>() != target)
                return "jws claim";
            var authorization = ctx.Request.Headers.Authorization.ToString();
            if (!string.IsNullOrEmpty(authorization))
            {
                var token = authorization.StartsWith("GNAP ") ? authorization[5..] : authorization;
                if (header["ath"]?.GetValue<string>() != TestCrypto.B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(token)))) return "ath";
            }
            else if (header.ContainsKey("ath")) return "ath present";
            var payload = string.IsNullOrEmpty(raw) ? "" : TestCrypto.B64Url(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
            if (parts[1] != payload) return "payload";
            var signature = TestCrypto.B64UrlDecode(parts[2]);
            if (key == null || !key.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                return "jwsd verify";
            return null;
        }

        static byte[] Pad(byte[] data, int size)
        {
            if (data.Length == size) return data;
            var padded = new byte[size];
            Buffer.BlockCopy(data, 0, padded, size - data.Length, data.Length);
            return padded;
        }

        static async Task Write(HttpContext ctx, int status, JsonObject body)
        {
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync(body.ToJsonString());
        }
    }
}
