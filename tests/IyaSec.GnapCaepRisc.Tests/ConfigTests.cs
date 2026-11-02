// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace IyaSec.Gnap.Tests;

public class ConfigTests
{
    static string PrivateKey()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ec.ExportPkcs8PrivateKeyPem();
    }

    static Config Resolve(JsonObject extra)
    {
        var body = new JsonObject
        {
            ["grantEndpoint"] = "https://idp.example/gnap",
            ["application"] = "app",
            ["privateKey"] = PrivateKey(),
            ["keyProof"] = "httpsig"
        };
        if (extra != null)
            foreach (var pair in extra)
                body[pair.Key] = pair.Value?.DeepClone();
        return ConfigLoader.Resolve(body, ".");
    }

    static string Shown(JsonNode node) => node == null ? "null" : node.ToJsonString();

    [Fact]
    public void DefaultsAccessAndFillsTransmitter()
    {
        var resolved = Resolve(new JsonObject { ["transmitterIssuer"] = "https://idp.example/issuer/" });
        Assert.Equal(new[] { "\"ssf.read\"", "\"ssf.manage\"" }, resolved.Access.Select(Shown).ToArray());
        Assert.Equal("https://idp.example/issuer", resolved.Ssf.Transmitter);
        Assert.Null(resolved.Signals);
        var on = Resolve(new JsonObject { ["signals"] = true, ["transmitterIssuer"] = "https://idp.example/issuer" });
        Assert.Null(on.Signals);
        Assert.NotNull(on.Ssf);
    }

    [Fact]
    public void DropsSsfRightsAndTransmitterWhenSignalsIsFalse()
    {
        var resolved = Resolve(new JsonObject
        {
            ["signals"] = false,
            ["access"] = new JsonArray("openid", "ssf.read"),
            ["transmitterIssuer"] = "https://idp.example",
            ["ssf"] = new JsonObject { ["transmitter"] = "https://idp.example/tx", ["pollIntervalMs"] = 3000 }
        });
        Assert.Equal(new[] { "\"openid\"" }, resolved.Access.Select(Shown).ToArray());
        Assert.Null(resolved.Ssf);
        Assert.False(resolved.Signals);
        var kept = Resolve(new JsonObject
        {
            ["signals"] = false,
            ["access"] = new JsonArray(
                "openid",
                " ssf.read ",
                new JsonObject { ["type"] = "ssf.manage", ["actions"] = new JsonArray("read") },
                new JsonObject { ["type"] = "api" },
                new JsonObject { ["type"] = " ssf.read " }),
            ["ssf"] = new JsonObject { ["transmitter"] = "not a url" }
        });
        Assert.Equal(new[]
        {
            "\"openid\"",
            "{\"type\":\"api\"}",
            "{\"type\":\" ssf.read \"}"
        }, kept.Access.Select(Shown).ToArray());
        Assert.Null(kept.Ssf);
    }

    [Fact]
    public void RefusesSignalsOffWhenSsfRightsWereTheOnlyOnes()
    {
        const string message = "signals is false and access has no rights left after ssf.read and ssf.manage were removed";
        void Check(JsonObject extra)
        {
            var body = new JsonObject
            {
                ["grantEndpoint"] = "https://idp.example/gnap",
                ["application"] = "app",
                ["privateKey"] = PrivateKey(),
                ["keyProof"] = "httpsig"
            };
            foreach (var pair in extra) body[pair.Key] = pair.Value?.DeepClone();
            var err = Assert.Throws<GnapException>(() => ConfigLoader.Resolve(body, "."));
            Assert.Contains(message, err.Message);
            Assert.Equal("config", err.Code);
            Assert.Contains("must name a right this authorization server grants", err.Message);
        }
        Check(new JsonObject { ["signals"] = false, ["access"] = new JsonArray("ssf.read", "ssf.manage") });
        Check(new JsonObject { ["signals"] = false, ["transmitterIssuer"] = "https://idp.example" });
        Check(new JsonObject
        {
            ["signals"] = false,
            ["access"] = new JsonArray(new JsonObject { ["type"] = "ssf.read" }, new JsonObject { ["type"] = "ssf.manage" })
        });
    }

    [Fact]
    public void RefusesASignalsValueThatIsNotTrueOrFalse()
    {
        var body = new JsonObject
        {
            ["grantEndpoint"] = "https://idp.example/gnap",
            ["application"] = "app",
            ["privateKey"] = PrivateKey(),
            ["keyProof"] = "httpsig",
            ["signals"] = "no"
        };
        var err = Assert.Throws<GnapException>(() => ConfigLoader.Resolve(body, "."));
        Assert.Equal("config", err.Code);
        Assert.Equal("signals must be true or false", err.Message);
    }
}
