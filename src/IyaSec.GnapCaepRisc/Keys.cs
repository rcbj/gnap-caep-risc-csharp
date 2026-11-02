// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace IyaSec.Gnap;

public sealed class ClientKey
{
    public string Proof { get; init; }
    public ECDsa Ec { get; init; }
    public RSA Rsa { get; init; }
    public string Thumb { get; init; }
    public string Alg { get; init; }
    public string Kid { get; init; }
    public JsonObject Jwk { get; init; }
    public string CertPem { get; init; }
    public string ChainPem { get; init; }

    public string PrivatePem()
    {
        byte[] der = Ec != null ? Ec.ExportPkcs8PrivateKey() : Rsa.ExportPkcs8PrivateKey();
        return Keys.Pem("PRIVATE KEY", der);
    }
}

public static class Keys
{
    public static readonly string[] Proofs = { "mtls", "httpsig", "jwsd" };
    static readonly Regex CertRe = new(@"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", RegexOptions.Compiled);
    static readonly Regex B64UrlRe = new(@"^[A-Za-z0-9_-]*$", RegexOptions.Compiled);

    public static string Pem(string label, byte[] der)
    {
        var body = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    public static ClientKey Load(string privatePem, string certificatePem, string proof)
    {
        var (ec, rsa) = ParsePrivate(privatePem);
        var jwk = PublicJwk(ec, rsa);
        System.Security.Cryptography.X509Certificates.X509Certificate2 cert = null;
        if (!string.IsNullOrWhiteSpace(certificatePem))
        {
            cert = ParseCert(certificatePem);
            if (!SamePublic(ec, rsa, cert))
                throw new GnapException("config", "the certificate is not the public half of the private key");
        }
        var chosen = proof;
        if (string.IsNullOrEmpty(chosen)) chosen = cert != null ? "mtls" : "httpsig";
        if (chosen == "mtls" && cert == null)
            throw new GnapException("config", "keyProof \"mtls\" needs certificate");
        var alg = jwk["alg"]!.GetValue<string>();
        var kid = jwk["kid"]!.GetValue<string>();
        if (chosen == "mtls")
        {
            var blocks = CertRe.Matches(certificatePem).Select(m => m.Value).ToList();
            var leaf = (blocks.Count > 0 ? blocks[0] : certificatePem).Trim() + "\n";
            var chain = blocks.Count == 0 ? new List<string> { certificatePem } : blocks;
            return new ClientKey
            {
                Proof = "mtls", Ec = ec, Rsa = rsa, Thumb = JsonUtil.B64Url(SHA256.HashData(cert.RawData)),
                Alg = alg, Kid = kid, Jwk = jwk, CertPem = leaf,
                ChainPem = string.Join("\n", chain.Select(b => b.Trim())) + "\n"
            };
        }
        return new ClientKey
        {
            Proof = chosen, Ec = ec, Rsa = rsa, Thumb = kid, Alg = alg, Kid = kid, Jwk = jwk,
            CertPem = certificatePem ?? ""
        };
    }

    public static JsonObject PublicKeyObject(ClientKey key)
    {
        if (key.Proof == "mtls")
        {
            if (string.IsNullOrWhiteSpace(key.CertPem))
                throw new GnapException("config", "mutual TLS needs the client certificate");
            return new JsonObject { ["proof"] = "mtls", ["cert"] = key.CertPem.Trim() };
        }
        var jwk = new JsonObject { ["kty"] = key.Jwk["kty"]!.GetValue<string>() };
        foreach (var name in new[] { "crv", "x", "y", "n", "e" })
            if (key.Jwk[name] != null) jwk[name] = key.Jwk[name]!.GetValue<string>();
        jwk["alg"] = key.Alg;
        jwk["kid"] = key.Kid;
        return new JsonObject { ["proof"] = key.Proof, ["jwk"] = jwk };
    }

    public static byte[] Sign(ClientKey key, byte[] data)
    {
        if (key.Ec != null)
        {
            var hash = HashFor(key.Alg);
            return key.Ec.SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        if (key.Rsa != null)
        {
            var hash = HashFor(key.Alg);
            var padding = key.Alg.StartsWith("PS") ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
            return key.Rsa.SignData(data, hash, padding);
        }
        throw new GnapException("config", "a key of this type is not a GNAP client key this library loads");
    }

    public static bool Verify(JsonObject jwk, string alg, byte[] data, byte[] signature)
    {
        try
        {
            var kty = jwk["kty"]?.GetValue<string>();
            if (kty == "RSA")
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = Strict(jwk["n"]?.GetValue<string>(), "signature"),
                    Exponent = Strict(jwk["e"]?.GetValue<string>(), "signature")
                });
                var padding = alg.StartsWith("PS") ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(data, signature, HashFor(alg), padding);
            }
            if (kty == "EC")
            {
                using var ec = ECDsa.Create(new ECParameters
                {
                    Curve = CurveOf(jwk["crv"]?.GetValue<string>()),
                    Q = new ECPoint
                    {
                        X = Pad(Strict(jwk["x"]?.GetValue<string>(), "signature"), SizeOf(jwk["crv"]?.GetValue<string>())),
                        Y = Pad(Strict(jwk["y"]?.GetValue<string>(), "signature"), SizeOf(jwk["crv"]?.GetValue<string>()))
                    }
                });
                return ec.VerifyData(data, signature, HashFor(alg), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
        }
        catch (GnapException) { throw; }
        catch { return false; }
        return false;
    }

    public static string Fingerprint(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        var sum = SHA256.HashData(cert.RawData);
        return string.Join(":", sum.Select(b => b.ToString("X2")));
    }

    static (ECDsa, RSA) ParsePrivate(string text)
    {
        Exception last = null;
        foreach (Match match in Regex.Matches(text, @"-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----"))
        {
            var label = match.Groups[1].Value;
            byte[] der;
            try { der = Convert.FromBase64String(Regex.Replace(match.Groups[2].Value, @"\s", "")); }
            catch (Exception err) { last = err; continue; }
            try
            {
                if (label == "PRIVATE KEY")
                {
                    try
                    {
                        var ec = ECDsa.Create();
                        ec.ImportPkcs8PrivateKey(der, out _);
                        return (ec, null);
                    }
                    catch
                    {
                        var rsa = RSA.Create();
                        rsa.ImportPkcs8PrivateKey(der, out _);
                        return (null, rsa);
                    }
                }
                if (label == "EC PRIVATE KEY")
                {
                    var ec = ECDsa.Create();
                    ec.ImportECPrivateKey(der, out _);
                    return (ec, null);
                }
                if (label == "RSA PRIVATE KEY")
                {
                    var rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(der, out _);
                    return (null, rsa);
                }
            }
            catch (Exception err) { last = err; }
        }
        if (last != null) throw new GnapException("config", "the private key could not be read: " + last.Message, last);
        throw new GnapException("config", "the private key could not be read: no PEM key");
    }

    static System.Security.Cryptography.X509Certificates.X509Certificate2 ParseCert(string text)
    {
        try { return System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(text); }
        catch (Exception err) { throw new GnapException("config", "the certificate could not be read: " + err.Message, err); }
    }

    static bool SamePublic(ECDsa ec, RSA rsa, System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        byte[] left = ec != null ? ec.ExportSubjectPublicKeyInfo() : rsa.ExportSubjectPublicKeyInfo();
        byte[] right = cert.PublicKey.ExportSubjectPublicKeyInfo();
        return left.AsSpan().SequenceEqual(right);
    }

    static JsonObject PublicJwk(ECDsa ec, RSA rsa)
    {
        JsonObject jwk;
        if (ec != null)
        {
            var p = ec.ExportParameters(false);
            var size = (ec.KeySize + 7) / 8;
            jwk = new JsonObject
            {
                ["kty"] = "EC",
                ["crv"] = CurveName(ec.KeySize),
                ["x"] = JsonUtil.B64Url(Pad(p.Q.X, size)),
                ["y"] = JsonUtil.B64Url(Pad(p.Q.Y, size))
            };
        }
        else
        {
            var p = rsa.ExportParameters(false);
            jwk = new JsonObject
            {
                ["kty"] = "RSA",
                ["n"] = JsonUtil.B64Url(Unsigned(p.Modulus)),
                ["e"] = JsonUtil.B64Url(Unsigned(p.Exponent))
            };
        }
        jwk["alg"] = AlgOf(jwk);
        jwk["kid"] = Thumb(jwk);
        return jwk;
    }

    public static string Thumb(JsonObject jwk)
    {
        var kty = jwk["kty"]!.GetValue<string>();
        string raw = kty switch
        {
            "EC" => "{\"crv\":\"" + jwk["crv"]!.GetValue<string>() + "\",\"kty\":\"EC\",\"x\":\"" + jwk["x"]!.GetValue<string>() + "\",\"y\":\"" + jwk["y"]!.GetValue<string>() + "\"}",
            "RSA" => "{\"e\":\"" + jwk["e"]!.GetValue<string>() + "\",\"kty\":\"RSA\",\"n\":\"" + jwk["n"]!.GetValue<string>() + "\"}",
            "OKP" => "{\"crv\":\"" + jwk["crv"]!.GetValue<string>() + "\",\"kty\":\"OKP\",\"x\":\"" + jwk["x"]!.GetValue<string>() + "\"}",
            _ => throw new GnapException("config", "a " + kty + " key is not a GNAP client key this library loads")
        };
        return JsonUtil.B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(raw)));
    }

    static string AlgOf(JsonObject jwk)
    {
        if (jwk["alg"] is JsonValue existing && existing.TryGetValue<string>(out var alg) && alg != "" && alg != "none") return alg;
        var kty = jwk["kty"]!.GetValue<string>();
        if (kty == "EC")
        {
            var crv = jwk["crv"]?.GetValue<string>() ?? "(none)";
            return crv switch
            {
                "P-256" => "ES256",
                "P-384" => "ES384",
                "P-521" => "ES512",
                _ => throw new GnapException("config", "the curve " + crv + " has no signature algorithm")
            };
        }
        if (kty == "RSA") return "RS256";
        if (kty == "OKP") return "EdDSA";
        throw new GnapException("config", "a " + kty + " key is not a GNAP client key this library loads");
    }

    static string CurveName(int bits) => bits switch
    {
        256 => "P-256",
        384 => "P-384",
        521 => "P-521",
        _ => throw new GnapException("config", "a key of this type is not a GNAP client key this library loads")
    };

    static ECCurve CurveOf(string name) => name switch
    {
        "P-256" => ECCurve.NamedCurves.nistP256,
        "P-384" => ECCurve.NamedCurves.nistP384,
        "P-521" => ECCurve.NamedCurves.nistP521,
        _ => throw new GnapException("signature", "the key cannot be read: unsupported curve")
    };

    static int SizeOf(string name) => name switch { "P-256" => 32, "P-384" => 48, "P-521" => 66, _ => 0 };

    static HashAlgorithmName HashFor(string alg) => alg switch
    {
        "ES256" or "RS256" or "PS256" => HashAlgorithmName.SHA256,
        "ES384" or "RS384" or "PS384" => HashAlgorithmName.SHA384,
        "ES512" or "RS512" or "PS512" => HashAlgorithmName.SHA512,
        _ => throw new GnapException("config", "this library does not sign with " + alg)
    };

    static byte[] Unsigned(byte[] raw)
    {
        int i = 0;
        while (i < raw.Length - 1 && raw[i] == 0) i++;
        if (i == 0) return raw;
        return raw[i..];
    }

    static byte[] Pad(byte[] raw, int size)
    {
        if (raw.Length == size) return raw;
        var outp = new byte[size];
        Buffer.BlockCopy(raw, 0, outp, size - raw.Length, raw.Length);
        return outp;
    }

    static byte[] Strict(string value, string what)
    {
        if (value == null || !B64UrlRe.IsMatch(value))
            throw new GnapException("signature", "the JWS " + what + " is not base64url");
        try { return JsonUtil.B64UrlDecode(value); }
        catch { throw new GnapException("signature", "the JWS " + what + " is not base64url"); }
    }
}
