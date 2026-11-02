// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace IyaSec.Gnap.Tests;

static class TestCrypto
{
    public static string B64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string value)
    {
        var text = value.Replace('-', '+').Replace('_', '/');
        switch (text.Length % 4)
        {
            case 2: text += "=="; break;
            case 3: text += "="; break;
        }
        return Convert.FromBase64String(text);
    }

    public static string Unsigned(byte[] data)
    {
        var start = 0;
        while (start < data.Length - 1 && data[start] == 0) start++;
        return B64Url(data[start..]);
    }

    public static JsonObject RsaJwk(RSA key, string kid)
    {
        var p = key.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "RSA",
            ["n"] = Unsigned(p.Modulus),
            ["e"] = Unsigned(p.Exponent),
            ["kid"] = kid,
            ["alg"] = "RS256",
            ["use"] = "sig"
        };
    }

    public static string SignJws(JsonObject header, JsonObject payload, RSA key)
    {
        var h = B64Url(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var p = B64Url(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var sig = key.SignData(Encoding.ASCII.GetBytes(h + "." + p), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return h + "." + p + "." + B64Url(sig);
    }

    public static (string KeyPem, string CertPem, string Fingerprint) SelfSigned(string commonName, string[] dns, string[] ips)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + commonName, ec, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        if ((dns?.Length ?? 0) + (ips?.Length ?? 0) > 0)
        {
            var san = new SubjectAlternativeNameBuilder();
            if (dns != null) foreach (var name in dns) san.AddDnsName(name);
            if (ips != null) foreach (var ip in ips) san.AddIpAddress(System.Net.IPAddress.Parse(ip));
            request.CertificateExtensions.Add(san.Build());
        }
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddYears(3));
        var certPem = cert.ExportCertificatePem();
        var keyPem = ec.ExportPkcs8PrivateKeyPem();
        var loaded = X509Certificate2.CreateFromPem(certPem, keyPem);
        return (keyPem, certPem, Keys.Fingerprint(loaded));
    }
}
