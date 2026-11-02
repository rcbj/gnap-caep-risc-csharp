// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IyaSec.Gnap;

public sealed class TlsOpt
{
    public string Ca { get; init; }
    public string Cert { get; init; }
    public string Key { get; init; }
    public bool Insecure { get; init; }
}

public sealed class Answer
{
    public int Status { get; init; }
    public string ContentType { get; init; }
    public string Body { get; init; }
}

public static class Http
{
    const int MaxBytes = 2 * 1024 * 1024;

    public static Answer Send(string rawUrl, string method, IDictionary<string, string> headers, string body, TlsOpt tls, string code)
    {
        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
            throw new GnapException(code, rawUrl + " is not an http(s) URL");
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 },
                TargetHost = uri.Host
            }
        };
        if (tls != null && tls.Insecure)
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        else if (tls != null && !string.IsNullOrEmpty(tls.Ca))
        {
            var ca = tls.Ca;
            var host = uri.Host;
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, _) => VerifyPinned(cert, ca, host);
        }
        if (tls != null && !string.IsNullOrEmpty(tls.Cert) && !string.IsNullOrEmpty(tls.Key))
        {
            var client = X509Certificate2.CreateFromPem(tls.Cert, tls.Key);
            handler.SslOptions.ClientCertificates = new X509CertificateCollection { client };
        }
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        var request = new HttpRequestMessage(new HttpMethod(method), uri) { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        if (body != null)
            request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
        if (headers != null)
        {
            foreach (var pair in headers)
            {
                if (!request.Headers.TryAddWithoutValidation(pair.Key, pair.Value))
                    request.Content?.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
        }
        try
        {
            using var response = http.Send(request);
            var stream = response.Content.ReadAsStream();
            var buffer = new byte[MaxBytes + 1];
            int read = 0;
            while (read <= MaxBytes)
            {
                int n = stream.Read(buffer, read, buffer.Length - read);
                if (n == 0) break;
                read += n;
            }
            if (read > MaxBytes)
                throw new GnapException(code, rawUrl + " answered more than " + MaxBytes + " bytes");
            return new Answer
            {
                Status = (int)response.StatusCode,
                ContentType = response.Content.Headers.ContentType?.ToString() ?? "",
                Body = Encoding.UTF8.GetString(buffer, 0, read)
            };
        }
        catch (GnapException) { throw; }
        catch (TaskCanceledException err) { throw new GnapException(code, rawUrl + " did not answer within 15 s", err); }
        catch (Exception err) { throw new GnapException(code, rawUrl + ": " + err.Message, err); }
    }

    static bool VerifyPinned(X509Certificate cert, string caPem, string host)
    {
        if (cert == null) return false;
        var leaf = new X509Certificate2(cert);
        var pinned = new X509Certificate2Collection();
        try
        {
            foreach (var block in System.Text.RegularExpressions.Regex.Matches(caPem, @"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----").Select(m => m.Value))
                pinned.Add(X509Certificate2.CreateFromPem(block));
        }
        catch { return false; }
        foreach (var one in pinned)
        {
            if (one.RawData.AsSpan().SequenceEqual(leaf.RawData))
                return leaf.MatchesHostname(host);
        }
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(pinned);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(leaf)) return false;
            return leaf.MatchesHostname(host);
        }
        catch { return false; }
    }
}

static class CertHost
{
    public static bool MatchesHostname(this X509Certificate2 cert, string host)
    {
        try { return cert.MatchesHostnameCore(host); }
        catch { return false; }
    }

    static bool MatchesHostnameCore(this X509Certificate2 cert, string host)
    {
        var dns = new List<string>();
        var ips = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            var san = new System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
            foreach (var name in san.EnumerateDnsNames()) dns.Add(name);
            foreach (var ip in san.EnumerateIPAddresses()) ips.Add(ip.ToString());
        }
        if (IPAddress.TryParse(host, out var parsed))
            return ips.Any(ip => IPAddress.TryParse(ip, out var one) && one.Equals(parsed));
        return dns.Any(name => string.Equals(name, host, StringComparison.OrdinalIgnoreCase));
    }
}
