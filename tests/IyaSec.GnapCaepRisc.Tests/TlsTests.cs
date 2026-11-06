// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace IyaSec.Gnap.Tests;

// The TLS half of Http.Send, against a raw SslStream server whose CertificateRequest is under the
// test's control: the client certificate the mtls proof presents, and the listener CA trust chain
// that tlsCa names.
public class TlsTests
{
    [Fact]
    public void PresentsTheSelfSignedClientCertificateWhenTheServerNamesAnotherCa()
    {
        // iya-sts names only its own CA in certificate_authorities. GNAP's mtls proof registers a
        // self-signed certificate by value, which that list does not name; it must still be sent.
        var root = Authority("CN=sts Root CA", null);
        var server = Leaf("CN=localhost", root.Cert, root.Key);
        var client = TestCrypto.SelfSigned("gnap-client", null, null);
        using var stub = TlsStub.Start(server.WithKey, new X509Certificate2Collection(), new X509Certificate2Collection { root.Cert });
        // The stub really names only the root in its CertificateRequest, as iya-sts does.
        Assert.Equal(new[] { root.Cert.Subject }, AcceptableIssuers(stub.Url));
        var answer = Http.Send(stub.Url, "GET", null, null, new TlsOpt
        {
            Ca = root.Cert.ExportCertificatePem(),
            Cert = client.CertPem,
            Key = client.KeyPem
        }, "test");
        Assert.Equal(200, answer.Status);
        Assert.NotNull(stub.ClientCertificate);
        Assert.Equal(X509Certificate2.CreateFromPem(client.CertPem).Thumbprint, stub.ClientCertificate.Thumbprint);
    }

    [Fact]
    public void AcceptsTheWholeListenerChainFileAsItsTrustStore()
    {
        // The file the install script writes: leaf, TLS Issuing CA, Intermediate, Root, in that order.
        var root = Authority("CN=sts Root CA", null);
        var intermediate = Authority("CN=sts Intermediate CA", root);
        var issuing = Authority("CN=sts TLS Issuing CA", intermediate);
        var server = Leaf("CN=localhost", issuing.Cert, issuing.Key);
        var dir = Directory.CreateTempSubdirectory("gnap-tls-");
        try
        {
            var generated = Directory.CreateDirectory(Path.Combine(dir.FullName, "generated"));
            File.WriteAllText(Path.Combine(generated.FullName, "idp-ca.pem"),
                server.Cert.ExportCertificatePem() + "\n" + issuing.Cert.ExportCertificatePem() + "\n" +
                intermediate.Cert.ExportCertificatePem() + "\n" + root.Cert.ExportCertificatePem() + "\n");
            using var stub = TlsStub.Start(server.WithKey,
                new X509Certificate2Collection { issuing.Cert, intermediate.Cert }, new X509Certificate2Collection { root.Cert });
            var config = ConfigLoader.Resolve(new JsonObject
            {
                ["grantEndpoint"] = stub.Url + "gnap",
                ["idTokenIssuer"] = stub.Url.TrimEnd('/'),
                ["application"] = "gnap-caep-risc-demo",
                ["keyProof"] = "httpsig",
                ["privateKey"] = TestCrypto.SelfSigned("unused", null, null).KeyPem,
                ["finishUri"] = "http://127.0.0.1:3000/callback",
                ["tlsCa"] = "generated/idp-ca.pem"
            }, dir.FullName);
            Assert.Equal(4, System.Text.RegularExpressions.Regex.Matches(config.TlsCa, "BEGIN CERTIFICATE").Count);
            var answer = Http.Send(stub.Url, "GET", null, null, new TlsOpt { Ca = config.TlsCa }, "test");
            Assert.Equal(200, answer.Status);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public void RefusesAListenerOutsideTheChainFile()
    {
        var root = Authority("CN=sts Root CA", null);
        var other = Authority("CN=another Root CA", null);
        var server = Leaf("CN=localhost", other.Cert, other.Key);
        using var stub = TlsStub.Start(server.WithKey, new X509Certificate2Collection(), new X509Certificate2Collection());
        var err = Assert.Throws<GnapException>(() =>
            Http.Send(stub.Url, "GET", null, null, new TlsOpt { Ca = root.Cert.ExportCertificatePem() }, "test"));
        Assert.Equal("test", err.Code);
    }

    // The certificate_authorities a raw client sees in the stub's CertificateRequest.
    static string[] AcceptableIssuers(string url)
    {
        var port = new Uri(url).Port;
        string[] seen = null;
        var probe = TestCrypto.SelfSigned("probe", null, null);
        var cert = new X509Certificate2(X509Certificate2.CreateFromPem(probe.CertPem, probe.KeyPem).Export(X509ContentType.Pfx));
        using var socket = new TcpClient("127.0.0.1", port);
        using var tls = new SslStream(socket.GetStream(), false);
        tls.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
            LocalCertificateSelectionCallback = (_, _, _, _, issuers) =>
            {
                // Called once before the handshake, with no issuers. A certificate returned then is
                // used without a second call, so hold it back until the server has named its CAs.
                if (issuers == null || issuers.Length == 0) return null;
                seen = issuers;
                return cert;
            }
        });
        tls.Write(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        tls.ReadByte();
        return seen ?? Array.Empty<string>();
    }

    sealed record Issued(X509Certificate2 Cert, ECDsa Key, X509Certificate2 WithKey);

    static Issued Authority(string subject, Issued parent)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.AddYears(2);
        X509Certificate2 cert;
        if (parent == null)
            cert = request.CreateSelfSigned(notBefore, notAfter);
        else
            cert = request.Create(parent.Cert.SubjectName, X509SignatureGenerator.CreateForECDsa(parent.Key), notBefore, notAfter, RandomSerial());
        var plain = X509Certificate2.CreateFromPem(cert.ExportCertificatePem());
        return new Issued(plain, key, plain.CopyWithPrivateKey(key));
    }

    static Issued Leaf(string subject, X509Certificate2 issuer, ECDsa issuerKey)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using var cert = request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), RandomSerial());
        var plain = X509Certificate2.CreateFromPem(cert.ExportCertificatePem());
        // A PFX round trip gives SslStream a key it can use on every platform.
        var withKey = new X509Certificate2(plain.CopyWithPrivateKey(key).Export(X509ContentType.Pfx));
        return new Issued(plain, key, withKey);
    }

    static byte[] RandomSerial() => RandomNumberGenerator.GetBytes(12);

    // One TLS listener on 127.0.0.1 that requires a client certificate, names only `named` in its
    // CertificateRequest, and answers every request 200 "ok".
    sealed class TlsStub : IDisposable
    {
        readonly TcpListener listener;
        readonly Task loop;
        public string Url;
        public X509Certificate2 ClientCertificate;

        public static TlsStub Start(X509Certificate2 serverCert, X509Certificate2Collection extra, X509Certificate2Collection named)
        {
            var context = SslStreamCertificateContext.Create(serverCert, extra, false,
                SslCertificateTrust.CreateForX509Collection(named, true));
            return new TlsStub(context);
        }

        TlsStub(SslStreamCertificateContext context)
        {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Url = "https://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/";
            loop = Task.Run(() => Serve(context));
        }

        async Task Serve(SslStreamCertificateContext context)
        {
            while (true)
            {
                TcpClient socket;
                try { socket = await listener.AcceptTcpClientAsync(); }
                catch { return; }
                using (socket)
                using (var tls = new SslStream(socket.GetStream(), false))
                {
                    try
                    {
                        await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                        {
                            ServerCertificateContext = context,
                            ClientCertificateRequired = true,
                            RemoteCertificateValidationCallback = (_, _, _, _) => true,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 }
                        });
                        if (tls.RemoteCertificate != null)
                            ClientCertificate = new X509Certificate2(tls.RemoteCertificate);
                        var buffer = new byte[8192];
                        var seen = new StringBuilder();
                        while (!seen.ToString().Contains("\r\n\r\n"))
                        {
                            var n = await tls.ReadAsync(buffer);
                            if (n == 0) break;
                            seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
                        }
                        var reply = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                        await tls.WriteAsync(reply);
                        await tls.FlushAsync();
                    }
                    catch
                    {
                        // A refused handshake is what RefusesAListenerOutsideTheChainFile expects.
                    }
                }
            }
        }

        public void Dispose()
        {
            listener.Stop();
            try { loop.Wait(2000); } catch { }
        }
    }
}
