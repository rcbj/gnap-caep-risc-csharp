# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""The install script's trust-chain step: it writes iya-sts's whole listener CA trust chain to the file
the configuration's tlsCa names.

    python3 -m unittest discover -s scripts -p 'test_*.py'

Runs in the test stage of the Dockerfile, which has python3 and openssl. A stub HTTPS listener on
127.0.0.1 presents a chain like iya-sts's (leaf, TLS Issuing CA, Intermediate, Root) and answers
GET /tls/server-certificate with it, or 404 to make the script fall back to the handshake.
"""

import http.server
import json
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import configure_iya_sts
import trust_chain

CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


def _openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _authority(cwd, name, subject, parent=None):
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{name}.key", cwd=cwd)
    ext = Path(cwd) / f"{name}.ext"
    ext.write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                   "subjectKeyIdentifier=hash\n", encoding="utf-8")
    if parent is None:
        _openssl("req", "-new", "-x509", "-key", f"{name}.key", "-out", f"{name}.crt", "-days", "30",
                 "-subj", subject, "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=cwd)
        return
    _openssl("req", "-new", "-key", f"{name}.key", "-out", f"{name}.csr", "-subj", subject, cwd=cwd)
    _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{parent}.crt", "-CAkey", f"{parent}.key",
             "-CAcreateserial", "-out", f"{name}.crt", "-days", "30", "-extfile", f"{name}.ext", cwd=cwd)


def _leaf(cwd, parent):
    _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key", cwd=cwd)
    (Path(cwd) / "leaf.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="utf-8")
    _openssl("req", "-new", "-key", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost", cwd=cwd)
    _openssl("x509", "-req", "-in", "leaf.csr", "-CA", f"{parent}.crt", "-CAkey", f"{parent}.key",
             "-CAcreateserial", "-out", "leaf.crt", "-days", "30", "-extfile", "leaf.ext", cwd=cwd)


class StubListener:
    """HTTPS on 127.0.0.1 that presents leaf + issuing + intermediate and publishes the whole chain."""

    def __init__(self, certs_dir, publish):
        work = Path(certs_dir)
        self.published = "".join((work / f"{name}.crt").read_text() for name in ("leaf", "issuing", "intermediate", "root"))
        presented = work / "presented.pem"
        presented.write_text("".join((work / f"{name}.crt").read_text() for name in ("leaf", "issuing", "intermediate")))
        published = self.published

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 (the http.server name)
                if publish and self.path == "/tls/server-certificate":
                    body = published.encode()
                    self.send_response(200)
                    self.send_header("content-type", "text/plain")
                else:
                    body = b"not found"
                    self.send_response(404)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(presented), str(work / "leaf.key"))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.origin = f"https://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class TrustChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory()
        cwd = cls.certs.name
        _authority(cwd, "root", "/CN=sts Root CA")
        _authority(cwd, "intermediate", "/CN=sts Intermediate CA", "root")
        _authority(cwd, "issuing", "/CN=sts TLS Issuing CA", "intermediate")
        _leaf(cwd, "issuing")
        cls.root_pem = (Path(cwd) / "root.crt").read_text()

    @classmethod
    def tearDownClass(cls):
        cls.certs.cleanup()

    def demo_dir(self, origin):
        demo = tempfile.TemporaryDirectory()
        self.addCleanup(demo.cleanup)
        config = Path(demo.name) / "gnap.json"
        config.write_text(json.dumps({
            "grantEndpoint": origin + "/gnap",
            "application": "gnap-caep-risc-demo",
            "finishUri": "http://localhost:3000/callback",
            "tlsCa": "generated/idp-ca.pem",
        }), encoding="utf-8")
        return Path(demo.name), config

    def test_install_script_writes_the_whole_published_chain_to_the_tlsca_file(self):
        stub = StubListener(self.certs.name, publish=True)
        self.addCleanup(stub.close)
        demo, config = self.demo_dir(stub.origin)
        files = configure_iya_sts.files_of(str(config), "http://localhost:3000")
        self.assertEqual(files["tlsCa"], str(demo / "generated" / "idp-ca.pem"))
        saved = trust_chain.save_trust_chain(stub.origin, files["tlsCa"])
        written = (demo / "generated" / "idp-ca.pem").read_text()
        self.assertEqual(saved["count"], 4)
        self.assertEqual(CERT_RE.findall(written), CERT_RE.findall(stub.published))
        self.assertIn("sts Root CA", saved["anchor_subject"])
        self.assertTrue(saved["anchor_fingerprint"])
        # The file is a trust store an OpenSSL-based verifier accepts for the listener as it is.
        context = ssl.create_default_context(cafile=files["tlsCa"])
        port = int(stub.origin.rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                self.assertIsNotNone(tls.getpeercert())

    def test_falls_back_to_the_chain_the_handshake_presents(self):
        stub = StubListener(self.certs.name, publish=False)
        self.addCleanup(stub.close)
        demo, config = self.demo_dir(stub.origin)
        self.assertEqual(trust_chain.main(["--config", str(config)]), 0)
        written = CERT_RE.findall((demo / "generated" / "idp-ca.pem").read_text())
        self.assertEqual(len(written), 3)
        self.assertEqual(written[0], CERT_RE.findall(stub.published)[0])

    def test_trust_chain_main_writes_the_file_tlsca_names(self):
        stub = StubListener(self.certs.name, publish=True)
        self.addCleanup(stub.close)
        demo, config = self.demo_dir(stub.origin)
        self.assertEqual(trust_chain.main(["--config", str(config)]), 0)
        written = CERT_RE.findall((demo / "generated" / "idp-ca.pem").read_text())
        self.assertEqual(len(written), 4)
        self.assertEqual(written[-1], CERT_RE.findall(self.root_pem)[0])


if __name__ == "__main__":
    unittest.main()
