# gnap-caep-risc

Server-side GNAP client. The package is `IyaSec.GnapCaepRisc`. The namespace is `IyaSec.Gnap`.

```csharp
var client = GnapClient.FromFile("gnap.json");
var started = client.RequestGrant();
var done = client.FinishRedirect(query, new[] { started.Pending.Id });
```

`ConfigLoader.Resolve` loads the same JSON keys as the Python and Node libraries. Methods are `FromFile`, `RequestGrant`, and `FinishRedirect`.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `dotnet test --nologo` in `mcr.microsoft.com/dotnet/sdk:8.0`. GitHub Actions uses that command. Do not run the .NET SDK on the host. The demo image does not run the suite.

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server. The test stage also runs `python3 -m unittest discover -s scripts -p 'test_*.py'`: `scripts/test_trust_chain.py` holds that the install script writes the whole listener chain to the `tlsCa` file. `TlsTests` holds that the library accepts that file as its trust store, and that the mtls proof presents its self-signed certificate when the server's CertificateRequest names only another CA (.NET sends it; Go did not, and needed a fix).

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts unless `IYA_STS_URL` names one that is already running; `IYA_STS_IMAGE` starts a fresh container from that image instead of cloning and building `main`. iya-sts runs in memory mode with clustering and request workers off, published on `127.0.0.1:LIVE_STS_PORT` (default 18523). In a copy of the repository it builds the `tools` stage and makes the client key there as the invoking user, runs the install script on the host, builds the demo image (which must then hold the same chain file; the script checks), and runs it on `LIVE_DEMO_PORT` (default 18623) with host networking and only the key and certificate mounted. It never fetches the CA for the demo, rewrites `tlsCa`, or mounts a CA. It signs in through `/authn-api`, emits credential-change and then session-revoked, and checks both on `GET /live-status`. Use a fresh iya-sts for every run: a second registration of the same application keeps the old key, and the grant then fails. It never binds port 3000 or 8081, or 18481 to 18495. `.github/workflows/nightly.yml` runs the unit suite and this script at 07:30 UTC (`30 7 * * *`) and on demand. Do not add a schedule to `tests.yml`.

`scripts/configure_iya_sts.py` continues when iya-sts refuses the `gnap_access_token` custom-claim set as "not one of" its sets; any other refusal stops it.

## The iya-sts TLS listener CA trust chain

`tlsCa` (default `generated/idp-ca.pem`, relative to `demo/`) is set by the install script, which writes the whole chain from `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root; the handshake's chain as a fallback) to that file. The demo image carries it from build time: `.dockerignore` admits only that file under `demo/generated`, and `COPY demo demo` takes it in; a build without it (CI, a fresh clone) succeeds. Rebuild the image after running the install script against a different iya-sts. The refresh at start stays, but is not the only way the chain gets in; `TLS_CA_REFRESH=0` turns it off, and the live script runs the demo that way and reports `tlsCaInImage`.

## Layout

- `src/IyaSec.GnapCaepRisc` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `tests/IyaSec.GnapCaepRisc.Tests` config, subject, client, TLS (client certificate, trust chain file), and the Shared Signals receiver
- `demo/IyaSec.GnapCaepRisc.Demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app (the install script); `scripts/redirects.py` and `scripts/trust_chain.py` support it; `scripts/test_trust_chain.py` tests the chain step; `scripts/live_iya_sts.py` is the live sign-in

## Demo

`docker compose up --build`. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` returns `signedIn`, `subject`, `receiver`, and each accepted event's `type` and `jti`; it carries no tokens. A session-revoked event ends the cookie sessions whose grant the receiver tracked; one that matched no tracked session still ends the demo's only local session. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`. `SignalsReceiver.Stop` waits until the background poll has finished.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.
