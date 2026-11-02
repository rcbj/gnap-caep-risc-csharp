# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Python and Node libraries loads: the JSON keys are identical.

## Build and tests

```bash
docker build --target test .
```

The `test` stage runs `dotnet test --nologo` in `mcr.microsoft.com/dotnet/sdk:8.0`, then the Python tests of the install script's trust-chain step (`scripts/test_trust_chain.py`). GitHub Actions uses that command. Do not run the .NET SDK on the host. The demo image does not run the suite.

`python3 scripts/live_iya_sts.py` is the live half. It starts a fresh iya-sts from its `main` branch in memory mode when `IYA_STS_URL` is unset (`IYA_STS_IMAGE` names an iya-sts image to start instead of building one). In a copy of the repository it makes the client key and its self-signed certificate with openssl in the `tools` stage, runs the install script `scripts/configure_iya_sts.py` (standard-library Python on the host), which registers the demo and writes iya-sts's listener CA trust chain to the `tlsCa` file, then builds the demo image, which carries that chain, and runs it with only the key and certificate mounted. It signs in and requires a credential-change event and a session-revoked event on `GET /live-status`; the second ends the local session. `LIVE_STS_PORT` (default 18523) and `LIVE_DEMO_PORT` (default 18623) choose the ports. It never binds port 3000 or 8081, or 18481 to 18495, and it runs no .NET on the host. Use a fresh iya-sts for every run. The nightly workflow (`.github/workflows/nightly.yml`) runs the unit suite and this script at 07:30 UTC (`30 7 * * *`) and on demand.

Package id: `IyaSec.GnapCaepRisc`. Namespace: `IyaSec.Gnap`. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.

## Three calls

```csharp
var client = GnapClient.FromFile("gnap.json");
var started = client.RequestGrant();
var done = client.FinishRedirect(query, new[] { started.Pending.Id });
```

`RequestGrant` returns a redirect and a pending grant. `FinishRedirect` checks the interaction hash against grants this process started, then continues the grant with the key proof. Pass the pending ids this browser was given.

`ConfigLoader.Resolve` loads the same document without starting a grant.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds. `SignalsReceiver.Stop` waits until the poll already in flight has finished.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` is JSON for the sign-in in this browser and the Shared Signals events the demo has accepted: `signedIn`, `subject`, `receiver`, and events of `type` and `jti`. It does not include tokens. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, and `POST /logout` signs out.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Register the application with:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
```

`--dry-run` prints the admin API calls and sends nothing. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

### The iya-sts TLS listener CA trust chain

`tlsCa` in `demo/gnap.json` is the trust store for iya-sts's TLS listener: the grant endpoint and the Shared Signals transmitter. Its default is `generated/idp-ca.pem`, relative to `demo/`. The install script sets it: `scripts/configure_iya_sts.py` fetches the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that document is missing, writes it to that file, and prints the path and the trust anchor's subject and SHA-256. The library takes the whole file as its trust store.

The demo image carries the chain from build time: `.dockerignore` admits `demo/generated/idp-ca.pem` and nothing else under `demo/generated`, and the Dockerfile's `COPY demo demo` puts it at `/app/demo/generated/idp-ca.pem`. A build before the install script has run still succeeds, without the file. Run the install script first, then build. After running it against a different iya-sts, rebuild the image (`docker compose up --build`). `docker-compose.yml` mounts only the client key and certificate. The container still refreshes the file from iya-sts when it starts (`scripts/trust_chain.py`), and keeps the built-in chain when that fails; `TLS_CA_REFRESH=0` turns that off, and the live script runs the demo that way.

The mtls proof presents its self-signed client certificate even when iya-sts's CertificateRequest names only iya-sts's own CA; .NET's `SslStream` sends the one configured certificate, and `TlsTests` holds that.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
