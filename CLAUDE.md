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

Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Layout

- `src/IyaSec.GnapCaepRisc` the client, key proofs (mtls, httpsig, jwsd), and one poll stream
- `tests/IyaSec.GnapCaepRisc.Tests` config, subject, client, and the Shared Signals receiver
- `demo/IyaSec.GnapCaepRisc.Demo` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`docker compose up --build`. `PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`. `SignalsReceiver.Stop` waits until the background poll has finished.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. A pull request merged into `main` publishes the package to nuget.org after the test workflow succeeds on that commit. A direct push does not. The key comes from nuget.org Trusted Publishing (`NuGet/login` trades the workflow's GitHub OIDC token for a one-hour API key); the `NUGET_USER` repository secret is the nuget.org profile name that owns the policy for this repository and `publish.yml`. A version already on nuget.org stays there; the next release is a new `Version` in the library's `.csproj`.
