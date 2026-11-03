# `docker build --target test .` runs the suite in this image: the .NET tests, then the Python tests of
# the install script's trust-chain step. The demo image below does not run it.
#
# The iya-sts listener CA trust chain is the one thing from demo/generated the demo image carries.
# scripts/configure_iya_sts.py writes it to the file demo/gnap.json's tlsCa names
# (demo/generated/idp-ca.pem), and `COPY demo demo` takes it in, because .dockerignore admits that file
# and nothing else under demo/generated (the client key and certificate stay out, and are mounted). A
# build before the install script has run (CI, a fresh clone) has no chain file and still succeeds: the
# same COPY simply finds none. Rebuild after running the install script against another iya-sts.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS test
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN dotnet test --nologo && python3 -m unittest discover -s scripts -p 'test_*.py' -v

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish demo/IyaSec.GnapCaepRisc.Demo/IyaSec.GnapCaepRisc.Demo.csproj -c Release -o /out --nologo

# The runtime without the demo: python3 for the scripts, openssl for the client key.
# scripts/live_iya_sts.py makes the key in this stage (`--target tools`) before the install script runs,
# because the install script registers the key and must run before the demo image is built.
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS tools
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scripts scripts

FROM tools
COPY --from=build /out /app
COPY demo demo
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()" || exit 1
# At start the chain is refreshed from iya-sts into the tlsCa file, keeping the built-in one when that
# fails. TLS_CA_REFRESH=0 turns the refresh off, so the chain is the one the image was built with.
ENV TLS_CA_REFRESH=1
CMD ["sh", "-c", "if [ \"${TLS_CA_REFRESH}\" != 0 ]; then python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; fi; exec dotnet /app/IyaSec.GnapCaepRisc.Demo.dll"]
