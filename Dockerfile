FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish demo/IyaSec.GnapCaepRisc.Demo/IyaSec.GnapCaepRisc.Demo.csproj -c Release -o /out --nologo

FROM mcr.microsoft.com/dotnet/aspnet:8.0
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out /app
COPY demo demo
COPY scripts scripts
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()" || exit 1
CMD ["sh", "-c", "python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; exec dotnet /app/IyaSec.GnapCaepRisc.Demo.dll"]
