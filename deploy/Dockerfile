# The secrethive command as an image. The build stage always runs on the builder's own architecture and
# cross-compiles for the target, and the final stage only copies, so a multi-architecture build needs no emulation.
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /src

# Docker says amd64 where .NET says x64. The restore has to be told it is for a self-contained publish,
# or it leaves out the runtime pack and the publish below fails.
RUN echo "linux-$([ "$TARGETARCH" = amd64 ] && echo x64 || echo "$TARGETARCH")" > /rid

COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/SecretHive.Cli/SecretHive.Cli.csproj src/SecretHive.Cli/
RUN dotnet restore src/SecretHive.Cli -r "$(cat /rid)" -p:SelfContained=true -p:PublishSingleFile=true

COPY src/ src/
RUN dotnet publish src/SecretHive.Cli -c Release -r "$(cat /rid)" --no-restore --self-contained \
      -p:PublishSingleFile=true -p:Version="$VERSION" -o /out

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/secrethive /usr/local/bin/secrethive
# Rendering gives files to other users, which only root can do: run with --user 0 for render, status and import.
ENTRYPOINT ["secrethive"]
