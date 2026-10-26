# SecretHive

A small, self-hosted key vault for the secrets that services, scripts and deploys need. One container with
SQLite (or SQL Server), pages for people, a REST API for tools (vaults, secrets and their versions, access, accounts,
keys; a browser session reads through it and changes nothing), a command line that writes a compose project's
secrets as files on a host, a PowerShell module for the session that needs one, CI jobs that read with the token
their platform gives them, the read side of the 1Password Connect API for a tool that fetches only that way (such as
Termix's Secret Sources), and an audit trail of every value read.

What it is, why, and how it is run: [docs.xact.cloud/secrethive](https://docs.xact.cloud/secrethive/index.html).
This file is the developer's entry: what is in the repository, how to build it, how to try it.

## What is in the repository

```text
src/SecretHive.Domain/                  the rules of the model: names, fields, certificates, limits
src/SecretHive.Application/             use cases and ports: secrets, access, accounts, keys, networks
src/SecretHive.Infrastructure/          the key ring (envelope encryption), EF Core persistence, backups
src/SecretHive.Infrastructure.Sqlite/   migrations for SQLite
src/SecretHive.Infrastructure.SqlServer/ migrations for SQL Server
src/SecretHive.Api/                     the REST API, version 1
src/SecretHive.Web/                     the server: Blazor pages, sign-in, TLS, jobs; the composition root
src/SecretHive.Cli/                     the secrethive command: render, check, status, run, bundle, host keygen
clients/powershell/                     the PowerShell module and its tests
tests/SecretHive.Unit.Tests/            every test, xUnit v3 on Microsoft.Testing.Platform
tests/browser/                          the pages in headless Chrome, run by CI against the image
deploy/Dockerfile.server                the server image
deploy/Dockerfile                       the command's image
.github/workflows/ci.yml                build, tests on both databases and as root, the images exercised, the pages in a browser, a release on a tag
```

## Building and testing

.NET 10 SDK (`global.json` says which). From the root:

```sh
dotnet build -c Release
dotnet test
```

`dotnet test` alone skips two groups, and CI fails on any skip, so a green local run is weaker than CI by exactly these:

- **SQL Server.** Set `SECRETHIVE_TEST_SQLSERVER` to a connection string without a database name; each test makes and
  drops a database of its own. LocalDB works:
  `SECRETHIVE_TEST_SQLSERVER="Server=(localdb)\MSSQLLocalDB;Integrated Security=true;TrustServerCertificate=True"`.
- **Ownership, modes and the atomic rename** need Linux and root. In the SDK container they run:
  `docker run --rm -v "$PWD":/src -w /src mcr.microsoft.com/dotnet/sdk:10.0 dotnet test`.

Warnings are errors. Nothing in the tests holds a real value: every value is spelt `generated-…`, so a leak shows up
as that word in an output.

## Running the server locally

The server does not start without three things: a master key file, a sign-in, and a database. Nothing has a default
that "works". The sign-in of a new installation is the bootstrap administrator token file; once a super admin has a
password of their own, that file can be taken away.

```sh
mkdir -p run/secrets run/data
openssl rand -base64 32 > run/secrets/master.key
printf '%s' "$(openssl rand -hex 24)" > run/secrets/admin.token     # at least 32 characters, no newline

SecretHive__MasterKeyFile=run/secrets/master.key \
SecretHive__Auth__BootstrapAdminTokenFile=run/secrets/admin.token \
SecretHive__DataDirectory=run/data \
SecretHive__Database__ConnectionString="Data Source=run/data/secrethive.db" \
SecretHive__Tls__HostNames=localhost \
dotnet run --project src/SecretHive.Web -c Release
```

It listens on `8443` (HTTPS, with a certificate it makes for itself) and `8080` (plain HTTP: `/health`, everything
else is sent to HTTPS). The pages are at `https://localhost:8443/`; the first account is `admin`, its first password
is the bootstrap token, and it has to be replaced at the first sign-in. The token itself works on the API as an
all-powerful bearer token:

```sh
auth="Authorization: Bearer $(cat run/secrets/admin.token)"
curl -k -X PUT -H "$auth" -H 'Content-Type: application/json' -d '{}' https://localhost:8443/api/v1/vaults/shop
curl -k -X PUT -H "$auth" -H 'Content-Type: application/json' -d '{"value":"generated-token"}' https://localhost:8443/api/v1/vaults/shop/secrets/api-token
curl -k -H "$auth" https://localhost:8443/api/v1/vaults/shop/secrets/api-token/value
```

Every setting, the proxy, backups, restore (`dotnet SecretHive.Web.dll restore <file>`) and master key rotation are on
[Running in production](https://docs.xact.cloud/secrethive/running-in-production.html). `SecretHive__Database__Provider=SqlServer`
with a connection string switches the database.

## The images

```sh
docker build -f deploy/Dockerfile.server -t secrethive .        # the server, non-root, any UID in group 0
docker build -f deploy/Dockerfile        -t secrethive-cli .    # the command
```

The server image expects `/run/secrets/master.key` and `/run/secrets/admin.token`, writes under `/data`, and listens
on 8443 and 8080. The command's image runs as root on purpose: it hands files to other users.

## The command

```text
secrethive render <stack> --host <profile> [--dry-run] [--target <name>]
secrethive check  <stack> --host <profile>
secrethive status <stack> --host <profile>
secrethive run    <stack> --host <profile> -- <command>

secrethive bundle pull   <stack> --host <profile>
secrethive bundle push   <stack> --host <profile> [--dry-run] [--server-key <file>]
secrethive bundle import <stack> --host <profile>
secrethive bundle set    <stack> <reference> --host <profile>
secrethive bundle prune  <stack> --host <profile>
secrethive host keygen --host <profile>

Run from the root of the compose repository, or pass --repo <dir> (or SECRETHIVE_REPO).
Exit: 0 nothing to do, 10 changed (restart what is named), 20 out of step, 1 refused.
```

`render`, `status` and `bundle import` write and read files that belong to other users, so they run on **Linux, as
root**; everywhere else they are refused by name and the bundle commands still work. `check` and `status` ask the
container runtime and need the `docker` command. No command prints, logs or takes a value as an argument: a value
arrives on standard input or from a prompt.

Two files live in the compose repository and hold no values. The host profile, at its root:

```yaml
# secrethive.host.yml
version: 1
host: web-1
appdata: /srv/appdata
bundle_key: /etc/secrethive/bundle.key           # this host's private key, outside the repository
providers: [api, bundle]                          # the server when it answers, the sealed bundle when it does not
server: https://vault.example.org
server_key: /etc/secrethive/server.key           # this host's key for the server, outside the repository
server_certificate: secrethive-server.crt        # only for a server with a certificate it made for itself
```

The manifest, one per stack:

```yaml
# shop/secrethive.yml
version: 1
stack: shop
vault: shop-prod
targets:
  app:
    path: ${appdata}/shop/secrets     # mounted whole at /run/secrets
    owner: "999:999"                  # the uid:gid the container runs as, in numbers
    restart: [shop]
    keys:
      ConnectionStrings__Default: sql-app-connection
      Mail__Password: mail/smtp-password
      Site__Pfx: site#pfx
  compose:                            # one file of KEY='value' lines, for containers that take variables
    path: ${appdata}/shop/compose-secrets
    owner: "0:0"
    format: env
    restart: []
    keys:
      SMTP_PASSWORD: mail/smtp-password
env:                                  # for `secrethive run`: variables in the command's environment
  API_TOKEN: api-token
```

A reference is `name`, `vault/name` or `vault/name/3` for a pinned version, optionally followed by `#field` or, for a
certificate, `#pfx`, `#pfx-password`, `#certificate`, `#chain` or `#key`. `shop/secrethive.bundle` holds the stack's
values sealed for that one host (RSA-OAEP over AES-GCM, one line per reference) and is safe to commit; sealing needs
only the committed public key, opening needs the private key that never leaves the host.

A single binary for a host:

```sh
dotnet publish src/SecretHive.Cli -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true
```

The whole story of a host, with the fallback rules, is on
[Secrets on a host](https://docs.xact.cloud/secrethive/hosts.html).

## The PowerShell module

`clients/powershell/SecretHive`, for Windows PowerShell 5.1 and PowerShell 7: `Connect-SecretHive`,
`Get-SecretHiveVault`, `Get-SecretHiveSecret`, `Get-SecretHiveValue`, `Invoke-WithSecretHive`,
`Disconnect-SecretHive`. Its exported commands read and never write. Its tests run against a real server:
`clients/powershell/tests/Start-TestServer.ps1` starts one from the build output, `Test-Module.ps1` runs them in
whichever PowerShell starts it. See [clients/powershell/README.md](clients/powershell/README.md).

## Working on it

`CLAUDE.md` is the working agreement: English everywhere, no value in a log line, an argument, an audit row or a test
fixture, a refusal before the first write, nothing temporary inside a target directory, explicit paths in every
commit. Migrations are added with `dotnet tool restore` and `dotnet ef migrations add <Name> --project
src/SecretHive.Infrastructure.Sqlite` (and the same for `.SqlServer`).

MIT licence.
