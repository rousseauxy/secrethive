using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Microsoft.AspNetCore.Antiforgery;
using SecretHive.Api;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Infrastructure.Backup;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;
using SecretHive.Infrastructure.Sqlite;
using SecretHive.Infrastructure.SqlServer;
using SecretHive.Web;
using SecretHive.Web.Components;
using SecretHive.Web.Security;
using SecretHive.Web.SignIn;

var builder = WebApplication.CreateBuilder(args);

// Every statement the database layer runs is not news. Its warnings and errors are.
builder.Logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);

// In a container the log is for a collector, not for eyes: one JSON object per line, with the fields of every
// audit event as fields. That is how the audit trail leaves the host without anything installed in the server.
if (builder.Configuration.GetValue<bool>("SecretHive:Logging:Json") || builder.Configuration.GetValue<bool>("DOTNET_RUNNING_IN_CONTAINER"))
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(json =>
    {
        // Without a format the line carries no time at all, and when something happened is half of an audit event.
        json.UseUtcTimestamp = true;
        json.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
    });
}

// With a collector address given, logs (the audit events among them), traces and request metrics go there too.
if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
{
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(resource => resource.AddService("secrethive"))
        .WithLogging(logging => logging.AddOtlpExporter())
        .WithTracing(tracing => tracing.AddAspNetCoreInstrumentation().AddOtlpExporter())
        .WithMetrics(metrics => metrics.AddAspNetCoreInstrumentation().AddOtlpExporter());
}

// Three things the server cannot run without, each from a file or a setting, none with a default that "works":
// a master key, a sign-in, a database. Missing any of them stops the start with a message that names it.
var section = builder.Configuration.GetSection("SecretHive");
var masterKeyFile = section["MasterKeyFile"] ?? throw new InvalidOperationException("SecretHive:MasterKeyFile is not set. The server does not start without a master key.");

// The bootstrap token sets an installation up and is the way back in. Once a super admin can sign in without it,
// the file may be taken away: the token then signs nobody in, and whether there still is a sign-in is checked
// below, against the accounts. A file that is there and does not hold a token is still refused.
var tokenFile = section["Auth:BootstrapAdminTokenFile"] is { Length: > 0 } named && File.Exists(named) ? named : null;
var provider = section["Database:Provider"] ?? "Sqlite";
var connectionString = section["Database:ConnectionString"] ?? throw new InvalidOperationException("SecretHive:Database:ConnectionString is not set.");
var dataDirectory = section["DataDirectory"] ?? "/data";

var masterKey = MasterKey.Load(masterKeyFile);

// Earlier master keys, named only while moving away from them: the server reads what they protected, stores it
// again under the current key at start, and from then on needs them for nothing.
var retiredKeys = (section["RetiredMasterKeyFiles"] ?? "").Split([',', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(MasterKey.Load).Where(old => old.Id != masterKey.Id).ToList();
var keyRing = new KeyRing(masterKey, retiredKeys);
var adminToken = new BootstrapAdminToken(tokenFile is null ? [] : BootstrapAdminHandler.HashTokenFile(tokenFile));

// TLS on the server itself, always, unless it is switched off on purpose. With no certificate given the server
// makes one for itself, so there is never a reason to send a secret over the wire in the clear: not on a LAN, and
// not between a proxy and this server. Plain HTTP stays open for one thing, a health probe; everything else on it
// is told where HTTPS is.
var tls = section.GetSection("Tls");
var httpPort = int.Parse(section["Http:Port"] ?? "8080", CultureInfo.InvariantCulture);
var httpsPort = int.Parse(tls["Port"] ?? "8443", CultureInfo.InvariantCulture);
var serverCertificate = string.Equals(tls["Enabled"], "false", StringComparison.OrdinalIgnoreCase)
    ? null
    : ServerCertificate.Resolve(tls, dataDirectory, masterKey, retiredKeys);
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.ListenAnyIP(httpPort);
    if (serverCertificate is not null)
    {
        kestrel.ListenAnyIP(httpsPort, listen => listen.UseHttps(serverCertificate.Certificate));
    }
});

// A proxy in front is believed about who the caller is and which scheme was used only when it is named here.
// Without that, anyone could put any address in the audit trail by sending a header.
var trustedProxies = (section["Proxy:Trusted"] ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = trustedProxies.Length == 0
        ? ForwardedHeaders.None
        : ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;

    // Behind a second proxy (a CDN in front of the named one) the last hop in X-Forwarded-For is the CDN, not the
    // visitor. Such a CDN names the visitor in a header of its own, and the trusted proxy passes it on. It is only
    // as true as the path is closed: whoever reaches the trusted proxy around the CDN, or whose header the proxy
    // passes on unchanged, chooses the address this server sees. That address is what the audit trail records and
    // what a vault's or a key's allowed networks are checked against (measured 2026-10-11), so the proxy has to
    // overwrite this header on every request, or the setting has to stay off.
    if (section["Proxy:ClientAddressHeader"] is { Length: > 0 } clientAddressHeader)
    {
        options.ForwardedForHeaderName = clientAddressHeader;
    }

    options.KnownProxies.Clear();
    options.KnownIPNetworks.Clear();
    foreach (var proxy in trustedProxies)
    {
        options.KnownProxies.Add(IPAddress.Parse(proxy));
    }
});

var version = typeof(ServerMarker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "unknown";
builder.Services.AddSingleton(new ServerInfo(version, DateTime.UtcNow, provider, masterKey.Id, [.. retiredKeys.Select(old => old.Id)], dataDirectory, serverCertificate, httpPort, serverCertificate is null ? null : httpsPort, trustedProxies, tokenFile is not null));

builder.Services.AddSingleton<IKeyRing>(keyRing);
builder.Services.AddSingleton(adminToken);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<AuditLogInterceptor>();
builder.Services.AddDbContext<SecretHiveDbContext>((services, options) =>
{
    options.AddInterceptors(services.GetRequiredService<AuditLogInterceptor>());
    if (string.Equals(provider, "SqlServer", StringComparison.OrdinalIgnoreCase))
    {
        options.UseSecretHiveSqlServer(connectionString);
    }
    else if (string.Equals(provider, "Sqlite", StringComparison.OrdinalIgnoreCase))
    {
        options.UseSecretHiveSqlite(connectionString);
    }
    else
    {
        throw new InvalidOperationException($"SecretHive:Database:Provider is '{provider}'; it must be Sqlite or SqlServer.");
    }
});
builder.Services.AddScoped<ISecretStore, EfSecretStore>();
builder.Services.AddScoped<SecretService>();
builder.Services.AddScoped<IUserStore, EfUserStore>();
builder.Services.AddSingleton<IPasswordHasher, SecretHive.Infrastructure.Accounts.PlatformPasswordHasher>();
builder.Services.AddScoped<AccountService>();
builder.Services.AddScoped<AuditWriter>();
builder.Services.AddScoped<IAccessStore, EfAccessStore>();
builder.Services.AddScoped<GroupService>();
builder.Services.AddScoped<IKeyStore, EfKeyStore>();
builder.Services.AddScoped<KeyService>();
builder.Services.AddSingleton<ICallerResolver, CallerResolver>();
builder.Services.AddScoped<IOidcProviderStore, EfOidcProviderStore>();
builder.Services.AddScoped<IExternalLoginStore, EfExternalLoginStore>();
builder.Services.AddScoped<ExternalAccountService>();
builder.Services.AddScoped<ProviderService>();
builder.Services.AddScoped<NetworkService>();

// Where a sign-in provider sends the browser back to. Behind a proxy that is the public address, not the one this
// server listens on, and a provider only accepts the exact address registered with it.
builder.Services.AddSingleton(new PublicUrl(section["PublicBaseUrl"], serverCertificate is not null));
builder.Services.AddHostedService<RetentionJob>();

// The server's own small secrets go under the master key, so a backup and the master key are all a restore needs.
builder.Services.AddSingleton(new MasterKeySecretProtector(masterKey, retiredKeys));
builder.Services.AddSingleton<DataProtectionSecretProtector>();
builder.Services.AddSingleton<ISecretProtector, ServerSecretProtector>();

// Backups: a file a day beside the data, each read back before it counts. They never hold the master key, and
// are only worth something together with it; keep the two apart.
var backupOptions = new BackupOptions(
    section["Backup:Directory"] ?? Path.Combine(dataDirectory, "backups"),
    int.Parse(section["Backup:Keep"] ?? "14", CultureInfo.InvariantCulture),
    int.Parse(section["Backup:IntervalHours"] ?? "24", CultureInfo.InvariantCulture),
    !string.Equals(section["Backup:Enabled"], "false", StringComparison.OrdinalIgnoreCase),
    version);
builder.Services.AddSingleton(backupOptions);
builder.Services.AddSingleton(BackupSeal.From(masterKey, retiredKeys));
builder.Services.AddScoped<KeyRotation>();
builder.Services.AddSingleton<BackupStatus>();
builder.Services.AddScoped<BackupArchive>();
builder.Services.AddScoped<BackupService>();
builder.Services.AddHostedService<BackupJob>();
builder.Services.AddScoped<ExpiryWatch>();
builder.Services.AddHostedService<ExpiryJob>();
builder.Services.AddSingleton(services => new KeyRateLimiter(int.Parse(section["Keys:RequestsPerMinute"] ?? "300", CultureInfo.InvariantCulture), services.GetRequiredService<TimeProvider>()));

// The keys that sign the session cookie are stored encrypted under a key derived from the master key. Left in the
// clear, whoever could read the data folder could forge the administrator's cookie and read every secret through
// the pages, without ever needing the master key.
var sessionKey = new SessionKey(masterKey.Derive("secrethive/data-protection/v1"), masterKey.Id);
// During a rotation the session keys stored under a retired master key are stored again under the current one,
// before anything reads the ring: whoever is signed in stays signed in, also once the old key is no longer named.
var retiredSessionKeys = retiredKeys.Select(old => new SessionKey(old.Derive("secrethive/data-protection/v1"), old.Id)).ToList();
SessionKeyXmlDecryptor.MoveToCurrentKey(Path.Combine(dataDirectory, "session-keys"), sessionKey, retiredSessionKeys);
foreach (var old in retiredSessionKeys)
{
    builder.Services.AddSingleton(old);
}

builder.Services.AddSingleton(sessionKey);
builder.Services.AddDataProtection()
    .SetApplicationName("SecretHive")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDirectory, "session-keys")));
builder.Services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(
    new ConfigureOptions<KeyManagementOptions>(keys => keys.XmlEncryptor = new SessionKeyXmlEncryptor(sessionKey)));

// Three ways in. People sign in with an account and get a cookie, checked on every request against the account as
// it is now. Tools send a key that belongs to an identity. The bootstrap token still works as a bearer token for
// setting things up, and may do everything.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/account/denied";
        options.Cookie.Name = "secrethive";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = serverCertificate is null ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = false;

        options.Events.OnValidatePrincipal = Accounts.ValidateCookieAsync;

        // A tool that calls the API without a token wants to hear "401", not to be sent to a sign-in page.
        options.Events.OnRedirectToLogin = context =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            }
            else
            {
                context.Response.Redirect(context.RedirectUri);
            }

            return Task.CompletedTask;
        };
    })
    .AddScheme<BootstrapAdminOptions, BootstrapAdminHandler>(BootstrapAdminHandler.SchemeName, options => options.TokenHash = adminToken.Hash)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyHandler>(ApiKeyHandler.SchemeName, _ => { })
    .AddScheme<AuthenticationSchemeOptions, ProviderTokenHandler>(ProviderTokenHandler.SchemeName, _ => { });

// Tokens signed by an issuer a super admin trusts for the API: a CI job's identity, with nothing stored for it.
builder.Services.AddSingleton<ApiTokenValidator>();
builder.Services.AddSingleton<IExternalTokenValidator>(services => services.GetRequiredService<ApiTokenValidator>());
builder.Services.AddOidcProviders();
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Api", new AuthorizationPolicyBuilder(ApiKeyHandler.SchemeName, ProviderTokenHandler.SchemeName, BootstrapAdminHandler.SchemeName, CookieAuthenticationDefaults.AuthenticationScheme).RequireAuthenticatedUser().Build());
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
// A page whose connection dropped (a phone switched to another app) is kept for half an hour, so coming back to it
// resumes it, an open dialog and what was typed included, instead of starting the page again. The framework keeps
// three minutes; a few people use this server, so the memory is no concern.
builder.Services.AddRazorComponents().AddInteractiveServerComponents(options => options.DisconnectedCircuitRetentionPeriod = TimeSpan.FromMinutes(30));
builder.Services.AddScoped<Vaults>();
builder.Services.AddSingleton<ContentSecurityPolicy>();

// Theme packs: YAML files that restate colours and a name, no code. The ones that ship, and the operator's own.
builder.Services.AddSingleton<SecretHive.Web.Theming.IThemeService, SecretHive.Web.Theming.ThemeService>();
builder.Services.AddSingleton<SecretHive.Web.Theming.ThemeChoice>();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Database.MigrateAsync();

    // "restore <file>": fill this (empty) database from a backup and stop. Run with the same master key file the
    // backup was made under; that and the backup are all it needs.
    if (args is ["restore", var backupFile])
    {
        try
        {
            var facts = await scope.ServiceProvider.GetRequiredService<BackupArchive>().RestoreAsync(() => File.OpenRead(backupFile));
            await scope.ServiceProvider.GetRequiredService<AuditWriter>().RecordAsync(
                "restore.executed",
                Caller.System("restore"),
                $"{Path.GetFileName(backupFile)} made={facts.CreatedUtc:yyyy-MM-ddTHH:mm:ssZ} rows={facts.Total.ToString(CultureInfo.InvariantCulture)}",
                SecretHive.Domain.Entities.AuditSeverity.Security);
            app.Logger.LogWarning("Restored {Rows} rows from {File}, made {Made:u} by release {Release}. Start the server normally now.", facts.Total, Path.GetFileName(backupFile), facts.CreatedUtc, facts.Server);
            return 0;
        }
        catch (Exception e) when (e is SecretHive.Domain.DomainException or IOException or UnauthorizedAccessException)
        {
            app.Logger.LogCritical("Restore refused: {Reason}", e.Message);
            return 2;
        }
    }

    // Everything wrapped under an earlier master key moves under the current one. What is under a key this server
    // was not given cannot be read by it at all: better not to start than to serve a vault that opens nothing.
    var rotation = await scope.ServiceProvider.GetRequiredService<KeyRotation>().RunAsync();
    if (rotation.Unreadable.Count > 0)
    {
        throw new InvalidOperationException(
            $"This database holds secrets under master key {string.Join(", ", rotation.Unreadable)}, and the server was started with {masterKey.Id}. " +
            "Start it with the master key the database was written under; or, to move to a new key, name the old key file in SecretHive:RetiredMasterKeyFiles.");
    }

    if (rotation.Moved > 0)
    {
        app.Logger.LogWarning("Master key rotated: {Versions} versions moved from {From} to {To}.", rotation.Moved, string.Join(",", rotation.From), masterKey.Id);
    }

    // Since 0.29 linked names share their ordinary fields. Links made before carry each their own: they are made to
    // agree once, on record, and from then on every start finds nothing to do.
    var aligned = await scope.ServiceProvider.GetRequiredService<SecretService>().AlignLinkedFieldsAsync(Caller.System("startup"));
    if (aligned > 0)
    {
        app.Logger.LogWarning("Linked secrets: the ordinary fields of {Values} value(s) were made to agree; the audit trail says which.", aligned);
    }

    // A client secret stored under the session keys (before 0.7) or under a retired master key moves under the current one.
    var providerStore = scope.ServiceProvider.GetRequiredService<IOidcProviderStore>();
    var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();
    var underMaster = scope.ServiceProvider.GetRequiredService<MasterKeySecretProtector>();
    foreach (var stored in await providerStore.ListAsync(CancellationToken.None))
    {
        if (stored.ProtectedClientSecret.Length > 0 && !underMaster.IsUnderCurrentKey(stored.ProtectedClientSecret) && protector.Unprotect(stored.ProtectedClientSecret) is { } clientSecret)
        {
            stored.ProtectedClientSecret = protector.Protect(clientSecret);
            await providerStore.UpdateAsync(stored, CancellationToken.None);
        }
    }

    app.Services.GetRequiredService<SecretHive.Web.Theming.ThemeChoice>().Name =
        await scope.ServiceProvider.GetRequiredService<ISecretStore>().GetSettingAsync(SecretHive.Web.Theming.ThemeChoice.SettingKey, CancellationToken.None);

    // The first administrator, when there is no account at all. Its first password is the bootstrap token, which
    // already is a secret in a file on this host, and it has to be replaced at the first sign-in.
    if (tokenFile is not null)
    {
        if (await scope.ServiceProvider.GetRequiredService<AccountService>().EnsureFirstAdminAsync(File.ReadAllText(tokenFile), CancellationToken.None))
        {
            app.Logger.LogWarning("No account existed. Created '{UserName}': sign in with the bootstrap token as its password and choose a new one.", AccountService.FirstAdminUserName);
        }
    }
    else
    {
        // Without the token there has to be someone who can run the server: an enabled super admin who signs in
        // with a password of their own choosing or through a provider. Otherwise nobody could ever get in.
        var administrators = (await scope.ServiceProvider.GetRequiredService<IUserStore>().ListAsync(CancellationToken.None))
            .Count(user => user is { Role: SecretHive.Domain.Entities.UserRole.SuperAdmin, IsDisabled: false, IsService: false, MustChangePassword: false });
        if (administrators == 0)
        {
            throw new InvalidOperationException(
                "There is no bootstrap admin token (SecretHive:Auth:BootstrapAdminTokenFile names no file that exists) and no super admin who can sign in. " +
                "There is no mode without a sign-in: put the token file in place, at least 32 characters with no whitespace.");
        }

        app.Logger.LogWarning("Running without a bootstrap admin token: {Count} super admin(s) can sign in. To get back in if they cannot, put a token file in place and restart.", administrators);
    }
}

app.UseForwardedHeaders();

// A proxy names the scheme of a WebSocket request as it is on the wire: Traefik sends X-Forwarded-Proto: wss (or ws).
// Taken as is, that request is "not HTTPS", and the redirect below answered the page's connection with a 302 it
// cannot follow: every page fell back to long polling (measured 2026-10-18 behind Traefik). It is HTTPS, so say so.
app.Use((context, next) =>
{
    if (string.Equals(context.Request.Scheme, "wss", StringComparison.OrdinalIgnoreCase))
    {
        context.Request.Scheme = Uri.UriSchemeHttps;
    }
    else if (string.Equals(context.Request.Scheme, "ws", StringComparison.OrdinalIgnoreCase))
    {
        context.Request.Scheme = Uri.UriSchemeHttp;
    }

    return next();
});

// On every answer: no guessing at content types, no framing by another site, no referrer carried elsewhere, no
// script but the server's own; and with TLS on, a year of HTTPS for the browser. A proxy may rewrite
// X-Frame-Options (one in front of this server did, to a value browsers ignore); frame-ancestors in the policy holds.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    headers.ContentSecurityPolicy = await context.RequestServices.GetRequiredService<ContentSecurityPolicy>()
        .HeaderAsync(context.RequestServices.GetRequiredService<IOidcProviderStore>(), context.RequestAborted);
    if (context.Request.IsHttps)
    {
        headers.StrictTransportSecurity = "max-age=31536000";
    }

    await next();
});

if (serverCertificate is not null)
{
    // Only to a name this server answers for: the Host header of a plain request is whatever the client sent, and
    // a redirect built from it would send the next request, with its path, wherever the client chose.
    var knownHosts = new KnownHosts((tls["HostNames"] ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), section["PublicBaseUrl"], Dns.GetHostName());
    app.Use(async (context, next) =>
    {
        if (!context.Request.IsHttps && !context.Request.Path.StartsWithSegments("/health"))
        {
            if (!knownHosts.Covers(context.Request.Host.Host))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("This server is reached over HTTPS, under one of its own names.");
                return;
            }

            var host = new HostString(context.Request.Host.Host, httpsPort);
            context.Response.Redirect($"https://{host}{context.Request.PathBase}{context.Request.Path}{context.Request.QueryString}");
            return;
        }

        await next();
    });
}

app.UseOidcCallbacks();
app.UseAuthentication();
app.UseForcedPasswordChange();
app.UseAuthorization();
app.UseAntiforgery();
app.MapStaticAssets();

// Facts a monitoring system can threshold, and nothing that needs a sign-in to be useful or reveals a name.
app.MapGet("/health", async (SecretHiveDbContext context, IKeyRing ring, BackupStatus backups, TimeProvider clock, CancellationToken ct) =>
{
    var database = await context.Database.CanConnectAsync(ct);

    // The age of the last backup that was read back whole; null when there is none. A monitor alerts on the number.
    var verified = backups.LastVerifiedUtc;
    var backup = new { lastVerifiedUtc = verified, ageHours = verified is { } at ? Math.Round((clock.GetUtcNow().UtcDateTime - at).TotalHours, 1) : (double?)null };

    // How many events of the kind somebody should look at were written in the last day. A count, never their content.
    var since = clock.GetUtcNow().UtcDateTime.AddHours(-24);
    var securityEvents24h = database ? await context.Audit.CountAsync(row => row.Severity == SecretHive.Domain.Entities.AuditSeverity.Security && row.AtUtc > since, ct) : (int?)null;
    return Results.Json(new { database, masterKey = ring.CurrentKeyId, backup, securityEvents24h }, statusCode: database ? StatusCodes.Status200OK : StatusCodes.Status503ServiceUnavailable);
}).AllowAnonymous();

// Nothing else is anonymous, on any vault, ever. A browser session may read through the API (a certificate part is
// downloaded that way) but may not change anything through it: changes from the pages go through the pages, so a
// link on another site can never act with the administrator's cookie.
var api = app.MapSecretHiveApi();
api.MapGet("/backups", (BackupService backups, ICallerResolver callers, HttpContext http) => backups.List(callers.Resolve(http)));
api.MapPost("/backups", async (BackupService backups, ICallerResolver callers, HttpContext http, CancellationToken ct) =>
    Results.Ok(await backups.CreateAsync(callers.Resolve(http), ct)));
api.MapGet("/backups/{name}", async (string name, BackupService backups, ICallerResolver callers, HttpContext http, CancellationToken ct) =>
    Results.File(await backups.OpenAsync(name, callers.Resolve(http), ct), "application/octet-stream", name));
// Which release answers, for a client that has to know what it can ask for. For anyone who is signed in.
api.MapGet("/server", (ServerInfo server) => Results.Ok(new { version = server.Version }));

// The theme for everyone, as the appearance page sets it: a pack by name, or nothing for the built-in look.
api.MapGet("/settings/theme", (SecretHive.Web.Theming.ThemeChoice theme, SecretHive.Web.Theming.IThemeService themes) =>
    Results.Ok(new { name = theme.Name, packs = themes.Packs.Select(pack => new { pack.Name, pack.Label, pack.Description }) }));
api.MapPut("/settings/theme", async (ThemeRequest request, SecretHive.Web.Theming.ThemeChoice theme, SecretHive.Web.Theming.IThemeService themes, ISecretStore store, AuditWriter audit, ICallerResolver callers, HttpContext http, CancellationToken ct) =>
{
    var caller = callers.Resolve(http);
    if (!caller.IsInstanceAdmin)
    {
        throw new SecretHive.Domain.DomainException("access.denied", "An administrator chooses the theme.");
    }

    var name = (request.Name ?? "").Trim();
    if (name.Length > 0 && themes.GetCss(name) is null)
    {
        throw new SecretHive.Domain.DomainException("theme.not_found", $"There is no pack named '{name}'.");
    }

    await store.SetSettingAsync(SecretHive.Web.Theming.ThemeChoice.SettingKey, name.Length == 0 ? null : name, ct);
    await store.SaveAsync(ct);
    theme.Name = name;
    await audit.RecordAsync("appearance.theme.changed", caller, name.Length == 0 ? "built-in" : name, cancellationToken: ct);
    return Results.NoContent();
});
api.RequireAuthorization("Api").AddEndpointFilter(ApiGate);

// The read side of the 1Password Connect API, for a tool that speaks only that (Termix's Secret Sources). The same
// sign-in, limits and pace as the API above; it only reads.
app.MapOnePasswordConnect().RequireAuthorization("Api").AddEndpointFilter(ApiGate);

async ValueTask<object?> ApiGate(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
{
    var http = context.HttpContext;

    // A credential that is not a person has a pace: a key, the bootstrap token, a job's token from its platform.
    // Beyond it the answer is 429 until the minute is over, and the first refusal is on record.
    var paced = http.User.Identity?.AuthenticationType switch
    {
        ApiKeyHandler.SchemeName => "key:" + http.User.FindFirst(ApiKeyHandler.KeyClaim)?.Value,
        BootstrapAdminHandler.SchemeName => "bootstrap",
        ProviderTokenHandler.SchemeName => "token:" + http.User.Identity.Name,
        _ => null,
    };
    if (paced is not null && !http.RequestServices.GetRequiredService<KeyRateLimiter>().Allow(paced, out var firstRefusal, out var retryAfter))
    {
        if (firstRefusal)
        {
            var limiter = http.RequestServices.GetRequiredService<KeyRateLimiter>();
            await http.RequestServices.GetRequiredService<AuditWriter>().RecordAsync(
                "key.rate_limited",
                http.RequestServices.GetRequiredService<ICallerResolver>().Resolve(http),
                $"{paced} limit={limiter.PerMinute.ToString(CultureInfo.InvariantCulture)}/min",
                SecretHive.Domain.Entities.AuditSeverity.Security);
        }

        http.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
        return Results.Problem(detail: "This credential is making more requests than it may in a minute.", statusCode: StatusCodes.Status429TooManyRequests, extensions: new Dictionary<string, object?> { ["code"] = "key.rate_limited" });
    }

    var throughCookie = http.User.Identity?.AuthenticationType == CookieAuthenticationDefaults.AuthenticationScheme;
    return throughCookie && !HttpMethods.IsGet(http.Request.Method)
        ? Results.Problem(detail: "Changes through the API need the bearer token, not a browser session.", statusCode: StatusCodes.Status403Forbidden)
        : await next(context);
}

// A POST with the page's antiforgery token: a sign-out that is a plain link can be triggered from any other site.
app.MapPost("/logout", async (HttpContext http, IAntiforgery antiforgery) =>
{
    if (await antiforgery.IsRequestValidAsync(http))
    {
        await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    return Results.Redirect("/login");
}).AllowAnonymous().DisableAntiforgery();

// A theme pack is a small stylesheet of colour overrides, loaded after the server's own. Open like the stylesheet
// itself: the sign-in page wears it too.
app.MapGet("/themes/{name}.css", (string name, HttpContext http, SecretHive.Web.Theming.IThemeService themes) =>
{
    if (themes.GetCss(name) is not { } theme)
    {
        return Results.NotFound();
    }

    http.Response.Headers.ETag = theme.ETag;
    http.Response.Headers.CacheControl = "no-cache";
    return Results.Text(theme.Css, "text/css");
}).AllowAnonymous();

// A logo a pack names, from the pack's own folder and nothing else. Served with a policy that runs nothing: an SVG
// opened by itself is a document, and one with a script in it must not run as this site.
app.MapGet("/themes/{name}/assets/{file}", (string name, string file, HttpContext http, SecretHive.Web.Theming.IThemeService themes) =>
{
    if (themes.GetAsset(name, file) is not { } asset)
    {
        return Results.NotFound();
    }

    http.Response.Headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
    http.Response.Headers.XContentTypeOptions = "nosniff";
    http.Response.Headers.CacheControl = "public, max-age=3600";
    return Results.File(asset.Path, asset.ContentType, enableRangeProcessing: false);
}).AllowAnonymous();

app.MapExternalSignIn();
// The framework adds a policy of its own (frame-ancestors 'self'); the one above already says 'none', and one
// policy per answer is easier to reason about than two the browser intersects.
app.MapRazorComponents<App>().AddInteractiveServerRenderMode(options => options.ContentSecurityFrameAncestorsPolicy = null);

await app.RunAsync();
return 0;

/// <summary>The theme pack for everyone, by name; empty for the built-in look.</summary>
internal sealed record ThemeRequest(string? Name);
