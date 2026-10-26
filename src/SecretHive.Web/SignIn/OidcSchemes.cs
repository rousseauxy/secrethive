using System.Collections.Concurrent;
using System.Net;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SecretHive.Web.SignIn;

/// <summary>
/// OpenID Connect providers as authentication schemes that come from the database rather than from startup code. A scheme
/// named <c>oidc-{slug}</c> exists while an enabled provider has that slug, and its options are rebuilt when the
/// provider's row changes. Nothing is registered in memory ahead of time, so a provider saved on one replica is there on
/// every replica at its next sign-in, with no restart.
/// </summary>
public static class OidcSchemes
{
    public const string Prefix = "oidc-";

    /// <summary>Where a provider sends the browser back: <c>/signin-oidc/{slug}</c>.</summary>
    public const string CallbackSegment = "/signin-oidc";

    /// <summary>
    /// Holds the provider's answer between its callback and <c>/account/external/complete</c>, for a few minutes. Never a
    /// session: the account decision is made on the complete endpoint, which then issues the normal sign-in cookie.
    /// </summary>
    public const string ExternalCookie = "secrethive.external";

    public static string Name(string slug) => Prefix + slug.ToLowerInvariant();

    public static string CallbackPath(string slug) => $"{CallbackSegment}/{slug.ToLowerInvariant()}";

    public static void AddOidcProviders(this IServiceCollection services)
    {
        services.AddAuthentication()
            .AddCookie(ExternalCookie, cookie =>
            {
                cookie.Cookie.Name = ExternalCookie;
                cookie.Cookie.HttpOnly = true;
                cookie.Cookie.SameSite = SameSiteMode.Lax;
                cookie.ExpireTimeSpan = TimeSpan.FromMinutes(10);
                cookie.SlidingExpiration = false;
            });
        services.AddWebEncoders();
        services.AddSingleton<IAuthenticationSchemeProvider, OidcSchemeProvider>();
        services.AddSingleton<IOptionsMonitor<OpenIdConnectOptions>, OidcOptionsMonitor>();
    }

    /// <summary>
    /// Runs a provider's callback. The authentication middleware only calls the handlers of schemes registered at
    /// startup, which these are not, so the callback path is recognised here and handed to that provider's handler.
    /// </summary>
    public static IApplicationBuilder UseOidcCallbacks(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments(CallbackSegment, StringComparison.OrdinalIgnoreCase, out var rest)
                && rest.Value is { Length: > 1 } slug
                && slug.IndexOf('/', 1) < 0)
            {
                var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
                if (await handlers.GetHandlerAsync(context, Name(slug[1..])) is IAuthenticationRequestHandler handler
                    && await handler.HandleRequestAsync())
                {
                    return;
                }
            }

            await next(context);
        });

    internal static OidcProvider? FindEnabled(IServiceScopeFactory scopes, string schemeName)
    {
        if (!schemeName.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var slug = schemeName[Prefix.Length..];
        using var scope = scopes.CreateScope();
        return scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().OidcProviders.AsNoTracking().FirstOrDefault(p => p.Slug == slug && p.Enabled);
    }
}

/// <summary>The registered schemes, plus one per enabled provider, looked up by name when a request asks for it.</summary>
public sealed class OidcSchemeProvider(IOptions<AuthenticationOptions> options, IServiceScopeFactory scopes) : AuthenticationSchemeProvider(options)
{
    public override async Task<AuthenticationScheme?> GetSchemeAsync(string name)
    {
        if (await base.GetSchemeAsync(name) is { } registered)
        {
            return registered;
        }

        var provider = OidcSchemes.FindEnabled(scopes, name);
        return provider is null ? null : new AuthenticationScheme(name, provider.DisplayName, typeof(OpenIdConnectHandler));
    }
}

/// <summary>
/// Options for the provider schemes, built from the provider's row. Kept per scheme while the row's
/// <see cref="OidcProvider.UpdatedUtc"/> is unchanged, because the options hold the provider's discovery document and
/// signing keys and fetching those on every sign-in would be slow; a saved change moves the stamp and rebuilds them.
/// </summary>
public sealed class OidcOptionsMonitor(
    IServiceScopeFactory scopes,
    IDataProtectionProvider dataProtection,
    ISecretProtector secrets,
    PublicUrl urls,
    TimeProvider time) : IOptionsMonitor<OpenIdConnectOptions>
{
    private readonly ConcurrentDictionary<string, (DateTime Version, OpenIdConnectOptions Options)> built = new(StringComparer.Ordinal);

    public OpenIdConnectOptions CurrentValue => Get(Options.DefaultName);

    public OpenIdConnectOptions Get(string? name)
    {
        var provider = name is null ? null : OidcSchemes.FindEnabled(scopes, name);
        if (provider is null)
        {
            // Asked for a scheme that no longer exists: options that cannot reach anything, rather than an exception in
            // the middle of the framework's handler set-up.
            return new OpenIdConnectOptions();
        }

        if (built.TryGetValue(name!, out var cached) && cached.Version == provider.UpdatedUtc)
        {
            return cached.Options;
        }

        var options = Build(name!, provider);
        built[name!] = (provider.UpdatedUtc, options);
        return options;
    }

    public IDisposable? OnChange(Action<OpenIdConnectOptions, string?> listener) => null;

    private OpenIdConnectOptions Build(string name, OidcProvider provider)
    {
        var authority = new Uri(provider.Authority);
        var options = new OpenIdConnectOptions
        {
            Authority = provider.Authority,
            ClientId = provider.ClientId,
            ClientSecret = secrets.Unprotect(provider.ProtectedClientSecret),
            ResponseType = OpenIdConnectResponseType.Code,

            // Query, not form_post: the answer then arrives as a top-level GET, which carries SameSite=Lax cookies, so the
            // correlation and nonce cookies need neither SameSite=None nor HTTPS on a local instance.
            ResponseMode = OpenIdConnectResponseMode.Query,
            UsePkce = true,
            CallbackPath = OidcSchemes.CallbackPath(provider.Slug),
            SignInScheme = OidcSchemes.ExternalCookie,
            MapInboundClaims = false,
            GetClaimsFromUserInfoEndpoint = true,
            SaveTokens = false,

            // A plain-HTTP issuer only on this machine, which is what a test provider is. Anything else must use HTTPS.
            RequireHttpsMetadata = !(authority.IsLoopback || IPAddress.TryParse(authority.Host, out var ip) && IPAddress.IsLoopback(ip)),
            TimeProvider = time,
        };

        options.Scope.Clear();
        foreach (var scope in provider.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Append("openid").Distinct(StringComparer.Ordinal))
        {
            options.Scope.Add(scope);
        }

        // Every claim of the user info answer, under its own name: the user name and groups claims are whatever the
        // provider page says, not a fixed list.
        options.ClaimActions.MapAll();
        options.TokenValidationParameters.NameClaimType = provider.UserNameClaim;
        options.CorrelationCookie.SameSite = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = urls.CookiePolicy;
        options.NonceCookie.SameSite = SameSiteMode.Lax;
        options.NonceCookie.SecurePolicy = urls.CookiePolicy;
        // Behind a proxy the request's own scheme and host are only as right as its forwarded headers. With a public base
        // URL configured, the redirect URI is built from it - the same URI the provider page tells people to register. The
        // handler keeps this value for redeeming the code, so both legs of the flow send the same one.
        options.Events.OnRedirectToIdentityProvider = context =>
        {
            if (urls.BaseUrl is { } configured)
            {
                context.ProtocolMessage.RedirectUri = configured + OidcSchemes.CallbackPath(provider.Slug);
            }

            return Task.CompletedTask;
        };
        options.Events.OnRemoteFailure = async context =>
        {
            // What the provider or the handler said went wrong: a protocol message, never a credential.
            var audit = context.HttpContext.RequestServices.GetRequiredService<AuditWriter>();
            await audit.RecordAsync("auth.external.failed", new Caller("unknown", context.HttpContext.Connection.RemoteIpAddress?.ToString(), "ui"), $"provider={provider.Slug} {context.Failure?.Message}", Domain.Entities.AuditSeverity.Notice);
            context.Response.Redirect("/login?external=failed");
            context.HandleResponse();
        };

        new OpenIdConnectPostConfigureOptions(dataProtection).PostConfigure(name, options);
        return options;
    }
}

/// <summary>
/// How a client secret was stored before 0.7: under the session keys in the data folder, which a backup does not
/// hold. Still read, so a secret stored that way keeps working until the start-up step has moved it under the
/// master key.
/// </summary>
public sealed class DataProtectionSecretProtector(IDataProtectionProvider provider) : ISecretProtector
{
    private readonly IDataProtector protector = provider.CreateProtector("SecretHive.OidcProvider.ClientSecret");

    public string Protect(string secret) => string.IsNullOrEmpty(secret) ? "" : protector.Protect(secret);

    public string? Unprotect(string protectedSecret)
    {
        if (string.IsNullOrEmpty(protectedSecret))
        {
            return null;
        }

        try
        {
            return protector.Unprotect(protectedSecret);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }
}

/// <summary>
/// The address people reach this server at, when it is not the one a request arrives with: behind a proxy, the
/// redirect address a provider is told has to be the public one. From <c>SecretHive:PublicBaseUrl</c>.
/// </summary>
public sealed class PublicUrl(string? baseUrl, bool tls)
{
    /// <summary>Without a trailing slash; null when none is configured and the request's own address is used.</summary>
    public string? BaseUrl { get; } = string.IsNullOrWhiteSpace(baseUrl) ? null : baseUrl.Trim().TrimEnd('/');

    public CookieSecurePolicy CookiePolicy { get; } = tls ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;

    /// <summary>The redirect address to register at a provider for a slug, as far as this server can know it.</summary>
    public string RedirectUri(string slug, HttpRequest? request) =>
        (BaseUrl ?? (request is null ? "https://<this server>" : $"{request.Scheme}://{request.Host}")) + OidcSchemes.CallbackPath(slug);
}

/// <summary>Stores under the master key; reads that, and what an earlier release stored under the session keys.</summary>
public sealed class ServerSecretProtector(SecretHive.Infrastructure.Encryption.MasterKeySecretProtector current, DataProtectionSecretProtector earlier) : ISecretProtector
{
    public string Protect(string secret) => current.Protect(secret);

    public string? Unprotect(string protectedSecret) =>
        string.IsNullOrEmpty(protectedSecret) ? null
        : IsCurrent(protectedSecret) ? current.Unprotect(protectedSecret)
        : earlier.Unprotect(protectedSecret);

    public static bool IsCurrent(string protectedSecret) =>
        protectedSecret.StartsWith(SecretHive.Infrastructure.Encryption.MasterKeySecretProtector.Prefix, StringComparison.Ordinal);
}
